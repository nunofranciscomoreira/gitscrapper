#!/usr/bin/python3
"""List all GitLab projects and run betterleaks against each of them.

Before running:
    - export GIT_ENDPOINT   (e.g. https://gitlab.example.com)
    - export GIT_PRIVATE_TOKEN
    - optionally export BETTERLEAKS_BIN (defaults to "betterleaks" on PATH)
    - optionally export GITSCRAPPER_WORKERS, GIT_CLONE_TIMEOUT_S, BETTERLEAKS_TIMEOUT_S,
      GITSCRAPPER_BETTERLEAKS_CONFIG, GITSCRAPPER_BETTERLEAKS_IGNORE_FILE,
      GITSCRAPPER_VALIDATE

The "repositories" and "leaks_reports" folders are created automatically.
Run with --help for CLI options (--mode, --workers, --dry-run, --skip-archived,
--validate).
"""
import argparse
import functools
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date

import gitlab

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("gitscrapper")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

BETTERLEAKS_BIN = os.environ.get(
    "BETTERLEAKS_BIN", shutil.which("betterleaks") or "betterleaks"
)
# Always passed with --config, so a repo's own .betterleaks.toml is never used.
BETTERLEAKS_CONFIG = os.environ.get(
    "GITSCRAPPER_BETTERLEAKS_CONFIG", os.path.join(SCRIPT_DIR, "betterleaks.toml")
)
# Central ignore file. Always passed with --ignore-file: without it betterleaks
# reads <scanned repo>/.betterleaksignore, which the repo itself controls.
BETTERLEAKS_IGNORE_FILE = os.environ.get(
    "GITSCRAPPER_BETTERLEAKS_IGNORE_FILE", os.path.join(SCRIPT_DIR, ".betterleaksignore")
)


def positive_int(value):
    """argparse type: parses value as an int > 0."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if number <= 0:
        raise argparse.ArgumentTypeError(f"{value!r} must be greater than 0")
    return number


def positive_int_env(name, default):
    """Reads an env var as an int > 0, or exits with a clear error."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return positive_int(raw)
    except argparse.ArgumentTypeError as exc:
        log.error("Invalid %s: %s", name, exc)
        sys.exit(1)


GIT_CLONE_TIMEOUT_S = positive_int_env("GIT_CLONE_TIMEOUT_S", 300)
BETTERLEAKS_TIMEOUT_S = positive_int_env("BETTERLEAKS_TIMEOUT_S", 600)

# This workload is I/O-bound (network clone dominates wall time, not CPU), so
# default to more workers than os.cpu_count() would give. Still capped so we
# don't hammer the GitLab instance; tune with --workers/GITSCRAPPER_WORKERS.
DEFAULT_WORKERS = min(32, (os.cpu_count() or 4) * 4)

CLONE_RETRIES = 1  # extra attempts after the first, on transient failures only
CLONE_RETRY_BACKOFF_S = 3

# "quick" scans every branch and tag of a normal clone. "full" also fetches
# GitLab merge-request refs, opens archives (zip, tar, ...), recursively
# decodes percent/hex/base64-encoded text, and scans merge-commit diffs and
# commit/tag messages.
SCAN_MODES = ("quick", "full")
# betterleaks' git default is 8, so quick mode has to turn archives off explicitly.
QUICK_MODE_ARCHIVE_DEPTH = 0
FULL_MODE_ARCHIVE_DEPTH = 2
FULL_MODE_DECODE_DEPTH = 5
FULL_MODE_INCLUDE = "merges,commit-messages,tag-messages"
MERGE_REQUEST_REFSPEC = "+refs/merge-requests/*/head:refs/remotes/origin/merge-requests/*"

# With --validate, keep every status except those proving the secret is dead:
# rules without a validator ("none") and failed checks must not become misses.
VALIDATE_KEEP_STATUSES = "valid,needs_validation,unknown,error,none"

# betterleaks exits 1 on fatal errors (e.g. a broken config) as well as on
# leaks by default, so leaks get their own exit code to keep the two apart.
LEAKS_EXIT_CODE = 2
# Percentage of each secret to mask in reports: enough to keep the real
# credential out of leaks_reports/, while leaving a prefix to triage with.
REDACT_PERCENT = 80

# Triage: a finding is actionable if a provider confirmed it live, or if its
# rule is confident and validation didn't prove it dead. Everything else,
# including findings with no confidence set, is left for manual review.
ACTIONABLE_CONFIDENCE = ("high", "medium")
DEAD_STATUSES = ("invalid", "revoked")

# Deleted from each clone before scanning, so a repo can't hide its own
# findings even if a future flag or default starts reading them.
REPO_SCAN_OVERRIDES = (
    ".betterleaksignore",
    ".gitleaksignore",
    ".betterleaks.toml",
    ".gitleaks.toml",
)

REPOSITORIES_DIR = "repositories"
LEAKS_REPORTS_DIR = "leaks_reports"

today = date.today()
today_frmt = today.strftime("%b-%d-%Y")


def require_env(name):
    """Returns the named environment variable, or exits with a clear error."""
    value = os.environ.get(name)
    if not value:
        log.error("Missing required environment variable: %s", name)
        sys.exit(1)
    return value


def is_safe_name(name):
    """Guards against a malformed/unexpected name escaping repositories/ or
    leaks_reports/ (e.g. via "/" or "..")."""
    return (
        bool(name)
        and "/" not in name
        and "\\" not in name
        and ".." not in name
        and not os.path.isabs(name)
    )


def repo_path(name):
    return f"{REPOSITORIES_DIR}/{name}"


def report_path(name):
    return f"{LEAKS_REPORTS_DIR}/secrets_{name}.json"


def _log_rmtree_error(func, path, exc_info):
    log.warning("Failed to remove %s during cleanup (%s): %s", path, func.__name__, exc_info[1])


def clone(ssh_url_to_repo, name):
    """Clones a repository to the machine.

    Raises CalledProcessError on failure, or subprocess.TimeoutExpired if it
    takes longer than GIT_CLONE_TIMEOUT_S.
    """
    subprocess.run(
        ["git", "clone", ssh_url_to_repo, repo_path(name)],
        check=True,
        capture_output=True,
        text=True,
        timeout=GIT_CLONE_TIMEOUT_S,
    )


def clone_with_retry(ssh_url_to_repo, name):
    """Clones a repository, retrying after a transient failure.

    Raises the same exceptions as clone() if every attempt fails.
    """
    attempts = CLONE_RETRIES + 1
    for attempt in range(1, attempts + 1):
        try:
            clone(ssh_url_to_repo, name)
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            remove_repo(name)  # clear any partial clone before retrying
            if attempt == attempts:
                raise
            log.warning(
                "Clone attempt %d/%d failed for %s, retrying in %ds",
                attempt,
                attempts,
                name,
                CLONE_RETRY_BACKOFF_S,
            )
            time.sleep(CLONE_RETRY_BACKOFF_S)


def fetch_merge_request_refs(name):
    """Fetches GitLab merge-request heads so their commits get scanned too.

    Raises CalledProcessError or subprocess.TimeoutExpired on failure.
    """
    subprocess.run(
        ["git", "-C", repo_path(name), "fetch", "--quiet", "origin", MERGE_REQUEST_REFSPEC],
        check=True,
        capture_output=True,
        text=True,
        timeout=GIT_CLONE_TIMEOUT_S,
    )


def remove_scan_overrides(name):
    """Deletes files a repo could use to hide its own findings from betterleaks."""
    for filename in REPO_SCAN_OVERRIDES:
        path = os.path.join(repo_path(name), filename)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        elif os.path.lexists(path):
            os.remove(path)


def betterleaks_command(name, mode, validate=False):
    command = [
        BETTERLEAKS_BIN,
        "git",
        # The .git dir, not the worktree: betterleaks resolves a worktree path
        # to its enclosing repository and ignores GIT_CEILING_DIRECTORIES, so a
        # clone missing its .git would get whatever repo encloses it scanned.
        os.path.join(repo_path(name), ".git"),
        "--config",
        BETTERLEAKS_CONFIG,
        "--ignore-file",
        BETTERLEAKS_IGNORE_FILE,
        "--no-allow-signatures",
        "--exit-code",
        str(LEAKS_EXIT_CODE),
        "--platform",
        "gitlab",
        f"--redact={REDACT_PERCENT}",
        "--output",
        report_path(name),
        "--silent",
        "--no-banner",
        "--log-level",
        "error",
    ]
    if mode == "full":
        command += ["--max-archive-depth", str(FULL_MODE_ARCHIVE_DEPTH)]
        command += ["--max-decode-depth", str(FULL_MODE_DECODE_DEPTH)]
        command += [f"--include={FULL_MODE_INCLUDE}"]
    else:
        command += ["--max-archive-depth", str(QUICK_MODE_ARCHIVE_DEPTH)]
    if validate:
        command += ["--validate", "--status", VALIDATE_KEEP_STATUSES]
    return command


def betterleaks_check(name, mode, validate=False):
    """Runs betterleaks against a cloned repository and returns the CompletedProcess.

    Exit code 0 means no leaks, LEAKS_EXIT_CODE means leaks were found, and
    anything else is a tool error. Raises subprocess.TimeoutExpired if the
    scan exceeds BETTERLEAKS_TIMEOUT_S.
    """
    return subprocess.run(
        betterleaks_command(name, mode, validate),
        capture_output=True,
        text=True,
        timeout=BETTERLEAKS_TIMEOUT_S,
    )


def report_complete(name):
    """False if betterleaks marked the scan incomplete (e.g. corrupt objects or
    unreadable refs), since a partial scan can't vouch for a clean repo."""
    try:
        with open(report_path(name), "r", encoding="utf-8") as report_file:
            report = json.load(report_file)
    except (FileNotFoundError, json.JSONDecodeError):
        return True
    if not isinstance(report, dict):
        return True
    return (report.get("scan") or {}).get("state") != "incomplete"


def drop_empty_report(name):
    """Removes the report if it holds no findings."""
    path = report_path(name)
    try:
        with open(path, "r", encoding="utf-8") as report_file:
            report = json.load(report_file)
    except FileNotFoundError:
        return
    except json.JSONDecodeError:
        log.warning("Could not parse report for %s, leaving it as-is", name)
        return
    if isinstance(report, dict) and not report.get("findings"):
        os.remove(path)


def finding_status(finding):
    """The validation status of a finding; "none" when it wasn't validated."""
    return (finding.get("analysis") or {}).get("status") or "none"


def finding_tier(finding):
    """Returns "actionable" or "review" for one betterleaks finding."""
    status = finding_status(finding)
    if status == "valid":
        return "actionable"
    if finding.get("confidence") in ACTIONABLE_CONFIDENCE and status not in DEAD_STATUSES:
        return "actionable"
    return "review"


def triage_report(name):
    """Reads a repo's report and returns {"actionable": [...], "review": [...]},
    one entry per unique secret (match.fingerprint). A secret is actionable if
    any of its occurrences is. Values in the report are already redacted."""
    triage = {"actionable": [], "review": []}
    try:
        with open(report_path(name), "r", encoding="utf-8") as report_file:
            report = json.load(report_file)
    except (FileNotFoundError, json.JSONDecodeError):
        return triage
    if not isinstance(report, dict):
        return triage

    entries = {}
    for finding in report.get("findings") or []:
        match = finding.get("match") or {}
        key = match.get("fingerprint") or (finding.get("rule_id"), match.get("value"))
        tier = finding_tier(finding)
        entry = entries.get(key)
        if entry is not None:
            entry["occurrences"] += 1
            if not (tier == "actionable" and entry["tier"] == "review"):
                continue
        location = finding.get("location") or {}
        entries[key] = {
            "tier": tier,
            "rule_id": finding.get("rule_id"),
            "confidence": finding.get("confidence"),
            "status": finding_status(finding),
            "path": location.get("path"),
            "line": location.get("start_line"),
            "commit": (finding.get("attributes") or {}).get("git.sha"),
            "occurrences": entry["occurrences"] if entry else 1,
            "fingerprint": match.get("fingerprint"),
        }
    for entry in entries.values():
        triage[entry.pop("tier")].append(entry)
    return triage


def remove_repo(name):
    """Deletes a cloned repository from the machine, logging (not raising) on failure."""
    path = repo_path(name)
    if not os.path.exists(path):
        return
    shutil.rmtree(path, onerror=_log_rmtree_error)


def _last_line(text):
    lines = (text or "").strip().splitlines()
    return lines[-1] if lines else ""


def organize(project, mode="quick", validate=False):
    """Clones, scans and cleans up a single project. Returns (name, status)
    where status is "clean", "review" (findings, none actionable), "pwned"
    (actionable findings) or "error". Never raises: any failure
    is logged and reported as "error" so one bad repo can't abort the run
    or skip cleanup for the others running concurrently.
    """
    name = project["name"]
    ssh_url_to_repo = project["ssh_url"]

    try:
        clone_with_retry(ssh_url_to_repo, name)
    except subprocess.CalledProcessError as exc:
        log.error("Clone failed for %s: %s", name, (exc.stderr or "").strip())
        remove_repo(name)
        return name, "error"
    except subprocess.TimeoutExpired:
        log.error("Clone timed out for %s after %ds", name, GIT_CLONE_TIMEOUT_S)
        remove_repo(name)
        return name, "error"

    result = None
    complete = True
    triage = None
    try:
        if not os.path.isdir(os.path.join(repo_path(name), ".git")):
            log.error("Clone of %s has no .git directory, not scanning it", name)
            return name, "error"
        remove_scan_overrides(name)
        if mode == "full":
            try:
                fetch_merge_request_refs(name)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                log.warning(
                    "Could not fetch merge-request refs for %s, scanning without them: %s",
                    name,
                    _last_line(getattr(exc, "stderr", "")) or type(exc).__name__,
                )
        result = betterleaks_check(name, mode, validate)
        complete = report_complete(name)
        drop_empty_report(name)
        triage = triage_report(name)
    except subprocess.TimeoutExpired:
        log.error("betterleaks timed out for %s after %ds", name, BETTERLEAKS_TIMEOUT_S)
    except Exception:  # pylint: disable=broad-except
        log.exception("Scan failed for %s", name)
    finally:
        remove_repo(name)

    if result is None:
        return name, "error"
    review_only = bool(triage and triage["review"] and not triage["actionable"])
    # An unreadable report still counts as pwned, and an incomplete scan with
    # only review-tier findings is an error: it may have missed actionable ones.
    if result.returncode == LEAKS_EXIT_CODE and not review_only:
        return name, "pwned"
    if result.returncode == LEAKS_EXIT_CODE and complete:
        return name, "review"
    if not complete:
        log.error("betterleaks scan of %s was incomplete: %s", name, _last_line(result.stderr))
        return name, "error"
    if result.returncode == 0 and not result.stderr.strip():
        return name, "clean"
    # Exit 0 with error output means betterleaks swallowed a failure (e.g. git
    # erroring out), so the "no leaks" result can't be trusted.
    log.error(
        "betterleaks exited %s on %s: %s", result.returncode, name, _last_line(result.stderr)
    )
    return name, "error"


def build_projects(git_projects):
    """Converts GitLab project objects into the plain dicts organize() expects,
    skipping any whose derived name isn't safe to use as a path segment.
    """
    projects = []
    for project in git_projects:
        # project.id is unique instance-wide; the repo's own name is kept
        # in the prefix only for readability, since two projects in
        # different namespaces (e.g. teamA/backend, teamB/backend) can
        # otherwise share the same last path segment and collide on
        # repositories/<name> and leaks_reports/secrets_<name>.json.
        name = f"{project.path}-{project.id}"
        if not is_safe_name(name):
            log.warning("Skipping project with unsafe derived name: %r", name)
            continue
        projects.append(
            {
                "name": name,
                "ssh_url": project.ssh_url_to_repo,
                "http_url": project.web_url,
            }
        )
    return projects


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=SCAN_MODES,
        default="quick",
        help="quick: all branches and tags. full: also merge-request refs and the "
        "contents of archives (slower). (default: %(default)s)",
    )
    parser.add_argument(
        "--workers",
        type=positive_int,
        default=positive_int_env("GITSCRAPPER_WORKERS", DEFAULT_WORKERS),
        help="number of repos to clone/scan concurrently (default: %(default)s)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="list the projects that would be scanned and exit, without cloning anything",
    )
    parser.add_argument(
        "--skip-archived",
        action="store_true",
        help="don't scan archived projects",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        default=os.environ.get("GITSCRAPPER_VALIDATE", "").lower() in ("1", "true", "yes"),
        help="check findings against provider APIs and drop only those confirmed "
        "invalid or revoked; sends each candidate secret to its provider "
        "(also set by GITSCRAPPER_VALIDATE=1)",
    )
    return parser.parse_args(argv)


def check_scan_setup():
    """Exits with a clear error if betterleaks or its pinned config/ignore file is missing."""
    if not shutil.which(BETTERLEAKS_BIN):
        log.error(
            "Could not find betterleaks binary %r. Install betterleaks v2, put it on PATH, "
            "or set BETTERLEAKS_BIN to its full path.",
            BETTERLEAKS_BIN,
        )
        sys.exit(1)
    if not os.path.isfile(BETTERLEAKS_CONFIG):
        log.error(
            "betterleaks config %r not found. Keep betterleaks.toml next to this script, "
            "or set GITSCRAPPER_BETTERLEAKS_CONFIG.",
            BETTERLEAKS_CONFIG,
        )
        sys.exit(1)
    if not os.path.isfile(BETTERLEAKS_IGNORE_FILE):
        log.error(
            "betterleaks ignore file %r not found. Keep .betterleaksignore next to this "
            "script, or set GITSCRAPPER_BETTERLEAKS_IGNORE_FILE.",
            BETTERLEAKS_IGNORE_FILE,
        )
        sys.exit(1)


def write_summary(projects, statuses):
    """Writes the per-bucket name lists and a JSON index tying each repo to
    its URL, status, report file and deduplicated, triaged findings."""
    for label in ("pwned", "review", "clean", "error"):
        names = [p["name"] for p in projects if statuses.get(p["name"]) == label]
        path = f"{LEAKS_REPORTS_DIR}/{today_frmt}_{label}_repos.txt"
        with open(path, "w", encoding="utf-8") as fp:
            fp.write("\n".join(names) + "\n" if names else "")

    summary = []
    for project in projects:
        name = project["name"]
        path = report_path(name)
        triage = triage_report(name)
        summary.append(
            {
                "name": name,
                "url": project["http_url"],
                "status": statuses.get(name, "error"),
                "report": path if os.path.exists(path) else None,
                "unique_secrets": len(triage["actionable"]) + len(triage["review"]),
                "actionable": len(triage["actionable"]),
                "review": len(triage["review"]),
                "triage": triage,
            }
        )
    with open(f"{LEAKS_REPORTS_DIR}/{today_frmt}_summary.json", "w", encoding="utf-8") as fp:
        json.dump(summary, fp, indent=2)


def main():
    args = parse_args()

    git_endpoint = require_env("GIT_ENDPOINT")
    git_private_token = require_env("GIT_PRIVATE_TOKEN")
    check_scan_setup()

    os.makedirs(REPOSITORIES_DIR, exist_ok=True)
    os.makedirs(LEAKS_REPORTS_DIR, exist_ok=True)

    gl = gitlab.Gitlab(url=git_endpoint, private_token=git_private_token)
    gl.auth()
    list_kwargs = {"get_all": True}
    if args.skip_archived:
        list_kwargs["archived"] = False
    git_projects = gl.projects.list(**list_kwargs)  # can take a while on large instances

    projects = build_projects(git_projects)
    total = len(projects)
    log.info(
        "Found %d project(s) to scan in %s mode%s",
        total,
        args.mode,
        " with validation" if args.validate else "",
    )

    if args.dry_run:
        for project in projects:
            log.info("[dry-run] would scan %s", project["name"])
        return

    start = time.monotonic()
    statuses = {}
    counts = {"clean": 0, "review": 0, "pwned": 0, "error": 0}
    progress_every = max(1, total // 20)  # ~5% increments
    scan = functools.partial(organize, mode=args.mode, validate=args.validate)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for completed, (name, status) in enumerate(pool.map(scan, projects), start=1):
            statuses[name] = status
            counts[status] += 1
            if completed % progress_every == 0 or completed == total:
                log.info(
                    "Progress: %d/%d done (clean=%d review=%d pwned=%d error=%d)",
                    completed,
                    total,
                    counts["clean"],
                    counts["review"],
                    counts["pwned"],
                    counts["error"],
                )
    elapsed = time.monotonic() - start

    write_summary(projects, statuses)

    log.info(
        "Scan done in %.0fs! clean=%d review=%d pwned=%d error=%d",
        elapsed,
        counts["clean"],
        counts["review"],
        counts["pwned"],
        counts["error"],
    )
    errored = [name for name, status in statuses.items() if status == "error"]
    if errored:
        log.warning("Repos that errored out: %s", ", ".join(errored))


if __name__ == "__main__":
    main()
