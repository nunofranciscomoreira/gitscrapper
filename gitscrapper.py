#!/usr/bin/python3
"""List all GitLab projects and run gitleaks against each of them.

Before running:
    - export GIT_ENDPOINT   (e.g. https://gitlab.example.com)
    - export GIT_PRIVATE_TOKEN
    - optionally export GITLEAKS_BIN (defaults to "gitleaks" on PATH)
    - optionally export GITSCRAPPER_WORKERS, GIT_CLONE_TIMEOUT_S, GITLEAKS_TIMEOUT_S,
      GITSCRAPPER_GITLEAKS_CONFIG, GITSCRAPPER_GITLEAKS_IGNORE_DIR

The "repositories" and "leaks_reports" folders are created automatically.
Run with --help for CLI options (--mode, --workers, --dry-run, --skip-archived).
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

GITLEAKS_BIN = os.environ.get("GITLEAKS_BIN", shutil.which("gitleaks") or "gitleaks")
# Always passed with --config, so a repo's own .gitleaks.toml is never used.
GITLEAKS_CONFIG = os.environ.get(
    "GITSCRAPPER_GITLEAKS_CONFIG", os.path.join(SCRIPT_DIR, "gitleaks.toml")
)
# Directory holding the central .gitleaksignore (if any). Pinned so gitleaks
# doesn't pick one up from whatever directory the script is run from.
GITLEAKS_IGNORE_DIR = os.environ.get("GITSCRAPPER_GITLEAKS_IGNORE_DIR", SCRIPT_DIR)


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
GITLEAKS_TIMEOUT_S = positive_int_env("GITLEAKS_TIMEOUT_S", 600)

# This workload is I/O-bound (network clone dominates wall time, not CPU), so
# default to more workers than os.cpu_count() would give. Still capped so we
# don't hammer the GitLab instance; tune with --workers/GITSCRAPPER_WORKERS.
DEFAULT_WORKERS = min(32, (os.cpu_count() or 4) * 4)

CLONE_RETRIES = 1  # extra attempts after the first, on transient failures only
CLONE_RETRY_BACKOFF_S = 3

# "quick" scans every branch and tag of a normal clone. "full" also fetches
# GitLab merge-request refs, opens archives (zip, tar, ...), and recursively
# decodes percent/hex/base64-encoded text in the repo.
SCAN_MODES = ("quick", "full")
FULL_MODE_ARCHIVE_DEPTH = 2
# gitleaks' own --help default for this flag has disagreed with its README
# across versions (seen 0 and 5 on different builds), so quick mode leaves it
# unset (whatever the installed gitleaks defaults to) and only full mode
# pins an explicit value, for a reproducible "maximum effort" scan.
FULL_MODE_DECODE_DEPTH = 5
MERGE_REQUEST_REFSPEC = "+refs/merge-requests/*/head:refs/remotes/origin/merge-requests/*"

# gitleaks exits 1 on fatal errors (e.g. a broken config) as well as on leaks
# by default, so leaks get their own exit code to keep the two apart.
LEAKS_EXIT_CODE = 2
# Percentage of each secret to mask in reports: enough to keep the real
# credential out of leaks_reports/, while leaving a prefix to triage with.
REDACT_PERCENT = 80

# gitleaks reads <repo root>/.gitleaksignore even when --gitleaks-ignore-path
# points elsewhere, so it is deleted from the clone before scanning.
REPO_SCAN_OVERRIDES = (".gitleaksignore",)

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
    """Deletes files a repo could use to hide its own findings from gitleaks."""
    for filename in REPO_SCAN_OVERRIDES:
        path = os.path.join(repo_path(name), filename)
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        elif os.path.lexists(path):
            os.remove(path)


def gitleaks_command(name, mode):
    command = [
        GITLEAKS_BIN,
        "git",
        repo_path(name),
        "--config",
        GITLEAKS_CONFIG,
        "--gitleaks-ignore-path",
        GITLEAKS_IGNORE_DIR,
        "--ignore-gitleaks-allow",
        "--exit-code",
        str(LEAKS_EXIT_CODE),
        "--platform",
        "gitlab",
        f"--redact={REDACT_PERCENT}",
        "--report-format",
        "json",
        "--report-path",
        report_path(name),
        "--no-banner",
        "--log-level",
        "error",
    ]
    if mode == "full":
        command += ["--max-archive-depth", str(FULL_MODE_ARCHIVE_DEPTH)]
        command += ["--max-decode-depth", str(FULL_MODE_DECODE_DEPTH)]
    return command


def gitleak_check(name, mode):
    """Runs gitleaks against a cloned repository and returns the CompletedProcess.

    Exit code 0 means no leaks, LEAKS_EXIT_CODE means leaks were found, and
    anything else is a tool error. Raises subprocess.TimeoutExpired if the
    scan exceeds GITLEAKS_TIMEOUT_S.
    """
    # Without a ceiling, a clone missing its .git would make git walk up and
    # scan whichever repository encloses repositories/ instead.
    env = {**os.environ, "GIT_CEILING_DIRECTORIES": os.path.abspath(REPOSITORIES_DIR)}
    return subprocess.run(
        gitleaks_command(name, mode),
        capture_output=True,
        text=True,
        timeout=GITLEAKS_TIMEOUT_S,
        env=env,
    )


def drop_empty_report(name):
    """Removes the report if it holds no findings."""
    path = report_path(name)
    try:
        with open(path, "r", encoding="utf-8") as report_file:
            findings = json.load(report_file)
    except FileNotFoundError:
        return
    except json.JSONDecodeError:
        log.warning("Could not parse report for %s, leaving it as-is", name)
        return
    if not findings:
        os.remove(path)


def remove_repo(name):
    """Deletes a cloned repository from the machine, logging (not raising) on failure."""
    path = repo_path(name)
    if not os.path.exists(path):
        return
    shutil.rmtree(path, onerror=_log_rmtree_error)


def _last_line(text):
    lines = (text or "").strip().splitlines()
    return lines[-1] if lines else ""


def organize(project, mode="quick"):
    """Clones, scans and cleans up a single project. Returns (name, status)
    where status is "clean", "pwned" or "error". Never raises: any failure
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
        result = gitleak_check(name, mode)
        drop_empty_report(name)
    except subprocess.TimeoutExpired:
        log.error("gitleaks timed out for %s after %ds", name, GITLEAKS_TIMEOUT_S)
    except Exception:  # pylint: disable=broad-except
        log.exception("Scan failed for %s", name)
    finally:
        remove_repo(name)

    if result is None:
        return name, "error"
    if result.returncode == LEAKS_EXIT_CODE:
        return name, "pwned"
    if result.returncode == 0 and not result.stderr.strip():
        return name, "clean"
    # Exit 0 with error output means gitleaks swallowed a failure (e.g. git
    # log erroring out), so the "no leaks" result can't be trusted.
    log.error(
        "gitleaks exited %s on %s: %s", result.returncode, name, _last_line(result.stderr)
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
    return parser.parse_args(argv)


def check_scan_setup():
    """Exits with a clear error if gitleaks or its pinned config/ignore dir is missing."""
    if not shutil.which(GITLEAKS_BIN):
        log.error(
            "Could not find gitleaks binary %r. Install gitleaks, put it on PATH, "
            "or set GITLEAKS_BIN to its full path.",
            GITLEAKS_BIN,
        )
        sys.exit(1)
    if not os.path.isfile(GITLEAKS_CONFIG):
        log.error(
            "gitleaks config %r not found. Keep gitleaks.toml next to this script, "
            "or set GITSCRAPPER_GITLEAKS_CONFIG.",
            GITLEAKS_CONFIG,
        )
        sys.exit(1)
    if not os.path.isdir(GITLEAKS_IGNORE_DIR):
        log.error(
            "GITSCRAPPER_GITLEAKS_IGNORE_DIR %r is not a directory", GITLEAKS_IGNORE_DIR
        )
        sys.exit(1)


def write_summary(projects, statuses):
    """Writes the per-bucket name lists and a JSON index tying each repo to
    its URL, status and report file."""
    for label in ("pwned", "clean", "error"):
        names = [p["name"] for p in projects if statuses.get(p["name"]) == label]
        path = f"{LEAKS_REPORTS_DIR}/{today_frmt}_{label}_repos.txt"
        with open(path, "w", encoding="utf-8") as fp:
            fp.write("\n".join(names) + "\n" if names else "")

    summary = []
    for project in projects:
        name = project["name"]
        path = report_path(name)
        summary.append(
            {
                "name": name,
                "url": project["http_url"],
                "status": statuses.get(name, "error"),
                "report": path if os.path.exists(path) else None,
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
    log.info("Found %d project(s) to scan in %s mode", total, args.mode)

    if args.dry_run:
        for project in projects:
            log.info("[dry-run] would scan %s", project["name"])
        return

    start = time.monotonic()
    statuses = {}
    counts = {"clean": 0, "pwned": 0, "error": 0}
    progress_every = max(1, total // 20)  # ~5% increments
    scan = functools.partial(organize, mode=args.mode)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for completed, (name, status) in enumerate(pool.map(scan, projects), start=1):
            statuses[name] = status
            counts[status] += 1
            if completed % progress_every == 0 or completed == total:
                log.info(
                    "Progress: %d/%d done (clean=%d pwned=%d error=%d)",
                    completed,
                    total,
                    counts["clean"],
                    counts["pwned"],
                    counts["error"],
                )
    elapsed = time.monotonic() - start

    write_summary(projects, statuses)

    log.info(
        "Scan done in %.0fs! clean=%d pwned=%d error=%d",
        elapsed,
        counts["clean"],
        counts["pwned"],
        counts["error"],
    )
    errored = [name for name, status in statuses.items() if status == "error"]
    if errored:
        log.warning("Repos that errored out: %s", ", ".join(errored))


if __name__ == "__main__":
    main()
