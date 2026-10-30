#!/usr/bin/python3
"""List all GitLab projects and run betterleaks against each of them.

Before running:
    - export GIT_ENDPOINT   (e.g. https://gitlab.example.com)
    - export GIT_PRIVATE_TOKEN
    - optionally export BETTERLEAKS_BIN (defaults to "betterleaks" on PATH)
    - optionally export GITSCRAPPER_WORKERS, GIT_CLONE_TIMEOUT_S, BETTERLEAKS_TIMEOUT_S,
      GITSCRAPPER_BETTERLEAKS_CONFIG, GITSCRAPPER_BETTERLEAKS_IGNORE_FILE,
      GITSCRAPPER_VALIDATE, GITSCRAPPER_GITLAB_RESOURCES

The "repositories" and "leaks_reports" folders are created automatically.
Run with --help for CLI options (--mode, --workers, --dry-run, --skip-archived,
--validate, --gitlab-resources).
"""
import argparse
import functools
import json
import logging
import os
import re
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


def bool_env(name):
    return os.environ.get(name, "").lower() in ("1", "true", "yes")


GIT_CLONE_TIMEOUT_S = positive_int_env("GIT_CLONE_TIMEOUT_S", 300)
BETTERLEAKS_TIMEOUT_S = positive_int_env("BETTERLEAKS_TIMEOUT_S", 600)

# This workload is I/O-bound (network clone dominates wall time, not CPU), so
# default to more workers than os.cpu_count() would give. Still capped so we
# don't hammer the GitLab instance; tune with --workers/GITSCRAPPER_WORKERS.
DEFAULT_WORKERS = min(32, (os.cpu_count() or 4) * 4)

CLONE_RETRIES = 1  # extra attempts after the first, on transient failures only
CLONE_RETRY_BACKOFF_S = 3

# Both modes scan every branch and tag of a normal clone plus commit and tag
# messages, open archives (zip, tar, ...) and recursively decode
# percent/hex/base64-encoded text, since all of these are cheap. "full" also
# fetches GitLab merge-request refs and git notes, scans merge-commit diffs and
# notes, and scans the project wiki. Reflogs and unreachable objects are left
# out: a fresh clone has none.
SCAN_MODES = ("quick", "full")
# Pinned in both modes: betterleaks' git defaults (archives 8, decode 5) may change.
ARCHIVE_DEPTH = 2
DECODE_DEPTH = 5
QUICK_MODE_INCLUDE = "commit-messages,tag-messages"
FULL_MODE_INCLUDE = "merges,commit-messages,tag-messages,notes"
MERGE_REQUEST_REFSPEC = "+refs/merge-requests/*/head:refs/remotes/origin/merge-requests/*"
NOTES_REFSPEC = "+refs/notes/*:refs/notes/*"

# With --gitlab-resources, the GitLab API content scanned next to the clone.
# Repos are excluded (the clone already covers them), and so are CI artifacts
# and release assets, which "ci-jobs" and "releases" would otherwise pull in.
GITLAB_RESOURCES_INCLUDE = "issues,issue-comments,mrs,mr-comments,snippets,releases,ci-jobs"
GITLAB_RESOURCES_EXCLUDE = "repos,forks,ci-artifacts,release-assets"

# With --validate, keep every status except those proving the secret is dead:
# rules without a validator ("none") and failed checks must not become misses.
VALIDATE_KEEP_STATUSES = "valid,needs_validation,unknown,error,none"

# betterleaks exits 1 on fatal errors (e.g. a broken config) as well as on
# leaks by default, so leaks get their own exit code to keep the two apart.
LEAKS_EXIT_CODE = 2
# Percentage of each secret to mask in reports: enough to keep the real
# credential out of leaks_reports/, while leaving a prefix to triage with.
REDACT_PERCENT = 80
# Shorter secrets aren't masked inside attributes (e.g. commit messages), so
# common words captured as URI schemes or hosts don't get masked there too.
REDACT_MIN_ATTRIBUTE_LENGTH = 8

# Triage: a finding is actionable if a provider confirmed it live, or if its
# rule is confident and validation didn't prove it dead. Everything else,
# including findings with no confidence set, is left for manual review.
ACTIONABLE_CONFIDENCE = ("high", "medium")
DEAD_STATUSES = ("invalid", "revoked")
# 1 = validated live, 2 = high confidence, 3 = medium confidence, 4 = review tier.
REVIEW_PRIORITY = 4
STATUS_ORDER = ("pwned", "review", "error", "clean")

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

# Each scan of a project writes its own report, secrets_<name><suffix>.json.
REPORT_SOURCES = (("repo", ""), ("wiki", ".wiki"), ("gitlab", ".gitlab"))

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


def wiki_name(name):
    return f"{name}.wiki"


def gitlab_name(name):
    return f"{name}.gitlab"


def report_targets(name):
    """(source, target name) for every report a project's scans can write."""
    return [(source, f"{name}{suffix}") for source, suffix in REPORT_SOURCES]


def wiki_url(ssh_url_to_repo):
    base = ssh_url_to_repo[:-4] if ssh_url_to_repo.endswith(".git") else ssh_url_to_repo
    return f"{base}.wiki.git"


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


def clone_wiki(ssh_url_to_repo, name):
    """Clones a project's wiki to repositories/<name>.wiki. Returns False,
    without raising, if the project has no wiki or the wiki has no pages."""
    wiki = wiki_name(name)
    try:
        clone(wiki_url(ssh_url_to_repo), wiki)
    except subprocess.CalledProcessError as exc:
        log.debug("No wiki cloned for %s: %s", name, _last_line(exc.stderr))
        remove_repo(wiki)
        return False
    except subprocess.TimeoutExpired:
        log.warning("Wiki clone timed out for %s after %ds, skipping it", name, GIT_CLONE_TIMEOUT_S)
        remove_repo(wiki)
        return False
    has_pages = (
        subprocess.run(
            ["git", "-C", repo_path(wiki), "rev-parse", "-q", "--verify", "HEAD"],
            capture_output=True,
            text=True,
            timeout=GIT_CLONE_TIMEOUT_S,
        ).returncode
        == 0
    )
    if not has_pages:
        remove_repo(wiki)
    return has_pages


def fetch_extra_refs(name):
    """Fetches GitLab merge-request heads and git notes so they get scanned too.

    Raises CalledProcessError or subprocess.TimeoutExpired on failure.
    """
    subprocess.run(
        [
            "git",
            "-C",
            repo_path(name),
            "fetch",
            "--quiet",
            "origin",
            MERGE_REQUEST_REFSPEC,
            NOTES_REFSPEC,
        ],
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


def scan_flags(name, validate):
    """Flags shared by every betterleaks scan writing report_path(name)."""
    flags = [
        "--config",
        BETTERLEAKS_CONFIG,
        "--ignore-file",
        BETTERLEAKS_IGNORE_FILE,
        "--no-allow-signatures",
        "--exit-code",
        str(LEAKS_EXIT_CODE),
        "--max-archive-depth",
        str(ARCHIVE_DEPTH),
        "--max-decode-depth",
        str(DECODE_DEPTH),
        "--output",
        report_path(name),
        "--silent",
        "--no-banner",
        "--log-level",
        "error",
    ]
    if validate:
        flags += ["--validate", "--status", VALIDATE_KEEP_STATUSES]
    return flags


def betterleaks_command(name, mode, validate=False):
    include = FULL_MODE_INCLUDE if mode == "full" else QUICK_MODE_INCLUDE
    return [
        BETTERLEAKS_BIN,
        "git",
        # The .git dir, not the worktree: betterleaks resolves a worktree path
        # to its enclosing repository and ignores GIT_CEILING_DIRECTORIES, so a
        # clone missing its .git would get whatever repo encloses it scanned.
        os.path.join(repo_path(name), ".git"),
        "--platform",
        "gitlab",
        f"--include={include}",
        *scan_flags(name, validate),
    ]


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


def gitlab_resources_command(name, web_url, validate=False):
    command = [
        BETTERLEAKS_BIN,
        "gitlab",
        web_url,
        f"--include={GITLAB_RESOURCES_INCLUDE}",
        f"--exclude={GITLAB_RESOURCES_EXCLUDE}",
    ]
    if os.environ.get("GIT_ENDPOINT"):
        command += ["--base-url", os.environ["GIT_ENDPOINT"]]
    return command + scan_flags(gitlab_name(name), validate)


def gitlab_resources_check(name, web_url, validate=False):
    """Scans a project's issues, merge requests, snippets, releases and CI job
    logs through the GitLab API. The token goes through the environment
    (GITLAB_TOKEN), never argv, so it can't show up in process listings."""
    return subprocess.run(
        gitlab_resources_command(name, web_url, validate),
        capture_output=True,
        text=True,
        timeout=BETTERLEAKS_TIMEOUT_S,
        env={**os.environ, "GITLAB_TOKEN": os.environ.get("GIT_PRIVATE_TOKEN", "")},
    )


def mask(value):
    """Keeps the first (100 - REDACT_PERCENT)% of value, like betterleaks --redact."""
    return value[: len(value) * (100 - REDACT_PERCENT) // 100] + "..."


def mask_within(text, secrets):
    """Masks each secret where it occurs in text, or all of text if none does."""
    present = [secret for secret in secrets if secret in text]
    if not present:
        return mask(text)
    for secret in present:
        text = text.replace(secret, mask(secret))
    return text


def match_secrets(match):
    values = [match.get("value")] + list((match.get("captures") or {}).values())
    return [value for value in values if isinstance(value, str) and value]


def redact_match(match, secrets):
    for field in ("full", "line", "context"):
        if isinstance(match.get(field), str) and match[field]:
            match[field] = mask_within(match[field], secrets)
    if isinstance(match.get("value"), str) and match["value"]:
        match["value"] = mask(match["value"])
    captures = match.get("captures")
    if isinstance(captures, dict):
        match["captures"] = {
            key: mask(value) if isinstance(value, str) else value
            for key, value in captures.items()
        }


def finding_components(finding):
    return [
        component
        for component_set in finding.get("component_sets") or []
        for component in component_set.get("components") or []
    ]


def redact_finding(finding):
    """Masks a finding's secret values and its components' in place. Paths and
    fingerprints are left alone; attributes (e.g. a commit message quoting the
    secret) only lose the full secret values they contain."""
    matches = [finding.get("match") or {}]
    matches += [component.get("match") or {} for component in finding_components(finding)]
    secrets = sorted({s for match in matches for s in match_secrets(match)}, key=len, reverse=True)
    for match in matches:
        redact_match(match, secrets)
    long_secrets = [s for s in secrets if len(s) >= REDACT_MIN_ATTRIBUTE_LENGTH]
    attributes = finding.get("attributes")
    if isinstance(attributes, dict):
        for key, value in attributes.items():
            if isinstance(value, str) and any(s in value for s in long_secrets):
                for secret in long_secrets:
                    value = value.replace(secret, mask(secret))
                attributes[key] = value


def discard_report(name):
    for path in (report_path(name), report_path(name) + ".tmp"):
        if os.path.lexists(path):
            os.remove(path)


def redact_report(name):
    """Rewrites a report with its secret values masked. On any failure the
    report is deleted, so no unredacted copy is left behind, and the error re-raised."""
    path = report_path(name)
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as report_file:
            report = json.load(report_file)
        for finding in report.get("findings") or []:
            redact_finding(finding)
        with open(path + ".tmp", "w", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=1)
        os.replace(path + ".tmp", path)
    except BaseException:
        discard_report(name)
        raise


def run_scan(name, check):
    """Runs check() (a betterleaks scan writing report_path(name)) and redacts
    its report straight away. A scan that fails or times out has its possibly
    partial, unredacted report deleted."""
    try:
        result = check()
    except BaseException:
        discard_report(name)
        raise
    redact_report(name)
    return result


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


def scan_succeeded(name, result):
    """True if a scan finished, found or not found leaks, and logged no error."""
    if not report_complete(name):
        log.error("betterleaks scan of %s was incomplete: %s", name, _last_line(result.stderr))
        return False
    if result.returncode == LEAKS_EXIT_CODE:
        return True
    if result.returncode == 0 and not result.stderr.strip():
        return True
    # Exit 0 with error output means betterleaks swallowed a failure (e.g. git
    # erroring out), so the "no leaks" result can't be trusted.
    log.error(
        "betterleaks exited %s on %s: %s", result.returncode, name, _last_line(result.stderr)
    )
    return False


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


def finding_priority(finding):
    """1 = validated live, 2 = high confidence, 3 = medium, 4 = review tier."""
    if finding_status(finding) == "valid":
        return 1
    if finding_tier(finding) == "review":
        return REVIEW_PRIORITY
    return 2 if finding.get("confidence") == "high" else 3


def report_findings(name):
    """Yields (source, finding) from every report of a project."""
    for source, target in report_targets(name):
        try:
            with open(report_path(target), "r", encoding="utf-8") as report_file:
                report = json.load(report_file)
        except (FileNotFoundError, json.JSONDecodeError):
            continue
        if isinstance(report, dict):
            for finding in report.get("findings") or []:
                yield source, finding


def triage_report(name):
    """Reads a project's reports and returns {"actionable": [...], "review": [...]},
    one entry per unique secret (match.fingerprint), each list sorted by
    priority then rule_id. An entry takes the best priority of its occurrences,
    and a secret also reported as a component of another finding (an AWS secret
    key next to its key ID) is folded into that finding. Values in the reports
    are already redacted."""
    entries = {}
    component_owner = {}
    for source, finding in report_findings(name):
        match = finding.get("match") or {}
        key = match.get("fingerprint") or (finding.get("rule_id"), match.get("value"))
        priority = finding_priority(finding)
        components = [
            {"rule_id": component.get("rule_id"), "fingerprint": fingerprint}
            for component in finding_components(finding)
            if (fingerprint := (component.get("match") or {}).get("fingerprint"))
        ]
        entry = entries.get(key)
        if entry is None or priority < entry["priority"]:
            location = finding.get("location") or {}
            entries[key] = {
                "rule_id": finding.get("rule_id"),
                "confidence": finding.get("confidence"),
                "status": finding_status(finding),
                "priority": priority,
                "source": source,
                "path": location.get("path"),
                "line": location.get("start_line"),
                "commit": (finding.get("attributes") or {}).get("git.sha"),
                "occurrences": entry["occurrences"] if entry else 0,
                "fingerprint": match.get("fingerprint"),
                "components": entry["components"] if entry else [],
            }
            entry = entries[key]
        entry["occurrences"] += 1
        for component in components:
            component_owner.setdefault(component["fingerprint"], key)
            if component not in entry["components"]:
                entry["components"].append(component)

    for key in list(entries):
        owner = component_owner.get(key)
        if owner != key and owner in entries:
            folded = entries.pop(key)
            entries[owner]["priority"] = min(entries[owner]["priority"], folded["priority"])

    triage = {"actionable": [], "review": []}
    for entry in sorted(entries.values(), key=lambda e: (e["priority"], e["rule_id"] or "")):
        tier = "review" if entry["priority"] == REVIEW_PRIORITY else "actionable"
        triage[tier].append(entry)
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


def organize(project, mode="quick", validate=False, gitlab_resources=False):
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

    results = []
    failed = False
    try:
        if not os.path.isdir(os.path.join(repo_path(name), ".git")):
            log.error("Clone of %s has no .git directory, not scanning it", name)
            return name, "error"
        remove_scan_overrides(name)
        targets = [name]
        if mode == "full":
            try:
                fetch_extra_refs(name)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
                log.warning(
                    "Could not fetch merge-request/notes refs for %s, scanning without them: %s",
                    name,
                    _last_line(getattr(exc, "stderr", "")) or type(exc).__name__,
                )
            if clone_wiki(ssh_url_to_repo, name):
                remove_scan_overrides(wiki_name(name))
                targets.append(wiki_name(name))
        scans = [
            (target, functools.partial(betterleaks_check, target, mode, validate))
            for target in targets
        ]
        if gitlab_resources:
            check = functools.partial(
                gitlab_resources_check, name, project["http_url"], validate
            )
            scans.append((gitlab_name(name), check))
        for target, check in scans:
            result = run_scan(target, check)
            results.append(result)
            failed |= not scan_succeeded(target, result)
            drop_empty_report(target)
    except subprocess.TimeoutExpired:
        log.error("betterleaks timed out for %s after %ds", name, BETTERLEAKS_TIMEOUT_S)
        failed = True
    except Exception:  # pylint: disable=broad-except
        log.exception("Scan failed for %s", name)
        failed = True
    finally:
        remove_repo(name)
        remove_repo(wiki_name(name))

    triage = triage_report(name)
    leaks = any(result.returncode == LEAKS_EXIT_CODE for result in results)
    # An unreadable report still counts as pwned, and a failed or incomplete
    # scan with only review-tier findings is an error: it may have missed
    # actionable ones.
    if leaks and (triage["actionable"] or not triage["review"]):
        return name, "pwned"
    if failed:
        return name, "error"
    if leaks:
        return name, "review"
    return name, "clean"


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
        help="quick: all branches and tags, commit/tag messages and archives. full: also "
        "merge-request refs, git notes, merge commits and the project wiki (slower). "
        "(default: %(default)s)",
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
        default=bool_env("GITSCRAPPER_VALIDATE"),
        help="check findings against provider APIs and drop only those confirmed "
        "invalid or revoked; sends each candidate secret to its provider "
        "(also set by GITSCRAPPER_VALIDATE=1)",
    )
    parser.add_argument(
        "--gitlab-resources",
        action="store_true",
        default=bool_env("GITSCRAPPER_GITLAB_RESOURCES"),
        help="also scan each project's issues, merge requests, snippets, releases and CI "
        "job logs through the GitLab API (also set by GITSCRAPPER_GITLAB_RESOURCES=1)",
    )
    return parser.parse_args(argv)


def check_scan_setup():
    """Exits with a clear error if betterleaks is missing, is v1, or its
    pinned config is invalid, or if the config or ignore file is missing."""
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

    version = subprocess.run(
        [BETTERLEAKS_BIN, "version"], capture_output=True, text=True, timeout=60
    )
    reported = _last_line(version.stdout) or _last_line(version.stderr)
    if version.returncode != 0 or re.match(r"v?1\.", reported):
        log.error(
            "betterleaks %r reports version %r; gitscrapper needs betterleaks v2.",
            BETTERLEAKS_BIN,
            reported,
        )
        sys.exit(1)
    # Source builds report "dev", which also skips the config's minVersion check.
    if reported == "dev":
        log.warning(
            "betterleaks %r reports version 'dev', so it can't be confirmed as v2.",
            BETTERLEAKS_BIN,
        )
    config_check = subprocess.run(
        [BETTERLEAKS_BIN, "config", "check", "--config", BETTERLEAKS_CONFIG],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if config_check.returncode != 0:
        log.error(
            "betterleaks config %r is invalid: %s",
            BETTERLEAKS_CONFIG,
            _last_line(config_check.stderr) or _last_line(config_check.stdout),
        )
        sys.exit(1)


def summary_order(entry):
    top_priority = entry["top_priority"] or REVIEW_PRIORITY + 1
    return (STATUS_ORDER.index(entry["status"]), top_priority, -entry["actionable"], entry["name"])


def write_summary(projects, statuses):
    """Writes the per-bucket name lists, the confirmed (validated live) list, and
    a JSON index tying each repo to its URL, status, reports and deduplicated,
    triaged findings, most urgent repos first."""
    for label in STATUS_ORDER:
        names = [p["name"] for p in projects if statuses.get(p["name"]) == label]
        path = f"{LEAKS_REPORTS_DIR}/{today_frmt}_{label}_repos.txt"
        with open(path, "w", encoding="utf-8") as fp:
            fp.write("\n".join(names) + "\n" if names else "")

    summary = []
    for project in projects:
        name = project["name"]
        triage = triage_report(name)
        entries = triage["actionable"] + triage["review"]
        summary.append(
            {
                "name": name,
                "url": project["http_url"],
                "status": statuses.get(name, "error"),
                "reports": [
                    report_path(target)
                    for _, target in report_targets(name)
                    if os.path.exists(report_path(target))
                ],
                "unique_secrets": len(entries),
                "actionable": len(triage["actionable"]),
                "review": len(triage["review"]),
                "confirmed": sum(1 for entry in entries if entry["priority"] == 1),
                "top_priority": min((entry["priority"] for entry in entries), default=None),
                "triage": triage,
            }
        )
    summary.sort(key=summary_order)
    confirmed = [entry["name"] for entry in summary if entry["confirmed"]]
    with open(f"{LEAKS_REPORTS_DIR}/{today_frmt}_confirmed_repos.txt", "w", encoding="utf-8") as fp:
        fp.write("\n".join(confirmed) + "\n" if confirmed else "")
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
        "Found %d project(s) to scan in %s mode%s%s",
        total,
        args.mode,
        " with validation" if args.validate else "",
        " and GitLab resources" if args.gitlab_resources else "",
    )

    if args.dry_run:
        for project in projects:
            log.info("[dry-run] would scan %s", project["name"])
        return

    start = time.monotonic()
    statuses = {}
    counts = {"clean": 0, "review": 0, "pwned": 0, "error": 0}
    progress_every = max(1, total // 20)  # ~5% increments
    scan = functools.partial(
        organize, mode=args.mode, validate=args.validate, gitlab_resources=args.gitlab_resources
    )
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
    if counts["pwned"] and not args.validate:
        log.info(
            "Hint: re-run with --validate to confirm which pwned findings are live "
            "(sends each candidate secret to its provider)."
        )


if __name__ == "__main__":
    main()
