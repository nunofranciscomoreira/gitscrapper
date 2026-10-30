#!/usr/bin/python3
"""List all GitLab projects and run gitleaks against each of them.

Before running:
    - create the "repositories" and "leaks_reports" folders
    - export GIT_ENDPOINT   (e.g. https://gitlab.example.com)
    - export GIT_PRIVATE_TOKEN
    - optionally export GITLEAKS_BIN (defaults to "gitleaks" on PATH)
"""
import json
import logging
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import date

import gitlab

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("gitscrapper")

GITLEAKS_BIN = os.environ.get("GITLEAKS_BIN", shutil.which("gitleaks") or "gitleaks")

today = date.today()
today_frmt = today.strftime("%b-%d-%Y")


def clone(ssh_url_to_repo, name):
    """Clones a repository to the machine. Raises CalledProcessError on failure."""
    dest = f"repositories/{name}"
    subprocess.run(
        ["git", "clone", ssh_url_to_repo, dest],
        check=True,
        capture_output=True,
        text=True,
    )


def gitleak_check(name):
    """Runs gitleaks against a cloned repository.

    gitleaks exits 0 when no leaks are found and 1 when leaks are found;
    any other exit code indicates a real tool error. Returns the exit code
    so the caller can distinguish these three cases.
    """
    report_path = f"leaks_reports/secrets_{name}.json"
    result = subprocess.run(
        [
            GITLEAKS_BIN,
            "detect",
            "-s",
            f"repositories/{name}",
            "--report-path",
            report_path,
        ],
        capture_output=True,
        text=True,
    )
    return result.returncode


def append_link(name, http_link):
    """Adds the repository's web URL to its json report, dropping empty reports."""
    report_path = f"leaks_reports/secrets_{name}.json"
    try:
        with open(report_path, "r", encoding="utf-8") as report_file:
            findings = json.load(report_file)
    except FileNotFoundError:
        return
    except json.JSONDecodeError:
        log.warning("Could not parse report for %s, leaving it as-is", name)
        return

    if not findings:
        os.remove(report_path)
        return

    findings.insert(0, {"RepoUrl": http_link})
    with open(report_path, "w", encoding="utf-8") as report_file:
        json.dump(findings, report_file, indent=2)


def remove_repo(name):
    """Deletes a cloned repository from the machine."""
    shutil.rmtree(f"repositories/{name}", ignore_errors=True)


def organize(project):
    """Clones, scans and cleans up a single project. Returns (name, status)
    where status is "clean", "pwned" or "error". Never raises: any failure
    is logged and reported as "error" so one bad repo can't abort the run
    or skip cleanup for the others running concurrently.
    """
    name = project["name"]
    ssh_url_to_repo = project["ssh_url"]
    http_link = project["http_url"]

    try:
        clone(ssh_url_to_repo, name)
    except subprocess.CalledProcessError as exc:
        log.error("Clone failed for %s: %s", name, exc.stderr.strip())
        remove_repo(name)
        return name, "error"

    try:
        returncode = gitleak_check(name)
        append_link(name, http_link)
    except Exception:  # pylint: disable=broad-except
        log.exception("Scan failed for %s", name)
        returncode = None
    finally:
        remove_repo(name)

    if returncode == 0:
        return name, "clean"
    if returncode == 1:
        return name, "pwned"
    log.error("gitleaks exited %s on %s", returncode, name)
    return name, "error"


def main():
    git_endpoint = os.environ["GIT_ENDPOINT"]
    git_private_token = os.environ["GIT_PRIVATE_TOKEN"]

    gl = gitlab.Gitlab(url=git_endpoint, private_token=git_private_token)
    gl.auth()
    git_projects = gl.projects.list(get_all=True)  # returns all projects, can take a while
    projects = [
        {
            # project.id is unique instance-wide; the repo's own name is kept
            # in the prefix only for readability, since two projects in
            # different namespaces (e.g. teamA/backend, teamB/backend) can
            # otherwise share the same last path segment and collide on
            # repositories/<name> and leaks_reports/secrets_<name>.json.
            "name": f"{project.path}-{project.id}",
            "ssh_url": project.ssh_url_to_repo,
            "http_url": project.web_url,
        }
        for project in git_projects
    ]

    pwned, clean, errored = [], [], []
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as pool:
        for name, status in pool.map(organize, projects):
            {"clean": clean, "pwned": pwned, "error": errored}[status].append(name)

    with open(f"leaks_reports/{today_frmt}_pwned_repos.txt", "w", encoding="utf-8") as fp:
        fp.write("\n".join(pwned) + "\n" if pwned else "")
    with open(f"leaks_reports/{today_frmt}_clean_repos.txt", "w", encoding="utf-8") as fp:
        fp.write("\n".join(clean) + "\n" if clean else "")

    log.info(
        "Scan done! clean=%d pwned=%d error=%d", len(clean), len(pwned), len(errored)
    )
    if errored:
        log.warning("Repos that errored out: %s", ", ".join(errored))


if __name__ == "__main__":
    main()
