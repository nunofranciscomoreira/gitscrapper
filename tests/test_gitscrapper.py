import json
import os
import shutil
import subprocess
import zipfile

import pytest

import gitscrapper as g

FIXTURES_DIR = os.path.join(g.SCRIPT_DIR, "test_fixtures")
AWS_KEY = "AKIAZ7EXAMPLE3QWERTY"

needs_gitleaks = pytest.mark.skipif(
    shutil.which(g.GITLEAKS_BIN) is None, reason="gitleaks is not installed"
)

# Fixtures gitleaks.toml (default rules + the custom rules we added for the
# formats the default rules missed) detects. A change in either set means the
# rules changed and this baseline should be reviewed.
EXPECTED_DETECTED = {
    "Adrafruit_IO_API_key.txt",
    "adobe_api_keys.txt",
    "agora_api_keys.txt",
    "airtable_apikey.txt",
    "aiven_api_key.txt",
    "akamai_api_credentials.txt",
    "alchemy_apikey.txt",
    "algolia_keys.txt",
    "alibaba_cloud_keys.txt",
    "amazon_mws_token.txt",
    "amqp_credentials.txt",
    "anypoint_keys.txt",
    "artifactory_token.txt",
    "asana_access_token.txt",
    "atlassian_oauth2.txt",
    "auth0_keys.txt",
    "aws_iam.txt",
    "aws_ses_keys.txt",
    "azure_active_directory_api_keys.txt",
    "azure_cosmosdb_credentials.txt",
    "azure_devops_personal_access_token.txt",
    "azure_service_management_certificate.txt",
    "azure_subscription_key.txt",
    "base64_aws_iam.txt",
    "beamer_apikey.txt",
    "bearer_token.txt",
    "bitbucket_keys.txt",
    "bitfinex_keys.txt",
    "buildkite_agent_token.txt",
    "buildkite_api_token.txt",
    "carto_jwt.txt",
    "checkout_secret_key.txt",
    "private_key.pem",
}
# aws.txt embeds "fake" in its values (ASIIAMFAKE...), matching the stopword
# both gitleaks' own generic-api-key allowlist and our aws-credentials-generic
# rule use to skip obvious placeholders. Treated as an intentional decoy, not
# a detection gap.
EXPECTED_MISSED = {"aws.txt"}


def git(cwd, *args):
    result = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def write_files(root, files):
    for relpath, content in files.items():
        path = os.path.join(root, relpath)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(path, mode) as fp:
            fp.write(content)


def make_repo(path, files):
    os.makedirs(path)
    git(path, "init", "-q", "-b", "main")
    write_files(path, files)
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "init")
    return path


def private_key():
    with open(os.path.join(FIXTURES_DIR, "private_key.pem"), encoding="utf-8") as fp:
        return fp.read()


def load_report(name):
    with open(g.report_path(name), encoding="utf-8") as fp:
        return json.load(fp)


def project(name, url):
    return {"name": name, "ssh_url": url, "http_url": f"https://gitlab.example.com/{name}"}


@pytest.fixture(autouse=True)
def workdir(tmp_path, monkeypatch):
    """Runs every test from an empty directory with an isolated git config."""
    run_dir = os.path.realpath(tmp_path / "run")
    os.makedirs(os.path.join(run_dir, g.REPOSITORIES_DIR))
    os.makedirs(os.path.join(run_dir, g.LEAKS_REPORTS_DIR))
    empty_config = tmp_path / "gitconfig"
    empty_config.write_text("")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty_config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    for var in ("GIT_AUTHOR_NAME", "GIT_COMMITTER_NAME"):
        monkeypatch.setenv(var, "test")
    for var in ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"):
        monkeypatch.setenv(var, "test@example.com")
    monkeypatch.setattr(g.time, "sleep", lambda _: None)
    monkeypatch.chdir(run_dir)
    return tmp_path


# --- unit tests --------------------------------------------------------------


@pytest.mark.parametrize(
    "name, safe",
    [
        ("backend-42", True),
        ("a/b-1", False),
        ("a\\b-1", False),
        ("..-1", False),
        ("", False),
    ],
)
def test_is_safe_name(name, safe):
    assert g.is_safe_name(name) is safe


@pytest.mark.parametrize("value", ["0", "-3", "abc", "1.5"])
def test_positive_int_rejects(value):
    with pytest.raises(Exception):
        g.positive_int(value)


def test_positive_int_env_exits_on_garbage(monkeypatch):
    monkeypatch.setenv("SOME_TIMEOUT", "soon")
    with pytest.raises(SystemExit):
        g.positive_int_env("SOME_TIMEOUT", 5)


def test_parse_args_defaults_to_quick_and_rejects_zero_workers():
    assert g.parse_args([]).mode == "quick"
    assert g.parse_args(["--mode", "full"]).mode == "full"
    with pytest.raises(SystemExit):
        g.parse_args(["--workers", "0"])


def test_gitleaks_command_pins_config_and_overrides():
    command = g.gitleaks_command("repo-1", "quick")
    assert command[1:3] == ["git", "repositories/repo-1"]
    assert command[command.index("--config") + 1] == g.GITLEAKS_CONFIG
    assert command[command.index("--gitleaks-ignore-path") + 1] == g.GITLEAKS_IGNORE_DIR
    assert "--ignore-gitleaks-allow" in command
    assert command[command.index("--exit-code") + 1] == str(g.LEAKS_EXIT_CODE)
    assert f"--redact={g.REDACT_PERCENT}" in command
    assert "--max-archive-depth" not in command
    assert "--max-decode-depth" not in command


def test_gitleaks_command_full_mode_opens_archives_and_pins_decode_depth():
    command = g.gitleaks_command("repo-1", "full")
    assert command[command.index("--max-archive-depth") + 1] == str(g.FULL_MODE_ARCHIVE_DEPTH)
    assert command[command.index("--max-decode-depth") + 1] == str(g.FULL_MODE_DECODE_DEPTH)


def fake_clone(ssh_url_to_repo, name):
    os.makedirs(os.path.join(g.repo_path(name), ".git"))


@pytest.mark.parametrize(
    "returncode, stderr, status",
    [
        (0, "", "clean"),
        (g.LEAKS_EXIT_CODE, "", "pwned"),
        (1, "FTL unable to load gitleaks config", "error"),
        (0, "ERR [git] fatal: bad object", "error"),
    ],
)
def test_organize_classifies_gitleaks_result(monkeypatch, returncode, stderr, status):
    monkeypatch.setattr(g, "clone", fake_clone)
    monkeypatch.setattr(
        g,
        "gitleak_check",
        lambda name, mode: subprocess.CompletedProcess([], returncode, "", stderr),
    )
    assert g.organize(project("repo-1", "unused")) == ("repo-1", status)
    assert not os.path.exists(g.repo_path("repo-1"))


def test_organize_retries_clone_then_errors(monkeypatch):
    calls = []

    def failing_clone(ssh_url_to_repo, name):
        calls.append(name)
        raise subprocess.CalledProcessError(128, "git", stderr="connection reset")

    monkeypatch.setattr(g, "clone", failing_clone)
    assert g.organize(project("repo-1", "unused")) == ("repo-1", "error")
    assert len(calls) == g.CLONE_RETRIES + 1


def test_organize_clone_timeout_is_error(monkeypatch):
    def slow_clone(ssh_url_to_repo, name):
        raise subprocess.TimeoutExpired("git", 1)

    monkeypatch.setattr(g, "clone", slow_clone)
    assert g.organize(project("repo-1", "unused")) == ("repo-1", "error")


def test_organize_gitleaks_timeout_is_error_and_cleans_up(monkeypatch):
    def slow_scan(name, mode):
        raise subprocess.TimeoutExpired("gitleaks", 1)

    monkeypatch.setattr(g, "clone", fake_clone)
    monkeypatch.setattr(g, "gitleak_check", slow_scan)
    assert g.organize(project("repo-1", "unused")) == ("repo-1", "error")
    assert not os.path.exists(g.repo_path("repo-1"))


def test_organize_refuses_clone_without_git_dir(monkeypatch):
    monkeypatch.setattr(g, "clone", lambda url, name: os.makedirs(g.repo_path(name)))
    monkeypatch.setattr(g, "gitleak_check", lambda name, mode: pytest.fail("scanned"))
    assert g.organize(project("repo-1", "unused")) == ("repo-1", "error")


def test_full_mode_scans_even_if_merge_request_fetch_fails(monkeypatch):
    def failing_fetch(name):
        raise subprocess.CalledProcessError(1, "git", stderr="refs not allowed")

    monkeypatch.setattr(g, "clone", fake_clone)
    monkeypatch.setattr(g, "fetch_merge_request_refs", failing_fetch)
    monkeypatch.setattr(
        g, "gitleak_check", lambda name, mode: subprocess.CompletedProcess([], 0, "", "")
    )
    assert g.organize(project("repo-1", "unused"), mode="full") == ("repo-1", "clean")


def test_drop_empty_report():
    write_files(".", {g.report_path("empty-1"): "[]", g.report_path("full-2"): '[{"a": 1}]'})
    g.drop_empty_report("empty-1")
    g.drop_empty_report("full-2")
    assert not os.path.exists(g.report_path("empty-1"))
    assert load_report("full-2") == [{"a": 1}]


def test_write_summary():
    projects = [project("a-1", "u"), project("b-2", "u"), project("c-3", "u")]
    write_files(".", {g.report_path("b-2"): '[{"RuleID": "x"}]'})
    g.write_summary(projects, {"a-1": "clean", "b-2": "pwned", "c-3": "error"})

    with open(f"{g.LEAKS_REPORTS_DIR}/{g.today_frmt}_summary.json", encoding="utf-8") as fp:
        summary = {entry["name"]: entry for entry in json.load(fp)}
    assert summary["b-2"] == {
        "name": "b-2",
        "url": "https://gitlab.example.com/b-2",
        "status": "pwned",
        "report": g.report_path("b-2"),
    }
    assert summary["a-1"]["report"] is None
    with open(f"{g.LEAKS_REPORTS_DIR}/{g.today_frmt}_error_repos.txt", encoding="utf-8") as fp:
        assert fp.read() == "c-3\n"


# --- integration tests (real git + gitleaks) ---------------------------------


@needs_gitleaks
def test_repo_cannot_silence_its_own_scan(workdir):
    src = make_repo(
        str(workdir / "src"),
        {
            "k.pem": private_key(),
            "allowed.txt": f"aws_access_key_id = {AWS_KEY} # gitleaks:allow\n",
            ".gitleaks.toml": '[extend]\nuseDefault = false\n[[rules]]\nid = "noop"\n'
            'regex = "zzzz_never_matches"\n',
        },
    )
    # Ignore every real finding by fingerprint, as a repo owner could.
    scan = subprocess.run(
        [g.GITLEAKS_BIN, "git", src, "-c", g.GITLEAKS_CONFIG, "--ignore-gitleaks-allow",
         "--report-format", "json", "--report-path", "-", "--no-banner", "-l", "error"],
        capture_output=True,
        text=True,
    )
    fingerprints = [finding["Fingerprint"] for finding in json.loads(scan.stdout)]
    assert len(fingerprints) == 3
    write_files(src, {".gitleaksignore": "\n".join(fingerprints) + "\n"})
    git(src, "add", "-A")
    git(src, "commit", "-q", "-m", "hide findings")

    assert g.organize(project("hostile-1", src)) == ("hostile-1", "pwned")
    report = load_report("hostile-1")
    assert {finding["RuleID"] for finding in report} == {
        "private-key",
        "aws-access-token",
        "aws-credentials-generic",
    }
    assert AWS_KEY not in json.dumps(report)


@needs_gitleaks
def test_full_mode_finds_secrets_inside_archives(workdir):
    archive = workdir / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("config/key.pem", private_key())
    src = make_repo(str(workdir / "src"), {"bundle.zip": archive.read_bytes()})

    assert g.organize(project("zip-1", src), mode="quick") == ("zip-1", "clean")
    assert g.organize(project("zip-1", src), mode="full") == ("zip-1", "pwned")
    assert any("!" in finding["File"] for finding in load_report("zip-1"))


@needs_gitleaks
def test_full_mode_scans_merge_request_refs(workdir):
    src = make_repo(str(workdir / "src"), {"README.md": "hello\n"})
    git(src, "checkout", "-q", "-b", "feature")
    write_files(src, {"k.pem": private_key()})
    git(src, "add", "-A")
    git(src, "commit", "-q", "-m", "oops")
    git(src, "update-ref", "refs/merge-requests/1/head", git(src, "rev-parse", "HEAD"))
    git(src, "checkout", "-q", "main")
    git(src, "branch", "-q", "-D", "feature")

    assert g.organize(project("mr-1", src), mode="quick") == ("mr-1", "clean")
    assert g.organize(project("mr-1", src), mode="full") == ("mr-1", "pwned")


@needs_gitleaks
def test_scan_does_not_escape_into_enclosing_repo():
    # The run directory itself is a repo with a leak; a clone missing its
    # .git must not cause gitleaks to scan this enclosing history instead.
    git(".", "init", "-q", "-b", "main")
    write_files(".", {"k.pem": private_key()})
    git(".", "add", "k.pem")
    git(".", "commit", "-q", "-m", "leak")
    os.makedirs(g.repo_path("broken-1"))

    result = g.gitleak_check("broken-1", "quick")
    assert result.returncode != g.LEAKS_EXIT_CODE
    assert not os.path.exists(g.report_path("broken-1")) or load_report("broken-1") == []


@needs_gitleaks
def test_fixture_detection_baseline(workdir):
    assert set(os.listdir(FIXTURES_DIR)) == EXPECTED_DETECTED | EXPECTED_MISSED
    dest = g.repo_path("fixtures-0")
    shutil.copytree(FIXTURES_DIR, dest)
    git(dest, "init", "-q", "-b", "main")
    git(dest, "add", "-A")
    git(dest, "commit", "-q", "-m", "fixtures")

    result = g.gitleak_check("fixtures-0", "quick")
    assert result.returncode == g.LEAKS_EXIT_CODE, result.stderr
    detected = {os.path.basename(finding["File"]) for finding in load_report("fixtures-0")}
    assert detected == EXPECTED_DETECTED, (
        f"newly missed: {sorted(EXPECTED_DETECTED - detected)}, "
        f"newly detected: {sorted(detected - EXPECTED_DETECTED)}"
    )
