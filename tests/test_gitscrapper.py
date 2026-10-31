import json
import os
import shutil
import subprocess
import zipfile

import pytest

import gitscrapper as g

FIXTURES_DIR = os.path.join(g.SCRIPT_DIR, "test_fixtures")
AWS_KEY = "AKIAZ7EXAMPLE3QWERTY"

needs_betterleaks = pytest.mark.skipif(
    shutil.which(g.BETTERLEAKS_BIN) is None, reason="betterleaks is not installed"
)

# Fixtures betterleaks.toml (default rules + the custom rules we added for the
# formats the default rules miss) detects. A change in either set means the
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
# aws.txt embeds "fake" in its values (ASIIAMFAKE...) and its key ID isn't a
# valid AWS prefix, so neither the default aws-access-token rule nor
# generic-api-key's placeholder filters report it. Treated as an intentional
# decoy, not a detection gap.
EXPECTED_MISSED = {"aws.txt"}

# Labeled benchmark corpora. Every file in NEGATIVE_DIR is false-positive bait
# and must produce no finding. Every file in HARD_DIR must surface the secret
# values listed in HARD_EXPECTED, as a finding or as a component of one.
# deleted_* files are committed and then removed; branch_* files only exist on
# a non-default branch.
NEGATIVE_DIR = os.path.join(g.SCRIPT_DIR, "test_fixtures_negative")
HARD_DIR = os.path.join(g.SCRIPT_DIR, "test_fixtures_hard")
# Sample credentials in tests, examples and docs that generic rules report:
# every file must be detected, and only ever in the review tier.
REVIEW_DIR = os.path.join(g.SCRIPT_DIR, "test_fixtures_review")
HARD_EXPECTED = {
    "multiline.json": {"sk_live_KTfg0EpeZ6FzFLd5jpffAVQ7"},
    "nested.yaml": {"AKIAXUIMYLEMFST2LSXP", "/KLHpxFReOKq5qPtGwlgYefVLFmFrmiovr/CY7Mz"},
    "quoted.env": {"bzhIfbgNk@GYUgsL"},
    "web.config": {"PsgQsNhpTL0hZn0Vc96l2tKaVPcDSHkJCBSCxZNR"},
    "url.txt": {"wL1M0F3F2kzEq8Vr"},
    "k8s_secret.yaml": {"xoxb-51136943514-948438804521-c9USN1xEDjv0acy1sS1xTZBf"},
    "deleted_github_token.txt": {"ghp_IoJv3AcUYHL2qOrhvsAjQjkfbsjRw6VCIA7u"},
    "branch_gitlab_token.txt": {"glpat-lh9RY-xEMWtxa6jxH9zq"},
    "zero_run.env": {
        "sk_live_4eC39HqLyjWDa00000000rjtT1zdp7dc",
        "https://hooks.slack.com/services/T0A1B2C3D/B00000000/Xk9mQ2vR7pL4sT8wZ1nY6bH3",
    },
    "dollar_brace.config": {"Vb8n${Wk2Lp7Zr9Tm4qX"},
}
# Positive files whose only findings come from low-confidence generic rules,
# so triage puts them in "review". Every other positive file is "actionable".
EXPECTED_REVIEW = {
    "Adrafruit_IO_API_key.txt",
    "adobe_api_keys.txt",
    "airtable_apikey.txt",
    "anypoint_keys.txt",
    "asana_access_token.txt",
    "atlassian_oauth2.txt",
    "auth0_keys.txt",
    "azure_cosmosdb_credentials.txt",
    "azure_subscription_key.txt",
    "beamer_apikey.txt",
    "bearer_token.txt",
    "bitfinex_keys.txt",
    "buildkite_agent_token.txt",
    "buildkite_api_token.txt",
}

# Placeholders, prose and low-entropy values that must not be reported.
DECOY_FILES = {
    "placeholders.env": (
        'API_KEY="YOUR_API_KEY_HERE"\n'
        "DB_PASSWORD=changeme\n"
        'GITHUB_TOKEN="<redacted>"\n'
        "AWS_ACCESS_KEY_ID=AKIAXXXXXXXXXXXXXXXX\n"
        "aws_secret_access_key = " + "x" * 40 + "\n"
        'client_secret = "' + "0" * 32 + '"\n'
        "STRIPE_SECRET=${STRIPE_SECRET}\n"
    ),
    "prose.md": (
        "Send the header `Authorization: Bearer your_token_here` with every request.\n"
        'Set api_key = "please_set_this_in_the_environment" before running.\n'
        'The secret = "this is not a real secret value"\n'
    ),
    "lowentropy.txt": (
        'token = "' + "a" * 30 + '"\n'
        'headers = {"Authorization": "Bearer ' + "ab" * 12 + '"}\n'
        "token=b_" + "a" * 36 + "\n"
        "asana 1/1111111111111111:" + "0" * 32 + "\n"
        "asana 1/1111111111111111:" + "ab" * 16 + "\n"
    ),
}


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


def load_findings(name):
    return load_report(name)["findings"]


def report_json(findings, state="complete"):
    return json.dumps({"schema_version": "1", "findings": findings, "scan": {"state": state}})


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


def test_parse_args_validate_from_flag_or_env(monkeypatch):
    monkeypatch.delenv("GITSCRAPPER_VALIDATE", raising=False)
    assert g.parse_args([]).validate is False
    assert g.parse_args(["--validate"]).validate is True
    monkeypatch.setenv("GITSCRAPPER_VALIDATE", "1")
    assert g.parse_args([]).validate is True


def test_parse_args_gitlab_resources_from_flag_or_env(monkeypatch):
    monkeypatch.delenv("GITSCRAPPER_GITLAB_RESOURCES", raising=False)
    assert g.parse_args([]).gitlab_resources is False
    assert g.parse_args(["--gitlab-resources"]).gitlab_resources is True
    monkeypatch.setenv("GITSCRAPPER_GITLAB_RESOURCES", "true")
    assert g.parse_args([]).gitlab_resources is True


def test_betterleaks_command_pins_config_and_overrides():
    command = g.betterleaks_command("repo-1", "quick")
    assert command[1:3] == ["git", "repositories/repo-1/.git"]
    assert command[command.index("--config") + 1] == g.BETTERLEAKS_CONFIG
    assert command[command.index("--ignore-file") + 1] == g.BETTERLEAKS_IGNORE_FILE
    assert "--no-allow-signatures" in command
    assert command[command.index("--exit-code") + 1] == str(g.LEAKS_EXIT_CODE)
    assert not any(arg.startswith("--redact") for arg in command)
    assert command[command.index("--output") + 1] == g.report_path("repo-1")
    assert "--silent" in command
    assert command[command.index("--max-archive-depth") + 1] == "2"
    assert command[command.index("--max-decode-depth") + 1] == "5"
    assert "--include=commit-messages,tag-messages" in command
    assert "--validate" not in command
    assert "--status" not in command


def test_betterleaks_command_full_mode_adds_merges_and_notes():
    command = g.betterleaks_command("repo-1", "full")
    assert command[command.index("--max-archive-depth") + 1] == "2"
    assert command[command.index("--max-decode-depth") + 1] == "5"
    assert "--include=merges,commit-messages,tag-messages,notes" in command


def test_gitlab_resources_check_passes_token_via_env_only(monkeypatch):
    monkeypatch.setenv("GIT_PRIVATE_TOKEN", "glpat-sekrit")
    monkeypatch.setenv("GIT_ENDPOINT", "https://gitlab.example.com")
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(g.subprocess, "run", fake_run)
    g.gitlab_resources_check("repo-1", "https://gitlab.example.com/team/repo")
    (command, kwargs), = calls
    assert command[1:3] == ["gitlab", "https://gitlab.example.com/team/repo"]
    assert f"--include={g.GITLAB_RESOURCES_INCLUDE}" in command
    assert f"--exclude={g.GITLAB_RESOURCES_EXCLUDE}" in command
    assert command[command.index("--base-url") + 1] == "https://gitlab.example.com"
    assert command[command.index("--config") + 1] == g.BETTERLEAKS_CONFIG
    assert command[command.index("--ignore-file") + 1] == g.BETTERLEAKS_IGNORE_FILE
    assert command[command.index("--exit-code") + 1] == str(g.LEAKS_EXIT_CODE)
    assert command[command.index("--output") + 1] == g.report_path("repo-1.gitlab")
    assert "--no-allow-signatures" in command
    assert not any("glpat-sekrit" in arg for arg in command)
    assert kwargs["env"]["GITLAB_TOKEN"] == "glpat-sekrit"


def fake_version_run(version="v2.0.0", config_rc=0, config_err=""):
    def run(command, **kwargs):
        if command[1:] == ["version"]:
            return subprocess.CompletedProcess(command, 0, version + "\n", "")
        if command[1:3] == ["config", "check"]:
            return subprocess.CompletedProcess(command, config_rc, "", config_err)
        raise AssertionError(command)

    return run


@pytest.fixture
def betterleaks_on_path(monkeypatch):
    monkeypatch.setattr(g.shutil, "which", lambda _: "/usr/bin/betterleaks")


def test_check_scan_setup_rejects_v1(monkeypatch, betterleaks_on_path):
    monkeypatch.setattr(g.subprocess, "run", fake_version_run("v1.1.0"))
    with pytest.raises(SystemExit):
        g.check_scan_setup()


def test_check_scan_setup_warns_on_dev_build(monkeypatch, betterleaks_on_path, caplog):
    monkeypatch.setattr(g.subprocess, "run", fake_version_run("dev"))
    g.check_scan_setup()
    assert "'dev'" in caplog.text


def test_check_scan_setup_accepts_v2(monkeypatch, betterleaks_on_path, caplog):
    monkeypatch.setattr(g.subprocess, "run", fake_version_run("v2.0.0-rc.5"))
    g.check_scan_setup()
    assert "WARNING" not in caplog.text


def test_check_scan_setup_rejects_invalid_config(monkeypatch, betterleaks_on_path, caplog):
    monkeypatch.setattr(
        g.subprocess, "run", fake_version_run(config_rc=1, config_err="FTL toml: bad rule id")
    )
    with pytest.raises(SystemExit):
        g.check_scan_setup()
    assert "toml: bad rule id" in caplog.text


def test_betterleaks_command_validate_drops_only_dead_secrets():
    command = g.betterleaks_command("repo-1", "quick", validate=True)
    assert "--validate" in command
    statuses = set(command[command.index("--status") + 1].split(","))
    assert statuses == {"valid", "needs_validation", "unknown", "error", "none"}


def fake_clone(ssh_url_to_repo, name):
    os.makedirs(os.path.join(g.repo_path(name), ".git"))


@pytest.mark.parametrize(
    "returncode, stderr, status",
    [
        (0, "", "clean"),
        (g.LEAKS_EXIT_CODE, "", "pwned"),
        (1, "FTL unable to load betterleaks config", "error"),
        (0, "ERR failed to scan Git repository", "error"),
    ],
)
def test_organize_classifies_betterleaks_result(monkeypatch, returncode, stderr, status):
    monkeypatch.setattr(g, "clone", fake_clone)
    monkeypatch.setattr(
        g,
        "betterleaks_check",
        lambda name, mode, validate: subprocess.CompletedProcess([], returncode, "", stderr),
    )
    assert g.organize(project("repo-1", "unused")) == ("repo-1", status)
    assert not os.path.exists(g.repo_path("repo-1"))


def test_organize_incomplete_scan_is_error(monkeypatch):
    def incomplete_scan(name, mode, validate):
        write_files(".", {g.report_path(name): report_json([], state="incomplete")})
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(g, "clone", fake_clone)
    monkeypatch.setattr(g, "betterleaks_check", incomplete_scan)
    assert g.organize(project("repo-1", "unused")) == ("repo-1", "error")


def test_organize_passes_validate_through(monkeypatch):
    calls = []

    def scan(name, mode, validate):
        calls.append(validate)
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(g, "clone", fake_clone)
    monkeypatch.setattr(g, "betterleaks_check", scan)
    g.organize(project("repo-1", "unused"), validate=True)
    assert calls == [True]


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


def test_organize_betterleaks_timeout_is_error_and_cleans_up(monkeypatch):
    def slow_scan(name, mode, validate):
        raise subprocess.TimeoutExpired("betterleaks", 1)

    monkeypatch.setattr(g, "clone", fake_clone)
    monkeypatch.setattr(g, "betterleaks_check", slow_scan)
    assert g.organize(project("repo-1", "unused")) == ("repo-1", "error")
    assert not os.path.exists(g.repo_path("repo-1"))


def test_organize_refuses_clone_without_git_dir(monkeypatch):
    monkeypatch.setattr(g, "clone", lambda url, name: os.makedirs(g.repo_path(name)))
    monkeypatch.setattr(
        g, "betterleaks_check", lambda name, mode, validate: pytest.fail("scanned")
    )
    assert g.organize(project("repo-1", "unused")) == ("repo-1", "error")


def test_full_mode_scans_even_if_merge_request_fetch_fails(monkeypatch):
    def failing_fetch(name):
        raise subprocess.CalledProcessError(1, "git", stderr="refs not allowed")

    monkeypatch.setattr(g, "clone", fake_clone)
    monkeypatch.setattr(g, "fetch_extra_refs", failing_fetch)
    monkeypatch.setattr(
        g,
        "betterleaks_check",
        lambda name, mode, validate: subprocess.CompletedProcess([], 0, "", ""),
    )
    assert g.organize(project("repo-1", "unused"), mode="full") == ("repo-1", "clean")


def test_drop_empty_report():
    write_files(
        ".",
        {
            g.report_path("empty-1"): report_json([]),
            g.report_path("full-2"): report_json([{"rule_id": "x"}]),
        },
    )
    g.drop_empty_report("empty-1")
    g.drop_empty_report("full-2")
    assert not os.path.exists(g.report_path("empty-1"))
    assert load_findings("full-2") == [{"rule_id": "x"}]


def test_report_complete():
    write_files(
        ".",
        {
            g.report_path("ok-1"): report_json([]),
            g.report_path("partial-2"): report_json([], state="incomplete"),
        },
    )
    assert g.report_complete("ok-1") is True
    assert g.report_complete("partial-2") is False
    assert g.report_complete("missing-3") is True


def fake_finding(fingerprint="fp1", confidence="high", status=None, path="k.pem", sha="c1"):
    result = {
        "rule_id": "some-rule",
        "confidence": confidence,
        "match": {"value": "AKIA****", "fingerprint": fingerprint},
        "location": {"path": path, "start_line": 3},
        "attributes": {"git.sha": sha},
    }
    if confidence is None:
        del result["confidence"]
    if status is not None:
        result["analysis"] = {"status": status}
    return result


@pytest.mark.parametrize(
    "confidence, status, tier",
    [
        ("high", None, "actionable"),
        ("medium", None, "actionable"),
        ("low", None, "review"),
        (None, None, "review"),
        ("low", "valid", "actionable"),
        (None, "valid", "actionable"),
        ("high", "unknown", "actionable"),
        ("medium", "error", "actionable"),
        ("high", "invalid", "review"),
        ("medium", "revoked", "review"),
        ("low", "needs_validation", "review"),
    ],
)
def test_finding_tier(confidence, status, tier):
    assert g.finding_tier(fake_finding(confidence=confidence, status=status)) == tier


@pytest.mark.parametrize(
    "rule_id, path, status, tier",
    [
        ("generic-password", "tests/unit/http.test.js", None, "review"),
        ("generic-password", "README.md", None, "review"),
        ("generic-api-key", "docs/config.rst", None, "review"),
        ("generic-credential-uri", "src/test_utils.py", None, "review"),
        ("generic-password", "tests/unit/http.test.js", "valid", "actionable"),
        ("generic-password", "src/settings.py", None, "actionable"),
        ("generic-password", "contest/settings.py", None, "actionable"),
        ("aws-access-token", "tests/fixtures/creds.txt", None, "actionable"),
    ],
)
def test_finding_tier_sends_generic_sample_paths_to_review(rule_id, path, status, tier):
    finding = dict(fake_finding(confidence="medium", status=status, path=path), rule_id=rule_id)
    assert g.finding_tier(finding) == tier


@pytest.mark.parametrize(
    "confidence, status, priority",
    [
        ("low", "valid", 1),
        ("high", "valid", 1),
        ("high", None, 2),
        ("high", "unknown", 2),
        ("medium", None, 3),
        ("low", None, 4),
        (None, None, 4),
        ("high", "invalid", 4),
    ],
)
def test_finding_priority(confidence, status, priority):
    assert g.finding_priority(fake_finding(confidence=confidence, status=status)) == priority


def test_triage_report_dedups_by_fingerprint():
    findings = [fake_finding(sha=f"c{i}", path=f"f{i}.txt") for i in range(3)]
    findings += [fake_finding("fp2", confidence="low"), fake_finding("fp2", sha="c9")]
    findings.append(fake_finding("fp3", confidence="low"))
    write_files(".", {g.report_path("r-1"): report_json(findings)})

    triage = g.triage_report("r-1")
    assert triage["actionable"] == [
        {
            "rule_id": "some-rule",
            "confidence": "high",
            "status": "none",
            "priority": 2,
            "source": "repo",
            "path": "f0.txt",
            "line": 3,
            "commit": "c0",
            "occurrences": 3,
            "fingerprint": "fp1",
            "components": [],
        },
        {
            "rule_id": "some-rule",
            "confidence": "high",
            "status": "none",
            "priority": 2,
            "source": "repo",
            "path": "k.pem",
            "line": 3,
            "commit": "c9",
            "occurrences": 2,
            "fingerprint": "fp2",
            "components": [],
        },
    ]
    assert [entry["fingerprint"] for entry in triage["review"]] == ["fp3"]
    assert g.triage_report("missing-2") == {"actionable": [], "review": []}


def test_triage_report_sorts_by_priority_then_rule():
    findings = [
        dict(fake_finding("m", confidence="medium"), rule_id="a-rule"),
        dict(fake_finding("h2"), rule_id="z-rule"),
        dict(fake_finding("h1"), rule_id="b-rule"),
        dict(fake_finding("v", confidence="low", status="valid"), rule_id="y-rule"),
    ]
    write_files(".", {g.report_path("r-1"): report_json(findings)})
    triage = g.triage_report("r-1")
    assert [(e["priority"], e["rule_id"]) for e in triage["actionable"]] == [
        (1, "y-rule"),
        (2, "b-rule"),
        (2, "z-rule"),
        (3, "a-rule"),
    ]


def with_components(finding, *components):
    finding["component_sets"] = [
        {"components": [{"rule_id": rule_id, "match": {"value": "x", "fingerprint": fp}}]}
        for rule_id, fp in components
    ]
    return finding


def test_triage_report_lists_components_and_folds_their_findings():
    findings = [
        with_components(
            dict(fake_finding("key-id"), rule_id="aws-access-token"),
            ("aws-secret-key", "secret"),
            ("aws-secret-key", "secret"),
        ),
        dict(fake_finding("secret", confidence="low", status="valid"), rule_id="generic-api-key"),
    ]
    write_files(".", {g.report_path("r-1"): report_json(findings)})
    triage = g.triage_report("r-1")
    assert triage["review"] == []
    (entry,) = triage["actionable"]
    assert entry["fingerprint"] == "key-id"
    assert entry["priority"] == 1
    assert entry["components"] == [{"rule_id": "aws-secret-key", "fingerprint": "secret"}]


def test_triage_report_merges_wiki_and_gitlab_reports():
    write_files(
        ".",
        {
            g.report_path("r-1"): report_json([fake_finding("fp1")]),
            g.report_path("r-1.wiki"): report_json([fake_finding("fp1"), fake_finding("fp2")]),
            g.report_path("r-1.gitlab"): report_json([fake_finding("fp3", confidence="low")]),
        },
    )
    triage = g.triage_report("r-1")
    assert [(e["fingerprint"], e["source"], e["occurrences"]) for e in triage["actionable"]] == [
        ("fp1", "repo", 2),
        ("fp2", "wiki", 1),
    ]
    assert [(e["fingerprint"], e["source"]) for e in triage["review"]] == [("fp3", "gitlab")]


def redaction_report():
    secret = "wJ8rTqXk2vN9pL4mZ7bH3cR6tY1sF5gD0aQeUiWj"
    key_id = "AKIAXUIMYLEMFST2LSXP"
    password = "m42xloz2wd"
    return {
        "findings": [
            {
                "rule_id": "aws-access-token",
                "match": {
                    "value": key_id,
                    "full": key_id,
                    "line": f"aws_access_key_id = {key_id}",
                    "context": f"aws_access_key_id = {key_id}\naws_secret = {secret}",
                    "fingerprint": "fp-key",
                },
                "attributes": {"git.message": f"rotate {secret}", "git.sha": "c1"},
                "location": {"path": "amqp/AKIA_creds.txt"},
                "component_sets": [
                    {
                        "components": [
                            {
                                "rule_id": "aws-secret-key",
                                "match": {"value": secret, "full": secret, "fingerprint": "fp-s"},
                            }
                        ]
                    }
                ],
            },
            {
                "rule_id": "generic-credential-uri",
                "match": {
                    "value": password,
                    "full": f"amqp://root:{password}@host",
                    "captures": {"scheme": "amqp", "password": password},
                    "fingerprint": "fp-uri",
                },
                "location": {"path": "amqp_credentials.txt"},
            },
        ]
    }, (secret, key_id, password)


def test_redact_report_masks_values_but_keeps_paths_and_fingerprints():
    report, secrets = redaction_report()
    write_files(".", {g.report_path("r-1"): json.dumps(report)})
    g.redact_report("r-1")
    text = open(g.report_path("r-1"), encoding="utf-8").read()
    for secret in secrets:
        assert secret not in text
    findings = load_findings("r-1")
    assert findings[0]["match"]["value"] == "AKIA..."
    assert findings[0]["match"]["line"] == "aws_access_key_id = AKIA..."
    assert findings[0]["match"]["context"] == "aws_access_key_id = AKIA...\naws_secret = wJ8rTqXk..."
    assert findings[0]["attributes"] == {"git.message": "rotate wJ8rTqXk...", "git.sha": "c1"}
    assert findings[0]["component_sets"][0]["components"][0]["match"]["value"] == "wJ8rTqXk..."
    assert findings[1]["match"]["captures"] == {"scheme": "...", "password": "m4..."}
    assert [f["location"]["path"] for f in findings] == ["amqp/AKIA_creds.txt", "amqp_credentials.txt"]
    assert [f["match"]["fingerprint"] for f in findings] == ["fp-key", "fp-uri"]


def test_redact_report_failure_deletes_unredacted_report(monkeypatch):
    report, _ = redaction_report()
    write_files(".", {g.report_path("r-1"): json.dumps(report)})

    def broken_dump(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(g.json, "dump", broken_dump)
    with pytest.raises(OSError):
        g.redact_report("r-1")
    assert os.listdir(g.LEAKS_REPORTS_DIR) == []


def test_run_scan_timeout_deletes_partial_report():
    def slow_scan():
        write_files(".", {g.report_path("r-1"): '{"findings": [{"match": {"value": "AKIA'})
        raise subprocess.TimeoutExpired("betterleaks", 1)

    with pytest.raises(subprocess.TimeoutExpired):
        g.run_scan("r-1", slow_scan)
    assert not os.path.exists(g.report_path("r-1"))


def test_organize_redaction_failure_is_error_and_leaves_no_report(monkeypatch):
    monkeypatch.setattr(g, "clone", fake_clone)
    monkeypatch.setattr(g, "betterleaks_check", scan_writing([fake_finding()]))
    monkeypatch.setattr(g, "redact_finding", lambda finding: 1 / 0)
    assert g.organize(project("repo-1", "unused")) == ("repo-1", "error")
    assert not os.path.exists(g.report_path("repo-1"))


def test_organize_merges_gitlab_resources_scan(monkeypatch):
    calls = []

    def resources_scan(name, web_url, validate):
        calls.append(web_url)
        write_files(".", {g.report_path(g.gitlab_name(name)): report_json([fake_finding()])})
        return subprocess.CompletedProcess([], g.LEAKS_EXIT_CODE, "", "")

    monkeypatch.setattr(g, "clone", fake_clone)
    monkeypatch.setattr(
        g, "betterleaks_check", lambda name, mode, validate: subprocess.CompletedProcess([], 0, "", "")
    )
    monkeypatch.setattr(g, "gitlab_resources_check", resources_scan)
    assert g.organize(project("repo-1", "unused")) == ("repo-1", "clean")
    assert calls == []
    assert g.organize(project("repo-1", "unused"), gitlab_resources=True) == ("repo-1", "pwned")
    assert calls == ["https://gitlab.example.com/repo-1"]
    assert g.triage_report("repo-1")["actionable"][0]["source"] == "gitlab"


def test_organize_failed_gitlab_resources_scan_is_error(monkeypatch):
    monkeypatch.setattr(g, "clone", fake_clone)
    monkeypatch.setattr(
        g, "betterleaks_check", lambda name, mode, validate: subprocess.CompletedProcess([], 0, "", "")
    )
    monkeypatch.setattr(
        g,
        "gitlab_resources_check",
        lambda name, web_url, validate: subprocess.CompletedProcess([], 1, "", "ERR HTTP 401"),
    )
    assert g.organize(project("repo-1", "unused"), gitlab_resources=True) == ("repo-1", "error")


def scan_writing(findings, returncode=g.LEAKS_EXIT_CODE, state="complete"):
    def scan(name, mode, validate):
        write_files(".", {g.report_path(name): report_json(findings, state=state)})
        return subprocess.CompletedProcess([], returncode, "", "")

    return scan


@pytest.mark.parametrize(
    "findings, state, status",
    [
        ([fake_finding(confidence="low")], "complete", "review"),
        ([fake_finding(confidence="low"), fake_finding("fp2")], "complete", "pwned"),
        ([fake_finding(confidence="low", status="valid")], "complete", "pwned"),
        ([fake_finding(confidence="low")], "incomplete", "error"),
        ([fake_finding()], "incomplete", "pwned"),
    ],
)
def test_organize_tiers_findings(monkeypatch, findings, state, status):
    monkeypatch.setattr(g, "clone", fake_clone)
    monkeypatch.setattr(g, "betterleaks_check", scan_writing(findings, state=state))
    assert g.organize(project("repo-1", "unused")) == ("repo-1", status)


def test_write_summary():
    projects = [project(name, "u") for name in ("a-1", "b-2", "c-3", "d-4", "e-5")]
    write_files(
        ".",
        {
            g.report_path("b-2"): report_json([fake_finding(), fake_finding(sha="c2")]),
            g.report_path("d-4"): report_json([fake_finding(confidence="low")]),
            g.report_path("e-5"): report_json([fake_finding(status="valid")]),
            g.report_path("e-5.wiki"): report_json([fake_finding("fp2", confidence="medium")]),
        },
    )
    g.write_summary(
        projects,
        {"a-1": "clean", "b-2": "pwned", "c-3": "error", "d-4": "review", "e-5": "pwned"},
    )

    with open(f"{g.LEAKS_REPORTS_DIR}/{g.today_frmt}_summary.json", encoding="utf-8") as fp:
        ordered = json.load(fp)
    assert [entry["name"] for entry in ordered] == ["e-5", "b-2", "d-4", "c-3", "a-1"]
    summary = {entry["name"]: entry for entry in ordered}
    assert summary["b-2"] == {
        "name": "b-2",
        "url": "https://gitlab.example.com/b-2",
        "status": "pwned",
        "reports": [g.report_path("b-2")],
        "unique_secrets": 1,
        "actionable": 1,
        "review": 0,
        "confirmed": 0,
        "top_priority": 2,
        "triage": g.triage_report("b-2"),
    }
    assert summary["b-2"]["triage"]["actionable"][0]["occurrences"] == 2
    assert summary["e-5"]["reports"] == [g.report_path("e-5"), g.report_path("e-5.wiki")]
    assert (summary["e-5"]["confirmed"], summary["e-5"]["top_priority"]) == (1, 1)
    assert (summary["d-4"]["actionable"], summary["d-4"]["review"]) == (0, 1)
    assert summary["d-4"]["top_priority"] == 4
    assert summary["a-1"]["reports"] == []
    assert summary["a-1"]["top_priority"] is None
    assert summary["a-1"]["triage"] == {"actionable": [], "review": []}
    for label, expected in (
        ("error", "c-3\n"),
        ("review", "d-4\n"),
        ("pwned", "b-2\ne-5\n"),
        ("confirmed", "e-5\n"),
    ):
        path = f"{g.LEAKS_REPORTS_DIR}/{g.today_frmt}_{label}_repos.txt"
        with open(path, encoding="utf-8") as fp:
            assert fp.read() == expected


# --- integration tests (real git + betterleaks) ------------------------------


def scan_findings(target, *extra):
    """Scans target directly with the pinned config, bypassing gitscrapper."""
    scan = subprocess.run(
        [g.BETTERLEAKS_BIN, "git", target, "-c", g.BETTERLEAKS_CONFIG, "--output", "-",
         "--no-banner", "-l", "error", *extra],
        capture_output=True,
        text=True,
    )
    return json.loads(scan.stdout)["findings"]


@needs_betterleaks
def test_repo_cannot_silence_its_own_scan(workdir):
    src = make_repo(
        str(workdir / "src"),
        {
            "k.pem": private_key(),
            "allowed.txt": f"aws_access_key_id = {AWS_KEY} # betterleaks:allow\n",
            ".betterleaks.toml": '[extend]\nuseDefault = false\n[[rules]]\nid = "noop"\n'
            'regex = "zzzz_never_matches"\n',
        },
    )
    # Ignore every real finding by fingerprint, as a repo owner could.
    findings = scan_findings(src, "--no-allow-signatures")
    assert len(findings) == 2
    fingerprints = [finding["match"]["fingerprint"] for finding in findings]
    write_files(src, {".betterleaksignore": "\n".join(fingerprints) + "\n"})
    git(src, "add", "-A")
    git(src, "commit", "-q", "-m", "hide findings")
    assert scan_findings(src) == []

    assert g.organize(project("hostile-1", src)) == ("hostile-1", "pwned")
    findings = load_findings("hostile-1")
    assert {finding["rule_id"] for finding in findings} == {"private-key", "aws-access-token"}
    report = open(g.report_path("hostile-1"), encoding="utf-8").read()
    assert AWS_KEY not in report
    assert "PRIVATE KEY-----\nMII" not in report


@needs_betterleaks
def test_redacted_report_keeps_secret_like_paths_readable(workdir):
    password = "m42xloz2wd9Q"
    src = make_repo(
        str(workdir / "src"),
        {"amqp/amqp_credentials.txt": f"broker = amqp://root:{password}@mq.internal.corp:5672/x\n"},
    )
    assert g.organize(project("uri-1", src)) == ("uri-1", "pwned")
    report = open(g.report_path("uri-1"), encoding="utf-8").read()
    assert password not in report
    assert {f["location"]["path"] for f in load_findings("uri-1")} == {"amqp/amqp_credentials.txt"}


@needs_betterleaks
@pytest.mark.parametrize("mode", g.SCAN_MODES)
def test_both_modes_find_secrets_inside_archives(workdir, mode):
    archive = workdir / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("config/key.pem", private_key())
    src = make_repo(str(workdir / "src"), {"bundle.zip": archive.read_bytes()})

    assert g.organize(project("zip-1", src), mode=mode) == ("zip-1", "pwned")
    assert any("!" in finding["location"]["path"] for finding in load_findings("zip-1"))


@needs_betterleaks
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


@needs_betterleaks
@pytest.mark.parametrize("mode", g.SCAN_MODES)
def test_both_modes_scan_commit_messages(workdir, mode):
    src = make_repo(str(workdir / "src"), {"README.md": "hello\n"})
    git(src, "commit", "-q", "--allow-empty", "-m", f"rotate key\n\nold: {AWS_KEY}")

    assert g.organize(project("msg-1", src), mode=mode) == ("msg-1", "pwned")
    assert AWS_KEY not in open(g.report_path("msg-1"), encoding="utf-8").read()


@needs_betterleaks
def test_full_mode_scans_git_notes(workdir):
    src = make_repo(str(workdir / "src"), {"README.md": "hello\n"})
    git(src, "notes", "add", "-m", f"deploy creds: aws_access_key_id = {AWS_KEY}")

    assert g.organize(project("notes-1", src), mode="quick") == ("notes-1", "clean")
    assert g.organize(project("notes-1", src), mode="full") == ("notes-1", "pwned")


@needs_betterleaks
def test_full_mode_scans_project_wiki(workdir):
    src = make_repo(str(workdir / "src"), {"README.md": "hello\n"})
    make_repo(str(workdir / "src.wiki.git"), {"home.md": private_key()})

    assert g.organize(project("wiki-1", src), mode="quick") == ("wiki-1", "clean")
    assert g.organize(project("wiki-1", src), mode="full") == ("wiki-1", "pwned")
    assert not os.path.exists(g.report_path("wiki-1"))
    assert [e["source"] for e in g.triage_report("wiki-1")["actionable"]] == ["wiki"]
    assert not os.path.exists(g.repo_path("wiki-1.wiki"))


@needs_betterleaks
def test_full_mode_without_wiki_is_clean(workdir):
    src = make_repo(str(workdir / "src"), {"README.md": "hello\n"})
    assert g.organize(project("nowiki-1", src), mode="full") == ("nowiki-1", "clean")


@needs_betterleaks
def test_scan_does_not_escape_into_enclosing_repo():
    # The run directory itself is a repo with a leak; a clone missing its
    # .git must not cause betterleaks to scan this enclosing history instead.
    git(".", "init", "-q", "-b", "main")
    write_files(".", {"k.pem": private_key()})
    git(".", "add", "k.pem")
    git(".", "commit", "-q", "-m", "leak")
    os.makedirs(g.repo_path("broken-1"))

    result = g.betterleaks_check("broken-1", "quick")
    assert result.returncode not in (0, g.LEAKS_EXIT_CODE)
    assert not os.path.exists(g.report_path("broken-1")) or load_findings("broken-1") == []


@needs_betterleaks
def test_false_positive_decoys_stay_clean(workdir):
    src = make_repo(str(workdir / "src"), DECOY_FILES)
    assert g.organize(project("decoy-1", src)) == ("decoy-1", "clean")


@needs_betterleaks
def test_fixture_detection_baseline(workdir):
    assert set(os.listdir(FIXTURES_DIR)) == EXPECTED_DETECTED | EXPECTED_MISSED
    dest = g.repo_path("fixtures-0")
    shutil.copytree(FIXTURES_DIR, dest)
    git(dest, "init", "-q", "-b", "main")
    git(dest, "add", "-A")
    git(dest, "commit", "-q", "-m", "fixtures")

    result = g.betterleaks_check("fixtures-0", "quick")
    assert result.returncode == g.LEAKS_EXIT_CODE, result.stderr
    detected = {
        os.path.basename(finding["location"]["path"]) for finding in load_findings("fixtures-0")
    }
    assert detected == EXPECTED_DETECTED, (
        f"newly missed: {sorted(EXPECTED_DETECTED - detected)}, "
        f"newly detected: {sorted(detected - EXPECTED_DETECTED)}"
    )


def corpus_files(src):
    return {
        os.path.relpath(os.path.join(root, filename), src)
        for root, _, filenames in os.walk(src)
        for filename in filenames
    }


def commit_corpus(src, name):
    """Commits src to repositories/<name>: deleted_* files are removed in a
    second commit and branch_* files only land on a "feature" branch."""
    dest = g.repo_path(name)
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns("branch_*"))
    git(dest, "init", "-q", "-b", "main")
    git(dest, "add", "-A")
    git(dest, "commit", "-q", "-m", "corpus")
    files = corpus_files(src)
    deleted = sorted(f for f in files if os.path.basename(f).startswith("deleted_"))
    if deleted:
        git(dest, "rm", "-q", *deleted)
        git(dest, "commit", "-q", "-m", "remove secrets")
    branch_only = sorted(f for f in files if os.path.basename(f).startswith("branch_"))
    if branch_only:
        git(dest, "checkout", "-q", "-b", "feature")
        for relpath in branch_only:
            shutil.copy(os.path.join(src, relpath), os.path.join(dest, relpath))
        git(dest, "add", "-A")
        git(dest, "commit", "-q", "-m", "feature")
        git(dest, "checkout", "-q", "main")


def benchmark_scan(src, name):
    """Scans src in full mode, unredacted so values stay comparable."""
    commit_corpus(src, name)
    result = g.betterleaks_check(name, "full")
    assert result.returncode in (0, g.LEAKS_EXIT_CODE), result.stderr
    return load_findings(name)


def finding_values(finding):
    values = {finding["match"]["value"]}
    for component_set in finding.get("component_sets") or []:
        for component in component_set["components"]:
            values.add(component["match"]["value"])
    return values


@needs_betterleaks
def test_benchmark(workdir):
    assert set(corpus_files(HARD_DIR)) == set(HARD_EXPECTED)
    corpora = {
        "fixtures": (FIXTURES_DIR, EXPECTED_DETECTED),
        "hard": (HARD_DIR, set(HARD_EXPECTED)),
        "negative": (NEGATIVE_DIR, set()),
        "review": (REVIEW_DIR, corpus_files(REVIEW_DIR)),
    }
    per_rule = {}
    false_positives, false_negatives, wrong_tiers = [], [], []
    for corpus, (src, positives) in corpora.items():
        findings = benchmark_scan(src, f"bench-{corpus}")
        by_path = {}
        for finding in findings:
            path = finding["location"]["path"]
            by_path.setdefault(path, []).append(finding)
            counts = per_rule.setdefault(finding["rule_id"], {"tp": 0, "fp": 0})
            if path in positives:
                counts["tp"] += 1
            else:
                counts["fp"] += 1
                false_positives.append((corpus, path, finding["rule_id"], finding["match"]["value"]))
        detected = positives & set(by_path)
        false_negatives += [(corpus, path) for path in sorted(positives - detected)]
        if corpus == "hard":
            for path, expected in HARD_EXPECTED.items():
                found = set().union(*(finding_values(f) for f in by_path.get(path, [])))
                false_negatives += [(corpus, path, value) for value in sorted(expected - found)]
        for path in sorted(detected):
            tiers = {g.finding_tier(finding) for finding in by_path[path]}
            tier = "actionable" if "actionable" in tiers else "review"
            expected_tier = (
                "review" if corpus == "review" or path in EXPECTED_REVIEW else "actionable"
            )
            if tier != expected_tier:
                wrong_tiers.append((corpus, path, tier))
        flagged = sum(len(by_path[path]) for path in by_path)
        true_positives = sum(len(by_path[path]) for path in detected)
        recall = f"{len(detected) / len(positives):.2f}" if positives else "n/a"
        print(
            f"\n{corpus}: recall={recall} ({len(detected)}/{len(positives)} files), "
            f"precision={true_positives / flagged if flagged else 1.0:.2f} "
            f"({true_positives}/{flagged} findings)"
        )
    for rule_id, counts in sorted(per_rule.items()):
        precision = counts["tp"] / (counts["tp"] + counts["fp"])
        print(f"  {rule_id:<32} tp={counts['tp']:<3} fp={counts['fp']:<3} precision={precision:.2f}")

    assert false_positives == []
    assert false_negatives == []
    assert wrong_tiers == []
