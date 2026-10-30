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
HARD_EXPECTED = {
    "multiline.json": {"sk_live_KTfg0EpeZ6FzFLd5jpffAVQ7"},
    "nested.yaml": {"AKIAXUIMYLEMFST2LSXP", "/KLHpxFReOKq5qPtGwlgYefVLFmFrmiovr/CY7Mz"},
    "quoted.env": {"bzhIfbgNk@GYUgsL"},
    "web.config": {"PsgQsNhpTL0hZn0Vc96l2tKaVPcDSHkJCBSCxZNR"},
    "url.txt": {"wL1M0F3F2kzEq8Vr"},
    "k8s_secret.yaml": {"xoxb-51136943514-948438804521-c9USN1xEDjv0acy1sS1xTZBf"},
    "deleted_github_token.txt": {"ghp_IoJv3AcUYHL2qOrhvsAjQjkfbsjRw6VCIA7u"},
    "branch_gitlab_token.txt": {"glpat-lh9RY-xEMWtxa6jxH9zq"},
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


def test_betterleaks_command_pins_config_and_overrides():
    command = g.betterleaks_command("repo-1", "quick")
    assert command[1:3] == ["git", "repositories/repo-1/.git"]
    assert command[command.index("--config") + 1] == g.BETTERLEAKS_CONFIG
    assert command[command.index("--ignore-file") + 1] == g.BETTERLEAKS_IGNORE_FILE
    assert "--no-allow-signatures" in command
    assert command[command.index("--exit-code") + 1] == str(g.LEAKS_EXIT_CODE)
    assert f"--redact={g.REDACT_PERCENT}" in command
    assert command[command.index("--output") + 1] == g.report_path("repo-1")
    assert "--silent" in command
    assert command[command.index("--max-archive-depth") + 1] == "0"
    assert "--max-decode-depth" not in command
    assert not any(arg.startswith("--include") for arg in command)
    assert "--validate" not in command
    assert "--status" not in command


def test_betterleaks_command_full_mode_opens_archives_and_pins_decode_depth():
    command = g.betterleaks_command("repo-1", "full")
    assert command[command.index("--max-archive-depth") + 1] == str(g.FULL_MODE_ARCHIVE_DEPTH)
    assert command[command.index("--max-decode-depth") + 1] == str(g.FULL_MODE_DECODE_DEPTH)
    assert "--include=merges,commit-messages,tag-messages" in command


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
    monkeypatch.setattr(g, "fetch_merge_request_refs", failing_fetch)
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
            "path": "f0.txt",
            "line": 3,
            "commit": "c0",
            "occurrences": 3,
            "fingerprint": "fp1",
        },
        {
            "rule_id": "some-rule",
            "confidence": "high",
            "status": "none",
            "path": "k.pem",
            "line": 3,
            "commit": "c9",
            "occurrences": 2,
            "fingerprint": "fp2",
        },
    ]
    assert [entry["fingerprint"] for entry in triage["review"]] == ["fp3"]
    assert g.triage_report("missing-2") == {"actionable": [], "review": []}


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
    projects = [project(name, "u") for name in ("a-1", "b-2", "c-3", "d-4")]
    write_files(
        ".",
        {
            g.report_path("b-2"): report_json([fake_finding(), fake_finding(sha="c2")]),
            g.report_path("d-4"): report_json([fake_finding(confidence="low")]),
        },
    )
    g.write_summary(projects, {"a-1": "clean", "b-2": "pwned", "c-3": "error", "d-4": "review"})

    with open(f"{g.LEAKS_REPORTS_DIR}/{g.today_frmt}_summary.json", encoding="utf-8") as fp:
        summary = {entry["name"]: entry for entry in json.load(fp)}
    assert summary["b-2"] == {
        "name": "b-2",
        "url": "https://gitlab.example.com/b-2",
        "status": "pwned",
        "report": g.report_path("b-2"),
        "unique_secrets": 1,
        "actionable": 1,
        "review": 0,
        "triage": g.triage_report("b-2"),
    }
    assert summary["b-2"]["triage"]["actionable"][0]["occurrences"] == 2
    assert (summary["d-4"]["actionable"], summary["d-4"]["review"]) == (0, 1)
    assert summary["a-1"]["report"] is None
    assert summary["a-1"]["triage"] == {"actionable": [], "review": []}
    for label, expected in (("error", "c-3\n"), ("review", "d-4\n"), ("pwned", "b-2\n")):
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
    assert AWS_KEY not in json.dumps(findings)


@needs_betterleaks
def test_full_mode_finds_secrets_inside_archives(workdir):
    archive = workdir / "bundle.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("config/key.pem", private_key())
    src = make_repo(str(workdir / "src"), {"bundle.zip": archive.read_bytes()})

    assert g.organize(project("zip-1", src), mode="quick") == ("zip-1", "clean")
    assert g.organize(project("zip-1", src), mode="full") == ("zip-1", "pwned")
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
def test_full_mode_scans_commit_messages(workdir):
    src = make_repo(str(workdir / "src"), {"README.md": "hello\n"})
    git(src, "commit", "-q", "--allow-empty", "-m", f"rotate key\n\nold: {AWS_KEY}")

    assert g.organize(project("msg-1", src), mode="quick") == ("msg-1", "clean")
    assert g.organize(project("msg-1", src), mode="full") == ("msg-1", "pwned")


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

    # Unredacted: --redact also masks captured values wherever they recur in
    # the report, including file paths (e.g. "amqp" in amqp_credentials.txt).
    command = [arg for arg in g.betterleaks_command("fixtures-0", "quick")
               if not arg.startswith("--redact")]
    result = subprocess.run(command, capture_output=True, text=True)
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
    """Scans src in full mode, unredacted so paths and values stay comparable."""
    commit_corpus(src, name)
    command = [arg for arg in g.betterleaks_command(name, "full")
               if not arg.startswith("--redact")]
    result = subprocess.run(command, capture_output=True, text=True)
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
            expected_tier = "review" if path in EXPECTED_REVIEW else "actionable"
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
