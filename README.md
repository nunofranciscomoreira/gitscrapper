# gitscrapper
Automation for gitleaks to use in large gitlab instances.

In the future it will support github enterprise instances, but I don't have an instance to test.

## How to

Generate a personal access token for the git instance

https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html#create-a-personal-access-token

Install [gitleaks](https://github.com/gitleaks/gitleaks) 8.19 or newer (e.g. `brew install gitleaks`),
then:

```sh
git clone https://github.com/nunofranciscomoreira/gitscrapper
cd gitscrapper
pip install -r requirements.txt
export GIT_ENDPOINT="https://gitlab.example.com"
export GIT_PRIVATE_TOKEN="<your personal access token>"
python3 gitscrapper.py            # quick scan
python3 gitscrapper.py --mode full
```

`gitleaks` must be on your `PATH`, or point `GITLEAKS_BIN` at the binary. The
`repositories/` and `leaks_reports/` folders are created automatically if missing.
Clones are made over SSH, so the machine needs an SSH key GitLab accepts.

### Scan modes

| Mode | Scans | Cost |
| --- | --- | --- |
| `quick` (default) | Full history of every branch and tag in a normal clone | Baseline |
| `full` | Everything in `quick`, plus GitLab merge-request refs (`refs/merge-requests/*/head`), the contents of archives (zip, tar, ...) up to 2 levels deep, and recursive decoding of percent/hex/base64-encoded text up to depth 5 | Larger clones, slower scans |

Neither mode can see branches that were deleted from GitLab, since a clone never receives them.

Recursive decoding (`--max-decode-depth`) is pinned explicitly in `full` mode only. gitleaks'
own documented default for this flag isn't reliable across versions/builds (seen both `0` and
`5`), so `quick` mode leaves it unset and inherits whatever the installed `gitleaks` binary
defaults to.

### Hardening against repos hiding their own findings

A scanned repo controls the files in its clone, so gitscrapper does not let it steer gitleaks:

- Rules always come from `gitleaks.toml` next to the script (passed with `--config`), never from
  the repo's own `.gitleaks.toml`. Edit that file to tune rules for every repo at once.
- `# gitleaks:allow` comments are ignored (`--ignore-gitleaks-allow`).
- The repo's `.gitleaksignore` is deleted from the clone before scanning. A central
  `.gitleaksignore` (by finding fingerprint) can live in `GITSCRAPPER_GITLEAKS_IGNORE_DIR`.

### Environment variables

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `GIT_ENDPOINT` | yes | - | GitLab instance URL |
| `GIT_PRIVATE_TOKEN` | yes | - | GitLab personal access token |
| `GITLEAKS_BIN` | no | `gitleaks` on `PATH` | Path to the gitleaks binary |
| `GITSCRAPPER_GITLEAKS_CONFIG` | no | `gitleaks.toml` next to the script | Pinned gitleaks rules |
| `GITSCRAPPER_GITLEAKS_IGNORE_DIR` | no | the script's directory | Directory holding the central `.gitleaksignore` |
| `GITSCRAPPER_WORKERS` | no | `min(32, cpu_count * 4)` | Concurrent clone/scan workers; same as `--workers` |
| `GIT_CLONE_TIMEOUT_S` | no | `300` | Per-repo `git clone` (and merge-request fetch) timeout, in seconds |
| `GITLEAKS_TIMEOUT_S` | no | `600` | Per-repo gitleaks timeout, in seconds |

### CLI flags

```sh
python3 gitscrapper.py --help
```

- `--mode quick|full` - scan depth, see [Scan modes](#scan-modes).
- `--workers N` - override the number of concurrent clone/scan workers (overrides `GITSCRAPPER_WORKERS`).
- `--dry-run` - list the projects that would be scanned and exit, without cloning anything.
- `--skip-archived` - don't scan archived GitLab projects.

## Output

- `leaks_reports/secrets_<name>.json` - the unmodified gitleaks JSON report for each repo with
  findings (removed if the scan was clean). Each finding has a `Link` to the line in GitLab.
  Secrets are 80% redacted (`--redact=80`): enough is kept to tell which credential it is, but not
  enough to use it.
- `leaks_reports/<date>_summary.json` - one entry per repo with its name, GitLab URL, status
  (`clean`, `pwned` or `error`) and report path.
- `leaks_reports/<date>_{clean,pwned,error}_repos.txt` - repo names in each bucket.

A repo is marked `error`, never `clean`, when its clone or scan fails, times out, or gitleaks
logs an error, so a silent tool failure can't pass as a clean result.

## Tests

```sh
pip install -r requirements-dev.txt
python3 -m pytest
```

Integration tests run the real `git` and `gitleaks` binaries against throwaway local repos (and
are skipped if gitleaks isn't installed). They check that a repo can't silence its own scan, that
`full` mode finds secrets in archives and merge-request refs, and that the fixture baseline below
still holds.

## test_fixtures/

`test_fixtures/` contains synthetic, fake credentials (not real secrets) used to
sanity-check that a secret-detection regex/rule actually matches a given format
(AWS keys, JWTs, PEM keys, etc.). They aren't read by `gitscrapper.py` itself.

`tests/test_gitscrapper.py` records which fixtures the pinned rules in `gitleaks.toml` detect.
Gitleaks 8.30.1's default rules alone only catch 24 of the 34 fixtures; `gitleaks.toml` adds 10
custom rules (agora, alchemy, amazon-mws, amqp, anypoint, asana, a generic aws_access_key_id/
aws_secret_access_key rule, azure management certificate, beamer, and a generic bearer token
rule). 33 of 34 fixtures are now detected; `aws.txt` is intentionally left undetected because its
values contain the literal word "fake" (`ASIIAMFAKE...`), which both gitleaks' own
`generic-api-key` allowlist and our `aws-credentials-generic` rule treat as an obvious placeholder
rather than a real credential. If a new fixture is added or a rule's format changes, update both
`gitleaks.toml` and the baseline in the test.

Three of the ten custom rules (asana, beamer, bearer) are not filling a true gap in gitleaks'
default rules — `asana-client-id`/`asana-client-secret` and `beamer-api-token` already exist, but
require the literal word "asana"/"beamer" nearby, which these fixtures omit on purpose (only the
*filename* names the service). Ours are intentionally looser, generic fallbacks for the same
credential shapes without that keyword.

Note: gitleaks' [README](https://github.com/gitleaks/gitleaks) states the project is feature
complete — the maintainer is only shipping security patches now and has moved new feature work to
a successor project ("Betterleaks"). `gitleaks.toml`'s custom rules are the only way this project
gains new secret-format coverage going forward.
