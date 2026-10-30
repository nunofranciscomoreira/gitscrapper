# gitscrapper
Automation for [betterleaks](https://github.com/betterleaks/betterleaks) to use in large gitlab instances.

In the future it will support github enterprise instances, but I don't have an instance to test.

## How to

Generate a personal access token for the git instance

https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html#create-a-personal-access-token

Install betterleaks **v2**. Homebrew and Docker `latest` may still ship v1, which `betterleaks.toml`
rejects (`minVersion`), so install with Go or from a
[v2 release archive](https://github.com/betterleaks/betterleaks/releases):

```sh
go install github.com/betterleaks/betterleaks/v2@latest   # installs to ~/go/bin
```

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

`betterleaks` must be on your `PATH`, or point `BETTERLEAKS_BIN` at the binary. The
`repositories/` and `leaks_reports/` folders are created automatically if missing.
Clones are made over SSH, so the machine needs an SSH key GitLab accepts.

### Scan modes

| Mode | Scans | Cost |
| --- | --- | --- |
| `quick` (default) | Full history of every branch and tag in a normal clone. Archives are not opened (`--max-archive-depth 0`; betterleaks' own git default is 8) | Baseline |
| `full` | Everything in `quick`, plus GitLab merge-request refs (`refs/merge-requests/*/head`), the contents of archives (zip, tar, ...) up to 2 levels deep, recursive decoding of percent/hex/base64-encoded text up to depth 5, merge-commit diffs, and commit and tag messages (`--include=merges,commit-messages,tag-messages`) | Larger clones, slower scans |

Neither mode can see branches that were deleted from GitLab, since a clone never receives them.

### Validation (`--validate`)

By default every finding is local: nothing leaves the machine except the git clone. With
`--validate` (or `GITSCRAPPER_VALIDATE=1`) betterleaks sends each candidate secret to its
provider's API (AWS, GitHub, Slack, ...) to check whether it is live. Only findings confirmed
`invalid` or `revoked` are dropped. Findings from rules with no validator (`none`), and checks that
error out or come back `unknown`/`needs_validation`, are kept, so validation never turns a secret
into a miss. Only enable it on a network where sending secrets to their providers is acceptable.

### Hardening against repos hiding their own findings

A scanned repo controls the files in its clone, so gitscrapper does not let it steer betterleaks:

- Rules always come from `betterleaks.toml` next to the script (passed with `--config`), never
  from the repo's own `.betterleaks.toml`. Edit that file to tune rules for every repo at once.
- `betterleaks:allow` (and other allow-marker) comments are ignored (`--no-allow-signatures`).
- The ignore file is always passed explicitly (`--ignore-file`, the comment-only
  `.betterleaksignore` next to the script by default). Without it, betterleaks would read the
  scanned repo's own `.betterleaksignore`.
- `.betterleaksignore`, `.gitleaksignore`, `.betterleaks.toml` and `.gitleaks.toml` are deleted
  from each clone before scanning, as extra protection.
- betterleaks is pointed at the clone's `.git` directory. Given a plain directory it would scan
  whatever repository encloses it, so a clone missing its `.git` fails instead.

### Ignoring a known secret

Each line of `.betterleaksignore` is the bare SHA-256 of a secret value (the `match.fingerprint`
of a finding in the report), not a gitleaks-style `commit:file:rule:line` fingerprint. Generate one
with:

```sh
printf %s '<secret value>' | betterleaks fingerprint >> .betterleaksignore
```

### Environment variables

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `GIT_ENDPOINT` | yes | - | GitLab instance URL |
| `GIT_PRIVATE_TOKEN` | yes | - | GitLab personal access token |
| `BETTERLEAKS_BIN` | no | `betterleaks` on `PATH` | Path to the betterleaks v2 binary |
| `GITSCRAPPER_BETTERLEAKS_CONFIG` | no | `betterleaks.toml` next to the script | Pinned betterleaks rules |
| `GITSCRAPPER_BETTERLEAKS_IGNORE_FILE` | no | `.betterleaksignore` next to the script | Central ignore file (must exist) |
| `GITSCRAPPER_VALIDATE` | no | unset | `1`/`true`/`yes` turns on `--validate` |
| `GITSCRAPPER_WORKERS` | no | `min(32, cpu_count * 4)` | Concurrent clone/scan workers; same as `--workers` |
| `GIT_CLONE_TIMEOUT_S` | no | `300` | Per-repo `git clone` (and merge-request fetch) timeout, in seconds |
| `BETTERLEAKS_TIMEOUT_S` | no | `600` | Per-repo betterleaks timeout, in seconds |

### CLI flags

```sh
python3 gitscrapper.py --help
```

- `--mode quick|full` - scan depth, see [Scan modes](#scan-modes).
- `--workers N` - override the number of concurrent clone/scan workers (overrides `GITSCRAPPER_WORKERS`).
- `--dry-run` - list the projects that would be scanned and exit, without cloning anything.
- `--skip-archived` - don't scan archived GitLab projects.
- `--validate` - check findings against provider APIs, see [Validation](#validation---validate).

## Output

- `leaks_reports/secrets_<name>.json` - the unmodified betterleaks v2 JSON report for each repo
  with findings (removed if the scan was clean). The report is an object,
  `{"schema_version", "findings": [...], "scan": {...}}`. Each finding has `rule_id`,
  `confidence`, `match.value`, `match.fingerprint`, `location.path`/`start_line`, and git
  `attributes` (commit, author, date). `scan.state` is `complete` or `incomplete`.
  Secrets are 80% redacted (`--redact=80`): enough is kept to tell which credential it is, but not
  enough to use it. betterleaks also masks short captured values (like an `amqp` URI scheme)
  wherever they recur in the report, so a file path can occasionally appear partly redacted.
- `leaks_reports/<date>_summary.json` - one entry per repo with its name, GitLab URL, status
  (`clean`, `pwned` or `error`) and report path.
- `leaks_reports/<date>_{clean,pwned,error}_repos.txt` - repo names in each bucket.

A repo is marked `error`, never `clean`, when its clone or scan fails, times out, betterleaks
logs an error, or the report says `scan.state` is `incomplete` (corrupt objects, unreadable refs),
so a silent or partial tool failure can't pass as a clean result.

## Tests

```sh
pip install -r requirements-dev.txt
python3 -m pytest
```

Integration tests run the real `git` and `betterleaks` binaries against throwaway local repos (and
are skipped if betterleaks isn't installed). They check that a repo can't silence its own scan,
that `full` mode finds secrets in archives, merge-request refs and commit messages, that
placeholder and low-entropy decoys stay `clean`, and that the fixture baseline below still holds.

## test_fixtures/

`test_fixtures/` contains synthetic, fake credentials (not real secrets) used to
sanity-check that a secret-detection regex/rule actually matches a given format
(AWS keys, JWTs, PEM keys, etc.). They aren't read by `gitscrapper.py` itself.

`tests/test_gitscrapper.py` records which fixtures the pinned rules in `betterleaks.toml` detect.
betterleaks v2's default rules alone catch 26 of the 34 fixtures; `betterleaks.toml` adds 7 custom
rules for the rest (agora, alchemy, amazon-mws, asana, azure management certificate, beamer, and a
generic bearer token rule). 33 of 34 fixtures are detected; `aws.txt` is intentionally left
undetected because its values contain the literal word "fake" (`ASIIAMFAKE...`) and its key ID
isn't a valid AWS prefix. If a new fixture is added or a rule's format changes, update both
`betterleaks.toml` and the baseline in the test.

The asana, beamer and bearer rules are loose, generic fallbacks for credential shapes whose
fixtures omit the service name, so they carry `confidence = "low"` and an entropy /
token-efficiency filter to drop readable or repetitive values. A global `filter` in
`betterleaks.toml` drops only unambiguous placeholders (`YOUR_API_KEY_HERE`, `changeme`,
`<redacted>`, `${VAR}`, runs of `x` or `0`). There is deliberately no exclusion by the word
`EXAMPLE` or by test/fixture paths: real secrets turn up there too.
