# gitscrapper
Automation for [betterleaks](https://github.com/betterleaks/betterleaks) to use in large gitlab instances.

In the future it will support github enterprise instances, but I don't have an instance to test.

## How to

Generate a personal access token for the git instance

https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html#create-a-personal-access-token

Install betterleaks **v2**. Homebrew and Docker `latest` may still ship v1, which gitscrapper
rejects at startup (it runs `betterleaks version`, and `betterleaks.toml` sets `minVersion`), so
install with Go or from a [v2 release archive](https://github.com/betterleaks/betterleaks/releases):

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

Before scanning, gitscrapper checks the setup and exits with a clear error if betterleaks is
missing, `betterleaks version` reports v1, or `betterleaks config check` rejects the pinned config.
Builds from source report version `dev`, which also skips the config's `minVersion` check, so
they only get a warning.

### Scan modes

| Mode | Scans | Cost |
| --- | --- | --- |
| `quick` (default) | Full history of every branch and tag in a normal clone, commit and tag messages (`--include=commit-messages,tag-messages`), the contents of archives (zip, tar, ...) up to 2 levels deep, and recursive decoding of percent/hex/base64-encoded text up to depth 5 | Baseline |
| `full` | Everything in `quick`, plus GitLab merge-request refs (`refs/merge-requests/*/head`) and git notes (`refs/notes/*`), merge-commit diffs (`--include=merges,commit-messages,tag-messages,notes`), and the project wiki | Larger clones, slower scans |

Archive depth (2) and decode depth (5) are passed explicitly in both modes, so a change in
betterleaks' defaults can't change coverage. Reflogs and unreachable objects aren't scanned: a fresh
clone has none. Neither mode can see branches that were deleted from GitLab, since a clone never
receives them.

In `full` mode the wiki is cloned from `<ssh_url without .git>.wiki.git` and scanned into its own
report, `secrets_<name>.wiki.json`, which is merged into the repo's triage. A project without a wiki
(or with an empty one) is not an error.

### GitLab resources (`--gitlab-resources`)

With `--gitlab-resources` (or `GITSCRAPPER_GITLAB_RESOURCES=1`), each project is also scanned
through the GitLab API with `betterleaks gitlab <project web_url>`: issues and their comments,
merge requests and their comments, snippets, releases and CI job logs
(`--include=issues,issue-comments,mrs,mr-comments,snippets,releases,ci-jobs`). Repos and forks are
excluded since the clone already covers them, and so are CI artifacts and release assets
(`--exclude=repos,forks,ci-artifacts,release-assets`), which can be large. It uses the same
config, ignore file, allow-marker and exit-code flags as the git scan, and writes
`secrets_<name>.gitlab.json`, merged into the repo's triage. `GIT_ENDPOINT` is passed as
`--base-url`, and `GIT_PRIVATE_TOKEN` is passed to betterleaks only through its environment
(`GITLAB_TOKEN`), never on the command line. This sends one API request per resource page to your
GitLab instance and nothing elsewhere; an API error marks the repo `error`. It needs a token that
can read those resources (`read_api`).

### Validation (`--validate`)

By default every finding is local: nothing leaves the machine except the git clone. With
`--validate` (or `GITSCRAPPER_VALIDATE=1`) betterleaks sends each candidate secret to its
provider's API (AWS, GitHub, Slack, ...) to check whether it is live. Only findings confirmed
`invalid` or `revoked` are dropped. Findings from rules with no validator (`none`), and checks that
error out or come back `unknown`/`needs_validation`, are kept, so validation never turns a secret
into a miss. Only enable it on a network where sending secrets to their providers is acceptable.
Validation stays opt-in; when it was off and some repos are `pwned`, the run ends with a one-line
hint suggesting it, since only validated findings can reach priority 1 (`confirmed`).

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
| `GITSCRAPPER_GITLAB_RESOURCES` | no | unset | `1`/`true`/`yes` turns on `--gitlab-resources` |
| `GITSCRAPPER_WORKERS` | no | `min(32, cpu_count * 4)` | Concurrent clone/scan workers; same as `--workers` |
| `GIT_CLONE_TIMEOUT_S` | no | `300` | Per-repo `git clone` (and wiki clone, merge-request/notes fetch) timeout, in seconds |
| `BETTERLEAKS_TIMEOUT_S` | no | `600` | Timeout for each betterleaks scan (repo, wiki, GitLab resources), in seconds |

### CLI flags

```sh
python3 gitscrapper.py --help
```

- `--mode quick|full` - scan depth, see [Scan modes](#scan-modes).
- `--workers N` - override the number of concurrent clone/scan workers (overrides `GITSCRAPPER_WORKERS`).
- `--dry-run` - list the projects that would be scanned and exit, without cloning anything.
- `--skip-archived` - don't scan archived GitLab projects.
- `--validate` - check findings against provider APIs, see [Validation](#validation---validate).
- `--gitlab-resources` - also scan issues, MRs, snippets, releases and CI job logs, see
  [GitLab resources](#gitlab-resources---gitlab-resources).

## Output

- `leaks_reports/secrets_<name>.json` - the betterleaks v2 JSON report of the repo's git scan,
  redacted (see below) and removed if the scan was clean. In `full` mode the wiki has its own
  `secrets_<name>.wiki.json`, and `--gitlab-resources` writes `secrets_<name>.gitlab.json`. A
  report is an object, `{"schema_version", "findings": [...], "scan": {...}}`. Each finding has
  `rule_id`, `confidence`, `match.value`, `match.fingerprint`, `location.path`/`start_line`, git
  `attributes` (commit, author, date, message), and `component_sets` (related values, like the AWS
  secret key paired with a key ID). `scan.state` is `complete` or `incomplete`.
- `leaks_reports/<date>_summary.json` - the actionable view: one entry per repo with its
  findings deduplicated, prioritized and triaged (see below), most urgent repos first. The raw
  reports stay as evidence.
- `leaks_reports/<date>_{pwned,review,clean,error}_repos.txt` - repo names in each bucket.
- `leaks_reports/<date>_confirmed_repos.txt` - repos with at least one finding validated live
  (priority 1). Empty unless `--validate` is on.

### Redaction

betterleaks is run without `--redact`, whose masking also hits every recurrence of a captured
value, file paths included (the `amqp` in `amqp_credentials.txt`, captured as a URI scheme). Instead
gitscrapper rewrites each report as soon as its scan finishes, before anything else reads it:
`match.value`, every `match.captures` value, and the same fields in each component keep their first
20% followed by `...` (`REDACT_PERCENT = 80`, same as betterleaks' `--redact=80`). In
`match.full`, `match.line` and `match.context` each secret is replaced by its masked form (the
whole field is masked if no known secret occurs in it). Attributes only lose full secret values of 8
or more characters, so a commit message quoting the secret is masked while short words stay. Paths,
other attributes and fingerprints are untouched. If redaction fails, or betterleaks fails or times
out mid-write, the report is deleted rather than left unredacted, and the repo is marked `error`.

### Status buckets

| Status | Meaning |
| --- | --- |
| `pwned` | At least one actionable finding |
| `review` | Findings, but none actionable: check them by hand |
| `clean` | No findings, and the scan completed without errors |
| `error` | Clone or scan failed, timed out, or was incomplete |

The status covers every scan of the project (repo, wiki, GitLab resources). A repo is marked
`error`, never `clean`, when its clone or any scan fails, times out, betterleaks logs an error, or a
report says `scan.state` is `incomplete` (corrupt objects, unreadable refs), so a silent or partial
tool failure can't pass as a clean result. A failed or incomplete scan with only review-tier
findings is also `error`, since it may have missed actionable ones. If betterleaks reports leaks
but the report can't be read, the repo is `pwned`.

### Triage tiers and priority

Every finding betterleaks reports is kept; triage only decides which bucket it lands in.
A finding is **actionable** if:

- validation confirmed it live (`analysis.status == "valid"`), or
- its rule's `confidence` is `high` or `medium`, validation did not prove it dead
  (`analysis.status` is not `invalid` or `revoked`), and it isn't a generic-rule finding in a
  sample path (below).

Everything else is **review**: low confidence, and findings with no `confidence` at all (none of
the current rules leave it unset, so this only guards future custom rules from silently counting
as actionable). Without `--validate` there is no `analysis` and the status is `none`, so the tier
comes from confidence alone. The low-confidence rules are the generic ones (`generic-api-key`,
`generic-password`, `generic-username`) and the asana, beamer and bearer fallbacks.

The generic rules (`generic-api-key`, `generic-password`, `generic-credential-uri`) judge a value
by the name it's assigned to, and tests, examples and docs are full of sample credentials
(`password: 'rapunz3l'` in a README). So their findings in test/spec/fixture/mock/example/sample/
demo/tutorial/docs directories, `*_test.*`/`test_*.*`-style files, READMEs and `.md`/`.rst`/`.adoc`
files are **review** unless validated live. This is a demotion, not an exclusion, and
provider-format rules (AWS keys, private keys, tokens with a known prefix) stay actionable there.

Each entry also gets a **priority**, and both tier lists are sorted by priority, then `rule_id`:

| Priority | Meaning |
| --- | --- |
| 1 | Validated live (`analysis.status == "valid"`) |
| 2 | High-confidence rule |
| 3 | Medium-confidence rule |
| 4 | Review tier |

Most default rules are high confidence, so without `--validate` most actionable findings are
priority 2; priority 1 needs validation.

Findings are deduplicated by `match.fingerprint` (the SHA-256 of the secret), so a secret
committed in many places is one entry with the best priority of its occurrences. Component
fingerprints count too: a secret that is both its own finding and a component of another (an AWS
secret key reported next to its key ID) is folded into that finding instead of counted twice.

### Summary fields

`<date>_summary.json` lists repos by status (`pwned`, `review`, `error`, `clean`), then best
priority, then most actionable secrets, so the most urgent repos come first. Each entry has:

| Field | Meaning |
| --- | --- |
| `name`, `url` | Repo name (`<path>-<id>`) and GitLab URL |
| `status` | `pwned`, `review`, `clean` or `error` |
| `reports` | Paths of the redacted betterleaks reports (repo, wiki, GitLab resources) that exist |
| `unique_secrets` | Distinct secrets (fingerprints) found |
| `actionable`, `review` | How many of those are in each tier |
| `confirmed` | How many were validated live (priority 1) |
| `top_priority` | Best priority among the repo's secrets, or `null` if none |
| `triage.actionable`, `triage.review` | One object per secret: `rule_id`, `confidence`, `status` (validation status, `none` if not validated), `priority`, `source` (`repo`, `wiki` or `gitlab`), `path`, `line` and `commit` of its best-priority occurrence, `occurrences`, `fingerprint`, and `components` (`[{rule_id, fingerprint}]`) |

The triage entries hold no secret values, only fingerprints and locations.

## Tests

```sh
pip install -r requirements-dev.txt
python3 -m pytest
```

Integration tests run the real `git` and `betterleaks` binaries against throwaway local repos (and
are skipped if betterleaks isn't installed). They check that a repo can't silence its own scan,
that both modes find secrets in archives and commit messages, that `full` mode finds them in
merge-request refs, git notes and the wiki, that reports are redacted but keep paths readable,
that placeholder and low-entropy decoys stay `clean`, and that the fixture baseline below still
holds.

### Benchmark

`test_benchmark` commits four labeled corpora to throwaway repos, scans each in `full` mode, and
prints recall and precision per corpus and per rule (run with `-s` to see them):

```sh
python3 -m pytest -s -k benchmark
```

- `test_fixtures/` - positives; every file except the `aws.txt` decoy must be detected.
- `test_fixtures_hard/` - positives that scanners tend to miss: multi-line JSON, nested YAML,
  quoted `.env` values, .NET XML `appSettings`, credentials in a URL, a base64-encoded token,
  a secret committed and then deleted (`deleted_*` files), a secret only on a non-default
  branch (`branch_*` files), tokens containing a `00000000` run (a Slack webhook's `B00000000`
  ID), and a value with `${` in the middle. `HARD_EXPECTED` in the test lists the secret values
  each file must surface, either as a finding or as a component of one (like an AWS secret key
  paired with its key ID).
- `test_fixtures_negative/` - false-positive bait that must produce no finding: lock-file
  integrity hashes, UUIDs, git SHAs and checksums, minified JS, `data:image/png` URIs, docs
  placeholders, translated `password` labels, the AWS docs key pair and jwt.io sample token,
  Terraform/Helm variable references, OAuth RFC sample tokens, Flask's docs `SECRET_KEY`s,
  dependency versions under password-named packages, and bare `password`/`pass#pass` test
  credentials.
- `test_fixtures_review/` - sample credentials in tests, examples and a README that the generic
  rules report with medium confidence: each file must be detected, and only in the review tier.

The test fails on any false positive, any missed file or hard-case value, or any positive file
whose tier differs from expectations (`EXPECTED_REVIEW` lists the positives expected in
`review`, as does every file in `test_fixtures_review/`; the rest must be actionable).

### Held-out evaluation on real repos

The benchmark corpora were tuned against, so `tools/evaluate_real_repos.py` measures how the config
generalizes: it clones a few well-known public repos with no live secrets (flask, click, requests,
express, axios, cobra by default; pass URLs to override) with full history into `.eval/`
(gitignored), scans each in `full` mode with the pinned config, and prints every finding with its
tier and priority, then per-rule totals. Values are masked unless `--show-values`; `--refresh`
fetches existing clones first.

```sh
python3 tools/evaluate_real_repos.py
```

Every finding there is a false-positive candidate. Review each one: if it is clearly a test,
sample or placeholder value, fix it with the narrowest filter in `betterleaks.toml` and add the
pattern as a new file in `test_fixtures_negative/` (or `test_fixtures_review/` if it should stay
reported but not actionable), then check the benchmark still passes. On the default repos the
current config reports 137 findings, 5 actionable unique secrets and 28 in review (down from 345,
19 and 34). The 5 actionable ones are TLS private keys that requests and axios commit for their
tests: real key material, kept actionable on purpose since a private key can't be told apart from
a production one by its path.

To add a case, drop a synthetic (fake but realistically formatted) file into the right corpus.
For a hard case, add its file and values to `HARD_EXPECTED` (and to `EXPECTED_REVIEW` if only
low-confidence rules catch it). Then run the benchmark and fix any false positive with the
narrowest filter in `betterleaks.toml`, never one that drops a positive. Don't add files to
`test_fixtures/`: its file set is pinned by the baseline test.

## test_fixtures/

`test_fixtures/` contains synthetic, fake credentials (not real secrets) used to
sanity-check that a secret-detection regex/rule actually matches a given format
(AWS keys, JWTs, PEM keys, etc.). They aren't read by `gitscrapper.py` itself.

`tests/test_gitscrapper.py` records which fixtures the pinned rules in `betterleaks.toml` detect.
betterleaks v2's default rules alone catch 26 of the 34 fixtures; `betterleaks.toml` adds 7 custom
rules for the rest (agora, alchemy, amazon-mws, asana, azure management certificate, beamer, and a
generic bearer token rule), plus one for secret-named .NET `appSettings` entries
(`dotnet-appsetting-secret`) found by the benchmark. 33 of 34 fixtures are detected; `aws.txt` is intentionally left
undetected because its values contain the literal word "fake" (`ASIIAMFAKE...`) and its key ID
isn't a valid AWS prefix. If a new fixture is added or a rule's format changes, update both
`betterleaks.toml` and the baseline in the test.

The asana, beamer and bearer rules are loose, generic fallbacks for credential shapes whose
fixtures omit the service name, so they carry `confidence = "low"` and an entropy /
token-efficiency filter to drop readable or repetitive values. A global `filter` in
`betterleaks.toml` drops only unambiguous placeholders (`YOUR_API_KEY_HERE`, `changeme`,
`<redacted>`), values that are entirely a variable reference (`${VAR}`, `$(cmd)`, `{{ x }}`,
`%VAR%`), a single repeated character, or at least 80% `x`/`X`/`0`/`*` filler (a `${` or a
`00000000` run inside a longer value is kept), published documentation samples by exact value
(AWS docs key pair, jwt.io token, OAuth RFC examples, Flask's docs `SECRET_KEY`s), and a few skips
scoped to default rules by `finding.rule_id`: letters-only `generic-password` values in locale
files, hex digests under hash-named keys (`token_sha`) for `generic-api-key`, dependency versions
for `generic-password`, and bare credential words (`password`, `pass#pass`) for
`generic-password`/`generic-credential-uri` in test, example and docs paths. Those skips live in
the global filter because redefining a default rule replaces it entirely (and a global filter
can't change a finding's confidence, which is why the sample-path demotion lives in
`gitscrapper.py`). There is deliberately no exclusion by the word `EXAMPLE` or by test/fixture
paths: real secrets turn up there too.
