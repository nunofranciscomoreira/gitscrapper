# gitscrapper
Automation for gitleaks to use in large gitlab instances.

In the future it will support github enterprise instances, but I don't have an instance to test.

## How to

Generate a personal access token for the git instance

https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html#create-a-personal-access-token

```sh
git clone https://github.com/nunofranciscomoreira/gitscrapper
git clone https://github.com/gitleaks/gitleaks
pip install -r gitscrapper/requirements.txt
cp gitscrapper/gitscrapper.py gitleaks
cd gitleaks
mkdir repositories leaks_reports
export GIT_ENDPOINT="https://gitlab.example.com"
export GIT_PRIVATE_TOKEN="<your personal access token>"
python3 gitscrapper.py
```

`gitleaks` must be on your `PATH`, or point `GITLEAKS_BIN` at the binary.

## Output

For each project, `leaks_reports/secrets_<name>.json` holds any findings (with the
repo's web URL prepended) if leaks were found, and is removed automatically if the
scan was clean. `leaks_reports/<date>_clean_repos.txt` and
`leaks_reports/<date>_pwned_repos.txt` list which repos fell into each bucket.

## test_fixtures/

`test_fixtures/` contains synthetic, fake credentials (not real secrets) used to
sanity-check that a secret-detection regex/rule actually matches a given format
(AWS keys, JWTs, PEM keys, etc.). They aren't read by `gitscrapper.py` itself.
