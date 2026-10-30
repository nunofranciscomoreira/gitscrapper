#!/usr/bin/python3
"""Held-out evaluation of betterleaks.toml on well-known public repositories.

Clones each repo (full history) into .eval/ next to gitscrapper.py, scans it
with the pinned config in full mode, and prints every finding with its rule,
triage tier and priority, then per-rule totals. These repos hold no live
credentials, so each finding is a false-positive candidate to review: one
that is clearly a test, sample or placeholder value calls for the narrowest
filter in betterleaks.toml and a new file in test_fixtures_negative/.

    python3 tools/evaluate_real_repos.py [--show-values] [--refresh] [URL ...]
"""
import argparse
import collections
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import gitscrapper as g  # noqa: E402  pylint: disable=wrong-import-position

DEFAULT_REPOS = (
    "https://github.com/pallets/flask",
    "https://github.com/pallets/click",
    "https://github.com/psf/requests",
    "https://github.com/expressjs/express",
    "https://github.com/axios/axios",
    "https://github.com/spf13/cobra",
)
SCRATCH_DIR = os.path.join(g.SCRIPT_DIR, ".eval")
MAX_VALUE_CHARS = 100


def repo_name(url):
    owner, repo = url.rstrip("/").removesuffix(".git").split("/")[-2:]
    return f"{owner}-{repo}"


def ensure_clone(url, name, refresh):
    if os.path.isdir(os.path.join(g.repo_path(name), ".git")):
        if refresh:
            subprocess.run(["git", "-C", g.repo_path(name), "fetch", "--quiet", "--tags"], check=True)
        return
    subprocess.run(["git", "clone", "--quiet", url, g.repo_path(name)], check=True)


def scan(name):
    result = g.betterleaks_check(name, "full")
    if result.returncode not in (0, g.LEAKS_EXIT_CODE):
        raise SystemExit(f"betterleaks failed on {name}: {result.stderr.strip()}")
    if not os.path.exists(g.report_path(name)):
        return []
    with open(g.report_path(name), encoding="utf-8") as report_file:
        return json.load(report_file).get("findings") or []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repos", nargs="*", default=DEFAULT_REPOS, help="git URLs to scan")
    parser.add_argument("--show-values", action="store_true", help="print secrets unmasked")
    parser.add_argument("--refresh", action="store_true", help="fetch existing clones first")
    args = parser.parse_args()

    os.makedirs(os.path.join(SCRATCH_DIR, g.REPOSITORIES_DIR), exist_ok=True)
    os.makedirs(os.path.join(SCRATCH_DIR, g.LEAKS_REPORTS_DIR), exist_ok=True)
    os.chdir(SCRATCH_DIR)

    per_rule = collections.Counter()
    tiers = collections.Counter()
    for url in args.repos:
        name = repo_name(url)
        ensure_clone(url, name, args.refresh)
        findings = scan(name)
        print(f"\n{name}: {len(findings)} finding(s)")
        for finding in findings:
            tier = g.finding_tier(finding)
            value = finding["match"]["value"].replace("\n", "\\n")[:MAX_VALUE_CHARS]
            location = finding["location"]
            per_rule[(finding["rule_id"], tier)] += 1
            tiers[tier] += 1
            print(
                f"  [{tier} p{g.finding_priority(finding)}] {finding['rule_id']} "
                f"{location['path']}:{location.get('start_line')} "
                f"{value if args.show_values else g.mask(value)}"
            )

    print(f"\nTotal: {sum(tiers.values())} finding(s), "
          f"actionable={tiers['actionable']} review={tiers['review']}")
    for (rule_id, tier), count in sorted(per_rule.items()):
        print(f"  {rule_id:<36} {tier:<10} {count}")


if __name__ == "__main__":
    main()
