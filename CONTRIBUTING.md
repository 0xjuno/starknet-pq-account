# Contributing

The rules this repository holds itself to are checks that fail, not text to remember. CI runs
them on every pull request and on main (`.github/workflows/ci.yml`, workflow `tests`), and you can
run the same checks before you push.

## Run the checks locally

```
node scripts/check.mjs           # what the CI lint job runs: rules (self-test first), the merge and
                                 # test-count judges' self-tests, docs page and candidate crates --check
node scripts/check.mjs --fast    # rules and self-tests only, under a second
node scripts/check.mjs --full    # also the release manifest and the exact test counts
```

`--full` needs scarb 2.18.0 on PATH (or `SCARB=<path to scarb>`), a build (`cd contracts && scarb
build`) and `npm install` in `signer/`. Each check prints its own result and the run ends with a
summary; nothing stops at the first failure. Node 24, no packages to install.

Secrets: CI runs gitleaks 8.30.1 with `.gitleaks.toml`, on the commits a run adds and on the whole
tree. Locally:

```
gitleaks git . --redact -c .gitleaks.toml --log-opts="origin/main..HEAD"
gitleaks dir . --redact -c .gitleaks.toml
```

`gitleaks dir` also reads untracked and ignored files (build output, local key files). A hit in a
file git does not track is not in the repository, but look at it anyway.

The rules, why each one exists and how to add an exception: [`rules/rules.md`](rules/rules.md).

## Turn on the hooks

`node scripts/install-hooks.mjs` sets `core.hooksPath=.githooks` for this clone:

- pre-commit: `node scripts/check.mjs --fast`, then `gitleaks git --staged` when gitleaks is
  installed (`GITLEAKS=<path>` for a binary that is not on PATH)
- commit-msg: no `Co-Authored-By:` lines (rule S3)

In a clone with several worktrees the script changes nothing, because the setting would reach
commits in every worktree. Use `git -c core.hooksPath=.githooks commit ...` for one commit, or run
`sh .githooks/pre-commit` yourself. `node scripts/install-hooks.mjs --uninstall` turns them off,
and `git commit --no-verify` skips them once; CI checks again either way.

## Commit messages

No `Co-Authored-By:` lines (rule S3). CI checks every commit a pull request adds.

## Merge with scripts/merge.mjs

```
node scripts/merge.mjs <PR number> --dry-run
node scripts/merge.mjs <PR number>
```

It merges (merge commit, as in this repository's history) only when the PR is open, not a draft
and up to date with main, and the six jobs of workflow `tests` (contracts, falcon-differential,
pf04-budgets, recovery, secrets, lint) passed on the `pull_request` event, each reported exactly
once. A required job name reported by another workflow is refused. A PR that changes a guardrail
file (CI, hooks, gitleaks config, rules, check scripts, budgets) is refused until you have read
that change and pass `--guardrail-change`. When main's branch protection rule requires the same
six checks, the script is a second look.

## Change the number of tests

`scripts/cairo_tests.mjs` checks the number of passing tests exactly: 109 in `contracts/` and 7 in
`recovery/` (main, 2026-11-27). A pull request that adds or removes tests updates `EXPECTED` in
that file in the same pull request, so the change shows in review. An `#[ignore]`d or filtered test
also fails the check. If a package gains a second test target, the script fails until it counts
each target.
