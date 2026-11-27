# Rules checked by scripts/check_rules.mjs

Each rule below is a mistake this repository has fixed by hand at least twice (S6: once, so it
only warns). A rule that lives only in a document is a weak constraint, so these run in CI (the
`lint` job, through `scripts/check.mjs`) and in the local hooks. When the same fix is made by hand
again, add a rule here and in the checker, with examples in its self-test.

Sources: the maintainers' wallet-testing checklist (item numbers below), commit history, and
the review notes of the PRs named in each rule.

## Running

- `node scripts/check_rules.mjs`: S1, S2, S4 and S5 on the tracked files (`git ls-files`), S6 as
  warnings. Prints `file:line: rule message` and a summary. Exit code 1 on a violation or an
  exception-list error.
- `node scripts/check_rules.mjs --commits A..B`: also S3 on the messages of those commits.
- `node scripts/check_rules.mjs --commit-msg FILE`: S3 on one message (`.githooks/commit-msg`).
- `node scripts/check_rules.mjs --self-test`: the checker's own test (below).
- `--root DIR` checks another tree, for example a `git archive` of a branch.
- On main 78350fc (2026-11-27): self-test 63 passed, 0 failed; 0 violations; 11 S6 warnings;
  0 exceptions. No dependencies, about 0.2 seconds.

## S1 Wallet wording

- What: a sentence that names a wallet must not call what the wallet did a defect.
- Wallet terms: Ready (capital R), Argent, Argent X, Braavos, wallet extension, the wallet.
- Defect words: bug, bugs, buggy, broken, blocks us, blocking us, blocked.
- Why: a warning or a refusal is a wallet protecting its user, and wallet teams read this
  repository. Checklist item 7, written down on 2026-11-17 when our wallet tests were first
  documented, and applied by hand again on 2026-11-21: commit f7b131b on branch
  wallet-connect-probe changed two lines from "blocked" to "refused".
- How the checker reads text: in Markdown, a paragraph or list item is joined across its lines
  and cut into sentences after `.`, `!`, `?` and `;`; a table row is one unit, since its first
  cell says what the row is about. Other files are read line by line.
- "broken" passes when its own subject, the words right before is, are or was, names something
  else: README's security note "could be front-run once ECDSA is broken" shares its sentence with
  an account type, and is not about it.
- Lines on main that S1 leaves alone: README's "Bugs in this code" table row, that security note,
  and "if the active verifier breaks".

## S2 Misspelled names

- What: a name listed in `rules/misspelled-names.json` anywhere outside `vendor/`. Each entry has
  `wrong`, `use`, `reason` and `date`. When a name is corrected by hand, add it to the list.
- Why: checklist item 8 (take a name from the person's own account or the company site). The
  Zealynx reviewer's name was misspelled in README.md and SECURITY.md from 2026-10-27; it was
  corrected by hand on branch wallet-connect-probe (2026-11-17) and on main by PR #4 (commit
  052e533, 2026-11-19).
- The list file itself is the only file S2 does not read.

## S3 Co-Authored-By lines

- What: no `Co-Authored-By:` line in a commit message, in any letter case. CI checks the commits a
  run adds (`--commits base..head` in the lint job); `.githooks/commit-msg` checks each local
  commit.
- Why: removed by hand twice on 2026-11-19, from PR #4 before it was pushed and from six commits
  on branch wallet-connect-probe when it was rebased. One older commit on main (72bed95, PR #3)
  keeps its line; published history is not rewritten.
- No exceptions.

## S4 Control characters

- What: in tracked text files, `vendor/` included, any byte below 0x20 other than tab, LF and CR.
  Binary files are skipped by extension (`BINARY_EXT` in the checker); a new binary type shows up
  as an S4 hit and is added there.
- Why: checklist item 11. Files with Windows paths were edited through shell heredocs and sed, and
  the backslashes in `\f`, `\b` and `\v` turned into control characters, three times on 2026-11-17.

## S5 Scratch files tracked

- What: a tracked path matching `*_tmp.*`, `.fund_tmp*`, `.probe_*` or `docs/_*.html`.
- Why: local scratch files sat next to tracked ones three times: `signer/.fund_tmp.mjs`
  (2026-11-17), `signer/.probe_*_tmp.mjs` and `docs/_phone_test.html` (2026-11-21). None was
  committed; this keeps it that way.

## S6 Fixed fee in a page (warning)

- What: `about <number> STRK` in `.md` and `.html` files outside `vendor/`. A warning: it never
  fails a run.
- Why: checklist item 13. Fees move with the L2 gas price, so a page people act on should give a
  range and be checked against the receipts at each end-to-end run. On 2026-11-21 the gas price
  rose 11% and "about 3" became 3.46 STRK; the page now says "3 to 4". Seen once, hence a warning.
  If it happens again, make it a failure for `docs/` and `signer/*.html`.
- On main: 11 warnings, all measured costs in tables and notes that name their source.

## Exceptions

- `rules/exceptions.json` is an array of `{ rule, file, line_or_pattern, max_hits, reason, date }`
  for S1, S2, S4, S5 and S6 (S3 has none). `file` is a repository path (`*` and `**` allowed).
  `line_or_pattern` is a line number, or text on that line that covers the reported column (for
  S5, text in the path). `max_hits` is how many lines the entry skips (default 1). `reason` says
  why the line is fine and how to remove the exception (10+ characters); `date` is YYYY-MM-DD.
- The run fails on an unknown field, a missing reason or date, an unknown rule, an entry that
  skips nothing (fixed: delete it), and an entry that skips more or fewer lines than `max_hits`
  (spare room would skip a new violation silently).
- Do not loosen a rule to let a change through. If a rule is wrong, change the checker, this file
  and the self-test examples together.

## Self-test

- Every rule has at least two examples it must catch and one it must pass, including the two lines
  fixed in f7b131b (S1) and the main lines above that S1 must leave alone. The examples are written
  with placeholders and filled in at run time, because the checker reads its own file like any
  other.
- It also tests the exception rules, that S1 reports the line of the word in a sentence spread over
  several lines, that S3 reads `git log` output, and the scope: S1 and S2 still read README.md,
  SECURITY.md, docs/index.html, signer/browser-wallet.template.html and contracts/docs; S4 reads
  `vendor/`; S6 reads pages only; build output and node_modules are not read.
- `scripts/check.mjs` runs the self-test before the rules, in CI and in the pre-commit hook, so a
  loosened pattern fails before it can pass anything.
