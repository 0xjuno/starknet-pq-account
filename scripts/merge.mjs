#!/usr/bin/env node
// Merges a pull request only when this repository's own CI passed on it. Until main has a branch
// protection rule with these checks required, this script is the gate; after that it is a second look.
//   node scripts/merge.mjs <PR number> [--merge|--squash|--rebase] [--delete-branch] [--dry-run] [--guardrail-change]
//   node scripts/merge.mjs --self-test
// It refuses (exit code 1) unless:
//   1. the PR is OPEN, not a draft, and GitHub does not report it BEHIND, DIRTY (conflicts) or UNKNOWN
//   2. among `gh pr checks`, those from workflow "tests" with event "pull_request" hold each required
//      job exactly once and every one passed. The same name twice, or a required name reported by
//      another workflow or event, is refused: an always-green workflow with the same job names must
//      not stand in for the real one
//   3. the PR does not touch the guardrail files (GUARDRAIL_PATHS), unless a person read that change
//      and passes --guardrail-change: a PR that edits a check and the code it checks turns every job green
//   4. `gh pr merge --match-head-commit <checked head>` so a push between the check and the merge is refused
// Default method --merge (this repository's history uses merge commits). Needs gh, logged in.
import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

/** Job names in .github/workflows/ci.yml (workflow "tests"). The branch protection rule requires the same list */
export const REQUIRED_CHECKS = ['contracts', 'falcon-differential', 'pf04-budgets', 'recovery', 'secrets', 'lint']
export const CI_WORKFLOW = 'tests'
export const CI_EVENT = 'pull_request'
/** Files that define the checks or their thresholds (repository-relative) */
export const GUARDRAIL_PATHS = [
  /^\.github\//,
  /^\.githooks\//,
  /^\.gitleaks\.toml$/,
  /^rules\//,
  /^scripts\/(?:check|check_rules|cairo_tests|merge|install-hooks|release_manifest|build_page)\.mjs$/,
  /^vendor\/provably-fast\/falcon-512\/(?:make_crates\.sh|SHA256SUMS)$/,
  /^bench\/pf0[34]\/run\.sh$/,
  /^bench\/pf04\/(?:budgets|network_libfuncs)\.json$/,
  /^signer\/(?:verifier_switch_check|verifiers_check)\.mjs$/,
  /^signer\/package\.json$/,
]

/** Judges `gh pr checks --json name,state,bucket,link,workflow,event`. Returns { refuse: string[], counted } */
export function judgeChecks(checks) {
  const refuse = []
  if (!Array.isArray(checks)) return { refuse: ['could not read the check list'], counted: [] }
  const ours = (c) => c.workflow === CI_WORKFLOW && c.event === CI_EVENT
  const ci = checks.filter(ours)
  for (const name of REQUIRED_CHECKS) {
    const same = ci.filter((c) => c.name === name)
    if (same.length === 0) refuse.push(`required check ${name} missing from workflow ${CI_WORKFLOW} (${CI_EVENT}): CI has not run, or the job was renamed`)
    else if (same.length > 1) refuse.push(`required check ${name} appears ${same.length} times in workflow ${CI_WORKFLOW} (${CI_EVENT})`)
    else if (same[0].bucket !== 'pass') refuse.push(`required check ${name}: ${same[0].bucket}/${same[0].state} ${same[0].link ?? ''}`)
  }
  for (const c of checks) {
    if (!ours(c) && REQUIRED_CHECKS.includes(c.name)) refuse.push(`required check name ${c.name} also reported by workflow ${c.workflow ?? '?'}, event ${c.event ?? '?'}: a name clash is refused ${c.link ?? ''}`)
    if (!ours(c) && c.bucket === 'fail') refuse.push(`other check ${c.name} (workflow ${c.workflow ?? '?'}) failed ${c.link ?? ''}`)
  }
  return { refuse, counted: ci }
}

export function guardrailHits(files) {
  return (files ?? []).filter((f) => GUARDRAIL_PATHS.some((re) => re.test(f)))
}

/** The PR state checks, without the checks list */
export function judgeView(view) {
  const refuse = []
  if (view.state !== 'OPEN') refuse.push(`PR state is ${view.state}, not OPEN`)
  if (view.isDraft) refuse.push('draft PR')
  if (view.mergeable === 'CONFLICTING') refuse.push('conflicts with the base: rebase first')
  if (view.mergeStateStatus === 'BEHIND') refuse.push(`behind ${view.baseRefName}: update the branch and let CI pass again`)
  else if (view.mergeStateStatus === 'DIRTY') refuse.push('conflicts with the base (DIRTY): rebase first')
  else if (view.mergeStateStatus === 'UNKNOWN') refuse.push('GitHub is still computing mergeability (UNKNOWN): try again shortly')
  return refuse
}

function selfTest() {
  const pass = (name, extra = {}) => ({ name, state: 'SUCCESS', bucket: 'pass', workflow: CI_WORKFLOW, event: CI_EVENT, link: '', ...extra })
  const green = REQUIRED_CHECKS.map((n) => pass(n))
  const cases = [
    ['all six pass', green, 0],
    ['one missing', green.slice(1), 1],
    ['one failing', [...green.slice(1), pass('contracts', { bucket: 'fail', state: 'FAILURE' })], 1],
    ['one pending', [...green.slice(1), pass('contracts', { bucket: 'pending', state: 'IN_PROGRESS' })], 1],
    ['an always-green workflow reports the same six names', [...green, ...REQUIRED_CHECKS.map((n) => pass(n, { workflow: 'probe' }))], 6],
    ['real CI red, a look-alike workflow green', [...green.filter((c) => c.name !== 'lint'), pass('lint', { bucket: 'fail' }), pass('lint', { workflow: 'probe' })], 2],
    ['the same job twice in our workflow', [...green, pass('secrets')], 1],
    ['our names from a push event only', REQUIRED_CHECKS.map((n) => pass(n, { event: 'push' })), 12],
    ['another workflow fails', [...green, pass('coverage', { workflow: 'coverage board', bucket: 'fail' })], 1],
    ['not a list', null, 1],
  ]
  let fail = 0
  for (const [what, checks, want] of cases) {
    const got = judgeChecks(checks).refuse.length
    if (got !== want) fail++
    console.log(`${got === want ? 'ok  ' : 'FAIL'} checks: ${what} (refusals ${got}, want ${want})`)
  }
  const files = ['README.md', '.github/workflows/ci.yml', 'rules/rules.md', 'scripts/check_rules.mjs', 'bench/pf04/budgets.json', 'contracts/src/lib.cairo', 'scripts/check.mjs', '.gitleaks.toml', 'signer/demo.mjs', 'vendor/provably-fast/falcon-512/make_crates.sh']
  const hits = guardrailHits(files)
  const want = ['.github/workflows/ci.yml', 'rules/rules.md', 'scripts/check_rules.mjs', 'bench/pf04/budgets.json', 'scripts/check.mjs', '.gitleaks.toml', 'vendor/provably-fast/falcon-512/make_crates.sh']
  const g = JSON.stringify(hits) === JSON.stringify(want)
  if (!g) fail++
  console.log(`${g ? 'ok  ' : 'FAIL'} guardrail paths: ${hits.length} of ${files.length} files flagged (want ${want.length})`)
  const views = [
    [{ state: 'OPEN', isDraft: false, mergeable: 'MERGEABLE', mergeStateStatus: 'CLEAN' }, 0],
    [{ state: 'MERGED', isDraft: false, mergeable: 'UNKNOWN', mergeStateStatus: 'UNKNOWN' }, 2],
    [{ state: 'OPEN', isDraft: true, mergeable: 'MERGEABLE', mergeStateStatus: 'BEHIND', baseRefName: 'main' }, 2],
  ]
  for (const [v, w] of views) {
    const got = judgeView(v).length
    if (got !== w) fail++
    console.log(`${got === w ? 'ok  ' : 'FAIL'} PR state ${v.state}${v.isDraft ? ' draft' : ''} ${v.mergeStateStatus} (refusals ${got}, want ${w})`)
  }
  console.log(`merge self-test: ${cases.length + 1 + views.length - fail} passed, ${fail} failed`)
  process.exitCode = fail ? 1 : 0
}

function gh(args, { allowFail = false } = {}) {
  // gh is an executable: no shell, so arguments never pass through one
  const r = spawnSync('gh', args, { encoding: 'utf8', maxBuffer: 64 << 20 })
  if (r.error) {
    console.error(`could not run gh: ${r.error.message}`)
    process.exit(1)
  }
  if (r.status !== 0 && !allowFail) {
    console.error(`gh ${args.join(' ')} failed: ${(r.stderr || r.stdout || '').trim()}`)
    process.exit(1)
  }
  return r
}

function main(args) {
  if (args.includes('--self-test')) return selfTest()
  const pr = args.find((a) => /^\d+$/.test(a))
  const known = new Set(['--squash', '--merge', '--rebase', '--delete-branch', '--dry-run', '--guardrail-change'])
  const bad = args.filter((a) => !/^\d+$/.test(a) && !known.has(a))
  if (!pr || bad.length) {
    console.error(`usage: node scripts/merge.mjs <PR number> [--merge|--squash|--rebase] [--delete-branch] [--dry-run] [--guardrail-change] | --self-test${bad.length ? `\nunknown: ${bad.join(' ')}` : ''}`)
    process.exit(2)
  }
  const method = args.includes('--squash') ? '--squash' : args.includes('--rebase') ? '--rebase' : '--merge'
  const view = JSON.parse(gh(['pr', 'view', pr, '--json', 'number,state,isDraft,baseRefName,headRefName,headRefOid,mergeable,mergeStateStatus,title,url']).stdout)
  console.log(`PR #${view.number} ${view.title}\n  ${view.headRefName} -> ${view.baseRefName}, ${view.state}${view.isDraft ? ' (draft)' : ''}, mergeable ${view.mergeable}, mergeStateStatus ${view.mergeStateStatus}, head ${view.headRefOid}\n  ${view.url}`)
  const refuse = judgeView(view)

  // gh pr checks exits non-zero when a check failed or none exist; the JSON list still comes out
  const raw = gh(['pr', 'checks', pr, '--json', 'name,state,bucket,link,workflow,event'], { allowFail: true })
  let checks = null
  try {
    checks = JSON.parse(raw.stdout || '[]')
  } catch {
    refuse.push(`could not read gh pr checks: ${(raw.stderr || raw.stdout || '').trim().slice(0, 200)}`)
  }
  const judged = judgeChecks(checks)
  refuse.push(...judged.refuse)
  console.log(`checks ${checks?.length ?? 0} (counted ${judged.counted.length}): ${(checks ?? []).map((c) => `${c.name}[${c.workflow ?? '?'}/${c.event ?? '?'}]=${c.bucket}`).join(', ') || 'none'}`)

  const files = gh(['api', `repos/{owner}/{repo}/pulls/${pr}/files`, '--paginate', '--jq', '.[].filename']).stdout.split('\n').map((s) => s.trim()).filter(Boolean)
  const hits = guardrailHits(files)
  console.log(`files changed ${files.length}, guardrail files ${hits.length}`)
  for (const f of hits) console.log(`  guardrail: ${f}`)
  if (hits.length && !args.includes('--guardrail-change')) refuse.push(`the PR changes ${hits.length} guardrail file(s). Read that change; if it is right, run again with --guardrail-change`)

  if (refuse.length) {
    console.error('\nnot merging:')
    for (const r of refuse) console.error(`  - ${r}`)
    process.exit(1)
  }
  const mergeArgs = ['pr', 'merge', pr, method, '--match-head-commit', view.headRefOid]
  if (args.includes('--delete-branch')) mergeArgs.push('--delete-branch')
  if (args.includes('--dry-run')) {
    console.log(`\n(--dry-run) all conditions hold. Would run: gh ${mergeArgs.join(' ')}`)
    return
  }
  console.log(`\nall ${REQUIRED_CHECKS.length} required checks passed (workflow ${CI_WORKFLOW}, ${CI_EVENT}). gh ${mergeArgs.join(' ')}`)
  gh(mergeArgs)
  console.log('merged')
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv.slice(2))
