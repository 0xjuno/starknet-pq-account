#!/usr/bin/env node
// Runs `scarb cairo-test` in one package and checks the count exactly (==) against EXPECTED.
// A deleted or #[ignore]d test lowers the count and fails here, and so does a PR that drops one
// test and adds another, so a change to the number shows up in the diff of this file.
//
//   node scripts/cairo_tests.mjs contracts      CI contracts job (after its Test step)
//   node scripts/cairo_tests.mjs recovery       CI recovery job
//   node scripts/cairo_tests.mjs --self-test    the judge on recorded outputs
//   --log FILE    judge a saved `scarb cairo-test` output instead of running scarb
//
// SCARB=<path> picks the scarb binary (default: scarb on PATH). No dependencies (Node 24).
// A PR that adds or removes tests updates EXPECTED in the same PR (CONTRIBUTING.md).
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..')
/** Passing tests per package, measured on main 78350fc on 2026-11-27 (scarb 2.18.0) */
export const EXPECTED = { contracts: 109, recovery: 7 }

const SUMMARY = /^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) filtered out;/gm

/** Reads the last summary block of a `scarb cairo-test` output. Returns { passed, failed, ignored, filtered, problems } */
export function judge(out, exitCode, expected) {
  const problems = []
  if (exitCode !== 0) problems.push(`scarb cairo-test exit code ${exitCode}`)
  const targets = (out.match(/^\s*Compiling test\(/gm) ?? []).length
  if (targets > 1) problems.push(`${targets} test targets compiled; this script reads one summary per package, so count each target before raising EXPECTED`)
  const all = [...out.matchAll(SUMMARY)]
  if (!all.length) {
    problems.push("no summary line ('test result: ok. N passed; M failed; K ignored; F filtered out;')")
    return { problems }
  }
  const m = all[all.length - 1]
  const r = { result: m[1], passed: Number(m[2]), failed: Number(m[3]), ignored: Number(m[4]), filtered: Number(m[5]) }
  if (r.result !== 'ok') problems.push(`result ${r.result}`)
  if (r.failed) problems.push(`${r.failed} failed`)
  if (r.ignored) problems.push(`${r.ignored} ignored (an #[ignore]d test is a deleted test for this count)`)
  if (r.filtered) problems.push(`${r.filtered} filtered out (run without a filter)`)
  if (r.passed !== expected) problems.push(`passed ${r.passed} != expected ${expected}. If the PR adds or removes tests on purpose, change EXPECTED in scripts/cairo_tests.mjs in the same PR`)
  return { ...r, problems }
}

function selfTest() {
  const ok = (n) => `   Compiling test(pq_x_unittest) pq_x v0.1.0\n    Finished \`dev\` profile target(s) in 1 second\nrunning ${n} tests\ntest pq_x::a ... ok\ntest result: ok. ${n} passed; 0 failed; 0 ignored; 0 filtered out;\n`
  const cases = [
    ['exact count passes', ok(7), 0, 7, 0],
    ['one test fewer fails', ok(6), 0, 7, 1],
    ['one test more fails', ok(8), 0, 7, 1],
    ['a failed test fails', '   Compiling test(pq_x_unittest)\ntest result: FAILED. 6 passed; 1 failed; 0 ignored; 0 filtered out;\n', 1, 7, 4],
    ['an ignored test fails', '   Compiling test(pq_x_unittest)\ntest result: ok. 6 passed; 0 failed; 1 ignored; 0 filtered out;\n', 0, 7, 2],
    ['a filter fails', '   Compiling test(pq_x_unittest)\ntest result: ok. 3 passed; 0 failed; 0 ignored; 4 filtered out;\n', 0, 7, 2],
    ['a summary printed by a test does not count; the last block does', 'test pq_x::a ... ok\ntest result: ok. 7 passed; 0 failed; 0 ignored; 0 filtered out;\n' + ok(6), 0, 7, 1],
    ['no summary fails', 'error: could not compile\n', 1, 7, 2],
    ['two test targets fail', ok(4) + ok(3), 0, 7, 2],
  ]
  let fail = 0
  for (const [what, out, code, want, problems] of cases) {
    const j = judge(out, code, want)
    const good = j.problems.length === problems
    if (!good) fail++
    console.log(`${good ? 'ok  ' : 'FAIL'} ${what} (problems ${j.problems.length}, want ${problems})`)
  }
  console.log(`cairo_tests self-test: ${cases.length - fail} passed, ${fail} failed`)
  process.exitCode = fail ? 1 : 0
}

function main(args) {
  if (args.includes('--self-test')) return selfTest()
  const pkg = args.find((a) => !a.startsWith('--') && args[args.indexOf(a) - 1] !== '--log')
  const li = args.indexOf('--log')
  const logFile = li >= 0 ? args[li + 1] : undefined
  if (!pkg || !(pkg in EXPECTED) || (li >= 0 && !logFile)) {
    console.error(`usage: node scripts/cairo_tests.mjs <${Object.keys(EXPECTED).join('|')}> [--log FILE] | --self-test`)
    process.exit(2)
  }
  let out
  let code = 0
  const t0 = Date.now()
  if (logFile) out = readFileSync(logFile, 'utf8')
  else {
    const scarb = process.env.SCARB || 'scarb'
    // scarb is an executable: no shell, so arguments never pass through one
    const r = spawnSync(scarb, ['cairo-test'], { cwd: resolve(REPO, pkg), encoding: 'utf8', maxBuffer: 256 << 20 })
    if (r.error) {
      console.error(`could not run ${scarb}: ${r.error.message} (set SCARB to the scarb binary)`)
      process.exit(1)
    }
    out = (r.stdout ?? '') + (r.stderr ?? '')
    code = r.status ?? 1
    process.stdout.write(out)
  }
  const j = judge(out, code, EXPECTED[pkg])
  const sec = ((Date.now() - t0) / 1000).toFixed(1)
  console.log(`\n${pkg} tests: passed ${j.passed ?? '?'}, failed ${j.failed ?? '?'}, ignored ${j.ignored ?? '?'}, filtered ${j.filtered ?? '?'}, expected ${EXPECTED[pkg]}${logFile ? ` (from ${logFile})` : `, ${sec}s`}`)
  if (j.problems.length) {
    for (const p of j.problems) console.error(`error: ${p}`)
    process.exit(1)
  }
  console.log(`${pkg} test count matches`)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv.slice(2))
