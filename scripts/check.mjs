#!/usr/bin/env node
// One command for the repository's checks. CI's lint job runs the default set; nothing needs installing.
//   node scripts/check.mjs                 rules (their self-test first), the judges' self-tests, docs page, candidate crates
//   node scripts/check.mjs --fast          rules and self-tests only, under a second (.githooks/pre-commit)
//   node scripts/check.mjs --full          also the release manifest and the exact test counts
//                                          (needs scarb, `cd contracts && scarb build`, and `npm install` in signer/)
//   --commits A..B                         also S3 on the messages of those commits (CI passes the PR range).
//                                          Without it a local run checks origin/main..HEAD when origin/main exists
// A check whose script is missing fails: deleting a checker must not make the run pass. A check that
// needs a tool this machine lacks is listed as skipped, with the reason. Exit code 1 if any check failed.
// No dependencies (Node 24).
import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const NODE = process.execPath

function git(args) {
  try {
    return execFileSync('git', ['-C', ROOT, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  } catch {
    return null
  }
}

/** bash for make_crates.sh. On Windows, Git's own bash: the bash.exe in System32 starts WSL instead */
function findBash() {
  if (process.env.BASH_FOR_CHECKS) return process.env.BASH_FOR_CHECKS
  if (process.platform !== 'win32') return 'bash'
  const exec = git(['--exec-path'])
  if (!exec) return null
  const gitRoot = exec.replace(/[\\/](?:mingw64|mingw32|ucrt64|clang64|clangarm64)[\\/]libexec[\\/]git-core$/i, '')
  for (const p of ['bin/bash.exe', 'usr/bin/bash.exe']) if (existsSync(join(gitRoot, p))) return join(gitRoot, p)
  return null
}

function hasTool(cmd, args = ['--version']) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
  return !r.error && r.status === 0
}

function main() {
  const args = process.argv.slice(2)
  const known = new Set(['--fast', '--full', '--commits'])
  for (let i = 0; i < args.length; i++) {
    if (!known.has(args[i])) {
      console.error(`unknown argument ${args[i]}\nusage: node scripts/check.mjs [--fast|--full] [--commits A..B]`)
      process.exit(2)
    }
    if (args[i] === '--commits') i++
  }
  const fast = args.includes('--fast')
  const full = args.includes('--full')
  let range = args.includes('--commits') ? args[args.indexOf('--commits') + 1] : undefined
  if (args.includes('--commits') && !range) {
    console.error('--commits needs a range A..B')
    process.exit(2)
  }
  let rangeNote = range ? `S3 on ${range}` : 'S3 not run'
  if (!range && !fast && git(['rev-parse', '--verify', '-q', 'origin/main'])) {
    const ahead = git(['rev-list', '--count', 'origin/main..HEAD'])
    if (ahead && ahead !== '0') {
      range = 'origin/main..HEAD'
      rangeNote = `S3 on origin/main..HEAD (${ahead} commits)`
    } else rangeNote = 'S3 not run: no commits ahead of origin/main'
  }
  const bash = findBash()
  const scarb = process.env.SCARB || 'scarb'

  // make_crates.sh runs `git apply` in a temp folder outside the repository, where .gitattributes
  // (eol=lf) does not reach. Git for Windows sets core.autocrlf=true system-wide, so the patched files
  // would come out CRLF and differ from crates/. Turn it off for this child process only.
  const lfGit = { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'core.autocrlf', GIT_CONFIG_VALUE_0: 'false' }
  // [name, command, script that must exist, set (fast | default | full), reason to skip or null, extra env]
  const CHECKS = [
    ['rules self-test', [NODE, 'scripts/check_rules.mjs', '--self-test'], 'scripts/check_rules.mjs', 'fast'],
    [`rules (${rangeNote})`, [NODE, 'scripts/check_rules.mjs', ...(range ? ['--commits', range] : [])], 'scripts/check_rules.mjs', 'fast'],
    ['merge judge self-test', [NODE, 'scripts/merge.mjs', '--self-test'], 'scripts/merge.mjs', 'fast'],
    ['test-count judge self-test', [NODE, 'scripts/cairo_tests.mjs', '--self-test'], 'scripts/cairo_tests.mjs', 'fast'],
    ['docs/index.html is built from its template', [NODE, 'scripts/build_page.mjs', '--check'], 'scripts/build_page.mjs', 'default'],
    ['candidate crates match baseline + pinned patches', [bash, 'vendor/provably-fast/falcon-512/make_crates.sh', '--check'], 'vendor/provably-fast/falcon-512/make_crates.sh', 'default', () => (bash ? null : 'no bash found (Git for Windows ships one; or set BASH_FOR_CHECKS)'), lfGit],
    ['built classes match the release manifest', [NODE, 'scripts/release_manifest.mjs', '--check'], 'scripts/release_manifest.mjs', 'full', () => (!existsSync(join(ROOT, 'contracts/target/dev')) ? 'no contracts/target/dev: run `cd contracts && scarb build`' : !existsSync(join(ROOT, 'signer/node_modules/starknet')) ? 'no signer/node_modules: run `npm install` in signer/' : null)],
    ['contracts test count', [NODE, 'scripts/cairo_tests.mjs', 'contracts'], 'scripts/cairo_tests.mjs', 'full', () => (hasTool(scarb) ? null : `no scarb (${scarb}); set SCARB to the binary`)],
    ['recovery test count', [NODE, 'scripts/cairo_tests.mjs', 'recovery'], 'scripts/cairo_tests.mjs', 'full', () => (hasTool(scarb) ? null : `no scarb (${scarb}); set SCARB to the binary`)],
  ]
  const wanted = (set) => set === 'fast' || (set === 'default' && !fast) || (set === 'full' && full)

  let failed = 0
  const rows = []
  for (const [name, cmd, file, set, skip, env] of CHECKS) {
    if (!wanted(set)) continue
    if (!existsSync(join(ROOT, file))) {
      failed++
      rows.push(['FAIL', name, `${file} is missing`])
      continue
    }
    const why = skip?.()
    if (why) {
      rows.push(['skip', name, why])
      continue
    }
    console.log(`\n== ${name}`)
    const t0 = Date.now()
    const r = spawnSync(cmd[0], cmd.slice(1), { cwd: ROOT, stdio: 'inherit', env: { ...process.env, ...env } })
    const sec = ((Date.now() - t0) / 1000).toFixed(1)
    if (r.status === 0) rows.push(['pass', name, `${sec}s`])
    else {
      failed++
      rows.push(['FAIL', name, r.error ? r.error.message : `exit code ${r.status ?? r.signal}, ${sec}s`])
    }
  }
  console.log(`\n== check.mjs ${fast ? '--fast' : full ? '--full' : '(default)'}`)
  for (const [state, name, note] of rows) console.log(`${state.padEnd(4)}  ${name}: ${note}`)
  console.log(failed ? `${failed} check(s) failed` : 'all checks passed')
  process.exit(failed ? 1 : 0)
}

main()
