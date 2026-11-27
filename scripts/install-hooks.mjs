#!/usr/bin/env node
// Turns on the hooks in .githooks (pre-commit: node scripts/check.mjs --fast and gitleaks on staged
// changes; commit-msg: rule S3) by setting core.hooksPath for this clone.
//   node scripts/install-hooks.mjs              set core.hooksPath=.githooks
//   node scripts/install-hooks.mjs --dry-run    say what it would do
//   node scripts/install-hooks.mjs --uninstall  unset it
// core.hooksPath lives in the clone's shared config, so in a clone with several worktrees it would
// apply to commits in all of them, including branches made before these hooks existed. There it
// changes nothing and prints the per-commit form instead: git -c core.hooksPath=.githooks commit ...
// Does nothing in CI or outside a git checkout. No dependencies (Node 24).
import { spawnSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const args = process.argv.slice(2)
const bad = args.filter((a) => !['--dry-run', '--uninstall'].includes(a))
if (bad.length) {
  console.error(`unknown argument ${bad.join(' ')}\nusage: node scripts/install-hooks.mjs [--dry-run] [--uninstall]`)
  process.exit(2)
}
const dry = args.includes('--dry-run')
const git = (a) => spawnSync('git', ['-C', ROOT, ...a], { encoding: 'utf8' })

if (process.env.CI) process.exit(0)
if (git(['rev-parse', '--git-dir']).status !== 0) {
  console.log('not a git checkout: nothing to do')
  process.exit(0)
}
const worktrees = git(['worktree', 'list', '--porcelain']).stdout.split('\n').filter((l) => l.startsWith('worktree ')).length
const current = git(['config', '--get', 'core.hooksPath']).stdout.trim()

if (args.includes('--uninstall')) {
  if (!current) console.log('core.hooksPath is not set: nothing to undo')
  else if (dry) console.log(`(--dry-run) would run: git config --unset core.hooksPath (now "${current}")`)
  else {
    git(['config', '--unset', 'core.hooksPath'])
    console.log(`unset core.hooksPath (was "${current}")`)
  }
  process.exit(0)
}
if (current === '.githooks') {
  console.log('hooks already on (core.hooksPath=.githooks)')
  process.exit(0)
}
if (worktrees > 1) {
  console.log(`this clone has ${worktrees} worktrees, and core.hooksPath would apply to commits in all of them. Not changed.`)
  console.log('Run the hooks for one commit instead:  git -c core.hooksPath=.githooks commit ...')
  console.log('or call them directly:                 sh .githooks/pre-commit   and   sh .githooks/commit-msg <message file>')
  process.exit(0)
}
if (current) console.log(`note: core.hooksPath was "${current}"`)
if (dry) {
  console.log('(--dry-run) would run: git config core.hooksPath .githooks')
  process.exit(0)
}
const r = git(['config', 'core.hooksPath', '.githooks'])
if (r.status !== 0) {
  console.error(`could not set core.hooksPath: ${(r.stderr || '').trim()}`)
  process.exit(1)
}
console.log('hooks on: core.hooksPath=.githooks (pre-commit runs node scripts/check.mjs --fast, commit-msg checks rule S3)')
