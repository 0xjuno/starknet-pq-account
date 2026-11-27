#!/usr/bin/env node
// Checks for mistakes this repository has fixed by hand more than once. What each rule is and why:
// rules/rules.md. Exceptions: rules/exceptions.json. Names list for S2: rules/misspelled-names.json.
//
//   node scripts/check_rules.mjs                      S1, S2, S4, S5 on the tracked files; S6 only warns
//   node scripts/check_rules.mjs --self-test          the checker's own test: each rule catches its bad examples and passes its good ones
//   node scripts/check_rules.mjs --commits A..B       S3 on the commit messages in a git range (CI lint job)
//   node scripts/check_rules.mjs --commit-msg FILE    S3 on one commit message (.githooks/commit-msg)
//   --root DIR    check another tree, for example a `git archive` of a branch, with this checkout's
//                 rules and lists. A git checkout is read with `git ls-files`; any other folder is
//                 walked (skipping .git, node_modules, target), and --commits then reads this checkout's git.
//
// Exit code 1 on a violation or an exception-list error, 2 on a usage error. No dependencies (Node 24).
// The self-test examples are written with placeholders ({B}, {D_BRK}, ...) and filled in at run time,
// so this file does not trip its own rules.
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const NAMES_FILE = 'rules/misspelled-names.json'
const EXCEPTIONS_FILE = 'rules/exceptions.json'

// ---------- which files ----------
const SKIP_DIRS = new Set(['.git', 'node_modules', 'target', '.snfoundry_cache', '__pycache__'])
// Binary by extension. Everything else is read as text, so a new binary type shows up as an S4 hit
// and gets added here instead of being skipped silently.
const BINARY_EXT = /\.(?:gif|png|jpe?g|webp|ico|bmp|pdf|zip|gz|tgz|xz|zst|wasm|woff2?|ttf|otf|eot|mp4|webm|mov|mp3|wav|ogg|bin|pickle)$/i
const OTHERS_CODE = (p) => p.startsWith('vendor/')
const isMarkdown = (p) => /\.md$/i.test(p)
const isPage = (p) => /\.(?:md|html?)$/i.test(p)

function walk(root, rel, out) {
  for (const d of readdirSync(join(root, rel), { withFileTypes: true })) {
    const p = rel ? `${rel}/${d.name}` : d.name
    if (d.isDirectory()) {
      if (!SKIP_DIRS.has(d.name)) walk(root, p, out)
    } else if (d.isFile()) out.push(p)
  }
}

function sameDir(a, b) {
  const n = (x) => resolve(x).replace(/[\\/]+$/, '')
  return process.platform === 'win32' ? n(a).toLowerCase() === n(b).toLowerCase() : n(a) === n(b)
}

export function listFiles(root) {
  try {
    const top = execFileSync('git', ['-C', root, 'rev-parse', '--show-toplevel'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
    if (sameDir(top, root)) {
      const out = execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', maxBuffer: 64 << 20 })
      return { how: 'git ls-files', paths: out.split('\0').filter(Boolean) }
    }
  } catch {}
  const paths = []
  walk(root, '', paths)
  return { how: 'walked', paths: paths.sort() }
}

/** A file as the rules see it: path (repository-relative, forward slashes), raw bytes, text, line helpers */
export function makeFile(path, data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8')
  const binary = BINARY_EXT.test(path)
  const text = binary ? '' : buf.toString('utf8')
  const starts = [0]
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1)
  const lineOf = (idx) => {
    let lo = 0
    let hi = starts.length - 1
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1
      if (starts[mid] <= idx) lo = mid
      else hi = mid - 1
    }
    return lo + 1
  }
  const lineText = (line) => text.slice(starts[line - 1], line < starts.length ? starts[line] - 1 : text.length).replace(/\r$/, '')
  return { path, buf, binary, text, lineOf, lineText, colOf: (idx) => idx - starts[lineOf(idx) - 1] }
}

// ---------- S1 helpers: sentences ----------
// A wallet named in the sentence. "Ready" only with a capital R (it is also an English word).
const WALLET_CASED = /\bReady\b/
const WALLET_ANY = /\bargent(?:x)?\b|\bbraavos\b|\bwallet extensions?\b|\bthe wallets?\b/i
// Words that call the wallet's behaviour a defect.
const DEFECT = /\b(?:bugs?|buggy|broken|blocks? us|blocking us|blocked)\b/gi
// Subject words that still point at a wallet when they come right before is/are + the adjective.
const WALLETISH = /^(?:it|they|them|this|that|extension|extensions|wallet|wallets|popup|app|ready|argent|argentx|braavos)(?:'s)?$/i
const hasWallet = (s) => WALLET_CASED.exec(s)?.[0] ?? WALLET_ANY.exec(s)?.[0] ?? null

/**
 * Units of text a sentence cannot cross. Markdown: a paragraph or list item (its lines joined), a
 * table row (the whole row: the first cell names what the row is about), a heading, one line in a
 * code fence. Other files: one line. Returns [{ start, end, whole }] as offsets into the file text.
 */
export function units(f) {
  const out = []
  const { text } = f
  let off = 0
  if (!isMarkdown(f.path)) {
    for (const raw of text.split('\n')) {
      out.push({ start: off, end: off + raw.replace(/\r$/, '').length })
      off += raw.length + 1
    }
    return out
  }
  let cur = null
  let fence = false
  const flush = () => {
    if (cur) out.push(cur)
    cur = null
  }
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '')
    const start = off
    const end = off + line.length
    off += raw.length + 1
    if (/^\s*(?:```|~~~)/.test(line)) {
      flush()
      fence = !fence
      continue
    }
    if (fence) {
      out.push({ start, end })
      continue
    }
    if (!line.trim()) {
      flush()
      continue
    }
    if (/^\s*\|/.test(line)) {
      flush()
      if (!/^\s*\|[\s:|-]*$/.test(line)) out.push({ start, end, whole: true })
      continue
    }
    if (/^\s*#{1,6}\s/.test(line)) {
      flush()
      out.push({ start, end })
      continue
    }
    if (/^\s*(?:[-*+]|\d+[.)])\s+/.test(line)) flush()
    if (cur) cur.end = end
    else cur = { start, end }
  }
  flush()
  return out
}

/** Sentences inside a unit: split after . ! ? ; followed by white space, not after e.g., i.e., etc., vs. */
export function sentences(text, u) {
  const s = text.slice(u.start, u.end)
  if (u.whole) return [{ text: s, start: u.start }]
  const out = []
  let from = 0
  const re = /[.!?;](?=\s)/g
  let m
  while ((m = re.exec(s))) {
    if (/(?:^|[\s(])(?:e\.g|i\.e|etc|vs|cf|approx)\.$/i.test(s.slice(Math.max(0, m.index - 7), m.index + 1))) continue
    out.push({ text: s.slice(from, m.index + 1), start: u.start + from })
    from = m.index + 1
  }
  out.push({ text: s.slice(from), start: u.start + from })
  return out
}

/**
 * "broken" whose own subject is something other than a wallet ("once ECDSA is broken") is let
 * through. The subject is up to three words before is/are/was/..., stopping at , ; : ( ) [ ].
 */
export function brokenHasOtherSubject(before) {
  const aux = /(?:^|\s)(?:is|are|was|were|be|been|being|get|gets|got|become|becomes|became)\s+(?:\w+ly\s+)?$/i.exec(before)
  if (!aux) return false
  const clause = before.slice(0, aux.index).split(/[,;:()[\]]/).pop()
  const words = clause.trim().split(/\s+/).filter(Boolean).slice(-3).map((w) => w.replace(/^[`"'*_]+|[`"'*_.]+$/g, ''))
  if (!words.length) return false
  if (hasWallet(words.join(' '))) return false
  return !words.some((w) => WALLETISH.test(w))
}

// ---------- rules ----------
// Each rule: id, what it looks at (files(path) or commit messages), check(file, ctx) -> [{ idx | line, col, msg }]
const S5_PATTERNS = [
  [/(?:^|\/)[^/]*_tmp\.[^/]+$/, '*_tmp.* scratch file'],
  [/(?:^|\/)\.fund_tmp[^/]*$/, '.fund_tmp* scratch file'],
  [/(?:^|\/)\.probe_[^/]*$/, '.probe_* scratch file'],
  [/^docs\/_[^/]*\.html?$/, 'docs/_*.html scratch page (GitHub Pages does not serve it either)'],
]

export const RULES = [
  {
    id: 'S1',
    title: 'wallet wording',
    files: (p) => !OTHERS_CODE(p),
    check(f) {
      const out = []
      for (const u of units(f)) {
        for (const s of sentences(f.text, u)) {
          const wallet = hasWallet(s.text)
          if (!wallet) continue
          for (const m of s.text.matchAll(DEFECT)) {
            if (/^broken$/i.test(m[0]) && brokenHasOtherSubject(s.text.slice(0, m.index))) continue
            out.push({ idx: s.start + m.index, msg: `"${m[0]}" in a sentence about a wallet ("${wallet}"). A wallet's warning or refusal is its normal protection: write refused, rejected, warned or stopped` })
          }
        }
      }
      return out
    },
  },
  {
    id: 'S2',
    title: 'misspelled names',
    files: (p) => !OTHERS_CODE(p) && p !== NAMES_FILE,
    check(f, ctx) {
      const out = []
      for (const n of ctx.names) {
        const re = new RegExp(`\\b${n.wrong.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi')
        for (const m of f.text.matchAll(re)) out.push({ idx: m.index, msg: `"${m[0]}" is a known misspelling: write "${n.use}" (${NAMES_FILE})` })
      }
      return out
    },
  },
  {
    id: 'S4',
    title: 'control characters',
    files: () => true,
    check(f) {
      if (f.binary) return []
      const out = []
      let line = 1
      let col = 0
      for (const b of f.buf) {
        if (b === 0x0a) {
          line++
          col = 0
          continue
        }
        if (b < 0x20 && b !== 0x09 && b !== 0x0d) out.push({ line, col, msg: `control character 0x${b.toString(16).padStart(2, '0')} (only tab, LF and CR belong in a text file; a shell heredoc or sed turns \\f, \\b, \\v in Windows paths into these)` })
        if ((b & 0xc0) !== 0x80) col++
      }
      return out
    },
  },
  {
    id: 'S5',
    title: 'scratch files tracked',
    files: () => true,
    path: true,
    check(f) {
      return S5_PATTERNS.filter(([re]) => re.test(f.path)).map(([, what]) => ({ line: 0, col: f.path.lastIndexOf('/') + 1, msg: `${what} is tracked by git. Remove it from the index (git rm --cached) and keep it local` }))
    },
  },
  {
    id: 'S6',
    title: 'fixed fee in a page (warning)',
    warn: true,
    hint: 'S6 fees move with the L2 gas price: on a page people act on, prefer a range ("3 to 4 STRK") and check it against the receipts (actual_fee, l2_gas) at each end-to-end run. Measured costs with their source and date can stay.',
    files: (p) => !OTHERS_CODE(p) && isPage(p),
    check(f) {
      return [...f.text.matchAll(/\babout\s+\d+(?:\.\d+)?\s*STRK\b/gi)].map((m) => ({ idx: m.index, msg: `"${m[0]}"` }))
    },
  },
]
const S3 = { id: 'S3', title: 'Co-Authored-By in commit messages' }
const FILE_RULE_IDS = new Set(RULES.map((r) => r.id))

// ---------- S3: commit messages ----------
const TRAILER = /^[ \t]*co-authored-by[ \t]*:/gim
export function s3Message(msg, { stripComments = false } = {}) {
  const text = stripComments ? msg.split('\n').filter((l) => !l.startsWith('#')).join('\n') : msg
  return [...text.matchAll(TRAILER)].length
}
/** Parses `git log --format=%H%x1f%B%x1e` output into [{ hash, msg }] */
export function parseLog(out) {
  return out.split('\x1e').map((r) => r.replace(/^\n/, '')).filter((r) => r.includes('\x1f')).map((r) => {
    const [hash, msg] = r.split('\x1f')
    return { hash, msg }
  })
}
function commitsInRange(root, range) {
  if (/^0{40}\.\./.test(range)) {
    console.log(`S3: range ${range} starts at the zero commit (a new ref); nothing to compare against`)
    return []
  }
  const out = execFileSync('git', ['-C', root, 'log', '--format=%H%x1f%B%x1e', range], { encoding: 'utf8', maxBuffer: 64 << 20 })
  return parseLog(out)
}

// ---------- names list (S2) and exceptions ----------
export function loadNames(text) {
  const errors = []
  let list
  try {
    list = JSON.parse(text)
  } catch (e) {
    return { names: [], errors: [`${NAMES_FILE} is not JSON (${e.message})`] }
  }
  if (!Array.isArray(list) || !list.length) return { names: [], errors: [`${NAMES_FILE} must be a non-empty array`] }
  const names = []
  list.forEach((n, i) => {
    const bad = []
    if (typeof n?.wrong !== 'string' || n.wrong.trim().length < 3) bad.push('wrong (3+ characters)')
    if (typeof n?.use !== 'string' || !n.use.trim()) bad.push('use')
    if (typeof n?.reason !== 'string' || n.reason.trim().length < 10) bad.push('reason (10+ characters)')
    if (typeof n?.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(n.date)) bad.push('date (YYYY-MM-DD)')
    if (bad.length) errors.push(`${NAMES_FILE} entry ${i + 1}: missing or bad ${bad.join(', ')}`)
    else names.push(n)
  })
  return { names, errors }
}

const EX_KEYS = new Set(['rule', 'file', 'line_or_pattern', 'max_hits', 'reason', 'date'])
export function loadExceptions(text) {
  const errors = []
  let list
  try {
    list = JSON.parse(text)
  } catch (e) {
    return { list: [], errors: [`${EXCEPTIONS_FILE} is not JSON (${e.message})`] }
  }
  if (!Array.isArray(list)) return { list: [], errors: [`${EXCEPTIONS_FILE} must be an array`] }
  const ok = []
  list.forEach((e, i) => {
    const at = `entry ${i + 1} (${e?.rule ?? '?'} ${e?.file ?? '?'})`
    const bad = []
    if (!e || typeof e !== 'object') bad.push('not an object')
    else {
      if (!FILE_RULE_IDS.has(e.rule)) bad.push(`unknown rule ${e.rule} (exceptions exist for ${[...FILE_RULE_IDS].join(', ')})`)
      if (typeof e.file !== 'string' || !e.file) bad.push('no file')
      if (!(Number.isInteger(e.line_or_pattern) && e.line_or_pattern > 0) && !(typeof e.line_or_pattern === 'string' && e.line_or_pattern.trim())) bad.push('no line_or_pattern (a line number or text on that line)')
      if (typeof e.reason !== 'string' || e.reason.trim().length < 10) bad.push('no reason (10+ characters)')
      if (typeof e.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(e.date)) bad.push('no date (YYYY-MM-DD)')
      if (e.max_hits !== undefined && !(Number.isInteger(e.max_hits) && e.max_hits >= 1)) bad.push('max_hits must be an integer >= 1')
      const extra = Object.keys(e).filter((k) => !EX_KEYS.has(k))
      if (extra.length) bad.push(`unknown field ${extra.join(', ')} (fields: ${[...EX_KEYS].join(', ')})`)
    }
    if (bad.length) errors.push(`${at}: ${bad.join(', ')}`)
    else ok.push({ ...e, max_hits: e.max_hits ?? 1, hits: new Set(), over: new Set(), n: i + 1 })
  })
  return { list: ok, errors }
}

function globMatch(pat, p) {
  if (pat === p) return true
  if (!pat.includes('*')) return false
  const re = new RegExp('^' + pat.split('**').map((s) => s.split('*').map((t) => t.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('[^/]*')).join('.*') + '$')
  return re.test(p)
}

/** Does exception e cover violation v? A line number covers that line; text must sit on the line and cover the hit's column */
function covers(e, v) {
  if (typeof e.line_or_pattern === 'number') return e.line_or_pattern === v.line
  const pat = e.line_or_pattern
  for (let p = v.lineText.indexOf(pat); p >= 0; p = v.lineText.indexOf(pat, p + 1)) if (p <= v.col && v.col < p + pat.length) return true
  return false
}

// ---------- run ----------
export function run(files, exceptions, ctx) {
  const found = []
  for (const f of files) {
    for (const r of RULES) {
      if (!r.files(f.path)) continue
      const seen = new Set()
      for (const v of r.check(f, ctx)) {
        const line = v.line ?? f.lineOf(v.idx)
        if (seen.has(line)) continue // one report per rule per line
        const col = v.col ?? f.colOf(v.idx)
        const hit = { rule: r.id, warn: !!r.warn, file: f.path, line, col, lineText: r.path ? f.path : f.lineText(line), msg: v.msg }
        const at = `${f.path}:${line}`
        const cands = exceptions.filter((e) => e.rule === r.id && globMatch(e.file, f.path) && covers(e, hit))
        const ex = cands.find((e) => e.hits.has(at)) ?? cands.find((e) => e.hits.size < e.max_hits)
        if (ex) {
          ex.hits.add(at)
          continue
        }
        if (cands.length) cands[0].over.add(at)
        seen.add(line)
        found.push(hit)
      }
    }
  }
  found.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line))
  const problems = []
  for (const e of exceptions) {
    const name = `${EXCEPTIONS_FILE} entry ${e.n} (${e.rule} ${e.file} "${e.line_or_pattern}")`
    if (e.over.size) problems.push({ e, kind: 'over', msg: `${name} matches more lines than max_hits ${e.max_hits} (${[...e.over].join(', ')} reported as violations)` })
    else if (e.hits.size === 0) problems.push({ e, kind: 'unused', msg: `${name} skips nothing. Fixed? Delete the exception` })
    else if (e.hits.size < e.max_hits) problems.push({ e, kind: 'under', msg: `${name} has max_hits ${e.max_hits} but skips ${e.hits.size}. Lower max_hits: spare room would skip a new violation silently` })
  }
  return {
    violations: found.filter((v) => !v.warn),
    warnings: found.filter((v) => v.warn),
    skipped: exceptions.reduce((s, e) => s + e.hits.size, 0),
    problems,
  }
}

function readTree(root) {
  const { how, paths } = listFiles(root)
  const files = []
  for (const p of paths) {
    const abs = join(root, p)
    if (!existsSync(abs)) continue // deleted in the working tree but still in the index
    files.push(makeFile(p, readFileSync(abs)))
  }
  return { how, files }
}

function loadRepoLists(root) {
  const nf = join(root, NAMES_FILE)
  const names = existsSync(nf) ? loadNames(readFileSync(nf, 'utf8')) : { names: [], errors: [`${NAMES_FILE} is missing`] }
  const xf = join(root, EXCEPTIONS_FILE)
  const ex = existsSync(xf) ? loadExceptions(readFileSync(xf, 'utf8')) : { list: [], errors: [] }
  return { names, ex }
}

const where = (v) => (v.line ? `${v.file}:${v.line}` : v.file)

function main(args) {
  const opt = (name) => {
    const i = args.indexOf(name)
    if (i < 0) return undefined
    if (!args[i + 1] || args[i + 1].startsWith('--')) usage(`${name} needs a value`)
    return args[i + 1]
  }
  const known = new Set(['--root', '--commits', '--commit-msg'])
  for (let i = 0; i < args.length; i++) {
    if (!known.has(args[i])) usage(`unknown argument ${args[i]}`)
    i++
  }
  const root = resolve(opt('--root') ?? REPO)
  const msgFile = opt('--commit-msg')
  if (msgFile) {
    const n = s3Message(readFileSync(msgFile, 'utf8'), { stripComments: true })
    if (n) console.log(`commit message: S3 ${n} Co-Authored-By line(s). This repository's commits carry none; delete the line and commit again`)
    process.exitCode = n ? 1 : 0
    return
  }
  const t0 = performance.now()
  // The lists travel with the checker: --root applies this checkout's rules to another tree
  const { names, ex } = loadRepoLists(REPO)
  const { how, files } = readTree(root)
  const r = run(files, ex.list, { names: names.names })
  for (const v of r.violations) console.log(`${where(v)}: ${v.rule} ${v.msg}`)
  for (const v of r.warnings) console.log(`${where(v)}: ${v.rule} (warning) ${v.msg}`)
  for (const x of RULES) if (x.hint && r.warnings.some((v) => v.rule === x.id)) console.log(`  ${x.hint}`)
  let s3 = 0
  const range = opt('--commits')
  if (range) {
    for (const c of commitsInRange(how === 'git ls-files' ? root : REPO, range)) {
      const n = s3Message(c.msg)
      if (n) {
        s3++
        console.log(`commit ${c.hash.slice(0, 7)}: S3 ${n} Co-Authored-By line(s) in the message. This repository's commits carry none; reword the commit (git rebase) before merging`)
      }
    }
  }
  const listErrors = [...names.errors, ...ex.errors, ...r.problems.map((p) => p.msg)]
  for (const e of listErrors) console.log(`rules: ${e}`)
  const ms = Math.round(performance.now() - t0)
  const byRule = RULES.filter((x) => !x.warn).map((x) => `${x.id} ${r.violations.filter((v) => v.rule === x.id).length}`).join(', ')
  console.log(`rules: violations ${r.violations.length + s3} (${byRule}${range ? `, S3 ${s3} in ${range}` : ', S3 not run: no --commits'}), warnings ${r.warnings.length} (S6), skipped by exceptions ${r.skipped}, list errors ${listErrors.length} (${files.length} files ${how}, ${ms}ms)`)
  process.exitCode = r.violations.length + s3 + listErrors.length ? 1 : 0
}

function usage(why) {
  console.error(`${why}\nusage: node scripts/check_rules.mjs [--root DIR] [--commits A..B] | --commit-msg FILE | --self-test`)
  process.exit(2)
}

// ---------- self-test ----------
// Placeholders keep the bad examples out of this file's own text. Their names are not words, so the
// rules do not match the placeholders either.
const T = {
  R: 'Rea' + 'dy',
  A: 'Arg' + 'ent',
  B: 'Braa' + 'vos',
  WE: 'wallet ext' + 'ension',
  TW: 'the wal' + 'let',
  D_BUG: 'b' + 'ug',
  D_BUGS: 'B' + 'ugs',
  D_BRK: 'bro' + 'ken',
  D_BLK: 'blo' + 'cked',
  D_BLKUS: 'blo' + 'cks us',
}
const fill = (s, names) => s.replace(/\{(\w+)\}/g, (all, k) => (k === 'NAME0' ? names[0].wrong : k === 'NAME0_LOWER' ? names[0].wrong.toLowerCase() : T[k] ?? all))

// [rule, path, text, lines with a hit]. Each rule: 2+ bad examples, 1+ good.
const FIXTURES = [
  // S1 bad: the two lines fixed by hand on 2026-11-21 (commit f7b131b), then other shapes
  ['S1', 'README.md', '- {B} 4.19.6: the extension {D_BLK} the dapp-initiated call to the wallet\'s own account before sending ("Security Error"); nothing went on chain.\n', 1],
  ['S1', 'contracts/docs/wallet-connect-probe.md', '| {B} 4.19.6 | {B} 1.2.0 (`0x3957…bf8a`) | "Sign Transaction" | None on the sign screen | None ({D_BLK} before sending) | No, class and keys unchanged |\n', 1],
  ['S1', 'README.md', 'Since 4.19, {B} shows its own screen\nfor this call and the call is {D_BLK} there.\n', 1],
  ['S1', 'docs/index.html', '<p>{TW} {D_BLKUS} here</p>\n<li>{A} X is {D_BRK}</li>\n', 2],
  ['S1', 'signer/probe.mjs', 'console.log("{R} {D_BUG}: it rejects the call");\n', 1],
  ['S1', 'contracts/docs/a.md', "{B}'s signer is {D_BRK}.\n\nThe {WE} is {D_BRK} for this call.\n", 2],
  // S1 good: README lines 107, 122-126 and 276 on main, and other sentences that only share a paragraph with a wallet
  ['S1', 'README.md', '| {D_BUGS} in this code | No | Unaudited. Testnet only. |\n', 0],
  ['S1', 'README.md', "- If a wallet calls `upgrade` without `migrate` in the same transaction, an OpenZeppelin account\n  waits in a bootstrap state that accepts one ECDSA-signed `migrate` call (it still needs the\n  key-possession proof, but could be front-run once ECDSA is {D_BRK}), and a {B} account has\n  no usable key at all, because its key is not stored where this class reads it. The kit always\n  puts both calls in one transaction, and {A}'s upgrade callbacks do both in one call.\n", 0],
  ['S1', 'README.md', '  The switch needs the active verifier to work: it validates the switch transaction itself, so it\n  is no fallback if the active verifier breaks.\n', 0],
  ['S1', 'README.md', '{B} refused the dapp-initiated call ("Security Error"). This browser {D_BLK} local storage.\n', 0],
  ['S1', 'recovery/README.md', '2. **Post-quantum soundness.** {A} and {B} keys need a hash-based proof (Groth16 and\n   similar are {D_BRK} by the same quantum computer).\n', 0],
  ['S1', 'README.md', '{R} shows a critical warning first.\n\nOnce ECDSA is {D_BRK}, every account is at risk.\n', 0],
  ['S1', 'vendor/x/README.md', '{B} is {D_BRK}\n', 0],
  // S2
  ['S2', 'README.md', 'Thanks to Carlos {NAME0} (Zealynx).\n', 1],
  ['S2', 'SECURITY.md', 'Reviewed by {NAME0_LOWER}.\nok\nAnd {NAME0}\n', 2],
  ['S2', 'README.md', 'Thanks to Carlos (Zealynx).\n', 0],
  ['S2', 'rules/misspelled-names.json', '[{ "wrong": "{NAME0}" }]\n', 0],
  ['S2', 'vendor/a/NOTES.md', '{NAME0}\n', 0],
  // S4 (the checker reads bytes; these are JS escapes in this file, real control characters at run time)
  ['S4', 'README.md', 'path D:\x0cools\nok\n\x08\x0b\n', 2],
  ['S4', 'vendor/provably-fast/falcon-512/a.patch', '\x1b[0m\n', 1],
  ['S4', 'signer/x.mjs', 'a\tb\r\nc\n', 0],
  ['S4', 'docs/media/demo.gif', '\x00\x1b\x01', 0],
  // S5 (the path is what counts)
  ['S5', 'signer/.fund_tmp.mjs', '', 1],
  ['S5', 'signer/.probe_rpc_tmp.mjs', '', 1],
  ['S5', 'docs/_phone_test.html', '', 1],
  ['S5', 'scripts/survey_tmp.json', '', 1],
  ['S5', 'signer/fund.mjs', '', 0],
  ['S5', 'docs/index.html', '', 0],
  ['S5', 'docs/coverage/index.html', '', 0],
  // S6 (warning)
  ['S6', 'README.md', 'The migration costs about 3 STRK.\n', 1],
  ['S6', 'docs/index.html', '<p>about 2.5 STRK</p>\n<p>About 7 STRK each</p>\n', 2],
  ['S6', 'README.md', 'The migration costs 3 to 4 STRK.\n', 0],
  ['S6', 'signer/x.mjs', 'const note = "about 3 STRK"\n', 0],
]
// [message, Co-Authored-By lines, from a commit-msg file (comments stripped)]
const S3_FIXTURES = [
  ['Docs: wording\n\nCo-Authored-By: Someone <someone@example.com>\n', 1, false],
  ['Fix\n\nco-authored-by: a <a@example.com>\n  Co-authored-by : b <b@example.com>\n', 2, false],
  ['Docs: wording\n\nSigned-off-by: a <a@example.com>\n', 0, false],
  ['Explain why Co-Authored-By lines are not used\n', 0, false],
  ['Docs: wording\n# Co-Authored-By: a line git strips\n', 0, true],
]

function selfTest() {
  let pass = 0
  let fail = 0
  const say = (ok, what) => {
    if (ok) pass++
    else {
      fail++
      console.log(`FAIL ${what}`)
    }
  }
  const { names: nl, ex: rex } = loadRepoLists(REPO)
  say(nl.errors.length === 0 && nl.names.length >= 1, `${NAMES_FILE} loads (${nl.names.length} names, errors: ${nl.errors.join('; ') || 'none'})`)
  say(rex.errors.length === 0, `${EXCEPTIONS_FILE} loads (errors: ${rex.errors.join('; ') || 'none'})`)
  const names = nl.names.length ? nl.names : [{ wrong: 'Placeholder', use: 'x' }]
  const ctx = { names }
  const tally = {}
  for (const [rule, path, raw, want] of FIXTURES) {
    const r = RULES.find((x) => x.id === rule)
    const text = fill(raw, names)
    const f = makeFile(path, text)
    const got = r.files(path) ? new Set(r.check(f, ctx).map((v) => v.line ?? f.lineOf(v.idx))).size : 0
    const t = (tally[rule] ??= { bad: 0, badOk: 0, good: 0, goodOk: 0 })
    if (want > 0) {
      t.bad++
      if (got === want) t.badOk++
    } else {
      t.good++
      if (got === 0) t.goodOk++
    }
    say(got === want, `${rule} ${path}: ${got} line(s) hit, want ${want}: ${JSON.stringify(text.slice(0, 90))}`)
  }
  const t3 = (tally.S3 = { bad: 0, badOk: 0, good: 0, goodOk: 0 })
  for (const [msg, want, strip] of S3_FIXTURES) {
    const got = s3Message(msg, { stripComments: strip })
    if (want > 0) {
      t3.bad++
      if (got === want) t3.badOk++
    } else {
      t3.good++
      if (got === 0) t3.goodOk++
    }
    say(got === want, `S3 message: ${got} trailer(s), want ${want}: ${JSON.stringify(msg.slice(0, 60))}`)
  }
  const log = parseLog(`${'a'.repeat(40)}\x1fFirst\n\nCo-Authored-By: x <x@example.com>\n\x1e\n${'b'.repeat(40)}\x1fSecond\n\x1e\n`)
  say(log.length === 2 && s3Message(log[0].msg) === 1 && s3Message(log[1].msg) === 0 && log[1].hash === 'b'.repeat(40), `S3: git log output parsed into commits (${log.length})`)
  // S1 reports the line of the word, inside a sentence that spans lines
  {
    const f = makeFile('README.md', fill('Since 4.19, {B} shows its own screen\nfor this call and the call is {D_BLK} there.\n', names))
    const v = run([f], [], ctx).violations
    say(v.length === 1 && v[0].line === 2 && v[0].rule === 'S1', `S1: a sentence across lines is reported at the word's line (${v.map((x) => x.line)})`)
  }
  // each rule has 2+ bad and 1+ good examples
  for (const id of ['S1', 'S2', 'S3', 'S4', 'S5', 'S6']) {
    const t = tally[id] ?? { bad: 0, good: 0 }
    say(t.bad >= 2 && t.good >= 1, `${id} has 2+ bad and 1+ good examples (bad ${t.bad}, good ${t.good})`)
  }
  // exceptions
  const f1 = makeFile('README.md', fill('{B} is {D_BRK} here.\n{B} {D_BUG} two.\n', names))
  const exOf = (arr) => loadExceptions(JSON.stringify(arr.map((o) => ({ reason: 'self-test exception entry', date: '2026-11-27', ...o }))))
  const e1 = exOf([
    { rule: 'S1', file: 'README.md', line_or_pattern: fill('is {D_BRK} here', names) },
    { rule: 'S1', file: 'README.md', line_or_pattern: 2 },
    { rule: 'S1', file: '*.md', line_or_pattern: 'nothing-here' },
  ])
  const r1 = run([f1], e1.list, ctx)
  say(e1.errors.length === 0 && r1.violations.length === 0 && r1.skipped === 2, `exceptions: text and line number skip (violations ${r1.violations.length}, skipped ${r1.skipped})`)
  say(r1.problems.length === 1 && r1.problems[0].kind === 'unused', `exceptions: an unused exception is an error (${r1.problems.map((p) => p.kind)})`)
  const bad = loadExceptions(
    JSON.stringify([
      { rule: 'S1', file: 'README.md', line_or_pattern: 1, reason: '', date: '2026-11-27' },
      { rule: 'Z9', file: 'x', line_or_pattern: 1, reason: 'unknown rule entry', date: '2026-11-27' },
      { rule: 'S3', file: 'x', line_or_pattern: 1, reason: 'S3 has no file exceptions', date: '2026-11-27' },
      { rule: 'S1', file: 'x', reason: 'no line and a bad date', date: '11/27' },
      { rule: 'S1', file: 'x', line_or_pattern: 1, max_hits: 0, reason: 'max_hits zero entry', date: '2026-11-27' },
      { rule: 'S1', file: 'x', line_or_pattern: 1, max_hit: 2, reason: 'misspelled field entry', date: '2026-11-27' },
    ]),
  )
  say(bad.errors.length === 6 && bad.list.length === 0, `exceptions: bad entries refused (${bad.errors.length} of 6)`)
  say(loadExceptions('{ not json').errors.length === 1, 'exceptions: not JSON is an error')
  const r2 = run([makeFile('README.md', fill('{B} {D_BUG} and Carlos {NAME0}\n', names))], exOf([{ rule: 'S1', file: 'README.md', line_or_pattern: 1 }]).list, ctx)
  say(r2.violations.length === 1 && r2.violations[0].rule === 'S2', `exceptions: an S1 exception does not skip S2 on the same line (${r2.violations.map((v) => v.rule)})`)
  const r3 = run([makeFile('README.md', fill('{B} is {D_BRK}. Other text here.\n', names))], exOf([{ rule: 'S1', file: 'README.md', line_or_pattern: 'Other text' }]).list, ctx)
  say(r3.violations.length === 1 && r3.problems[0]?.kind === 'unused', `exceptions: text elsewhere on the line does not cover the hit (violations ${r3.violations.length})`)
  const two = fill('{B} {D_BUG} one.\n{B} {D_BUG} two.\n', names)
  const rx = (o) => run([makeFile('README.md', two)], exOf([{ rule: 'S1', file: 'README.md', line_or_pattern: fill('{D_BUG}', names), ...o }]).list, ctx)
  const o1 = rx({})
  say(o1.violations.length === 1 && o1.problems[0]?.kind === 'over', `exceptions: past max_hits 1 the extra line is a violation and an error (${o1.violations.length}, ${o1.problems.map((p) => p.kind)})`)
  const o2 = rx({ max_hits: 2 })
  say(o2.violations.length === 0 && o2.problems.length === 0 && o2.skipped === 2, `exceptions: max_hits 2 skips two lines (${o2.skipped})`)
  const o3 = rx({ max_hits: 3 })
  say(o3.problems[0]?.kind === 'under', `exceptions: max_hits above the real count is an error (${o3.problems.map((p) => p.kind)})`)
  const s5 = run([makeFile('signer/.fund_tmp.mjs', 'x')], exOf([{ rule: 'S5', file: 'signer/.fund_tmp.mjs', line_or_pattern: '.fund_tmp' }]).list, ctx)
  say(s5.violations.length === 0 && s5.skipped === 1, `exceptions: S5 matches text in the path (${s5.skipped})`)
  // scope: the rules still see the files that matter in this repository
  const { files } = readTree(REPO)
  const seen = (id) => new Set(files.filter((f) => RULES.find((r) => r.id === id).files(f.path)).map((f) => f.path))
  const s1 = seen('S1')
  const must = ['README.md', 'SECURITY.md', 'docs/index.html', 'signer/browser-wallet.template.html', 'contracts/docs/wallet-integration.md']
  const miss = must.filter((p) => !s1.has(p))
  say(miss.length === 0, `scope: S1 and S2 read ${must.join(', ')} (missing: ${miss.join(', ') || 'none'})`)
  say(files.length >= 100, `scope: ${files.length} tracked files read (100+)`)
  const vend = [...seen('S4')].filter((p) => p.startsWith('vendor/')).length
  say(vend > 0 && !seen('S1').has([...seen('S4')].find((p) => p.startsWith('vendor/'))), `scope: S4 reads vendor/ (${vend} files), S1 does not`)
  const pages = [...seen('S6')]
  say(pages.includes('README.md') && pages.includes('docs/index.html') && !pages.some((p) => p.endsWith('.mjs')), `scope: S6 reads pages and docs only (${pages.length} files)`)
  say(!files.some((f) => f.path.includes('/node_modules/') || f.path.startsWith('contracts/target/')), 'scope: build output and node_modules are not read')

  for (const id of ['S1', 'S2', 'S3', 'S4', 'S5', 'S6']) {
    const t = tally[id]
    console.log(`${id}: bad examples caught ${t.badOk}/${t.bad}, good examples passed ${t.goodOk}/${t.good}`)
  }
  console.log(`self-test: ${pass} passed, ${fail} failed (${FIXTURES.length + S3_FIXTURES.length} examples, ${RULES.length + 1} rules)`)
  process.exitCode = fail ? 1 : 0
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2)
  if (args.includes('--self-test')) selfTest()
  else main(args)
}
