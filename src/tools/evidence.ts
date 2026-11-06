/**
 * Tamper-evident evidence chain (run-8 proposals §6): every capture appends
 * one hash-chained entry (each entry hashes the previous one), so the record
 * is self-verifying — a dropped or edited line breaks every later hash.
 * evidence_bundle means a report is a VIEW of the record, not a re-assembly.
 * Lanes re-invented sha256+timestamp per capture in run 7 and one lane found
 * its log clock 30 minutes off; the chain catches that class of drift.
 */

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { z } from 'zod'
import { errorResult, textResult, type ToolRegistrar, type ToolResult } from '../browser/tools.js'
import { redactSecrets } from '../redact.js'
import type { ConstellationConfig } from '../config.js'

export interface ChainEntry {
  seq: number
  ts: string
  owner: string
  label: string
  files?: Array<{ name: string; sha256: string }>
  note?: string
  prev_hash: string
  entry_hash: string
}

const GENESIS = '0'.repeat(64)

export function hashEntry(entry: Omit<ChainEntry, 'entry_hash'>): string {
  const { entry_hash, ...rest } = entry as ChainEntry
  void entry_hash
  return createHash('sha256').update(JSON.stringify(rest)).digest('hex')
}

/** Append one entry; returns the entry WITH its hash. Corrupt existing lines
 *  are preserved (never rewritten) and the chain continues from the last
 *  VALID entry. */
export function appendChainEntry(config: ConstellationConfig, entry: Omit<ChainEntry, 'seq' | 'ts' | 'prev_hash' | 'entry_hash'>): ChainEntry {
  const file = path.join(config.rootDir, 'evidence-chain.jsonl')
  const existing = readChain(config)
  const prev = existing.length > 0 ? existing[existing.length - 1]!.entry_hash : GENESIS
  const full: ChainEntry = {
    ...entry,
    seq: existing.length > 0 ? existing[existing.length - 1]!.seq + 1 : 1,
    ts: new Date().toISOString(),
    prev_hash: prev,
    entry_hash: '',
  }
  full.entry_hash = hashEntry(full)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.appendFileSync(file, JSON.stringify(full) + '\n')
  return full
}

/** Read every VALID chain line (invalid JSON lines are skipped, never fatal). */
export function readChain(config: ConstellationConfig): ChainEntry[] {
  const file = path.join(config.rootDir, 'evidence-chain.jsonl')
  let text = ''
  try { text = fs.readFileSync(file, 'utf8') } catch { return [] }
  const out: ChainEntry[] = []
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue
    try {
      const parsed = JSON.parse(line) as ChainEntry
      if (typeof parsed.entry_hash === 'string' && typeof parsed.seq === 'number') out.push(parsed)
    } catch { /* skip malformed */ }
  }
  return out
}

/** Verify the chain end-to-end: hash links and per-entry hashes. */
export function verifyChain(config: ConstellationConfig): { ok: boolean; brokenAt?: number; reason?: string; entries: number } {
  const chain = readChain(config)
  let prev = GENESIS
  for (const entry of chain) {
    const recomputed = hashEntry(entry)
    if (recomputed !== entry.entry_hash) return { ok: false, brokenAt: entry.seq, reason: 'entry hash mismatch (content edited after capture)', entries: chain.length }
    if (entry.prev_hash !== prev) return { ok: false, brokenAt: entry.seq, reason: 'chain link broken (an entry was dropped or reordered)', entries: chain.length }
    prev = entry.entry_hash
  }
  return { ok: true, entries: chain.length }
}

/** One leg's report core: status + body sha — exactly what a report cites. */
export interface VerdictLeg {
  status: number
  sha: string
}

/** Append a VERDICT-shaped chain entry (round-7 gap list, "small change"):
 *  diff_pair's four fields ARE the report core, yet a lane had to re-run
 *  evidence_capture to cite them. Shared by diff_pair, cell_run and recipe
 *  drift transitions — the chain then covers the verdict itself, not a
 *  screenshot taken minutes later. Returns the entry (for the tool output). */
export function appendVerdictEntry(
  config: ConstellationConfig,
  owner: string,
  source: string,
  tuple: {
    verdict: string
    deciding_field: string
    probe: VerdictLeg
    miss: VerdictLeg
    own?: VerdictLeg
    expect?: string
    passed?: boolean
    object?: string
    transition?: string
  },
): ChainEntry {
  return appendChainEntry(config, {
    owner,
    label: `${source}: ${tuple.verdict}`
      + (tuple.transition !== undefined ? ` (transition ${tuple.transition})` : '')
      + (tuple.expect !== undefined ? ` — expect ${tuple.expect} ${tuple.passed === true ? 'HELD' : 'BROKE'}` : ''),
    note: JSON.stringify(tuple),
  })
}

// ── evidence_scan (advice 2026-11-06 #3) ──────────────────────────────────────
// The bundle-secret scan that run 4,780 files / 114 MB / 593 pattern hits in a
// hand-written PowerShell script: real value, but the redaction discipline
// (first4…last4 + sha256 + placeholder filter) lived in whoever wrote the
// script, and the result was a repo file, not evidence. Here it is one call
// per lane: hits are reported redacted ONLY, and the scan itself appends a
// chain entry — "we never grepped the bundles" stops being possible.

export interface SecretPattern {
  name: string
  re: RegExp
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  { name: 'aws-access-key-id', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'stripe-secret-key', re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g },
  { name: 'stripe-webhook-secret', re: /\bwhsec_[0-9a-zA-Z]{20,}\b/g },
  { name: 'slack-token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { name: 'github-token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g },
  { name: 'github-pat', re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g },
  { name: 'sendgrid-key', re: /\bSG\.[A-Za-z0-9_-]{16,32}\.[A-Za-z0-9_-]{16,64}\b/g },
  { name: 'pem-private-key', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g },
  { name: 'jwt', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { name: 'mongodb-uri', re: /\bmongodb(?:\+srv)?:\/\/[^\s'"<>]+/gi },
  { name: 'sql-password', re: /\b(?:password|pwd)\s*=\s*[^\s;'"]{6,}/gi },
  { name: 'sharedsecret-assignment', re: /["']?sharedSecret["']?\s*[:=]\s*["'][^"'\n]{8,}["']/gi },
]

const PLACEHOLDER_RE = /xxxx|your[-_ ]|<[^>]*>|\{\{|changeme|change[-_]?me|placeholder|example|dummy|insert[-_ ]|redacted|sample[-_ ]|todo|fixme|\*{3,}/i

/** Placeholder-shaped values (docs strings, templates) are counted, not
 *  reported — a scan that cries wolf 593 times gets ignored. Pure. */
export function looksLikePlaceholder(value: string): boolean {
  if (/^(.)\1+$/.test(value)) return true
  return PLACEHOLDER_RE.test(value)
}

export interface ScanHit {
  name: string
  index: number
  value: string
}

/** Run the pattern set over one text — pure. Deduped by (name, value); every
 *  hit keeps its FIRST index so the line context is stable. */
export function scanText(text: string, patterns: readonly SecretPattern[] = SECRET_PATTERNS): ScanHit[] {
  const seen = new Set<string>()
  const out: ScanHit[] = []
  for (const { name, re } of patterns) {
    re.lastIndex = 0
    for (const match of text.matchAll(re)) {
      const value = match[0]
      const key = `${name}:${value}`
      if (seen.has(key)) continue
      seen.add(key)
      out.push({ name, index: match.index ?? 0, value })
      if (out.length >= 200) return out
    }
  }
  return out
}

/** The ONLY shape a hit's value ever takes in output: first4…last4 + length. */
export function redactScanValue(value: string): string {
  if (value.length <= 8) return `[redacted ${value.length}-char value]`
  return `${value.slice(0, 4)}…${value.slice(-4)} (${value.length} chars)`
}

function lineOf(text: string, index: number): { line: number; text: string } {
  let line = 1
  let at = 0
  while (at < index) {
    const next = text.indexOf('\n', at)
    if (next === -1 || next >= index) break
    line++
    at = next + 1
  }
  const end = text.indexOf('\n', at)
  return { line, text: text.slice(at, end === -1 ? undefined : end) }
}

export function registerEvidenceTools(server: ToolRegistrar, config: ConstellationConfig): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  // A5 (2026-11-05): evidence_capture needs a live page, so an on-disk
  // artifact (an mcp_tools tools/list snapshot, a body_file, a forged
  // document) could not enter the tamper-evident chain. evidence_file
  // hashes ANY on-disk file into it — a report then cites the snapshot's
  // hash, not a path a human has to re-hash.
  t('evidence_file', 'Hash-chain an ON-DISK artifact into the tamper-evident evidence chain (A5) — evidence_capture needs a live page, but an mcp_tools snapshot, an http_request body_file, or a forged fixture document is already bytes on disk. Reads the file, sha256-hashes it, optionally copies it into the owner\'s evidence dir, and appends one chain entry. Never prints file contents.',
    {
      label: z.string().min(1).describe('Evidence label, e.g. "mcp tools/list snapshot"'),
      path: z.string().describe('Absolute file path (or ~-relative) of the artifact to chain'),
      owner: z.string().optional().describe('Owner whose evidence dir receives the copy and the chain attribution'),
      copy: z.boolean().optional().describe('Copy the bytes into <owner>/evidence/<stamp>-<label>/ (default true); false = hash in place'),
    },
    async ({ label, path: rawPath, owner, copy }: any) => {
      const who = owner ?? 'unknown'
      const resolved = rawPath.startsWith('~/')
        ? path.join(process.env.USERPROFILE ?? process.env.HOME ?? '.', rawPath.slice(2))
        : rawPath
      let stat: fs.Stats
      try { stat = fs.statSync(resolved) } catch {
        return textResult(`No such file: ${resolved}`, true)
      }
      if (stat.isDirectory()) return textResult(`${resolved} is a directory — evidence_file chains ONE file`, true)
      const bytes = fs.readFileSync(resolved)
      const sha256 = createHash('sha256').update(bytes).digest('hex')
      let evidenceDir = path.dirname(resolved)
      if (copy !== false) {
        const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
        const safeLabel = label.replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60)
        evidenceDir = path.join(config.outputDir, who, 'evidence', `${stamp}-${safeLabel}`)
        fs.mkdirSync(evidenceDir, { recursive: true })
        fs.copyFileSync(resolved, path.join(evidenceDir, path.basename(resolved)))
      }
      const chained = appendChainEntry(config, {
        owner: who,
        label,
        files: [{ name: path.basename(resolved), sha256 }],
      })
      return textResult([
        `Evidence "${label}" captured in ${evidenceDir}`,
        `  ${path.basename(resolved)} — ${bytes.length} bytes — sha256 ${sha256.slice(0, 16)}…`,
        `chain entry #${chained.seq} — hash ${chained.entry_hash.slice(0, 12)}… (evidence_verify checks the whole chain)`,
      ].join('\n'))
    })

  // Advice 2026-11-06 #3: the secret-pattern scan as a lane step. Runs the
  // harness pattern set over an owner's artifacts dir (or an explicit root),
  // reports hits REDACTED ONLY (first4…last4 + sha256 + context line with
  // every secret in it masked), filters placeholder-shaped values into their
  // own count, and appends a chain entry so the scan itself is evidence.
  t('evidence_scan', 'Secret-pattern scan over the owner\'s artifacts dir (or an explicit `root` path): AWS/Google/Stripe/Slack/GitHub/SendGrid keys, PEM private keys, JWTs, MongoDB URIs, SQL passwords, sharedSecret assignments. Hits are reported REDACTED ONLY (first4…last4 + sha256 + the context line with secrets masked) — the value NEVER enters the transcript; placeholder-shaped values are counted separately so the report is signal, not noise. Appends one chain entry, so "we scanned the bundles" is itself evidence. Read-only.',
    {
      owner: z.string().optional().describe('Owner whose artifacts dir (<outputDir>/<owner>) is scanned'),
      root: z.string().optional().describe('Explicit absolute root to scan instead of the owner dir (e.g. a fixture bundle folder)'),
      patterns: z.array(z.string()).optional().describe('Restrict to these pattern names (default: all)'),
      max_files: z.number().int().optional().describe('File cap (default 5000)'),
    },
    async ({ owner, root, patterns, max_files }: any) => {
      const who = owner ?? 'unknown'
      const scanRoot = root !== undefined && root !== ''
        ? root
        : owner !== undefined && owner !== '' ? path.join(config.outputDir, owner) : undefined
      if (scanRoot === undefined)
        return textResult('pass owner (scans that owner\'s artifacts dir) or root (an explicit path) — one of them is required', true)
      if (!fs.existsSync(scanRoot) || !fs.statSync(scanRoot).isDirectory())
        return textResult(`No such directory: ${scanRoot}`, true)
      const wanted = patterns !== undefined && patterns.length > 0 ? new Set(patterns) : undefined
      const active = SECRET_PATTERNS.filter(p => wanted === undefined || wanted.has(p.name))
      if (active.length === 0)
        return textResult(`No known pattern names matched [${[...new Set(patterns as string[])].join(', ')}] — known: ${SECRET_PATTERNS.map(p => p.name).join(', ')}`, true)
      const fileCap = max_files ?? 5_000
      const SKIP_DIRS = new Set(['node_modules', '.git'])
      const files: string[] = []
      const walk = (dir: string): void => {
        if (files.length >= fileCap) return
        let entries: fs.Dirent[]
        try { entries = fs.readdirSync(dir, { withFileTypes: true }) } catch { return }
        for (const entry of entries) {
          if (files.length >= fileCap) return
          const full = path.join(dir, entry.name)
          if (entry.isDirectory()) {
            if (!SKIP_DIRS.has(entry.name)) walk(full)
          } else if (entry.isFile()) {
            files.push(full)
          }
        }
      }
      walk(scanRoot)
      const rows: Array<{ rel: string; line: number; name: string; value: string; sha: string; context: string }> = []
      let scanned = 0
      let skippedBinary = 0
      let skippedBig = 0
      let placeholders = 0
      const seenValues = new Set<string>()
      for (const file of files) {
        let stat: fs.Stats
        try { stat = fs.statSync(file) } catch { continue }
        if (stat.size > 5 * 1024 * 1024) { skippedBig++; continue }
        let buffer: Buffer
        try { buffer = fs.readFileSync(file) } catch { continue }
        if (buffer.subarray(0, 8_192).includes(0)) { skippedBinary++; continue }
        scanned++
        const text = buffer.toString('utf8')
        for (const hit of scanText(text, active)) {
          if (seenValues.has(`${hit.name}:${hit.value}`)) continue
          seenValues.add(`${hit.name}:${hit.value}`)
          if (looksLikePlaceholder(hit.value)) { placeholders++; continue }
          const { line, text: lineText } = lineOf(text, hit.index)
          // The context line has EVERY hit value in it replaced, then runs
          // through the general redactor — a JWT in the surrounding text
          // must not ride along on the context.
          let context = lineText
          for (const other of scanText(text, active)) context = context.split(other.value).join(redactScanValue(other.value))
          context = redactSecrets(context.trim()).replace(/\s+/g, ' ')
          rows.push({
            rel: path.relative(scanRoot, file),
            line,
            name: hit.name,
            value: redactScanValue(hit.value),
            sha: createHash('sha256').update(hit.value).digest('hex'),
            context: context.length > 160 ? `${context.slice(0, 160)}…` : context,
          })
          if (rows.length >= 200) break
        }
        if (rows.length >= 200) break
      }
      const truncated = files.length >= fileCap ? ` (hit the ${fileCap}-file cap — scan a narrower root)` : ''
      const chained = appendChainEntry(config, {
        owner: who,
        label: `evidence_scan: ${rows.length} hit(s), ${placeholders} placeholder(s) filtered`,
        note: JSON.stringify({
          root: scanRoot, files: scanned, skippedBinary, skippedBig, placeholders,
          hits: rows.slice(0, 50).map(row => `${row.rel}:${row.line} ${row.name} sha256=${row.sha.slice(0, 16)}`),
        }),
      })
      return textResult([
        `Scanned ${scanned} file(s) under ${scanRoot}${truncated}${skippedBinary > 0 ? `, ${skippedBinary} binary skipped` : ''}${skippedBig > 0 ? `, ${skippedBig} over-5MB skipped` : ''}`,
        rows.length === 0
          ? `0 credential hits${placeholders > 0 ? ` (${placeholders} placeholder-shaped match(es) filtered)` : ''} — clean, and the scan is recorded`
          : `${rows.length} credential hit(s)${placeholders > 0 ? `, ${placeholders} placeholder-shaped match(es) filtered` : ''}:`,
        ...rows.map(row => `  ${row.rel}:${row.line} [${row.name}] value=${row.value} sha256 ${row.sha.slice(0, 16)}… — ${row.context}`),
        `chain entry #${chained.seq} — hash ${chained.entry_hash.slice(0, 12)}… (values never enter the chain either — file:line + sha only)`,
      ].join('\n'), rows.length > 0)
    })

  t('evidence_log', 'Read the tamper-evident evidence chain (every evidence_capture and evidence_file appended here, each entry hashing the previous). Newest first.',
    { owner: z.string().optional().describe('Filter to one owner'), limit: z.number().int().optional().describe('Default 20') },
    async ({ owner, limit }: any) => {
      let chain = readChain(config).reverse()
      if (owner !== undefined) chain = chain.filter(entry => entry.owner === owner)
      chain = chain.slice(0, limit ?? 20)
      if (chain.length === 0) return textResult('(chain empty or nothing from this owner — evidence_capture/evidence_file write it)')
      return textResult(chain.map(entry =>
        `#${entry.seq} ${entry.ts} [${entry.owner}] ${entry.label}${entry.files !== undefined ? ` — ${entry.files.length} file(s)` : ''} hash ${entry.entry_hash.slice(0, 12)}…`,
      ).join('\n'))
    })

  t('evidence_verify', 'Verify the evidence chain end-to-end: every entry hash and every link between entries. A report built on this record can cite the verification result.',
    {},
    async () => {
      const result = verifyChain(config)
      return textResult(result.ok
        ? `CHAIN VERIFIED: ${result.entries} entr${result.entries === 1 ? 'y' : 'ies'}, every hash and link intact.`
        : `CHAIN BROKEN at entry #${result.brokenAt}: ${result.reason} — entries after the break are suspect; note it in the report.`, !result.ok)
    })
}
