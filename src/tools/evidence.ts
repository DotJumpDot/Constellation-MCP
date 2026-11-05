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
