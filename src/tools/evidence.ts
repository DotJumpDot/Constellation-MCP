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

export function registerEvidenceTools(server: ToolRegistrar, config: ConstellationConfig): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('evidence_log', 'Read the tamper-evident evidence chain (every evidence_capture appended here, each entry hashing the previous). Newest first.',
    { owner: z.string().optional().describe('Filter to one owner'), limit: z.number().int().optional().describe('Default 20') },
    async ({ owner, limit }: any) => {
      let chain = readChain(config).reverse()
      if (owner !== undefined) chain = chain.filter(entry => entry.owner === owner)
      chain = chain.slice(0, limit ?? 20)
      if (chain.length === 0) return textResult('(chain empty or nothing from this owner — evidence_capture writes it)')
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
