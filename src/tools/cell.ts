/**
 * Cell ledger with memory (round-7 gap list §1 — highest value).
 *
 * The "untested cell ledger" was hand-curated markdown and the run-7 review
 * found it wrong in the optimistic direction: of ~370 requests only ~1
 * P1/P2-shaped cell ever executed, while the ledger said otherwise. A cell is
 * *object graph + principal + expected verdict* — which a fixture recipe +
 * diff_pair already express; what they lacked was memory and a queue. This
 * module is that memory: cells.json (persisted, like budgets.json — never
 * in-memory after that restart bug), cell-runs.jsonl (append-only evidence
 * tuple per run).
 *
 * The one rule that matters, enforced in code: **NOT_FOUND is INCONCLUSIVE,
 * never NEGATIVE** — that is exactly the false-green the run kept producing
 * by hand. A ledger that records "tested" without the verdict tuple is how
 * this run shipped a green pipeline with zero findings, so every run stores
 * probe/miss/own statuses + body shas + deciding field, never a checkbox.
 */

import fs from 'node:fs'
import path from 'node:path'
import { z } from 'zod'
import { errorResult, textResult, type ToolRegistrar, type ToolResult } from '../browser/tools.js'
import type { ConstellationConfig } from '../config.js'
import { performLeg, type RequestResult, type RequestSpec } from './http.js'
import { verdictOf, type AuthzVerdict } from './diff.js'
import { expectPasses, executeRecipe, loadRecipes, type RecipeEnv } from './recipe.js'
import { appendVerdictEntry } from './evidence.js'

export interface CellRecord {
  id: string
  engagement: string
  /** What object graph this cell exercises (human sentence). */
  object: string
  /** The lane/identity whose attribution legs run under. */
  principal: string
  expect: 'deny' | 'allow'
  /** Named fixture recipe that stages this cell (runs INSTEAD of legs). */
  recipe?: string
  /** http_request-shaped legs (probe + miss required unless a recipe is named);
   *  each accepts `browser: "<owner>"` to ride a live session. */
  probe?: Record<string, unknown>
  miss?: Record<string, unknown>
  own?: Record<string, unknown>
  notes?: string
  createdAt: string
}

export interface CellRunRecord {
  ts: string
  id: string
  ok: boolean
  source: 'legs' | 'recipe'
  expect: string
  verdict?: AuthzVerdict
  deciding_field?: string
  statuses?: { probe: number; miss: number; own?: number }
  shas?: { probe: string; miss: string; own?: string }
  /** recipe-source failures: which step action failed (expect = the boundary,
   *  anything else = the fixture/session broke → INCONCLUSIVE). */
  failedAction?: string
  reason?: string
  evidenceSeq?: number
  evidenceHash?: string
}

export type CellStatus = 'NEVER TESTED' | 'INCONCLUSIVE' | 'NEGATIVE' | 'CANDIDATE'

export function cellsFile(config: ConstellationConfig): string {
  return path.join(config.rootDir, 'cells.json')
}

function runsFile(config: ConstellationConfig): string {
  return path.join(config.rootDir, 'cell-runs.jsonl')
}

export function loadCells(config: ConstellationConfig): Record<string, CellRecord> {
  try {
    const parsed = JSON.parse(fs.readFileSync(cellsFile(config), 'utf8')) as Record<string, unknown>
    const out: Record<string, CellRecord> = {}
    for (const [id, value] of Object.entries(parsed)) {
      if (value === null || typeof value !== 'object') continue
      const raw = value as Partial<CellRecord> & { remove?: unknown }
      if (raw.remove === true) continue
      if (typeof raw.engagement !== 'string' || typeof raw.object !== 'string') continue
      out[id] = {
        id,
        engagement: raw.engagement,
        object: raw.object,
        principal: typeof raw.principal === 'string' ? raw.principal : 'unknown',
        expect: raw.expect === 'allow' ? 'allow' : 'deny',
        ...(typeof raw.recipe === 'string' ? { recipe: raw.recipe } : {}),
        ...(raw.probe !== undefined ? { probe: raw.probe as Record<string, unknown> } : {}),
        ...(raw.miss !== undefined ? { miss: raw.miss as Record<string, unknown> } : {}),
        ...(raw.own !== undefined ? { own: raw.own as Record<string, unknown> } : {}),
        ...(typeof raw.notes === 'string' ? { notes: raw.notes } : {}),
        createdAt: typeof raw.createdAt === 'string' ? raw.createdAt : new Date().toISOString(),
      }
    }
    return out
  } catch { return {} }
}

function saveCell(config: ConstellationConfig, cell: CellRecord): void {
  const file = cellsFile(config)
  let parsed: Record<string, unknown> = {}
  try { parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, unknown> } catch { /* first cell */ }
  parsed[cell.id] = cell
  fs.mkdirSync(config.rootDir, { recursive: true })
  fs.writeFileSync(file, JSON.stringify(parsed, null, 2) + '\n')
}

export function readRuns(config: ConstellationConfig, cellId?: string): CellRunRecord[] {
  let text = ''
  try { text = fs.readFileSync(runsFile(config), 'utf8') } catch { return [] }
  const out: CellRunRecord[] = []
  for (const line of text.split('\n')) {
    if (line.trim() === '') continue
    try {
      const parsed = JSON.parse(line) as CellRunRecord
      if (typeof parsed.id === 'string' && (cellId === undefined || parsed.id === cellId)) out.push(parsed)
    } catch { /* skip malformed */ }
  }
  return out
}

function appendRun(config: ConstellationConfig, record: CellRunRecord): void {
  try {
    fs.mkdirSync(config.rootDir, { recursive: true })
    fs.appendFileSync(runsFile(config), JSON.stringify(record) + '\n')
  } catch { /* best effort */ }
}

/** Pure: fold a cell's runs into its status. THE rule: NOT_FOUND (or a
 *  recipe failing anywhere but its expect step) is INCONCLUSIVE — never
 *  NEGATIVE. A run that behaved as designed is NEGATIVE; the opposite of
 *  the expected verdict is CANDIDATE. */
export function foldCellStatus(cell: CellRecord, runs: CellRunRecord[]): { status: CellStatus; last?: CellRunRecord } {
  const mine = runs.filter(run => run.id === cell.id)
  if (mine.length === 0) return { status: 'NEVER TESTED' }
  const last = mine[mine.length - 1]!
  if (last.source === 'recipe') {
    if (last.ok) return { status: 'NEGATIVE', last }
    if (last.failedAction === 'expect') return { status: 'CANDIDATE', last }
    return { status: 'INCONCLUSIVE', last }
  }
  if (last.verdict === undefined) return { status: 'INCONCLUSIVE', last }
  if (last.verdict === 'NOT_FOUND') return { status: 'INCONCLUSIVE', last }
  return expectPasses(last.verdict, cell.expect) ? { status: 'NEGATIVE', last } : { status: 'CANDIDATE', last }
}

export type CellEnv = RecipeEnv

export function registerCellTools(server: ToolRegistrar, env: CellEnv): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('cell_register', 'Register one TEST CELL in the machine ledger (round-7 §1): object graph + principal + expected verdict (deny|allow), with either http legs (probe + miss [+ own] — http_request shape, `browser: "<owner>"` rides a live session) or a named fixture recipe that stages the whole cell. This replaces hand-curated "untested cells" markdown: the run-7 review found that ledger wrong in the optimistic direction. `remove: true` deletes.',
    {
      id: z.string().describe('Stable cell id, e.g. "klaviyo-shared-page-revoke"'),
      engagement: z.string().describe('Engagement/lane name for cell_status filtering'),
      object: z.string().describe('What object graph this cell exercises (one sentence)'),
      principal: z.string().describe('Lane/identity whose attribution the legs run under'),
      expect: z.enum(['deny', 'allow']).describe('The verdict a HEALTHY boundary returns'),
      probe: z.record(z.string(), z.unknown()).optional().describe('Leg AS THE OTHER IDENTITY against the real object'),
      miss: z.record(z.string(), z.unknown()).optional().describe('The random-id lookup-miss control'),
      own: z.record(z.string(), z.unknown()).optional().describe('Leg as the object owner (enables DATA_LEAK)'),
      recipe: z.string().optional().describe('Named fixture recipe that stages this cell (runs INSTEAD of legs)'),
      notes: z.string().optional().describe('Preconditions worth remembering (accounts, state)'),
      remove: z.boolean().optional(),
    },
    async ({ id, engagement, object: cellObject, principal, expect, probe, miss, own, recipe, notes, remove }: any) => {
      if (remove === true) {
        const file = cellsFile(env.config)
        let parsed: Record<string, unknown> = {}
        try { parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, unknown> } catch { /* none */ }
        if (!(id in parsed)) return textResult(`No cell "${id}".`)
        parsed[id] = { remove: true }
        fs.mkdirSync(env.config.rootDir, { recursive: true })
        fs.writeFileSync(file, JSON.stringify(parsed, null, 2) + '\n')
        return textResult(`Cell "${id}" removed.`)
      }
      if (recipe === undefined && (probe === undefined || miss === undefined))
        return textResult('Refusing to save: a cell needs either probe + miss legs or a named recipe.', true)
      if (recipe !== undefined && loadRecipes(env.config)[recipe] === undefined)
        return textResult(`Refusing to save: unknown recipe "${recipe}" (fixture_recipe_set creates one).`, true)
      const cell: CellRecord = {
        id, engagement, object: cellObject, principal, expect,
        ...(recipe !== undefined ? { recipe } : {}),
        ...(probe !== undefined ? { probe } : {}),
        ...(miss !== undefined ? { miss } : {}),
        ...(own !== undefined ? { own } : {}),
        ...(notes !== undefined ? { notes } : {}),
        createdAt: new Date().toISOString(),
      }
      saveCell(env.config, cell)
      return textResult(`Cell "${id}" registered — ${engagement}: ${cellObject} (expect ${expect}, principal "${principal}")${recipe !== undefined ? ` via recipe "${recipe}"` : ' via diff legs'}. Run it with cell_run {id}.`)
    })

  t('cell_run', 'Execute one registered cell and store its verdict tuple (round-7 §1): legs cells run probe/miss/own through diff_pair semantics; recipe cells execute their fixture recipe. Every run appends the FULL evidence tuple (statuses, body shas, deciding field) to cell-runs.jsonl and — when a real verdict lands — cites itself in the tamper-evident chain. NOT_FOUND records as INCONCLUSIVE, never negative: a lookup miss proves nothing.',
    { id: z.string().describe('Cell id from cell_register'), owner: z.string().optional().describe('Overrides the cell principal for this run') },
    async ({ id, owner }: any) => {
      const cells = loadCells(env.config)
      const cell = cells[id]
      if (cell === undefined) {
        const known = Object.keys(cells).join(', ')
        return textResult(`unknown cell "${id}"${known !== '' ? ` (known: ${known})` : ' — none registered; cell_register creates one'}`, true)
      }
      const who = owner ?? cell.principal
      if (cell.recipe !== undefined) {
        const recipes = loadRecipes(env.config)
        const recipe = recipes[cell.recipe]
        if (recipe === undefined) return textResult(`cell "${id}" names recipe "${cell.recipe}" which no longer exists — re-register with legs or recreate the recipe.`, true)
        const outcome = await executeRecipe(env, recipe, who)
        const record: CellRunRecord = {
          ts: new Date().toISOString(), id, ok: outcome.ok, source: 'recipe', expect: cell.expect,
          ...(!outcome.ok ? { failedAction: outcome.failedAction, reason: outcome.reason } : {}),
        }
        appendRun(env.config, record)
        const { status } = foldCellStatus(cell, [...readRuns(env.config), record])
        return textResult([
          outcome.ok
            ? `CELL "${id}" NEGATIVE — recipe "${cell.recipe}" completed, every expect held (${outcome.seconds} s).`
            : `CELL "${id}" ${outcome.failedAction === 'expect' ? 'CANDIDATE — the recipe FAILED AT ITS expect STEP: the boundary did not behave as designed' : 'INCONCLUSIVE — the recipe failed outside its expect step (fixture/session): '}`,
          ...(outcome.ok ? [] : [outcome.reason ?? '']),
          ...outcome.lines.slice(-6),
          `status: ${status} (run recorded; cell_status summarizes)`,
        ].join('\n'), !outcome.ok)
      }
      // Legs path — the diff_pair core, remembered.
      const leg = (raw: Record<string, unknown>): Promise<RequestResult> =>
        performLeg(env, raw as unknown as RequestSpec & { browser?: unknown }, who, 'cell')
      const [probe, miss, own] = await Promise.all([
        leg(cell.probe!),
        leg(cell.miss!),
        cell.own !== undefined ? leg(cell.own) : Promise.resolve(undefined),
      ])
      const verdict = verdictOf({ probe, miss, ...(own !== undefined ? { own } : {}) })
      const passed = expectPasses(verdict.verdict, cell.expect)
      const record: CellRunRecord = {
        ts: new Date().toISOString(), id, ok: passed, source: 'legs', expect: cell.expect,
        verdict: verdict.verdict,
        deciding_field: verdict.deciding_field,
        statuses: { probe: probe.status, miss: miss.status, ...(own !== undefined ? { own: own.status } : {}) },
        shas: { probe: probe.body_sha256, miss: miss.body_sha256, ...(own !== undefined ? { own: own.body_sha256 } : {}) },
        ...(verdict.verdict === 'NOT_FOUND' ? { reason: 'probe ≡ miss: the lookup missed — INCONCLUSIVE by rule' } : {}),
      }
      if (verdict.verdict !== 'NOT_FOUND') {
        try {
          const entry = appendVerdictEntry(env.config, who, 'cell_run', {
            verdict: verdict.verdict,
            deciding_field: verdict.deciding_field,
            probe: { status: probe.status, sha: probe.body_sha256 },
            miss: { status: miss.status, sha: miss.body_sha256 },
            ...(own !== undefined ? { own: { status: own.status, sha: own.body_sha256 } } : {}),
            expect: cell.expect,
            passed,
            object: cell.object,
          })
          record.evidenceSeq = entry.seq
          record.evidenceHash = entry.entry_hash
        } catch { /* the chain must never fail the verdict */ }
      }
      appendRun(env.config, record)
      const { status } = foldCellStatus(cell, [...readRuns(env.config), record])
      return textResult([
        `CELL "${id}": ${verdict.verdict} (deciding: ${verdict.deciding_field}) — status ${status}`,
        verdict.note,
        `probe HTTP ${probe.status} sha=${probe.body_sha256.slice(0, 12)}… · miss HTTP ${miss.status} sha=${miss.body_sha256.slice(0, 12)}…${own !== undefined ? ` · own HTTP ${own.status} sha=${own.body_sha256.slice(0, 12)}…` : ''}`,
        record.evidenceSeq !== undefined ? `evidence: chain entry #${record.evidenceSeq} (hash ${record.evidenceHash!.slice(0, 12)}…)` : '(NOT_FOUND records no evidence — it proves nothing)',
      ].join('\n'))
    })

  t('cell_status', 'The engagement scoreboard (round-7 §1): every cell as NEVER TESTED | INCONCLUSIVE | NEGATIVE | CANDIDATE with its last verdict tuple. NOT_FOUND is INCONCLUSIVE by rule — the false-green that shipped a green pipeline with zero findings cannot be re-created by optimism here.',
    { engagement: z.string().optional().describe('Filter to one engagement (default: all)') },
    async ({ engagement }: any) => {
      const cells = Object.values(loadCells(env.config)).filter(cell => engagement === undefined || cell.engagement === engagement)
      if (cells.length === 0) return textResult(`(no cells${engagement !== undefined ? ` for "${engagement}"` : ''} — cell_register creates one)`)
      const runs = readRuns(env.config)
      return textResult(cells.map(cell => {
        const { status, last } = foldCellStatus(cell, runs)
        const tuple = last?.verdict !== undefined
          ? ` — last ${last.verdict} (${last.deciding_field}) ${last.ts.slice(0, 16).replace('T', ' ')}`
          : last?.reason !== undefined ? ` — ${last.reason}` : ''
        return `${status.padEnd(12)} ${cell.id} [${cell.engagement}] expect ${cell.expect}${cell.recipe !== undefined ? ` via ${cell.recipe}` : ''}${tuple}`
      }).join('\n'))
    })

  t('cell_ledger', 'The machine ledger for one engagement (round-7 §1) — generated output replacing intel/76-style hand-curated markdown: every cell with its definition, run count, last verdict tuple and evidence citation. What the run-7 review had to reconstruct by hand, as one call.',
    { engagement: z.string() },
    async ({ engagement }: any) => {
      const cells = Object.values(loadCells(env.config)).filter(cell => cell.engagement === engagement)
      if (cells.length === 0) return textResult(`(no cells for "${engagement}")`)
      const runs = readRuns(env.config)
      const blocks = cells.map(cell => {
        const mine = runs.filter(run => run.id === cell.id)
        const { status, last } = foldCellStatus(cell, runs)
        return [
          `${cell.id} — ${status}`,
          `  object:    ${cell.object}`,
          `  principal: ${cell.principal} · expect ${cell.expect}${cell.recipe !== undefined ? ` · recipe ${cell.recipe}` : ''}`,
          ...(cell.notes !== undefined ? [`  notes:     ${cell.notes}`] : []),
          `  runs: ${mine.length}${last !== undefined ? ` · last ${last.source === 'legs' ? `${last.verdict} (${last.deciding_field}) probe ${last.statuses?.probe}/miss ${last.statuses?.miss}` : `${last.ok ? 'recipe ok' : `recipe failed at ${last.failedAction}`}`} ${last.ts}` : ''}`,
          ...(last?.evidenceSeq !== undefined ? [`  evidence:  chain #${last.evidenceSeq} hash ${last.evidenceHash?.slice(0, 12)}…`] : []),
        ].join('\n')
      })
      const counts = { candidate: 0, negative: 0, inconclusive: 0, untested: 0 } as Record<string, number>
      for (const cell of cells) counts[foldCellStatus(cell, runs).status === 'NEVER TESTED' ? 'untested' : foldCellStatus(cell, runs).status.toLowerCase()]! += 1
      return textResult([
        `LEDGER "${engagement}": ${cells.length} cell(s) — ${counts.candidate} CANDIDATE · ${counts.negative} NEGATIVE · ${counts.inconclusive} INCONCLUSIVE · ${counts.untested} NEVER TESTED`,
        ...blocks,
      ].join('\n\n'))
    })
}
