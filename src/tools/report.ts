/**
 * Report skeleton assembly (round-7 gap list §6).
 *
 * "AI drafts, human submits" holds; what was manual for every report was the
 * MECHANICS — statuses, hashes, timestamps, VRT row. This tool assembles a
 * markdown skeleton from verified cells + the evidence chain, keeps prose as
 * explicit placeholders (Google's quality table scores unedited AI text at
 * 0.8×, so prose stays the human's), and REFUSES to assemble from anything
 * but CANDIDATE cells — no reports built out of negatives.
 */

import fs from 'node:fs'
import path from 'node:path'
import { z } from 'zod'
import { errorResult, textResult, type ToolRegistrar, type ToolResult } from '../browser/tools.js'
import type { ConstellationConfig } from '../config.js'
import { foldCellStatus, loadCells, readRuns, type CellRecord } from './cell.js'

export interface ReportEnv {
  config: ConstellationConfig
}

function renderCellRow(cell: CellRecord, evidence: string): string {
  return `| ${cell.id} | ${cell.object} | ${cell.principal} | expect ${cell.expect} | ${evidence} |`
}

export function registerReportTools(server: ToolRegistrar, env: ReportEnv): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('report_assemble', 'Assemble a report SKELETON from verified CANDIDATE cells (round-7 §6): repro table (cell → object → verdict tuple → evidence chain citation), precondition list, a VRT placeholder row, and TODO markers where HUMAN prose belongs (AI-slop scoring is real; prose stays yours). REFUSES any cell that is not CANDIDATE — no report is built out of a negative or an inconclusive run. `write: true` also saves the markdown under the engagement\'s artifacts dir; it never writes into Reports/.',
    {
      engagement: z.string().describe('Engagement name (report header + artifacts dir)'),
      cells: z.array(z.string()).min(1).describe('Cell ids to include — every one must be CANDIDATE'),
      write: z.boolean().optional().describe('Also write the skeleton to outputDir/<engagement>/'),
    },
    async ({ engagement, cells: cellIds, write }: any) => {
      const cells = loadCells(env.config)
      const runs = readRuns(env.config)
      const rows: string[] = []
      const preconditions: string[] = []
      const refusals: string[] = []
      const missing = cellIds.filter((id: string) => cells[id] === undefined)
      if (missing.length > 0) return textResult(`unknown cell id(s): ${missing.join(', ')} — cell_register first.`, true)
      for (const id of cellIds as string[]) {
        const cell = cells[id]!
        const { status, last } = foldCellStatus(cell, runs)
        if (status !== 'CANDIDATE') {
          refusals.push(`${id} is ${status}${last?.verdict !== undefined ? ` (last verdict ${last.verdict})` : ''} — only CANDIDATE cells belong in a report`)
          continue
        }
        const tuple = last?.source === 'legs' && last.statuses !== undefined && last.shas !== undefined
          ? `${last.verdict} (probe ${last.statuses.probe}/miss ${last.statuses.miss}${last.statuses.own !== undefined ? `/own ${last.statuses.own}` : ''}; sha ${last.shas.probe.slice(0, 8)}…/${last.shas.miss.slice(0, 8)}…; deciding ${last.deciding_field})`
          : `recipe expect step FAILED (${last?.reason?.slice(0, 120) ?? 'see cell_ledger'})`
        const citation = last?.evidenceSeq !== undefined ? `chain #${last.evidenceSeq} hash ${last.evidenceHash?.slice(0, 12)}…` : '⚠ no chain citation — re-run with cell_run'
        rows.push(renderCellRow(cell, `${tuple} · ${citation}`))
        if (cell.notes !== undefined) preconditions.push(`- ${cell.notes}`)
      }
      if (refusals.length > 0) {
        return textResult(['REFUSING to assemble:', ...refusals.map(line => `- ${line}`), '', 'A report cites what the boundary DID do; re-run the cells (cell_run) until the verdicts are real.'].join('\n'), true)
      }
      const now = new Date().toISOString().slice(0, 16).replace('T', ' ')
      const markdown = [
        `# ${engagement} — candidate finding report (skeleton)`,
        '',
        `Assembled ${now} from ${rows.length} CANDIDATE cell(s). Verify the chain before submitting: \`evidence_verify\`.`,
        '',
        '## Summary',
        '',
        '<!-- HUMAN: one paragraph — what the boundary should do, what it does, who is affected. -->',
        '',
        '## Reproduction',
        '',
        '| cell | object | principal | expected | observed |',
        '|---|---|---|---|---|',
        ...rows,
        '',
        '## Preconditions',
        '',
        ...(preconditions.length > 0 ? preconditions : ['- <!-- HUMAN: accounts/state/setup a triager needs -->']),
        '',
        '## VRT row (draft)',
        '',
        '| severity | title | | |',
        '|---|---|---|---|',
        `| <!-- HUMAN: VRT severity --> | <!-- HUMAN: short title --> | | |`,
        '',
        '## Evidence',
        '',
        `- Run \`evidence_verify\` — every verdict above cites its chain entry by number and hash.`,
        `- <!-- HUMAN: attach body_file pairs / screenshots if the program wants them -->`,
        '',
        '## Impact',
        '',
        '<!-- HUMAN: your words. Unedited AI prose scores 0.8× on quality tables — write this yourself. -->',
        '',
      ].join('\n')
      let stored = ''
      if (write === true) {
        try {
          const dir = path.join(env.config.outputDir, engagement.replace(/[^A-Za-z0-9._-]/g, '_'))
          fs.mkdirSync(dir, { recursive: true })
          const file = path.join(dir, `report-skeleton-${Date.now()}.md`)
          fs.writeFileSync(file, markdown)
          stored = `\n\nwritten to ${file}`
        } catch { /* best effort */ }
      }
      return textResult(markdown + stored)
    })
}
