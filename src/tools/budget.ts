import fs from 'node:fs'
import path from 'node:path'
import { z } from 'zod'
import { errorResult, textResult, type ToolRegistrar, type ToolResult } from '../browser/tools.js'

/**
 * Per-owner target-request budgets (run-7 advice P2-14).
 *
 * Two caps were exceeded in one run (37 vs 25, 35 vs 30) and the only lane
 * that finished cleanly was the one that stopped AT its cap on its own. A
 * budget set by the Lead is now ENFORCED at the target-request choke points
 * (browser navigation, new tabs, http_request/http_download): past the limit
 * the call is refused with a message naming budget_raise as the only way out.
 */

export interface BudgetState {
  max: number
  used: number
}

export class BudgetGuard {
  private state = new Map<string, BudgetState>()

  /** Persisted to `<rootDir>/budgets.json` (smoke round 2, defect 4: budgets
   *  died with the server while the evidence chain survived — inconsistent). */
  constructor(private persistFile?: string) {
    if (persistFile === undefined) return
    try {
      const rows = JSON.parse(fs.readFileSync(persistFile, 'utf8')) as Array<{ owner: string; max: number; used: number }>
      for (const row of rows) {
        if (typeof row?.owner === 'string' && Number.isInteger(row?.max) && Number.isInteger(row?.used) && row.max > 0)
          this.state.set(row.owner, { max: row.max, used: Math.max(0, Math.min(row.used, row.max)) })
      }
    } catch { /* first run or unreadable file: start empty */ }
  }

  private save(): void {
    if (this.persistFile === undefined) return
    try {
      fs.mkdirSync(path.dirname(this.persistFile), { recursive: true })
      fs.writeFileSync(this.persistFile, JSON.stringify(this.list(), null, 2) + '\n')
    } catch { /* best effort */ }
  }

  set(owner: string, maxRequests: number): BudgetState {
    if (!Number.isInteger(maxRequests) || maxRequests <= 0)
      throw new Error(`max_requests must be a positive integer, got ${String(maxRequests)}`)
    const prior = this.state.get(owner)
    const state = { max: maxRequests, used: Math.min(prior?.used ?? 0, maxRequests) }
    this.state.set(owner, state)
    this.save()
    return { ...state }
  }

  /** Raise an existing budget (the Lead approves an overrun explicitly). */
  raise(owner: string, to?: number, add?: number): BudgetState {
    const prior = this.state.get(owner)
    if (prior === undefined)
      throw new Error(`no budget set for "${owner}" — set one with budget_set first`)
    const next = to !== undefined ? to : prior.max + (add ?? 0)
    if (!Number.isInteger(next) || next <= prior.max)
      throw new Error(`budget_raise must raise "${owner}" above its current ${prior.max} (currently used: ${prior.used}) — pass to: or add:`)
    const state = { max: next, used: prior.used }
    this.state.set(owner, state)
    this.save()
    return { ...state }
  }

  get(owner: string): BudgetState | undefined {
    const state = this.state.get(owner)
    return state === undefined ? undefined : { ...state }
  }

  list(): Array<BudgetState & { owner: string }> {
    return [...this.state.entries()]
      .map(([owner, state]) => ({ owner, ...state }))
      .sort((a, b) => a.owner.localeCompare(b.owner))
  }

  clear(owner: string): boolean {
    return this.state.delete(owner)
  }

  /**
   * Count one target request for an owner, refusing past the cap. Refused
   * requests are NOT counted (the action never ran).
   * @returns the state after counting, for the audit line.
   */
  spend(owner: string): BudgetState | undefined {
    const state = this.state.get(owner)
    if (state === undefined) return undefined
    if (state.used >= state.max)
      throw new Error(`BUDGET EXCEEDED: "${owner}" has used ${state.used}/${state.max} target requests — the cap is enforced. Ask the Lead for budget_raise {owner} before continuing.`)
    state.used += 1
    return { ...state }
  }
}

export function registerBudgetTools(server: ToolRegistrar, budget: BudgetGuard): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('budget_set', 'Set one owner\'s target-request cap (run-7 P2-14): past the limit, browser navigations, new tabs and http_request/http_download are REFUSED with a budget message. Caps make lane discipline automatic instead of moral — the only lane that finished cleanly in run 7 was the one that stopped at its cap on its own.',
    { owner: z.string().describe('Owner/lane the cap applies to'), max_requests: z.number().int().positive().describe('Cap on target requests (navigations, new tabs, http calls)') },
    async ({ owner, max_requests }: any) => {
      const state = budget.set(owner, max_requests)
      return textResult(`Budget for "${owner}": ${state.used}/${state.max} used (cap set). Past the cap, target requests are refused until budget_raise.`)
    })

  t('budget_raise', 'Raise an owner\'s existing cap (the Lead approves an overrun explicitly — this is the only way past a cap).',
    { owner: z.string(), to: z.number().int().positive().optional().describe('New absolute cap'), add: z.number().int().positive().optional().describe('Add to the current cap') },
    async ({ owner, to, add }: any) => {
      const state = budget.raise(owner, to, add)
      return textResult(`Budget for "${owner}" raised: ${state.used}/${state.max} used.`)
    })
}
