import { z } from 'zod'
import { errorResult, textResult, type ToolResult, type ToolRegistrar } from '../browser/tools.js'
import type { ScopeGuard } from '../scope.js'

/** The agent-facing arm of the scope guard: scope_set arms a rule (optionally
 *  per owner/lane — a 10-lane run spans 10 engagements), scope_get prints it,
 *  scope_clear drops stale rules, scope_audit replays the allow/deny log. */
export function registerScopeTools(server: ToolRegistrar, scope: ScopeGuard, requireScope: boolean): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('scope_set', 'Declare the engagement scope ONCE at lane start: in_scope hosts are then the ONLY hosts http_request and browser navigation may touch (out_scope always wins; every decision is audited). Entries: `example.com`, `*.example.com`, `example.com/api/`. Pass `owner` to arm a PER-LANE rule for one teammate (each lane gets its own engagement scope); omit it for the global fallback rule.',
    {
      engagement: z.string().describe('Engagement/lane name, e.g. "klaviyo-mbb"'),
      in_scope: z.array(z.string()).min(1).describe('Allowed host entries'),
      out_scope: z.array(z.string()).optional().describe('Explicitly denied entries (win over in_scope)'),
      owner: z.string().optional().describe('Arm this rule for ONE owner/lane only; others keep the global rule'),
    },
    async ({ engagement, in_scope, out_scope, owner }: any) => {
      const rule = { engagement, in_scope, out_scope: out_scope ?? [] }
      scope.set(rule, owner)
      const scopeOwner = owner === undefined ? 'global fallback' : `owner "${owner}"`
      return textResult([
        `scope ARMED for ${rule.engagement} (${scopeOwner})`,
        `in_scope:  ${rule.in_scope.join(', ')}`,
        `out_scope: ${rule.out_scope.join(', ') || '∅'}`,
        ...(owner === undefined ? [] : [`other owners fall back to: ${scope.current() === null ? 'UNRESTRICTED' : scope.current()!.engagement}`]),
        `http_request and browser navigation are now enforced; scope_audit prints the log.`,
      ].join('\n'))
    })

  t('scope_get', 'Print the armed scope: your owner rule if one exists, else the global rule (or UNRESTRICTED).',
    { owner: z.string().optional().describe('Inspect this owner\'s rule instead of the global one') },
    async ({ owner }: any) => {
      const rule = scope.current(owner)
      const mine = owner !== undefined && scope.current(owner) !== null
      if (rule === null) {
        const perOwners = scope.owners()
        return textResult(requireScope
          ? `scope: LOCKED — no scope set and CONSTELLATION_REQUIRE_SCOPE=1, so every non-local request is denied. Call scope_set first.${perOwners.length > 0 ? ` (per-owner rules exist for: ${perOwners.join(', ')})` : ''}`
          : `scope: UNRESTRICTED (no scope set — call scope_set before engaging a target)${perOwners.length > 0 ? `; per-owner rules exist for: ${perOwners.join(', ')}` : ''}`)
      }
      return textResult([
        `scope: ${rule.engagement}${mine && owner !== undefined ? ` (owner "${owner}")` : owner !== undefined ? ` (no owner rule for "${owner}" — showing the global fallback)` : ''}`,
        `in_scope:  ${rule.in_scope.join(', ')}`,
        `out_scope: ${rule.out_scope.join(', ') || '∅'}`,
        ...(scope.owners().length > 0 ? [`per-owner rules: ${scope.owners().join(', ')}`] : []),
      ].join('\n'))
    })

  t('scope_clear', 'Drop the armed scope so a new engagement starts clean — a stale persisted rule silently denies a fresh run after a restart, so clear it at lane end. Pass owner to drop just that lane\'s rule.',
    { owner: z.string().optional().describe('Clear only this owner\'s rule; omit to clear everything') },
    async ({ owner }: any) => {
      scope.clear(owner)
      return textResult(owner === undefined
        ? 'scope CLEARED (global + all per-owner rules). Requests are unrestricted again (unless CONSTELLATION_REQUIRE_SCOPE=1).'
        : `scope CLEARED for owner "${owner}". Remaining per-owner rules: ${scope.owners().join(', ') || '∅'}.`)
    })

  t('scope_audit', 'Replay the scope decision log (newest first): every allowed/denied request with owner, tool, host, reason.',
    { limit: z.number().int().optional().describe('Newest N decisions (default 50)'), owner: z.string().optional().describe('Filter by owner') },
    async ({ limit, owner }: any) => {
      const lines = scope.auditLines(limit ?? 50, owner)
      if (lines.length === 0) return textResult('(no scope decisions recorded yet)')
      return textResult(lines.map(l => `${l.allowed ? 'ALLOW' : 'DENY '} ${l.ts} ${l.owner} ${l.tool} ${l.host}${l.allowed ? '' : ' — ' + l.reason}`).join('\n'))
    })
}
