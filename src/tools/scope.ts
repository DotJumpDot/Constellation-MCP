import { z } from 'zod'
import { errorResult, textResult, type ToolResult, type ToolRegistrar } from '../browser/tools.js'
import type { ScopeGuard } from '../scope.js'

/** The missing arm of the scope guard: agents could be REFUSED out-of-scope
 *  but had no tool to ARM it. scope_set writes the engagement rule (persisted),
 *  scope_get prints it, scope_audit replays the allow/deny log. */
export function registerScopeTools(server: ToolRegistrar, scope: ScopeGuard, requireScope: boolean): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('scope_set', 'Declare the engagement scope ONCE at lane start: in_scope hosts are then the ONLY hosts http_request and browser navigation may touch (out_scope always wins; every decision is audited). Entries: `example.com`, `*.example.com`, `example.com/api/`.',
    {
      engagement: z.string().describe('Engagement/lane name, e.g. "klaviyo-mbb"'),
      in_scope: z.array(z.string()).min(1).describe('Allowed host entries'),
      out_scope: z.array(z.string()).optional().describe('Explicitly denied entries (win over in_scope)'),
    },
    async ({ engagement, in_scope, out_scope }: any) => {
      scope.set({ engagement, in_scope, out_scope: out_scope ?? [] })
      const rule = scope.current()!
      return textResult([
        `scope ARMED for ${rule.engagement}`,
        `in_scope:  ${rule.in_scope.join(', ')}`,
        `out_scope: ${rule.out_scope.join(', ') || '∅'}`,
        `http_request and browser navigation are now enforced; scope_audit prints the log.`,
      ].join('\n'))
    })

  t('scope_get', 'Print the currently armed engagement scope (or UNRESTRICTED).',
    {},
    async () => {
      const rule = scope.current()
      if (rule === null) {
        return textResult(requireScope
          ? `scope: LOCKED — no scope set and CONSTELLATION_REQUIRE_SCOPE=1, so every non-local request is denied. Call scope_set first.`
          : `scope: UNRESTRICTED (no scope set — call scope_set before engaging a target)`)
      }
      return textResult(`scope: ${rule.engagement}\nin_scope:  ${rule.in_scope.join(', ')}\nout_scope: ${rule.out_scope.join(', ') || '∅'}`)
    })

  t('scope_audit', 'Replay the scope decision log (newest first): every allowed/denied request with owner, tool, host, reason.',
    { limit: z.number().int().optional().describe('Newest N decisions (default 50)'), owner: z.string().optional().describe('Filter by owner') },
    async ({ limit, owner }: any) => {
      const lines = scope.auditLines(limit ?? 50, owner)
      if (lines.length === 0) return textResult('(no scope decisions recorded yet)')
      return textResult(lines.map(l => `${l.allowed ? 'ALLOW' : 'DENY '} ${l.ts} ${l.owner} ${l.tool} ${l.host}${l.allowed ? '' : ' — ' + l.reason}`).join('\n'))
    })
}
