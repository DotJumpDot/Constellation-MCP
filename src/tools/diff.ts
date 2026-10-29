/**
 * Control-pair comparison as a primitive (run-8 proposals §4).
 *
 * Every authorization cell ends in the same hand-argument: is the
 * other-identity response a REAL authorization decision or just a lookup
 * miss? diff_pair encodes the C0/C1/C2 pattern — a different STATUS between
 * the probe and the random-id miss control means a real decision; an
 * IDENTICAL body means the object lookup missed and the cell proves nothing.
 * That distinction flipped two verdicts in run 7 and was argued by hand each
 * time.
 */

import { z } from 'zod'
import { errorResult, textResult, type ToolRegistrar, type ToolResult } from '../browser/tools.js'
import type { ScopeGuard } from '../scope.js'
import type { JarStore, RequestResult, RequestSpec } from './http.js'
import { performLeg } from './http.js'

export type AuthzVerdict = 'AUTHORIZATION_DENIAL' | 'NOT_FOUND' | 'SOFT_ALLOW' | 'DATA_LEAK'

export interface DiffPairLegs {
  own?: RequestResult
  probe: RequestResult
  miss: RequestResult
  anon?: RequestResult
}

/** Pure verdict logic so tests pin the rules. */
export function verdictOf(legs: DiffPairLegs): {
  verdict: AuthzVerdict
  deciding_field: string
  note: string
} {
  const { probe, miss } = legs
  if (probe.body_sha256 === miss.body_sha256 && probe.status === miss.status) {
    return { verdict: 'NOT_FOUND', deciding_field: 'none', note: 'probe and random-id miss control are byte-identical: the object lookup MISSED for the other identity too — the fixture does not exercise authorization; rebuild the fixture before reading anything into this cell' }
  }
  const statusDiffers = probe.status !== miss.status
  let decidingField = statusDiffers ? 'status' : 'body'
  if (probe.status >= 200 && probe.status < 300) {
    if (legs.own !== undefined && legs.own.status >= 200 && legs.own.status < 300
      && probe.body_sha256 === legs.own.body_sha256) {
      return {
        verdict: 'DATA_LEAK',
        deciding_field: decidingField,
        note: `another identity received the SAME bytes as the owner (both sha ${probe.body_sha256.slice(0, 12)}…) with HTTP ${probe.status} — the object is not access-controlled`,
      }
    }
    return {
      verdict: 'SOFT_ALLOW',
      deciding_field: 'body',
      // Round-7 D3: without an own leg there IS no owner to differ from — the
      // honest comparison is against the miss control, and the note must say
      // the DATA_LEAK verdict is unavailable rather than imply it ran.
      note: legs.own !== undefined
        ? `another identity got HTTP ${probe.status} but different bytes than the owner — a soft allow: some data or a different rendering leaked; diff the bodies for the deciding field`
        : `another identity got HTTP ${probe.status} with different bytes than the MISS CONTROL (no owner leg was sent — the DATA_LEAK verdict is unavailable) — a soft allow: some data or a different rendering leaked; diff the probe against the miss control`,
    }
  }
  return {
    verdict: 'AUTHORIZATION_DENIAL',
    deciding_field: statusDiffers ? 'status' : 'body',
    note: `probe HTTP ${probe.status} vs miss control HTTP ${miss.status}${statusDiffers ? '' : ' (same status, different body)'} — the server makes a REAL authorization decision for the other identity; this is the deny half of a valid C1/C2 pair`,
  }
}

/** First JSON pointer where two parsed bodies differ (added/removed/changed). */
export function firstJsonDiff(a: unknown, b: unknown, prefix = ''): string | undefined {
  if (a === b) return undefined
  if (typeof a !== 'object' || a === null || typeof b !== 'object' || b === null) return prefix === '' ? '$' : prefix
  if (Array.isArray(a) !== Array.isArray(b)) return prefix === '' ? '$' : prefix
  const aObj = a as Record<string, unknown>
  const bObj = b as Record<string, unknown>
  const keys = [...new Set([...Object.keys(aObj), ...Object.keys(bObj)])]
  for (const key of keys) {
    const child = `${prefix}/${key}`
    if (!(key in aObj)) return `${child} (added)`
    if (!(key in bObj)) return `${child} (removed)`
    const found = firstJsonDiff(aObj[key], bObj[key], child)
    if (found !== undefined) return found
  }
  return undefined
}

export interface DiffEnv {
  jars: JarStore
  scope: ScopeGuard
  budget?: import('./budget.js').BudgetGuard
  /** Live-browser bridge (round 6): lets legs carry `browser: '<owner>'`. */
  sessionFor?: (owner: string) => { ensure(): Promise<{ request: import('./http.js').BrowserRequestClient }> }
}

export function registerDiffTools(server: ToolRegistrar, env: DiffEnv): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  const REQUEST = () => z.object({
    url: z.string(), method: z.string().optional(), headers: z.record(z.string(), z.string()).optional(),
    body: z.unknown().optional(), jar: z.string().optional(), auth: z.any().optional(), timeout_ms: z.number().optional(),
    browser: z.union([z.boolean(), z.string()]).optional().describe('Send this leg through that owner\'s LIVE browser session (its cookie state) instead of a jar — for identities that logged in via the browser'),
  }).describe('http_request spec (use $secret:NAME refs; jar = identity; browser = live session identity)')

  t('diff_pair', 'The authorization verdict primitive (run-8 §4): send the SAME object request as your identity, another identity, and a random-id MISS CONTROL, and get a verdict — AUTHORIZATION_DENIAL (real decision: status/body differs from miss), NOT_FOUND (probe ≡ miss: lookup missed, cell proves nothing), SOFT_ALLOW (2xx but different bytes), DATA_LEAK (same bytes as owner). The probe-vs-miss distinction flipped two run-7 verdicts by hand; this is that argument, mechanized. Legs carry `browser: "<owner>"` (or true = your own owner) to ride that identity\'s LIVE browser session — the bridge for browser-login identities no jar can represent (round 6: grant → expect allow → revoke → expect deny held by two owners).',
    {
      probe: REQUEST().describe('Request AS THE OTHER IDENTITY against the real object (their jar, or browser: their lane)'),
      miss: REQUEST().describe('The same request against a RANDOM/NONEXISTENT id — the lookup-miss control'),
      own: REQUEST().optional().describe('The same request as the object owner (your jar, or browser: your lane) — enables the DATA_LEAK verdict'),
      anon: REQUEST().optional().describe('The same request UNAUTHENTICATED (no jar) — flags unauthenticated access'),
      owner: z.string().optional().describe('Attribution for the scope audit'),
    },
    async ({ probe, miss, own, anon, owner }: any) => {
      const who = owner ?? 'unknown'
      const run = (spec: RequestSpec & { browser?: unknown }): Promise<import('./http.js').RequestResult> =>
        performLeg(env, spec, who, 'diff_pair')
      const [probeResult, missResult, ownResult, anonResult] = await Promise.all([
        run(probe),
        run(miss),
        own !== undefined ? run(own) : Promise.resolve(undefined),
        anon !== undefined ? run(anon) : Promise.resolve(undefined),
      ])
      const legs: DiffPairLegs = { probe: probeResult, miss: missResult, ...(ownResult !== undefined ? { own: ownResult } : {}), ...(anonResult !== undefined ? { anon: anonResult } : {}) }
      const { verdict, deciding_field, note } = verdictOf(legs)
      let deciding = deciding_field
      if (deciding_field === 'body') {
        try {
          const found = firstJsonDiff(JSON.parse(missResult.body), JSON.parse(probeResult.body))
          if (found !== undefined) deciding = `body ${found}`
        } catch { /* non-JSON bodies: keep 'body' */ }
      }
      const line = (label: string, result: RequestResult): string =>
        `${label}: HTTP ${result.status} sha=${result.body_sha256.slice(0, 12)}… (${result.timing_ms} ms)`
      return textResult([
        `VERDICT: ${verdict} (deciding: ${deciding})`,
        note,
        ...(anonResult !== undefined && anonResult.status >= 200 && anonResult.status < 300
          ? [`⚠ UNAUTHENTICATED access also returns HTTP ${anonResult.status} — check whether this object needs any session at all`]
          : []),
        '',
        line('probe (other identity)', probeResult),
        line('miss control (random id)', missResult),
        ...(ownResult !== undefined ? [line('own (owner)', ownResult)] : []),
        ...(anonResult !== undefined ? [line('anon (no session)', anonResult)] : []),
      ].join('\n'))
    })
}
