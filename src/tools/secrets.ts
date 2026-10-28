import { z } from 'zod'
import { errorResult, textResult, type ToolResult } from '../browser/tools.js'
import type { ToolRegistrar } from '../browser/tools.js'

const SECRET_ENV = /^(?:CONSTELLATION|DSH)_SECRET_(.+)$/

export function secretNames(): string[] {
  return Object.keys(process.env)
    .map(k => SECRET_ENV.exec(k)?.[1])
    .filter((n): n is string => n !== undefined)
    .map(n => n.toLowerCase())
    .sort()
}

export function secretValue(name: string): string | undefined {
  const upper = name.toUpperCase()
  return process.env[`CONSTELLATION_SECRET_${upper}`] ?? process.env[`DSH_SECRET_${upper}`]
}

/** Replace `$secret:NAME` occurrences in a string with env values. Values
 *  never round-trip through the MCP transcript this way. */
export function interpolateSecretRefs(input: string): { text: string; missing: string[] } {
  const missing: string[] = []
  const text = input.replace(/\$secret:([A-Za-z0-9_-]+)/g, (_, name: string) => {
    const value = secretValue(name)
    if (value === undefined) { missing.push(name); return `$secret:${name}` }
    return value
  })
  return { text, missing }
}

export function interpolateDeep(value: unknown): { value: unknown; missing: string[] } {
  const missing: string[] = []
  const walk = (v: unknown): unknown => {
    if (typeof v === 'string') {
      const out = interpolateSecretRefs(v)
      missing.push(...out.missing)
      return out.text
    }
    if (Array.isArray(v)) return v.map(walk)
    if (v !== null && typeof v === 'object') {
      return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x)]))
    }
    return v
  }
  return { value: walk(value), missing: [...new Set(missing)] }
}

/** RFC 7396 JSON Merge Patch — pure so tests pin the semantics. */
export function applyJsonMergePatch(target: unknown, patch: unknown): unknown {
  if (patch === null || typeof patch !== 'object' || Array.isArray(patch)) return patch
  if (target === null || typeof target !== 'object' || Array.isArray(target)) target = {}
  const out: Record<string, unknown> = { ...(target as Record<string, unknown>) }
  for (const [key, value] of Object.entries(patch as Record<string, unknown>)) {
    if (value === undefined) continue
    if (value === null) delete out[key]
    else out[key] = key in out ? applyJsonMergePatch(out[key], value) : applyJsonMergePatch(undefined, value)
  }
  return out
}

/** Serialized mutation of env-held JSON secrets (run-7 P1-10): two lanes
 *  doing read-modify-write on seek-accounts.json clobbered each other and
 *  only one account survived. Every patch runs under a per-name lock and
 *  writes back to BOTH env spellings the reader uses. */
const secretLocks = new Map<string, Promise<unknown>>()

export async function patchJsonSecret(name: string, patch: Record<string, unknown>): Promise<{ before: string[]; after: string[]; chars: number }> {
  const execute = async (): Promise<{ before: string[]; after: string[]; chars: number }> => {
    const value = secretValue(name)
    if (value === undefined) throw new Error(`no secret "${name}" to patch — set CONSTELLATION_SECRET_${name.toUpperCase()} first`)
    let parsed: unknown
    try {
      parsed = JSON.parse(value)
    } catch (error) {
      throw new Error(`secret "${name}" is not JSON (${error instanceof Error ? error.message : String(error)}) — only JSON secrets can be patched`)
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed))
      throw new Error(`secret "${name}" is JSON but not an object — merge patch needs an object root`)
    const merged = applyJsonMergePatch(parsed, patch)
    const serialized = JSON.stringify(merged)
    const upper = name.toUpperCase()
    const wrote: string[] = []
    for (const key of [`CONSTELLATION_SECRET_${upper}`, `DSH_SECRET_${upper}`]) {
      if (process.env[key] !== undefined) { process.env[key] = serialized; wrote.push(key) }
    }
    if (wrote.length === 0) { process.env[`CONSTELLATION_SECRET_${upper}`] = serialized; wrote.push(`CONSTELLATION_SECRET_${upper}`) }
    return {
      before: Object.keys(parsed as Record<string, unknown>).sort(),
      after: Object.keys(merged as Record<string, unknown>).sort(),
      chars: serialized.length,
    }
  }
  // Single-flight per name: patches queue behind the previous patch whatever
  // its outcome, so two lanes can never interleave read-modify-write.
  const prior = secretLocks.get(name) ?? Promise.resolve()
  const run = prior.then(execute, execute)
  secretLocks.set(name, run.then(() => undefined, () => undefined))
  return run
}

/** Top-level keys of a JSON secret, for masked listing (run-7 P1-10). */
export function jsonSecretKeys(value: string): string[] | undefined {
  try {
    const parsed: unknown = JSON.parse(value)
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed))
      return Object.keys(parsed as Record<string, unknown>).sort()
  } catch { /* not JSON */ }
  return undefined
}

export function registerSecretTools(server: ToolRegistrar): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('secrets_list', 'List secret NAMES available from the environment (values are never shown).',
    {},
    async () => textResult(secretNames().length === 0
      ? '(no CONSTELLATION_SECRET_* / DSH_SECRET_* env vars set)'
      : secretNames().join('\n')))

  t('secrets_get', 'Fetch one secret value. Masks by default (a JSON secret also lists its top-level KEYS — run-7 P1-10, enough to navigate shared account pools without reading values); prefer `$secret:<name>` interpolation in http_request so the value never enters the transcript.',
    { name: z.string().describe('Secret name (without the CONSTELLATION_SECRET_ prefix)'), reveal: z.boolean().optional().describe('Return the actual value (appears in the transcript)') },
    async ({ name, reveal }: any) => {
      const value = secretValue(name)
      if (value === undefined) return textResult(`no secret "${name}" — set CONSTELLATION_SECRET_${name.toUpperCase()} or DSH_SECRET_${name.toUpperCase()}`, true)
      if (reveal !== true) {
        const keys = jsonSecretKeys(value)
        return textResult(`"${name}": ***set (${value.length} chars)***${keys !== undefined ? ` — JSON keys: ${keys.join(', ')}` : ''} — pass reveal: true to print, use $secret:${name} inside http_request, or secrets_patch to edit server-side`)
      }
      return textResult(value)
    })

  t('secrets_patch', 'Atomically edit a JSON secret server-side under a lock (run-7 P1-10: concurrent read-modify-write clobbered seek-accounts.json). RFC 7396 JSON Merge Patch: objects merge recursively, null deletes a key, other values replace. Values never enter the transcript — the result lists keys before/after.',
    {
      name: z.string().describe('Secret name (an existing JSON object value)'),
      patch: z.record(z.string(), z.unknown()).describe('Merge-patch object, e.g. {"accounts":{"lane-b": null}}'),
    },
    async ({ name, patch }: any) => {
      if (patch === null || typeof patch !== 'object' || Array.isArray(patch))
        return textResult('patch must be a JSON object (RFC 7396 merge patch)', true)
      const result = await patchJsonSecret(name, patch)
      const removed = result.before.filter(key => !result.after.includes(key))
      const added = result.after.filter(key => !result.before.includes(key))
      return textResult([
        `Patched "${name}" under the per-secret lock — now ${result.chars} chars.`,
        `keys before: ${result.before.join(', ') || '(none)'}`,
        `keys after:  ${result.after.join(', ') || '(none)'}`,
        ...(removed.length > 0 ? [`removed: ${removed.join(', ')}`] : []),
        ...(added.length > 0 ? [`added: ${added.join(', ')}`] : []),
      ].join('\n'))
    })
}
