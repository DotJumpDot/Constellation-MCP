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

  t('secrets_get', 'Fetch one secret value. Masks by default; prefer `$secret:<name>` interpolation in http_request so the value never enters the transcript.',
    { name: z.string().describe('Secret name (without the CONSTELLATION_SECRET_ prefix)'), reveal: z.boolean().optional().describe('Return the actual value (appears in the transcript)') },
    async ({ name, reveal }: any) => {
      const value = secretValue(name)
      if (value === undefined) return textResult(`no secret "${name}" — set CONSTELLATION_SECRET_${name.toUpperCase()} or DSH_SECRET_${name.toUpperCase()}`, true)
      if (reveal !== true)
        return textResult(`"${name}": ***set (${value.length} chars)*** — pass reveal: true to print, or use $secret:${name} inside http_request headers/body to keep it out of the transcript`)
      return textResult(value)
    })
}
