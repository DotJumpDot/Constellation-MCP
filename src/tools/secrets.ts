import { z } from 'zod'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
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

/** Serialized mutation of a JSON FILE on disk (run-50 §3: two lanes
 *  hand-rolling read-modify-write on atlassian-run50-tenant2.json clobbered
 *  each other and one generated password was lost — ~6 units to recover).
 *  Same contract as patchJsonSecret: per-path single-flight lock, RFC 7396
 *  merge patch, values never enter the return value; the write is atomic
 *  (temp file in the same dir + rename) so a crash mid-patch leaves either
 *  the old or the new whole file, never a truncated one. */
const jsonFileLocks = new Map<string, Promise<unknown>>()
const JSON_FILE_MAX_BYTES = 8 * 1024 * 1024

export async function patchJsonFile(file: string, patch: Record<string, unknown>): Promise<{ before: string[]; after: string[]; bytes: number; sha256: string; created: boolean }> {
  const resolved = path.resolve(file)
  if (!resolved.toLowerCase().endsWith('.json'))
    throw new Error(`"${file}" is not a .json file — the atomic merge is for JSON objects only`)
  const execute = async (): Promise<{ before: string[]; after: string[]; bytes: number; sha256: string; created: boolean }> => {
    let parsed: unknown = {}
    let created = false
    if (fs.existsSync(resolved)) {
      const stat = fs.statSync(resolved)
      if (stat.size > JSON_FILE_MAX_BYTES)
        throw new Error(`"${resolved}" is ${Math.round(stat.size / 1024)} KB — over the ${JSON_FILE_MAX_BYTES / 1024 / 1024} MB merge limit (a fixture/secrets file, not a data dump)`)
      const text = fs.readFileSync(resolved, 'utf8')
      try {
        parsed = JSON.parse(text)
      } catch (error) {
        throw new Error(`"${resolved}" is not valid JSON (${error instanceof Error ? error.message : String(error)}) — the merge refuses to guess; fix or move the file first`)
      }
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed))
        throw new Error(`"${resolved}" is JSON but not an object — merge patch needs an object root`)
    } else {
      created = true
    }
    const merged = applyJsonMergePatch(parsed, patch)
    const serialized = JSON.stringify(merged, null, 2) + '\n'
    const tmp = `${resolved}.tmp-${process.pid}-${Date.now()}`
    fs.writeFileSync(tmp, serialized)
    try {
      fs.renameSync(tmp, resolved)
    } catch (error) {
      try { fs.rmSync(tmp, { force: true }) } catch { /* best effort */ }
      const code = (error as NodeJS.ErrnoException).code
      if (code === 'EBUSY' || code === 'EPERM' || code === 'EACCES')
        throw new Error(`could not replace "${resolved}" atomically (${code}) — another process holds the file; the original is UNTOUCHED (the merge wrote a temp file and discarded it)`)
      throw error
    }
    return {
      before: Object.keys(parsed as Record<string, unknown>).sort(),
      after: Object.keys(merged as Record<string, unknown>).sort(),
      bytes: Buffer.byteLength(serialized),
      sha256: createHash('sha256').update(serialized).digest('hex'),
      created,
    }
  }
  // Single-flight per resolved path: patches queue behind the previous patch
  // whatever its outcome, so two lanes can never interleave read-modify-write.
  const prior = jsonFileLocks.get(resolved) ?? Promise.resolve()
  const run = prior.then(execute, execute)
  jsonFileLocks.set(resolved, run.then(() => undefined, () => undefined))
  return run
}

export function registerSecretTools(server: ToolRegistrar, scope?: import('../scope.js').ScopeGuard): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('secrets_list', 'List secret NAMES available from the environment (values are never shown).',
    {},
    async () => textResult(secretNames().length === 0
      ? '(no CONSTELLATION_SECRET_* / DSH_SECRET_* env vars set)'
      : secretNames().join('\n')))

  t('secrets_get', 'Fetch one secret value. Masks by default (a JSON secret also lists its top-level KEYS — run-7 P1-10, enough to navigate shared account pools without reading values); prefer `$secret:<name>` interpolation in http_request so the value never enters the transcript. Run-39 §12.11: `reveal:true` prints the value into the transcript and is AUDITED — per-lane read scoping is not enforceable here (the MCP server sees one shared connection and self-declared owner names), so the audit trail is the detective control.',
    {
      name: z.string().describe('Secret name (without the CONSTELLATION_SECRET_ prefix)'),
      reveal: z.boolean().optional().describe('Return the actual value (appears in the transcript; audited)'),
      owner: z.string().optional().describe('Your agent name (audit identity for reveals)'),
    },
    async ({ name, reveal, owner }: any) => {
      const value = secretValue(name)
      if (value === undefined) return textResult(`no secret "${name}" — set CONSTELLATION_SECRET_${name.toUpperCase()} or DSH_SECRET_${name.toUpperCase()}`, true)
      if (reveal !== true) {
        const keys = jsonSecretKeys(value)
        return textResult(`"${name}": ***set (${value.length} chars)***${keys !== undefined ? ` — JSON keys: ${keys.join(', ')}` : ''} — pass reveal: true to print, use $secret:${name} inside http_request, or secrets_patch to edit server-side`)
      }
      const who = owner === undefined || owner.trim() === '' ? 'unattributed' : owner.trim()
      scope?.audit(`secret:${name}`, who, 'secrets_get', { allowed: true, reason: 'reveal — value entered the transcript' })
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

  t('secrets_file_patch', 'Atomically merge-patch a JSON FILE on disk (run-50 §3: two lanes hand-rolling read-modify-write on the shared fixture JSON clobbered each other and lost a generated password). RFC 7396 JSON Merge Patch — objects merge recursively, null deletes a key, other values replace — under a per-path lock, written atomically (temp + rename, so a crash leaves the old or the new whole file, never a truncated one). A missing file starts as {}. Values never enter the transcript: the result lists keys before/after plus the new file\'s size and sha256 (citable in evidence_capture). Use this for shared per-run fixtures like tenant identity pools; env secrets still go through secrets_patch.',
    {
      file: z.string().describe('Path to the .json file (absolute, or relative to the server cwd — the run workspace)'),
      patch: z.record(z.string(), z.unknown()).describe('Merge-patch object, e.g. {"identities":{"lane-b":{"email":"…","password":"…"}}}'),
      owner: z.string().optional().describe('Your agent name (audit identity for the write)'),
    },
    async ({ file, patch, owner }: any) => {
      if (patch === null || typeof patch !== 'object' || Array.isArray(patch))
        return textResult('patch must be a JSON object (RFC 7396 merge patch)', true)
      const result = await patchJsonFile(file, patch)
      const who = owner === undefined || owner.trim() === '' ? 'unattributed' : owner.trim()
      scope?.audit(`file:${file}`, who, 'secrets_file_patch', {
        allowed: true,
        reason: `atomic merge under lock${result.created ? ' (file created)' : ''}: ${result.after.length} top-level key(s), values never printed`,
      })
      const removed = result.before.filter(key => !result.after.includes(key))
      const added = result.after.filter(key => !result.before.includes(key))
      return textResult([
        `Patched "${file}" under the per-file lock${result.created ? ' — file CREATED (was missing)' : ''} — now ${result.bytes} bytes.`,
        `keys before: ${result.before.join(', ') || '(none)'}`,
        `keys after:  ${result.after.join(', ') || '(none)'}`,
        ...(removed.length > 0 ? [`removed: ${removed.join(', ')}`] : []),
        ...(added.length > 0 ? [`added: ${added.join(', ')}`] : []),
        `sha256: ${result.sha256} (values never printed; cite the hash in evidence_capture)`,
      ].join('\n'))
    })
}
