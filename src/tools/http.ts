import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { z } from 'zod'
import { CookieJar } from 'tough-cookie'
import type { ConstellationConfig } from '../config.js'
import type { ScopeGuard } from '../scope.js'
import { errorResult, textResult, type ToolRegistrar, type ToolResult } from '../browser/tools.js'
import { HTTP_SCHEMES } from '../scope.js'
import { interpolateDeep } from './secrets.js'

export interface HttpEnv {
  config: ConstellationConfig
  scope: ScopeGuard
}

const MAX_BODY_DEFAULT = 20_000

interface JarEntry {
  serialized: unknown
  savedAt: number
}

export class JarStore {
  private jars = new Map<string, JarEntry>()

  jar(id: string): CookieJar {
    const existing = this.jars.get(id)
    if (existing) return CookieJar.fromJSON(existing.serialized as never)
    const jar = new CookieJar()
    try {
      const file = this.fileFor(id)
      const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as unknown
      const restored = CookieJar.fromJSON(raw as never)
      this.jars.set(id, { serialized: raw, savedAt: Date.now() })
      return restored
    } catch {
      this.jars.set(id, { serialized: jar.toJSON(), savedAt: Date.now() })
      return jar
    }
  }

  /** Remove a jar from memory and disk — sticky jars from previous runs are
   *  an A/B-testing hazard (cookies you forgot you have). */
  forget(id: string): boolean {
    const known = this.jars.has(id) || this.list().includes(id)
    this.jars.delete(id)
    try { fs.rmSync(this.fileFor(id), { force: true }) } catch { /* best effort */ }
    return known
  }

  persist(id: string, jar: CookieJar): void {
    const serialized = jar.toJSON()
    this.jars.set(id, { serialized, savedAt: Date.now() })
    try {
      fs.mkdirSync(path.dirname(this.fileFor(id)), { recursive: true })
      fs.writeFileSync(this.fileFor(id), JSON.stringify(serialized))
    } catch { /* best effort */ }
  }

  list(): string[] {
    let names: string[] = []
    try {
      names = fs.readdirSync(path.dirname(this.fileFor('x'))).filter(f => f.endsWith('.json')).map(f => f.slice(0, -5))
    } catch { names = [] }
    return [...new Set([...this.jars.keys(), ...names])].sort()
  }

  private fileFor(id: string): string {
    const safe = id.replace(/[^A-Za-z0-9._-]/g, '_')
    return path.join(this.config.rootDir, 'jars', `${safe}.json`)
  }

  constructor(private config: ConstellationConfig) {}
}

export interface RequestResult {
  status: number
  statusText: string
  url_final: string
  headers: Record<string, string>
  body: string
  body_sha256: string
  timing_ms: number
  set_cookies: number
}

export async function performRequest(jars: JarStore, scope: ScopeGuard, spec: RequestSpec, owner: string, tool: string): Promise<RequestResult> {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(spec.url)
  } catch {
    throw new Error(`unparseable URL: ${spec.url}`)
  }
  if (!HTTP_SCHEMES.has(parsedUrl.protocol.replace(':', '')))
    throw new Error(`scheme "${parsedUrl.protocol}" is not allowed — http_request supports http/https only`)
  scope.assert(spec.url, owner, tool)
  const jar = jars.jar(spec.jar ?? 'default')
  const { value: headersInterp, missing } = interpolateDeep(spec.headers ?? {})
  if (missing.length > 0) throw new Error(`unknown secret(s): ${missing.join(', ')} — set them via CONSTELLATION_SECRET_* env`)
  const headers: Record<string, string> = { ...(headersInterp as Record<string, string>) }
  if (spec.body !== undefined && headers['content-type'] === undefined && headers['Content-Type'] === undefined && isJsonObject(spec.body))
    headers['content-type'] = 'application/json'
  const cookie = jar.getCookieStringSync(spec.url)
  if (cookie !== '') headers['cookie'] = headers['cookie'] ?? cookie
  const { value: bodyInterp, missing: missingBody } = interpolateDeep(spec.body)
  if (missingBody.length > 0) throw new Error(`unknown secret(s) in body: ${missingBody.join(', ')}`)
  const body = bodyInterp === undefined ? undefined : (isJsonObject(bodyInterp) ? JSON.stringify(bodyInterp) : String(bodyInterp))

  const started = Date.now()
  const response = await fetch(spec.url, {
    method: spec.method ?? 'GET',
    headers,
    body,
    redirect: spec.redirect ?? 'manual',
    signal: AbortSignal.timeout(spec.timeout_ms ?? 30_000),
  })
  const text = await response.text()
  const timing = Date.now() - started

  const setCookies = response.headers.getSetCookie?.() ?? []
  for (const c of setCookies) {
    try { jar.setCookieSync(c, response.url) } catch { /* skip malformed */ }
  }
  jars.persist(spec.jar ?? 'default', jar)

  const headerRecord: Record<string, string> = {}
  response.headers.forEach((value, key) => { headerRecord[key] = value })
  const maxBody = spec.max_body_bytes ?? MAX_BODY_DEFAULT
  return {
    status: response.status,
    statusText: response.statusText,
    url_final: response.url,
    headers: headerRecord,
    // The sha covers the FULL body (diffing stays exact); only the preview
    // shown to the caller is capped so big pages cannot flood agent context.
    body: text.length > maxBody ? text.slice(0, maxBody) + `\n…[preview of ${text.length} bytes — sha256 covers the full body; raise max_body_bytes if you need more]` : text,
    body_sha256: crypto.createHash('sha256').update(text).digest('hex'),
    timing_ms: timing,
    set_cookies: setCookies.length,
  }
}

export interface RequestSpec {
  url: string
  method?: string
  headers?: Record<string, string>
  body?: unknown
  jar?: string
  redirect?: 'follow' | 'manual'
  timeout_ms?: number
  max_body_bytes?: number
}

function isJsonObject(v: unknown): boolean {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function formatResult(r: RequestResult): string {
  const headerLines = Object.entries(r.headers).map(([k, v]) => `  ${k}: ${v}`).join('\n')
  return [
    `HTTP ${r.status} ${r.statusText} (${r.timing_ms} ms) — final URL: ${r.url_final}`,
    `body sha256: ${r.body_sha256}${r.set_cookies > 0 ? ` — ${r.set_cookies} Set-Cookie stored in jar` : ''}`,
    `headers:\n${headerLines}`,
    `body:\n${r.body}`,
  ].join('\n\n')
}

const REQUEST_SHAPE: z.ZodRawShape = {
  url: z.string().describe('Absolute URL — scope-guarded'),
  method: z.string().optional(),
  headers: z.record(z.string()).optional().describe('Header map; values may use $secret:NAME'),
  body: z.unknown().optional().describe('Body; object → JSON. Values may use $secret:NAME'),
  jar: z.string().optional().describe('Cookie jar id (persisted per id); default "default"'),
  redirect: z.enum(['follow', 'manual']).optional(),
  timeout_ms: z.number().int().optional(),
  max_body_bytes: z.number().int().optional().describe('Body preview cap (default 20000; sha256 always covers the full body)'),
}

export function registerHttpTools(server: ToolRegistrar, env: HttpEnv): void {
  const jars = new JarStore(env.config)

  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('http_request', 'Server-side HTTP client with a persistent per-id cookie jar, scope-guarded. Returns status, headers, body, timing, body sha256.',
    { ...REQUEST_SHAPE, owner: z.string().optional().describe('Attribution for the scope audit log') },
    async (args: any) => {
      const { owner, ...spec } = args
      const result = await performRequest(jars, env.scope, spec as RequestSpec, owner ?? 'unknown', 'http_request')
      return textResult(formatResult(result))
    })

  t('http_diff', 'Send two requests and diff them (status, body sha, first diverging body line). IDOR/BOLA A/B pairs.',
    { a: z.object(REQUEST_SHAPE).describe('Request A (e.g. account A session)'), b: z.object(REQUEST_SHAPE).describe('Request B'), owner: z.string().optional() },
    async ({ a, b, owner }: any) => {
      const who = owner ?? 'unknown'
      const [ra, rb] = await Promise.all([
        performRequest(jars, env.scope, a as RequestSpec, who, 'http_diff'),
        performRequest(jars, env.scope, b as RequestSpec, who, 'http_diff'),
      ])
      const lines: string[] = []
      lines.push(`A: HTTP ${ra.status} sha=${ra.body_sha256} (${ra.timing_ms} ms)`)
      lines.push(`B: HTTP ${rb.status} sha=${rb.body_sha256} (${rb.timing_ms} ms)`)
      if (ra.status !== rb.status) lines.push(`STATUS DIVERGES: A=${ra.status} B=${rb.status}`)
      if (ra.body_sha256 !== rb.body_sha256) {
        const la = ra.body.split('\n')
        const lb = rb.body.split('\n')
        for (let i = 0; i < Math.max(la.length, lb.length); i++) {
          if (la[i] !== lb[i]) {
            const show = (line: string | undefined): string => {
              if (line === undefined) return '(no line)'
              const trimmed = line.trim()
              return trimmed === '' ? '(blank line)' : line.slice(0, 300)
            }
            lines.push(`first body divergence at line ${i + 1}:`)
            lines.push(`  A: ${show(la[i])}`)
            lines.push(`  B: ${show(lb[i])}`)
            break
          }
        }
      } else if (ra.status === rb.status) {
        lines.push('bodies identical (same sha256)')
      }
      return textResult(lines.join('\n'))
    })

  t('http_jars', 'List cookie jars known to the HTTP client, or `forget` one (deletes it from disk — use before an A/B pair so stale cookies cannot contaminate the matrix).',
    { forget: z.string().optional().describe('Jar id to delete') },
    async ({ forget }: any) => {
      if (forget !== undefined) {
        const known = jars.forget(forget)
        return textResult(known ? `Forgot jar "${forget}" (memory + disk).` : `No jar "${forget}" existed.`)
      }
      const list = jars.list()
      return textResult(list.length === 0 ? '(no jars yet — created on first http_request)' : list.join('\n'))
    })
}
