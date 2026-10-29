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
import { queryJsonPath, renderStructuralDiff, structuralJsonDiff } from './structural.js'

export interface HttpEnv {
  config: ConstellationConfig
  scope: ScopeGuard
  budget?: import('./budget.js').BudgetGuard
  /** Live-browser bridge (round 6): resolve an owner's browser session so
   *  request legs can ride its cookie state via context.request. */
  sessionFor?: (owner: string) => { ensure(): Promise<{ request: BrowserRequestClient }> }
}

/** Structural slice of Playwright's APIRequestContext (browserContext.request)
 *  — keeps this module free of a playwright-core import while letting request
 *  specs name a live browser session as their transport. */
export interface BrowserRequestClient {
  fetch(url: string, options: {
    method?: string
    headers?: Record<string, string>
    data?: string
    maxRedirects?: number
    timeout?: number
  }): Promise<{
    status(): number
    statusText(): string
    url(): string
    headers(): Record<string, string>
    headersArray(): Array<{ name: string; value: string }>
    text(): Promise<string>
  }>
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
  /** The COMPLETE body when `body` is a capped preview (round-7 gap list §2:
   *  body_file used to store the PREVIEW, so "saved whole to disk" was false —
   *  http_extract reads the full bytes from here or from disk). Never shown. */
  body_full?: string
  body_sha256: string
  timing_ms: number
  set_cookies: number
}

export async function performRequest(jars: JarStore, scope: ScopeGuard, spec: RequestSpec, owner: string, tool: string, budget?: import('./budget.js').BudgetGuard): Promise<RequestResult> {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(spec.url)
  } catch {
    throw new Error(`unparseable URL: ${spec.url}`)
  }
  if (!HTTP_SCHEMES.has(parsedUrl.protocol.replace(':', '')))
    throw new Error(`scheme "${parsedUrl.protocol}" is not allowed — http_request supports http/https only`)
  scope.assert(spec.url, owner, tool)
  budget?.spend(owner)
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
  applyAuth(headers, spec.auth)

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
    ...(text.length > maxBody ? { body_full: text } : {}),
    body_sha256: crypto.createHash('sha256').update(text).digest('hex'),
    timing_ms: timing,
    set_cookies: setCookies.length,
  }
}

/** `browser: '<owner>' | true` on a request leg: which live browser session
 *  the request should ride (true = the calling/step owner). */
export function browserOwnerOf(spec: { browser?: unknown }, fallbackOwner: string): string | undefined {
  if (spec.browser === true) return fallbackOwner
  if (typeof spec.browser === 'string' && spec.browser !== '') return spec.browser
  return undefined
}

/** Copy of a spec without the transport-only `browser` key. */
export function stripBrowserField<T extends object>(spec: T): T {
  const copy = { ...spec }
  delete (copy as { browser?: unknown }).browser
  return copy
}

/** Send one request through a live browser session's context.request — it
 *  carries that owner's REAL cookie state (the identity the browser stages
 *  established), which is the bridge recipe/diff legs need when login happens
 *  in the browser and no jar can represent it. Cookies set by the response
 *  flow back into the browser context (Playwright shares storage state), so
 *  the identity stays live. DBSC caveat: this is still an out-of-page request
 *  with copied cookie values — on device-bound-session products it can come
 *  back unauthenticated (reads as NOT_FOUND); hold those cells in the page. */
export async function performBrowserRequest(
  client: BrowserRequestClient,
  scope: ScopeGuard,
  spec: RequestSpec,
  owner: string,
  tool: string,
  budget?: import('./budget.js').BudgetGuard,
): Promise<RequestResult> {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(spec.url)
  } catch {
    throw new Error(`unparseable URL: ${spec.url}`)
  }
  if (!HTTP_SCHEMES.has(parsedUrl.protocol.replace(':', '')))
    throw new Error(`scheme "${parsedUrl.protocol}" is not allowed — browser-authenticated requests support http/https only`)
  scope.assert(spec.url, owner, tool)
  budget?.spend(owner)
  const { value: headersInterp, missing } = interpolateDeep(spec.headers ?? {})
  if (missing.length > 0) throw new Error(`unknown secret(s): ${missing.join(', ')}`)
  const headers: Record<string, string> = { ...(headersInterp as Record<string, string>) }
  if (spec.body !== undefined && headers['content-type'] === undefined && headers['Content-Type'] === undefined && isJsonObject(spec.body))
    headers['content-type'] = 'application/json'
  // No jar merge: the browser context's cookie state IS the identity here.
  const { value: bodyInterp, missing: missingBody } = interpolateDeep(spec.body)
  if (missingBody.length > 0) throw new Error(`unknown secret(s) in body: ${missingBody.join(', ')}`)
  const body = bodyInterp === undefined ? undefined : (isJsonObject(bodyInterp) ? JSON.stringify(bodyInterp) : String(bodyInterp))
  applyAuth(headers, spec.auth)

  const started = Date.now()
  const response = await client.fetch(spec.url, {
    method: spec.method ?? 'GET',
    headers,
    ...(body !== undefined ? { data: body } : {}),
    maxRedirects: spec.redirect === 'follow' ? 20 : 0,
    timeout: spec.timeout_ms ?? 30_000,
  })
  const text = await response.text()
  const timing = Date.now() - started
  const setCookies = response.headersArray().filter(h => h.name.toLowerCase() === 'set-cookie').length
  const maxBody = spec.max_body_bytes ?? MAX_BODY_DEFAULT
  return {
    status: response.status(),
    statusText: response.statusText(),
    url_final: response.url(),
    headers: response.headers(),
    body: text.length > maxBody ? text.slice(0, maxBody) + `\n…[preview of ${text.length} bytes — sha256 covers the full body; raise max_body_bytes if you need more]` : text,
    ...(text.length > maxBody ? { body_full: text } : {}),
    body_sha256: crypto.createHash('sha256').update(text).digest('hex'),
    timing_ms: timing,
    set_cookies: setCookies,
  }
}

export interface LegTransports {
  jars: JarStore
  scope: ScopeGuard
  budget?: import('./budget.js').BudgetGuard
  sessionFor?: (owner: string) => { ensure(): Promise<{ request: BrowserRequestClient }> }
}

/** Run one authorization leg: jar transport by default, or through the live
 *  browser session named by `browser: '<owner>'` (true = the calling owner).
 *  One routing rule shared by http_request, diff_pair legs and recipe expect
 *  legs, so all four primitives can speak the SAME identity the browser
 *  stages established (round 6 — grant → expect allow → revoke → expect deny
 *  on a live product). */
export async function performLeg(
  transports: LegTransports,
  rawSpec: RequestSpec & { browser?: unknown },
  fallbackOwner: string,
  tool: string,
): Promise<RequestResult> {
  const browserOwner = browserOwnerOf(rawSpec, fallbackOwner)
  const spec = stripBrowserField(rawSpec)
  if (browserOwner !== undefined) {
    if (transports.sessionFor === undefined)
      throw new Error(`leg requests browser transport for "${browserOwner}" but no browser session provider is wired here`)
    const context = await transports.sessionFor(browserOwner).ensure()
    return performBrowserRequest(context.request, transports.scope, spec, fallbackOwner, tool, transports.budget)
  }
  return performRequest(transports.jars, transports.scope, spec, fallbackOwner, tool, transports.budget)
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
  auth?: AuthSpec
}

/** HTTP authorization (DST-Comet live-run ask: B2's b2_authorize_account wants
 *  HTTP Basic; agents were base64-encoding credentials in PowerShell). */
export interface AuthSpec {
  type: 'basic' | 'bearer'
  username?: string
  password?: string
  token?: string
}

/** Interpolate secrets and set the Authorization header. */
function applyAuth(headers: Record<string, string>, auth: AuthSpec | undefined): void {
  if (auth === undefined) return
  const { value, missing } = interpolateDeep(auth)
  if (missing.length > 0) throw new Error(`unknown secret(s) in auth: ${missing.join(', ')}`)
  const a = value as AuthSpec
  if (a.type === 'basic') {
    if (a.username === undefined || a.password === undefined) throw new Error('auth.type "basic" needs username and password')
    headers['authorization'] ??= `Basic ${Buffer.from(`${a.username}:${a.password}`).toString('base64')}`
  } else if (a.type === 'bearer') {
    if (a.token === undefined) throw new Error('auth.type "bearer" needs token')
    headers['authorization'] ??= `Bearer ${a.token}`
  } else {
    throw new Error('auth.type must be "basic" or "bearer"')
  }
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
  auth: z.object({
    type: z.enum(['basic', 'bearer']),
    username: z.string().optional(),
    password: z.string().optional().describe('May use $secret:NAME'),
    token: z.string().optional().describe('Bearer token; may use $secret:NAME'),
  }).optional().describe('Authorization: basic (username+password) or bearer (token)'),
  browser: z.union([z.boolean(), z.string()]).optional().describe('Send through a LIVE browser session (its cookie state) instead of a jar — the owner\'s name, or true = your own owner. For identities that logged in via the browser (OAuth/JS) where no jar exists. DBSC products may still deny out-of-page requests.'),
}

/** Save a URL server-side and return metadata only — reading a 338 KB rendered
 *  page into the transcript costs ~100k tokens; evidence collection should not
 *  (live-run ask 2026-10-27). */
export async function performDownload(
  jars: JarStore,
  scope: ScopeGuard,
  config: ConstellationConfig,
  spec: RequestSpec,
  owner: string,
  destName: string | undefined,
  sha256Expected: string | undefined,
  budget?: import('./budget.js').BudgetGuard,
): Promise<{ file: string; status: number; bytes: number; sha256: string; contentType: string }> {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(spec.url)
  } catch {
    throw new Error(`unparseable URL: ${spec.url}`)
  }
  if (!HTTP_SCHEMES.has(parsedUrl.protocol.replace(':', '')))
    throw new Error(`scheme "${parsedUrl.protocol}" is not allowed — http_download supports http/https only`)
  scope.assert(spec.url, owner, 'http_download')
  budget?.spend(owner)
  const jar = jars.jar(spec.jar ?? 'default')
  const { value: headersInterp, missing } = interpolateDeep(spec.headers ?? {})
  if (missing.length > 0) throw new Error(`unknown secret(s): ${missing.join(', ')}`)
  const headers: Record<string, string> = { ...(headersInterp as Record<string, string>) }
  const cookie = jar.getCookieStringSync(spec.url)
  if (cookie !== '') headers['cookie'] ??= cookie
  applyAuth(headers, spec.auth)
  const response = await fetch(spec.url, {
    method: 'GET',
    headers,
    redirect: spec.redirect ?? 'follow',
    signal: AbortSignal.timeout(spec.timeout_ms ?? 60_000),
  })
  const buffer = Buffer.from(await response.arrayBuffer())
  for (const c of response.headers.getSetCookie?.() ?? []) {
    try { jar.setCookieSync(c, response.url) } catch { /* skip malformed */ }
  }
  jars.persist(spec.jar ?? 'default', jar)
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex')
  const safe = (value: string) => value.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '') || 'download'
  const ownerDir = path.join(config.outputDir, safe(owner), 'downloads')
  const fromUrl = decodeURIComponent(parsedUrl.pathname.split('/').filter(Boolean).pop() ?? '')
  const fileName = safe(destName ?? fromUrl ?? `download-${Date.now()}`)
  fs.mkdirSync(ownerDir, { recursive: true })
  const file = path.join(ownerDir, fileName)
  fs.writeFileSync(file, buffer)
  if (sha256Expected !== undefined && sha256Expected.toLowerCase() !== sha256)
    throw new Error(`sha256 mismatch: expected ${sha256Expected}, got ${sha256} — file was still written to ${file}`)
  return {
    file,
    status: response.status,
    bytes: buffer.length,
    sha256,
    contentType: response.headers.get('content-type') ?? '(none)',
  }
}

export function registerHttpTools(server: ToolRegistrar, env: HttpEnv, jars: JarStore = new JarStore(env.config)): void {
  // Capture ring for http_replay (run-8 §7) + http_extract (round-7 §2): the
  // "vary exactly one field" cards were re-typed by hand all run. Last 20
  // requests per owner. The captured spec keeps its `browser` transport so a
  // replay rides the same live session the original did, and the entry keeps
  // the FULL body (capped at 1 MB in memory; on-disk body_file beyond) so
  // http_extract reads values WITHOUT re-fetching or flooding the transcript.
  const captures = new Map<string, Array<{
    id: string
    ts: string
    spec: RequestSpec & { browser?: unknown }
    body?: string
    bodyFile?: string
    contentType?: string
  }>>()
  let captureSeq = 0
  const transports: LegTransports = {
    jars,
    scope: env.scope,
    ...(env.budget !== undefined ? { budget: env.budget } : {}),
    ...(env.sessionFor !== undefined ? { sessionFor: env.sessionFor } : {}),
  }

  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('http_request', 'Server-side HTTP client with a persistent per-id cookie jar, scope-guarded. Returns status, headers, body, timing, body sha256. Bodies past 20 KB are ALSO saved whole to disk with a body_file reference (run-8 §7 — delicate candidates were truncated at 20 KB). `browser: "<owner>"` (or true) sends the request through that owner\'s LIVE browser session — its cookie state, the identity the browser stages logged in — instead of a jar.',
    { ...REQUEST_SHAPE, owner: z.string().optional().describe('Attribution for the scope audit log') },
    async (args: any) => {
      const { owner, ...spec } = args
      const who = owner ?? 'unknown'
      const result = await performLeg(transports, spec as RequestSpec & { browser?: unknown }, who, 'http_request')
      captureSeq += 1
      const captureId = `hr-${captureSeq}`
      const ring = captures.get(who) ?? []
      let stored = ''
      let bodyFile: string | undefined
      if (result.body.length > 20_000) {
        try {
          const dir = path.join(env.config.outputDir, who, 'responses')
          fs.mkdirSync(dir, { recursive: true })
          const file = path.join(dir, `${result.body_sha256}.txt`)
          // body_full is the COMPLETE body (round-7 fix: this used to write
          // the capped preview, so body_file lied about being whole).
          if (!fs.existsSync(file)) fs.writeFileSync(file, result.body_full ?? result.body)
          bodyFile = file
          stored = `\nbody_file: ${file} (full ${result.body_full?.length ?? result.body.length} bytes; output truncated above)`
        } catch { /* best effort */ }
      }
      ring.push({
        id: captureId,
        ts: new Date().toISOString(),
        spec: spec as RequestSpec & { browser?: unknown },
        ...(result.body_full === undefined && result.body.length <= 1_000_000 ? { body: result.body } : {}),
        ...(result.body_full !== undefined && result.body_full.length <= 1_000_000 ? { body: result.body_full } : {}),
        ...(bodyFile !== undefined ? { bodyFile } : {}),
        contentType: result.headers['content-type'],
      })
      if (ring.length > 20) ring.shift()
      captures.set(who, ring)
      return textResult(`${formatResult(result)}\ncapture_id: ${captureId} (http_replay re-sends it with one field changed)${stored}`)
    })

  t('http_replay', 'Replay a captured http_request with EXACTLY the overrides you pass (run-8 §7): the correct shape for "vary one field" — url/header/body substitutions on a byte-identical template instead of re-typing the whole request and drifting.',
    {
      capture_id: z.string().optional().describe('capture_id from a prior http_request (or last: true)'),
      last: z.boolean().optional().describe('Replay this owner\'s most recent capture'),
      override: z.object({
        url: z.string().optional().describe('Replace the URL (e.g. swap the object id)'),
        method: z.string().optional(),
        headers: z.record(z.string(), z.string()).optional().describe('MERGED into the captured headers'),
        body: z.unknown().optional().describe('REPLACES the body'),
      }).describe('Overrides applied to the captured spec'),
      owner: z.string().optional().describe('Same owner as the capture (jars + captures are per-owner)'),
    },
    async ({ capture_id, last, override, owner }: any) => {
      const who = owner ?? 'unknown'
      const ring = captures.get(who)
      if (ring === undefined || ring.length === 0) return textResult(`no captures for "${who}" — http_request records them`, true)
      if (capture_id === undefined && last !== true) {
        const recent = ring[ring.length - 1]!
        return textResult(`pass capture_id: "${recent.id}" (this owner's latest) — or last: true. Recent captures for "${who}": ${ring.map(row => row.id).join(', ')}`, true)
      }
      const captured = last === true
        ? ring[ring.length - 1]!
        : ring.find(row => row.id === capture_id)
      if (captured === undefined) {
        return textResult(`unknown capture_id "${capture_id}" for "${who}" — recent: ${ring.map(row => row.id).join(', ')}`, true)
      }
      const spec: RequestSpec = {
        ...captured.spec,
        ...(override?.url !== undefined ? { url: override.url } : {}),
        ...(override?.method !== undefined ? { method: override.method } : {}),
        ...(override?.headers !== undefined ? { headers: { ...captured.spec.headers, ...override.headers } } : {}),
        ...(override?.body !== undefined ? { body: override.body } : {}),
      }
      const result = await performLeg(transports, spec as RequestSpec & { browser?: unknown }, who, 'http_replay')
      const changed = [
        override?.url !== undefined ? 'url' : null,
        override?.method !== undefined ? 'method' : null,
        override?.headers !== undefined ? 'headers' : null,
        override?.body !== undefined ? 'body' : null,
      ].filter(Boolean).join('+') || 'nothing (verbatim replay)'
      return textResult(`Replayed ${captured.id} (changed: ${changed}) from ${captured.ts}\n${formatResult(result)}`)
    })

  t('http_extract', 'Pull one VALUE out of a captured response instead of the body (round-7 §2): jsonpath (`.key`, `[n]`, `[*]`, chained — e.g. "data.items[0].id") over a JSON capture, or a regex over any body. Reads the retained capture (memory, or its body_file on disk) — never re-fetches. Output is values only, each capped ~500 chars, at most 40 — this is what makes $var:NAME chaining real without bodies in the transcript.',
    {
      capture_id: z.string().optional().describe('capture_id from a prior http_request (or last: true)'),
      last: z.boolean().optional().describe('Use this owner\'s most recent capture'),
      jsonpath: z.string().optional().describe('`.key`, `[n]`, `[*]` chains over the parsed JSON body'),
      regex: z.string().optional().describe('Regex over the raw body; first capture group if present'),
      all: z.boolean().optional().describe('Return every match (default: first only)'),
      owner: z.string().optional().describe('Same owner as the capture'),
    },
    async ({ capture_id, last, jsonpath, regex, all, owner }: any) => {
      const who = owner ?? 'unknown'
      const ring = captures.get(who)
      if (ring === undefined || ring.length === 0) return textResult(`no captures for "${who}" — http_request records them`, true)
      const captured = last === true
        ? ring[ring.length - 1]!
        : (capture_id !== undefined ? ring.find(row => row.id === capture_id) : ring[ring.length - 1]!)
      if (captured === undefined) {
        return textResult(`unknown capture_id "${capture_id}" for "${who}" — recent: ${ring.map(row => row.id).join(', ')}`, true)
      }
      if (jsonpath === undefined && regex === undefined) return textResult('pass jsonpath or regex (e.g. jsonpath: "data.items[0].id", regex: "org-([a-z0-9]+)")', true)
      // Body source: the retained in-memory body, else its disk file, else refuse.
      let body = captured.body
      let readFrom = 'capture (in memory)'
      if (body === undefined && captured.bodyFile !== undefined) {
        try { body = fs.readFileSync(captured.bodyFile, 'utf8'); readFrom = `body_file ${captured.bodyFile}` } catch { /* unreadable */ }
      }
      if (body === undefined) return textResult(`capture ${captured.id} retained no body (>${1_000_000} bytes and no body_file) — re-send with http_replay and extract from the new capture`, true)
      const MAX_VALUES = 40
      const MAX_VALUE_CHARS = 500
      const cap = (value: string): string => value.length > MAX_VALUE_CHARS ? value.slice(0, MAX_VALUE_CHARS) + `…[${value.length} chars]` : value
      if (jsonpath !== undefined) {
        if (captured.contentType !== undefined && !captured.contentType.includes('json')) {
          return textResult(`capture ${captured.id} is ${captured.contentType} — jsonpath needs JSON; use regex instead`, true)
        }
        let parsed: unknown
        try { parsed = JSON.parse(body) } catch { return textResult(`capture ${captured.id}'s body does not parse as JSON — use regex`, true) }
        let matches = queryJsonPath(parsed, jsonpath)
        const total = matches.length
        matches = all === true ? matches.slice(0, MAX_VALUES) : matches.slice(0, 1)
        if (matches.length === 0) return textResult(`jsonpath "${jsonpath}" matched nothing in capture ${captured.id} (read from ${readFrom})`, true)
        const values = matches.map(match => cap(typeof match === 'string' ? match : JSON.stringify(match)))
        return textResult([
          values.map((value, index) => (all === true ? `[${index}] ${value}` : value)).join('\n'),
          `(${all === true ? `${values.length} of ${total} match(es)` : 'first match'}; read_from: ${readFrom})`,
        ].join('\n'))
      }
      // regex mode
      let re: RegExp
      try { re = new RegExp(regex!, all === true ? 'g' : '') } catch (error) { return textResult(`invalid regex: ${error instanceof Error ? error.message : String(error)}`, true) }
      const found: string[] = []
      let m: RegExpExecArray | null
      while ((m = re.exec(body)) !== null && found.length < MAX_VALUES) {
        found.push(m[1] ?? m[0])
        if (all !== true) break
        if (m.index === re.lastIndex) re.lastIndex++ // zero-width guard
      }
      if (found.length === 0) return textResult(`regex /${regex}/ matched nothing in capture ${captured.id} (read from ${readFrom})`, true)
      return textResult([
        found.map((value, index) => (all === true ? `[${index}] ${cap(value)}` : cap(value))).join('\n'),
        `(${all === true ? `${found.length} match(es)` : 'first match'}; read_from: ${readFrom})`,
      ].join('\n'))
    })

  t('http_diff', 'Send two requests and diff them. Plain mode: status, body sha, first diverging body LINE (IDOR/BOLA A/B pairs). `structural: true` (round-7 §3): when both bodies parse as JSON, walk them into per-FIELD changes (path → a → b, capped 50×200 chars) with volatile keys/values (csrf/timestamps/UUID-shapes) SUPPRESSED but listed — the deciding field is named instead of "the minified line differs". Not both JSON → falls back to the line diff.',
    { a: z.object(REQUEST_SHAPE).describe('Request A (e.g. account A session)'), b: z.object(REQUEST_SHAPE).describe('Request B'), structural: z.boolean().optional().describe('Walk JSON bodies field-by-field (falls back to line diff)'), owner: z.string().optional() },
    async ({ a, b, structural, owner }: any) => {
      const who = owner ?? 'unknown'
      const [ra, rb] = await Promise.all([
        performLeg(transports, a as RequestSpec & { browser?: unknown }, who, 'http_diff'),
        performLeg(transports, b as RequestSpec & { browser?: unknown }, who, 'http_diff'),
      ])
      const lines: string[] = []
      lines.push(`A: HTTP ${ra.status} sha=${ra.body_sha256} (${ra.timing_ms} ms)`)
      lines.push(`B: HTTP ${rb.status} sha=${rb.body_sha256} (${rb.timing_ms} ms)`)
      if (ra.status !== rb.status) lines.push(`STATUS DIVERGES: A=${ra.status} B=${rb.status}`)
      if (structural === true) {
        let parsedA: unknown
        let parsedB: unknown
        try {
          parsedA = JSON.parse(ra.body_full ?? ra.body)
          parsedB = JSON.parse(rb.body_full ?? rb.body)
        } catch { /* fall through to the line diff */ }
        if (parsedA !== undefined && parsedB !== undefined) {
          lines.push(renderStructuralDiff(structuralJsonDiff(parsedA, parsedB, { suppressVolatile: true })))
          return textResult(lines.join('\n'))
        }
        lines.push('(structural: bodies are not both JSON — line diff below)')
      }
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

  t('http_download', 'Fetch a URL server-side and save it under the owner\'s artifacts downloads/ dir — the transcript sees only status, bytes, sha256, and content-type. Optional sha256_expected verifies integrity. Use this for evidence blobs instead of reading bodies into context.',
    {
      url: z.string().describe('Absolute URL — scope-guarded'),
      name: z.string().optional().describe('File name under downloads/ (default: derived from the URL path)'),
      headers: z.record(z.string()).optional().describe('Header map; values may use $secret:NAME'),
      auth: REQUEST_SHAPE.auth!.optional(),
      jar: z.string().optional(),
      redirect: z.enum(['follow', 'manual']).optional().describe('Default follow (unlike http_request)'),
      timeout_ms: z.number().int().optional().describe('Default 60000'),
      sha256_expected: z.string().optional().describe('Verify the downloaded bytes (mismatch still writes the file, but errors)'),
      owner: z.string().optional().describe('Attribution for the scope audit log and the artifacts subdir'),
    },
    async ({ url, name, headers, auth, jar, redirect, timeout_ms, sha256_expected, owner }: any) => {
      const result = await performDownload(jars, env.scope, env.config, {
        url, headers, auth, jar, redirect, timeout_ms,
      } as RequestSpec, owner ?? 'unknown', name, sha256_expected, env.budget)
      return textResult(`Saved ${result.bytes} bytes → ${result.file}\nHTTP ${result.status} · ${result.contentType} · sha256 ${result.sha256}`)
    })
}
