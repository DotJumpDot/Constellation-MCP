import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import { spawn, type ChildProcess } from 'node:child_process'
import { z } from 'zod'
import { errorResult, textResult, type ToolResult, type ToolRegistrar } from '../browser/tools.js'

export interface OobEvent {
  ts: string
  method: string
  path: string
  query: string
  remote: string
  headers: Record<string, string>
  body: string
}

export interface OobToken {
  token: string
  label?: string
  createdAt: number
  events: OobEvent[]
  /** Public quick-tunnel URL fronting this token (run-7 P1-9). */
  publicUrl?: string
}

interface OobTunnel {
  child: ChildProcess
  url: string
}

const MAX_EVENTS_PER_TOKEN = 100
const MAX_BODY_CAPTURE = 4_096
const TUNNEL_URL_TIMEOUT_MS = 45_000

export class OobStore {
  private tokens = new Map<string, OobToken>()
  private server?: http.Server
  private boundPort?: number
  /** Per-token cloudflared quick tunnels (run-7 P1-9). */
  private tunnels = new Map<string, OobTunnel>()
  /** Extra path handlers mounted on the same receiver (fixture content host). */
  private routes = new Map<string, (req: http.IncomingMessage, res: http.ServerResponse, pathname: string, body: string) => void>()

  constructor(private port: number, private publicBase?: string, private persistFile?: string) {
    this.loadPersisted()
  }

  /** Mount a handler for URL paths starting with `prefix` (first match wins,
   *  before OOB token handling). The handler must end the response. */
  registerRoute(prefix: string, handler: (req: http.IncomingMessage, res: http.ServerResponse, pathname: string, body: string) => void): void {
    this.routes.set(prefix, handler)
  }

  private loadPersisted(): void {
    if (this.persistFile === undefined) return
    let text = ''
    try { text = fs.readFileSync(this.persistFile, 'utf8') } catch { return }
    for (const line of text.split('\n')) {
      if (line.trim() === '') continue
      try {
        const record = JSON.parse(line) as { type: string; token: string; label?: string; createdAt?: number; event?: OobEvent }
        if (record.type === 'token') {
          if (!this.tokens.has(record.token)) {
            this.tokens.set(record.token, {
              token: record.token,
              ...(record.label === undefined ? {} : { label: record.label }),
              createdAt: record.createdAt ?? Date.now(),
              events: [],
            })
          }
        } else if (record.type === 'event') {
          const entry = this.tokens.get(record.token)
          if (entry !== undefined && record.event !== undefined) entry.events.push(record.event)
        }
      } catch { /* skip malformed line */ }
    }
  }

  private persist(record: object): void {
    if (this.persistFile === undefined) return
    try { fs.appendFileSync(this.persistFile, JSON.stringify(record) + '\n') } catch { /* best effort */ }
  }

  newToken(label?: string): OobToken {
    const token = crypto.randomBytes(8).toString('hex')
    const entry: OobToken = { token, ...(label === undefined ? {} : { label }), createdAt: Date.now(), events: [] }
    this.tokens.set(token, entry)
    this.persist({ type: 'token', token, ...(label === undefined ? {} : { label }), createdAt: entry.createdAt })
    return entry
  }

  /** Start the local receiver (idempotent). Returns the port actually bound —
   *  when the configured port is taken (a second Constellation session), it
   *  falls back to an ephemeral port instead of dying. */
  async ensureServer(): Promise<number> {
    if (this.server !== undefined && this.boundPort !== undefined) return this.boundPort
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = []
      req.on('data', chunk => { if (chunks.reduce((n, c) => n + c.length, 0) < MAX_BODY_CAPTURE) chunks.push(chunk as Buffer) })
      req.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8').slice(0, MAX_BODY_CAPTURE)
        const pathname = (req.url ?? '/').split('?')[0] ?? '/'
        for (const [prefix, handler] of this.routes) {
          if (pathname.startsWith(prefix)) {
            handler(req, res, pathname, body)
            return
          }
        }
        const tokenMatch = /\/oob\/([A-Za-z0-9]{6,64})(?:[/?#]|$)/.exec(req.url ?? '')
        const event: OobEvent = {
          ts: new Date().toISOString(),
          method: req.method ?? '?',
          path: req.url ?? '/',
          query: req.url?.includes('?') ? req.url.slice(req.url.indexOf('?') + 1) : '',
          remote: req.socket.remoteAddress ?? '',
          headers: Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, String(v)])),
          body,
        }
        if (tokenMatch !== null) {
          const entry = this.tokens.get(tokenMatch[1]!)
          if (entry !== undefined) {
            entry.events.push(event)
            if (entry.events.length > MAX_EVENTS_PER_TOKEN) entry.events.shift()
            this.persist({ type: 'event', token: entry.token, event })
          }
        }
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.end('constellation-oob\n')
      })
    })
    const listen = (port: number) => new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(port, '127.0.0.1', () => resolve())
    })
    try {
      await listen(this.port)
    } catch {
      // EADDRINUSE (or bind failure): fall back to an ephemeral port so a
      // second session keeps working; its oob_new output reports the real port.
      await listen(0)
    }
    // Keep an error handler attached so a late socket error cannot crash the
    // whole MCP server process.
    server.on('error', () => {})
    const address = server.address()
    this.server = server
    this.boundPort = typeof address === 'object' && address !== null ? address.port : this.port
    return this.boundPort
  }

  urls(token: string): { local: string; public?: string } {
    const port = this.boundPort ?? this.port
    const entry = this.tokens.get(token)
    const tunnelUrl = this.tunnels.get(token)?.url
    const publicBase = tunnelUrl ?? this.publicBase
    return {
      local: `http://127.0.0.1:${port}/oob/${token}`,
      ...(publicBase === undefined ? {} : { public: `${publicBase.replace(/\/$/, '')}/oob/${token}` }),
    }
  }

  /** Spawn a cloudflared quick tunnel to the local receiver (run-7 P1-9):
   *  SSRF/blind-XSS proof NEEDS a public callback — a loopback URL is refused
   *  by models and unreachable by remote fetchers. Brings the technique
   *  INSIDE the audited surface with guaranteed teardown. */
  async startQuickTunnel(token: string): Promise<string> {
    if (this.tunnels.has(token)) return this.tunnels.get(token)!.url
    const port = await this.ensureServer()
    let child: ChildProcess
    try {
      child = spawn('cloudflared', ['tunnel', '--url', `http://127.0.0.1:${port}`, '--no-autoupdate'], {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    } catch (error) {
      throw new Error(`cannot spawn cloudflared (${error instanceof Error ? error.message : String(error)}) — install it from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/ and retry`)
    }
    const url = await new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`cloudflared did not report a trycloudflare.com URL within ${TUNNEL_URL_TIMEOUT_MS / 1000}s`)), TUNNEL_URL_TIMEOUT_MS)
      let text = ''
      const scan = (chunk: Buffer): void => {
        text += chunk.toString('utf8')
        const match = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/i.exec(text)
        if (match !== null) {
          clearTimeout(timer)
          resolve(match[0])
        }
      }
      child.stdout?.on("data", scan)
      child.stderr?.on("data", scan)
      child.on('error', error => { clearTimeout(timer); reject(new Error(`cloudflared failed to start: ${error instanceof Error ? error.message : String(error)} — is it on PATH?`)) })
      child.on('close', code => { clearTimeout(timer); reject(new Error(`cloudflared exited early (code ${code}) — check "cloudflared tunnel --url http://127.0.0.1:${port}" by hand`)) })
    }).catch(error => {
      try { child.kill() } catch { /* already gone */ }
      throw error
    })
    this.tunnels.set(token, { child, url })
    return url
  }

  /** Teardown guarantee (run-7 P1-9): closing a token kills its tunnel. */
  closeToken(token: string): { closedToken: boolean; killedTunnel: boolean } {
    const tunnel = this.tunnels.get(token)
    let killedTunnel = false
    if (tunnel !== undefined) {
      try { tunnel.child.kill() } catch { /* already gone */ }
      this.tunnels.delete(token)
      killedTunnel = true
    }
    return { closedToken: this.tokens.delete(token), killedTunnel }
  }

  /** Live exposure view for oob_list: token → public URL while exposed. */
  exposedTunnels(): Array<{ token: string; url: string }> {
    return [...this.tunnels.entries()].map(([token, tunnel]) => ({ token, url: tunnel.url }))
  }

  events(token: string): OobEvent[] | undefined {
    return this.tokens.get(token)?.events
  }

  list(): Array<{ token: string; label?: string; events: number; age_min: number; publicUrl?: string }> {
    return [...this.tokens.values()].map(t => ({
      token: t.token,
      ...(t.label === undefined ? {} : { label: t.label }),
      events: t.events.length,
      age_min: Math.round((Date.now() - t.createdAt) / 60_000),
      ...(this.tunnels.has(t.token) ? { publicUrl: `${this.tunnels.get(t.token)!.url}/oob/${t.token}` } : {}),
    }))
  }

  async dispose(): Promise<void> {
    for (const { child } of this.tunnels.values()) {
      try { child.kill() } catch { /* already gone */ }
    }
    this.tunnels.clear()
    await new Promise<void>(resolve => {
      if (this.server === undefined) return resolve()
      this.server.close(() => resolve())
      this.server = undefined
      this.boundPort = undefined
    })
  }
}

export function registerOobTools(server: ToolRegistrar, store: OobStore): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('oob_new', 'Create an out-of-band callback token for SSRF/blind-XSS proof. `public: true` spawns a cloudflared quick tunnel automatically (run-7 P1-9) — a PUBLIC https://…trycloudflare.com URL that remote fetchers can reach; oob_close tears the tunnel down. Without it: local receiver on 127.0.0.1, public URL only when CONSTELLATION_OOB_PUBLIC_BASE is set. Tokens and hits survive a server restart (tunnels do not — re-run oob_new public after a restart).',
    { label: z.string().optional().describe('What this token is for, e.g. "launchdarkly-webhook"'), public: z.boolean().optional().describe('Spawn a cloudflared quick tunnel and return a public URL') },
    async ({ label, public: wantsPublic }: any) => {
      const port = await store.ensureServer()
      const entry = store.newToken(label)
      const urls = store.urls(entry.token)
      let publicLine: string
      if (wantsPublic === true) {
        const tunnel = await store.startQuickTunnel(entry.token)
        publicLine = `public: ${tunnel}/oob/${entry.token} (cloudflared quick tunnel; oob_close {token} guarantees teardown)`
      } else if (urls.public !== undefined) {
        publicLine = `public: ${urls.public}`
      } else {
        publicLine = 'public: pass public: true (cloudflared quick tunnel) or set CONSTELLATION_OOB_PUBLIC_BASE — remote fetchers cannot reach a loopback URL'
      }
      return textResult([
        `token: ${entry.token}${label === undefined ? '' : ` (${label})`}`,
        `local:  ${urls.local}`,
        publicLine,
        `receiver listening on 127.0.0.1:${port} — call oob_events {token} to read hits`,
      ].join('\n'))
    })

  t('oob_close', 'Close one OOB token and KILL its cloudflared tunnel (run-7 P1-9: guaranteed teardown — a forgotten quick tunnel keeps exposing this machine).',
    { token: z.string() },
    async ({ token }: any) => {
      const result = store.closeToken(token)
      if (!result.closedToken && !result.killedTunnel)
        return textResult(`unknown token "${token}" — nothing to close`, true)
      return textResult(`Closed token ${token}: token removed${result.killedTunnel ? ' and cloudflared tunnel killed (no longer exposed)' : ' (no tunnel was running)'}.`)
    })

  t('oob_events', 'Callbacks recorded for an OOB token (method, path, query, headers, body, timestamp).',
    { token: z.string() },
    async ({ token }: any) => {
      const events = store.events(token)
      if (events === undefined) return textResult(`unknown token "${token}" — create one with oob_new`, true)
      if (events.length === 0) return textResult('(no callbacks yet)')
      return textResult(events.map(e => [
        `${e.ts} ${e.method} ${e.path} from ${e.remote}`,
        `  headers: ${Object.entries(e.headers).filter(([k]) => ['host', 'user-agent', 'content-type', 'x-forwarded-for', 'referer'].includes(k)).map(([k, v]) => `${k}=${v}`).join('; ')}`,
        ...(e.body !== '' ? [`  body: ${e.body.slice(0, 500)}`] : []),
      ].join('\n')).join('\n---\n'))
    })

  t('oob_list', 'List OOB tokens and hit counts.',
    {},
    async () => {
      const rows = store.list()
      if (rows.length === 0) return textResult('(no OOB tokens yet)')
      return textResult(rows.map(r => `${r.token}${r.label === undefined ? '' : ` (${r.label})`} — ${r.events} hits, created ${r.age_min} min ago`).join('\n'))
    })
}
