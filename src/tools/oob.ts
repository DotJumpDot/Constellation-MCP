import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
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
}

const MAX_EVENTS_PER_TOKEN = 100
const MAX_BODY_CAPTURE = 4_096

export class OobStore {
  private tokens = new Map<string, OobToken>()
  private server?: http.Server
  private boundPort?: number

  constructor(private port: number, private publicBase?: string, private persistFile?: string) {
    this.loadPersisted()
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
        const tokenMatch = /\/oob\/([A-Za-z0-9]{6,64})(?:[/?#]|$)/.exec(req.url ?? '')
        const event: OobEvent = {
          ts: new Date().toISOString(),
          method: req.method ?? '?',
          path: req.url ?? '/',
          query: req.url?.includes('?') ? req.url.slice(req.url.indexOf('?') + 1) : '',
          remote: req.socket.remoteAddress ?? '',
          headers: Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, String(v)])),
          body: Buffer.concat(chunks).toString('utf8').slice(0, MAX_BODY_CAPTURE),
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
    return {
      local: `http://127.0.0.1:${port}/oob/${token}`,
      ...(this.publicBase === undefined ? {} : { public: `${this.publicBase.replace(/\/$/, '')}/oob/${token}` }),
    }
  }

  events(token: string): OobEvent[] | undefined {
    return this.tokens.get(token)?.events
  }

  list(): Array<{ token: string; label?: string; events: number; age_min: number }> {
    return [...this.tokens.values()].map(t => ({
      token: t.token,
      ...(t.label === undefined ? {} : { label: t.label }),
      events: t.events.length,
      age_min: Math.round((Date.now() - t.createdAt) / 60_000),
    }))
  }

  async dispose(): Promise<void> {
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

  t('oob_new', 'Create an out-of-band callback token for SSRF/blind-XSS proof. Local receiver on 127.0.0.1; set CONSTELLATION_OOB_PUBLIC_BASE for a public tunnel URL. Tokens and hits survive a server restart.',
    { label: z.string().optional().describe('What this token is for, e.g. "launchdarkly-webhook"') },
    async ({ label }: any) => {
      const port = await store.ensureServer()
      const entry = store.newToken(label)
      const urls = store.urls(entry.token)
      return textResult([
        `token: ${entry.token}${label === undefined ? '' : ` (${label})`}`,
        `local:  ${urls.local}`,
        ...(urls.public !== undefined ? [`public: ${urls.public}`] : ['public: set CONSTELLATION_OOB_PUBLIC_BASE (e.g. a cloudflared/ngrok tunnel to this port) and re-run for a public URL']),
        `receiver listening on 127.0.0.1:${port} — call oob_events {token} to read hits`,
      ].join('\n'))
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
