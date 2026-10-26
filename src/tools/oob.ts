import crypto from 'node:crypto'
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

  constructor(private port: number, private publicBase?: string) {}

  newToken(label?: string): OobToken {
    const token = crypto.randomBytes(8).toString('hex')
    const entry: OobToken = { token, ...(label === undefined ? {} : { label }), createdAt: Date.now(), events: [] }
    this.tokens.set(token, entry)
    return entry
  }

  /** Start the local receiver (idempotent). Returns the listening port. */
  async ensureServer(): Promise<number> {
    if (this.server !== undefined) {
      const addr = this.server.address()
      if (addr !== null && typeof addr === 'object') return addr.port
    }
    const server = http.createServer((req, res) => {
      const chunks: Buffer[] = []
      req.on('data', chunk => { if (chunks.reduce((n, c) => n + c.length, 0) < MAX_BODY_CAPTURE) chunks.push(chunk as Buffer) })
      req.on('end', () => {
        const tokenMatch = /\/oob\/([A-Za-z0-9]+)(?:\/|$)/.exec(req.url ?? '')
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
          }
        }
        res.writeHead(200, { 'content-type': 'text/plain' })
        res.end('constellation-oob\n')
      })
    })
    this.server = server
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(this.port, '127.0.0.1', () => resolve())
    })
    return this.port
  }

  urls(token: string): { local: string; public?: string } {
    return {
      local: `http://127.0.0.1:${this.port}/oob/${token}`,
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
    })
  }
}

export function registerOobTools(server: ToolRegistrar, store: OobStore): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('oob_new', 'Create an out-of-band callback token for SSRF/blind-XSS proof. Local receiver on 127.0.0.1; set CONSTELLATION_OOB_PUBLIC_BASE for a public tunnel URL.',
    { label: z.string().optional().describe('What this token is for, e.g. "launchdarkly-webhook"') },
    async ({ label }: any) => {
      const port = await store.ensureServer()
      const entry = store.newToken(label)
      const urls = store.urls(entry.token)
      return textResult([
        `token: ${entry.token}${label === undefined ? '' : ` (${label})`}`,
        `local:  ${urls.local}`,
        ...(urls.public !== undefined ? [`public: ${urls.public}`] : ['public: set CONSTELLATION_OOB_PUBLIC_BASE (e.g. a cloudflared/ngrok tunnel to 127.0.0.1:8787) and re-run for a public URL']),
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
