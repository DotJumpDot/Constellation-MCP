/**
 * Fixture primitives (run-8 proposals §1a/1b): the harness could browse,
 * observe and record — it could not MANUFACTURE the objects under test.
 *
 * - fixture_publish: attacker-controlled content behind a PUBLIC cloudflared
 *   URL with an attacker-chosen canary; fixture_hits answers "was the canary
 *   in this request" so a hit proves exfiltration, not just traffic.
 * - fixture_forge: real .docx/.pdf/.html files generated locally (pure Node,
 *   no editor needed) for browser_upload — content creation must not depend
 *   on a contenteditable driven by synthetic events (the kix lesson).
 */

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { z } from 'zod'
import { errorResult, textResult, type ToolRegistrar, type ToolResult } from '../browser/tools.js'
import type { OobStore } from './oob.js'
import type { ConstellationConfig } from '../config.js'

const FIXTURE_ROUTE = '/f/'
const TUNNEL_KEY = '__fixtures__'
const DEFAULT_TTL_HOURS = 2

export interface FixtureEntry {
  id: string
  kind: 'html' | 'markdown' | 'json' | 'pdf' | 'docx' | 'file'
  contentType: string
  body: Buffer
  canary?: string
  label?: string
  createdAt: number
  expiresAt: number
  hits: Array<{ ts: string; method: string; query: string; remote: string; canarySeen: boolean; referer?: string }>
}

export class FixtureStore {
  private fixtures = new Map<string, FixtureEntry>()

  constructor(private oob: OobStore, readonly config: ConstellationConfig) {
    this.oob.registerRoute(FIXTURE_ROUTE, (req, res, pathname, body) => this.serve(req, res, pathname, body))
  }

  /** One shared quick tunnel for every fixture (spawned on first publish). */
  private async publicBase_(): Promise<string> {
    await this.oob.ensureServer()
    return this.oob.startQuickTunnel(TUNNEL_KEY)
  }

  publish(input: { kind: FixtureEntry['kind']; body: string; canary?: string; label?: string; ttl_hours?: number }): FixtureEntry {
    const id = crypto.randomBytes(5).toString('hex')
    const contentTypes: Record<FixtureEntry['kind'], string> = {
      html: 'text/html; charset=utf-8',
      markdown: 'text/plain; charset=utf-8',
      json: 'application/json',
      pdf: 'application/pdf',
      docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      file: 'application/octet-stream',
    }
    const entry: FixtureEntry = {
      id,
      kind: input.kind,
      contentType: contentTypes[input.kind],
      body: Buffer.from(input.body, input.kind === 'pdf' || input.kind === 'docx' ? 'binary' : 'utf8'),
      ...(input.canary !== undefined && input.canary !== '' ? { canary: input.canary } : {}),
      ...(input.label !== undefined ? { label: input.label } : {}),
      createdAt: Date.now(),
      expiresAt: Date.now() + Math.max(input.ttl_hours ?? DEFAULT_TTL_HOURS, 0.1) * 3_600_000,
      hits: [],
    }
    this.fixtures.set(id, entry)
    return entry
  }

  publishFile(filePath: string, input: { canary?: string; label?: string; ttl_hours?: number }): FixtureEntry {
    const id = crypto.randomBytes(5).toString('hex')
    const entry: FixtureEntry = {
      id,
      kind: 'file',
      contentType: 'application/octet-stream',
      body: fs.readFileSync(filePath),
      ...(input.canary !== undefined && input.canary !== '' ? { canary: input.canary } : {}),
      ...(input.label !== undefined ? { label: input.label } : {}),
      createdAt: Date.now(),
      expiresAt: Date.now() + Math.max(input.ttl_hours ?? DEFAULT_TTL_HOURS, 0.1) * 3_600_000,
      hits: [],
    }
    this.fixtures.set(id, entry)
    return entry
  }

  /** Pure canary decision: a hit proves exfiltration only when the outbound
   *  request carries a value the attacker planted and the target chose to send. */
  static canarySeen(canary: string | undefined, parts: { query: string; headers: Record<string, string>; body: string; path: string }): boolean {
    if (canary === undefined) return false
    const haystack = [parts.path, parts.query, parts.body, ...Object.entries(parts.headers).map(([k, v]) => `${k}:${v}`)].join('\n')
    return haystack.includes(canary)
  }

  private serve(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, pathname: string, bodyText: string): void {
    const id = pathname.slice(FIXTURE_ROUTE.length).split('/')[0] ?? ''
    const entry = this.fixtures.get(id)
    if (entry === undefined) {
      res.writeHead(404, { 'content-type': 'text/plain' })
      res.end('fixture not found (or expired) — republish with fixture_publish\n')
      return
    }
    if (entry.expiresAt < Date.now()) {
      this.fixtures.delete(id)
      res.writeHead(410, { 'content-type': 'text/plain' })
      res.end('fixture expired\n')
      return
    }
    const headers = Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k, String(v)]))
    entry.hits.push({
      ts: new Date().toISOString(),
      method: req.method ?? '?',
      query: req.url?.includes('?') ? req.url.slice(req.url.indexOf('?') + 1) : '',
      remote: req.socket.remoteAddress ?? '',
      ...(entry.canary !== undefined ? { canarySeen: FixtureStore.canarySeen(entry.canary, { query: req.url?.split('?')[1] ?? '', headers, body: bodyText, path: pathname }) } : { canarySeen: false }),
      ...(headers['referer'] !== undefined ? { referer: headers['referer'] } : {}),
    })
    if (entry.hits.length > 200) entry.hits.shift()
    res.writeHead(200, { 'content-type': entry.contentType })
    res.end(entry.body)
  }

  hits(id: string): Array<FixtureEntry['hits'][number]> | undefined {
    const entry = this.fixtures.get(id)
    if (entry === undefined) return undefined
    if (entry.expiresAt < Date.now()) { this.fixtures.delete(id); return undefined }
    return entry.hits
  }

  async urlFor(id: string): Promise<string> {
    const base = await this.publicBase_()
    return `${base}${FIXTURE_ROUTE}${id}`
  }

  list(): Array<{ id: string; kind: string; label?: string; hits: number; canary_hits: number; age_min: number }> {
    return [...this.fixtures.values()].map(entry => ({
      id: entry.id,
      kind: entry.kind,
      ...(entry.label === undefined ? {} : { label: entry.label }),
      hits: entry.hits.length,
      canary_hits: entry.hits.filter(hit => hit.canarySeen).length,
      age_min: Math.round((Date.now() - entry.createdAt) / 60_000),
    }))
  }
}

// ── fixture_forge: local document generation (run-8 proposals §1b) ──────────

const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = (c & 1) !== 0 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1
    table[n] = c >>> 0
  }
  return table
})()

function crc32(buf: Buffer): number {
  let c = 0xFFFFFFFF
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xFF]! ^ (c >>> 8)
  return (c ^ 0xFFFFFFFF) >>> 0
}

/** Minimal STORED (uncompressed) ZIP writer — enough for a valid .docx. */
export function zipStore(entries: Array<{ name: string; data: Buffer }>): Buffer {
  const parts: Buffer[] = []
  const central: Buffer[] = []
  let offset = 0
  for (const entry of entries) {
    const nameBytes = Buffer.from(entry.name, 'utf8')
    const crc = crc32(entry.data)
    const local = Buffer.alloc(30)
    local.writeUInt32LE(0x04034b50, 0)
    local.writeUInt16LE(20, 4)
    local.writeUInt16LE(0, 6)
    local.writeUInt16LE(0, 8)
    local.writeUInt16LE(0, 10)
    local.writeUInt16LE(0, 12)
    local.writeUInt32LE(crc, 14)
    local.writeUInt32LE(entry.data.length, 18)
    local.writeUInt32LE(entry.data.length, 22)
    local.writeUInt16LE(nameBytes.length, 26)
    local.writeUInt16LE(0, 28)
    parts.push(local, nameBytes, entry.data)
    const dir = Buffer.alloc(46)
    dir.writeUInt32LE(0x02014b50, 0)
    dir.writeUInt16LE(20, 4)
    dir.writeUInt16LE(20, 6)
    dir.writeUInt16LE(0, 8)
    dir.writeUInt16LE(0, 10)
    dir.writeUInt16LE(0, 12)
    dir.writeUInt16LE(0, 14)
    dir.writeUInt32LE(crc, 16)
    dir.writeUInt32LE(entry.data.length, 20)
    dir.writeUInt32LE(entry.data.length, 24)
    dir.writeUInt16LE(nameBytes.length, 28)
    dir.writeUInt32LE(offset, 42)
    central.push(dir, nameBytes)
    offset += local.length + nameBytes.length + entry.data.length
  }
  const centralBuf = Buffer.concat(central)
  const end = Buffer.alloc(22)
  end.writeUInt32LE(0x06054b50, 0)
  end.writeUInt16LE(entries.length, 8)
  end.writeUInt16LE(entries.length, 10)
  end.writeUInt32LE(centralBuf.length, 12)
  end.writeUInt32LE(offset, 16)
  return Buffer.concat([...parts, centralBuf, end])
}

const xmlEscape = (value: string): string =>
  value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

/** Markdown-ish lines → minimal valid .docx (headings bold+size, rest plain). */
export function markdownToDocx(title: string, markdown: string): Buffer {
  const paragraphs = [`## ${title}`, '', ...markdown.split('\n')]
  const body = paragraphs.map(line => {
    if (line.trim() === '') return '<w:p/>'
    const heading = /^#{1,3}\s+(.*)$/.exec(line)
    const text = xmlEscape(heading !== null ? heading[1]! : line)
    const runProps = heading !== null ? '<w:rPr><w:b/><w:sz w:val="32"/></w:rPr>' : ''
    return `<w:p><w:r>${runProps}<w:t xml:space="preserve">${text}</w:t></w:r></w:p>`
  }).join('')
  const document = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${body}</w:body></w:document>`
  const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`
  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`
  return zipStore([
    { name: '[Content_Types].xml', data: Buffer.from(contentTypes, 'utf8') },
    { name: '_rels/.rels', data: Buffer.from(rels, 'utf8') },
    { name: 'word/document.xml', data: Buffer.from(document, 'utf8') },
  ])
}

const pdfEscape = (value: string): string => value.replace(/([\\()])/g, '\\$1')

/** Minimal single/multi-page PDF with Helvetica text (no deps, Docs-importable). */
export function markdownToPdf(title: string, markdown: string): Buffer {
  const lines = [`## ${title}`, '', ...markdown.split('\n')]
  const pageLines = 48
  const pages: string[][] = []
  for (let at = 0; at < lines.length; at += pageLines) pages.push(lines.slice(at, at + pageLines))
  if (pages.length === 0) pages.push([''])
  const objects: string[] = []
  const pageObjectStart = 3
  const kids = pages.map((_, at) => `${pageObjectStart + at * 2} 0 R`).join(' ')
  objects.push(`<< /Type /Catalog /Pages 2 0 R >>`)
  objects.push(`<< /Type /Pages /Kids [${kids}] /Count ${pages.length} >>`)
  pages.forEach((page, index) => {
    const content = page.map((line, row) => {
      const heading = /^#{1,3}\s+(.*)$/.exec(line)
      const size = heading !== null ? 16 : 10
      const y = 792 - 40 - row * 14
      return `BT /F1 ${size} Tf 40 ${y} Td (${pdfEscape(heading !== null ? heading[1]! : line)}) Tj ET`
    }).join('\n')
    const contentId = pageObjectStart + index * 2 + 1
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents ${contentId} 0 R /Resources << /Font << /F1 1 0 R >> >> >>`)
    objects.push(`<< /Length ${content.length} >>\nstream\n${content}\nendstream`)
  })
  let pdf = '%PDF-1.4\n'
  const offsets: number[] = [0]
  objects.forEach((object, index) => {
    offsets.push(pdf.length)
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`
  })
  const xrefAt = pdf.length
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
  for (let at = 1; at <= objects.length; at++) pdf += `${String(offsets[at]).padStart(10, '0')} 00000 n \n`
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefAt}\n%%EOF\n`
  return Buffer.from(pdf, 'latin1')
}

export function registerFixtureTools(server: ToolRegistrar, store: FixtureStore): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('fixture_publish', 'Publish attacker-controlled content behind a PUBLIC trycloudflare.com URL (run-8 §1a): the SSRF/blind-XSS/AI-exfil content host lanes used to hand-roll with cloudflared + a text file. `canary` is the proof value — fixture_hits reports canary_seen per hit, so a hit PROVES exfiltration instead of making you grep headers. Content must be things you are authorized to test with; the tunnel is torn down by oob_close {token:"__fixtures__"} or server shutdown.',
    {
      kind: z.enum(['html', 'markdown', 'json']).describe('Served content type (use fixture_forge + upload for docx/pdf)'),
      body: z.string().describe('The content to serve (the injection payload / SSRF bait / exfil marker)'),
      canary: z.string().optional().describe('Proof value embedded in the content — hits carrying it back prove ingestion+exfil'),
      label: z.string().optional(),
      ttl_hours: z.number().optional().describe('Default 2h; content 410s after expiry'),
    },
    async ({ kind, body, canary, label, ttl_hours }: any) => {
      const entry = store.publish({ kind, body, canary, label, ttl_hours })
      const url = await store.urlFor(entry.id)
      return textResult([
        `url: ${url}`,
        `id: ${entry.id}${label !== undefined ? ` (${label})` : ''}`,
        ...(canary !== undefined && canary !== '' ? [`canary: ${canary} — fixture_hits {id:"${entry.id}"} reports canary_seen per hit`] : ['canary: (none — a hit proves traffic, not exfiltration)']),
        `ttl: ${ttl_hours ?? DEFAULT_TTL_HOURS}h — read hits with fixture_hits {id:"${entry.id}"}`,
      ].join('\n'))
    })

  t('fixture_hits', 'Callbacks recorded for a published fixture, with canary_seen per hit (the exfiltration verdict — never "go grep the headers").',
    { id: z.string().describe('Fixture id from fixture_publish') },
    async ({ id }: any) => {
      const hits = store.hits(id)
      if (hits === undefined) return textResult(`unknown or expired fixture "${id}"`, true)
      if (hits.length === 0) return textResult('(no callbacks yet)')
      const canaryHits = hits.filter(hit => hit.canarySeen).length
      return textResult([
        `${hits.length} hit(s), CANARY SEEN in ${canaryHits}${canaryHits > 0 ? ' — EXFILTRATION CONFIRMED' : ''}`,
        ...hits.slice(-20).map(hit => `${hit.ts} ${hit.method} from ${hit.remote}${hit.canarySeen ? ' ★canary' : ''}${hit.query !== '' ? ` ?${hit.query.slice(0, 200)}` : ''}`),
      ].join('\n'))
    })

  t('fixture_forge', 'Generate a REAL document file locally (run-8 §1b): .docx (valid OOXML zip) / .pdf / .html from markdown — no editor, no synthetic input. Returns the file path for browser_upload {trigger} (Drive: upload the .docx, then "Open with Google Docs" bypasses the kix editor entirely).',
    {
      kind: z.enum(['docx', 'pdf', 'html']),
      title: z.string().describe('Document title (rendered as the first heading)'),
      body_markdown: z.string().describe('Body as markdown-ish text (# headings, paragraphs, blank lines)'),
      filename: z.string().optional().describe('Output file name (default: forged-<ts>.<ext> in the shared artifacts dir)'),
    },
    async ({ kind, title, body_markdown, filename }: any) => {
      const dir = path.join(store['config'].outputDir, 'forge')
      fs.mkdirSync(dir, { recursive: true })
      const safe = (filename ?? `forged-${Date.now()}`).replace(/[^A-Za-z0-9._-]/g, '_')
      const file = path.join(dir, `${safe}.${kind}`)
      if (kind === 'docx') fs.writeFileSync(file, markdownToDocx(title, body_markdown))
      else if (kind === 'pdf') fs.writeFileSync(file, markdownToPdf(title, body_markdown))
      else {
        const esc = xmlEscape(body_markdown)
        const html = `<!doctype html><meta charset="utf-8"><title>${xmlEscape(title)}</title><body style="font:14px/1.6 system-ui,sans-serif;max-width:44em;margin:2em auto">${esc.split('\n').map(line => {
          const heading = /^#{1,3}\s+(.*)$/.exec(line)
          if (heading !== null) return `<h2>${heading[1]}</h2>`
          if (line.trim() === '') return '<p></p>'
          return `<p>${line}</p>`
        }).join('\n')}</body>`
        fs.writeFileSync(file, html)
      }
      const stat = fs.statSync(file)
      return textResult(`Forged ${kind}: ${file} — ${stat.size} bytes. Upload it with browser_upload (Drive: upload then "Open with Google Docs"; Docs/Word import real documents without touching the kix editor).`)
    })

  t('fixture_list', 'List published fixtures with hit and canary-hit counts.',
    {},
    async () => {
      const rows = store.list()
      if (rows.length === 0) return textResult('(no fixtures published — fixture_publish creates one)')
      return textResult(rows.map(row =>
        `${row.id}${row.label === undefined ? '' : ` (${row.label})`} — ${row.kind}, ${row.hits} hit(s), ${row.canary_hits} canary, ${row.age_min} min old`,
      ).join('\n'))
    })
}
