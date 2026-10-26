import { z } from 'zod'
import * as imapflowNs from 'imapflow'
import * as mailparserNs from 'mailparser'
import { errorResult, textResult, type ToolResult, type ToolRegistrar } from '../browser/tools.js'

const ImapFlow = ((imapflowNs as any).ImapFlow ?? (imapflowNs as any).default?.ImapFlow) as new (opts: ImapOptions) => ImapClient
const simpleParser = ((mailparserNs as any).simpleParser ?? (mailparserNs as any).default?.simpleParser) as (src: Buffer) => Promise<ParsedMail>

interface ParsedMail {
  subject?: string
  text?: string
  html?: string | false
  date?: Date
}

interface ImapOptions {
  host: string
  port: number
  secure: boolean
  auth: { user: string; pass: string }
  logger?: boolean
  tls?: { rejectUnauthorized: boolean }
}

interface ImapMessage {
  seq: number
  uid?: number
  envelope?: {
    subject?: string
    from?: Array<{ name?: string; address?: string }>
    to?: Array<{ name?: string; address?: string }>
    date?: Date
  }
  source?: Buffer
}

interface ImapClient {
  connect(): Promise<boolean>
  logout(): Promise<void>
  close(): void
  mailboxOpen?(name: string): Promise<unknown>
  search(query: Record<string, unknown>, options?: { uid?: boolean }): Promise<number[] | false>
  fetch(range: number[] | string, query: Record<string, unknown>): AsyncIterable<ImapMessage>
}

export interface MailConfig {
  host: string
  port: number
  user: string
  pass: string
  folder: string
}

export function mailConfig(): MailConfig | undefined {
  const host = process.env.CONSTELLATION_MAIL_HOST
  const user = process.env.CONSTELLATION_MAIL_USER
  const pass = process.env.CONSTELLATION_MAIL_PASS
  if (host === undefined || user === undefined || pass === undefined) return undefined
  return {
    host,
    user,
    pass,
    port: Number.parseInt(process.env.CONSTELLATION_MAIL_PORT ?? '993', 10) || 993,
    folder: process.env.CONSTELLATION_MAIL_FOLDER ?? 'INBOX',
  }
}

export interface MailHit {
  subject: string
  from: string
  to: string
  date: string
  seq: number
  extracted_links: string[]
  extracted_codes: string[]
}

export function extractLinks(text: string): string[] {
  const matches = text.match(/https?:\/\/[^\s"'<>()[\]{}]+/g) ?? []
  return [...new Set(matches)].slice(0, 20)
}

/** OTP-shaped codes: 4-8 digit standalone numbers, plus alnum codes near
 *  code/otp/verification words. Ordered by confidence. */
export function extractCodes(text: string): string[] {
  const codes: string[] = []
  const contexty = text.match(/(?:code|otp|verification|verify|pin)[^\n0-9]{0,40}?(\d{4,8})/gi) ?? []
  for (const m of contexty) {
    const digits = m.match(/(\d{4,8})\s*$/)
    if (digits?.[1] !== undefined) codes.push(digits[1])
  }
  const bare = text.match(/\b\d{6}\b/g) ?? []
  codes.push(...bare)
  const alnum = text.match(/\b[A-Z0-9]{5,8}\b/g) ?? []
  for (const a of alnum) if (/\d/.test(a) && /[A-Z]/.test(a)) codes.push(a)
  return [...new Set(codes)].slice(0, 8)
}

async function searchMail(config: MailConfig, query: { alias?: string; from_contains?: string; subject_contains?: string; since_hours?: number }, limit: number): Promise<MailHit[]> {
  const client = new ImapFlow({
    host: config.host,
    port: config.port,
    secure: config.port === 993,
    auth: { user: config.user, pass: config.pass },
    logger: false,
    tls: { rejectUnauthorized: false },
  })
  try {
    await client.connect()
    await client.mailboxOpen?.(config.folder)
    const search: Record<string, unknown> = {}
    if (query.alias !== undefined && query.alias !== '') search.to = `+${query.alias}@`
    if (query.from_contains !== undefined && query.from_contains !== '') search.from = query.from_contains
    if (query.subject_contains !== undefined && query.subject_contains !== '') search.subject = query.subject_contains
    if (query.since_hours !== undefined) search.since = new Date(Date.now() - query.since_hours * 3_600_000)
    const seqs = (await client.search(search)) || []
    const wanted = seqs.slice(-limit)
    const hits: MailHit[] = []
    for await (const message of client.fetch(wanted, { envelope: true, source: true })) {
      const parsed = message.source === undefined ? null : await simpleParser(message.source)
      const textBody = [parsed?.text ?? '', typeof parsed?.html === 'string' ? parsed.html : ''].join('\n')
      const addr = (list?: Array<{ name?: string; address?: string }>) =>
        (list ?? []).map(a => (a.name !== undefined && a.name !== '' ? `${a.name} <${a.address ?? ''}>` : a.address ?? '')).join(', ')
      hits.push({
        subject: message.envelope?.subject ?? parsed?.subject ?? '(no subject)',
        from: addr(message.envelope?.from),
        to: addr(message.envelope?.to),
        date: (message.envelope?.date ?? parsed?.date ?? new Date()).toISOString(),
        seq: message.seq,
        extracted_links: extractLinks(textBody),
        extracted_codes: extractCodes(textBody),
      })
    }
    hits.sort((a, b) => b.date.localeCompare(a.date))
    return hits
  } finally {
    try { client.close() } catch { /* done */ }
  }
}

function formatHits(hits: MailHit[]): string {
  if (hits.length === 0) return '(no matching mail)'
  return hits.map(h => [
    `[seq ${h.seq}] ${h.date} — ${h.subject}`,
    `  from: ${h.from} → to: ${h.to}`,
    ...(h.extracted_codes.length > 0 ? [`  codes: ${h.extracted_codes.join(', ')}`] : []),
    ...(h.extracted_links.length > 0 ? [`  links: ${h.extracted_links.slice(0, 5).join(' | ')}`] : []),
  ].join('\n')).join('\n')
}

export function registerMailTools(server: ToolRegistrar): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  const requireConfig = (): MailConfig => {
    const config = mailConfig()
    if (config === undefined)
      throw new Error('mail tools not configured — set CONSTELLATION_MAIL_HOST / CONSTELLATION_MAIL_USER / CONSTELLATION_MAIL_PASS (env only, never in files)')
    return config
  }

  t('mail_search', 'Search the project inbox via IMAP. `alias` matches plus-addressing (To contains +<alias>@). Returns codes + links extracted.',
    {
      alias: z.string().optional().describe('Plus-address tag, e.g. "ynab" matches dotjumpdot+ynab@…'),
      from_contains: z.string().optional(),
      subject_contains: z.string().optional(),
      since_hours: z.number().optional().describe('Only mail newer than N hours'),
      limit: z.number().int().optional(),
    },
    async ({ alias, from_contains, subject_contains, since_hours, limit }: any) => {
      const config = requireConfig()
      const hits = await searchMail(config, { alias, from_contains, subject_contains, since_hours }, limit ?? 10)
      return textResult(formatHits(hits))
    })

  t('mail_latest_otp', 'Latest matching mail with extracted verification codes — the one-call signup helper.',
    { alias: z.string().optional(), from_contains: z.string().optional(), subject_contains: z.string().optional() },
    async ({ alias, from_contains, subject_contains }: any) => {
      const config = requireConfig()
      const hits = await searchMail(config, { alias, from_contains, subject_contains, since_hours: 24 }, 5)
      const withCodes = hits.find(h => h.extracted_codes.length > 0) ?? hits[0]
      return textResult(formatHits(withCodes === undefined ? [] : [withCodes]))
    })

  t('mail_wait', 'Poll the inbox until a matching mail arrives (or timeout). Frees workers from Gmail tab-hopping.',
    {
      alias: z.string().optional(), subject_contains: z.string().optional(), from_contains: z.string().optional(),
      timeout_ms: z.number().int().optional().describe('Default 120000'),
      poll_ms: z.number().int().optional().describe('Default 5000'),
    },
    async ({ alias, subject_contains, from_contains, timeout_ms, poll_ms }: any) => {
      const config = requireConfig()
      const startedAt = Date.now()
      const deadline = startedAt + (timeout_ms ?? 120_000)
      const poll = poll_ms ?? 5_000
      for (;;) {
        const hits = await searchMail(config, { alias, subject_contains, from_contains, since_hours: 1 }, 5)
        const fresh = hits.find(h => new Date(h.date).getTime() >= startedAt - 5_000)
        if (fresh !== undefined) return textResult(`Arrived after ${Math.round((Date.now() - startedAt) / 1000)}s:\n${formatHits([fresh])}`)
        if (Date.now() >= deadline) return textResult(`No matching mail within ${timeout_ms ?? 120_000} ms.`, true)
        await new Promise(resolve => setTimeout(resolve, poll))
      }
    })
}
