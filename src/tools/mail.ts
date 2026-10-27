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
  headers?: Map<string, unknown>
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

interface MailboxList {
  path: string
  specialUse?: string | string[]
  flags?: string | string[]
}

interface OpenedMailbox {
  exists?: number
  path?: string
}

interface ImapClient {
  connect(): Promise<boolean>
  logout(): Promise<void>
  close(): void
  list?(): Promise<MailboxList[]>
  mailboxOpen?(name: string): Promise<OpenedMailbox>
  search(query: Record<string, unknown>, options?: { uid?: boolean }): Promise<number[] | false>
  fetch(range: number[] | string, query: Record<string, unknown>): AsyncIterable<ImapMessage>
}

export interface MailConfig {
  host: string
  user: string
  pass: string
  port: number
  folder: string
}

export function mailConfig(): MailConfig | undefined {
  const host = process.env.CONSTELLATION_MAIL_HOST?.trim()
  const user = process.env.CONSTELLATION_MAIL_USER?.trim()
  // Google shows app passwords as "xxxx xxxx xxxx xxxx"; a pasted copy keeps
  // the internal spaces and IMAP auth fails with an opaque "Command failed".
  const pass = process.env.CONSTELLATION_MAIL_PASS?.trim().replace(/\s+/g, '')
  if (host === undefined || host === '' || user === undefined || user === '' || pass === undefined || pass === '') return undefined
  return {
    host,
    user,
    pass,
    port: Number.parseInt(process.env.CONSTELLATION_MAIL_PORT ?? '993', 10) || 993,
    folder: process.env.CONSTELLATION_MAIL_FOLDER?.trim() || 'INBOX',
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

/** Human-readable text for any thrown value, including non-Error objects that
 *  imapflow rejects with (`Error: [object Object]` in the live run). */
function describeError(error: unknown): string {
  if (error instanceof Error) {
    const response = (error as { responseText?: unknown }).responseText
    const responseText = typeof response === 'string' && response !== '' ? `: ${response}` : ''
    return `${error.message}${responseText}`
  }
  if (typeof error === 'string') return error
  try { return JSON.stringify(error) } catch { return String(error) }
}

function mailError(phase: string, config: MailConfig, error: unknown): Error {
  return new Error(`mail ${phase} failed for ${config.user}@${config.host} (folder ${config.folder}): ${describeError(error)}`)
}

const specialUseFlags = (box: MailboxList): string[] => {
  const raw = [...(Array.isArray(box.specialUse) ? box.specialUse : box.specialUse !== undefined ? [box.specialUse] : []),
    ...(Array.isArray(box.flags) ? box.flags : box.flags !== undefined ? [box.flags] : [])]
  return raw.map(flag => String(flag).toLowerCase())
}

/** Resolve the mailbox to open: the server's \\All special-use folder when one
 *  exists (localized Gmail names like "[Gmail]/อีเมลทั้งหมด" break a configured
 *  literal), else the configured folder, else INBOX. Cached per account. */
async function resolveMailbox(client: ImapClient, config: MailConfig): Promise<string> {
  const cacheKey = `${config.user}@${config.host}`
  const cached = mailboxCache.get(cacheKey)
  if (cached !== undefined) return cached
  let resolved = config.folder
  try {
    const boxes = (await client.list?.()) ?? []
    const allMail = boxes.find(box => specialUseFlags(box).includes('\\all'))
    if (allMail !== undefined) {
      const configuredExists = boxes.some(box => box.path === config.folder)
      // An \All mailbox is the superset every search wants; prefer it when the
      // configured literal is the plain INBOX default or no longer exists on
      // the server (localized Gmail renames break literal paths).
      if (!configuredExists || config.folder.toUpperCase() === 'INBOX' || config.folder === '[Gmail]/All Mail') {
        resolved = allMail.path
      }
    }
  } catch { /* list is advisory: fall back to the configured folder */ }
  mailboxCache.set(cacheKey, resolved)
  return resolved
}

const mailboxCache = new Map<string, string>()

/** One flat blob of every message header value — plus-addressing tags survive
 *  delivery rewrites in *some* header (To, Delivered-To, X-Original-To,
 *  X-Forwarded-To, or a relay subject prefix), so match the tag anywhere in it
 *  instead of betting on one field. */
function headerBlob(parsed: ParsedMail | null): string {
  if (parsed?.headers === undefined) return ''
  const parts: string[] = []
  for (const [key, value] of parsed.headers) {
    parts.push(`${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`)
  }
  return parts.join('\n')
}

function bodyText(parsed: ParsedMail | null): string {
  return [parsed?.text ?? '', typeof parsed?.html === 'string' ? parsed.html : ''].join('\n')
}

async function openClient(config: MailConfig): Promise<{ client: ImapClient; folder: string }> {
  const client = new ImapFlow({
    host: config.host,
    port: config.port,
    secure: config.port === 993,
    auth: { user: config.user, pass: config.pass },
    logger: false,
  })
  try {
    await client.connect()
  } catch (error) {
    try { client.close() } catch { /* not connected */ }
    throw mailError('connect (auth or host)', config, error)
  }
  try {
    const folder = await resolveMailbox(client, config)
    await client.mailboxOpen?.(folder)
    return { client, folder }
  } catch (error) {
    try { client.logout().catch(() => undefined) } catch { /* ignore */ }
    try { client.close() } catch { /* ignore */ }
    throw mailError(`open mailbox`, config, error)
  }
}

interface MailQuery {
  alias?: string
  from_contains?: string
  subject_contains?: string
  since_hours?: number
}

interface ScoredMessage {
  seq: number
  parsed: ParsedMail | null
  envelope: ImapMessage['envelope']
}

/** Fetch and parse the candidate sequence numbers, newest slice first work. */
async function fetchMessages(client: ImapClient, seqs: number[]): Promise<ScoredMessage[]> {
  const messages: ScoredMessage[] = []
  for await (const message of client.fetch(seqs, { envelope: true, source: true })) {
    const parsed = message.source === undefined ? null : await simpleParser(message.source)
    messages.push({ seq: message.seq, parsed, envelope: message.envelope })
  }
  return messages
}

function toHit(message: ScoredMessage): MailHit {
  const textBody = bodyText(message.parsed)
  const addr = (list?: Array<{ name?: string; address?: string }>) =>
    (list ?? []).map(a => (a.name !== undefined && a.name !== '' ? `${a.name} <${a.address ?? ''}>` : a.address ?? '')).join(', ')
  return {
    subject: message.envelope?.subject ?? message.parsed?.subject ?? '(no subject)',
    from: addr(message.envelope?.from),
    to: addr(message.envelope?.to),
    date: (message.envelope?.date ?? message.parsed?.date ?? new Date()).toISOString(),
    seq: message.seq,
    extracted_links: extractLinks(textBody),
    extracted_codes: extractCodes(textBody),
  }
}

/** IMAP `TO` misses plus-addressed mail on forwarding relays (Bugcrowd Relay
 *  rewrites To: to the destination account), so alias filtering happens
 *  client-side against every header plus the subject and body. */
function matchesAlias(message: ScoredMessage, alias: string): boolean {
  const tag = `+${alias}@`
  const haystack = [headerBlob(message.parsed), message.envelope?.subject ?? '', bodyText(message.parsed)].join('\n')
  return haystack.includes(tag)
}

async function searchMail(config: MailConfig, query: MailQuery, limit: number): Promise<MailHit[]> {
  const { client, folder } = await openClient(config)
  try {
    const search: Record<string, unknown> = {}
    // Alias never narrows the IMAP search: forwarding relays rewrite To:, and a
    // `to` filter returned "(no matching mail)" while the message sat in the
    // inbox (live run 2026-10-27). Filtering happens client-side.
    if (query.from_contains !== undefined && query.from_contains !== '') search.from = query.from_contains
    if (query.subject_contains !== undefined && query.subject_contains !== '') search.subject = query.subject_contains
    if (query.since_hours !== undefined) search.since = new Date(Date.now() - query.since_hours * 3_600_000)
    const seqs = (await client.search(search)) || []
    const scanCap = query.alias !== undefined && query.alias !== '' ? Math.min(Math.max(limit * 10, 30), 120) : limit
    const wanted = seqs.slice(-scanCap)
    const messages = await fetchMessages(client, wanted)
    let hits = messages.map(message => ({ message, hit: toHit(message) }))
    if (query.alias !== undefined && query.alias !== '') {
      hits = hits.filter(row => matchesAlias(row.message, query.alias!))
    }
    if (query.from_contains !== undefined && query.from_contains !== '') {
      hits = hits.filter(row => row.hit.from.toLowerCase().includes(query.from_contains!.toLowerCase()))
    }
    if (query.subject_contains !== undefined && query.subject_contains !== '') {
      hits = hits.filter(row => row.hit.subject.toLowerCase().includes(query.subject_contains!.toLowerCase()))
    }
    hits.sort((a, b) => b.hit.date.localeCompare(a.hit.date))
    if (hits.length === 0) {
      lastSearchNote = `searched folder "${folder}": ${seqs.length} message(s) matched IMAP filters`
        + (query.alias !== undefined && query.alias !== '' ? `, then +${query.alias}@ was matched against To/Delivered-To/X-Original-To/X-Forwarded-To/subject/body of the ${messages.length} scanned` : '')
        + ' — widen since_hours or drop filters if the mail is older.'
    } else {
      lastSearchNote = `folder "${folder}"`
    }
    return hits.slice(0, limit).map(row => row.hit)
  } finally {
    try { client.logout().catch(() => undefined) } catch { /* ignore */ }
    try { client.close() } catch { /* ignore */ }
  }
}

let lastSearchNote = ''

function formatHits(hits: MailHit[]): string {
  if (hits.length === 0) return `(no matching mail — ${lastSearchNote})`
  return hits.map(h => [
    `[seq ${h.seq}] ${h.date} — ${h.subject}`,
    `  from: ${h.from} → to: ${h.to}`,
    ...(h.extracted_codes.length > 0 ? [`  codes: ${h.extracted_codes.join(', ')}`] : []),
    ...(h.extracted_links.length > 0 ? [`  links: ${h.extracted_links.slice(0, 5).join(' | ')}`] : []),
  ].join('\n')).join('\n')
}

/** Anchor pairs `<href> ← <text>` from the HTML body — the real link text is
 *  how you tell the verification link from the unsubscribe footer. */
export function extractAnchors(html: string): Array<{ href: string; text: string }> {
  const decode = (value: string): string => value
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&#x27;/gi, "'")
  const anchors: Array<{ href: string; text: string }> = []
  const seen = new Set<string>()
  for (const match of html.matchAll(/<a\s[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gis)) {
    const href = decode(match[1]!)
    if (!/^https?:/i.test(href) || seen.has(href)) continue
    seen.add(href)
    anchors.push({ href, text: decode(match[2]!.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ')).trim() })
    if (anchors.length >= 20) break
  }
  return anchors
}

/** HEAD with redirects disabled: surfaces a tracking redirect's target without
 *  touching whatever the Location points at (it may be out of scope). */
async function resolveRedirect(url: string): Promise<string | undefined> {
  try {
    const response = await fetch(url, { method: 'HEAD', redirect: 'manual', signal: AbortSignal.timeout(4_000) })
    const location = response.headers.get('location')
    if (response.status >= 300 && response.status < 400 && location !== null) return location
    return undefined
  } catch {
    return undefined
  }
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

  t('mail_search', 'Search the project inbox via IMAP. `alias` matches plus-addressing against To/Delivered-To/X-Original-To/X-Forwarded-To, the subject, and the body (forwarding relays rewrite To:, so no single header is trusted). Returns codes + links extracted; empty results state exactly what was searched.',
    {
      alias: z.string().optional().describe('Plus-address tag, e.g. "ynab" matches dotjumpdot+ynab@… anywhere in the headers or body'),
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

  t('mail_get', 'Read one message in full by seq: text and HTML (capped), every link with its anchor text, and each link\'s redirect target resolved with redirects DISABLED (a manual HEAD — never follows into an out-of-scope host).',
    {
      seq: z.number().int().describe('Sequence number from mail_search / mail_latest_otp'),
      resolve_links: z.boolean().optional().describe('Resolve redirect targets for the first 5 links (default true)'),
    },
    async ({ seq, resolve_links }: any) => {
      const config = requireConfig()
      const { client, folder } = await openClient(config)
      let message: ScoredMessage | undefined
      try {
        const messages = await fetchMessages(client, [seq])
        message = messages[0]
      } finally {
        try { client.logout().catch(() => undefined) } catch { /* ignore */ }
        try { client.close() } catch { /* ignore */ }
      }
      if (message === undefined) return textResult(`no message at seq ${seq} in folder "${folder}"`, true)
      const text = message.parsed?.text ?? ''
      const html = typeof message.parsed?.html === 'string' ? message.parsed.html : ''
      const lines = [
        `[seq ${message.seq}] ${(message.envelope?.date ?? message.parsed?.date ?? new Date()).toISOString()} — ${message.envelope?.subject ?? message.parsed?.subject ?? '(no subject)'}`,
        `from: ${message.envelope?.from?.map(a => a.address ?? '').join(', ') ?? ''}`,
      ]
      if (text !== '') lines.push(`\ntext (capped):\n${text.slice(0, 4_000)}${text.length > 4_000 ? `\n…(${text.length - 4_000} more chars)` : ''}`)
      const anchors = extractAnchors(html)
      if (anchors.length > 0) {
        lines.push('\nlinks:')
        const top = anchors.slice(0, 5)
        if (resolve_links !== false) {
          for (const anchor of top) {
            const redirect = await resolveRedirect(anchor.href)
            lines.push(`  ${anchor.href}${anchor.text !== '' ? ` ← "${anchor.text}"` : ''}${redirect !== undefined ? `\n    redirects to: ${redirect}` : ''}`)
          }
          for (const anchor of anchors.slice(5)) lines.push(`  ${anchor.href}${anchor.text !== '' ? ` ← "${anchor.text}"` : ''}`)
        } else {
          for (const anchor of anchors) lines.push(`  ${anchor.href}${anchor.text !== '' ? ` ← "${anchor.text}"` : ''}`)
        }
      }
      return textResult(lines.join('\n'))
    })

  t('mail_status', 'One-call mail health check: authenticates, resolves the mailbox by special-use (localized Gmail folder names break literal paths), and reports folder + message count.',
    {},
    async () => {
      const config = requireConfig()
      const { client, folder } = await openClient(config)
      let exists: number | undefined
      try {
        const opened = await client.mailboxOpen?.(folder)
        exists = opened?.exists
      } finally {
        try { client.logout().catch(() => undefined) } catch { /* ignore */ }
        try { client.close() } catch { /* ignore */ }
      }
      return textResult(`authenticated as ${config.user}@${config.host}\nfolder: ${folder}${exists === undefined ? '' : ` (${exists} messages)`}`)
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
        if (Date.now() >= deadline) return textResult(`No matching mail within ${timeout_ms ?? 120_000} ms. ${lastSearchNote}`, true)
        await new Promise(resolve => setTimeout(resolve, poll))
      }
    })
}
