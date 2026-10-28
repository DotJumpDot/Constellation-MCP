import { createRequire } from 'node:module'
import fs from 'node:fs'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { randomBytes } from 'node:crypto'
import { z } from 'zod'
import type { Frame, Page } from 'playwright-core'
import type { ConstellationConfig } from '../config.js'
import { ScopeGuard } from '../scope.js'
import { maskSecrets, passwordValuesProbe, redactSecrets } from '../redact.js'
import { SHARED_OWNER, canTouchTab, loadOwnerLabels, type BrowserSession } from './session.js'
import { cookieMatchesAnyDomain, detectDeviceBoundSessions, readProfileCookies } from './cookies.js'
import type { OwnerRegistry } from './registry.js'
import type { BudgetGuard } from '../tools/budget.js'
import { appendChainEntry } from '../tools/evidence.js'

export interface ToolEnv {
  config: ConstellationConfig
  registry: OwnerRegistry
  scope: ScopeGuard
  budget: BudgetGuard
}

export type ToolResult = { content: Array<{ type: 'text'; text: string }>; isError?: boolean }

export function textResult(text: string, isError = false): ToolResult {
  return { content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) }
}

export function errorResult(error: unknown): ToolResult {
  return textResult(`Error: ${redactSecrets(describeErrorChain(error))}`, true)
}

/** Walk an Error's cause chain: Node's fetch throws a bare
 *  `TypeError: fetch failed` with the real transport failure (DNS, TLS,
 *  connect ECONNREFUSED, HTTP/2 …) one level down in `cause`. The generic
 *  text alone sent an agent to PowerShell to learn why (run-4 advice §3). */
export function describeErrorChain(error: unknown): string {
  const parts: string[] = []
  let at: unknown = error
  for (let depth = 0; depth < 4 && at !== undefined && at !== null; depth++) {
    const line = at instanceof Error ? at.message : (depth === 0 ? String(at) : '')
    if (line !== '' && !parts.includes(line)) parts.push(line)
    at = (at as { cause?: unknown }).cause
  }
  return parts.join(' · caused by: ')
}

const OWNER_FIELD = { owner: z.string().optional().describe('Agent owner name (your teammate name). Omitted = the shared human session.') }
const TAB_FIELD = { tab: z.number().int().optional().describe('Tab index as listed by browser_tabs list; omitted = the session\'s selected tab.') }
const FRAME_FIELD = { frame: z.string().optional().describe('iframe name or URL substring when the control lives inside a cross-origin iframe (see browser_frames_list)') }

/** Resolve an iframe root by name or URL substring. A locator timeout inside a
 *  frame reads like "the element does not exist" and sends agents down the
 *  wrong path — name the frame instead (live-run ask 2026-10-27). */
function frameFor(page: Page, frame?: string): Page | Frame {
  if (frame === undefined || frame === '') return page
  const frames = page.frames()
  const main = page.mainFrame()
  const match = frames.find(f => f !== main && f.name() === frame)
    ?? frames.find(f => f !== main && f.url().includes(frame!))
  if (match === undefined) {
    const listing = frames.map((f, i) => `[${i}] ${f.name() || '(unnamed)'} — ${f.url()}`).join('; ')
    throw new Error(`no iframe matching "${frame}" — frames on this page: ${listing}. If a control is inside an iframe, pass frame: (or use browser_run_code_unsafe).`)
  }
  return match
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max)}\n… [truncated ${s.length - max} chars]`
}

/** Compile a user-supplied `async (page, require) => {...}` expression. Pure
 *  so tests can pin the shape without a browser. */
export function makeUserFn(code: string): (page: unknown, requireFn: NodeJS.Require) => Promise<unknown> {
  let fn: unknown
  try {
    fn = (0, eval)(`(${code})`)
  } catch (error) {
    throw new Error(`code must be a function expression like \`async (page, require) => { ... }\` (${error instanceof Error ? error.message : String(error)})`)
  }
  if (typeof fn !== 'function')
    throw new Error('code must be a function expression like `async (page, require) => { ... }`')
  return fn as (page: unknown, requireFn: NodeJS.Require) => Promise<unknown>
}

function sessionOf(env: ToolEnv, ownerRaw: string | undefined): { session: BrowserSession; owner: string } {
  const owner = resolveOwner(ownerRaw)
  return { session: env.registry.sessionFor(owner), owner }
}

function resolveOwner(ownerRaw: string | undefined): string {
  const name = ownerRaw?.trim() || SHARED_OWNER
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(name))
    throw new Error(`invalid owner "${ownerRaw}" — use 1..32 chars of letters, digits, dot, dash, underscore`)
  return name
}

async function tabFor(session: BrowserSession, owner: string, tabIndex: number | undefined): Promise<Page> {
  if (tabIndex === undefined) return session.currentPage()
  const pages = session.pages()
  const page = pages[tabIndex]
  if (page === undefined)
    throw new Error(`no tab at index ${tabIndex} in ${session.owner === SHARED_OWNER ? 'the shared' : `${session.owner}'s`} session (0..${pages.length - 1}) — tab indices are PER-OWNER; call browser_tabs {action:'list'} with your owner to see your tabs`)
  const verdict = canTouchTab(session.metaOf(page), owner, session.owner)
  if (!verdict.ok) throw new Error(verdict.reason ?? 'tab is leased by another owner')
  return page
}

function locatorFor(root: Page | Frame, selector?: string, element?: string, name?: string, nth?: number) {
  if (selector !== undefined && selector !== '') {
    const loc = root.locator(selector)
    return nth === undefined ? loc : loc.nth(nth)
  }
  if (element === undefined || element === '') throw new Error('provide either `selector` or `element` (ARIA role) with optional `name`')
  const role = root.getByRole(element as never, name === undefined ? {} : { name, exact: false })
  return nth === undefined ? role : role.nth(nth)
}

/** P2-12: warn at export when the session's profile is DBSC-bound. */
function dbscWarningForProfile(userDir: string): string[] {
  try {
    if (detectDeviceBoundSessions(userDir, 'Default') || detectDeviceBoundSessions(path.join(userDir, 'Default'), 'Default')) {
      return ['WARNING: this profile carries Device Bound Sessions — replayed cookies WILL be revoked server-side within minutes. Use browser_attach for this identity.']
    }
  } catch { /* not a profile dir / not windows-shaped: no warning */ }
  return []
}

/** Evidence record for one upload (run-7 P1-8): filename, bytes, route. */
async function uploadRecord(session: BrowserSession, how: string, files: string[]): Promise<string> {
  const rows = files.map(file => {
    const stat = fs.statSync(file)
    return { file: path.basename(file), bytes: stat.size, path: file }
  })
  const record = { ts: new Date().toISOString(), owner: session.owner, route: how, files: rows }
  try {
    fs.appendFileSync(path.join(session.artifactDir(), 'uploads.jsonl'), JSON.stringify(record) + '\n')
  } catch { /* best effort */ }
  return [
    `Uploaded ${rows.length} file(s) via ${how}.`,
    ...rows.map(row => `  ${row.file} — ${row.bytes} bytes`),
    `recorded: ${path.join(session.artifactDir(), 'uploads.jsonl')}`,
    `Now at: see browser_snapshot for the page state`,
  ].join('\n')
}

async function pageOverview(page: Page): Promise<string> {
  const [title] = await Promise.all([page.title().catch(() => '')])
  return `${page.url()}${title === '' ? '' : ` — ${title}`}`
}

/** Password-field values on the page, collected straight from the DOM (run-5
 *  advice §6): an aria snapshot serializes filled textboxes, so a login or
 *  master-password field would otherwise land in the transcript verbatim.
 *  The probe result is validated — run-7 advice P0-3: one malformed probe
 *  result must never take the whole snapshot down. */
async function passwordValuesOf(page: Page): Promise<string[]> {
  try {
    const values = await page.evaluate(passwordValuesProbe)
    if (!Array.isArray(values)) return []
    return values.filter((value): value is string => typeof value === 'string')
  } catch {
    return []
  }
}

/** One page snapshot: aria snapshot when available, masked DOM text as the
 *  degraded fallback (run-7 advice P0-3 — a partial snapshot is far more
 *  useful than a hard failure). */
async function snapshotOf(page: Page): Promise<string> {
  const secrets = await passwordValuesOf(page)
  try {
    return maskSecrets(await page.locator('html').ariaSnapshot(), secrets)
  } catch (ariaError) {
    const reason = ariaError instanceof Error ? ariaError.message : String(ariaError)
    try {
      const text = await page.evaluate(() => document.body?.innerText ?? '')
      return maskSecrets(`[aria snapshot unavailable (${reason}); DOM text fallback]\n${text}`, secrets)
    } catch (domError) {
      const domReason = domError instanceof Error ? domError.message : String(domError)
      return `[aria snapshot unavailable: ${reason}; DOM text fallback failed: ${domReason}]\nURL: ${page.url()}`
    }
  }
}

async function afterActionResult(page: Page): Promise<string> {
  return `Now at: ${await pageOverview(page)}\n\n${truncate(await snapshotOf(page), 120_000)}`
}

export function registerBrowserTools(server: ToolRegistrar, env: ToolEnv): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try {
        return await handler(args)
      } catch (error) {
        return errorResult(error)
      }
    })

  t('browser_navigate', 'Navigate the owner\'s current tab to a URL and return the accessibility snapshot. Scope-guarded.',
    { url: z.string().describe('URL to navigate to'), ...OWNER_FIELD, ...TAB_FIELD },
    async ({ url, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      const meta = session.metaOf(page)
      if (meta?.infoTab === true)
        throw new Error('tab 0 is the ownership-label info tab — it stays on the owner label. Open your own tab first (browser_tabs new / tab_open).')
      env.scope.assert(url, who, 'browser_navigate')
      env.budget.spend(who)
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45_000 })
      return textResult(await afterActionResult(page))
    })

  t('browser_snapshot', 'Accessibility snapshot (YAML) of the owner\'s current tab. Password-field values are masked as •••••• — never paste credentials into automation fields you do not own.',
    { ...OWNER_FIELD, ...TAB_FIELD },
    async ({ owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      return textResult(`URL: ${await pageOverview(page)}\n\n${truncate(await snapshotOf(page), 150_000)}`)
    })

  t('browser_click', 'Click an element (by CSS/XPath selector, or ARIA role + accessible name). `frame:` reaches inside cross-origin iframes; `force: true` bypasses actionability (covered/hidden elements); x/y clicks raw viewport coordinates. Returns the new page state.',
    {
      selector: z.string().optional().describe('CSS or XPath selector'),
      element: z.string().optional().describe('ARIA role, e.g. button, link, textbox'),
      name: z.string().optional().describe('Accessible name to match (substring)'),
      nth: z.number().int().optional().describe('0-based match index when several elements match'),
      force: z.boolean().optional().describe('Skip actionability checks (element covered by an overlay)'),
      x: z.number().optional().describe('Viewport x for a raw coordinate click'),
      y: z.number().optional().describe('Viewport y for a raw coordinate click'),
      ...FRAME_FIELD,
      ...OWNER_FIELD, ...TAB_FIELD,
    },
    async ({ selector, element, name, nth, force, x, y, frame, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      if (x !== undefined && y !== undefined) {
        await page.mouse.click(x, y)
      } else {
        await locatorFor(frameFor(page, frame), selector, element, name, nth).click({ timeout: 10_000, ...(force === true ? { force: true } : {}) })
      }
      return textResult(await afterActionResult(page))
    })

  t('browser_type', 'Fill a text field (by selector or role+name). Submits with Enter on request — with submit, the tool waits for the resulting navigation to settle and reports whether the URL changed (previously it returned before navigation started, so callers polled snapshots).',
    {
      text: z.string().describe('Text to enter'),
      selector: z.string().optional(), element: z.string().optional(), name: z.string().optional(), nth: z.number().int().optional(),
      submit: z.boolean().optional().describe('Press Enter after filling and wait for navigation to settle'),
      ...FRAME_FIELD,
      ...OWNER_FIELD, ...TAB_FIELD,
    },
    async ({ text, selector, element, name, nth, submit, frame, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      const loc = locatorFor(frameFor(page, frame), selector, element, name, nth)
      await loc.fill(text, { timeout: 10_000 })
      if (submit === true) {
        const before = page.url()
        await loc.press('Enter')
        await page.waitForLoadState('domcontentloaded', { timeout: 8_000 }).catch(() => undefined)
        await page.waitForTimeout(400)
        const navigated = page.url() !== before
        return textResult(`${navigated ? '(navigated)\n' : '(no navigation)\n'}${await afterActionResult(page)}`)
      }
      return textResult(await afterActionResult(page))
    })

  t('browser_press_key', 'Press a key or combo on the owner\'s current tab (e.g. "Enter", "Control+A").',
    { key: z.string(), ...OWNER_FIELD, ...TAB_FIELD },
    async ({ key, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      await page.keyboard.press(key)
      return textResult(await afterActionResult(page))
    })

  t('browser_clipboard', 'Write text to the browser\'s clipboard (clipboardReadWrite granted first). Pairs with browser_paste — the paste event path is accepted by editors that refuse every synthetic-typing route (Google Docs kix, run-7 P1-7). The value never echoes: the result reports only its length.',
    {
      text: z.string().describe('Text to place on the clipboard'),
      ...OWNER_FIELD, ...TAB_FIELD,
    },
    async ({ text, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      const context = page.context()
      try {
        await context.grantPermissions(['clipboard-read', 'clipboard-write'])
      } catch { /* older Chrome / already granted */ }
      await page.evaluate(
        (payload: { t: string }) => void (navigator as { clipboard?: { writeText(text: string): Promise<void> } }).clipboard?.writeText(payload.t),
        { t: text },
      )
      return textResult(`Clipboard set: ${text.length} chars. Focus the target field (browser_click) and call browser_paste.`)
    })

  t('browser_paste', 'Dispatch a REAL paste into the owner\'s current tab: focuses the optional target, then sends a trusted CDP Ctrl+V so the page receives the paste event path (the one route editors like Google Docs accept — run-7 P1-7). Load the text first with browser_clipboard.',
    {
      selector: z.string().optional().describe('Selector to focus first (the paste lands in the focused element)'),
      element: z.string().optional(), name: z.string().optional(),
      ...OWNER_FIELD, ...TAB_FIELD,
    },
    async ({ selector, element, name, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      if (selector !== undefined || element !== undefined) {
        await locatorFor(page, selector, element, name).first().click({ timeout: 10_000 })
      }
      const cdp = await page.context().newCDPSession(page)
      try {
        for (const type of ['keyDown', 'keyUp'] as const) {
          await cdp.send('Input.dispatchKeyEvent', {
            type,
            key: 'v',
            code: 'KeyV',
            windowsVirtualKeyCode: 86,
            nativeVirtualKeyCode: 86,
            modifiers: 2,
          })
        }
      } finally {
        await cdp.detach().catch(() => {})
      }
      await page.waitForTimeout(400)
      return textResult(`Pasted (trusted Ctrl+V). Now at: ${await pageOverview(page)}\n\n${truncate(await snapshotOf(page), 60_000)}`)
    })

  t('browser_fill_otp', 'Distribute a verification code across a row of single-character OTP boxes in ONE call (run 4: one browser_type per box cost six calls per login, and a missed box failed silently). Fills the single autocomplete="one-time-code" input when the site uses one; otherwise fills the visible input[maxlength=1] boxes in DOM order.',
    {
      code: z.string().min(1).describe('The code exactly as delivered (letters/digits, no spaces)'),
      ...FRAME_FIELD,
      ...OWNER_FIELD, ...TAB_FIELD,
    },
    async ({ code, frame, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      const root = frameFor(page, frame)
      const chars = [...code]
      const whole = root.locator('input[autocomplete="one-time-code"]')
      if (await whole.count() > 0) {
        await whole.first().fill(code, { timeout: 10_000 })
        return textResult(`(single one-time-code input filled)\n${await afterActionResult(page)}`)
      }
      const boxes = root.locator('input[maxlength="1"]')
      const found = await boxes.count()
      if (found < chars.length) {
        throw new Error(`found ${found} single-char input box(es) but the code has ${chars.length} characters — snapshot the page; if the widget is one full-code input, use browser_type on it instead`)
      }
      for (let at = 0; at < chars.length; at++) {
        await boxes.nth(at).fill(chars[at]!, { timeout: 10_000 })
      }
      return textResult(`(filled ${chars.length}/${chars.length} boxes in DOM order)\n${await afterActionResult(page)}`)
    })

  t('browser_select_option', 'Select option(s) on a <select> element (by selector or role+name). `frame:` reaches inside cross-origin iframes.',
    {
      values: z.array(z.string()).min(1).describe('Option values or labels'),
      selector: z.string().optional(), element: z.string().optional(), name: z.string().optional(), nth: z.number().int().optional(),
      ...FRAME_FIELD,
      ...OWNER_FIELD, ...TAB_FIELD,
    },
    async ({ values, selector, element, name, nth, frame, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      await locatorFor(frameFor(page, frame), selector, element, name, nth).selectOption(values, { timeout: 10_000 })
      return textResult(await afterActionResult(page))
    })

  t('browser_evaluate', 'Run JavaScript in the owner\'s current tab and return the JSON result.',
    { function: z.string().describe('JS function or arrow expression, e.g. () => document.title'), arg: z.unknown().optional(), ...OWNER_FIELD, ...TAB_FIELD },
    async ({ function: fn, arg, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      const runnable = (0, eval)(`(${fn})`)
      const result = await page.evaluate(runnable, arg)
      return textResult(truncate(JSON.stringify(result, null, 2) ?? 'undefined', 50_000))
    })

  t('browser_console_messages', 'Recent console + page-error lines from the owner\'s browser session.',
    { ...OWNER_FIELD, limit: z.number().int().optional() },
    async ({ owner, limit }: any) => {
      const { session } = sessionOf(env, owner)
      const lines = session.consoleLines.slice(-(limit ?? 50))
      return textResult(lines.length === 0 ? '(no console output captured)' : lines.join('\n'))
    })

  t('browser_network_requests', 'Recent network requests (method, URL, status) from the owner\'s browser session.',
    { ...OWNER_FIELD, limit: z.number().int().optional(), filter: z.string().optional().describe('Substring filter on URL') },
    async ({ owner, limit, filter }: any) => {
      const { session } = sessionOf(env, owner)
      let rows = session.network.slice(-(limit ?? 50))
      if (filter !== undefined && filter !== '') rows = rows.filter(r => r.url.includes(filter))
      if (rows.length === 0) return textResult('(no network activity captured)')
      return textResult(rows.map(r => `${r.status === undefined ? ' →' : r.status} ${r.method} ${r.url}`).join('\n'))
    })

  t('browser_take_screenshot', 'Screenshot the owner\'s current tab into that owner\'s artifacts folder.',
    { filename: z.string().optional().describe('File name (defaults to a timestamp)'), fullPage: z.boolean().optional(), ...OWNER_FIELD, ...TAB_FIELD },
    async ({ filename, fullPage, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      const safe = (filename ?? `${Date.now()}.png`).replace(/[^A-Za-z0-9._-]/g, '_')
      const file = path.join(session.artifactDir(), safe)
      await page.screenshot({ path: file, fullPage: fullPage === true })
      return textResult(`Saved: ${file}`)
    })

  t('evidence_capture', 'Standardized finding evidence (run-7 P2-16): capture dom text / page HTML / screenshot into the owner\'s artifacts with sha256 hashes, and append a manifest.json entry. Stops every lane re-inventing body-hash + screenshot + timestamp, and keeps bodies OUT of transcripts. `har` is accepted but reported unsupported (HAR must be recorded from before the navigation — use browser_network_requests for what already happened).',
    {
      label: z.string().min(1).describe('Evidence label, e.g. "stored-xss payload reflected"'),
      include: z.array(z.enum(['dom', 'html', 'png', 'har'])).optional().describe('What to capture; default ["dom","html","png"]'),
      ...OWNER_FIELD, ...TAB_FIELD,
    },
    async ({ label, include, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      const wanted = new Set<string>(include ?? ['dom', 'html', 'png'])
      const stamp = new Date().toISOString().replace(/[:.]/g, '-')
      const dir = path.join(session.artifactDir(), 'evidence', `${stamp}-${label.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 60)}`)
      fs.mkdirSync(dir, { recursive: true })
      const files: Array<{ name: string; bytes: number; sha256: string }> = []
      const write = (name: string, data: Buffer | string): void => {
        const buffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data
        const file = path.join(dir, name)
        fs.writeFileSync(file, buffer)
        files.push({ name, bytes: buffer.length, sha256: createHash('sha256').update(buffer).digest('hex') })
      }
      const notes: string[] = []
      if (wanted.has('dom')) write('dom.txt', await page.evaluate(() => document.body?.innerText ?? ''))
      if (wanted.has('html')) write('page.html', await page.content())
      if (wanted.has('png')) {
        const png = await page.screenshot({ fullPage: true })
        write('page.png', png)
      }
      if (wanted.has('har')) notes.push('har: unsupported retroactively — HAR must wrap the navigation; browser_network_requests lists what was captured')
      const manifestFile = path.join(session.artifactDir(), 'manifest.json')
      const entry = {
        label, ts: new Date().toISOString(), owner: who, url: page.url(),
        files: files.map(f => ({ ...f, path: path.join(dir, f.name) })),
      }
      let manifest: unknown[] = [entry]
      try {
        const prior = JSON.parse(fs.readFileSync(manifestFile, 'utf8')) as unknown
        if (Array.isArray(prior)) manifest = [...prior, entry]
      } catch { /* first entry */ }
      fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2) + '\n')
      // Hash-chained record (run-8 §6): the report cites a verifiable chain,
      // not a directory of loose files.
      const chained = appendChainEntry(env.config, {
        owner: who, label,
        files: files.map(f => ({ name: f.name, sha256: f.sha256 })),
      })
      return textResult([
        `Evidence "${label}" captured in ${dir}`,
        ...files.map(f => `  ${f.name} — ${f.bytes} bytes — sha256 ${f.sha256.slice(0, 16)}…`),
        ...notes,
        `manifest: ${manifestFile} (${manifest.length} entries)`,
        `chain entry #${chained.seq} — hash ${chained.entry_hash.slice(0, 12)}… (evidence_verify checks the whole chain)`,
      ].join('\n'))
    })

  t('browser_tabs', 'List, open, select, or close tabs in the owner\'s session. Selecting a tab leased by another owner is refused.',
    {
      action: z.enum(['list', 'new', 'select', 'close']),
      index: z.number().int().optional().describe('Tab index for select/close'),
      url: z.string().optional().describe('URL for new (scope-guarded)'),
      ...OWNER_FIELD,
    },
    async ({ action, index, url, owner }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      if (action === 'list') {
        const snap = await session.snapshot()
        if (snap.tabs.length === 0) return textResult('(no tabs yet)')
        return textResult(snap.tabs.map(tab =>
          `${tab.index === indexOfSelected(session) ? '▶' : ' '} [${tab.index}] id=${tab.id} ${tab.title} — ${tab.url}${tab.leasedBy ? ` (leased by ${tab.leasedBy}${tab.purpose ? `: ${tab.purpose}` : ''})` : ''}${tab.purpose && !tab.leasedBy ? ` (purpose: ${tab.purpose})` : ''}`,
        ).join('\n'))
      }
      if (action === 'new') {
        if (url !== undefined) env.scope.assert(url, who, 'browser_tabs(new)')
        env.budget.spend(who)
        const { meta } = await session.newTab(who, url)
        const snap = await session.snapshot()
        const listed = snap.tabs.find(x => x.id === meta.id)
        // `tab:` arguments are the INDEX, not the id — the smoke run passed
        // the id and hit a confusing error, so the pass-it form is spelled out.
        return textResult(`Opened tab [${listed?.index}] id=${meta.id} — ${url ?? 'about:blank'}${meta.purpose ? ` (purpose: ${meta.purpose})` : ''}\n→ pass tab: ${listed?.index} (the INDEX — not the id) to tab-scoped tools`)
      }
      if (index === undefined) throw new Error(`action '${action}' requires an index`)
      const pages = session.pages()
      const page = pages[index]
      if (page === undefined) throw new Error(`no tab at index ${index}; call browser_tabs {action:'list'} first`)
      const meta = session.metaOf(page)!
      if (action === 'select') {
        const verdict = canTouchTab(meta, who, session.owner)
        if (!verdict.ok) throw new Error(verdict.reason ?? 'tab is leased by another owner')
        session.selected = meta.id
        return textResult(`Selected tab [${index}] id=${meta.id} — ${await pageOverview(page)}`)
      }
      const verdict = canTouchTab(meta, who, session.owner)
      if (!verdict.ok) throw new Error(verdict.reason ?? 'tab is leased by another owner')
      if (action === 'close' && meta.infoTab === true)
        throw new Error('the info tab is the ownership label and cannot be closed — close the whole window (browser_close) instead; the harness re-opens the label in any new owner window')
      await page.close()
      return textResult(`Closed tab [${index}] id=${meta.id}`)
    })

  t('tab_open', 'Open a new tab WITH a lease for the calling owner (tab leases: only you may select/act on it until tab_release).',
    { purpose: z.string().optional().describe('Why this tab exists, shown in browser_map'), url: z.string().optional(), ...OWNER_FIELD },
    async ({ purpose, url, owner }: any) => {
      if (owner === undefined || owner.trim() === '')
        throw new Error('tab_open requires an explicit owner — a lease held by "shared" protects nothing and cannot be released by you')
      const { session, owner: who } = sessionOf(env, owner)
      if (url !== undefined) env.scope.assert(url, who, 'tab_open')
      env.budget.spend(who)
      const { meta } = await session.newTab(who, url, purpose)
      meta.leasedBy = who
      meta.leasedAt = Date.now()
      const snap = await session.snapshot()
      const listed = snap.tabs.find(x => x.id === meta.id)
      return textResult(`Opened + leased tab [${listed?.index}] id=${meta.id} for "${who}"${purpose ? ` (${purpose})` : ''} — ${url ?? 'about:blank'}\n→ pass tab: ${listed?.index} (the INDEX — not the id) to tab-scoped tools`)
    })

  t('tab_lease', 'Lease an existing tab: other owners can no longer select or close it.',
    { index: z.number().int(), purpose: z.string().optional(), ...OWNER_FIELD },
    async ({ index, purpose, owner }: any) => {
      if (owner === undefined || owner.trim() === '')
        throw new Error('tab_lease requires an explicit owner — a lease held by "shared" protects nothing and cannot be released by you')
      const { session, owner: who } = sessionOf(env, owner)
      const page = session.pages()[index]
      if (page === undefined) throw new Error(`no tab at index ${index}`)
      const meta = session.metaOf(page)!
      if (meta.leasedBy !== undefined && meta.leasedBy !== who)
        throw new Error(`tab ${meta.id} is already leased by "${meta.leasedBy}"`)
      meta.leasedBy = who
      meta.leasedAt = Date.now()
      if (purpose !== undefined) meta.purpose = purpose
      return textResult(`Leased tab [${index}] id=${meta.id} for "${who}"${purpose ? ` (${purpose})` : ''}`)
    })

  t('tab_release', 'Release a lease you hold on a tab.',
    { index: z.number().int(), ...OWNER_FIELD },
    async ({ index, owner }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = session.pages()[index]
      if (page === undefined) throw new Error(`no tab at index ${index}`)
      const meta = session.metaOf(page)!
      if (meta.leasedBy === undefined) return textResult(`tab [${index}] was not leased`)
      if (meta.leasedBy !== who && who !== session.owner)
        throw new Error(`lease on tab ${meta.id} belongs to "${meta.leasedBy}" — only they (or the session owner) may release it`)
      meta.leasedBy = undefined
      meta.leasedAt = undefined
      return textResult(`Released lease on tab [${index}] id=${meta.id}`)
    })

  t('browser_frames_list', 'List every frame on the owner\'s current tab (name, URL, index). Use the name or a URL substring as the `frame:` argument on click/type/select_option when a control lives inside a cross-origin iframe.',
    { ...OWNER_FIELD, ...TAB_FIELD },
    async ({ owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      const frames = page.frames()
      return textResult(frames.map((frame, index) =>
        `[${index}]${frame === page.mainFrame() ? ' (main)' : ''} ${frame.name() === '' ? '(unnamed)' : frame.name()} — ${frame.url()}`,
      ).join('\n'))
    })

  t('browser_upload', 'Upload file(s) into DYNAMICALLY-CREATED file inputs (run-7 P1-8: Drive/Docs create their input[type=file] after the menu click, inside shadow roots). Clicks the trigger (CSS pierces open shadow roots; `deep_text` matches button text through shadow DOM + same-origin frames), intercepts the file chooser, and records the upload as an artefact row. Falls back to the first file input found by a deep DOM walk when no chooser appears.',
    {
      trigger: z.string().optional().describe('CSS selector of the button/menu item that opens the upload UI (pierces open shadow roots)'),
      deep_text: z.string().optional().describe('Button text to find through shadow DOM + frames when no selector works (e.g. "Upload file")'),
      files: z.array(z.string()).min(1).describe('Absolute file paths'),
      ...OWNER_FIELD, ...TAB_FIELD,
    },
    async ({ trigger, deep_text, files, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      for (const file of files) {
        if (!fs.existsSync(file)) throw new Error(`file not found: ${file}`)
      }
      const target = trigger !== undefined && trigger !== ''
        ? { kind: 'selector' as const, value: trigger }
        : deep_text !== undefined && deep_text !== ''
          ? { kind: 'text' as const, value: deep_text }
          : undefined
      let how: string
      if (target !== undefined) {
        how = target.kind === 'selector' ? `trigger selector "${target.value}"` : `deep text "${target.value}"`
        const locator = target.kind === 'selector'
          ? page.locator(target.value).first()
          : page.locator(`text=${JSON.stringify(target.value)}`).first()
        const [chooser] = await Promise.all([
          page.waitForEvent('filechooser', { timeout: 10_000 }).catch(() => undefined),
          (async () => {
            try { await locator.click({ timeout: 8_000 }) } catch { /* deep fallback below */ } })(),
        ])
        if (chooser !== undefined) {
          await chooser.setFiles(files)
          await page.waitForTimeout(500)
          return textResult(await uploadRecord(session, how, files))
        }
      }
      // No chooser fired (or no trigger given): find an input[type=file] by
      // walking shadow roots + same-origin frames directly in the DOM.
      const handle = await page.evaluateHandle(() => {
        const walk = (root: { querySelectorAll(selector: string): any[] }): any => {
          for (const el of root.querySelectorAll('input[type="file"]')) return el
          for (const el of root.querySelectorAll('*')) {
            const shadow: { querySelectorAll(selector: string): any[] } | null | undefined = el.shadowRoot
            if (shadow != null) {
              const found = walk(shadow)
              if (found !== null) return found
            }
          }
          return null
        }
        const docs: Array<{ querySelectorAll(selector: string): any[] }> = [document]
        for (const frame of document.querySelectorAll('iframe')) {
          const inner: { querySelectorAll(selector: string): any[] } | null = frame.contentDocument
          if (inner !== null) docs.push(inner)
        }
        for (const doc of docs) {
          const found = walk(doc)
          if (found !== null) return found
        }
        return null
      })
      const input = handle.asElement()
      if (input === null) {
        handle.dispose()
        throw new Error('no file chooser opened and no input[type=file] found (even through shadow roots and frames) — snapshot the page and check the trigger')
      }
      how = 'direct deep input[type=file]'
      await input.setInputFiles(files)
      await handle.dispose()
      await page.waitForTimeout(500)
      return textResult(await uploadRecord(session, how, files))
    })

  t('browser_set_files', 'Upload file(s). Direct mode: set them on the matched <input type=file>. File-chooser mode (click_selector): click the button that opens the OS chooser and intercept it — the reliable path for hidden inputs (input[type=file].sr-only), where setInputFiles on the hidden input fired zero requests in the live run. For inputs created AFTER the menu click or buried in shadow roots, prefer browser_upload.',
    {
      files: z.array(z.string()).min(1).describe('Absolute file paths'),
      selector: z.string().optional().describe('Selector of the file input (direct mode)'),
      element: z.string().optional(), name: z.string().optional(), nth: z.number().int().optional(),
      click_selector: z.string().optional().describe('Selector of the button that opens the file chooser (file-chooser mode)'),
      ...OWNER_FIELD, ...TAB_FIELD,
    },
    async ({ files, selector, element, name, nth, click_selector, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      for (const file of files) {
        if (!fs.existsSync(file)) throw new Error(`file not found: ${file}`)
      }
      if (click_selector !== undefined && click_selector !== '') {
        const [chooser] = await Promise.all([
          page.waitForEvent('filechooser', { timeout: 10_000 }),
          page.locator(click_selector).first().click({ timeout: 10_000 }),
        ])
        await chooser.setFiles(files)
        await page.waitForTimeout(500)
        return textResult(`Set ${files.length} file(s) via the file chooser.\nNow at: ${await pageOverview(page)}`)
      }
      await locatorFor(page, selector, element, name, nth).first().setInputFiles(files, { timeout: 10_000 })
      await page.waitForTimeout(500)
      return textResult(`Set ${files.length} file(s) on the input.\nNow at: ${await pageOverview(page)}`)
    })

  t('browser_owner_info', 'Set the job/engagement label shown on an owner\'s window: the first tab of every owner window is an ownership info tab ("[owner] — job — engagement") that agents cannot close and the harness re-opens if the human closes it. Set this right after spawn so every Chrome window answers "whose is this and what is it doing".',
    {
      owner: z.string().describe('Owner/teammate name whose window gets the label'),
      job: z.string().optional().describe('One-line job, e.g. "klaviyo lane: signup + MCP surfaces"'),
      engagement: z.string().optional().describe('Engagement/program name'),
    },
    async ({ owner, job, engagement }: any) => {
      if (owner === undefined || owner.trim() === '' || owner.trim() === SHARED_OWNER)
        throw new Error('browser_owner_info labels a specific owner window — pass the teammate name (the shared human session gets no label)')
      const { session, owner: who } = sessionOf(env, owner)
      const info = await session.setOwnerInfo(job, engagement)
      return textResult(`[${who}] label set — job: ${info.job ?? '(unset)'} · engagement: ${info.engagement ?? '(unset)'}${session.context === undefined ? ' (window not launched yet; the label renders at launch)' : ' (info tab updated)'}`)
    })

  // ── Cookie handoff (DST-Comet P0, live run 2026-10-27) ────────────────────
  // "Human logs in, agent works" needed cookies transcribed through model
  // context (one cookies() call dumped 150+ unrelated cookies into the
  // transcript). Values now stay server-side behind a short-lived handoff id;
  // the transcript only ever sees the redacted preview.
  const cookieHandoffs = new Map<string, { id: string; fromOwner: string; domain: string; expiresAt: number; cookies: Array<Record<string, unknown>> }>()
  const HANDOFF_TTL_MS = 10 * 60_000
  const sweepHandoffs = (): void => {
    const now = Date.now()
    for (const [id, handoff] of cookieHandoffs) if (handoff.expiresAt < now) cookieHandoffs.delete(id)
  }
  const cookiePreview = (cookies: Array<Record<string, unknown>>): string =>
    cookies.map(c => `  ${c.name} — ${c.domain}${c.path} ${c.httpOnly === true ? 'httpOnly ' : ''}${c.secure === true ? 'secure ' : ''}${String(c.sameSite ?? '')}${typeof c.expires === 'number' && c.expires > 0 ? ` expires ${new Date(c.expires * 1000).toISOString()}` : ' session'}`).join('\n')

  t('browser_cookies_export', 'Export cookies from one owner\'s browser into a server-side handoff (values NEVER enter the transcript — the preview shows name/domain/flags only). Gives a handoff_id for browser_cookies_import. `domains` accepts a LIST and includes host-only cookies from subdomains in BOTH directions (run-7: domain "google.com" silently omitted accounts.google.com LSID/__Host-GAPS/OSID and the target browser stayed signed out). The captcha-walled-login recipe: human logs in in their own Chrome (or the shared session) → export → import into the worker\'s owner browser.',
    {
      owner: z.string().describe('Owner whose cookies are exported'),
      domains: z.array(z.string()).min(1).optional().describe('Only cookies for these domains (hostname or host:port); subdomains both ways, host-only included'),
      domain: z.string().optional().describe('Deprecated single-domain form — prefer domains: [...]'),
      names: z.array(z.string()).optional().describe('Only these cookie names'),
    },
    async ({ owner, domains, domain, names }: any) => {
      sweepHandoffs()
      const { session, owner: who } = sessionOf(env, owner)
      const context = await session.ensure()
      const wantedDomains = domains !== undefined && domains.length > 0 ? domains : domain !== undefined ? [domain] : undefined
      // Fetch the WHOLE jar and filter in code: Playwright's context.cookies(urls)
      // filter drops host-only cookies of subdomains — the exact run-7 gap.
      const all = (await context.cookies()) as unknown as Array<Record<string, unknown>>
      let cookies = wantedDomains === undefined
        ? all
        : all.filter(c => cookieMatchesAnyDomain(String(c.domain), wantedDomains))
      if (names !== undefined && names.length > 0) cookies = cookies.filter(c => names.includes(String(c.name)))
      if (cookies.length === 0) {
        return textResult(`no cookies matched${wantedDomains !== undefined ? ` domains [${wantedDomains.join(', ')}]` : ''}${names !== undefined ? ` names [${names.join(', ')}]` : ''}. Cookie names present in this browser (values not shown): ${all.map(c => c.name).join(', ') || '(none)'}`, true)
      }
      const warned = session.userDir !== undefined && session.userDir.startsWith('(attached)')
        ? []
        : dbscWarningForProfile(session.userDir)
      const id = `ch-${randomBytes(4).toString('hex')}`
      cookieHandoffs.set(id, { id, fromOwner: who, domain: wantedDomains?.join(',') ?? '(all)', expiresAt: Date.now() + HANDOFF_TTL_MS, cookies })
      return textResult([
        `handoff_id: ${id} — ${cookies.length} cookie(s) from "${who}", domains ${wantedDomains?.join(', ') ?? '(all)'}`,
        `values are held server-side for ${Math.round(HANDOFF_TTL_MS / 60_000)} minutes; import with browser_cookies_import({ owner, handoff_id: "${id}" })`,
        ...warned,
        'preview (no values):',
        cookiePreview(cookies),
      ].join('\n'))
    })

  t('browser_cookies_import', 'Import cookies into an owner\'s browser. Two sources: `handoff_id` from browser_cookies_export, or `profile_dir` to read an EXTERNAL Chrome/Edge profile directly (run-7 P0-1: DPAPI-decrypted v10/v11, values stay server-side; v20 app-bound rows and Device-Bound-Session profiles are reported, not silently broken). Scope-guarded: every imported domain must be in the importer\'s scope; the audit records the host list only.',
    {
      owner: z.string().describe('Owner whose browser receives the cookies'),
      handoff_id: z.string().optional().describe('Handoff id from browser_cookies_export'),
      profile_dir: z.string().optional().describe('Absolute path to an external Chrome/Edge user-data-dir or profile directory (reads its Cookies store)'),
      domain_filter: z.array(z.string()).min(1).optional().describe('Only import cookies for these domains (both-direction subdomain match, host-only included)'),
      domain_override: z.string().optional().describe('Rewrite the cookies onto a different host (e.g. staging)'),
    },
    async ({ owner, handoff_id, profile_dir, domain_filter, domain_override }: any) => {
      sweepHandoffs()
      const { session, owner: who } = sessionOf(env, owner)
      let cookies: Array<Record<string, unknown>>
      let targetLabel: string
      let extraLines: string[] = []
      if (profile_dir !== undefined && profile_dir !== '') {
        const report = await readProfileCookies(profile_dir, domain_filter)
        cookies = report.cookies as unknown as Array<Record<string, unknown>>
        targetLabel = report.hosts.join(', ')
        extraLines = report.warnings
        if (report.hosts.length > 0) {
          // The audited host list — values never appear in audit or transcript.
          env.scope.audit(`cookie-import:${targetLabel}`, who, 'browser_cookies_import', {
            allowed: true,
            reason: `external profile "${profile_dir}": ${cookies.length} cookie(s) across ${report.hosts.length} host(s)`,
          })
          for (const host of report.hosts) {
            env.scope.assert(/^https?:\/\//i.test(host) ? `https://${host}/` : `https://${host}/`, who, 'browser_cookies_import')
          }
        }
      } else {
        if (handoff_id === undefined) throw new Error('pass either handoff_id (from browser_cookies_export) or profile_dir (an external Chrome/Edge profile)')
        const handoff = cookieHandoffs.get(handoff_id)
        if (handoff === undefined) throw new Error(`unknown or expired handoff_id "${handoff_id}" (handoffs live ${Math.round(HANDOFF_TTL_MS / 60_000)} minutes)`)
        cookies = handoff.cookies
        targetLabel = handoff.domain
        if (targetLabel !== '(all)') {
          for (const part of targetLabel.split(',')) {
            env.scope.assert(/^https?:\/\//i.test(part) ? part : `https://${part}/`, who, 'browser_cookies_import')
          }
        }
      }
      if (domain_override === undefined && targetLabel !== '(all)') {
        // The assert above already ran for every imported host; nothing more.
      }
      const context = await session.ensure()
      const finalCookies = cookies.map(cookie => ({ ...cookie, ...(domain_override === undefined ? {} : { domain: domain_override }) }))
      if (finalCookies.length === 0) {
        return textResult([...(extraLines.length > 0 ? extraLines : []), 'no importable cookies matched — see the warnings above (app-bound v20 rows cannot be imported out-of-process; use browser_attach for that identity)'].join('\n'), true)
      }
      await context.addCookies(finalCookies as never)
      return textResult([
        `Imported ${finalCookies.length} cookie(s) into "${who}"'s browser.`,
        ...extraLines,
        'preview (no values):',
        cookiePreview(finalCookies),
      ].join('\n'))
    })

  t('browser_cookies_list', 'Redacted cookie preview for one owner\'s browser — reason about which sessions are alive without ever seeing values.',
    { owner: z.string().describe('Owner whose cookies are listed'), domain: z.string().optional() },
    async ({ owner, domain }: any) => {
      const { session } = sessionOf(env, owner)
      const context = await session.ensure()
      const urls = domain === undefined ? undefined : [/^https?:\/\//i.test(domain) ? domain : `https://${domain}/`]
      const cookies = (await context.cookies(urls)) as unknown as Array<Record<string, unknown>>
      if (cookies.length === 0) return textResult('(no cookies match — the owner has no session for this domain)')
      return textResult(cookiePreview(cookies))
    })

  t('browser_focus_window', 'Bring one owner\'s Chrome window to the foreground. Resolves the EXACT window: the browser process is found by its unique --user-data-dir on the command line (the owner\'s profile), so no title guessing is involved — a title search matched an unrelated YouTube window in the live run. Windows only.',
    { owner: z.string().describe('Owner whose window to focus') },
    async ({ owner }: any) => {
      const { spawn } = await import('node:child_process')
      const { session, owner: who } = sessionOf(env, owner)
      if (session.owner === SHARED_OWNER) throw new Error('browser_focus_window focuses a labeled owner window — pass the teammate name')
      await session.ensure()
      // Only the single quotes need escaping (PS single-quoted string). The
      // backslashes stay RAW: in a -like pattern a doubled `\\` matches a
      // literal double backslash and finds nothing — proven against a live
      // chrome.exe command line (raw path: 8 matches, doubled: 0).
      const userDirLike = session.userDir.replace(/'/g, "''")
      // Every chrome.exe child carries --user-data-dir, and only ~1 of the
      // ~11 processes owns the window — take First and it is almost always a
      // windowless child. Walk the matching PIDs and pick the one with a
      // MainWindowHandle.
      const script =
        `$procs = Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" ` +
        `| Where-Object { $_.CommandLine -like '*${userDirLike}*' }; ` +
        `$target = $null; ` +
        `foreach ($proc in $procs) { ` +
        `$alive = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue; ` +
        `if ($alive -and $alive.MainWindowHandle -ne 0) { $target = $alive; break } }; ` +
        `if (-not $target) { if (-not $procs) { exit 2 } else { exit 3 } }; ` +
        `(New-Object -ComObject WScript.Shell).AppActivate($target.Id) | Out-Null; ` +
        `Write-Output $target.MainWindowTitle`
      const result = await new Promise<{ code: number | null; stdout: string }>(resolve => {
        const child = spawn('powershell.exe', ['-NoProfile', '-Command', script], { windowsHide: true })
        let stdout = ''
        child.stdout.on('data', chunk => { stdout += String(chunk) })
        child.on('close', code => resolve({ code, stdout: stdout.trim() }))
        child.on('error', () => resolve({ code: 1, stdout: '' }))
      })
      if (result.code === 0 && result.stdout !== '') return textResult(`Focused "${who}"'s window: ${result.stdout.split('\n')[0]}`)
      if (result.code === 2) return textResult(`no chrome.exe process carries "${who}"'s profile — the window may have been closed`, true)
      return textResult(`could not bring "${who}"'s window to the foreground (exit ${result.code}) — it may be minimized to the tray`, true)
    })

  t('browser_map', 'Ownership map: browser sessions, window labels, tabs, leases, retained (closed) profiles on disk, plus scope status. Default shows EVERY owner (the Lead\'s view); pass `owner` to see only your own session + the shared one (teammates should — the global view exposes other lanes\' URLs).',
    { owner: z.string().optional().describe('Your owner name: scopes the map to your session + shared') },
    async ({ owner }: any) => {
      const who = owner === undefined ? undefined : resolveOwner(owner)
      const all = await env.registry.snapshot()
      const snaps = who === undefined ? all : all.filter(snap => snap.owner === who || snap.owner === SHARED_OWNER)
      const scopeRule = env.scope.current(who)
      const perOwners = env.scope.owners()
      const lines = snaps.length === 0 ? ['(no live sessions — retained profiles below, if any)'] : snaps.map(snap => {
        const head = snap.owner === SHARED_OWNER
          ? `shared (human session, no label prefix) — profile: ${snap.userDir}`
          : `${snap.owner} — own window, titles prefixed "[${snap.owner}]" — profile: ${snap.userDir}`
        const tabs = snap.tabs.map(tab => {
          const marks = [snap.selected === tab.id ? '▶' : ' ', tab.infoTab === true ? 'ℹ' : '', tab.leasedBy ? `leased:${tab.leasedBy}${tab.purpose ? `(${tab.purpose})` : ''}` : '', tab.openedBy !== SHARED_OWNER && tab.openedBy !== snap.owner ? `openedBy:${tab.openedBy}` : ''].filter(Boolean).join(' ')
          return `   ${marks} [${tab.index}] ${tab.title} — ${tab.url}`
        })
        return [head, ...(tabs.length === 0 ? ['   (no tabs)'] : tabs)].join('\n')
      })
      // Retained profiles (run-4 advice §8h): after a restart browser_map said
      // "no sessions launched yet" while owner labels and profiles persisted
      // on disk — the Lead could not see what exists for cleanup. A profile
      // dir with no live session reads as one "(closed)" line with its label
      // and the directory's last-modified time as a last-use approximation.
      // Run-7 P2-13: the line also reads PROCESS state — a "(closed)" profile
      // whose chrome.exe still runs (restart, crashed server) says so instead
      // of silently disagreeing with reality.
      const live = new Set(snaps.map(snap => snap.owner))
      const runningDirs = await env.registry.runningProfileDirs()
      const isProfileRunning = (dir: string): boolean =>
        runningDirs.has(dir.toLowerCase()) || [...runningDirs].some(r => dir.toLowerCase().endsWith(r) || r.endsWith(dir.toLowerCase()))
      const labels = loadOwnerLabels(env.config.rootDir)
      const retained: string[] = []
      try {
        for (const entry of fs.readdirSync(env.config.profilesRoot, { withFileTypes: true })) {
          if (!entry.isDirectory()) continue
          // A stray non-owner directory must not sink the whole map.
          if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(entry.name)) continue
          const profileOwner = entry.name
          if (live.has(profileOwner) || (who !== undefined && profileOwner !== who && profileOwner !== SHARED_OWNER)) continue
          const stat = fs.statSync(path.join(env.config.profilesRoot, entry.name))
          const label = labels[profileOwner]
          const described = label === undefined ? '' : ` — ${[label.job, label.engagement].filter(Boolean).join(' · ')}`
          const dir = path.join(env.config.profilesRoot, entry.name)
          const state = isProfileRunning(dir)
            ? 'chrome.exe ALIVE with this profile (close it via owner re-open + browser_close, or browser_attach to adopt it)'
            : 'closed'
          retained.push(`(${state}) ${profileOwner}${described} — last write ${stat.mtime.toISOString().slice(0, 16).replace('T', ' ')}Z`)
        }
      } catch { /* profiles dir absent = no retained profiles */ }
      if (retained.length > 0) lines.push(...retained)
      // Run-8 §5: surface attach/launch traffic violations right on the map.
      for (const snap of snaps) {
        const session = env.registry.sessionFor(snap.owner)
        if (session.scopeViolations.length > 0) {
          lines.push(`⚠ ${snap.owner}: ${session.scopeViolations.length} out-of-scope request(s) observed — browser_scope_violations {owner:"${snap.owner}"}`)
        }
      }
      const scopeLine = scopeRule === null
        ? `scope: UNRESTRICTED (call scope_set before engaging a target)${perOwners.length > 0 ? `; per-owner rules: ${perOwners.join(', ')}` : ''}`
        : `scope${who === undefined ? '' : ` (${who})`}: ${scopeRule.engagement ?? '(unnamed)'} — in: ${scopeRule.in_scope.join(', ') || '∅'} — out: ${scopeRule.out_scope.join(', ') || '∅'}${perOwners.length > 0 ? `; per-owner rules: ${perOwners.join(', ')}` : ''}`
      return textResult([...lines, '', scopeLine].join('\n'))
    })

  t('browser_attach', 'Adopt a browser the human is already driving as this owner\'s session, over CDP (run-7 P0-2). THE route for Device-Bound-Session identities (Google, banking, cloud consoles): the session stays bound to the human\'s browser instance, so nothing is replayed and nothing expires. Launch the target Chrome with --remote-debugging-port=PORT --user-data-dir=<dir>, then attach. Same scope guard, tab leases and audit as a launched owner; browser_close only DISCONNECTS — the human\'s browser is never closed by the harness.',
    {
      owner: z.string().describe('Owner name the attached browser is adopted as'),
      cdp_url: z.string().describe('CDP endpoint, e.g. http://127.0.0.1:9222'),
    },
    async ({ owner, cdp_url }: any) => {
      const who = resolveOwner(owner)
      if (who === SHARED_OWNER) throw new Error('browser_attach needs a named owner — the shared session is a launched profile')
      if (!/^https?:\/\/127\.0\.0\.1:|^https?:\/\/localhost:/i.test(cdp_url))
        throw new Error('cdp_url must be a loopback endpoint (http://127.0.0.1:PORT or http://localhost:PORT)')
      env.scope.audit(cdp_url, who, 'browser_attach', {
        allowed: true,
        reason: `adopting a running browser over CDP as owner "${who}"`,
      })
      const session = env.registry.attachFor(who, cdp_url)
      const context = await session.ensure()
      // Run-8 §5: the scope guard follows the ATTACHED browser — every request
      // is checked against the owner's scope and violations are audited, so
      // moving to CDP attach no longer means leaving the audit behind.
      session.networkObserver = (method, url) => {
        const decision = env.scope.check(url, who)
        if (!decision.allowed && !url.startsWith('chrome://') && !url.startsWith('devtools://')) {
          session.scopeViolations.push({ ts: new Date().toISOString(), method, url, reason: decision.reason })
          if (session.scopeViolations.length > 100) session.scopeViolations.shift()
          env.scope.audit(url, who, 'attached-traffic', decision)
        }
      }
      const pages = context.pages()
      return textResult([
        `Attached "${who}" to ${cdp_url} — ${pages.length} tab(s) adopted; the existing tabs are theirs to drive (browser_tabs {action:'list', owner:"${who}"}).`,
        'closing this session (browser_close/browser_reset) only DISCONNECTS; the human\'s browser keeps running.',
        ...(await session.snapshot()).tabs.map(tab => `  [${tab.index}] ${tab.title} — ${tab.url}`),
      ].join('\n'))
    })

  t('browser_launch', 'Launch this owner\'s browser on an EXPLICIT user-data-dir with extra Chrome args and NO automation flag (a normal-looking window — run-7 P0-2). Sign the human in there once, then browser_cookies_export works from it, or re-launch + attach for DBSC-bound identities.',
    {
      owner: z.string().describe('Owner name for the launched browser'),
      user_data_dir: z.string().describe('Absolute user-data-dir (created if missing)'),
      extra_args: z.array(z.string()).optional().describe('Extra Chrome args (e.g. ["--profile-directory=Profile 1"])'),
    },
    async ({ owner, user_data_dir, extra_args }: any) => {
      const who = resolveOwner(owner)
      if (who === SHARED_OWNER) throw new Error('browser_launch needs a named owner — the shared session uses its own configured profile')
      if (!path.isAbsolute(user_data_dir)) throw new Error('user_data_dir must be an absolute path')
      env.scope.audit(`launch:${user_data_dir}`, who, 'browser_launch', {
        allowed: true,
        reason: `persistent launch on explicit user-data-dir${extra_args !== undefined ? ` with ${extra_args.length} extra arg(s)` : ''}`,
      })
      const session = env.registry.launchFor(who, user_data_dir, extra_args)
      await session.ensure()
      return textResult(`Launched "${who}" on ${user_data_dir} (automation flag suppressed${extra_args !== undefined && extra_args.length > 0 ? `, args: ${extra_args.join(' ')}` : ''}). The window looks like a normal Chrome.`)
    })

  t('browser_scope_violations', 'Out-of-scope requests OBSERVED from an owner\'s browser (launched or CDP-attached; run-8 §5): the attach-mode audit keeps the scope guard a property of what goes out. Violations were already audited — this lists them so a lane can stop and re-scope.',
    { ...OWNER_FIELD },
    async ({ owner }: any) => {
      const { session } = sessionOf(env, owner)
      const rows = session.scopeViolations
      if (rows.length === 0) return textResult(`No out-of-scope requests observed from "${session.owner}".`)
      return textResult([
        `${rows.length} out-of-scope request(s) from "${session.owner}" (audited; STOP the lane and fix the scope):`,
        ...rows.slice(-20).map(row => `  ${row.ts} ${row.method} ${row.url.slice(0, 160)} — ${row.reason}`),
      ].join('\n'), true)
    })

  t('browser_reset', 'Close ONE owner\'s browser session — by default ONLY the caller named in `owner` (run-7 P1-6: a lane\'s end-of-run reset used to close every owner window mid-block). Closing other owners\' sessions requires `all: true` and is refused while those owners hold tab leases; `keep` names owners to spare (default ["shared"]).',
    {
      ...OWNER_FIELD,
      all: z.boolean().optional().describe('Close every owner session except keep (refused while others hold tab leases)'),
      keep: z.array(z.string()).optional().describe(`Owner names to keep when all=true; default ["${SHARED_OWNER}"]`),
    },
    async ({ owner, all, keep }: any) => {
      if (all === true) {
        const { closed, refused } = await env.registry.resetAll(keep ?? [SHARED_OWNER])
        const refusedLines = refused.map(row =>
          `REFUSED "${row.owner}": tabs leased (${row.leases.map(l => `#${l.tabId} by ${l.leasedBy}${l.purpose ? ` (${l.purpose})` : ''}`).join(', ')}) — resolve the leases first (tab_release) or have those owners close their own sessions`)
        return textResult([
          ...(closed.length === 0 ? ['Nothing to close.'] : [`Closed sessions: ${closed.join(', ')}`]),
          ...refusedLines,
        ].join('\n'), refusedLines.length > 0)
      }
      if (owner === undefined || owner.trim() === '')
        return textResult(`browser_reset closes only ONE session now — pass owner: "<your-name>" to close your own (or all: true, keep: [...] to close every lane's session). Nothing was closed.`, true)
      const who = resolveOwner(owner)
      const closed = await env.registry.close(who)
      return textResult(closed ? `Closed session for "${who}" (profile preserved; attached sessions only DISCONNECT — the human's browser stays open).` : `No running session for "${who}".`)
    })

  t('browser_close', 'Close one owner\'s browser session (profile on disk is preserved for next time).',
    { ...OWNER_FIELD },
    async ({ owner }: any) => {
      const who = resolveOwner(owner)
      const closed = await env.registry.close(who)
      return textResult(closed ? `Closed session for "${who}" (profile preserved).` : `No running session for "${who}".`)
    })

  t('browser_force_action', 'Escape hatch for pages that ignore automation input: dispatch trusted CDP input events (mouse click at x/y, key, or typed text).',
    {
      action: z.enum(['click', 'dblclick', 'key', 'type']),
      x: z.number().optional(), y: z.number().optional(),
      key: z.string().optional().describe('Key name for action=key (e.g. Enter, ArrowDown)'),
      text: z.string().optional().describe('Text for action=type'),
      delay_ms: z.number().int().optional().describe('Delay between keyDown/keyUp'),
      ...OWNER_FIELD, ...TAB_FIELD,
    },
    async ({ action, x, y, key, text, delay_ms, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      const cdp = await page.context().newCDPSession(page)
      try {
        if (action === 'click' || action === 'dblclick') {
          if (x === undefined || y === undefined) throw new Error('action click/dblclick requires x and y viewport coordinates')
          const clickCount = action === 'dblclick' ? 2 : 1
          for (const type of ['mouseMoved', 'mousePressed', 'mouseReleased'] as const)
            await cdp.send('Input.dispatchMouseEvent', { type, x, y, button: 'left', clickCount: type === 'mouseMoved' ? 0 : clickCount })
        } else if (action === 'key') {
          if (key === undefined) throw new Error('action key requires key')
          for (const type of ['keyDown', 'keyUp'] as const)
            await cdp.send('Input.dispatchKeyEvent', { type, key, ...(delay_ms === undefined ? {} : { delay: delay_ms }) })
        } else {
          if (text === undefined) throw new Error('action type requires text')
          await cdp.send('Input.insertText', { text })
        }
      } finally {
        await cdp.detach().catch(() => {})
      }
      return textResult(`Dispatched ${action} via CDP.\nNow at: ${await pageOverview(page)}\n\n${truncate(await snapshotOf(page), 40_000)}`)
    })

  t('browser_run_code_unsafe', 'UNSAFE escape hatch: run `async (page, require) => {...}` server-side with the full Playwright Page API on the owner\'s current tab, plus Node `require` (fs, path, …) for saving artifacts. NOT scope-guarded inside — only use it when the guarded tools cannot express the step (bulk sweeps, waitUntil networkidle, complex flows).',
    { code: z.string().describe('Function expression, e.g. `async (page, require) => { await page.goto(url); return page.title() }`'), ...OWNER_FIELD, ...TAB_FIELD },
    async ({ code, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      const fn = makeUserFn(code)
      const nodeRequire = createRequire(import.meta.url)
      const result = await fn(page, nodeRequire)
      const rendered = result === undefined ? 'undefined' : JSON.stringify(result, null, 2) ?? String(result)
      return textResult(truncate(rendered, 50_000))
    })

  t('browser_wait_for', 'Wait for text to appear or for a time to pass on the owner\'s current tab.',
    { text: z.string().optional(), time_ms: z.number().int().optional().describe('Max wait in ms (either text or time_ms required)'), ...OWNER_FIELD, ...TAB_FIELD },
    async ({ text, time_ms, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      if (text === undefined && time_ms === undefined) throw new Error('provide text or time_ms')
      const started = Date.now()
      try {
        if (text !== undefined) {
          await page.waitForSelector(`text=${JSON.stringify(text)}`, { timeout: time_ms ?? 30_000 })
        } else {
          await page.waitForTimeout(time_ms ?? 0)
        }
      } catch {
        return textResult(`Timeout after ${Date.now() - started}ms waiting for ${text ?? 'timer'}.`, true)
      }
      return textResult(`Done after ${Date.now() - started}ms.\n\n${truncate(await snapshotOf(page), 60_000)}`)
    })
}

function indexOfSelected(session: BrowserSession): number {
  if (session.selected === null) return -1
  return session.pages().findIndex(p => session.metaOf(p)?.id === session.selected)
}

export interface ToolRegistrar {
  registerTool(name: string, info: { title: string; description: string }, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>): void
}
