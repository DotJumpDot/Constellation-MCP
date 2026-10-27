import { createRequire } from 'node:module'
import fs from 'node:fs'
import path from 'node:path'
import { randomBytes } from 'node:crypto'
import { z } from 'zod'
import type { Frame, Page } from 'playwright-core'
import type { ConstellationConfig } from '../config.js'
import { ScopeGuard } from '../scope.js'
import { SHARED_OWNER, canTouchTab, type BrowserSession } from './session.js'
import type { OwnerRegistry } from './registry.js'

export interface ToolEnv {
  config: ConstellationConfig
  registry: OwnerRegistry
  scope: ScopeGuard
}

export type ToolResult = { content: Array<{ type: 'text'; text: string }>; isError?: boolean }

export function textResult(text: string, isError = false): ToolResult {
  return { content: [{ type: 'text', text }], ...(isError ? { isError: true } : {}) }
}

export function errorResult(error: unknown): ToolResult {
  const message = error instanceof Error ? error.message : String(error)
  return textResult(`Error: ${message}`, true)
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

async function pageOverview(page: Page): Promise<string> {
  const [title] = await Promise.all([page.title().catch(() => '')])
  return `${page.url()}${title === '' ? '' : ` — ${title}`}`
}

async function snapshotOf(page: Page): Promise<string> {
  try {
    return await page.locator('html').ariaSnapshot()
  } catch (error) {
    return `[aria snapshot unavailable: ${error instanceof Error ? error.message : String(error)}]\nURL: ${page.url()}`
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
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45_000 })
      return textResult(await afterActionResult(page))
    })

  t('browser_snapshot', 'Accessibility snapshot (YAML) of the owner\'s current tab.',
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
        const { meta } = await session.newTab(who, url)
        const snap = await session.snapshot()
        const listed = snap.tabs.find(x => x.id === meta.id)
        return textResult(`Opened tab [${listed?.index}] id=${meta.id} — ${url ?? 'about:blank'}${meta.purpose ? ` (purpose: ${meta.purpose})` : ''}`)
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
      const { meta } = await session.newTab(who, url, purpose)
      meta.leasedBy = who
      meta.leasedAt = Date.now()
      const snap = await session.snapshot()
      const listed = snap.tabs.find(x => x.id === meta.id)
      return textResult(`Opened + leased tab [${listed?.index}] id=${meta.id} for "${who}"${purpose ? ` (${purpose})` : ''} — ${url ?? 'about:blank'}`)
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

  t('browser_set_files', 'Upload file(s). Direct mode: set them on the matched <input type=file>. File-chooser mode (click_selector): click the button that opens the OS chooser and intercept it — the reliable path for hidden inputs (input[type=file].sr-only), where setInputFiles on the hidden input fired zero requests in the live run.',
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

  t('browser_cookies_export', 'Export cookies from one owner\'s browser into a server-side handoff (values NEVER enter the transcript — the preview shows name/domain/flags only). Gives a handoff_id for browser_cookies_import. The captcha-walled-login recipe: human logs in in their own Chrome (or the shared session) → export → import into the worker\'s owner browser.',
    {
      owner: z.string().describe('Owner whose cookies are exported'),
      domain: z.string().optional().describe('Only cookies for this domain (hostname or host:port)'),
      names: z.array(z.string()).optional().describe('Only these cookie names'),
    },
    async ({ owner, domain, names }: any) => {
      sweepHandoffs()
      const { session, owner: who } = sessionOf(env, owner)
      const context = await session.ensure()
      const urls = domain === undefined ? undefined : [/^https?:\/\//i.test(domain) ? domain : `https://${domain}/`]
      let cookies = (await context.cookies(urls)) as unknown as Array<Record<string, unknown>>
      if (names !== undefined && names.length > 0) cookies = cookies.filter(c => names.includes(String(c.name)))
      if (domain !== undefined) {
        const host = domain.replace(/^https?:\/\//i, '').split('/')[0]!
        cookies = cookies.filter(c => String(c.domain).endsWith(host) || host.endsWith(String(c.domain).replace(/^\./, '')))
      }
      if (cookies.length === 0) {
        const all = (await context.cookies()) as unknown as Array<Record<string, unknown>>
        return textResult(`no cookies matched${domain !== undefined ? ` domain "${domain}"` : ''}${names !== undefined ? ` names [${names.join(', ')}]` : ''}. Cookie names present in this browser (values not shown): ${all.map(c => c.name).join(', ') || '(none)'}`, true)
      }
      const id = `ch-${randomBytes(4).toString('hex')}`
      cookieHandoffs.set(id, { id, fromOwner: who, domain: domain ?? '(all)', expiresAt: Date.now() + HANDOFF_TTL_MS, cookies })
      return textResult([
        `handoff_id: ${id} — ${cookies.length} cookie(s) from "${who}", domain ${domain ?? '(all)'}`,
        `values are held server-side for ${Math.round(HANDOFF_TTL_MS / 60_000)} minutes; import with browser_cookies_import({ owner, handoff_id: "${id}" })`,
        'preview (no values):',
        cookiePreview(cookies),
      ].join('\n'))
    })

  t('browser_cookies_import', 'Import a cookie handoff into an owner\'s browser (the worker side of the human-login recipe). Scope-guarded: the handoff\'s domain must be in the importer\'s scope; every import is audited.',
    {
      owner: z.string().describe('Owner whose browser receives the cookies'),
      handoff_id: z.string().describe('Handoff id from browser_cookies_export'),
      domain_override: z.string().optional().describe('Rewrite the cookies onto a different host (e.g. staging)'),
    },
    async ({ owner, handoff_id, domain_override }: any) => {
      sweepHandoffs()
      const { session, owner: who } = sessionOf(env, owner)
      const handoff = cookieHandoffs.get(handoff_id)
      if (handoff === undefined) throw new Error(`unknown or expired handoff_id "${handoff_id}" (handoffs live ${Math.round(HANDOFF_TTL_MS / 60_000)} minutes)`)
      const targetDomain = domain_override ?? handoff.domain
      if (targetDomain !== '(all)') {
        env.scope.assert(/^https?:\/\//i.test(targetDomain) ? targetDomain : `https://${targetDomain}/`, who, 'browser_cookies_import')
      }
      const context = await session.ensure()
      const cookies = handoff.cookies.map(cookie => ({ ...cookie, ...(domain_override === undefined ? {} : { domain: domain_override }) }))
      await context.addCookies(cookies as never)
      env.scope.audit(`cookie-import:${targetDomain}`, who, 'browser_cookies_import', {
        allowed: true,
        reason: `handoff ${handoff.id}: ${cookies.length} cookie(s) from "${handoff.fromOwner}" onto ${targetDomain}`,
      })
      return textResult(`Imported ${cookies.length} cookie(s) from "${handoff.fromOwner}" onto ${targetDomain} in "${who}"'s browser.\nPreview (no values):\n${cookiePreview(cookies)}`)
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
      const userDirLike = session.userDir.replace(/'/g, "''").replace(/\\/g, '\\\\')
      const script =
        `$proc = Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" ` +
        `| Where-Object { $_.CommandLine -like '*${userDirLike}*' } | Select-Object -First 1; ` +
        `if (-not $proc) { exit 2 }; ` +
        `$alive = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue; ` +
        `if (-not $alive -or $alive.MainWindowHandle -eq 0) { exit 3 }; ` +
        `(New-Object -ComObject WScript.Shell).AppActivate($proc.ProcessId) | Out-Null; ` +
        `Write-Output $alive.MainWindowTitle`
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

  t('browser_map', 'Ownership map: browser sessions, window labels, tabs, leases, plus scope status. Default shows EVERY owner (the Lead\'s view); pass `owner` to see only your own session + the shared one (teammates should — the global view exposes other lanes\' URLs).',
    { owner: z.string().optional().describe('Your owner name: scopes the map to your session + shared') },
    async ({ owner }: any) => {
      const who = owner === undefined ? undefined : resolveOwner(owner)
      const all = await env.registry.snapshot()
      const snaps = who === undefined ? all : all.filter(snap => snap.owner === who || snap.owner === SHARED_OWNER)
      const scopeRule = env.scope.current(who)
      const perOwners = env.scope.owners()
      const lines = snaps.length === 0 ? ['(no sessions launched yet — sessions appear when an owner first uses a browser tool)'] : snaps.map(snap => {
        const head = snap.owner === SHARED_OWNER
          ? `shared (human session, no label prefix) — profile: ${snap.userDir}`
          : `${snap.owner} — own window, titles prefixed "[${snap.owner}]" — profile: ${snap.userDir}`
        const tabs = snap.tabs.map(tab => {
          const marks = [snap.selected === tab.id ? '▶' : ' ', tab.infoTab === true ? 'ℹ' : '', tab.leasedBy ? `leased:${tab.leasedBy}${tab.purpose ? `(${tab.purpose})` : ''}` : '', tab.openedBy !== SHARED_OWNER && tab.openedBy !== snap.owner ? `openedBy:${tab.openedBy}` : ''].filter(Boolean).join(' ')
          return `   ${marks} [${tab.index}] ${tab.title} — ${tab.url}`
        })
        return [head, ...(tabs.length === 0 ? ['   (no tabs)'] : tabs)].join('\n')
      })
      const scopeLine = scopeRule === null
        ? `scope: UNRESTRICTED (call scope_set before engaging a target)${perOwners.length > 0 ? `; per-owner rules: ${perOwners.join(', ')}` : ''}`
        : `scope${who === undefined ? '' : ` (${who})`}: ${scopeRule.engagement ?? '(unnamed)'} — in: ${scopeRule.in_scope.join(', ') || '∅'} — out: ${scopeRule.out_scope.join(', ') || '∅'}${perOwners.length > 0 ? `; per-owner rules: ${perOwners.join(', ')}` : ''}`
      return textResult([...lines, '', scopeLine].join('\n'))
    })

  t('browser_reset', 'Close all harness-owned browser sessions except the kept ones (default: keep the shared human profile). Use at lane end / wrap-up.',
    { keep: z.array(z.string()).optional().describe('Owner names to keep; default ["shared"]') },
    async ({ keep }: any) => {
      const closed = await env.registry.reset(keep ?? [SHARED_OWNER])
      return textResult(closed.length === 0 ? 'Nothing to close.' : `Closed sessions: ${closed.join(', ')}`)
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
