import { createRequire } from 'node:module'
import path from 'node:path'
import { z } from 'zod'
import type { Page } from 'playwright-core'
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

function locatorFor(page: Page, selector?: string, element?: string, name?: string, nth?: number) {
  if (selector !== undefined && selector !== '') {
    const loc = page.locator(selector)
    return nth === undefined ? loc : loc.nth(nth)
  }
  if (element === undefined || element === '') throw new Error('provide either `selector` or `element` (ARIA role) with optional `name`')
  const role = page.getByRole(element as never, name === undefined ? {} : { name, exact: false })
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

  t('browser_click', 'Click an element (by CSS/XPath selector, or ARIA role + accessible name). Returns the new page state.',
    {
      selector: z.string().optional().describe('CSS or XPath selector'),
      element: z.string().optional().describe('ARIA role, e.g. button, link, textbox'),
      name: z.string().optional().describe('Accessible name to match (substring)'),
      nth: z.number().int().optional().describe('0-based match index when several elements match'),
      ...OWNER_FIELD, ...TAB_FIELD,
    },
    async ({ selector, element, name, nth, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      await locatorFor(page, selector, element, name, nth).click({ timeout: 10_000 })
      return textResult(await afterActionResult(page))
    })

  t('browser_type', 'Fill a text field (by selector or role+name). Submits with Enter on request.',
    {
      text: z.string().describe('Text to enter'),
      selector: z.string().optional(), element: z.string().optional(), name: z.string().optional(), nth: z.number().int().optional(),
      submit: z.boolean().optional().describe('Press Enter after filling'),
      ...OWNER_FIELD, ...TAB_FIELD,
    },
    async ({ text, selector, element, name, nth, submit, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      const loc = locatorFor(page, selector, element, name, nth)
      await loc.fill(text, { timeout: 10_000 })
      if (submit === true) await loc.press('Enter')
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

  t('browser_select_option', 'Select option(s) on a <select> element (by selector or role+name).',
    {
      values: z.array(z.string()).min(1).describe('Option values or labels'),
      selector: z.string().optional(), element: z.string().optional(), name: z.string().optional(), nth: z.number().int().optional(),
      ...OWNER_FIELD, ...TAB_FIELD,
    },
    async ({ values, selector, element, name, nth, owner, tab }: any) => {
      const { session, owner: who } = sessionOf(env, owner)
      const page = await tabFor(session, who, tab)
      await locatorFor(page, selector, element, name, nth).selectOption(values, { timeout: 10_000 })
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

  t('browser_map', 'Ownership map: every browser session (per owner), its window label, tabs, leases, plus scope status. The Lead\'s view.',
    {},
    async () => {
      const snaps = await env.registry.snapshot()
      const scope = env.scope.current()
      const lines = snaps.length === 0 ? ['(no sessions launched yet — sessions appear when an owner first uses a browser tool)'] : snaps.map(snap => {
        const head = snap.owner === SHARED_OWNER
          ? `shared (human session, no label prefix) — profile: ${snap.userDir}`
          : `${snap.owner} — own window, titles prefixed "[${snap.owner}]" — profile: ${snap.userDir}`
        const tabs = snap.tabs.map(tab => {
          const marks = [snap.selected === tab.id ? '▶' : ' ', tab.leasedBy ? `leased:${tab.leasedBy}${tab.purpose ? `(${tab.purpose})` : ''}` : '', tab.openedBy !== SHARED_OWNER && tab.openedBy !== snap.owner ? `openedBy:${tab.openedBy}` : ''].filter(Boolean).join(' ')
          return `   ${marks} [${tab.index}] ${tab.title} — ${tab.url}`
        })
        return [head, ...(tabs.length === 0 ? ['   (no tabs)'] : tabs)].join('\n')
      })
      const scopeLine = scope === null ? 'scope: UNRESTRICTED (call scope_set before engaging a target)' : `scope: ${scope.engagement ?? '(unnamed)'} — in: ${scope.in_scope.join(', ') || '∅'} — out: ${scope.out_scope.join(', ') || '∅'}`
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
