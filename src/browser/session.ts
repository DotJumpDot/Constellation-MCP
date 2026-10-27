import fs from 'node:fs'
import path from 'node:path'
import pwCore from 'playwright-core'
import type { BrowserContext, Page } from 'playwright-core'
import type { ConstellationConfig } from '../config.js'

const { chromium } = pwCore

export const SHARED_OWNER = 'shared'

export interface TabMeta {
  id: number
  openedBy: string
  purpose?: string
  leasedBy?: string
  leasedAt?: number
  openedAt: number
  /** The ownership-label tab pinned at the head of an owner's window. */
  infoTab?: boolean
}

export interface NetworkRecord {
  method: string
  url: string
  status?: number
  resourceType?: string
}

const CONSOLE_RING = 300
const NET_RING = 200

export interface SessionSnapshot {
  owner: string
  running: boolean
  userDir: string
  windowLabel: string
  selected: number | null
  tabs: Array<{ index: number; id: number; title: string; url: string; openedBy: string; purpose?: string; leasedBy?: string; infoTab?: boolean }>
}

/** Decision helper — pure so tests can pin the lease rules. A session owner
 *  may always touch their own tabs; a lease holder may touch a leased tab;
 *  nobody else may select or close it. */
export function canTouchTab(meta: TabMeta | undefined, owner: string, sessionOwner: string): { ok: boolean; reason?: string } {
  if (meta === undefined) return { ok: false, reason: 'no such tab' }
  if (owner === sessionOwner) return { ok: true }
  if (meta.leasedBy !== undefined && meta.leasedBy !== owner)
    return { ok: false, reason: `tab ${meta.id} is leased by "${meta.leasedBy}"${meta.purpose ? ` for ${meta.purpose}` : ''} — pick another tab or ask them to tab_release` }
  return { ok: true }
}

export class BrowserSession {
  context?: BrowserContext
  private tabs = new Map<Page, TabMeta>()
  private nextTabId = 1
  selected: number | null = null
  lastUsed = Date.now()
  consoleLines: string[] = []
  network: NetworkRecord[] = []
  launching?: Promise<BrowserContext>
  /** Job/engagement label shown on the info tab (browser_owner_info). */
  infoJob?: string
  infoEngagement?: string
  private infoOpenedAt?: string

  constructor(readonly owner: string, readonly userDir: string, private config: ConstellationConfig) {}

  private get windowLabel(): string {
    return this.owner === SHARED_OWNER ? '' : `[${this.owner}] `
  }

  private labelScript(): string {
    const label = this.windowLabel
    if (label === '') return ''
    return `(() => { const P = ${JSON.stringify(label)}; const fix = () => { try { if (!document.title.startsWith(P)) document.title = P + document.title } catch {} }; let t = document.querySelector('title'); if (!t) { t = document.createElement('title'); (document.head || document.documentElement).appendChild(t) } new MutationObserver(fix).observe(t, { subtree: true, childList: true, characterData: true }); addEventListener('load', fix); fix() })()`
  }

  async ensure(): Promise<BrowserContext> {
    this.lastUsed = Date.now()
    if (this.context) {
      // The human (or Chrome itself) can close the info tab from the UI; the
      // ownership label must survive, so re-pin it whenever it is missing.
      if (this.owner !== SHARED_OWNER && this.context !== undefined && !this.hasInfoTab()) {
        try { await this.openInfoTab() } catch { /* never block tool calls on the label */ }
      }
      return this.context
    }
    if (!this.launching) {
      this.launching = this.launch().finally(() => { this.launching = undefined })
    }
    return this.launching
  }

  private async launch(): Promise<BrowserContext> {
    fs.mkdirSync(this.userDir, { recursive: true })
    const labelScript = this.labelScript()
    let context: BrowserContext
    try {
      context = await chromium.launchPersistentContext(this.userDir, {
        channel: this.config.channel,
        headless: this.config.headless,
        viewport: null,
        acceptDownloads: true,
      })
    } catch (error) {
      throw new Error(`failed to launch ${this.config.channel} browser for "${this.owner}": ${error instanceof Error ? error.message : String(error)}`)
    }
    if (labelScript !== '') await context.addInitScript(labelScript)
    context.on('page', page => { this.registerPage(page, this.owner) })
    context.on('request', request => {
      this.network.push({ method: request.method(), url: request.url(), resourceType: request.resourceType() })
      if (this.network.length > NET_RING) this.network.splice(0, this.network.length - NET_RING)
    })
    context.on('response', response => {
      this.network.push({ method: response.request().method(), url: response.url(), status: response.status() })
      if (this.network.length > NET_RING) this.network.splice(0, this.network.length - NET_RING)
    })
    for (const page of context.pages()) this.registerPage(page, this.owner)
    this.context = context
    // The very first tab of an owner window is the ownership label: which
    // agent owns this window and what job it is running. It cannot be closed
    // by tool calls and is re-pinned if the human closes it in Chrome.
    if (this.owner !== SHARED_OWNER) {
      try { await this.openInfoTab() } catch { /* never block a launch on the label */ }
      this.selected = null
    }
    return context
  }

  private hasInfoTab(): boolean {
    for (const [page, meta] of this.tabs) if (meta.infoTab === true && !page.isClosed()) return true
    return false
  }

  /** Navigate (or re-navigate) the pinned ownership-label tab. */
  private async openInfoTab(): Promise<void> {
    const context = this.context
    if (context === undefined) return
    this.infoOpenedAt ??= new Date().toISOString()
    // Reuse the existing info tab when it is still open; otherwise open a new
    // page and move it to the head of the tab map so indices stay stable.
    let infoPage: Page | undefined
    for (const [page, meta] of this.tabs) {
      if (meta.infoTab === true && !page.isClosed()) { infoPage = page; break }
    }
    let reordering = false
    if (infoPage === undefined) {
      infoPage = await context.newPage()
      const meta = this.metaOf(infoPage)!
      meta.infoTab = true
      reordering = true
    }
    await infoPage.goto(this.infoUrl(), { waitUntil: 'domcontentloaded', timeout: 10_000 }).catch(() => undefined)
    if (reordering) {
      const entries = [...this.tabs.entries()]
      this.tabs = new Map(entries.filter(([page]) => page === infoPage).concat(entries.filter(([page]) => page !== infoPage)))
    }
  }

  private infoUrl(): string {
    const esc = (value: string) => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
    const html = `<!doctype html><meta charset="utf-8"><title>info — ${esc(this.infoJob ?? 'no job set')}</title>
<body style="font:15px/1.6 system-ui,sans-serif;max-width:38em;margin:auto;padding:3em 2em;background:#101418;color:#e8e8e8">
<h1 style="margin:0 0 .2em">[${esc(this.owner)}]</h1>
<p style="margin:.2em 0;color:#9fd0ff">job: <b>${esc(this.infoJob ?? '(not set — the Lead can call browser_owner_info)')}</b></p>
<p style="margin:.2em 0">engagement: <b>${esc(this.infoEngagement ?? '—')}</b></p>
<p style="margin:.8em 0 .2em;font-size:.9em;color:#888">This Chrome window belongs to owner <b>${esc(this.owner)}</b> (Constellation per-owner browser).
Tab 1 is the ownership label — it is restored automatically if closed; close the whole window to end the owner's session.
Window opened: ${esc(this.infoOpenedAt ?? new Date().toISOString())}</p>
</body>`
    return `data:text/html;charset=utf-8,${encodeURIComponent(html)}`
  }

  /** Update the ownership label (browser_owner_info); re-renders a live tab. */
  async setOwnerInfo(job?: string, engagement?: string): Promise<{ job?: string; engagement?: string }> {
    if (job !== undefined) this.infoJob = job
    if (engagement !== undefined) this.infoEngagement = engagement
    if (this.context !== undefined) {
      try { await this.openInfoTab() } catch { /* rendered on next ensure */ }
    }
    return { ...(this.infoJob === undefined ? {} : { job: this.infoJob }), ...(this.infoEngagement === undefined ? {} : { engagement: this.infoEngagement }) }
  }

  private registerPage(page: Page, openedBy: string): void {
    if (this.tabs.has(page)) return
    const id = this.nextTabId++
    this.tabs.set(page, { id, openedBy, openedAt: Date.now() })
    page.on('console', message => {
      this.consoleLines.push(`[${message.type()}] ${message.text()}`)
      if (this.consoleLines.length > CONSOLE_RING) this.consoleLines.splice(0, this.consoleLines.length - CONSOLE_RING)
    })
    page.on('pageerror', error => {
      this.consoleLines.push(`[pageerror] ${error.message}`)
      if (this.consoleLines.length > CONSOLE_RING) this.consoleLines.splice(0, this.consoleLines.length - CONSOLE_RING)
    })
    page.on('close', () => { this.tabs.delete(page) })
    if (this.selected === null) this.selected = id
  }

  pages(): Page[] {
    return [...this.tabs.keys()]
  }

  metaOf(page: Page): TabMeta | undefined {
    return this.tabs.get(page)
  }

  pageById(id: number): { page?: Page; meta?: TabMeta } {
    for (const [page, meta] of this.tabs) if (meta.id === id) return { page, meta }
    return {}
  }

  async currentPage(): Promise<Page> {
    const context = await this.ensure()
    if (this.selected !== null) {
      const { page } = this.pageById(this.selected)
      if (page && !page.isClosed() && this.metaOf(page)?.infoTab !== true) return page
    }
    const existing = [...this.tabs.keys()].reverse().find(page => !page.isClosed() && this.metaOf(page)?.infoTab !== true)
    if (existing) {
      const meta = this.metaOf(existing)
      if (meta) this.selected = meta.id
      return existing
    }
    return context.newPage()
  }

  async newTab(openedBy: string, url?: string, purpose?: string): Promise<{ page: Page; meta: TabMeta }> {
    const context = await this.ensure()
    const page = await context.newPage()
    const meta = this.metaOf(page)!
    meta.purpose = purpose
    this.selected = meta.id
    if (url !== undefined) await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45_000 })
    return { page, meta }
  }

  touch(): void {
    this.lastUsed = Date.now()
  }

  async snapshot(): Promise<SessionSnapshot> {
    const tabs = []
    let index = 0
    for (const [page, meta] of this.tabs) {
      let title = ''
      try { title = await page.title() } catch { title = '' }
      if (title === '') title = page.url()
      tabs.push({
        index: index++,
        id: meta.id,
        title,
        url: page.url(),
        openedBy: meta.openedBy,
        ...(meta.purpose === undefined ? {} : { purpose: meta.purpose }),
        ...(meta.leasedBy === undefined ? {} : { leasedBy: meta.leasedBy }),
        ...(meta.infoTab === true ? { infoTab: true } : {}),
      })
    }
    return {
      owner: this.owner,
      running: this.context !== undefined,
      userDir: this.userDir,
      windowLabel: this.windowLabel === '' ? 'shared profile (no label prefix)' : `${this.windowLabel.trim()} window`,
      selected: this.selected,
      tabs,
    }
  }

  artifactDir(): string {
    const dir = path.join(this.config.outputDir, this.owner === SHARED_OWNER ? 'shared' : this.owner)
    fs.mkdirSync(dir, { recursive: true })
    return dir
  }

  async close(): Promise<void> {
    const context = this.context
    this.context = undefined
    this.tabs.clear()
    this.selected = null
    if (context) { try { await context.close() } catch { /* already gone */ } }
  }
}
