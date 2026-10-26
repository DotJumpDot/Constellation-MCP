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
  tabs: Array<{ index: number; id: number; title: string; url: string; openedBy: string; purpose?: string; leasedBy?: string }>
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
    if (this.context) return this.context
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
    return context
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
      if (page && !page.isClosed()) return page
    }
    const existing = this.pages().at(-1)
    if (existing && !existing.isClosed()) {
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
