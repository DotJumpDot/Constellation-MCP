import fs from 'node:fs'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import pwCore from 'playwright-core'
import type { BrowserContext, Page } from 'playwright-core'
import type { ConstellationConfig } from '../config.js'

const { chromium } = pwCore
const exec = promisify(execFile)

/** Work area (taskbar-excluded bounds) of the Windows screen containing a
 *  point — the bottom-anchor input. Undefined on any failure (best effort). */
async function workAreaAt(x: number, y: number): Promise<{ top: number; height: number } | undefined> {
  try {
    const script =
      'Add-Type -AssemblyName System.Windows.Forms; ' +
      `$s = [System.Windows.Forms.Screen]::FromPoint([System.Drawing.Point]::new(${Math.round(x)}, ${Math.round(y)})); ` +
      '"{0} {1}" -f $s.WorkingArea.Y, $s.WorkingArea.Height'
    const { stdout } = await exec('powershell.exe', ['-NoProfile', '-Command', script], { windowsHide: true, timeout: 10_000 })
    const parts = stdout.trim().split(/\s+/)
    const top = Number.parseInt(parts[0] ?? '', 10)
    const height = Number.parseInt(parts[1] ?? '', 10)
    if (Number.isFinite(top) && Number.isFinite(height)) return { top, height }
    return undefined
  } catch {
    return undefined
  }
}

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

/** Owner info-label persistence (DST-Comet P3, build-session advice): labels
 *  were in-memory only, so a browser_reset or server restart brought the
 *  window back as "no job set". They now live in `<rootDir>/owner-labels.json`
 *  keyed by owner. Pure helpers so tests can pin the round-trip. */
const OWNER_LABELS_FILE = 'owner-labels.json'

export interface OwnerLabel {
  readonly job?: string
  readonly engagement?: string
}

export function loadOwnerLabels(rootDir: string): Record<string, OwnerLabel> {
  try {
    const parsed = JSON.parse(fs.readFileSync(path.join(rootDir, OWNER_LABELS_FILE), 'utf8')) as Record<string, unknown>
    if (parsed === null || typeof parsed !== 'object') return {}
    const labels: Record<string, OwnerLabel> = {}
    for (const [owner, label] of Object.entries(parsed)) {
      if (label === null || typeof label !== 'object') continue
      const job = (label as { job?: unknown }).job
      const engagement = (label as { engagement?: unknown }).engagement
      labels[owner] = {
        ...(typeof job === 'string' && job !== '' ? { job } : {}),
        ...(typeof engagement === 'string' && engagement !== '' ? { engagement } : {}),
      }
    }
    return labels
  } catch {
    return {}
  }
}

export function saveOwnerLabel(rootDir: string, owner: string, label: OwnerLabel): void {
  try {
    const all = loadOwnerLabels(rootDir)
    all[owner] = label
    fs.mkdirSync(rootDir, { recursive: true })
    fs.writeFileSync(path.join(rootDir, OWNER_LABELS_FILE), JSON.stringify(all, null, 2) + '\n')
  } catch { /* best effort: a lost label only costs the info-tab text */ }
}

export interface SessionSnapshot {
  owner: string
  running: boolean
  /** True when the browser was adopted over CDP instead of launched. */
  attached: boolean
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

/** Stable per-owner cascade on a pinned window position (user ask: 10+ owner
 *  windows pinned to one monitor must not stack exactly on top of each other).
 * X-ONLY (lead's round-7 measurement): a y-cascade walks windows down the
 *  screen — the bottom edge is where stacked owner windows belong, and the
 *  post-launch bottom-anchor moves y there. Invalid input passes through
 *  untouched — Chrome ignores a bad flag. Pure. */
export function cascadeWindowPosition(position: string, owner: string): string {
  const [xRaw, yRaw] = position.split(',').map(part => part.trim())
  const x = Number.parseInt(xRaw ?? '', 10)
  const y = Number.parseInt(yRaw ?? '', 10)
  if (!Number.isFinite(x) || !Number.isFinite(y)) return position
  let hash = 0
  for (const ch of owner) hash = (hash * 31 + (ch.codePointAt(0) ?? 0)) | 0
  const offset = (Math.abs(hash) % 10) * 30
  return `${x + offset},${y}`
}

/** Clamp the configured peek into the sane band (round-8 §5): the tab strip
 *  must stay clickable — 20 px minimum — and never eat half the work area.
 *  Pure. */
export function clampWindowPeek(peek: number): number {
  if (!Number.isFinite(peek)) return 36
  return Math.min(60, Math.max(20, Math.round(peek)))
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
  /** Attach mode (run-7 P0-2): adopt a running browser over CDP. */
  attached = false
  cdpUrl?: string
  private attachedBrowser?: pwCore.Browser
  /** Custom launch options (browser_launch): extra args + a normal,
   *  non-automation-flagged window. */
  launchExtraArgs?: string[]
  launchNoAutomationFlag = false
  /** Attach-mode traffic audit (run-8 §5): set by the attach tool so every
   *  request an adopted browser makes is scope-checked — the guard becomes a
   *  property of what goes out, not how the browser was launched. */
  networkObserver?: (method: string, url: string) => void
  /** Out-of-scope requests observed from this session (audit lines). */
  scopeViolations: Array<{ ts: string; method: string; url: string; reason: string }> = []

  constructor(readonly owner: string, readonly userDir: string, private config: ConstellationConfig) {
    // Seed the info-tab label from disk so a reset/restart window still says
    // what this owner is doing (the last browser_owner_info written wins).
    if (owner !== SHARED_OWNER) {
      const label = loadOwnerLabels(config.rootDir)[owner]
      if (label !== undefined) {
        if (label.job !== undefined) this.infoJob = label.job
        if (label.engagement !== undefined) this.infoEngagement = label.engagement
      }
    }
  }

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
      if (this.owner !== SHARED_OWNER && !this.attached && this.context !== undefined && !this.hasInfoTab()) {
        try { await this.openInfoTab() } catch { /* never block tool calls on the label */ }
      }
      return this.context
    }
    if (!this.launching) {
      this.launching = (this.attached ? this.connectOverCdp() : this.launch()).finally(() => { this.launching = undefined })
    }
    return this.launching
  }

  /** Adopt a browser the human is already driving (run-7 P0-2). DBSC binds
   *  sessions to the browser instance, so launching is fatal by design for
   *  such identities — attaching to the signed-in browser is the working
   *  route, and doing it INSIDE the session keeps it under the scope guard,
   *  tab leases and audit like any launched owner. */
  private async connectOverCdp(): Promise<BrowserContext> {
    if (this.cdpUrl === undefined) throw new Error('attach session has no cdp_url')
    let browser: pwCore.Browser
    try {
      browser = await chromium.connectOverCDP(this.cdpUrl, { timeout: 15_000 })
    } catch (error) {
      throw new Error(`failed to attach to ${this.cdpUrl}: ${error instanceof Error ? error.message : String(error)} — the target Chrome must run with --remote-debugging-port and the port reachable from this server`)
    }
    const context = browser.contexts()[0]
    if (context === undefined) throw new Error(`attached to ${this.cdpUrl} but it exposes no browser context`)
    this.attachedBrowser = browser
    this.attached = true
    // Adopted pages keep their own identity: no ownership-label init script
    // (it cannot apply retroactively anyway) and no info tab.
    context.on('page', page => { this.registerPage(page, this.owner) })
    // Run-8 §5: an attached browser's traffic is audited exactly like a
    // launched one — lanes used to hand-log requests to compensate.
    this.wireNetwork(context)
    for (const page of context.pages()) this.registerPage(page, this.owner)
    this.context = context
    return context
  }

  /** Request/response ring + the scope observer, shared by launch and attach. */
  private wireNetwork(context: BrowserContext): void {
    context.on('request', request => {
      this.network.push({ method: request.method(), url: request.url(), resourceType: request.resourceType() })
      if (this.network.length > NET_RING) this.network.splice(0, this.network.length - NET_RING)
      try { this.networkObserver?.(request.method(), request.url()) } catch { /* audit never breaks traffic */ }
    })
    context.on('response', response => {
      this.network.push({ method: response.request().method(), url: response.url(), status: response.status() })
      if (this.network.length > NET_RING) this.network.splice(0, this.network.length - NET_RING)
    })
  }

  /** Quiet-window Preferences, written before every launch (user ask: with
   *  10+ owner windows the "Restore pages?" bubble and Chrome's save-password
   *  prompts pile up unusable noise):
   *  - exit_type Normal / exited_cleanly — Chrome believes the last session
   *    ended cleanly (belt to --hide-crash-restore-bubble's braces);
   *  - password manager off — no "Save password?" bubble when agents drive
   *    logins (values must NEVER be captured into profiles anyway).
   *  Merged into an existing profile's Preferences; best-effort. */
  private writeSuppressionPrefs(): void {
    try {
      const prefsDir = path.join(this.userDir, 'Default')
      const prefsFile = path.join(prefsDir, 'Preferences')
      let prefs: Record<string, unknown> = {}
      try { prefs = JSON.parse(fs.readFileSync(prefsFile, 'utf8')) as Record<string, unknown> } catch { /* new profile */ }
      prefs['credentials_enable_service'] = false
      prefs['credentials_enable_autosignin'] = false
      prefs['profile'] = {
        ...(prefs['profile'] as Record<string, unknown> ?? {}),
        password_manager_enabled: false,
        exit_type: 'Normal',
        exited_cleanly: true,
      }
      fs.mkdirSync(prefsDir, { recursive: true })
      fs.writeFileSync(prefsFile, JSON.stringify(prefs))
    } catch { /* a locked or exotic profile launches without the quieting */ }
  }

  private async launch(): Promise<BrowserContext> {
    fs.mkdirSync(this.userDir, { recursive: true })
    this.writeSuppressionPrefs()
    const labelScript = this.labelScript()
    // Quiet-window defaults (user ask, 10+ windows per run): no "Restore
    // pages?" bubble after an unclean exit, no first-run/default-browser
    // nagging. The password-save bubble is disabled via Preferences below.
    // Window pinning/minimized start (user ask: spawned windows must never
    // cover a fullscreen game on the main screen or steal its focus).
    const args = [
      '--hide-crash-restore-bubble',
      '--no-first-run',
      '--no-default-browser-check',
      ...(this.config.windowPosition !== undefined
        ? [`--window-position=${cascadeWindowPosition(this.config.windowPosition, this.owner)}`]
        : []),
      ...(this.config.startMinimized ? ['--start-minimized'] : []),
      ...(this.launchExtraArgs ?? []),
    ]
    let context: BrowserContext
    try {
      context = await chromium.launchPersistentContext(this.userDir, {
        channel: this.config.channel,
        headless: this.config.headless,
        viewport: null,
        acceptDownloads: true,
        args,
        // browser_launch "normal window" mode: drop the automation flag so
        // sites fingerprinting it (and DBSC) see a regular Chrome.
        ...(this.launchNoAutomationFlag ? { ignoreDefaultArgs: ['--enable-automation'] } : {}),
      })
    } catch (error) {
      throw new Error(`failed to launch ${this.config.channel} browser for "${this.owner}": ${error instanceof Error ? error.message : String(error)}`)
    }
    if (labelScript !== '') await context.addInitScript(labelScript)
    context.on('page', page => { this.registerPage(page, this.owner) })
    this.wireNetwork(context)
    for (const page of context.pages()) this.registerPage(page, this.owner)
    this.context = context
    // EVERY launched window parks at the bottom of its monitor with only the
    // tab strip peeking (round-8 §5 — one shared placement on every launch
    // path; a window appearing at the top of the screen is a regression of
    // the preference). Minimized starts have no visible bounds to park.
    if (!this.config.startMinimized) {
      await this.parkWindow(context)
    }
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

  /** PARK the freshly launched window at the bottom of its monitor's work
   *  area with only the tab strip peeking (round-8 §5, the human's MEASURED
   *  preference — they dragged a live window to demonstrate it: top = availTop
   *  + availH − peekPx, peek 36, never clamped fully on-screen, windowState
   *  normal so the strip stays clickable). The peek is FIXED, never derived
   *  from the window's height — round-8 D5 measured the old height-derived
   *  anchor landing on a stale 43 px box when it raced Chrome's sizing, and
   *  one launch path skipped the anchor entirely. Bounds are read back and
   *  the park retried ONCE so the peek is what was asked for (DPI drift,
   *  CDP DIP-vs-physical rounding). Best effort — never blocks a launch. */
  private async parkWindow(context: BrowserContext): Promise<void> {
    try {
      const page = context.pages()[0]
      if (page === undefined) return
      const cdp = await context.newCDPSession(page)
      try {
        const { windowId } = await cdp.send('Browser.getWindowForTarget') as { windowId: number }
        const readBounds = () => cdp.send('Browser.getWindowBounds', { windowId }) as Promise<{ bounds: { left: number; top: number } }>
        let { bounds } = await readBounds()
        const work = await workAreaAt(bounds.left + 50, bounds.top + 50)
        if (work === undefined) return
        const peek = clampWindowPeek(this.config.windowPeekPx)
        await cdp.send('Browser.setWindowBounds', { windowId, bounds: { top: work.top + work.height - peek } })
        // Read-back + one retry: Chrome applies bounds asynchronously and a
        // first read can still show the pre-park position or a DPI-rounded
        // strip. The spec's verification is by MEASUREMENT (visibleStrip =
        // availTop + availH − screenY) — measure here too, not the flag.
        await new Promise(resolve => setTimeout(resolve, 250))
        ;({ bounds } = await readBounds())
        const strip = work.top + work.height - bounds.top
        if (Math.abs(strip - peek) > 8) {
          await cdp.send('Browser.setWindowBounds', { windowId, bounds: { top: work.top + work.height - peek } })
        }
      } finally {
        await cdp.detach().catch(() => undefined)
      }
    } catch { /* placement is best effort */ }
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
    // The window title MUST carry the [owner] prefix: the label init script
    // does not run on data: URLs, and the human-wall panel's "focus chrome"
    // action matches windows by that prefix (live-run bug 2026-10-27).
    const html = `<!doctype html><meta charset="utf-8"><title>[${esc(this.owner)}] info — ${esc(this.infoJob ?? 'no job set')}</title>
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

  /** Update the ownership label (browser_owner_info); re-renders a live tab
   *  and persists so the label survives resets and restarts. */
  async setOwnerInfo(job?: string, engagement?: string): Promise<{ job?: string; engagement?: string }> {
    if (job !== undefined) this.infoJob = job
    if (engagement !== undefined) this.infoEngagement = engagement
    saveOwnerLabel(this.config.rootDir, this.owner, {
      ...(this.infoJob === undefined ? {} : { job: this.infoJob }),
      ...(this.infoEngagement === undefined ? {} : { engagement: this.infoEngagement }),
    })
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
      attached: this.attached,
      userDir: this.userDir,
      windowLabel: this.attached
        ? `attached over CDP (${this.cdpUrl ?? '?'}) — closing only disconnects, never closes the human's browser`
        : this.windowLabel === '' ? 'shared profile (no label prefix)' : `${this.windowLabel.trim()} window`,
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
    if (this.attached) {
      // An attached browser belongs to the human: closing only DISCONNECTS.
      const browser = this.attachedBrowser
      this.attachedBrowser = undefined
      this.attached = false
      if (browser) { try { await browser.close() } catch { /* already gone */ } }
      return
    }
    if (context) { try { await context.close() } catch { /* already gone */ } }
  }

  /** Tab leases held in this session (any holder) — reset safety (P1-6). */
  heldLeases(): Array<{ tabId: number; leasedBy: string; purpose?: string }> {
    const out: Array<{ tabId: number; leasedBy: string; purpose?: string }> = []
    for (const meta of this.tabs.values()) {
      if (meta.leasedBy !== undefined) out.push({ tabId: meta.id, leasedBy: meta.leasedBy, ...(meta.purpose === undefined ? {} : { purpose: meta.purpose }) })
    }
    return out
  }
}
