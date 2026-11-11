import path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { SHARED_OWNER, BrowserSession, type SessionSnapshot } from './session.js'
import { chromeProcessCensus } from './plain-launch.js'
import type { ConstellationConfig } from '../config.js'

const exec = promisify(execFile)

/** Compare profile paths the way Windows does (case-insensitive, either
 * slash, no trailing separator). Pure; tested. */
export function normalizeDir(dir: string): string {
  return dir.replaceAll('/', '\\').replace(/\\+$/, '').toLowerCase()
}

export class OwnerRegistry {
  private sessions = new Map<string, BrowserSession>()
  private sweeper?: ReturnType<typeof setInterval>

  constructor(private config: ConstellationConfig) {}

  /** Owner names become profile directory names — sanitize hard. */
  static resolveOwner(raw: string | undefined): string {
    const name = raw?.trim() || SHARED_OWNER
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(name))
      throw new Error(`invalid owner "${raw}" — use 1..32 chars of letters, digits, dot, dash, underscore`)
    return name
  }

  sessionFor(owner: string): BrowserSession {
    const existing = this.sessions.get(owner)
    if (existing) return existing
    const userDir = owner === SHARED_OWNER
      ? this.config.sharedUserDataDir
      : path.join(this.config.profilesRoot, owner)
    const session = new BrowserSession(owner, userDir, this.config)
    this.sessions.set(owner, session)
    return session
  }

  /** The owner's live session, if any (browser_kill and map state lines:
   * never fabricates one). */
  sessionIfExists(owner: string): BrowserSession | undefined {
    return this.sessions.get(owner)
  }

  /** Whether another LIVE session already owns this profile dir (run-39
   * §11.2: attach must not adopt another lane's window through a recycled
   * port). Path comparison is case-insensitive, slash- and trailing-slash-
   * tolerant — the census and PS layers hand us every variant. */
  liveOwnerOfUserDir(userDir: string, exceptOwner: string): string | undefined {
    const want = normalizeDir(userDir)
    for (const [owner, session] of this.sessions) {
      if (owner === exceptOwner || session.context === undefined) continue
      if (normalizeDir(session.userDir) === want) return owner
    }
    return undefined
  }

  /** Attach mode (run-7 P0-2): adopt a running browser over CDP as an owner
   *  session. Re-attaching an owner replaces its previous session. */
  attachFor(owner: string, cdpUrl: string): BrowserSession {
    void this.sessions.get(owner)?.close().catch(() => undefined)
    const session = new BrowserSession(owner, `(attached) ${cdpUrl}`, this.config)
    session.attached = true
    session.cdpUrl = cdpUrl
    this.sessions.set(owner, session)
    return session
  }

  /** Custom launch (run-7 P0-2): a persistent context on an explicit
   *  user-data-dir with extra Chrome args, without the automation flag. */
  launchFor(owner: string, userDir: string, extraArgs?: string[]): BrowserSession {
    void this.sessions.get(owner)?.close().catch(() => undefined)
    const session = new BrowserSession(owner, userDir, this.config)
    if (extraArgs !== undefined && extraArgs.length > 0) session.launchExtraArgs = extraArgs
    session.launchNoAutomationFlag = true
    this.sessions.set(owner, session)
    return session
  }

  /** Plain launch (advice D12, 2026-11-11): spawn our own chrome.exe (no
   *  automation flags — the only route measured to pass Cloudflare-class
   *  edges), no-activate, free debug port, adopted over CDP and owned by the
   *  harness (label, badge, graceful close). Idempotent: a live plain session
   *  for the owner is returned as-is instead of relaunching. */
  plainFor(owner: string, userDir: string, extraArgs?: string[]): BrowserSession {
    const existing = this.sessions.get(owner)
    if (existing !== undefined && existing.plainOwned && existing.userDir === userDir) return existing
    void existing?.close().catch(() => undefined)
    const session = new BrowserSession(owner, userDir, this.config)
    if (extraArgs !== undefined && extraArgs.length > 0) session.launchExtraArgs = extraArgs
    session.plainOwned = true
    this.sessions.set(owner, session)
    return session
  }

  async snapshot(): Promise<SessionSnapshot[]> {
    const out: SessionSnapshot[] = []
    for (const session of this.sessions.values()) out.push(await session.snapshot())
    return out
  }

  /** Close a session; `reaped` = stray chrome.exe processes the exact-match
   *  profile sweep killed after the graceful close (run-39 §12.8). */
  async close(owner: string): Promise<boolean> {
    const session = this.sessions.get(owner)
    if (!session) return false
    const { reaped } = await session.close()
    this.lastReapCount = reaped
    if (owner !== SHARED_OWNER) this.sessions.delete(owner)
    return true
  }

  /** Stray-process count from the most recent close (surfaced by
   *  browser_kill so the Lead sees zombie reaping, not silence). */
  lastReapCount = 0

  /** Run-7 P1-6: reset closes ONLY the caller's session. Closing others needs
   *  `{all: true}` and is refused while those owners hold tab leases. */
  async resetAll(callerKeep: string[], refuseLeased = true): Promise<{ closed: string[]; refused: Array<{ owner: string; leases: Array<{ tabId: number; leasedBy: string; purpose?: string }> }> }> {
    const keepSet = new Set(callerKeep)
    const closed: string[] = []
    const refused: Array<{ owner: string; leases: Array<{ tabId: number; leasedBy: string; purpose?: string }> }> = []
    for (const owner of [...this.sessions.keys()]) {
      if (keepSet.has(owner)) continue
      const session = this.sessions.get(owner)!
      if (refuseLeased) {
        const leases = session.heldLeases()
        if (leases.length > 0) { refused.push({ owner, leases }); continue }
      }
      await this.close(owner)
      closed.push(owner)
    }
    return { closed, refused }
  }

  /** Retained compatibility shim for callers that really mean "everything but". */
  async reset(keep: string[] = [SHARED_OWNER]): Promise<string[]> {
    return (await this.resetAll(keep, false)).closed
  }

  /** Profile directories that still have a live chrome.exe (P2-13): the map
   *  must read process state, not just this server's session registry — after
   *  a restart the registry is empty while the owner Chromes keep running. */
  async runningProfileDirs(): Promise<Set<string>> {
    const out = new Set<string>()
    try {
      const script =
        `Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" -ErrorAction SilentlyContinue | ` +
        `ForEach-Object { if ($_.CommandLine -match '--user-data-dir=("([^"]+)"|([^ ]+))' ) { $Matches[2]; if (-not $Matches[2]) { $Matches[3] } } } | Sort-Object -Unique`
      const { stdout } = await exec('powershell.exe', ['-NoProfile', '-Command', script], { windowsHide: true, timeout: 15_000 })
      for (const line of stdout.split('\n')) {
        const dir = line.trim()
        if (dir !== '') out.add(dir.toLowerCase())
      }
    } catch { /* non-Windows or no chrome: no process info */ }
    return out
  }

  startIdleSweeper(): void {
    if (this.config.idleTimeoutMin <= 0 || this.sweeper) return
    const limitMs = this.config.idleTimeoutMin * 60_000
    // RAM guard cadence (run-39 RAM round): a census every 5 minutes is
    // one short CIM sweep — cheap next to a 13-lane hunt, and it is what
    // turns "Task Manager says 10 GB" into a warning the Lead can see.
    const ramGuardMs = 5 * 60_000
    let nextRamCheck = 0
    this.sweeper = setInterval(() => {
      const now = Date.now()
      for (const [owner, session] of this.sessions) {
        if (owner === SHARED_OWNER) continue
        if (session.context === undefined) continue
        if (now - session.lastUsed > limitMs) void this.close(owner)
      }
      if (this.config.ramGuardMb > 0 && now >= nextRamCheck) {
        nextRamCheck = now + ramGuardMs
        void this.ramGuardSweep().catch(() => undefined)
      }
    }, 60_000)
    this.sweeper.unref()
  }

  /** One RAM-guard pass: sum each live session's chrome.exe working set by
   *  profile dir; over `ramGuardMb` the session gets `ramWarning` (shown on
   *  browser_map/browser_tabs), and with `ramAutoPark` it is closed instead —
   *  the run-39 mtree2a case (a single renderer ballooning past 10 GB while
   *  "active") must never again need the human's Task Manager to notice. */
  async ramGuardSweep(): Promise<Array<{ owner: string, mb: number, parked: boolean }>> {
    const census = await chromeProcessCensus()
    const out: Array<{ owner: string, mb: number, parked: boolean }> = []
    for (const [owner, session] of this.sessions) {
      if (session.context === undefined) continue
      const dirs = [session.userDir, session.adoptedProfileDir]
        .filter((dir): dir is string => dir !== undefined && !dir.startsWith('(attached)'))
        .map(normalizeDir)
      let total = 0
      for (const [udd, stats] of census) {
        if (dirs.includes(normalizeDir(udd))) total += stats.totalWsBytes
      }
      const mb = Math.round(total / 1_048_576)
      if (mb <= this.config.ramGuardMb) {
        if (session.ramWarning !== undefined) session.ramWarning = undefined
        continue
      }
      const warn = `chrome at ${mb} MB (RAM guard ${this.config.ramGuardMb} MB) — close unused tabs or browser_kill {owner:"${owner}"}`
      if (this.config.ramAutoPark && owner !== SHARED_OWNER) {
        out.push({ owner, mb, parked: true })
        session.ramWarning = warn
        await this.close(owner)
      } else {
        session.ramWarning = warn
        out.push({ owner, mb, parked: false })
      }
    }
    return out
  }

  async disposeAll(): Promise<void> {
    if (this.sweeper) clearInterval(this.sweeper)
    await Promise.allSettled([...this.sessions.values()].map(s => s.close()))
  }
}
