import path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { SHARED_OWNER, BrowserSession, type SessionSnapshot } from './session.js'
import type { ConstellationConfig } from '../config.js'

const exec = promisify(execFile)

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

  async snapshot(): Promise<SessionSnapshot[]> {
    const out: SessionSnapshot[] = []
    for (const session of this.sessions.values()) out.push(await session.snapshot())
    return out
  }

  async close(owner: string): Promise<boolean> {
    const session = this.sessions.get(owner)
    if (!session) return false
    await session.close()
    if (owner !== SHARED_OWNER) this.sessions.delete(owner)
    return true
  }

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
    this.sweeper = setInterval(() => {
      const now = Date.now()
      for (const [owner, session] of this.sessions) {
        if (owner === SHARED_OWNER) continue
        if (session.context === undefined) continue
        if (now - session.lastUsed > limitMs) void this.close(owner)
      }
    }, 60_000)
    this.sweeper.unref()
  }

  async disposeAll(): Promise<void> {
    if (this.sweeper) clearInterval(this.sweeper)
    await Promise.allSettled([...this.sessions.values()].map(s => s.close()))
  }
}
