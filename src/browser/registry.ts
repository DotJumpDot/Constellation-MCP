import path from 'node:path'
import { SHARED_OWNER, BrowserSession, type SessionSnapshot } from './session.js'
import type { ConstellationConfig } from '../config.js'

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

  /** Close every owner session except the kept ones. `shared` is kept by
   *  default so the human's logged-in profile is never torn down by a
   *  lane wrap-up (the browser_reset keep contract). */
  async reset(keep: string[] = [SHARED_OWNER]): Promise<string[]> {
    const keepSet = new Set(keep)
    const closed: string[] = []
    for (const owner of [...this.sessions.keys()]) {
      if (keepSet.has(owner)) continue
      await this.close(owner)
      closed.push(owner)
    }
    return closed
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
