import fs from 'node:fs'
import path from 'node:path'

/**
 * Noise governor (ARTEX mining round, 2026-11-20 — clean-room, ideas only;
 * see docs/research/artex-mining-2026-11-20.md §1).
 *
 * budget_set is a per-owner TOTAL cap that REFUSES past the limit — a hard
 * stop the Lead must remember to set. This governor is the missing soft
 * tier: a process-wide pacer installed at the SAME choke points
 * (browser navigations / new tabs / every HTTP leg). It QUEUES, never
 * drops: a call sleeps until per-owner, per-host AND global token buckets
 * all have a token, plus a small uniform jitter so even legal traffic stays
 * human-spaced. A lane over the ceiling physically cannot burst; it crawls
 * (and a lane that keeps hammering past a 120 s wait is told to back off).
 *
 * Only http/https URLs are paced — local plumbing (about:blank, file:) is
 * not noise. Chrome subresource traffic inside a page is invisible here,
 * exactly like ARTEX's "a command that ignores the proxy is not paced".
 */

export type NoiseProfileName = 'off' | 'quiet' | 'balanced' | 'aggressive'

export interface NoiseLevers {
  /** Token refill per second for the owner's own bucket. */
  rpsOwner: number
  /** Token refill per second for the target host's bucket (shared by all owners). */
  rpsHost: number
  /** Token refill per second for the one global bucket (all owners, all hosts). */
  rpsGlobal: number
  /** Bucket size for every bucket (immediate burst allowance). */
  burst: number
  /** Uniform send jitter cap in ms (applied on every paced send). */
  jitterMaxMs: number
}

/** Our own numbers, tuned for human-like lanes (requests-per-minute in
 *  comments). Quiet is the default: the standing rule is that noise only
 *  gets harder — raising the profile is a Lead decision via the
 *  noise_profile tool or CONSTELLATION_NOISE_PROFILE. */
export const NOISE_PROFILES: Record<Exclude<NoiseProfileName, 'off'>, NoiseLevers> = {
  quiet:      { rpsOwner: 0.1,  rpsHost: 0.2, rpsGlobal: 0.35, burst: 3,  jitterMaxMs: 250 }, // 6/12/21 rpm
  balanced:   { rpsOwner: 0.25, rpsHost: 0.5, rpsGlobal: 1.0,  burst: 5,  jitterMaxMs: 250 }, // 15/30/60 rpm
  aggressive: { rpsOwner: 1.0,  rpsHost: 2.0, rpsGlobal: 4.0,  burst: 10, jitterMaxMs: 100 }, // 60/120/240 rpm
}

export function isNoiseProfileName(name: string): name is NoiseProfileName {
  return name === 'off' || name === 'quiet' || name === 'balanced' || name === 'aggressive'
}

/** One token bucket. `tokens` may go negative — the debt IS the wait. */
export interface Bucket {
  tokens: number
  last: number
}

/** Take one token from a bucket; returns how long to wait for it (ms).
 *  Pure: mutates the bucket passed in, touches nothing else. */
export function reserve(bucket: Bucket, rps: number, burst: number, now: number): number {
  const elapsed = (now - bucket.last) / 1000
  bucket.tokens = Math.min(burst, bucket.tokens + elapsed * rps) - 1
  bucket.last = now
  return Math.max(0, (-bucket.tokens / rps) * 1000)
}

/** `host[:port]` of a URL for the host bucket (non-default ports kept). */
export function hostKeyOf(url: string): string {
  try {
    const u = new URL(url)
    const host = u.hostname.toLowerCase()
    const port = u.port === '' || (u.protocol === 'http:' && u.port === '80') || (u.protocol === 'https:' && u.port === '443') ? '' : `:${u.port}`
    return `${host}${port}`
  } catch {
    return '(unparseable)'
  }
}

const MINUTE_MS = 60_000
/** A pace that would wait longer than this refuses instead — the governor
 *  throttles hard, but a runaway lane gets a clear NOISE GOVERNOR error
 *  rather than an unbounded sleep. */
export const MAX_PACE_WAIT_MS = 120_000

export interface Counter {
  sent: number
  peakRpm: number
  windowStart: number
  waits: number
  totalWaitMs: number
}

function newCounter(now: number): Counter {
  return { sent: 0, peakRpm: 0, windowStart: now, waits: 0, totalWaitMs: 0 }
}

/** Roll the one-minute window so `sent` is always the CURRENT minute and
 *  peakRpm keeps the high-water mark. Pure-ish (mutates the counter). */
function rollWindow(counter: Counter, now: number): void {
  if (now - counter.windowStart >= MINUTE_MS) {
    counter.peakRpm = Math.max(counter.peakRpm, counter.sent)
    counter.sent = 0
    counter.windowStart = now
  }
}

export interface NoiseSnapshot {
  profile: NoiseProfileName
  levers: NoiseLevers | undefined
  owners: Array<Counter & { owner: string }>
  hosts: Array<Counter & { host: string }>
  global: Counter
}

export interface GovernorOptions {
  sleep?: (ms: number) => Promise<void>
  now?: () => number
  /** Appended one JSON line per paced send (ts/owner/host/waited_ms). */
  auditFile?: string
}

export class NoiseGovernor {
  private profile: NoiseProfileName
  private levers: NoiseLevers | undefined
  private ownerBuckets = new Map<string, Bucket>()
  private hostBuckets = new Map<string, Bucket>()
  private globalBucket: Bucket = { tokens: 0, last: 0 }
  private ownerCounters = new Map<string, Counter>()
  private hostCounters = new Map<string, Counter>()
  private globalCounter: Counter
  private readonly sleep: (ms: number) => Promise<void>
  private readonly now: () => number
  private readonly auditFile?: string

  constructor(profile: NoiseProfileName, options: GovernorOptions = {}) {
    this.profile = profile
    this.levers = profile === 'off' ? undefined : NOISE_PROFILES[profile]
    // Buckets start FULL (the burst is an allowance, not a warm-up penalty).
    const full = this.levers?.burst ?? 0
    this.globalBucket = { tokens: full, last: 0 }
    this.globalCounter = newCounter(0)
    this.sleep = options.sleep ?? (ms => new Promise(resolve => { setTimeout(resolve, ms).unref?.() }))
    this.now = options.now ?? (() => Date.now())
    this.auditFile = options.auditFile
  }

  profileName(): NoiseProfileName { return this.profile }

  /** Switch the runtime profile (the Lead's lever). Counters and buckets
   *  start afresh, and the switch itself is audited. */
  setProfile(next: NoiseProfileName): { from: NoiseProfileName; to: NoiseProfileName } {
    if (next === this.profile) return { from: this.profile, to: next }
    const from = this.profile
    this.profile = next
    this.levers = next === 'off' ? undefined : NOISE_PROFILES[next]
    const full = this.levers?.burst ?? 0
    const now = this.now()
    this.ownerBuckets.clear()
    this.hostBuckets.clear()
    this.globalBucket = { tokens: full, last: now }
    this.ownerCounters.clear()
    this.hostCounters.clear()
    this.globalCounter = newCounter(now)
    this.audit({ ts: new Date().toISOString(), event: 'profile', from, to: next })
    return { from, to: next }
  }

  /** Wait until every bucket has a token (+ jitter). Returns the waited ms.
   *  Off profile: strict passthrough — nothing counted, nothing waited.
   *  http/https only; other schemes are not target noise. */
  async pace(owner: string, url: string): Promise<number> {
    if (this.profile === 'off' || this.levers === undefined) return 0
    if (!/^https?:/i.test(url)) return 0
    const host = hostKeyOf(url)
    const now = this.now()
    const ownerBucket = this.ownerBuckets.get(owner) ?? { tokens: this.levers.burst, last: now }
    this.ownerBuckets.set(owner, ownerBucket)
    const hostBucket = this.hostBuckets.get(host) ?? { tokens: this.levers.burst, last: now }
    this.hostBuckets.set(host, hostBucket)
    if (this.globalBucket.last === 0) this.globalBucket = { tokens: this.levers.burst, last: now }
    const waitOwner = reserve(ownerBucket, this.levers.rpsOwner, this.levers.burst, now)
    const waitHost = reserve(hostBucket, this.levers.rpsHost, this.levers.burst, now)
    const waitGlobal = reserve(this.globalBucket, this.levers.rpsGlobal, this.levers.burst, now)
    const bucketWait = Math.max(waitOwner, waitHost, waitGlobal)
    // Uniform jitter on EVERY paced send (human spacing), capped.
    const jitter = this.levers.jitterMaxMs > 0 ? Math.floor(Math.random() * (this.levers.jitterMaxMs + 1)) : 0
    const waitMs = bucketWait + jitter
    if (waitMs > MAX_PACE_WAIT_MS)
      throw new Error(`NOISE GOVERNOR: pacing "${owner}" → ${host} would wait ${Math.round(waitMs / 1000)}s under profile "${this.profile}" (owner/host/global rpm ${this.levers.rpsOwner * 60}/${this.levers.rpsHost * 60}/${this.levers.rpsGlobal * 60}). This request was NOT sent — back off, wait a minute, or ask the Lead for noise_profile {profile:"balanced"}. budget_raise does NOT lift the governor.`)
    if (waitMs > 0) await this.sleep(waitMs)
    const done = this.now()
    const ownerCounter = this.ownerCounters.get(owner) ?? newCounter(done)
    this.ownerCounters.set(owner, ownerCounter)
    const hostCounter = this.hostCounters.get(host) ?? newCounter(done)
    this.hostCounters.set(host, hostCounter)
    for (const counter of [ownerCounter, hostCounter, this.globalCounter]) {
      rollWindow(counter, done)
      counter.sent += 1
      if (waitMs > 0) { counter.waits += 1; counter.totalWaitMs += waitMs }
    }
    this.audit({ ts: new Date().toISOString(), owner, host, waited_ms: Math.round(waitMs) })
    return waitMs
  }

  snapshot(): NoiseSnapshot {
    const now = this.now()
    rollWindow(this.globalCounter, now)
    const owners = [...this.ownerCounters.entries()].map(([owner, c]) => { rollWindow(c, now); return { owner, ...c } })
    const hosts = [...this.hostCounters.entries()].map(([host, c]) => { rollWindow(c, now); return { host, ...c } })
    owners.sort((a, b) => b.peakRpm - a.peakRpm || a.owner.localeCompare(b.owner))
    hosts.sort((a, b) => b.peakRpm - a.peakRpm || a.host.localeCompare(b.host))
    return { profile: this.profile, levers: this.levers, owners, hosts, global: { ...this.globalCounter } }
  }

  private audit(row: Record<string, unknown>): void {
    if (this.auditFile === undefined) return
    try {
      fs.mkdirSync(path.dirname(this.auditFile), { recursive: true })
      fs.appendFileSync(this.auditFile, JSON.stringify(row) + '\n')
    } catch { /* best effort — the governor never breaks a tool call */ }
  }
}

// ── Process-wide installation ────────────────────────────────────────────────
// Every choke point calls the module-level paceNoise() so no env threading
// is needed across the tool modules (http legs, browser tools, diff/recipe
// legs all get pacing from one import). server.ts installs the configured
// governor; tests install and reset their own.

let installed: NoiseGovernor | undefined

/** Install the process governor; returns the previous one (tests restore). */
export function installNoiseGovernor(governor: NoiseGovernor | undefined): NoiseGovernor | undefined {
  const prior = installed
  installed = governor
  return prior
}

export function noiseGovernor(): NoiseGovernor | undefined { return installed }

/** The one-liner every choke point uses, right after budget.spend(). */
export async function paceNoise(owner: string, url: string): Promise<void> {
  const governor = installed
  if (governor === undefined) return
  await governor.pace(owner, url)
}

/** Levers as a human line for reports and stderr. */
export function noiseLeversLine(profile: Exclude<NoiseProfileName, 'off'>): string {
  const l = NOISE_PROFILES[profile]
  return `owner/host/global ${Math.round(l.rpsOwner * 60)}/${Math.round(l.rpsHost * 60)}/${Math.round(l.rpsGlobal * 60)} rpm, burst ${l.burst}, jitter ≤${l.jitterMaxMs}ms`
}
