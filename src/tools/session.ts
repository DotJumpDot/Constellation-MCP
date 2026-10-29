/**
 * Session-state tools (run-8 proposals §3): four Google lanes spent ~60
 * requests and ~3 hours on authentication, and twice a lane "verified" a
 * session that was actually signed out — the account chooser lists remembered
 * accounts next to "Signed out", and myaccount.google.com accepting a session
 * says NOTHING about Gemini accepting it. session_verify therefore takes a
 * PER-SITE PROOF RULE (an account-owned surface), and session_watch polls so
 * a lane learns its session died at request 3, not request 30.
 */

import fs from 'node:fs'
import path from 'node:path'
import { z } from 'zod'
import { errorResult, textResult, type ToolRegistrar, type ToolResult } from '../browser/tools.js'
import { SHARED_OWNER, type BrowserSession } from '../browser/session.js'
import type { ConstellationConfig } from '../config.js'

export interface SessionProofRule {
  /** Human label, e.g. "Google Gemini (account chip)". */
  name: string
  /** The account-owned surface to render. */
  url: string
  /** Text that must appear (any-of). */
  must_contain?: string[]
  /** Text that must NOT appear (any-of) — e.g. "Sign in". */
  must_not_contain?: string[]
}

export const DEFAULT_PROOF_RULES: Record<string, SessionProofRule> = {
  'google-gemini': { name: 'Google Gemini (app surface)', url: 'https://gemini.google.com/app', must_contain: ['Gemini'], must_not_contain: ['Sign in'] },
  'google-drive': { name: 'Google Drive (My Drive)', url: 'https://drive.google.com/drive/my-drive', must_not_contain: ['Sign in'] },
  'google-account': { name: 'Google Account (shared surface — weak proof for other Google products)', url: 'https://myaccount.google.com/', must_contain: ['Google Account'] },
  'statuspage': { name: 'Statuspage (org dashboard)', url: 'https://manage.statuspage.io/', must_not_contain: ['Log in', 'Sign in'] },
}

export function loadProofRules(config: ConstellationConfig): Record<string, SessionProofRule> {
  const file = path.join(config.rootDir, 'session-proofs.json')
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, unknown>
    const rules: Record<string, SessionProofRule> = { ...DEFAULT_PROOF_RULES }
    for (const [key, value] of Object.entries(parsed)) {
      if (value === null || typeof value !== 'object') continue
      const raw = value as { name?: unknown; url?: unknown; must_contain?: unknown; must_not_contain?: unknown; remove?: unknown }
      if (raw.remove === true) { delete rules[key]; continue }
      if (typeof raw.url !== 'string') continue
      rules[key] = {
        ...(typeof raw.name === 'string' ? { name: raw.name } : { name: key }),
        url: raw.url,
        ...(Array.isArray(raw.must_contain) ? { must_contain: raw.must_contain.filter((v): v is string => typeof v === 'string') } : {}),
        ...(Array.isArray(raw.must_not_contain) ? { must_not_contain: raw.must_not_contain.filter((v): v is string => typeof v === 'string') } : {}),
      }
    }
    return rules
  } catch { return { ...DEFAULT_PROOF_RULES } }
}

/** Pure rule evaluation so tests pin the verdicts. */
export function evaluateProof(rule: SessionProofRule, pageText: string): { ok: boolean; reason: string } {
  for (const needle of rule.must_contain ?? []) {
    if (!pageText.includes(needle)) return { ok: false, reason: `expected "${needle}" on ${rule.url}` }
  }
  for (const needle of rule.must_not_contain ?? []) {
    if (pageText.includes(needle)) return { ok: false, reason: `"${needle}" is visible on ${rule.url} — the surface is the sign-in/chooser, not a signed-in view` }
  }
  return { ok: true, reason: rule.name }
}

export interface SessionWatch {
  owner: string
  site: string
  intervalS: number
  timer: ReturnType<typeof setInterval>
  lastOk?: boolean
  lastReason?: string
  lastCheckedAt?: string
  /** When the CURRENT state began (a transition flips this). */
  since?: string
  history: Array<{ ts: string; ok: boolean; reason: string }>
}

export class SessionWatchRegistry {
  private watches = new Map<string, SessionWatch>()

  static key(owner: string, site: string): string {
    return `${owner}::${site}`
  }

  add(watch: Omit<SessionWatch, 'history'>): SessionWatch {
    this.remove(watch.owner, watch.site)
    const full: SessionWatch = { ...watch, history: [] }
    this.watches.set(SessionWatchRegistry.key(watch.owner, watch.site), full)
    return full
  }

  get(owner: string, site: string): SessionWatch | undefined {
    return this.watches.get(SessionWatchRegistry.key(owner, site))
  }

  record(owner: string, site: string, ok: boolean, reason: string): void {
    const watch = this.get(owner, site)
    if (watch === undefined) return
    const now = new Date().toISOString()
    if (watch.lastOk !== ok) watch.since = now
    watch.lastOk = ok
    watch.lastReason = reason
    watch.lastCheckedAt = now
    watch.history.push({ ts: now, ok, reason })
    if (watch.history.length > 20) watch.history.shift()
  }

  remove(owner: string, site: string): boolean {
    const key = SessionWatchRegistry.key(owner, site)
    const watch = this.watches.get(key)
    if (watch === undefined) return false
    clearInterval(watch.timer)
    this.watches.delete(key)
    return true
  }

  list(): Array<Omit<SessionWatch, 'timer'>> {
    return [...this.watches.values()].map(({ timer, ...rest }) => {
      void timer
      return rest
    })
  }

  stopAll(): void {
    for (const watch of this.watches.values()) clearInterval(watch.timer)
    this.watches.clear()
  }
}

export interface SessionEnv {
  config: ConstellationConfig
  sessionFor: (owner: string) => BrowserSession
  budget?: import('./budget.js').BudgetGuard
  scope?: import('../scope.js').ScopeGuard
}

/** ---------------- session_keepalive (round-7 gap list §5) ----------------
 *  Measured twice: Google test accounts verify SIGNED IN then are signed out
 *  ~20 minutes later; session_watch observes, nothing acts. A keepalive tick
 *  is an account-owned VISIT (verifySessionOnce's throwaway tab, mode
 *  "visit") or a no-navigation state read (mode "noop" against the owner's
 *  current page). HONESTY REQUIREMENT (from the advice, verbatim in spirit):
 *  if the sign-out is server-side, no keepalive prevents it — the
 *  deliverable is the MEASURED LIFETIME + the transition alert, and the tool
 *  must not be described as keeping sessions alive when it only watches them
 *  better. */

export type KeepaliveTickState = 'SIGNED_IN' | 'SIGNED_OUT' | 'SKIPPED_BUDGET' | 'ERROR'

export interface KeepaliveEntry {
  owner: string
  site: string
  mode: 'visit' | 'noop'
  everyS: number
  startedAt: string
  lastState?: KeepaliveTickState
  lastSignedInAt?: string
  lastTickAt?: string
  ticks: number
  timer: ReturnType<typeof setInterval>
}

export class KeepaliveRegistry {
  private entries = new Map<string, KeepaliveEntry>()
  /** Keys with a tick in flight — a tick must never interleave with a lane's navigation. */
  private inFlight = new Set<string>()

  static key(owner: string, site: string): string { return `${owner}::${site}` }

  inFlightGuard(key: string): boolean {
    if (this.inFlight.has(key)) return false
    this.inFlight.add(key)
    return true
  }

  releaseFlight(key: string): void { this.inFlight.delete(key) }

  add(entry: Omit<KeepaliveEntry, 'ticks'>): KeepaliveEntry {
    this.remove(entry.owner, entry.site)
    const full: KeepaliveEntry = { ...entry, ticks: 0 }
    this.entries.set(KeepaliveRegistry.key(entry.owner, entry.site), full)
    return full
  }

  get(owner: string, site: string): KeepaliveEntry | undefined {
    return this.entries.get(KeepaliveRegistry.key(owner, site))
  }

  record(owner: string, site: string, state: KeepaliveTickState): 'STOP' | 'CONTINUE' {
    const entry = this.get(owner, site)
    if (entry === undefined) return 'STOP'
    entry.ticks += 1
    entry.lastTickAt = new Date().toISOString()
    entry.lastState = state
    if (state === 'SIGNED_IN') entry.lastSignedInAt = entry.lastTickAt
    return 'CONTINUE'
  }

  /** Measured signed-in lifetime: first tick → last SIGNED_IN tick. */
  lifetime(entry: KeepaliveEntry): string {
    if (entry.lastSignedInAt === undefined) return '(never signed in during this keepalive)'
    const ms = Date.parse(entry.lastSignedInAt) - Date.parse(entry.startedAt)
    const min = Math.max(0, Math.round(ms / 60_000))
    return `${min} min (first tick → last SIGNED_IN tick)`
  }

  remove(owner: string, site: string): boolean {
    const key = KeepaliveRegistry.key(owner, site)
    const entry = this.entries.get(key)
    if (entry === undefined) return false
    clearInterval(entry.timer)
    this.entries.delete(key)
    return true
  }

  list(): Array<Omit<KeepaliveEntry, 'timer'>> {
    return [...this.entries.values()].map(({ timer, ...rest }) => {
      void timer
      return rest
    })
  }

  stopAll(): void {
    for (const entry of this.entries.values()) clearInterval(entry.timer)
    this.entries.clear()
  }
}

function appendKeepaliveTick(config: ConstellationConfig, line: Record<string, unknown>): void {
  try {
    fs.mkdirSync(config.rootDir, { recursive: true })
    fs.appendFileSync(path.join(config.rootDir, 'session-keepalive.jsonl'), JSON.stringify({ ts: new Date().toISOString(), ...line }) + '\n')
  } catch { /* best effort */ }
}

/** One verification pass against a live owner session, shared by
 *  session_verify AND inject_run's per-variant session gate (smoke round 3:
 *  Google test accounts die in ~20 minutes — a sweep must check before each
 *  variant or a session expiry silently deflates the hit-rate). Opens and
 *  closes its own tab, so leases on the caller's tabs are untouched. */
export async function verifySessionOnce(
  config: ConstellationConfig,
  sessionFor: (owner: string) => BrowserSession,
  ownerRaw: string | undefined,
  site: string,
  /** Run-9 §2 widening: the proof visit navigates an agent-set URL — it
   *  re-enters the scope guard like every other navigation, including the
   *  landed-URL check (a redirect chain must not cross the boundary here
   *  either). Optional so non-tool callers keep compiling. */
  scope?: import('../scope.js').ScopeGuard,
): Promise<{ ok: boolean; reason: string; rule: SessionProofRule; owner: string }> {
  const rules = loadProofRules(config)
  const rule = rules[site]
  if (rule === undefined) {
    const known = Object.keys(rules).join(', ')
    throw new Error(`no proof rule for site "${site}" — add one with session_proof_set (known: ${known}). Verification without a site-specific proof is what produced the run-7 false green`)
  }
  const who = ownerRaw === undefined || ownerRaw.trim() === '' ? SHARED_OWNER : ownerRaw.trim()
  scope?.assert(rule.url, who, 'session_verify')
  const session = sessionFor(who)
  const context = await session.ensure()
  const page = await context.newPage()
  try {
    await page.goto(rule.url, { waitUntil: 'domcontentloaded', timeout: 30_000 })
    const landed = page.url()
    const decision = scope?.check(landed, who)
    if (scope !== undefined && decision !== undefined && !decision.allowed) {
      scope.audit(landed, who, 'session_verify(redirect)', decision)
      throw new Error(`SCOPE DENIED on redirect: proof visit to ${rule.url} landed on ${landed} — ${decision.reason}`)
    }
    await page.waitForTimeout(1200)
    const text = await page.evaluate(() => document.body?.innerText ?? '')
    const verdict = evaluateProof(rule, text)
    return { ...verdict, rule, owner: who }
  } finally {
    await page.close().catch(() => undefined)
  }
}

export function registerSessionTools(server: ToolRegistrar, env: SessionEnv, watches: SessionWatchRegistry, keepalives: KeepaliveRegistry): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  /** One verification pass against a live owner session (opens + closes its
   *  own tab, so leases on the caller's tabs are untouched). */
  const verifyOnce = (ownerRaw: string | undefined, site: string) =>
    verifySessionOnce(env.config, env.sessionFor, ownerRaw, site, env.scope)

  /** One keepalive tick. Visit mode = verifySessionOnce (a throwaway tab at
   *  the proof surface — an actual account-owned visit, budget-counted); noop
   *  mode = read the owner's CURRENT page and evaluate the rule against it
   *  (no navigation; a mid-load read retries once after 2 s). */
  const keepaliveTick = async (owner: string, site: string, mode: 'visit' | 'noop'): Promise<void> => {
    const key = KeepaliveRegistry.key(owner, site)
    if (!keepalives.inFlightGuard(key)) return
    try {
      const session = env.sessionFor(owner)
      if (session.context === undefined) {
        keepalives.remove(owner, site)
        appendKeepaliveTick(env.config, { owner, site, mode, state: 'STOPPED', reason: 'browser session closed — keepalive stopped' })
        return
      }
      let ok = false
      let reason = ''
      if (mode === 'visit') {
        if (env.budget !== undefined) {
          try { env.budget.spend(owner) } catch {
            appendKeepaliveTick(env.config, { owner, site, mode, state: 'SKIPPED_BUDGET', reason: 'budget exhausted — tick skipped, keepalive continues' })
            keepalives.record(owner, site, 'SKIPPED_BUDGET')
            return
          }
        }
        ;({ ok, reason } = await verifyOnce(owner, site))
      } else {
        const rule = loadProofRules(env.config)[site]
        if (rule === undefined) {
          keepalives.remove(owner, site)
          appendKeepaliveTick(env.config, { owner, site, mode, state: 'STOPPED', reason: `no proof rule for "${site}"` })
          return
        }
        const read = async (): Promise<{ ok: boolean; reason: string }> => {
          const page = await session.currentPage()
          const text = await page.evaluate(() => document.body?.innerText ?? '')
          return evaluateProof(rule, text)
        }
        ;({ ok, reason } = await read())
        if (!ok) {
          // The page may be mid-navigation (a lane's own work) — one retry
          // after a settle beats a false SIGNED_OUT transition.
          await new Promise(resolve => setTimeout(resolve, 2_000))
          ;({ ok, reason } = await read())
        }
      }
      const state: KeepaliveTickState = ok ? 'SIGNED_IN' : 'SIGNED_OUT'
      const prev = keepalives.get(owner, site)?.lastState
      appendKeepaliveTick(env.config, { owner, site, mode, state, reason })
      keepalives.record(owner, site, state)
      if (prev === 'SIGNED_IN' && state === 'SIGNED_OUT') {
        const entry = keepalives.get(owner, site)
        appendKeepaliveTick(env.config, { owner, site, mode, state: 'TRANSITION', reason: 'SIGNED IN → SIGNED OUT', lifetime: entry !== undefined ? keepalives.lifetime(entry) : '?' })
        keepalives.remove(owner, site) // the transition IS the deliverable; stop cleanly
      }
    } catch (error) {
      const reasonText = error instanceof Error ? error.message : String(error)
      appendKeepaliveTick(env.config, { owner, site, mode, state: 'ERROR', reason: reasonText })
      keepalives.record(owner, site, 'ERROR')
      if (/failed to launch|no proof rule|Target page|Browser has been closed/i.test(reasonText)) {
        keepalives.remove(owner, site) // no orphan timers
      }
    } finally {
      keepalives.releaseFlight(key)
    }
  }

  t('session_verify', 'Verify one owner\'s session against a PER-SITE PROOF RULE (run-8 §3): renders the site\'s account-owned surface in its own throwaway tab and asserts must_contain/must_not_contain. `myaccount.google.com` accepting a session is NOT proof that Gemini accepts it — that false green cost two run-7 lanes two hours; each site needs its own rule.',
    { owner: z.string().describe('Owner whose session to verify'), site: z.string().describe('Proof-rule key, e.g. "google-gemini" (session_proof_set adds rules)') },
    async ({ owner, site }: any) => {
      const result = await verifyOnce(owner, site)
      watches.record(result.owner, site, result.ok, result.reason)
      return textResult([
        result.ok
          ? `SIGNED IN — proof "${result.rule.name}" passed for "${result.owner}" (${site})`
          : `NOT SIGNED IN (or the wrong surface rendered) for "${result.owner}" on ${site}: ${result.reason}`,
        `proof rule: ${result.rule.name} — ${result.rule.url}`,
      ].join('\n'), !result.ok)
    })

  t('session_watch', 'Poll a session\'s proof rule every N seconds so a lane learns its session died at request 3, not request 30 (run-8 §3). Results and transitions are visible via session_status; the poll opens a throwaway tab each cycle. Keep the interval ≥30s.',
    { owner: z.string(), site: z.string(), interval_s: z.number().int().optional().describe('Default 60, min 30') },
    async ({ owner, site, interval_s }: any) => {
      const interval = Math.max(interval_s ?? 60, 30)
      if (watches.list().length >= 20) throw new Error('20 session watches already running — session_watch_stop one first')
      const first = await verifyOnce(owner, site)
      watches.record(first.owner, site, first.ok, first.reason)
      const timer = setInterval(() => {
        void verifyOnce(owner, site)
          .then(result => watches.record(result.owner, site, result.ok, result.reason))
          .catch((error: unknown) => watches.record(owner, site, false, `verify failed: ${error instanceof Error ? error.message : String(error)}`))
      }, interval * 1000)
      timer.unref()
      const watch = watches.add({ owner: first.owner, site, intervalS: interval, timer, lastOk: first.ok, lastReason: first.reason, lastCheckedAt: new Date().toISOString(), since: new Date().toISOString() })
      return textResult(`Watching "${first.owner}" × ${site} every ${interval}s — currently ${first.ok ? 'SIGNED IN' : `NOT SIGNED IN (${first.reason})`}. session_status reads transitions.`)
    })

  t('session_status', 'Live session health: every watch (owner × site), its current state, and when that state began — plus one-shot verification via session_verify, and every running keepalive with its measured lifetime. The run-8 answer to "the lane discovered its session was dead at request 30".',
    {},
    async () => {
      const rows = watches.list()
      const keepaliveRows = keepalives.list()
      if (rows.length === 0 && keepaliveRows.length === 0) return textResult('(no session watches or keepalives — session_watch {owner, site} starts one; session_verify is the one-shot)')
      const lines: string[] = []
      for (const row of rows) {
        lines.push(`${row.owner} × ${row.site}: ${row.lastOk === true ? 'SIGNED IN' : 'NOT SIGNED IN'} since ${row.since ?? '?'} (checked ${row.lastCheckedAt ?? '?'})${row.lastOk === false ? ` — ${row.lastReason ?? ''}` : ''}`)
      }
      for (const row of keepaliveRows) {
        lines.push(`keepalive ${row.owner} × ${row.site} (${row.mode}, every ${row.everyS}s): last ${row.lastState ?? '?'} at ${row.lastTickAt ?? '?'} · ${row.ticks} tick(s) · lifetime so far ${keepalives.get(row.owner, row.site) ? keepalives.lifetime(keepalives.get(row.owner, row.site)!) : '?'}`)
      }
      return textResult(lines.join('\n'))
    })

  t('session_watch_stop', 'Stop one session watch.',
    { owner: z.string(), site: z.string() },
    async ({ owner, site }: any) =>
      textResult(watches.remove(owner, site) ? `Stopped watching "${owner}" × ${site}.` : `No watch for "${owner}" × ${site}.`, ))

  t('session_proof_set', 'Add or replace a per-site proof rule (persisted to session-proofs.json): the account-owned surface that PROVES this site\'s session, as must_contain/must_not_contain text assertions. Always pick a surface the SIGNED-IN product renders — not a shared account page (the run-7 trap). `remove: true` deletes a rule.',
    {
      site: z.string().describe('Rule key, e.g. "google-gemini" or "mattermost"'),
      name: z.string().optional().describe('Human label, e.g. "Mattermost (direct messages)"'),
      url: z.string().optional().describe('Account-owned surface URL'),
      must_contain: z.array(z.string()).optional(),
      must_not_contain: z.array(z.string()).optional(),
      remove: z.boolean().optional(),
    },
    async ({ site, name, url, must_contain, must_not_contain, remove }: any) => {
      const file = path.join(env.config.rootDir, 'session-proofs.json')
      let parsed: Record<string, unknown> = {}
      try { parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, unknown> } catch { /* first rule */ }
      if (remove === true) {
        parsed[site] = { remove: true }
      } else {
        if (url === undefined) throw new Error('url is required (the account-owned surface)')
        parsed[site] = { ...(name !== undefined ? { name } : {}), url, ...(must_contain !== undefined ? { must_contain } : {}), ...(must_not_contain !== undefined ? { must_not_contain } : {}) }
      }
      fs.mkdirSync(env.config.rootDir, { recursive: true })
      fs.writeFileSync(file, JSON.stringify(parsed, null, 2) + '\n')
      const rules = loadProofRules(env.config)
      return textResult(remove === true
        ? `Removed proof rule "${site}" (known now: ${Object.keys(rules).join(', ') || 'none'})`
        : `Proof rule "${site}" saved: ${rules[site]?.name} — ${url}. Verify with session_verify {owner, site:"${site}"}.`)
    })

  t('session_keepalive', 'Periodic account-owned visit against a proof rule (round-7 §5): every ≥300 s, mode "visit" opens a throwaway tab at the proof surface (an actual visit — budget-counted) and asserts the rule; mode "noop" only reads the owner\'s current page. MEASURES the session\'s real lifetime and fires a TRANSITION record (session-keepalive.jsonl) the moment it dies — HONEST LIMIT: if the sign-out is server-side (the measured ~20-minute Google behavior), no keepalive prevents it; the deliverable is the measured lifetime + the alert, not a promise. Stops cleanly on the transition, on browser close, or via session_keepalive_stop. No arguments lists active keepalives.',
    {
      owner: z.string().optional().describe('Owner whose session to keep measuring'),
      site: z.string().optional().describe('Proof-rule key (session_proof_set adds rules)'),
      every_s: z.number().int().optional().describe('Tick interval, default 600, FLOOR 300 (login-protection politeness)'),
      mode: z.enum(['visit', 'noop']).optional().describe('visit = navigate the proof surface (default); noop = read the current page only'),
    },
    async ({ owner, site, every_s, mode }: any) => {
      if (owner === undefined || site === undefined) {
        const rows = keepalives.list()
        return textResult(rows.length === 0
          ? '(no keepalives — session_keepalive {owner, site} starts one; ticks log to session-keepalive.jsonl)'
          : rows.map(row => `${row.owner} × ${row.site} (${row.mode}, every ${row.everyS}s): last ${row.lastState ?? '?'} at ${row.lastTickAt ?? '?'} · ${row.ticks} tick(s)`).join('\n'))
      }
      const tickMode = mode ?? 'visit'
      const interval = Math.max(every_s ?? 600, 300)
      if (keepalives.list().length >= 10) throw new Error('10 keepalives already running — session_keepalive_stop one first')
      const first = await verifyOnce(owner, site)
      if (!first.ok) {
        return textResult([
          `NOT starting: "${first.owner}" is NOT signed in on ${site} (${first.reason}).`,
          'A keepalive measures a LIVE session\'s lifetime — sign in (and session_verify) first; starting from signed-out would measure nothing.',
        ].join('\n'), true)
      }
      const timer = setInterval(() => { void keepaliveTick(first.owner, site, tickMode) }, interval * 1000)
      timer.unref()
      keepalives.add({ owner: first.owner, site, mode: tickMode, everyS: interval, startedAt: new Date().toISOString(), lastState: 'SIGNED_IN', lastSignedInAt: new Date().toISOString(), lastTickAt: new Date().toISOString(), timer })
      appendKeepaliveTick(env.config, { owner: first.owner, site, mode: tickMode, state: 'SIGNED_IN', reason: 'keepalive started (initial verify passed)' })
      return textResult([
        `Keepalive ON: "${first.owner}" × ${site} every ${interval}s (${tickMode}) — currently SIGNED IN.`,
        `Measuring lifetime and visiting the proof surface each tick; the TRANSITION record fires the moment the session dies (watch it in session_status / session-keepalive.jsonl).`,
        `Honest limit: a server-side sign-out (~20 min on Google test accounts) will NOT be prevented — this measures and alerts, it does not promise to keep the session alive.`,
      ].join('\n'))
    })

  t('session_keepalive_stop', 'Stop one session keepalive (it also stops itself on the signed-in→signed-out transition or browser close).',
    { owner: z.string(), site: z.string() },
    async ({ owner, site }: any) => {
      const entry = keepalives.get(owner, site)
      const lifetime = entry !== undefined ? keepalives.lifetime(entry) : ''
      return textResult(keepalives.remove(owner, site)
        ? `Stopped keepalive "${owner}" × ${site}. Measured lifetime: ${lifetime}.`
        : `No keepalive for "${owner}" × ${site}.`, )
    })
}
