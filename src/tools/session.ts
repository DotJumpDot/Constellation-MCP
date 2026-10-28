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
}

export function registerSessionTools(server: ToolRegistrar, env: SessionEnv, watches: SessionWatchRegistry): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  /** One verification pass against a live owner session (opens + closes its
   *  own tab, so leases on the caller's tabs are untouched). */
  const verifyOnce = async (ownerRaw: string | undefined, site: string): Promise<{ ok: boolean; reason: string; rule: SessionProofRule; owner: string }> => {
    const rules = loadProofRules(env.config)
    const rule = rules[site]
    if (rule === undefined) {
      const known = Object.keys(rules).join(', ')
      throw new Error(`no proof rule for site "${site}" — add one with session_proof_set (known: ${known}). Verification without a site-specific proof is what produced the run-7 false green`)
    }
    const who = ownerRaw === undefined || ownerRaw.trim() === '' ? SHARED_OWNER : ownerRaw.trim()
    const session = env.sessionFor(who)
    const context = await session.ensure()
    const page = await context.newPage()
    try {
      await page.goto(rule.url, { waitUntil: 'domcontentloaded', timeout: 30_000 })
      await page.waitForTimeout(1200)
      const text = await page.evaluate(() => document.body?.innerText ?? '')
      const verdict = evaluateProof(rule, text)
      return { ...verdict, rule, owner: who }
    } finally {
      await page.close().catch(() => undefined)
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

  t('session_status', 'Live session health: every watch (owner × site), its current state, and when that state began — plus one-shot verification via session_verify. The run-8 answer to "the lane discovered its session was dead at request 30".',
    {},
    async () => {
      const rows = watches.list()
      if (rows.length === 0) return textResult('(no session watches — session_watch {owner, site} starts one; session_verify is the one-shot)')
      return textResult(rows.map(row =>
        `${row.owner} × ${row.site}: ${row.lastOk === true ? 'SIGNED IN' : 'NOT SIGNED IN'} since ${row.since ?? '?'} (checked ${row.lastCheckedAt ?? '?'})${row.lastOk === false ? ` — ${row.lastReason ?? ''}` : ''}`,
      ).join('\n'))
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
}
