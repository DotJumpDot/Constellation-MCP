import fs from 'node:fs'

export interface ScopeRule {
  engagement?: string
  /** Host patterns: `example.com`, `*.example.com`, optionally with a path
   *  prefix (`example.com/api/`). */
  in_scope: string[]
  /** Host patterns always denied even when inside in_scope. */
  out_scope: string[]
}

export interface ScopeDecision {
  allowed: boolean
  reason: string
  engagement?: string
}

export interface ScopeAuditLine {
  ts: string
  owner: string
  tool: string
  url: string
  host: string
  allowed: boolean
  reason: string
}

function hostPatternMatches(pattern: string, host: string): boolean {
  const p = pattern.trim().toLowerCase()
  if (p === '*') return true
  if (p.startsWith('*.')) return host === p.slice(2) || host.endsWith('.' + p.slice(2))
  return host === p
}

/** URL entry form: `host`, `host:port`, `host/path-prefix/`, `host:port/path/`.
 *  A PORT in the entry is PORT-EXACT (round-7 D2: `127.0.0.1:8799` used to
 *  match nothing because entries were compared against the portless hostname —
 *  scope armed, then denied); a portless entry stays port-agnostic as before.
 *  Scheme-default ports resolve (443 ≡ https with no explicit port). */
export function entryMatches(entry: string, url: URL): boolean {
  const slash = entry.indexOf('/')
  const hostPort = (slash === -1 ? entry : entry.slice(0, slash)).trim().toLowerCase()
  const pathPart = slash === -1 ? '' : entry.slice(slash)
  let hostPattern = hostPort
  let port: number | undefined
  const colon = hostPort.lastIndexOf(':')
  // A colon AFTER any ']' is a port ([::1]:8080); a colon inside brackets is
  // part of the address. A non-numeric suffix (e.g. a bare '::1') is left whole.
  if (colon !== -1 && hostPort.indexOf(']') < colon) {
    const maybePort = Number.parseInt(hostPort.slice(colon + 1), 10)
    if (Number.isFinite(maybePort)) {
      port = maybePort
      hostPattern = hostPort.slice(0, colon)
    }
  }
  if (!hostPatternMatches(hostPattern, url.hostname)) return false
  if (port !== undefined) {
    const urlPort = url.port === '' ? (url.protocol === 'https:' ? 443 : 80) : Number.parseInt(url.port, 10)
    if (urlPort !== port) return false
  }
  if (pathPart === '') return true
  return url.pathname.startsWith(pathPart)
}

/** Schemes that never leave the machine (allowed without a scope — they
 *  cannot reach a target host). */
const LOCAL_SCHEMES = new Set(['data', 'blob', 'about'])
/** Schemes navigation must NEVER accept: `file:` reads local disk into the
 *  agent's transcript, `view-source:`/`javascript:` are injection vectors. */
const NAV_DENIED_SCHEMES = new Set(['file', 'view-source', 'javascript', 'chrome', 'devtools', 'edge', 'http+unix', 'https+unix'])
/** The HTTP client speaks exactly these. */
export const HTTP_SCHEMES = new Set(['http', 'https'])

export function normalizeUrl(raw: string): URL {
  try {
    return new URL(raw)
  } catch {
    return new URL(`https://${raw}`)
  }
}

export function evaluateScope(rule: ScopeRule | null, rawUrl: string, options: { requireScope?: boolean } = {}): ScopeDecision {
  let url: URL
  try {
    url = normalizeUrl(rawUrl)
  } catch {
    return { allowed: false, reason: `unparseable URL: ${rawUrl}` }
  }
  const scheme = url.protocol.replace(':', '')
  if (NAV_DENIED_SCHEMES.has(scheme))
    return { allowed: false, reason: `${url.protocol} URLs are never allowed (local-file and injection risk)` }
  if (LOCAL_SCHEMES.has(scheme))
    return { allowed: true, reason: `${url.protocol} is a local scheme (no network)` }
  if (rule === null) {
    if (options.requireScope === true)
      return { allowed: false, reason: 'no scope set and CONSTELLATION_REQUIRE_SCOPE=1 — call scope_set before touching any host' }
    return { allowed: true, reason: 'no scope set (unrestricted)' }
  }
  const host = url.hostname
  for (const entry of rule.out_scope) {
    if (entryMatches(entry, url))
      return { allowed: false, reason: `${host} is explicitly out of scope for ${rule.engagement ?? 'this engagement'}`, engagement: rule.engagement }
  }
  for (const entry of rule.in_scope) {
    if (entryMatches(entry, url))
      return { allowed: true, reason: `${host} is in scope for ${rule.engagement ?? 'this engagement'}`, engagement: rule.engagement }
  }
  return {
    allowed: false,
    // url.host keeps a non-default port (round-7 D2): a port-mismatch denial
    // now shows "127.0.0.1:8800 is not in the declared scope (127.0.0.1:8799)"
    // instead of a portless host that LOOKS like it matches the entry.
    reason: `${url.host} is not in the declared scope (${rule.in_scope.join(', ') || 'empty'}) — call scope_set first or ask the Lead`,
    engagement: rule.engagement,
  }
}

/** The persisted shape: one global rule plus optional per-owner (per-lane)
 *  rules — a 10-teammate run spans 10 engagements, and a single global list
 *  would force every lane into one union scope. */
export interface ScopeFile {
  global: ScopeRule | null
  perOwner: Record<string, ScopeRule>
}

export class ScopeGuard {
  private rule: ScopeRule | null
  private perOwner: Record<string, ScopeRule> = {}

  constructor(private scopeFile: string, private auditFile: string, private requireScope = false) {
    try {
      const parsed = JSON.parse(fs.readFileSync(scopeFile, 'utf8')) as ScopeFile | ScopeRule
      if ('global' in parsed && 'perOwner' in parsed) {
        this.rule = parsed.global
        this.perOwner = parsed.perOwner ?? {}
      } else {
        // v1 single-rule file
        this.rule = parsed as ScopeRule
      }
    } catch {
      this.rule = null
    }
  }

  current(owner?: string): ScopeRule | null {
    if (owner !== undefined && this.perOwner[owner] !== undefined) return this.perOwner[owner]
    return this.rule
  }

  set(rule: ScopeRule, owner?: string): void {
    if (owner === undefined) this.rule = rule
    else this.perOwner[owner] = rule
    this.persist()
  }

  /** Drop the global rule and every per-owner rule (or just one owner's). */
  clear(owner?: string): void {
    if (owner === undefined) {
      this.rule = null
      this.perOwner = {}
    } else {
      delete this.perOwner[owner]
    }
    this.persist()
  }

  owners(): string[] {
    return Object.keys(this.perOwner).sort()
  }

  private persist(): void {
    const file: ScopeFile = { global: this.rule, perOwner: this.perOwner }
    fs.writeFileSync(this.scopeFile, JSON.stringify(file, null, 2) + '\n')
  }

  check(rawUrl: string, owner?: string): ScopeDecision {
    const rule = owner !== undefined && this.perOwner[owner] !== undefined ? this.perOwner[owner]! : this.rule
    return evaluateScope(rule, rawUrl, { requireScope: this.requireScope })
  }

  /** Enforcement entry point: throws with a refusal message when denied.
   *  Per-owner rules win for that owner; everyone else falls back to the
   *  global rule. Every decision is audited, allow and deny alike. */
  assert(rawUrl: string, owner: string, tool: string): ScopeDecision {
    const decision = this.check(rawUrl, owner)
    this.audit(rawUrl, owner, tool, decision)
    if (!decision.allowed)
      throw new Error(`SCOPE DENIED: ${decision.reason}. Requested: ${rawUrl}`)
    return decision
  }

  audit(rawUrl: string, owner: string, tool: string, decision: ScopeDecision): void {
    let host = rawUrl
    try { host = normalizeUrl(rawUrl).hostname } catch { /* keep raw */ }
    const line: ScopeAuditLine = {
      ts: new Date().toISOString(), owner, tool, url: rawUrl, host,
      allowed: decision.allowed, reason: decision.reason,
    }
    try { fs.appendFileSync(this.auditFile, JSON.stringify(line) + '\n') } catch { /* best effort */ }
  }

  auditLines(limit: number, owner?: string): ScopeAuditLine[] {
    let text = ''
    try { text = fs.readFileSync(this.auditFile, 'utf8') } catch { return [] }
    const lines = text.split('\n').filter(l => l.trim() !== '')
    const out: ScopeAuditLine[] = []
    for (let i = lines.length - 1; i >= 0 && out.length < limit; i--) {
      try {
        const parsed = JSON.parse(lines[i]!) as ScopeAuditLine
        if (owner === undefined || parsed.owner === owner) out.push(parsed)
      } catch { /* skip malformed */ }
    }
    return out
  }
}
