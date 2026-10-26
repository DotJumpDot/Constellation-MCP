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

/** URL entry form: `host` or `host/path-prefix/`. */
export function entryMatches(entry: string, url: URL): boolean {
  const slash = entry.indexOf('/')
  const hostPart = (slash === -1 ? entry : entry.slice(0, slash)).trim().toLowerCase()
  const pathPart = slash === -1 ? '' : entry.slice(slash)
  if (!hostPatternMatches(hostPart, url.hostname)) return false
  if (pathPart === '') return true
  return url.pathname.startsWith(pathPart)
}

const LOCAL_SCHEMES = new Set(['data', 'blob', 'about', 'javascript', 'view-source'])

export function normalizeUrl(raw: string): URL {
  try {
    return new URL(raw)
  } catch {
    return new URL(`https://${raw}`)
  }
}

export function evaluateScope(rule: ScopeRule | null, rawUrl: string): ScopeDecision {
  let url: URL
  try {
    url = normalizeUrl(rawUrl)
  } catch {
    return { allowed: false, reason: `unparseable URL: ${rawUrl}` }
  }
  if (LOCAL_SCHEMES.has(url.protocol.replace(':', '')))
    return { allowed: true, reason: `${url.protocol} is a local scheme (no network)` }
  if (rule === null) return { allowed: true, reason: 'no scope set (unrestricted)' }
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
    reason: `${host} is not in the declared scope (${rule.in_scope.join(', ') || 'empty'}) — call scope_set first or ask the Lead`,
    engagement: rule.engagement,
  }
}

export class ScopeGuard {
  private rule: ScopeRule | null

  constructor(private scopeFile: string, private auditFile: string) {
    try {
      this.rule = JSON.parse(fs.readFileSync(scopeFile, 'utf8')) as ScopeRule
    } catch {
      this.rule = null
    }
  }

  current(): ScopeRule | null {
    return this.rule
  }

  set(rule: ScopeRule): void {
    this.rule = rule
    fs.writeFileSync(this.scopeFile, JSON.stringify(rule, null, 2) + '\n')
  }

  check(rawUrl: string): ScopeDecision {
    return evaluateScope(this.rule, rawUrl)
  }

  /** Enforcement entry point: throws with a refusal message when denied.
   *  Every decision is audited, allow and deny alike. */
  assert(rawUrl: string, owner: string, tool: string): ScopeDecision {
    const decision = this.check(rawUrl)
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
