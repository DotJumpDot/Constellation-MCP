import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

/**
 * Execution fence for the escape hatch (ARTEX-mining mechanism 4,
 * 2026-11-20 — clean-room; see docs/research/artex-mining-2026-11-20.md §4).
 *
 * browser_run_code_unsafe runs agent-authored JS server-side with the full
 * Playwright Page API AND Node `require` — an unfenced surface that already
 * produced window spam and STILL_RUNNING zombies. The fence is a deny-
 * pattern gate at the TOP of the tool (before the code is ever compiled):
 *
 * - Built-in denies can never be exempted: shelling out
 *   (require/import of child_process — that is where scanner binaries and
 *   arbitrary commands would enter), killing the MCP server itself
 *   (process.exit), window spam (window.open — the tab registry, leases
 *   and the ownership label do not see new windows), and busy-wait zombies
 *   (bare while(true)/for(;;) — D11 timeouts never stop the code, so a
 *   busy-wait burns a CPU forever).
 * - CONSTELLATION_UNSAFE_DENY adds patterns (semicolon-separated regex
 *   sources); CONSTELLATION_UNSAFE_ALLOW may exempt ONLY user-added
 *   denies, never the built-ins — allow matches less, deny matches more
 *   (ARTEX's rule-strength asymmetry).
 * - Every decision appends <rootDir>/fence-audit.jsonl (ts, owner,
 *   verdict, rule, code sha256 + size — the code itself never enters the
 *   audit, same discipline as the evidence chain's values).
 */

export interface FenceRule {
  name: string
  re: RegExp
  builtin: boolean
}

export const BUILTIN_DENIES: readonly FenceRule[] = [
  { name: 'child_process (shell/scanner escape — no arbitrary binaries from the escape hatch)', re: /\b(?:require\s*\(\s*|import\s*\(\s*|from\s+)['"](?:node:)?child_process['"]/, builtin: true },
  { name: 'process.exit (would kill the MCP server itself)', re: /\bprocess\.exit\s*\(/, builtin: true },
  { name: 'window.open (spawns windows the tab registry, leases and ownership label cannot see — use browser_tabs new / tab_open)', re: /\bwindow\.open\s*\(/, builtin: true },
  { name: 'bare busy-wait (a timeout never stops escape-hatch code — while(true)/for(;;) burns a CPU forever)', re: /\bwhile\s*\(\s*(?:!{0,2})\s*(?:true|1)\s*\)\s*\{|\bfor\s*\(\s*;{2}\s*\)\s*\{/, builtin: true },
]

export interface FenceVerdict {
  allowed: boolean
  rule?: string
  message?: string
}

/** Split the semicolon-separated env form (';'-joined regex sources). */
export function parsePatternList(raw: string | undefined): string[] {
  return (raw ?? '').split(';').map(part => part.trim()).filter(part => part !== '')
}

function compilePatterns(raw: string | undefined): FenceRule[] {
  const out: FenceRule[] = []
  for (const source of parsePatternList(raw)) {
    try { out.push({ name: `user deny /${source}/`, re: new RegExp(source, 'i'), builtin: false }) } catch { /* an unparseable pattern is skipped — the fence never widens on bad input */ }
  }
  return out
}

/**
 * Decide one escape-hatch call. Order: built-in denies (nothing exempts),
 * user denies (CONSTELLATION_UNSAFE_ALLOW may exempt those and only
 * those), else allowed. The deny message uses platform-control framing so
 * the lane does not mistake it for a target-side defense to bypass.
 */
export function checkUnsafeCode(code: string, deny?: string, allow?: string): FenceVerdict {
  for (const rule of BUILTIN_DENIES) {
    if (rule.re.test(code))
      return {
        allowed: false,
        rule: rule.name,
        message: `[constellation fence — platform policy, NOT a target defense] this browser_run_code_unsafe call was REFUSED: ${rule.name}. This operation class is forbidden at the platform level — rewriting the call will not help; use the guarded tools or express the step without it. (The refusal is audited in fence-audit.jsonl.)`,
      }
  }
  const userDenies = compilePatterns(deny)
  const allows = compilePatterns(allow)
  for (const rule of userDenies) {
    if (!rule.re.test(code)) continue
    if (allows.some(a => a.re.test(code))) continue // user allow exempts user denies only
    return {
      allowed: false,
      rule: rule.name,
      message: `[constellation fence — platform policy, NOT a target defense] this browser_run_code_unsafe call matched an operator deny rule (${rule.name}) and was REFUSED. Rewriting the call will not help; CONSTELLATION_UNSAFE_ALLOW can exempt operator rules only if the operator chooses to.`,
    }
  }
  return { allowed: true }
}

/** Append the decision to the fence audit — sha256 + size of the code,
 *  never its content. */
export function auditFence(rootDir: string, owner: string, code: string, verdict: FenceVerdict): void {
  try {
    const file = path.join(rootDir, 'fence-audit.jsonl')
    fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.appendFileSync(file, JSON.stringify({
      ts: new Date().toISOString(),
      owner,
      verdict: verdict.allowed ? 'allowed' : 'denied',
      ...(verdict.rule !== undefined ? { rule: verdict.rule } : {}),
      code_sha256: createHash('sha256').update(code).digest('hex'),
      bytes: code.length,
    }) + '\n')
  } catch { /* best effort — the fence never breaks a tool call */ }
}
