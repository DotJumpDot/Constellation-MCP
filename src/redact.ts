/**
 * Secret redaction for tool output (run-5 advice §1): a Playwright error's
 * call log can echo the page's own Authorization/token lines, and once such a
 * value reaches the transcript it lives there forever. Redaction runs at the
 * tool-result boundary (errorResult), not in each tool.
 */

import './browser/page-dom.js'

/** Header-ish `key: value` / `key=value` pairs whose value is a secret. The
 *  key match tolerates dotted call-log prefixes (`request.headers.authorization`);
 *  the lead char keeps a URL path like `/tokens/abc123` out of the key match. */
const SECRET_KEY_RE = /((?:^|[\s[({,;&?"']))([A-Za-z0-9._-]*(?:(?:authorization|cookie|api[-_]?key|apikey|token|secret|password|passwd|pwd|session[-_]?id)[A-Za-z0-9._-]*))(\s*[=:]\s*)((?:bearer|basic|token)\s+)?("[^"\n]*"|'[^'\n]*'|[^\s,;&)"']+)/gi

/** JSON-body style `"secretKey": "value"` — quotes sit inside the lead/sep, so
 *  the general key regex never sees them. */
const JSON_KEY_RE = /["']([A-Za-z0-9._-]*(?:(?:authorization|api[-_]?key|apikey|token|secret|password|passwd|pwd)[A-Za-z0-9._-]*))["']\s*:\s*["']([^"'\n]{2,})["']/gi

/** Long base64-ish runs: 48+ chars of token alphabet — inside an error text
 *  that is a credential, not prose (run-5: an app access token echoed back). */
const LONG_TOKEN_RE = /\b[A-Za-z0-9+/_-]{48,}={0,2}\b/g

/** JSON Web Tokens: three dotted base64url segments. */
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g

/** `Bearer`/`Basic` scheme credentials. */
const AUTH_SCHEME_RE = /\b(bearer|basic|token)\s+([A-Za-z0-9._~+/=-]{8,})/gi

function maskValue(value: string): string {
  const head = value.slice(0, 6)
  return value.length <= 8 ? '[redacted]' : `${head}…[redacted]`
}

/** Replace secret-looking values in free text while keeping the shape readable:
 *  a redacted line still tells the agent WHICH header/param carried the value. */
export function redactSecrets(text: string): string {
  let out = text.replace(JSON_KEY_RE, (_all, key: string, value: string) => `"${key}": "${maskValue(value)}"`)
  out = out.replace(SECRET_KEY_RE, (_all, lead: string, key: string, sep: string, scheme: string | undefined, value: string) =>
    `${lead}${key}${sep}${scheme === undefined ? '' : scheme}${maskValue(value)}`)
  out = out.replace(JWT_RE, '[redacted-jwt]')
  out = out.replace(AUTH_SCHEME_RE, (_all, scheme: string, value: string) => {
    // `token authentication failed` is prose, not a credential: a scheme value
    // must carry token punctuation/digits or be long enough that prose is out.
    if (/^[A-Za-z]+$/.test(value) && value.length < 20) return `${scheme} ${value}`
    return `${scheme} ${maskValue(value)}`
  })
  out = out.replace(LONG_TOKEN_RE, '[redacted]')
  return out
}

/** Replace every occurrence of each known secret value (run-5 advice §6):
 *  password-field values collected from the live DOM are matched literally in
 *  snapshot text. Short values are skipped — a 2-char match would corrupt the
 *  snapshot more than it protects. A non-array secrets value is ignored, not
 *  thrown on: one bad probe result must never take the whole snapshot down
 *  (run-7 advice P0-3). */
export function maskSecrets(text: string, secrets: readonly string[], replacement = '••••••'): string {
  if (!Array.isArray(secrets)) return text
  let out = text
  for (const secret of secrets) {
    if (typeof secret !== 'string' || secret.length < 4) continue
    out = out.split(secret).join(replacement)
  }
  return out
}

/** DOM probe run inside the page: every non-empty password-field value.
 *  Expressed as a real closure-free function so Playwright always CALLS it —
 *  the previous string form let page.evaluate return the function object
 *  itself, and every snapshot then died on "secrets is not iterable". */
export function passwordValuesProbe(): string[] {
  const values = new Set<string>()
  for (const el of document.querySelectorAll('input[type="password"], input[autocomplete="current-password"], input[autocomplete="new-password"]')) {
    const value = el.value ?? ''
    if (value !== '') values.add(value)
  }
  return [...values]
}
