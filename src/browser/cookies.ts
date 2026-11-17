/**
 * External-profile cookie import (run-7 advice P0-1).
 *
 * Reads a Chrome/Edge profile's SQLite `Cookies` store directly and decrypts
 * `v10`/`v11` values with the profile's DPAPI-protected `Local State` key —
 * the sanctioned "human's own browser" import path. Decrypted VALUES never
 * enter any tool result: this module returns cookie objects that go straight
 * into `context.addCookies`; the transcript only ever sees names/domains/flags
 * and the audited host list.
 *
 * `v20` (app-bound encryption, Chrome 127+) cannot be decrypted out-of-process
 * by design — those rows surface as a warning pointing at browser_attach (the
 * DBSC-safe route). A profile containing `Default/Network/Device Bound
 * Sessions` is flagged too (P2-12): cookie replay from it will be revoked
 * server-side within minutes.
 */

import { createDecipheriv, createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { DatabaseSync } from 'node:sqlite'

const exec = promisify(execFile)

/** One cookie ready for `context.addCookies` (value included, server-side only). */
export interface ImportedCookie {
  name: string
  value: string
  domain: string
  path: string
  expires?: number
  secure: boolean
  httpOnly: boolean
  sameSite?: 'Strict' | 'Lax' | 'None'
}

export interface ProfileCookieReport {
  cookies: ImportedCookie[]
  /** Distinct hosts actually read (the audited host list — never values). */
  hosts: string[]
  warnings: string[]
  /** True when the profile is Device-Bound-Session bound: replay will be revoked. */
  deviceBoundSessions: boolean
}

/** Chromium's epoch (1601-01-01) to Unix seconds; 0 = session cookie. */
export function chromiumTimeToUnixSeconds(expiresUtc: number): number {
  if (expiresUtc <= 0) return -1
  const seconds = (expiresUtc - 116444736000000000) / 1_000_000
  return Number.isFinite(seconds) && seconds > 0 ? Math.floor(seconds) : -1
}

/** Unix seconds from SQLite-side pre-divided `expires_utc / 1000000` (µs → s).
 * Run-39 §10.1: reading the RAW µs column made node:sqlite throw "Value is
 * too large" on far-future cookies (1.3e16 µs > 2^53) and killed the whole
 * import; dividing INSIDE SQLite keeps every value in safe-integer range
 * (seconds since 1601 ≈ 1.3e10) and the epoch shift is a small subtraction.
 * `expiresSeconds` ≤ 0 = session cookie. Pure; tested. */
export function unixSecondsFromSqlite(expiresSeconds: number): number {
  if (!Number.isFinite(expiresSeconds) || expiresSeconds <= 0) return -1
  const unix = expiresSeconds - 11_644_473_600
  return unix > 0 ? Math.floor(unix) : -1
}

/** Host part of a cookie domain (leading dot stripped, lowercased). */
export function cookieHost(domain: string): string {
  return domain.replace(/^\./, '').toLowerCase()
}

/**
 * Whether a cookie's domain is wanted for the requested domains (run-7 P0-1:
 * `domain: "google.com"` silently omitted host-only `accounts.google.com`
 * cookies). Subdomains count in BOTH directions: a request for google.com
 * includes host-only accounts.google.com; a request for accounts.google.com
 * includes domain cookies scoped to .google.com.
 */
export function cookieMatchesAnyDomain(cookieDomain: string, domains: readonly string[] | undefined): boolean {
  if (domains === undefined || domains.length === 0) return true
  const host = cookieHost(cookieDomain).toLowerCase()
  return domains.some(requested => {
    const want = cookieHost(requested.toLowerCase())
    return host === want || host.endsWith(`.${want}`) || want.endsWith(`.${host}`)
  })
}

/** DPAPI-unprotect one blob via PowerShell (no native addon dependency). */
export async function dpapiUnprotect(encrypted: Buffer): Promise<Buffer> {
  const inFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'constellation-dpapi-')), 'in.b64')
  const outFile = `${inFile}.out`
  try {
    fs.writeFileSync(inFile, encrypted.toString('base64'))
    // Add-Type first: plain powershell.exe 5.1 -NoProfile does NOT auto-load
    // System.Security, so [Security.Cryptography.ProtectedData] is "unable to
    // find type" without it (run-12 field defect — broke every profile_dir
    // import on a stock box; the load is idempotent and free when present).
    const script =
      `Add-Type -AssemblyName System.Security; ` +
      `$in = [IO.File]::ReadAllText('${inFile.replace(/'/g, "''")}'); ` +
      `$out = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($in), $null, 'CurrentUser'); ` +
      `[IO.File]::WriteAllText('${outFile.replace(/'/g, "''")}', [Convert]::ToBase64String($out))`
    await exec('powershell.exe', ['-NoProfile', '-Command', script], { windowsHide: true, timeout: 15_000 })
    return Buffer.from(fs.readFileSync(outFile, 'utf8').trim(), 'base64')
  } finally {
    try { fs.rmSync(path.dirname(inFile), { recursive: true, force: true }) } catch { /* best effort */ }
  }
}

/** Load the profile's AES-256-GCM cookie key from `Local State`. */
export async function loadChromiumCookieKey(stateDir: string): Promise<Buffer> {
  const stateFile = path.join(stateDir, 'Local State')
  const state = JSON.parse(fs.readFileSync(stateFile, 'utf8')) as { os_crypt?: { encrypted_key?: string } }
  const encoded = state.os_crypt?.encrypted_key
  if (typeof encoded !== 'string') throw new Error(`"${stateFile}" has no os_crypt.encrypted_key — is this a Chromium profile?`)
  const raw = Buffer.from(encoded, 'base64')
  if (!raw.subarray(0, 5).equals(Buffer.from('DPAPI', 'utf8')))
    throw new Error('Local State encrypted_key has an unexpected prefix (not DPAPI)')
  const key = await dpapiUnprotect(raw.subarray(5))
  if (key.length !== 32) throw new Error(`decrypted cookie key is ${key.length} bytes, expected 32`)
  return key
}

/** Strip Chrome 130+'s 32-byte SHA-256(host_key) binding prefix when present. */
export function stripHostKeyBinding(plain: Buffer, hostKey: string): string {
  if (plain.length > 32 && createHash('sha256').update(hostKey, 'utf8').digest().equals(plain.subarray(0, 32)))
    return plain.subarray(32).toString('utf8')
  return plain.toString('utf8')
}

/** Decrypt one `encrypted_value` blob. Returns unsupported for `v20`. */
export function decryptCookieValue(encryptedValue: Buffer, key: Buffer, hostKey: string): { value?: string; unsupported?: string } {
  if (encryptedValue.length === 0) return { value: '' }
  const prefix = encryptedValue.subarray(0, 3).toString('utf8')
  if (prefix === 'v10' || prefix === 'v11') {
    const nonce = encryptedValue.subarray(3, 15)
    const cipher = encryptedValue.subarray(15, -16)
    const tag = encryptedValue.subarray(-16)
    const decipher = createDecipheriv('aes-256-gcm', key, nonce)
    decipher.setAuthTag(tag)
    const plain = Buffer.concat([decipher.update(cipher), decipher.final()])
    return { value: stripHostKeyBinding(plain, hostKey) }
  }
  if (prefix === 'v20')
    return { unsupported: 'app-bound encryption (v20)' }
  // Chrome <=80: a raw DPAPI blob.
  return { unsupported: 'legacy raw DPAPI value' }
}

export interface ProfileLayout {
  /** Directory containing `Local State`. */
  stateDir: string
  /** SQLite Cookies file. */
  cookiesFile: string
  /** Profile label for messages ('Default', a named profile, or '(direct)'). */
  profileLabel: string
}

/** Accept a user-data-dir (has Local State + Default/), a profile dir (has
 *  Cookies), or a Network dir; resolve the actual layout. */
export function resolveProfileLayout(profileDir: string): ProfileLayout {
  const candidates: ProfileLayout[] = [
    { stateDir: profileDir, cookiesFile: path.join(profileDir, 'Cookies'), profileLabel: '(direct)' },
    { stateDir: path.dirname(profileDir), cookiesFile: path.join(profileDir, 'Network', 'Cookies'), profileLabel: path.basename(profileDir) },
    { stateDir: path.dirname(profileDir), cookiesFile: path.join(profileDir, 'Cookies'), profileLabel: path.basename(profileDir) },
    { stateDir: profileDir, cookiesFile: path.join(profileDir, 'Default', 'Network', 'Cookies'), profileLabel: 'Default' },
    { stateDir: profileDir, cookiesFile: path.join(profileDir, 'Default', 'Cookies'), profileLabel: 'Default' },
  ]
  for (const candidate of candidates) {
    if (fs.existsSync(candidate.cookiesFile)) return candidate
  }
  throw new Error(`no Cookies store under "${profileDir}" — pass the browser's user-data-dir (contains "Local State" + "Default") or a profile directory`)
}

/** P2-12: Device Bound Sessions marker in the profile. */
export function detectDeviceBoundSessions(stateDir: string, profileLabel: string): boolean {
  const profileDir = profileLabel === '(direct)' ? stateDir : path.join(stateDir, profileLabel)
  return fs.existsSync(path.join(profileDir, 'Network', 'Device Bound Sessions'))
}

/** Per-origin DBSC probe (run-9 §4: the whole-profile warning fired on a plain
 *  bugcrowd.com export and cost the lanes their platform session). Chrome's
 *  Device Bound Sessions store is a LevelDB whose keys carry the session's
 *  origin — a raw byte scan of the store's files for the requested domain
 *  answers "is THIS domain bound" without a LevelDB reader. Compressed blocks
 *  can hide a match, so a MISS is a hint, not proof; a hit is decisive.
 *  Returns matched domains, or null when the store exists but cannot be read
 *  (locked/empty) — the caller must word that as inconclusive. */
export function deviceBoundSessionsFor(stateDir: string, profileLabel: string, domains: readonly string[]): string[] | null {
  const profileDir = profileLabel === '(direct)' ? stateDir : path.join(stateDir, profileLabel)
  const store = path.join(profileDir, 'Network', 'Device Bound Sessions')
  try {
    const blob = fs.readdirSync(store)
      .filter(f => { try { return !fs.statSync(path.join(store, f)).isDirectory() } catch { return false } })
      .map(f => fs.readFileSync(path.join(store, f)).toString('latin1'))
      .join('\n')
    const found = new Set<string>()
    for (const domain of domains) {
      const host = cookieHost(domain.toLowerCase())
      if (host !== '' && blob.includes(host)) found.add(domain)
    }
    return [...found]
  } catch (error) {
    // Verification #6: a store that does not EXIST is not "unreadable" —
    // Chrome only creates it on the first DBSC registration, so absence
    // means no device-bound sessions were ever recorded (decisive "not
    // bound"), while other failures (locked DB, permissions) stay
    // inconclusive-null.
    const code = (error as NodeJS.ErrnoException).code
    if (code === 'ENOENT') return []
    return null
  }
}

/** Warning lines for a DBSC-marked profile, naming the exact signal and
 *  scoped to the domains the caller actually asked for (run-9 §4 — "the
 *  warning fired" must never again read as "the handoff is doomed" when the
 *  bound origin is unrelated to the request). */
export function dbscWarningLines(stateDir: string, profileLabel: string, domains: readonly string[] | undefined): string[] {
  if (domains === undefined || domains.length === 0) {
    return ['WARNING (signal: whole-profile "Network/Device Bound Sessions" marker; no domain filter to narrow it): some session in this profile is device-bound and its replay WILL be revoked server-side (Chrome 156+) — use browser_attach for a bound identity']
  }
  const matched = deviceBoundSessionsFor(stateDir, profileLabel, domains)
  if (matched === null) {
    return [`WARNING (signal: whole-profile "Network/Device Bound Sessions" marker; per-origin scan of the store was INCONCLUSIVE — unreadable): treat [${domains.join(', ')}] as possibly bound; if an imported session dies within minutes, switch to browser_attach`]
  }
  if (matched.length > 0) {
    return [`WARNING (signal: per-origin scan of the Device Bound Sessions store MATCHED [${matched.join(', ')}]): replayed cookies for ${matched.join(', ')} WILL be revoked server-side within minutes (Chrome 156+) — use browser_attach for this identity`]
  }
  return [`NOTE (signal: whole-profile "Network/Device Bound Sessions" marker, but the per-origin store scan found NO match for [${domains.join(', ')}]): these cookies are unlikely to be device-bound — proceed with the handoff; if the imported session still dies within minutes, treat it as DBSC and use browser_attach`]
}

function mapSameSite(samesite: number | null | undefined, secure: boolean): ImportedCookie['sameSite'] {
  if (samesite === 1) return 'Lax'
  if (samesite === 2) return 'Strict'
  if (samesite === 0 && secure) return 'None'
  return undefined
}

/** Normalize a caller-supplied domain input to a bare lowercase hostname
 *  (verification round 2026-11-16, defect #1: digest_domains/domain accepted
 *  "https://host/path", "host:8443", ".host" verbatim — the domain matcher
 *  and the DBSC store scan both compare bare hostnames, so anything with a
 *  scheme/port/path silently matched NOTHING and read as "0 cookies, not
 *  bound"). Pure; tested. */
export function normalizeHostInput(raw: string): string {
  const trimmed = raw.trim()
  if (trimmed === '') return ''
  try {
    // new URL keeps a leading dot (".example.com" is a legal hostname to it)
    // and a trailing dot (the FQDN root, "example.com."); cookie matching
    // wants the bare host either way. A wildcard prefix ("*.example.com")
    // is a scope-style entry, not a cookie host — strip it.
    return new URL(/^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`)
      .hostname.toLowerCase().replace(/^\*+\./, '').replace(/^\.+/, '').replace(/\.+$/, '')
  } catch {
    // Not URL-parseable even with a scheme prepended (bare IPv6 etc.) — fall
    // back to a conservative strip: no scheme, no port, no path, no dots.
    return trimmed.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split('/')[0]!.split(':')[0]!.toLowerCase().replace(/^\*+\./, '').replace(/^\.+/, '').replace(/\.+$/, '')
  }
}

/** Partition imported cookie rows for browser_cookies_import (run-44 §8):
 *  Playwright's addCookies aborts the WHOLE batch on the first malformed row
 *  ("Invalid cookie fields"), so one stray row cost lanes a 3-failure tax and
 *  per-domain narrowing was the only route. Here: trivially-fixable fields are
 *  fixed in place (empty sameSite dropped, SQLite samesite ints mapped 0/1/2,
 *  secure forced for SameSite=None, non-numeric expires dropped) and
 *  unimportable rows are dropped WITH a named reason. Pure; tested. */
export interface CookiePartition {
  good: Array<Record<string, unknown>>
  dropped: string[]
  notes: string[]
}
export function partitionCookieRows(rows: Array<Record<string, unknown>>): CookiePartition {
  const good: Array<Record<string, unknown>> = []
  const dropped: string[] = []
  const notes: string[] = []
  for (const original of rows) {
    const row: Record<string, unknown> = { ...original }
    const name = typeof row.name === 'string' ? row.name : ''
    const why = (reason: string): string => `"${name || '(unnamed)'}" ${String(row.domain ?? row.url ?? '?')} — ${reason}`
    if (name === '') { dropped.push(why('no name')); continue }
    if (typeof row.value !== 'string') { dropped.push(why('value is not a string')); continue }
    // Playwright accepts domain OR url as the cookie's host source
    // (verification #13: url-only rows used to be dropped though they
    // import fine).
    const hasDomain = typeof row.domain === 'string' && row.domain !== ''
    const hasUrl = typeof row.url === 'string' && row.url !== ''
    if (!hasDomain && !hasUrl) { dropped.push(why('no domain or url')); continue }
    if (row.sameSite === '') { delete row.sameSite; notes.push(`"${name}": empty sameSite dropped`) }
    else if (row.sameSite !== undefined && !['Strict', 'Lax', 'None'].includes(String(row.sameSite))) {
      const n = Number(row.sameSite)
      if (n === 1 || n === 2) { row.sameSite = n === 1 ? 'Lax' : 'Strict'; notes.push(`"${name}": sameSite ${String(original.sameSite)} → ${String(row.sameSite)}`) }
      else if (n === 0 && row.secure === true) { row.sameSite = 'None'; notes.push(`"${name}": sameSite 0 (secure) → None`) }
      else if (n === 0) { delete row.sameSite; notes.push(`"${name}": sameSite 0 without secure dropped (Chrome would reject the cookie)`) }
      else { delete row.sameSite; notes.push(`"${name}": unrecognized sameSite ${JSON.stringify(original.sameSite)} dropped`) }
    }
    if (row.sameSite === 'None' && row.secure !== true) { row.secure = true; notes.push(`"${name}": secure forced for SameSite=None (None is only valid on secure)`) }
    // Verification #13: NaN is a `number` to typeof — passing it through
    // could abort the whole batch at addCookies. Non-finite expires goes.
    const expiresRaw = row.expires
    if (expiresRaw !== undefined && expiresRaw !== -1
      && (typeof expiresRaw !== 'number' || !Number.isFinite(expiresRaw as number))) {
      delete row.expires
      notes.push(`"${name}": ${typeof expiresRaw === 'number' ? 'non-finite' : 'non-numeric'} expires dropped`)
    }
    good.push(row)
  }
  return { good, dropped, notes }
}

/**
 * Read and decrypt one Chrome/Edge profile's cookies. The SQLite file is
 * copied to a temp dir first (Chrome holds it locked while running); v20 rows
 * are counted into warnings, never into values.
 */
export async function readProfileCookies(profileDir: string, domainFilter?: string[]): Promise<ProfileCookieReport> {
  const layout = resolveProfileLayout(profileDir)
  const warnings: string[] = []
  const deviceBoundSessions = detectDeviceBoundSessions(layout.stateDir, layout.profileLabel)
  if (deviceBoundSessions) {
    warnings.push(...dbscWarningLines(layout.stateDir, layout.profileLabel, domainFilter))
  }
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'constellation-cookies-'))
  let cookies: ImportedCookie[] = []
  let unsupported = 0
  try {
    const tempDb = path.join(tempDir, 'Cookies')
    try {
      fs.copyFileSync(layout.cookiesFile, tempDb)
    } catch (error) {
      // Run-11 D14: while the profile's own browser is RUNNING it holds the
      // Cookies DB locked — retries do not help (a pwsh Copy-Item retry
      // failed identically in the field). Say the fix, not the stack.
      const code = (error as NodeJS.ErrnoException).code
      if (code === 'EBUSY' || code === 'EPERM' || code === 'ETXTBSY') {
        throw new Error(`"${layout.cookiesFile}" is locked by the browser that owns it (${code}) — close that Chrome/Edge first, or read the cookies from the LIVE session instead (browser_cookies_export on an attached/owner browser) and import the handoff. Retrying while it runs will keep failing.`)
      }
      throw error
    }
    const key = await loadChromiumCookieKey(layout.stateDir)
    const db = new DatabaseSync(tempDb, { readOnly: true })
    try {
      // expires_utc is divided to SECONDS inside SQLite (run-39 §10.1): the
      // raw µs column overflows node:sqlite's safe-integer range on far-future
      // cookies and threw "Value is too large", killing every profile import.
      const rows = db.prepare(
        'SELECT host_key, name, encrypted_value, path, CAST(expires_utc / 1000000 AS INTEGER) AS expires_s, is_secure, is_httponly, samesite FROM cookies',
      ).all() as Array<{ host_key: string; name: string; encrypted_value: Uint8Array; path: string; expires_s: number; is_secure: number; is_httponly: number; samesite?: number | null }>
      for (const row of rows) {
        if (!cookieMatchesAnyDomain(row.host_key, domainFilter)) continue
        const decrypted = decryptCookieValue(Buffer.from(row.encrypted_value), key, row.host_key)
        if (decrypted.unsupported !== undefined) {
          unsupported++
          continue
        }
        const secure = row.is_secure === 1
        const expires = unixSecondsFromSqlite(row.expires_s)
        const sameSite = mapSameSite(row.samesite, secure)
        cookies.push({
          name: row.name,
          value: decrypted.value ?? '',
          domain: row.host_key,
          path: row.path,
          secure,
          httpOnly: row.is_httponly === 1,
          ...(expires > 0 ? { expires } : {}),
          ...(sameSite === undefined ? {} : { sameSite }),
        })
      }
    } finally {
      db.close()
    }
  } finally {
    try { fs.rmSync(tempDir, { recursive: true, force: true }) } catch { /* best effort */ }
  }
  if (unsupported > 0) {
    warnings.push(`${unsupported} cookie(s) use app-bound encryption (v20) and cannot be imported out-of-process — those identities need browser_attach (DBSC-safe) or a non-app-bound profile`)
  }
  cookies = cookies.filter(cookie => cookie.value !== '')
  const hosts = [...new Set(cookies.map(cookie => cookieHost(cookie.domain)))].sort()
  return { cookies, hosts, warnings, deviceBoundSessions }
}
