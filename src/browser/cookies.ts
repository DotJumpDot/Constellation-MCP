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
    const script =
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
  } catch {
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
      const rows = db.prepare(
        'SELECT host_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly, samesite FROM cookies',
      ).all() as Array<{ host_key: string; name: string; encrypted_value: Uint8Array; path: string; expires_utc: number; is_secure: number; is_httponly: number; samesite?: number | null }>
      for (const row of rows) {
        if (!cookieMatchesAnyDomain(row.host_key, domainFilter)) continue
        const decrypted = decryptCookieValue(Buffer.from(row.encrypted_value), key, row.host_key)
        if (decrypted.unsupported !== undefined) {
          unsupported++
          continue
        }
        const secure = row.is_secure === 1
        const expires = chromiumTimeToUnixSeconds(row.expires_utc)
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
