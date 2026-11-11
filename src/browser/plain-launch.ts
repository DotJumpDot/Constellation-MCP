/**
 * Plain-Chrome launch (advice 2026-11-11 D12 + the Maki_Live/StarCodex
 * research): spawn the HUMAN'S chrome.exe ourselves — zero Playwright launch
 * flags, zero automation marker — then adopt it over CDP. This is the only
 * launch path measured to pass Cloudflare/reCAPTCHA-class edges (every
 * Playwright-launched profile still reports navigator.webdriver=true; run-31
 * mfp/jeteat/ttd STATE files).
 *
 * Extras this module owns:
 *  - SW_SHOWNOACTIVATE spawn (user ask 2026-11-11: a new lane window must
 *    never steal the human's focus; the reactive focus guard stays for the
 *    Playwright path, this prevents the steal at creation instead);
 *  - free debug-port allocation + owner binding (advice D2: two owners
 *    adopting the same endpoint cross-contaminated browsers);
 *  - challenge-page detection (StarCodex's WAF ladder heuristics) so
 *    browser_navigate can tell a lane WHY a page is empty;
 *  - exact-match profile kill (advice D11: a lane's substring taskkill took
 *    out 61 pids including two sibling lanes' browsers).
 */
import net from 'node:net'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const exec = promisify(execFile)

// ── Chrome executable resolution ───────────────────────────────────────────

/** Resolve the installed chrome.exe (Playwright's channel launcher does this
 *  internally; we spawn the binary ourselves, so mirror the search). */
export function resolveChromeExecutable(): string {
  const candidates = [
    process.env.PROGRAMFILES ? path.join(process.env.PROGRAMFILES, 'Google/Chrome/Application/chrome.exe') : undefined,
    process.env['PROGRAMFILES(X86)'] ? path.join(process.env['PROGRAMFILES(X86)']!, 'Google/Chrome/Application/chrome.exe') : undefined,
    process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'Google/Chrome/Application/chrome.exe') : undefined,
  ].filter((p): p is string => p !== undefined)
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate
  }
  throw new Error('chrome.exe not found in PROGRAMFILES/PROGRAMFILES(X86)/LOCALAPPDATA — install Google Chrome or use browser_launch')
}

// ── Free debug-port allocation (advice D2) ─────────────────────────────────

/** Grab a free TCP port on loopback (bind :0, read it, release). The window
 *  between release and Chrome's bind is tiny and retried by waitForCdp; a
 *  collision fails the launch loudly instead of adopting a stranger (D2). */
export function allocateDebugPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.unref()
    server.on('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      const port = typeof address === 'object' && address !== null ? address.port : 0
      server.close(() => {
        if (port > 0) resolve(port)
        else reject(new Error('could not allocate a debug port'))
      })
    })
  })
}

// ── No-activate spawn ──────────────────────────────────────────────────────

/** CreateProcess with STARTF_USESHOWWINDOW + SW_SHOWNOACTIVATE: the window
 *  MAPS (becomes visible) but never becomes foreground — the human's focus
 *  never moves when a lane spawns its browser. Same escaping rules as the
 *  badge helper: placeholders replaced in TS, ' doubled for PS, no backticks. */
const PLAIN_LAUNCH_PS = `
$ErrorActionPreference = 'Stop'
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class PL {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct STARTUPINFO {
    public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle;
    public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize;
    public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute;
    public uint dwFlags; public short wShowWindow; public short cbReserved2; public IntPtr lpReserved2;
    public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct PROCESS_INFORMATION { public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId; }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool CreateProcessW(string app, string cmdLine, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  public static uint Spawn(string app, string args) {
    STARTUPINFO si = new STARTUPINFO();
    si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
    si.dwFlags = 0x00000001; // STARTF_USESHOWWINDOW
    si.wShowWindow = 4;      // SW_SHOWNOACTIVATE
    PROCESS_INFORMATION pi;
    if (!CreateProcessW(app, "\"" + app + "\" " + args, IntPtr.Zero, IntPtr.Zero, false, 0x04000000 /*CREATE_DEFAULT_ERROR_MODE*/, IntPtr.Zero, null, ref si, out pi))
      throw new Exception("CreateProcessW failed: " + Marshal.GetLastWin32Error());
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return pi.dwProcessId;
  }
}
"@
try {
  $pid2 = [PL]::Spawn('__CHROME__', '__ARGS__')
  Write-Output ("PID " + $pid2)
  exit 0
} catch {
  Write-Output ("SPAWNFAIL " + $_.Exception.Message)
  exit 3
}
`

export interface PlainSpawnResult {
  pid: number
}

function psQuote(value: string): string {
  return value.replaceAll("'", "''")
}

/** Spawn chrome.exe no-activate with the plain flags. Pure orchestration
 *  around the PS helper; never rejects (SPAWNFAIL becomes an Error). */
export async function spawnPlainChrome(options: {
  chromePath: string
  userDir: string
  port: number
  windowPosition?: string
  extraArgs?: string[]
}): Promise<PlainSpawnResult> {
  const args = [
    `--remote-debugging-port=${options.port}`,
    `--user-data-dir=${options.userDir.includes(' ') ? `"${options.userDir}"` : options.userDir}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--hide-crash-restore-bubble',
    '--disable-blink-features=AutomationControlled',
    ...(options.windowPosition !== undefined
      ? [`--window-position=${options.windowPosition}`]
      : []),
    ...(options.extraArgs ?? []),
    'about:blank',
  ]
  const script = PLAIN_LAUNCH_PS
    .replaceAll('__CHROME__', psQuote(options.chromePath))
    .replaceAll('__ARGS__', psQuote(args.join(' ')))
  const { stdout } = await exec(
    'powershell.exe',
    ['-NoProfile', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
    { windowsHide: true, timeout: 20_000 },
  ).catch(error => { throw new Error(`plain spawn helper failed: ${error instanceof Error ? error.message : String(error)}`) })
  const match = /PID (\d+)/.exec(stdout)
  if (match === null) {
    const fail = /SPAWNFAIL (.+)/.exec(stdout)
    throw new Error(`plain chrome spawn failed: ${fail?.[1] ?? stdout.trim().slice(0, 200)}`)
  }
  return { pid: Number(match[1]) }
}

// ── CDP readiness + owner bindings (D2) ────────────────────────────────────

export interface CdpVersion {
  browserGuid?: string
  userAgent?: string
}

/** Poll /json/version until Chrome answers. Resolves with the browser GUID —
 *  the identity a binding is keyed on. */
export async function waitForCdp(port: number, timeoutMs = 20_000): Promise<CdpVersion> {
  const deadline = Date.now() + timeoutMs
  let lastError = 'no attempt'
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`, { signal: AbortSignal.timeout(1500) })
      if (response.ok) {
        const body = await response.json() as { Browser?: string; 'User-Agent'?: string; webSocketDebuggerUrl?: string }
        return { browserGuid: body.Browser, userAgent: body['User-Agent'] }
      }
      lastError = `HTTP ${response.status}`
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error)
    }
    await new Promise(resolve => setTimeout(resolve, 300))
  }
  throw new Error(`plain Chrome CDP endpoint 127.0.0.1:${port} never answered (${lastError})`)
}

export interface CdpBinding {
  owner: string
  port: number
  browserGuid?: string
  since: string
}

/** port → binding. In-process only (a server restart loses it; the typed
 *  error on a stale endpoint is the recovery path, not silent adoption). */
const cdpBindings = new Map<number, CdpBinding>()

/** Bind an endpoint to an owner, REFUSING an endpoint another owner holds
 *  (advice D2: cross-owner browser contamination is the worst failure this
 *  harness can produce). */
export function bindCdpEndpoint(port: number, owner: string, browserGuid?: string): CdpBinding {
  const existing = cdpBindings.get(port)
  if (existing !== undefined && existing.owner !== owner) {
    throw new Error(`cdp ${port} is owned by "${existing.owner}" since ${existing.since} — pick another port / let browser_launch_plain allocate one (bindCdpEndpoint refused)`)
  }
  const binding: CdpBinding = { owner, port, ...(browserGuid === undefined ? {} : { browserGuid }), since: new Date().toISOString() }
  cdpBindings.set(port, binding)
  return binding
}

/** Owner-visible binding for maps/audits. */
export function cdpBindingFor(port: number): CdpBinding | undefined {
  return cdpBindings.get(port)
}

/** Who owns this endpoint, for browser_attach's D2 refusal. */
export function cdpEndpointOwner(cdpUrl: string): CdpBinding | undefined {
  const port = Number(/:(\d+)\/?$/.exec(cdpUrl)?.[1] ?? 0)
  return port > 0 ? cdpBindings.get(port) : undefined
}

export function releaseCdpBinding(port: number): void {
  cdpBindings.delete(port)
}

// ── Challenge detection (StarCodex heuristics) ─────────────────────────────

export type ChallengeKind = 'cloudflare-managed' | 'cloudflare-interactive' | 'recaptcha' | 'hcaptcha' | 'generic-captcha'

export interface ChallengeDetection {
  kind: ChallengeKind
  markers: string[]
}

const CF_BODY_MARKERS = [
  'just a moment', 'cf-chl', 'challenge-platform', 'checking your browser',
  'attention required! | cloudflare', 'verify you are human',
]
const INTERACTIVE_MARKERS = ['turnstile', 'cf-turnstile', 'verify you are human', 'are you a robot']
const RECAPTCHA_MARKERS = ['g-recaptcha', 'www.google.com/recaptcha', 'recaptcha/api']
const HCAPTCHA_MARKERS = ['hcaptcha.com', 'h-captcha']

/** Classify a loaded page as a bot-challenge interstitial. Pure; tested. */
export function detectChallenge(title: string, bodySample: string, status?: number): ChallengeDetection | undefined {
  const haystack = `${title}\n${bodySample}`.toLowerCase()
  const hits = (markers: string[]) => markers.filter(marker => haystack.includes(marker))
  const cf = hits(CF_BODY_MARKERS)
  if (cf.length > 0) {
    const interactive = hits(INTERACTIVE_MARKERS)
    return { kind: interactive.length > 0 ? 'cloudflare-interactive' : 'cloudflare-managed', markers: [...new Set([...cf, ...interactive])] }
  }
  if (status === 403 || status === 429 || status === 503) {
    // CF signature without body markers (an empty challenge body): managed.
    return { kind: 'cloudflare-managed', markers: [`status ${status}`] }
  }
  const recaptcha = hits(RECAPTCHA_MARKERS)
  if (recaptcha.length > 0) return { kind: 'recaptcha', markers: recaptcha }
  const hcaptcha = hits(HCAPTCHA_MARKERS)
  if (hcaptcha.length > 0) return { kind: 'hcaptcha', markers: hcaptcha }
  if (hits(['captcha', 'robot']).length >= 2) return { kind: 'generic-captcha', markers: ['captcha', 'robot'] }
  return undefined
}

/** Human-facing hint for a detected challenge (what a lane should do). */
export function challengeAdvice(detection: ChallengeDetection): string {
  switch (detection.kind) {
    case 'cloudflare-managed':
      return 'managed Cloudflare challenge — usually self-clears; wait a few seconds and re-read the page (browser_read) before doing anything else'
    case 'cloudflare-interactive':
      return 'interactive Cloudflare/Turnstile — the human must click it once; raise a human_task with the window\'s taskbar badge, then re-read after done_when'
    case 'recaptcha':
    case 'hcaptcha':
    case 'generic-captcha':
      return 'captcha wall — do not retry-solve; record BLOCKED-CAPTCHA with the URL and move on (or wall the human if this fixture is essential)'
  }
}

// ── Exact-match kill (advice D11) ──────────────────────────────────────────

/** Kill exactly the chrome.exe processes whose --user-data-dir EQUALS this
 *  profile path (parsed arg comparison, never substring: run-37 mkt-36's
 *  "*cdp-r36-mkt-36*" substring filter killed 61 pids including two sibling
 *  lanes' browsers). */
export async function killChromeByProfile(userDir: string): Promise<number> {
  const script =
    `$udd = '${userDir.replaceAll("'", "''")}'\n` +
    `$norm = { param($v) if ($v) { ($v.Trim('"')).ToLower() } else { $null } }\n` +
    `$target = & $norm $udd\n` +
    `$victims = @(Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" -ErrorAction SilentlyContinue | Where-Object {\n` +
    `  if ($_.CommandLine -match '(?:^| )--user-data-dir=(?:"([^"]+)"|([^ ]+))') {\n` +
    `    $v = & $norm $Matches[1]; if (-not $v) { $v = & $norm $Matches[2] }\n` +
    `    $v -eq $target\n` +
    `  } else { $false }\n})\n` +
    `foreach ($v in $victims) { Stop-Process -Id $v.ProcessId -Force -ErrorAction SilentlyContinue }\n` +
    `Write-Output ("KILLED " + $victims.Count)\n`
  try {
    const { stdout } = await exec(
      'powershell.exe',
      ['-NoProfile', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
      { windowsHide: true, timeout: 20_000 },
    )
    return Number(/KILLED (\d+)/.exec(stdout)?.[1] ?? 0)
  } catch {
    return 0
  }
}

/** True while the spawn's browser process is alive (graceful-close check). */
export async function pidAlive(pid: number): Promise<boolean> {
  try {
    const script = `Get-Process -Id ${Number.isInteger(pid) ? pid : 0} -ErrorAction SilentlyContinue | Measure-Object | ForEach-Object { $_.Count }`
    const { stdout } = await exec('powershell.exe', ['-NoProfile', '-Command', script], { windowsHide: true, timeout: 8_000 })
    return Number(stdout.trim()) > 0
  } catch {
    return false
  }
}

/** Default warm-profile dir for a plain owner (reused across runs: cookies,
 *  including any solved cf_clearance, persist — StarCodex's core lesson:
 *  clearance is bound to TLS+UA+IP and this machine/Chrome keeps all three). */
export function plainProfileDir(profilesRoot: string, owner: string, fresh: boolean): string {
  if (!fresh) return path.join(profilesRoot, `plain-${owner}`)
  return fs.mkdtempSync(path.join(os.tmpdir(), `constellation-plain-${owner}-`))
}
