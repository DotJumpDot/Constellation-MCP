/**
 * Post-spawn focus watchdog (window-placement-and-focus advice §3–§4, run 9).
 *
 * MEASURED FACT: a spawned Chrome STEALS the foreground at window creation —
 * `--start-minimized` does not prevent it, nothing in this codebase calls
 * bringToFront, and Chrome yields focus back on its own only ~2 s later. A
 * single post-spawn GetForegroundWindow snapshot reads "unchanged" while the
 * human felt the steal; only a 40 ms poll THROUGH the spawn sees it. The
 * human verified the counter design on their own desktop: when the foreground
 * becomes a window of the Chrome we just spawned, hand the foreground back.
 *
 * Plain SetForegroundWindow is refused to a background process, so the
 * restore attaches thread input first (the C# recipe from the advice,
 * transliterated to PowerShell/Add-Type). The watchdog runs as a detached
 * PowerShell helper — a small process with its own 40 ms loop, unaffected by
 * the Node event loop — armed BEFORE the Chrome spawn (it captures the
 * protect target itself, prints ARMED, and the launch proceeds only then).
 *
 * It matches ONLY windows whose process command line carries this session's
 * user-data-dir: a window the human opened in their own Chrome can never be
 * fought, and an attach-mode window (the human's browser) is never guarded
 * at all. After TWO counters it drops out — a third appearance of our window
 * in the foreground is the human deliberately focusing it.
 */
import { spawn } from 'node:child_process'

/** The watchdog script. Placeholders (__SECS__ etc.) are replaced per arm —
 *  mixing TS interpolation into PowerShell syntax is how quoting bugs are
 *  born. No backticks anywhere (they would need escaping inside the TS
 *  template literal); newlines in the log are [char]13+[char]10. */
const FOCUS_GUARD_PS = `
$ErrorActionPreference = 'SilentlyContinue'
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class FG {
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
}
"@
function Log([string]$m) {
  if ($script:LogFile -ne '') {
    [IO.File]::AppendAllText($script:LogFile, (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fff') + ' ' + $m + [char]13 + [char]10)
  }
}
$secs = __SECS__
$udd = '__UDD__'
$procName = '__PROCNAME__'
$script:LogFile = '__LOGFILE__'

# The protect target is whatever holds the foreground RIGHT NOW, before the
# Chrome spawn the caller is about to perform.
$protect = [FG]::GetForegroundWindow()
Write-Output ("ARMED " + $protect.ToInt64())
if ($protect -eq [IntPtr]::Zero) { Log "watchdog: no foreground window to protect - exiting"; exit 0 }

# OUR Chrome only: processes whose command line carries this session's
# user-data-dir (IndexOf OrdinalIgnoreCase - -like would need its brackets
# escaped and its backslashes left raw, a known trap). The scan RETRIES: at
# arm time the spawn has not happened yet, so give the browser up to 6 s to
# appear before declaring the guard unarmed.
$chromePids = @()
$scanDeadline = (Get-Date).AddSeconds(6)
while ((Get-Date) -lt $scanDeadline) {
  $chromePids = @(Get-CimInstance Win32_Process -Filter ("Name='" + $procName + "'") |
    Where-Object { $_.CommandLine -ne $null -and $_.CommandLine.IndexOf($udd, [StringComparison]::OrdinalIgnoreCase) -ge 0 } |
    ForEach-Object { [uint32]$_.ProcessId })
  if ($chromePids.Count -gt 0) { break }
  Start-Sleep -Milliseconds 200
}
if ($chromePids.Count -eq 0) { Log "watchdog: no $procName carries the user-data-dir within 6s - exiting"; exit 0 }
Log ("watchdog: protecting hwnd=" + $protect.ToInt64() + " pids=" + ($chromePids -join ','))

$counters = 0
$deadline = (Get-Date).AddSeconds($secs)
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Milliseconds 40
  $fg = [FG]::GetForegroundWindow()
  if ($fg -eq [IntPtr]::Zero) { continue }
  if ($fg -eq $protect) { continue }
  $wpid = [uint32]0
  [FG]::GetWindowThreadProcessId($fg, [ref]$wpid) | Out-Null
  if ($wpid -eq 0 -or -not ($chromePids -contains $wpid)) { continue }
  if ($counters -ge 2) { Log ("watchdog: chrome foreground again (count " + $counters + ") - dropping out, likely deliberate"); break }
  $counters++
  Log ("STEAL by hwnd=" + $fg.ToInt64() + " pid=" + $wpid + " -> restoring hwnd=" + $protect.ToInt64())
  $t1 = [uint32]0; $t2 = [uint32]0
  $me = [FG]::GetCurrentThreadId()
  $fgT = [FG]::GetWindowThreadProcessId($fg, [ref]$t1)
  $tgT = [FG]::GetWindowThreadProcessId($protect, [ref]$t2)
  [FG]::AttachThreadInput($me, $fgT, $true) | Out-Null
  [FG]::AttachThreadInput($me, $tgT, $true) | Out-Null
  [FG]::SetForegroundWindow($protect) | Out-Null
  [FG]::AttachThreadInput($me, $fgT, $false) | Out-Null
  [FG]::AttachThreadInput($me, $tgT, $false) | Out-Null
  Start-Sleep -Milliseconds 150
  $now = [FG]::GetForegroundWindow()
  Log ("after restore: hwnd=" + $now.ToInt64())
}
Log ("watchdog end - steals countered: " + $counters)
`

export interface FocusGuard {
  /** The hwnd the watchdog protects (0 when it could not arm). */
  protectHwnd: number
  /** Kill the helper early (best effort — it also self-expires). */
  stop(): void
}

/** The browser executable's process name for a Playwright channel. */
export function focusGuardProcessName(channel: string | undefined): string {
  return channel === 'msedge' ? 'msedge.exe' : 'chrome.exe'
}

/** Assemble the watchdog script with the call's parameters baked in (pure —
 *  unit-tested for the needle-escaping rules). */
export function buildFocusGuardScript(userDir: string, channel: string | undefined, seconds: number, logFile: string): string {
  return FOCUS_GUARD_PS
    .replaceAll('__SECS__', String(seconds))
    // Inside PS single-quoted strings only ' needs doubling; backslashes are
    // literal — escaping them would corrupt the path and the pid needle.
    .replaceAll('__UDD__', userDir.replaceAll("'", "''"))
    .replaceAll('__PROCNAME__', focusGuardProcessName(channel).replaceAll("'", "''"))
    .replaceAll('__LOGFILE__', logFile.replaceAll("'", "''"))
}

/** Arm the watchdog: start the helper, wait for its ARMED line (so the
 *  foreground capture happens strictly BEFORE the Chrome spawn that follows),
 *  then return. Resolves with protectHwnd 0 when arming fails — focus
 *  guarding is best effort and must never block a launch. */
export async function armFocusGuard(options: {
  userDir: string
  channel: string | undefined
  /** How long to keep polling after arming (default 10 — covers spawn +
   *  window park + ownership-label tab on a cold start). */
  seconds?: number
  /** Append-only event log (armed/steal/restore lines); '' disables. */
  logFile?: string
}): Promise<FocusGuard> {
  const seconds = Math.max(1, Math.min(60, Math.round(options.seconds ?? 10)))
  const script = buildFocusGuardScript(options.userDir, options.channel, seconds, options.logFile ?? '')
  // -EncodedCommand takes UTF-16LE base64 — no command-line quoting hazards
  // for a path-shaped argument list.
  const encoded = Buffer.from(script, 'utf16le').toString('base64')
  return await new Promise<FocusGuard>(resolve => {
    let child: ReturnType<typeof spawn>
    try {
      child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'ignore'],
      })
    } catch {
      resolve({ protectHwnd: 0, stop: () => undefined })
      return
    }
    let buffer = ''
    let armed = false
    const finish = (hwnd: number): void => {
      armed = true
      child.unref()
      resolve({
        protectHwnd: hwnd,
        stop: () => { try { child.kill() } catch { /* already gone */ } },
      })
    }
    child.stdout?.on('data', (chunk: Buffer) => {
      if (armed) return
      buffer += chunk.toString('utf8')
      const match = buffer.match(/ARMED (-?\d+)/)
      if (match !== null) finish(Number.parseInt(match[1]!, 10))
    })
    child.on('error', () => { if (!armed) finish(0) })
    child.on('exit', () => { if (!armed) finish(0) })
    // PowerShell cold start should be well under this; on timeout we proceed
    // unguarded rather than blocking the launch.
    setTimeout(() => { if (!armed) finish(0) }, 5_000).unref()
  })
}
