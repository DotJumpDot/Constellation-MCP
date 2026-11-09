/**
 * Taskbar badge numbers for lane Chrome windows (user ask 2026-11-10).
 *
 * With 10+ agent lanes each spawning its own Chrome, every taskbar icon is
 * the same Chrome logo — the human cannot tell whose window is whose without
 * hovering titles. This module gives every LAUNCHED owner window a small
 * NUMBER rendered as a taskbar OVERLAY icon (the same corner badge Windows
 * apps use for notification counts), hands that number to the lane in the
 * tool output (browser_launch / browser_map / browser_owner_info), and the
 * engine's human_task_create carries it onto the human wall so an ask can
 * say "Chrome 7" and the human finds window 7 by looking at the taskbar.
 *
 * Three parts, all safe to unit-test without a shell:
 *  - a per-process badge pool: lowest-free allocation, freed on close, and
 *    seeded from a persisted `last` so a server restart cannot hand a live
 *    window's badge number to a new window (numbers stay unique across
 *    restarts until the 99 cap wraps);
 *  - pure icon generation: the digits are drawn with a hand-rolled 5x7
 *    bitmap font into a 32x32 RGBA buffer, PNG-encoded (node zlib, no
 *    dependencies) and wrapped in an ICO container (PNG-in-ICO, Vista+);
 *  - a detached PowerShell helper (the focus-guard pattern) that finds the
 *    Chrome processes carrying this session's --user-data-dir and calls
 *    ITaskbarList3::SetOverlayIcon on every visible Chrome_WidgetWin_1
 *    window of those processes. Best effort by design: on any failure the
 *    number still exists in tool output, the window title prefix
 *    ([owner]) and the info tab — the badge is a convenience, never a gate.
 */
import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import { spawn } from 'node:child_process'
import { focusGuardProcessName } from './focus.js'

/** Numbers stay human-glanceable: at most two digits on the badge. */
export const BADGE_LIMIT = 99

/** Per-process badge pool with restart-unique seeding. Pure logic; the pool
 *  instances used by sessions live in a small root-keyed registry below. */
export class TaskbarBadgePool {
  private readonly held = new Set<number>()
  private last = 0

  constructor(private readonly stateFile?: string, private readonly limit: number = BADGE_LIMIT) {
    if (stateFile === undefined) return
    try {
      const parsed = JSON.parse(fs.readFileSync(stateFile, 'utf8')) as { last?: unknown }
      const last = typeof parsed.last === 'number' ? Math.floor(parsed.last) : Number.NaN
      if (Number.isFinite(last)) this.last = Math.min(this.limit, Math.max(0, last))
    } catch { /* fresh root: start at 1 */ }
  }

  private persist(): void {
    if (this.stateFile === undefined) return
    try {
      fs.mkdirSync(path.dirname(this.stateFile), { recursive: true })
      fs.writeFileSync(this.stateFile, JSON.stringify({ last: this.last }) + '\n')
    } catch { /* a lost seed file only risks a badge reuse after a restart */ }
  }

  /** Take the next badge number: prefer numbers ABOVE the highest ever
   *  handed out (restart uniqueness), wrap at the limit, undefined when all
   *  are held. */
  alloc(): number | undefined {
    for (let step = 0; step < this.limit; step++) {
      this.last = this.last >= this.limit ? 1 : this.last + 1
      if (!this.held.has(this.last)) {
        this.held.add(this.last)
        this.persist()
        return this.last
      }
    }
    return undefined
  }

  /** Return a number to the pool (close/reset). */
  free(badge: number): void {
    this.held.delete(badge)
  }

  /** Numbers currently assigned (diagnostics/tests). */
  heldBadges(): number[] {
    return [...this.held].sort((a, b) => a - b)
  }
}

const pools = new Map<string, TaskbarBadgePool>()

/** The badge pool for one Constellation root dir (one per server process). */
export function badgePoolFor(rootDir: string): TaskbarBadgePool {
  let pool = pools.get(rootDir)
  if (pool === undefined) {
    pool = new TaskbarBadgePool(path.join(rootDir, 'badges', 'state.json'))
    pools.set(rootDir, pool)
  }
  return pool
}

// ── Icon generation (pure) ─────────────────────────────────────────────────

/** 5x7 bitmap font rows for 0-9 (bit strings; '1' = lit pixel). */
const DIGIT_ROWS: Record<string, readonly string[]> = {
  '0': ['01110', '10001', '10011', '10101', '11001', '10001', '01110'],
  '1': ['00100', '01100', '00100', '00100', '00100', '00100', '01110'],
  '2': ['01110', '10001', '00001', '00010', '00100', '01000', '11111'],
  '3': ['11111', '00010', '00100', '00010', '00001', '10001', '01110'],
  '4': ['00010', '00110', '01010', '10010', '11111', '00010', '00010'],
  '5': ['11111', '10000', '11110', '00001', '00001', '10001', '01110'],
  '6': ['00110', '01000', '10000', '11110', '10001', '10001', '01110'],
  '7': ['11111', '00001', '00010', '00100', '01000', '01000', '01000'],
  '8': ['01110', '10001', '10001', '01110', '10001', '10001', '01110'],
  '9': ['01110', '10001', '10001', '01111', '00001', '00010', '01100'],
}

/** Scale so 1-3 digits always fit 32px with a margin: 1 digit 4x, 2 digits
 *  2x, 3 digits 1x. Pure. */
export function badgeDigitScale(badge: number): number {
  const digits = String(badge).length
  return digits <= 1 ? 4 : digits === 2 ? 2 : 1
}

/** Draw the badge's RGBA pixels (32x32, 4 bytes/px): a solid blue square
 *  (the Windows notification-badge look) with white digits centered. Pure —
 *  pinned by unit tests, including differing bytes per number. */
export function renderBadgeRgba(badge: number, size = 32): Buffer {
  if (!Number.isInteger(badge) || badge < 0) throw new Error(`badge must be a non-negative integer, got ${badge}`)
  const pixels = Buffer.alloc(size * size * 4)
  // Background #0b57d0 (solid; overlay icons render at ~16-24px so a hard
  // square reads cleaner than a rounded one at that size).
  for (let at = 0; at < size * size; at++) {
    pixels[at * 4] = 0x0b
    pixels[at * 4 + 1] = 0x57
    pixels[at * 4 + 2] = 0xd0
    pixels[at * 4 + 3] = 0xff
  }
  const text = String(badge)
  const scale = badgeDigitScale(badge)
  const glyphW = 5 * scale
  const glyphH = 7 * scale
  const spacing = scale
  const totalW = text.length * glyphW + (text.length - 1) * spacing
  const originX = Math.floor((size - totalW) / 2)
  const originY = Math.floor((size - glyphH) / 2)
  for (let digitAt = 0; digitAt < text.length; digitAt++) {
    const rows = DIGIT_ROWS[text[digitAt]]
    if (rows === undefined) continue
    const digitX = originX + digitAt * (glyphW + spacing)
    for (let row = 0; row < 7; row++) {
      for (let col = 0; col < 5; col++) {
        if (rows[row]![col] !== '1') continue
        for (let dy = 0; dy < scale; dy++) {
          for (let dx = 0; dx < scale; dx++) {
            const x = digitX + col * scale + dx
            const y = originY + row * scale + dy
            if (x < 0 || x >= size || y < 0 || y >= size) continue
            const at = (y * size + x) * 4
            pixels[at] = 0xff
            pixels[at + 1] = 0xff
            pixels[at + 2] = 0xff
          }
        }
      }
    }
  }
  return pixels
}

/** CRC-32 (PNG chunk checksums) — table-driven, standard polynomial. */
const CRC_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = (c & 1) === 1 ? (0xedb88320 ^ (c >>> 1)) >>> 0 : c >>> 1
    table[n] = c >>> 0
  }
  return table
})()

function crc32(buf: Buffer): number {
  let crc = 0xffffffff
  for (const byte of buf) crc = CRC_TABLE[(crc ^ byte) & 0xff]! ^ (crc >>> 8)
  return (crc ^ 0xffffffff) >>> 0
}

function pngChunk(type: string, data: Buffer): Buffer {
  const out = Buffer.alloc(8 + data.length + 4)
  out.writeUInt32BE(data.length, 0)
  out.write(type, 4, 'ascii')
  data.copy(out, 8)
  out.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type, 'ascii'), data])), 8 + data.length)
  return out
}

/** Encode one RGBA buffer as a PNG (8-bit, color type 6). Pure. */
export function encodePng(rgba: Buffer, width: number, height: number): Buffer {
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(width, 0)
  ihdr.writeUInt32BE(height, 4)
  ihdr[8] = 8 // bit depth
  ihdr[9] = 6 // RGBA
  const rows: Buffer[] = []
  for (let y = 0; y < height; y++) {
    rows.push(Buffer.from([0])) // filter: none
    rows.push(rgba.subarray(y * width * 4, (y + 1) * width * 4))
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(Buffer.concat(rows), { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ])
}

/** Wrap a PNG in a one-image ICO container (PNG-in-ICO, Vista+). Pure. */
export function wrapIco(png: Buffer, size = 32): Buffer {
  const out = Buffer.alloc(22 + png.length)
  out.writeUInt16LE(0, 0) // reserved
  out.writeUInt16LE(1, 2) // type: icon
  out.writeUInt16LE(1, 4) // one image
  out[6] = size
  out[7] = size
  out[10] = 1 // color planes
  out[12] = 32 // bits per pixel
  out.writeUInt32LE(png.length, 14)
  out.writeUInt32LE(22, 18) // image offset
  png.copy(out, 22)
  return out
}

/** The badge icon for one number as ICO bytes (PNG payload inside). Pure. */
export function badgeIconBytes(badge: number): Buffer {
  return wrapIco(encodePng(renderBadgeRgba(badge), 32, 32))
}

/** Icon file for a badge, generated once into <rootDir>/badges/ and cached. */
export function ensureBadgeIcon(rootDir: string, badge: number): string {
  const dir = path.join(rootDir, 'badges')
  fs.mkdirSync(dir, { recursive: true })
  const file = path.join(dir, `badge-${badge}.ico`)
  if (!fs.existsSync(file)) fs.writeFileSync(file, badgeIconBytes(badge))
  return file
}

// ── Overlay application (Windows shell, best effort) ───────────────────────

/** The overlay helper script. Placeholders (__UDD__ etc.) are replaced per
 *  application — same rules as the focus guard: no backticks anywhere, only
 *  ' needs doubling inside PS single-quoted strings, backslashes stay raw
 *  (doubling them corrupts the path needle — proven against a live chrome.exe
 *  command line). */
const TASKBAR_BADGE_PS = `
$ErrorActionPreference = 'SilentlyContinue'
Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class TB {
  public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lParam);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr hWnd, StringBuilder sb, int max);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr LoadImage(IntPtr hInst, string name, uint type, int cx, int cy, uint flags);
  [StructLayout(LayoutKind.Sequential)] public struct THUMBBUTTON { public uint dwMask; public uint iId; public uint iBitmap; public IntPtr hIcon; [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)] public string szTip; public uint dwFlags; }
  [ComImport, Guid("56FDF342-FD6D-11d0-958A-006097C9A090"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface ITaskbarList3 {
    void HrInit();
    void AddTab(IntPtr hWnd);
    void RemoveTab(IntPtr hWnd);
    void ActivateTab(IntPtr hWnd);
    void SetActiveAlt(IntPtr hWnd);
    void MarkFullscreenWindow(IntPtr hWnd, bool fFullscreen);
    void SetProgressValue(IntPtr hWnd, ulong ullCompleted, ulong ullTotal);
    void SetProgressState(IntPtr hWnd, int tbpFlags);
    void RegisterTab(IntPtr hwndTab, IntPtr hwndMDI);
    void UnregisterTab(IntPtr hwndTab);
    void SetTabOrder(IntPtr hwndTab, IntPtr hwndInsertBefore);
    void SetTabActive(IntPtr hwndTab, IntPtr hwndMDI, uint dwReserved);
    void ThumbBarAddButtons(IntPtr hWnd, uint cButtons, ref THUMBBUTTON pButtons);
    void ThumbBarUpdateButtons(IntPtr hWnd, uint cButtons, ref THUMBBUTTON pButtons);
    void ThumbBarSetImageList(IntPtr hWnd, IntPtr himl);
    void SetOverlayIcon(IntPtr hWnd, IntPtr hIcon, [MarshalAs(UnmanagedType.LPWStr)] string pszDescription);
  }
  [DllImport("ole32.dll", PreserveSig=false)] public static extern void CoCreateInstance([In] ref Guid rclsid, IntPtr pUnkOuter, uint dwClsContext, [In] ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out ITaskbarList3 ppv);
  public static int Badge(uint[] pids, string icoPath, string desc) {
    Guid clsid = new Guid("56FDF344-FD6D-11d0-958A-006097C9A090");
    Guid iid = new Guid("56FDF342-FD6D-11d0-958A-006097C9A090");
    ITaskbarList3 tb;
    CoCreateInstance(ref clsid, IntPtr.Zero, 1, ref iid, out tb);
    tb.HrInit();
    IntPtr hIcon = LoadImage(IntPtr.Zero, icoPath, 1, 32, 32, 0x10);
    if (hIcon == IntPtr.Zero) return -1;
    int count = 0;
    EnumWindows(delegate(IntPtr hWnd, IntPtr lParam) {
      uint pid; GetWindowThreadProcessId(hWnd, out pid);
      if (Array.IndexOf(pids, pid) < 0) return true;
      if (!IsWindowVisible(hWnd)) return true;
      StringBuilder sb = new StringBuilder(64);
      GetClassName(hWnd, sb, 64);
      if (sb.ToString() != "Chrome_WidgetWin_1") return true;
      try { tb.SetOverlayIcon(hWnd, hIcon, desc); count++; } catch {}
      return true;
    }, IntPtr.Zero);
    return count;
  }
}
"@
$udd = '__UDD__'
$procName = '__PROCNAME__'
$ico = '__ICO__'
$n = __N__
$deadline = (Get-Date).AddSeconds(__SECS__)
$badged = 0
while ((Get-Date) -lt $deadline -and $badged -le 0) {
  $chromePids = @(Get-CimInstance Win32_Process -Filter ("Name='" + $procName + "'") |
    Where-Object { $_.CommandLine -ne $null -and $_.CommandLine.IndexOf($udd, [StringComparison]::OrdinalIgnoreCase) -ge 0 } |
    ForEach-Object { [uint32]$_.ProcessId })
  if ($chromePids.Count -gt 0) {
    $badged = [TB]::Badge($chromePids, $ico, ("Chrome taskbar badge " + $n))
    if ($badged -gt 0) { break }
  }
  Start-Sleep -Milliseconds 500
}
if ($badged -gt 0) {
  Write-Output ("BADGED " + $n + " " + $badged)
  Start-Sleep -Milliseconds 1500
  exit 0
}
Write-Output ("NOBADGE " + $n)
exit 3
`

/** Assemble the helper script with the application's parameters baked in
 *  (pure — unit-tested for the needle-escaping rules). */
export function buildTaskbarBadgeScript(userDir: string, channel: string | undefined, icoPath: string, badge: number, seconds: number): string {
  return TASKBAR_BADGE_PS
    .replaceAll('__UDD__', userDir.replaceAll("'", "''"))
    .replaceAll('__PROCNAME__', focusGuardProcessName(channel).replaceAll("'", "''"))
    .replaceAll('__ICO__', icoPath.replaceAll("'", "''"))
    .replaceAll('__N__', String(badge))
    .replaceAll('__SECS__', String(seconds))
}

export interface TaskbarBadgeResult {
  /** The badge number that was applied. */
  badge: number
  /** How many top-level Chrome windows received the overlay (0 = helper
   *  found none / failed — the number still stands in tool output). */
  windows: number
}

/** Apply the overlay badge to every visible Chrome window of the processes
 *  carrying this session's user-data-dir. Resolves when the helper reports
 *  BADGED/NOBADGE or after `waitMs` (the helper keeps retrying on its own up
 *  to its deadline and then exits). Never rejects — a badge is best effort. */
export async function applyTaskbarBadge(options: {
  userDir: string
  channel: string | undefined
  icoPath: string
  badge: number
  /** Helper's own retry window in seconds (default 12). */
  seconds?: number
  /** How long the caller waits for the helper's verdict (default 9000). */
  waitMs?: number
}): Promise<TaskbarBadgeResult> {
  const seconds = Math.max(1, Math.min(60, Math.round(options.seconds ?? 12)))
  const script = buildTaskbarBadgeScript(options.userDir, options.channel, options.icoPath, options.badge, seconds)
  // -EncodedCommand (UTF-16LE base64) — no command-line quoting hazards.
  const encoded = Buffer.from(script, 'utf16le').toString('base64')
  return await new Promise<TaskbarBadgeResult>(resolve => {
    let settled = false
    let stdout = ''
    let child: ReturnType<typeof spawn>
    const finish = (windows: number): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ badge: options.badge, windows })
    }
    const timer = setTimeout(() => finish(0), options.waitMs ?? 9_000)
    try {
      child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'ignore'],
      })
    } catch {
      finish(0)
      return
    }
    child.stdout?.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8')
      const match = stdout.match(/BADGED (\d+) (\d+)/)
      if (match !== null) {
        child.unref()
        finish(Number.parseInt(match[2]!, 10))
      }
    })
    child.on('exit', () => {
      if (stdout.includes('NOBADGE')) finish(0)
      else finish(0)
    })
    child.on('error', () => finish(0))
  })
}
