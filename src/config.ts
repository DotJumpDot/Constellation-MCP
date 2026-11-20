import path from 'node:path'
import os from 'node:os'
import fs from 'node:fs'

export interface ConstellationConfig {
  /** State root: profiles, artifacts, scope, jars, oob records. */
  rootDir: string
  /** user-data-dir of the `shared` session (the human's logged-in profile). */
  sharedUserDataDir: string
  /** Parent directory for per-owner profiles. */
  profilesRoot: string
  /** Screenshots/artifacts land in outputDir/<owner>/. */
  outputDir: string
  /** Browser channel: 'chrome' uses the installed Google Chrome. */
  channel: string
  headless: boolean
  oobPort: number
  /** Public base for OOB tokens when a tunnel fronts the local receiver. */
  oobPublicBase?: string
  /** Minutes of idleness before an owner session auto-closes (0 = never). */
  idleTimeoutMin: number
  scopeFile: string
  auditFile: string
  /** When true (CONSTELLATION_REQUIRE_SCOPE=1): no scope set ⇒ every
   *  non-local request is denied. Default: unrestricted until scope_set. */
  requireScope: boolean
  /** "x,y" (CONSTELLATION_WINDOW_POSITION): every spawned Chrome window is
   *  pinned there (--window-position) — e.g. "2560,100" for the right monitor
   *  so spawns never cover a fullscreen game on the main screen. Per-owner
   *  cascade keeps 10+ windows from stacking exactly. */
  windowPosition?: string
  /** true (CONSTELLATION_START_MINIMIZED=1): spawn windows start minimized to
   *  the taskbar (--start-minimized) — maximum quiet; CDP tooling still works,
   *  but prefer window-position when you need to SEE the windows. */
  startMinimized: boolean
  /** Visible tab-strip pixels for a PARKED window (CONSTELLATION_WINDOW_PEEK_PX,
   *  default 36; clamped to 20–60): every launched window parks at the BOTTOM
   *  of its monitor's work area with only the tab strip peeking (round-8 §5,
   *  the human's measured preference — top = availTop + availH − peek). */
  windowPeekPx: number
  /** PARK box applied by the launch helper in addition to the peek (round-11
   *  fix — the human's MEASURED preference is also a fixed left offset and
   *  size; the launch flag alone left windows flush at the screen's left edge,
   *  measured left = availLeft + 0 vs spec availLeft + 367):
   *  left = workArea.left + offset, width/height in px.
   *  CONSTELLATION_WINDOW_PARK_LEFT_OFFSET (default 367),
   *  CONSTELLATION_WINDOW_PARK_WIDTH (default 945),
   *  CONSTELLATION_WINDOW_PARK_HEIGHT (default 1012). */
  windowParkLeftOffset: number
  windowParkWidth: number
  windowParkHeight: number
  /** true (default; CONSTELLATION_FOCUS_GUARD=0 disables): arm the post-spawn
   *  focus watchdog on every launch — when the freshly spawned Chrome steals
   *  the foreground (it always does, at window creation), hand it back via
   *  AttachThreadInput (run-9 focus advice §4, verified by the human). */
  focusGuard: boolean
  /** RAM guard (run-39 RAM round): a live session whose chrome.exe tree sums
   *  above this many MB gets `ramWarning` on browser_map/browser_tabs. 0 =
   * off. CONSTELLATION_RAM_GUARD_MB (default 2500 — the run-39 mtree2a lane
   * ballooned a single renderer past 10 GB while "active" and nothing
   * surfaced it until the human opened Task Manager). */
  ramGuardMb: number
  /** true (CONSTELLATION_RAM_AUTOPARK=1): the RAM guard CLOSES an
   *  over-threshold session instead of only warning (profile preserved —
   *  browser_launch_plain relaunches warm). Off by default: a live lane's
   *  browser dying mid-card is a decision for the Lead, not a default. */
  ramAutoPark: boolean
  /** Disk budget in MB for the rootDir (2026-11-20: 60+ GB accumulated
   *  across hunt runs). On server start — and every diskBudgetCheckMin
   *  minutes — the oldest NON-evictable-safe items (retained profile dirs
   *  with no live session/chrome, then artifact files, oldest first) are
   *  deleted until the root is under the cap. 0 = off.
   *  CONSTELLATION_DISK_BUDGET_MB (default 10240 = 10 GB). */
  diskBudgetMb: number
  /** Disk-budget re-check cadence in minutes (0 = startup check only).
   *  CONSTELLATION_DISK_BUDGET_CHECK_MIN (default 30). */
  diskBudgetCheckMin: number
  /** Noise-governor profile (ARTEX-mining round 2026-11-20): off|quiet|
   *  balanced|aggressive. Every outbound target touch is paced by
   *  per-owner/per-host/global token buckets + jitter — queued, never
   *  dropped; budget_set stays the hard tier. Default quiet (noise only
   *  gets harder). CONSTELLATION_NOISE_PROFILE; runtime noise_profile. */
  noiseProfile: string
  /** true (default; CONSTELLATION_UNTRUSTED_FRAMING=0 disables): wrap
   *  target-derived tool output (page snapshots, HTTP body previews,
   *  escape-hatch results) in UNTRUSTED TARGET CONTENT markers with a
   *  standing ignore-directives line — prompt-injection defense
   *  (ARTEX-mining mechanism 5). Advisory, and marker-shaped text inside
   *  the content is neutralized so a page cannot forge frames. */
  untrustedFraming: boolean
  /** Extra deny patterns for the escape-hatch fence (ARTEX-mining
   *  mechanism 4): semicolon-separated regex sources checked against the
   *  browser_run_code_unsafe code text, ON TOP of the built-ins
   *  (child_process, process.exit, window.open, bare busy-waits).
   *  CONSTELLATION_UNSAFE_ALLOW may exempt ONLY these operator rules,
   *  never the built-ins. Every decision is audited (sha256, not code). */
  unsafeDeny?: string
  unsafeAllow?: string
}

function env(name: string): string | undefined {
  const v = process.env[`CONSTELLATION_${name}`]
  return v === undefined || v === '' ? undefined : v
}

function int(name: string, fallback: number): number {
  const v = env(name)
  if (v === undefined) return fallback
  const n = Number.parseInt(v, 10)
  return Number.isFinite(n) ? n : fallback
}

export function defaultConfig(): ConstellationConfig {
  const rootDir = env('ROOT')
    ?? path.join(process.env.LOCALAPPDATA ?? os.homedir(), 'constellation-mcp')
  return {
    rootDir,
    sharedUserDataDir: env('SHARED_USER_DATA_DIR')
      ?? path.join(rootDir, 'shared-profile'),
    profilesRoot: path.join(rootDir, 'profiles'),
    outputDir: env('OUTPUT_DIR') ?? path.join(rootDir, 'artifacts'),
    channel: env('BROWSER') ?? 'chrome',
    headless: env('HEADLESS') === '1' || env('HEADLESS') === 'true',
    oobPort: int('OOB_PORT', 8787),
    oobPublicBase: env('OOB_PUBLIC_BASE'),
    idleTimeoutMin: int('IDLE_TIMEOUT_MIN', 45),
    scopeFile: path.join(rootDir, 'scope.json'),
    auditFile: path.join(rootDir, 'scope-audit.jsonl'),
    requireScope: env('REQUIRE_SCOPE') === '1' || env('REQUIRE_SCOPE') === 'true',
    windowPosition: env('WINDOW_POSITION'),
    startMinimized: env('START_MINIMIZED') === '1' || env('START_MINIMIZED') === 'true',
    windowPeekPx: int('WINDOW_PEEK_PX', 36),
    windowParkLeftOffset: int('WINDOW_PARK_LEFT_OFFSET', 367),
    windowParkWidth: int('WINDOW_PARK_WIDTH', 945),
    windowParkHeight: int('WINDOW_PARK_HEIGHT', 1012),
    focusGuard: env('FOCUS_GUARD') !== '0' && env('FOCUS_GUARD') !== 'false',
    ramGuardMb: int('RAM_GUARD_MB', 2500),
    ramAutoPark: env('RAM_AUTOPARK') === '1' || env('RAM_AUTOPARK') === 'true',
    diskBudgetMb: int('DISK_BUDGET_MB', 10240),
    diskBudgetCheckMin: int('DISK_BUDGET_CHECK_MIN', 30),
    noiseProfile: env('NOISE_PROFILE') ?? 'quiet',
    untrustedFraming: env('UNTRUSTED_FRAMING') !== '0' && env('UNTRUSTED_FRAMING') !== 'false' && env('UNTRUSTED_FRAMING') !== 'off',
    unsafeDeny: env('UNSAFE_DENY'),
    unsafeAllow: env('UNSAFE_ALLOW'),
  }
}

const FLAG_MAP: Record<string, keyof ConstellationConfig> = {
  '--root': 'rootDir',
  '--shared-user-data-dir': 'sharedUserDataDir',
  '--output-dir': 'outputDir',
  '--browser': 'channel',
  '--oob-public-base': 'oobPublicBase',
  '--scope-file': 'scopeFile',
  '--audit-file': 'auditFile',
  '--window-position': 'windowPosition',
}

/** Mutates config from argv; returns argv with recognized flags removed. */
export function applyCliArgs(config: ConstellationConfig, argv: string[]): string[] {
  const rest: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!
    const value = (): string | undefined => {
      if (arg.includes('=')) return arg.slice(arg.indexOf('=') + 1)
      const next = argv[i + 1]
      if (next === undefined) return undefined
      i += 1
      return next
    }
    if (arg === '--headless') { config.headless = true; continue }
    if (arg === '--start-minimized') { config.startMinimized = true; continue }
    if (arg === '--no-untrusted-framing') { config.untrustedFraming = false; continue }
    if ((arg === '--window-peek-px' || arg.startsWith('--window-peek-px='))) {
      const raw = arg.includes('=') ? arg.slice(arg.indexOf('=') + 1) : value()
      const v = Number.parseInt(raw ?? '', 10)
      if (Number.isFinite(v)) config.windowPeekPx = v
      continue
    }
    const parkFlag = ['--window-park-left-offset', '--window-park-width', '--window-park-height']
      .find(flag => arg === flag || arg.startsWith(`${flag}=`))
    if (parkFlag !== undefined) {
      const raw = arg.includes('=') ? arg.slice(arg.indexOf('=') + 1) : value()
      const v = Number.parseInt(raw ?? '', 10)
      if (Number.isFinite(v)) {
        if (parkFlag === '--window-park-left-offset') config.windowParkLeftOffset = v
        else if (parkFlag === '--window-park-width') config.windowParkWidth = v
        else config.windowParkHeight = v
      }
      continue
    }
    const key = arg.includes('=') ? arg.slice(0, arg.indexOf('=')) : arg
    const field = FLAG_MAP[key]
    if (field !== undefined) {
      const v = value()
      if (v !== undefined) (config as unknown as Record<string, unknown>)[field] = v
      continue
    }
    if (key === '--oob-port' || key === '--idle-timeout-min' || key === '--disk-budget-mb' || key === '--disk-budget-check-min') {
      const v = Number.parseInt(value() ?? '', 10)
      if (Number.isFinite(v)) {
        const field = key === '--oob-port' ? 'oobPort' : key === '--idle-timeout-min' ? 'idleTimeoutMin'
          : key === '--disk-budget-mb' ? 'diskBudgetMb' : 'diskBudgetCheckMin'
        ;(config as unknown as Record<string, unknown>)[field] = v
      }
      continue
    }
    if (key === '--noise-profile') {
      const v = value()
      if (v !== undefined) config.noiseProfile = v
      continue
    }
    rest.push(arg)
  }
  return rest
}

export function ensureDirs(config: ConstellationConfig): void {
  for (const dir of [config.rootDir, config.profilesRoot, config.outputDir, path.dirname(config.scopeFile)])
    fs.mkdirSync(dir, { recursive: true })
}
