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
    if ((arg === '--window-peek-px' || arg.startsWith('--window-peek-px='))) {
      const raw = arg.includes('=') ? arg.slice(arg.indexOf('=') + 1) : value()
      const v = Number.parseInt(raw ?? '', 10)
      if (Number.isFinite(v)) config.windowPeekPx = v
      continue
    }
    const key = arg.includes('=') ? arg.slice(0, arg.indexOf('=')) : arg
    const field = FLAG_MAP[key]
    if (field !== undefined) {
      const v = value()
      if (v !== undefined) (config as unknown as Record<string, unknown>)[field] = v
      continue
    }
    if (key === '--oob-port' || key === '--idle-timeout-min') {
      const v = Number.parseInt(value() ?? '', 10)
      if (Number.isFinite(v)) {
        ;(config as unknown as Record<string, unknown>)[key === '--oob-port' ? 'oobPort' : 'idleTimeoutMin'] = v
      }
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
