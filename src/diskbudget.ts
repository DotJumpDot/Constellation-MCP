import path from 'node:path'
import fs from 'node:fs'
import { normalizeDir } from './browser/registry.js'
import type { ConstellationConfig } from './config.js'

/** Disk budget (2026-11-20, user ask: the rootDir swelled past 60 GB across
 *  hunt runs because retained profile dirs and artifact files are only ever
 *  reaped when a Lead remembers to call browser_profiles_reap). This module
 *  measures the Constellation root and enforces a size cap by deleting the
 *  OLDEST evictable items first:
 *   - retained owner profile dirs under profilesRoot (deleted whole), and
 *   - artifact FILES under outputDir (screenshots, downloads, response
 *     bodies, evidence dirs — evicted per file, oldest mtime first).
 *  NEVER evictable: the shared profile (the human's logins), any dir with a
 *  LIVE session, any dir a running chrome.exe holds (fresh census right
 *  before deletion, not the walk's snapshot), the plain-shared dir, and all
 *  rootDir state (scope/jars/injectlab/fixture records — the small JSON and
 *  JSONL the tools depend on). */

export type DiskKind = 'profile' | 'artifact'

export interface DiskItem {
  path: string
  kind: DiskKind
  bytes: number
  mtime: number
}

export interface DiskMeasure {
  /** Everything counted under rootDir (+outputDir when it lives outside the
   *  root). Junctions/symlinks are skipped and only counted in skippedLinks. */
  totalBytes: number
  /** Every retained profile dir under profilesRoot, live ones included —
   *  protection is applied later so a measure never lies about what exists. */
  profiles: DiskItem[]
  /** Every regular file under outputDir. */
  artifacts: DiskItem[]
  /** Shared profile, injectlab, fixture/scope/jar state, logs — bytes that
   *  no budget pass may delete. */
  protectedBytes: number
  skippedLinks: number
  errors: string[]
}

export interface DiskPlan {
  /** Non-live, non-running, non-shared items, OLDEST FIRST. */
  evictable: DiskItem[]
  evictableBytes: number
  /** Profile dir names kept out of eviction (live session / chrome.exe /
   *  shared). */
  protectedNames: string[]
}

export interface DiskRun extends DiskPlan {
  measure: DiskMeasure
  capBytes: number
  evicted: DiskItem[]
  freedBytes: number
  /** True when this run only SIMULATED the eviction (dryRun): evicted and
   *  freedBytes describe what the next real pass would take, not deletions
   *  that already happened. */
  dryRun: boolean
  /** Still over the cap after every evictable item went — the mass sits in
   *  protected storage (usually the shared profile); surfaced instead of
   *  silently sitting over budget. */
  overCap: boolean
  errors: string[]
}

export interface DiskBudgetDeps {
  /** Live session dirs (userDir + adopted), normalized — re-queried right
   *  before EACH deletion so a lane launching mid-pass is never reaped. */
  liveDirs: () => string[]
  /** chrome.exe census (profile dirs currently running), normalized. */
  runningDirs: () => Promise<Set<string>>
}

const PROFILE_NEVER_TOUCHED = new Set(['shared-profile', 'plain-shared'])

export function fmtBytes(bytes: number): string {
  if (bytes >= 1_073_741_824) return `${(bytes / 1_073_741_824).toFixed(1)} GB`
  if (bytes >= 1_048_576) return `${Math.round(bytes / 1_048_576)} MB`
  return `${Math.max(0, Math.round(bytes / 1024))} KB`
}

function isUnder(child: string, parent: string): boolean {
  const rel = path.relative(parent, child)
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel)
}

/** Walk one directory tree. Async and sequential on purpose: a 60 GB Chrome
 *  profile tree is hundreds of thousands of stat calls — the MCP event loop
 *  must keep serving tool calls while the walk grinds. Symlinks/junctions
 *  are never followed (a junctioned profile would double-count or loop);
 *  unreadable entries are recorded, never fatal. */
async function walkTree(
  dir: string,
  onFile: (file: string, bytes: number, mtime: number) => void,
  acc: { bytes: number; newestMtime: number; skippedLinks: number; errors: string[] },
): Promise<void> {
  let entries: fs.Dirent[]
  try { entries = await fs.promises.readdir(dir, { withFileTypes: true }) } catch (error) {
    acc.errors.push(`${dir}: ${error instanceof Error ? error.message : String(error)}`)
    return
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name)
    if (entry.isSymbolicLink()) { acc.skippedLinks++; continue }
    if (!entry.isDirectory()) {
      try {
        const st = await fs.promises.stat(full)
        acc.bytes += st.size
        if (st.mtimeMs > acc.newestMtime) acc.newestMtime = st.mtimeMs
        onFile(full, st.size, st.mtimeMs)
      } catch (error) {
        acc.errors.push(`${full}: ${error instanceof Error ? error.message : String(error)}`)
      }
      continue
    }
    await walkTree(full, onFile, acc)
  }
}

async function dirExists(dir: string): Promise<boolean> {
  try { return (await fs.promises.stat(dir)).isDirectory() } catch { return false }
}

/** Measure the root. One pass, no side effects. Three concerns measured
 *  independently so an outputDir configured OUTSIDE the root still counts
 *  exactly once: retained profiles (whole-dir items), artifact files under
 *  outputDir (per-file items), and everything else under rootDir (protected
 *  mass — the shared profile, injectlab, fixture/scope/jar state, logs). */
export async function measureDisk(config: ConstellationConfig): Promise<DiskMeasure> {
  const measure: DiskMeasure = { totalBytes: 0, profiles: [], artifacts: [], protectedBytes: 0, skippedLinks: 0, errors: [] }
  const outputDirIsRoot = normalizeDir(config.outputDir) === normalizeDir(config.rootDir)

  if (await dirExists(config.profilesRoot)) {
    for (const pe of await fs.promises.readdir(config.profilesRoot, { withFileTypes: true })) {
      if (pe.isSymbolicLink()) { measure.skippedLinks++; continue }
      if (!pe.isDirectory()) continue
      const profileDir = path.join(config.profilesRoot, pe.name)
      const acc = { bytes: 0, newestMtime: 0, skippedLinks: 0, errors: measure.errors }
      await walkTree(profileDir, () => undefined, acc)
      try {
        const st = await fs.promises.stat(profileDir)
        if (st.mtimeMs > acc.newestMtime) acc.newestMtime = st.mtimeMs
      } catch { /* dir stat is a nicety */ }
      measure.totalBytes += acc.bytes
      measure.skippedLinks += acc.skippedLinks
      if (PROFILE_NEVER_TOUCHED.has(pe.name)) measure.protectedBytes += acc.bytes
      else measure.profiles.push({ path: profileDir, kind: 'profile', bytes: acc.bytes, mtime: acc.newestMtime })
    }
  }

  if (!outputDirIsRoot && await dirExists(config.outputDir)) {
    const acc = { bytes: 0, newestMtime: 0, skippedLinks: 0, errors: measure.errors }
    await walkTree(config.outputDir,
      (file, bytes, mtime) => measure.artifacts.push({ path: file, kind: 'artifact', bytes, mtime }), acc)
    measure.skippedLinks += acc.skippedLinks
    measure.totalBytes += measure.artifacts.reduce((sum, item) => sum + item.bytes, 0)
  }

  if (await dirExists(config.rootDir)) {
    for (const entry of await fs.promises.readdir(config.rootDir, { withFileTypes: true })) {
      const full = path.join(config.rootDir, entry.name)
      if (entry.isSymbolicLink()) { measure.skippedLinks++; continue }
      if (normalizeDir(full) === normalizeDir(config.profilesRoot)) continue // counted above
      if (!outputDirIsRoot && normalizeDir(full) === normalizeDir(config.outputDir)) continue // counted above
      if (entry.isDirectory()) {
        const acc = { bytes: 0, newestMtime: 0, skippedLinks: 0, errors: measure.errors }
        await walkTree(full, () => undefined, acc)
        measure.totalBytes += acc.bytes
        measure.protectedBytes += acc.bytes
        measure.skippedLinks += acc.skippedLinks
      } else {
        try {
          const st = await fs.promises.stat(full)
          measure.totalBytes += st.size
          measure.protectedBytes += st.size
        } catch { /* unreadable top-level file: counted as nothing */ }
      }
    }
  }
  return measure
}

function dirMatches(dir: string, known: string): boolean {
  const a = normalizeDir(dir)
  const b = normalizeDir(known)
  return a === b || a.endsWith(b) || b.endsWith(a)
}

/** Pure: which items MAY go under the cap, oldest first. `liveDirs` and
 *  `runningDirs` are already normalized. */
export function planEviction(measure: DiskMeasure, config: ConstellationConfig, liveDirs: string[], runningDirs: string[]): DiskPlan {
  const shared = normalizeDir(config.sharedUserDataDir)
  const protectedNames: string[] = []
  const evictable: DiskItem[] = []
  for (const profile of measure.profiles) {
    const name = path.basename(profile.path)
    if (normalizeDir(profile.path) === shared || PROFILE_NEVER_TOUCHED.has(name)) { protectedNames.push(name); continue }
    if (liveDirs.some(dir => dirMatches(profile.path, dir))) { protectedNames.push(name); continue }
    if (runningDirs.some(dir => dirMatches(profile.path, dir))) { protectedNames.push(name); continue }
    evictable.push(profile)
  }
  evictable.push(...measure.artifacts)
  evictable.sort((a, b) => a.mtime - b.mtime)
  return { evictable, evictableBytes: evictable.reduce((sum, item) => sum + item.bytes, 0), protectedNames }
}

/** Best-effort prune of dirs left empty by artifact-file eviction. */
function pruneEmptyDirs(file: string, stopAt: string): void {
  let dir = path.dirname(file)
  while (dir.length > stopAt.length && isUnder(dir, stopAt)) {
    try { fs.rmdirSync(dir) } catch { return /* not empty / in use */ }
    dir = path.dirname(dir)
  }
}

/** Measure, then delete oldest-first until the root is under the cap.
 *  Census and live-session checks run right before deletion (the walk can
 *  take minutes on a swelled tree — a lane that launched mid-walk must not
 *  have its fresh profile reaped). */
export async function enforceDiskBudget(config: ConstellationConfig, deps: DiskBudgetDeps, dryRun = false): Promise<DiskRun> {
  const capBytes = config.diskBudgetMb * 1_048_576
  const measure = await measureDisk(config)
  if (capBytes <= 0)
    return { measure, capBytes, evictable: [], evictableBytes: 0, protectedNames: [], evicted: [], freedBytes: 0, dryRun: false, overCap: false, errors: measure.errors }
  const running = [...await deps.runningDirs()].map(normalizeDir)
  const plan = planEviction(measure, config, deps.liveDirs().map(normalizeDir), running)
  const run: DiskRun = { measure, capBytes, ...plan, evicted: [], freedBytes: 0, dryRun, overCap: false, errors: [...measure.errors] }
  if (measure.totalBytes <= capBytes) return run
  const isLiveNow = (item: DiskItem): boolean =>
    deps.liveDirs().map(normalizeDir).some(dir => dirMatches(item.path, dir))
  for (const item of plan.evictable) {
    if (measure.totalBytes - run.freedBytes <= capBytes) break
    if (item.kind === 'profile' && isLiveNow(item)) { run.protectedNames.push(path.basename(item.path)); continue }
    if (dryRun) { run.evicted.push(item); run.freedBytes += item.bytes; continue }
    try {
      fs.rmSync(item.path, { recursive: true, force: true })
      if (item.kind === 'artifact') pruneEmptyDirs(item.path, config.outputDir)
      run.evicted.push(item)
      run.freedBytes += item.bytes
    } catch (error) {
      run.errors.push(`${item.path}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
  run.overCap = measure.totalBytes - run.freedBytes > capBytes
  return run
}

/** One-line summary for stderr / tool output. */
export function diskBudgetLine(run: DiskRun): string {
  const evictedProfiles = run.evicted.filter(item => item.kind === 'profile').length
  const evictedFiles = run.evicted.length - evictedProfiles
  if (run.evicted.length === 0) {
    return `${fmtBytes(run.measure.totalBytes)} / ${fmtBytes(run.capBytes)} cap — OK`
      + (run.overCap ? ` — OVER CAP with nothing evictable (protected mass: shared profile/state — storage_reap shows the breakdown)` : '')
  }
  return `${fmtBytes(run.measure.totalBytes)} > ${fmtBytes(run.capBytes)} cap — evicted ${evictedProfiles} profile dir(s) + ${evictedFiles} artifact file(s), freed ${fmtBytes(run.freedBytes)} (now ~${fmtBytes(run.measure.totalBytes - run.freedBytes)})`
    + (run.overCap ? ` — still over cap: protected mass (shared profile/state) — storage_reap shows the breakdown` : '')
}
