import z from 'zod'
import path from 'node:path'
import { errorResult, textResult, type ToolResult, type ToolRegistrar } from '../browser/tools.js'
import { enforceDiskBudget, fmtBytes, type DiskBudgetDeps } from '../diskbudget.js'
import type { ConstellationConfig } from '../config.js'
import type { OwnerRegistry } from '../browser/registry.js'

/** The agent-facing arm of the disk budget: the same measurement + oldest-
 *  first eviction the server runs automatically at start and every 30 min,
 *  callable on demand (status by default — deletion needs dry_run:false). */

function depsFor(config: ConstellationConfig, registry: OwnerRegistry): DiskBudgetDeps {
  return {
    liveDirs: () => registry.liveUserDirs(),
    runningDirs: () => registry.runningProfileDirs(),
  }
}

function statusLines(result: Awaited<ReturnType<typeof enforceDiskBudget>>, rootDir: string): string[] {
  const shortPath = (p: string): string => {
    const rel = path.relative(rootDir, p)
    return rel === '' || rel.startsWith('..') ? p : rel
  }
  const { measure, capBytes } = result
  const profilesBytes = measure.profiles.reduce((sum, item) => sum + item.bytes, 0)
  const artifactsBytes = measure.artifacts.reduce((sum, item) => sum + item.bytes, 0)
  const protectedProfiles = measure.profiles
    .filter(item => result.protectedNames.includes(path.basename(item.path)))
    .reduce((sum, item) => sum + item.bytes, 0)
  return [
    `storage: ${fmtBytes(measure.totalBytes)} / ${fmtBytes(capBytes)} cap${measure.totalBytes > capBytes ? ' — OVER CAP' : ''}`,
    `  retained profiles: ${measure.profiles.length} dir(s) = ${fmtBytes(profilesBytes)} (${result.protectedNames.length} protected: live session / running chrome / shared — ${fmtBytes(protectedProfiles)})`,
    `  artifacts: ${measure.artifacts.length} file(s) = ${fmtBytes(artifactsBytes)} (screenshots, downloads, response bodies, evidence dirs)`,
    `  protected state (shared profile, injectlab, fixture/scope/jar records, logs): ${fmtBytes(measure.protectedBytes)}`,
    ...(measure.skippedLinks > 0 ? [`  skipped ${measure.skippedLinks} symlink/junction(s) (never followed)`] : []),
    ...(result.evictable.length > 0
      ? [
          `oldest evictable (deleted oldest-FIRST when the cap is exceeded):`,
          ...result.evictable.slice(0, 10).map(item =>
            `  ${new Date(item.mtime).toISOString().slice(0, 10)}  ${fmtBytes(item.bytes).padStart(8)}  ${item.kind === 'profile' ? '[profile] ' : ''}${shortPath(item.path)}`),
          ...(result.evictable.length > 10 ? [`  … +${result.evictable.length - 10} more`] : []),
        ]
      : ['nothing evictable (no retained profiles, no artifacts)']),
    ...(result.evicted.length > 0
      ? [result.dryRun
          ? `NEXT PASS WOULD EVICT ${result.evicted.length} item(s) = ${fmtBytes(result.freedBytes)} (oldest first) — call with dry_run:false to do it now`
          : `EVICTED just now: ${result.evicted.length} item(s), freed ${fmtBytes(result.freedBytes)} — now ~${fmtBytes(measure.totalBytes - result.freedBytes)}`]
      : []),
    ...(result.overCap ? [`STILL OVER CAP: the mass sits in protected storage (usually the shared profile's Chrome caches) — clear Chrome caches manually or raise CONSTELLATION_DISK_BUDGET_MB.`] : []),
    ...(result.errors.length > 0 ? [`errors: ${result.errors.slice(0, 3).join(' | ')}`] : []),
  ]
}

export function registerStorageTools(server: ToolRegistrar, config: ConstellationConfig, registry: OwnerRegistry): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('storage_reap', 'Disk budget report for the Constellation root (call with NO arguments = status only). The root is CAPPED (default 10 GB, CONSTELLATION_DISK_BUDGET_MB) and enforced automatically at server start and every 30 min: when over the cap the OLDEST safe items are deleted — retained profile dirs with NO live session and NO running chrome.exe first, then artifact files (screenshots/downloads/response bodies/evidence) oldest-first. NEVER deleted: the shared profile (human logins), live-session dirs, dirs a running chrome.exe holds, and the small state files (scope/jars/injectlab/fixture records). `dry_run:false` enforces NOW instead of waiting for the next automatic pass. Answers "why is constellation eating my disk".',
    {
      dry_run: z.boolean().optional().describe('false = enforce the cap NOW (default true = status report only)'),
    },
    async ({ dry_run }: any) => {
      if (config.diskBudgetMb <= 0)
        return textResult(`disk budget is OFF (CONSTELLATION_DISK_BUDGET_MB=0) — nothing is measured or evicted. Restart with the budget enabled to use this tool.`)
      const result = await enforceDiskBudget(config, depsFor(config, registry), dry_run !== false)
      const head = dry_run === false
        ? `ENFORCED: ${fmtBytes(result.measure.totalBytes)} vs ${fmtBytes(result.capBytes)} cap`
        : `STATUS (dry run — dry_run:false enforces now):`
      return textResult([head, ...statusLines(result, config.rootDir)].join('\n'))
    })
}
