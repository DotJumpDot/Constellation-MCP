import z from 'zod'
import { errorResult, textResult, type ToolRegistrar, type ToolResult } from '../browser/tools.js'
import { isNoiseProfileName, noiseGovernor, noiseLeversLine, type NoiseProfileName } from '../noise.js'

/** The Lead-facing arm of the noise governor: the live report and the
 *  runtime profile lever. The governor itself paces silently at every
 *  choke point (browser navigations, new tabs, http_request/replay/
 *  download, diff/recipe legs). */

function fmtCounter(row: { sent: number; peakRpm: number; waits: number; totalWaitMs: number }): string {
  return `${row.sent}/min now · peak ${row.peakRpm}/min · throttled ${row.waits}× (${(row.totalWaitMs / 1000).toFixed(1)}s waited)`
}

function report(): string {
  const governor = noiseGovernor()
  if (governor === undefined)
    return 'noise governor not installed (this server predates the 2026-11-20 round — restart to load it).'
  const snap = governor.snapshot()
  if (snap.profile === 'off')
    return ['noise governor: OFF (strict passthrough — nothing paced, nothing counted).', 'noise_profile {profile:"quiet"} re-arms it; budget_set caps still apply either way.'].join('\n')
  const levers = snap.levers!
  const lines = [
    `noise governor: profile "${snap.profile}" — ${noiseLeversLine(snap.profile)}`,
    `global: ${fmtCounter(snap.global)}`,
  ]
  if (snap.owners.length > 0) {
    lines.push('per owner:')
    for (const row of snap.owners.slice(0, 12)) lines.push(`  ${row.owner.padEnd(18)} ${fmtCounter(row)}`)
    if (snap.owners.length > 12) lines.push(`  … +${snap.owners.length - 12} more`)
  }
  if (snap.hosts.length > 0) {
    lines.push('per host (shared across owners):')
    for (const row of snap.hosts.slice(0, 12)) lines.push(`  ${row.host.padEnd(34)} ${fmtCounter(row)}`)
    if (snap.hosts.length > 12) lines.push(`  … +${snap.hosts.length - 12} more`)
  }
  lines.push('hard tier: budget_set/budget_raise still REFUSE past a per-owner TOTAL cap — the governor paces, the budget stops.')
  lines.push('every paced request is appended to noise-audit.jsonl (ts/owner/host/waited_ms).')
  return lines.join('\n')
}

export function registerNoiseTools(server: ToolRegistrar): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('noise_report', 'Live noise-governor report (ARTEX-mining round 2026-11-20): every outbound target touch (browser_navigate, browser_fetch, browser_tabs new, tab_open, http_request/http_replay/http_download, diff/recipe legs) is PACED by three token buckets — per-owner, per-host (shared across owners) and global — plus uniform send jitter. Calls QUEUE (sleep) until a token frees; only a wait beyond 120s refuses. Reads rpm now / peak rpm / throttle waits per owner and per host. The hard tier is separate: budget_set still refuses past a per-owner TOTAL. Answers "how loud have my lanes been".',
    {},
    async () => textResult(report()))

  t('noise_profile', `Switch the noise-governor profile at runtime (the Lead's lever; also CONSTELLATION_NOISE_PROFILE at start). Profiles: quiet — ${noiseLeversLine('quiet')}; balanced — ${noiseLeversLine('balanced')}; aggressive — ${noiseLeversLine('aggressive')}; off — strict passthrough (nothing paced or counted; budget caps still apply). Switching resets counters and is audited in noise-audit.jsonl.`,
    {
      profile: z.enum(['off', 'quiet', 'balanced', 'aggressive']).describe('quiet = default human-like lanes; balanced/aggressive raise ceilings deliberately; off disables pacing'),
    },
    async ({ profile }: any) => {
      const governor = noiseGovernor()
      if (governor === undefined) return textResult('noise governor not installed — restart the server to load it.', true)
      const name = String(profile) as NoiseProfileName
      if (!isNoiseProfileName(name)) return textResult(`unknown profile "${String(profile)}"`, true)
      const { from, to } = governor.setProfile(name)
      process.stderr.write(`constellation-mcp noise: profile ${from} → ${to} (${to === 'off' ? 'pacing off' : noiseLeversLine(to)})\n`)
      return textResult(`noise governor: ${from} → ${to}${to === 'off' ? ' (strict passthrough; budget caps still apply)' : ` — ${noiseLeversLine(to)}. Counters reset.`}`)
    })
}
