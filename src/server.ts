import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { McpError } from '@modelcontextprotocol/sdk/types.js'
import path from 'node:path'
import type { ConstellationConfig } from './config.js'
import { ScopeGuard } from './scope.js'
import { OwnerRegistry } from './browser/registry.js'
import { registerBrowserTools, type ToolEnv, type ToolRegistrar } from './browser/tools.js'
import { JarStore, registerHttpTools } from './tools/http.js'
import { registerMailTools } from './tools/mail.js'
import { registerScopeTools } from './tools/scope.js'
import { registerSecretTools } from './tools/secrets.js'
import { OobStore, registerOobTools } from './tools/oob.js'
import { registerGitTools } from './tools/git.js'
import { BudgetGuard, registerBudgetTools } from './tools/budget.js'
import { FixtureStore, registerFixtureTools } from './tools/fixture.js'
import { registerDiffTools } from './tools/diff.js'
import { SessionWatchRegistry, KeepaliveRegistry, registerSessionTools } from './tools/session.js'
import { registerEvidenceTools } from './tools/evidence.js'
import { registerDupeTools } from './tools/dupcheck.js'
import { InjectStore, registerInjectTools } from './tools/injectlab.js'
import { registerRecipeTools } from './tools/recipe.js'
import { registerCellTools } from './tools/cell.js'
import { registerMcpTools } from './tools/mcp.js'
import { registerDnsTools } from './tools/dns.js'
import { registerReportTools } from './tools/report.js'
import { registerStorageTools } from './tools/storage.js'
import { diskBudgetLine, enforceDiskBudget } from './diskbudget.js'

export interface ConstellationServer {
  connect(): Promise<void>
  dispose(): Promise<void>
}

/** Best candidate for a mistyped tool name (run-50 §14: lanes guessed
 * "browser_import" and burned a call on the bare not-found). Two honest
 * signals only: EVERY 3+ char token of the guess appears in the candidate
 * (browser_import → browser_cookies_import, even though edit distance says
 * 8), or a near typo on the normalized forms (scope_reep → scope_reap).
 * Partial overlap suggests nothing — that is a different tool, not a typo.
 * Pure; tested. */
export function suggestToolName(raw: string, known: readonly string[]): string | undefined {
  const norm = (s: string) => s.toLowerCase().replace(/^mcp__constellation__/, '').replace(/[-_]/g, '')
  const stripped = raw.toLowerCase().replace(/^mcp__constellation__/, '')
  const n = norm(raw)
  if (n === '') return undefined
  // A name that IS real is not a typo — never "suggest" a sibling instead.
  if (known.some(k => norm(k) === n)) return undefined
  const tokens = stripped.split(/[^a-z0-9]+/).filter(t => t.length >= 3)
  const maxEdits = Math.max(2, Math.floor(n.length / 5))
  let best: { name: string; extra: number } | undefined
  for (const name of known) {
    const cand = norm(name)
    const fullOverlap = tokens.length > 0 && tokens.every(t => cand.includes(t))
    const nearTypo = !fullOverlap && editDistance(n, cand) <= maxEdits
    if (!fullOverlap && !nearTypo) continue
    const extra = Math.abs(cand.length - n.length)
    if (best === undefined || extra < best.extra) best = { name, extra }
  }
  return best?.name
}

function editDistance(a: string, b: string): number {
  // bounded Wagner–Fischer; strings here are short tool names
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i)
  for (let i = 1; i <= a.length; i++) {
    let carry = prev[0]!
    prev[0] = i
    for (let j = 1; j <= b.length; j++) {
      const temp = prev[j]!
      prev[j] = Math.min(prev[j]! + 1, prev[j - 1]! + 1, carry + (a[i - 1] === b[j - 1] ? 0 : 1))
      carry = temp
    }
  }
  return prev[b.length]!
}

/** Append a "did you mean" hint to the SDK's bare `Tool X not found` error.
 * Feature-detected on the SDK's internal handler map (keyed by the method
 * STRING 'tools/call' in SDK ≥1.25) — if a future SDK release moves it, the
 * hint silently disappears and the server behaves exactly as before (the
 * suggestion itself lives in the tested suggestToolName above). */
function installUnknownToolHint(mcp: McpServer, names: Set<string>): void {
  const hintFor = (guessed: string): string => {
    const best = suggestToolName(guessed, [...names])
    return best !== undefined
      ? ` — did you mean "${best}"? (mcp_tools lists all ${names.size} tools)`
      : ` (mcp_tools lists all ${names.size} tools)`
  }
  try {
    const handlers = (mcp as unknown as { server?: { _requestHandlers?: unknown } }).server?._requestHandlers
    if (!(handlers instanceof Map)) return
    const original = handlers.get('tools/call') as
      | ((request: unknown, extra: unknown) => Promise<unknown>)
      | undefined
    if (typeof original !== 'function') return
    handlers.set('tools/call', async (request: unknown, extra: unknown) => {
      try {
        const result = await original(request, extra)
        // SDK ≥1.25 folds the not-found McpError into an isError RESULT
        // (createToolError), carrying the McpError text — sometimes with its
        // "MCP error -32602: " toString prefix — patch the text there.
        const first = (result as { isError?: boolean; content?: Array<{ text?: string }> })?.content?.[0]
        if ((result as { isError?: boolean })?.isError === true && first?.text !== undefined) {
          const match = /^(?:MCP error -\d+: )?(Tool (.+) not found)$/.exec(first.text)
          if (match !== null) first.text = `${match[1]}${hintFor(match[2]!)}`
        }
        return result
      } catch (error) {
        // Older/other paths throw the McpError instead — patch the throw.
        const message = error instanceof Error ? error.message : String(error)
        const match = /^Tool (.+) not found$/.exec(message)
        if (match === null || !(error instanceof McpError)) throw error
        throw new McpError((error as McpError).code, `${message}${hintFor(match[1]!)}`)
      }
    })
  } catch { /* feature-detect failed — no hint, original behavior */ }
}

/** Disk-budget loop (2026-11-20, user ask: the rootDir swelled past 60 GB
 *  because nothing reaps retained profiles/artifacts unless a Lead calls a
 *  tool): first pass ~2 s after start (after the MCP handshake), then every
 *  diskBudgetCheckMin minutes. Announces the measurement once at start;
 *  later passes only speak when they evicted something or sit over the cap
 *  with nothing left to take. */
function startDiskBudgetLoop(config: ConstellationConfig, registry: OwnerRegistry): { stop(): void } {
  if (config.diskBudgetMb <= 0) return { stop() { /* budget off */ } }
  let busy = false
  const pass = async (announce: boolean): Promise<void> => {
    if (busy) return
    busy = true
    try {
      const run = await enforceDiskBudget(config, {
        liveDirs: () => registry.liveUserDirs(),
        runningDirs: () => registry.runningProfileDirs(),
      })
      if (run.evicted.length > 0 || announce || run.overCap)
        process.stderr.write(`constellation-mcp disk-budget: ${diskBudgetLine(run)}\n`)
    } catch (error) {
      process.stderr.write(`constellation-mcp disk-budget pass failed: ${error instanceof Error ? error.message : String(error)}\n`)
    } finally {
      busy = false
    }
  }
  const timer = setTimeout(() => void pass(true), 2_000)
  timer.unref()
  let interval: ReturnType<typeof setInterval> | undefined
  if (config.diskBudgetCheckMin > 0) {
    interval = setInterval(() => void pass(false), config.diskBudgetCheckMin * 60_000)
    interval.unref()
  }
  return {
    stop(): void {
      clearTimeout(timer)
      if (interval !== undefined) clearInterval(interval)
    },
  }
}

export function buildServer(config: ConstellationConfig): ConstellationServer {
  const registry = new OwnerRegistry(config)
  const scope = new ScopeGuard(config.scopeFile, config.auditFile, config.requireScope)
  const budget = new BudgetGuard(path.join(config.rootDir, 'budgets.json'))
  const env: ToolEnv = { config, registry, scope, budget }
  const oob = new OobStore(config.oobPort, config.oobPublicBase, path.join(config.rootDir, 'oob-log.jsonl'))
  const jars = new JarStore(config)
  const fixtures = new FixtureStore(oob, config)
  const injects = new InjectStore(path.join(config.rootDir, 'injectlab'))
  const watches = new SessionWatchRegistry()
  const keepalives = new KeepaliveRegistry()

  const mcp = new McpServer({ name: 'constellation', version: '0.1.0' }, {
    instructions: [
      'Constellation: per-agent browser isolation + engagement tooling for agent teams.',
      'Every browser tool takes an optional `owner` — pass YOUR agent name so your cookies, tabs, and window stay isolated. Omitted = the shared human session.',
      'Call browser_map for the ownership map; tab_open/tab_lease to hold tabs; browser_reset {keep:["shared"]} at lane end.',
      'scope_set before engaging a target — http_request and navigation are then scope-enforced and audited.',
      'Secrets: reference $secret:NAME inside http_request instead of pasting values.',
      'browser_run_code_unsafe is the escape hatch (full Page API + Node require, NOT scope-guarded inside) — use it only when guarded tools cannot express the step.',
      'human_task_* / lane_freeze / team_snapshot are NATIVE team tools with no mcp__ prefix — do not add a server prefix to them.',
      'Manufacture fixtures, do not hand-build them: fixture_publish (public URL + canary; fixture_hits answers canary_seen), fixture_forge (real .docx/.pdf for browser_upload), dupe_check before deep work (KEV/sightings/bundles enriched), diff_pair for the authorization verdict (it cites itself in the evidence chain), session_verify/session_watch with per-site proof rules, http_replay to vary exactly one field, http_extract for one VALUE out of a capture, evidence_capture/evidence_file/evidence_verify for the tamper-evident chain.',
      'Track the work in CELLS, not memory: cell_register the object+principal+expected verdict (a `shape` tag recalls the same bug shape across engagements), cell_run stores the verdict tuple (NOT_FOUND = INCONCLUSIVE, never negative), cell_status is the scoreboard, cell_ledger replaces hand-curated markdown, recipe_drift names DENY→ALLOW transitions, report_assemble builds the skeleton from CANDIDATE cells only.',
      'MCP surfaces (Methods/72): mcp_tools FIRST (snapshot tools/list — descriptions are agent instructions, so their text stays on disk and never enters the transcript), mcp_diff for rug pulls (description changes after approval), mcp_auth_gate for the none/malformed matrix (bounded 12 requests, 1 req/s, never destructive tools); http_request {save_body:true} captures a JSON body to disk whole; chain the snapshot with evidence_file.',
      'P1/P2 asks (2026-11-06): browser_network_bodies exports the captured request/response bodies of calls the browser ALREADY made (sha256 + artifacts dir, redacted preview — the input every replay card needs); dns_takeover_check is the read-only dangling-CNAME sweep (versioned fingerprint table, claimable verdicts, fetch:true reads the origin page — NO claiming, ever); evidence_scan runs the secret-pattern scan over an owner\'s artifacts and chains it (hits redacted to first4…last4 + sha256); repo_commit accepts git-mv renames (pass the new path; the staged source is included) and its "Pushed." claim is verified against git status.',
    ].join('\n'),
  })

  const toolNames = new Set<string>()
  const registrar: ToolRegistrar = {
    registerTool: (name, info, schema, handler) => {
      toolNames.add(name)
      mcp.registerTool(name, { ...info, inputSchema: schema }, async args => handler(args))
    },
  }

  registerBrowserTools(registrar, env)
  registerHttpTools(registrar, { ...env, sessionFor: owner => registry.sessionFor(owner) }, jars)
  registerFixtureTools(registrar, fixtures)
  registerDiffTools(registrar, { config, jars, scope, budget, sessionFor: owner => registry.sessionFor(owner) })
  registerSessionTools(registrar, { config, sessionFor: owner => registry.sessionFor(owner), budget, scope }, watches, keepalives)
  registerEvidenceTools(registrar, config)
  registerDupeTools(registrar)
  registerInjectTools(registrar, injects, { config, fixtures, budget, sessionFor: owner => registry.sessionFor(owner), scope }, config.outputDir)
  registerRecipeTools(registrar, { config, sessionFor: owner => registry.sessionFor(owner), jars, scope, budget })
  registerCellTools(registrar, { config, sessionFor: owner => registry.sessionFor(owner), jars, scope, budget })
  registerMcpTools(registrar, { config, scope, budget })
  registerDnsTools(registrar, { scope, budget, jars })
  registerReportTools(registrar, { config })
  registerScopeTools(registrar, scope, config.requireScope, () => new Set(registry.liveOwnerNames()))
  registerSecretTools(registrar, scope)
  registerMailTools(registrar)
  registerOobTools(registrar, oob)
  registerGitTools(registrar)
  registerBudgetTools(registrar, budget)
  registerStorageTools(registrar, config, registry)
  installUnknownToolHint(mcp, toolNames)
  registry.startIdleSweeper()
  const diskBudget = startDiskBudgetLoop(config, registry)

  return {
    async connect(): Promise<void> {
      const transport = new StdioServerTransport()
      await mcp.connect(transport)
    },
    async dispose(): Promise<void> {
      watches.stopAll()
      keepalives.stopAll()
      diskBudget.stop()
      await registry.disposeAll()
      await oob.dispose()
    },
  }
}
