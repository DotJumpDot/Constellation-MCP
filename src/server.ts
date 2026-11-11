import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
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

export interface ConstellationServer {
  connect(): Promise<void>
  dispose(): Promise<void>
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

  const registrar: ToolRegistrar = {
    registerTool: (name, info, schema, handler) => {
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
  registerScopeTools(registrar, scope, config.requireScope)
  registerSecretTools(registrar, scope)
  registerMailTools(registrar)
  registerOobTools(registrar, oob)
  registerGitTools(registrar)
  registerBudgetTools(registrar, budget)
  registry.startIdleSweeper()

  return {
    async connect(): Promise<void> {
      const transport = new StdioServerTransport()
      await mcp.connect(transport)
    },
    async dispose(): Promise<void> {
      watches.stopAll()
      keepalives.stopAll()
      await registry.disposeAll()
      await oob.dispose()
    },
  }
}
