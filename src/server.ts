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
import { SessionWatchRegistry, registerSessionTools } from './tools/session.js'
import { registerEvidenceTools } from './tools/evidence.js'
import { registerDupeTools } from './tools/dupcheck.js'
import { InjectStore, registerInjectTools } from './tools/injectlab.js'

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

  const mcp = new McpServer({ name: 'constellation', version: '0.1.0' }, {
    instructions: [
      'Constellation: per-agent browser isolation + engagement tooling for agent teams.',
      'Every browser tool takes an optional `owner` — pass YOUR agent name so your cookies, tabs, and window stay isolated. Omitted = the shared human session.',
      'Call browser_map for the ownership map; tab_open/tab_lease to hold tabs; browser_reset {keep:["shared"]} at lane end.',
      'scope_set before engaging a target — http_request and navigation are then scope-enforced and audited.',
      'Secrets: reference $secret:NAME inside http_request instead of pasting values.',
      'browser_run_code_unsafe is the escape hatch (full Page API + Node require, NOT scope-guarded inside) — use it only when guarded tools cannot express the step.',
      'human_task_* / lane_freeze / team_snapshot are NATIVE team tools with no mcp__ prefix — do not add a server prefix to them.',
      'Manufacture fixtures, do not hand-build them: fixture_publish (public URL + canary; fixture_hits answers canary_seen), fixture_forge (real .docx/.pdf for browser_upload), dupe_check before deep work, diff_pair for the authorization verdict, session_verify/session_watch with per-site proof rules, http_replay to vary exactly one field, evidence_capture/evidence_verify for the tamper-evident chain.',
    ].join('\n'),
  })

  const registrar: ToolRegistrar = {
    registerTool: (name, info, schema, handler) => {
      mcp.registerTool(name, { ...info, inputSchema: schema }, async args => handler(args))
    },
  }

  registerBrowserTools(registrar, env)
  registerHttpTools(registrar, env, jars)
  registerFixtureTools(registrar, fixtures)
  registerDiffTools(registrar, { jars, scope })
  registerSessionTools(registrar, { config, sessionFor: owner => registry.sessionFor(owner) }, watches)
  registerEvidenceTools(registrar, config)
  registerDupeTools(registrar)
  registerInjectTools(registrar, injects, { config, fixtures, budget, sessionFor: owner => registry.sessionFor(owner) }, config.outputDir)
  registerScopeTools(registrar, scope, config.requireScope)
  registerSecretTools(registrar)
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
      await registry.disposeAll()
      await oob.dispose()
    },
  }
}
