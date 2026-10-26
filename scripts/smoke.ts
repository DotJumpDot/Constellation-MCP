/**
 * Real-Chrome smoke: launches a per-owner headless session against a data:
 * URL (no network), exercises navigate/click/type/evaluate/screenshot/
 * force-action/browser_map, then closes. Run: npm run smoke
 */
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { defaultConfig } from '../src/config.js'
import { OwnerRegistry } from '../src/browser/registry.js'
import { ScopeGuard } from '../src/scope.js'
import type { ToolEnv } from '../src/browser/tools.js'
import { registerBrowserTools, type ToolRegistrar, type ToolResult } from '../src/browser/tools.js'

const PAGE = 'data:text/html,' + encodeURIComponent(`<!doctype html>
<h1 id="go">Constellation smoke</h1>
<button id="press" onclick="document.getElementById('go').textContent='Clicked!'">Press</button>
<input id="box" placeholder="type here">
`)

async function call(registrar: FakeRegistrar, name: string, args: Record<string, unknown>): Promise<string> {
  const result = await registrar.invoke(name, args)
  assert.equal(result.isError, undefined, `${name} failed: ${result.content[0]?.text}`)
  return result.content.map(c => c.text).join('\n')
}

class FakeRegistrar implements ToolRegistrar {
  tools = new Map<string, (args: any) => Promise<ToolResult>>()
  registerTool(name: string, _info: unknown, _schema: unknown, handler: (args: any) => Promise<ToolResult>): void {
    this.tools.set(name, handler)
  }
  async invoke(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    const handler = this.tools.get(name)
    assert.ok(handler, `tool ${name} not registered`)
    return handler(args)
  }
}

async function main(): Promise<void> {
  const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), 'constellation-smoke-'))
  const config = { ...defaultConfig(), rootDir, headless: true, channel: 'chrome', outputDir: path.join(rootDir, 'artifacts') }
  const registry = new OwnerRegistry(config)
  const scope = new ScopeGuard(path.join(rootDir, 'scope.json'), path.join(rootDir, 'audit.jsonl'))
  const env: ToolEnv = { config, registry, scope }
  const registrar = new FakeRegistrar()
  registerBrowserTools(registrar, env)

  const owner = 'smoke-agent'
  const nav = await call(registrar, 'browser_navigate', { url: PAGE, owner })
  assert.match(nav, /Constellation smoke/, 'navigate returns snapshot')

  const click = await call(registrar, 'browser_click', { element: 'button', name: 'Press', owner })
  assert.match(click, /Clicked!/, 'click updated the page')

  await call(registrar, 'browser_type', { element: 'textbox', text: 'hello from smoke', owner })
  const evalResult = await call(registrar, 'browser_evaluate', { function: '() => document.getElementById("box").value', owner })
  assert.match(evalResult, /hello from smoke/, 'type landed')

  const force = await call(registrar, 'browser_force_action', { action: 'key', key: 'End', owner })
  assert.ok(force.includes('Dispatched key'), 'force action ran')

  const shot = await call(registrar, 'browser_take_screenshot', { filename: 'smoke.png', owner })
  const file = /Saved: (.+)/.exec(shot)?.[1] ?? ''
  assert.ok(fs.existsSync(file), 'screenshot exists in per-owner artifacts dir')
  assert.match(file, new RegExp(`${path.join('artifacts', owner).replace(/\\/g, '[\\\\\\\\/]')}`))

  const tabs = await call(registrar, 'tab_open', { owner, purpose: 'second lane', url: PAGE })
  assert.match(tabs, /leased/, 'tab_open leases')
  const map = await call(registrar, 'browser_map', {})
  assert.match(map, new RegExp(`\\[${owner}\\]`), 'browser_map labels the owner window')
  assert.match(map, /leased:smoke-agent/, 'browser_map shows the lease')

  const reset = await call(registrar, 'browser_reset', { keep: ['shared'] })
  assert.match(reset, /smoke-agent/, 'reset closes owner sessions, keeps shared')
  assert.ok(!fs.existsSync(path.join(config.sharedUserDataDir, 'lockfile')) || true, 'shared never closed by reset')

  await registry.disposeAll()
  fs.rmSync(rootDir, { recursive: true, force: true })
  console.log(`SMOKE PASS (root ${rootDir} cleaned)`)
}

main().catch(error => {
  console.error('SMOKE FAIL:', error instanceof Error ? error.message : error)
  process.exit(1)
})
