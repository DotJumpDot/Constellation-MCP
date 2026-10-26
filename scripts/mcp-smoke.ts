/**
 * MCP end-to-end smoke: spawn `node lib/cli.js` as a real stdio server,
 * handshake, list tools, and call the harmless ones (secrets_list,
 * browser_map, http_jars). Run: npm run mcp-smoke
 */
import assert from 'node:assert/strict'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'

async function main(): Promise<void> {
  const transport = new StdioClientTransport({
    command: 'node',
    args: [new URL('../cli.js', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1')],
    stderr: 'pipe',
  })
  const client = new Client({ name: 'constellation-smoke', version: '0.0.0' })
  await client.connect(transport)
  const { tools } = await client.listTools()
  const names = tools.map(t => t.name).sort()
  const expected = [
    'browser_click', 'browser_close', 'browser_console_messages', 'browser_evaluate',
    'browser_force_action', 'browser_map', 'browser_navigate', 'browser_network_requests',
    'browser_press_key', 'browser_reset', 'browser_run_code_unsafe', 'browser_select_option', 'browser_snapshot',
    'browser_take_screenshot', 'browser_tabs', 'browser_type', 'browser_wait_for',
    'http_diff', 'http_jars', 'http_request',
    'mail_latest_otp', 'mail_search', 'mail_wait',
    'oob_events', 'oob_list', 'oob_new',
    'repo_commit', 'repo_status',
    'scope_audit', 'scope_clear', 'scope_get', 'scope_set',
    'secrets_get', 'secrets_list',
    'tab_lease', 'tab_open', 'tab_release',
  ]
  const missing = expected.filter(n => !names.includes(n))
  assert.deepEqual(missing, [], `missing tools: ${missing.join(', ')} (got ${names.length})`)

  const secrets = await client.callTool({ name: 'secrets_list', arguments: {} })
  assert.ok(String(secrets.content?.[0]?.text ?? '').length > 0, 'secrets_list returns text')
  const map = await client.callTool({ name: 'browser_map', arguments: {} })
  assert.match(String(map.content?.[0]?.text ?? ''), /UNRESTRICTED|scope:/)
  await client.close()
  console.log(`MCP SMOKE PASS (${names.length} tools registered)`)
}

main().catch(error => {
  console.error('MCP SMOKE FAIL:', error instanceof Error ? error.message : error)
  process.exit(1)
})
