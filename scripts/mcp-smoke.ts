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
    'browser_attach', 'browser_click', 'browser_clipboard', 'browser_close', 'browser_console_messages',
    'browser_cookies_export', 'browser_cookies_import', 'browser_cookies_list', 'browser_evaluate', 'browser_fill_otp',
    'browser_focus_window', 'browser_force_action', 'browser_frames_list', 'browser_launch', 'browser_map',
    'browser_navigate', 'browser_network_requests', 'browser_owner_info', 'browser_paste', 'browser_press_key',
    'browser_reset', 'browser_run_code_unsafe', 'browser_select_option', 'browser_set_files', 'browser_snapshot',
    'browser_take_screenshot', 'browser_tabs', 'browser_type', 'browser_upload', 'browser_wait_for',
    'browser_scope_violations',
    'budget_raise', 'budget_set', 'diff_pair', 'dupe_check',
    'evidence_capture', 'evidence_log', 'evidence_verify',
    'fixture_forge', 'fixture_hits', 'fixture_list', 'fixture_publish',
    'http_diff', 'http_download', 'http_jars', 'http_replay', 'http_request',
    'inject_create', 'inject_run', 'inject_score',
    'mail_diagnose', 'mail_get', 'mail_latest_otp', 'mail_search', 'mail_status', 'mail_wait',
    'oob_close', 'oob_events', 'oob_list', 'oob_new',
    'repo_commit', 'repo_status',
    'scope_audit', 'scope_clear', 'scope_get', 'scope_set',
    'secrets_get', 'secrets_list', 'secrets_patch',
    'session_proof_set', 'session_status', 'session_verify', 'session_watch', 'session_watch_stop',
    'tab_lease', 'tab_open', 'tab_release',
  ]
  const missing = expected.filter(n => !names.includes(n))
  const unexpected = names.filter(n => !expected.includes(n))
  assert.deepEqual(missing, [], `missing tools: ${missing.join(', ')} (got ${names.length})`)
  assert.deepEqual(unexpected, [], `unexpected tools: ${unexpected.join(', ')}`)

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
