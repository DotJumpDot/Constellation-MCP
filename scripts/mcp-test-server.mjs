// Minimal MCP Streamable-HTTP stub. Modes via MCP_STUB_MODE:
//   normal  - 2 tools, all requests 200
//   auth    - no credential => 401 (the "TESTED-PROTECTED" matrix)
//   open    - no credential => 200 + data (the "AUTH-BYPASS" matrix)
// State file (MCP_STUB_STATE) holds {"tools":[...]} and is re-read per request.
import http from 'node:http'
import fs from 'node:fs'

const port = Number(process.env.MCP_STUB_PORT ?? 18777)
const mode = process.env.MCP_STUB_MODE ?? 'normal'
const state = process.env.MCP_STUB_STATE ?? ''

const defaultTools = [
  { name: 'get_project', description: 'Return one project by id.', inputSchema: { type: 'object', properties: { id: { type: 'string' } } } },
  { name: 'list_issues', description: 'List issues in a project.', inputSchema: { type: 'object', properties: { projectId: { type: 'string' } } } },
]

function tools() {
  if (state && fs.existsSync(state)) {
    try { return JSON.parse(fs.readFileSync(state, 'utf8')).tools } catch { /* fall through */ }
  }
  return defaultTools
}

const hasAuth = req => {
  const h = req.headers.authorization
  if (typeof h !== 'string') return false
  return /^Bearer not-a-real-token$/.test(h) ? false : /^Bearer .+/.test(h)
}

const server = http.createServer((req, res) => {
  if (req.method !== 'POST') { res.writeHead(405).end(); return }
  let raw = ''
  req.on('data', c => { raw += c })
  req.on('end', () => {
    const send = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json', 'mcp-session-id': 'stub-session' })
      res.end(JSON.stringify(body))
    }
    let msg
    try { msg = JSON.parse(raw) } catch { send(400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'parse error' } }); return }
    if (msg.method !== undefined && msg.id === undefined) { send(202, {}); return } // notification
    if (mode === 'auth' && !hasAuth(req)) { res.writeHead(401).end(); return }
    if (msg.method === 'initialize') {
      send(200, { jsonrpc: '2.0', id: msg.id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: 'stub', version: '0.0.0' } } })
      return
    }
    if (msg.method === 'tools/list') {
      send(200, { jsonrpc: '2.0', id: msg.id, result: { tools: tools() } })
      return
    }
    if (msg.method === 'tools/call') {
      send(200, { jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: 'STUB-DATA' }] } })
      return
    }
    send(200, { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'method not found' } })
  })
})
server.listen(port, '127.0.0.1', () => console.log(`mcp stub on http://127.0.0.1:${port}/mcp mode=${mode}`))
