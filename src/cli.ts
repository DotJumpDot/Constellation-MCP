import { defaultConfig, applyCliArgs, ensureDirs, type ConstellationConfig } from './config.js'
import { buildServer } from './server.js'

export async function main(argv: string[]): Promise<void> {
  const config: ConstellationConfig = defaultConfig()
  const rest = applyCliArgs(config, argv)
  if (rest.includes('--print-config')) {
    process.stdout.write(JSON.stringify(config, null, 2) + '\n')
    return
  }
  ensureDirs(config)
  // A long-lived MCP server must never take the session down with one bad
  // async path — log and keep serving; the tool call itself returns the error.
  process.on('uncaughtException', error => {
    process.stderr.write(`constellation-mcp uncaught: ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`)
  })
  process.on('unhandledRejection', reason => {
    process.stderr.write(`constellation-mcp unhandled rejection: ${reason instanceof Error ? reason.stack ?? reason.message : String(reason)}\n`)
  })
  const server = buildServer(config)
  process.on('SIGINT', () => { void server.dispose().finally(() => process.exit(0)) })
  process.on('SIGTERM', () => { void server.dispose().finally(() => process.exit(0)) })
  await server.connect()
  // stdout is the MCP protocol channel — status goes to stderr only.
  process.stderr.write(`constellation-mcp ready (root: ${config.rootDir}, browser: ${config.channel}${config.headless ? ', headless' : ''})\n`)
}
