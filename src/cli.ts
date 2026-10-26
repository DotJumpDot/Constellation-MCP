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
  const server = buildServer(config)
  process.on('SIGINT', () => { void server.dispose().finally(() => process.exit(0)) })
  process.on('SIGTERM', () => { void server.dispose().finally(() => process.exit(0)) })
  await server.connect()
  // stdout is the MCP protocol channel — status goes to stderr only.
  process.stderr.write(`constellation-mcp ready (root: ${config.rootDir}, browser: ${config.channel}${config.headless ? ', headless' : ''})\n`)
}
