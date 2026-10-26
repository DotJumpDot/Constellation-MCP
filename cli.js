#!/usr/bin/env node
import { main } from './lib/cli.js'

main(process.argv.slice(2)).catch(error => {
  process.stderr.write(`constellation-mcp: ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`)
  process.exit(1)
})
