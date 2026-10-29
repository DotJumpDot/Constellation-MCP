/** Safe probe for the focus watchdog (run-9): arms the helper with a
 *  user-data-dir no Chrome uses — it must print ARMED (handshake), find no
 *  matching process within its scan window, log, and exit cleanly. It never
 *  restores focus in this probe because nothing matches the needle. */
import { armFocusGuard } from '../lib/browser/focus.js'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'focus-probe-'))
const logFile = path.join(dir, 'focus-guard.log')
const started = Date.now()
const guard = await armFocusGuard({ userDir: path.join(dir, 'no-such-profile'), channel: 'chrome', seconds: 1, logFile })
console.log(`protectHwnd: ${guard.protectHwnd}`)
if (guard.protectHwnd === 0) { console.log('PROBE FAIL: watchdog did not arm'); process.exit(1) }
// Give the helper time to finish its 6s process scan + write its log lines.
await new Promise(resolve => setTimeout(resolve, 8_000))
const log = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : '(no log)'
console.log('--- focus-guard.log ---')
console.log(log.trim())
const exited = log.includes('no chrome.exe carries the user-data-dir')
console.log(exited ? 'PROBE PASS: armed, scanned, exited without touching focus' : 'PROBE FAIL: unexpected log')
fs.rmSync(dir, { recursive: true, force: true })
process.exit(exited ? 0 : 1)
