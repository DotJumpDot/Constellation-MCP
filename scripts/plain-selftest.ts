/**
 * Live self-test for the plain-launch path (run-39 §12.1: the helper's C#
 * codegen failed 100% in the field and the error only surfaced in lane logs —
 * "a compile self-test with the error surfaced" was the #1 request).
 *
 * Runs the REAL chain against the installed chrome.exe on a throwaway
 * profile: spawn → CDP → navigator.webdriver → census → port resolution →
 * exact-match kill. Prints PASS/FAIL per step and exits non-zero on failure.
 *
 *   npm run plain-selftest
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { chromium } = require('playwright-core') as typeof import('playwright-core')

const {
  resolveChromeExecutable, allocateDebugPort, spawnPlainChrome, waitForCdp,
  chromeProcessCensus, resolveChromeByDebugPort, killChromeByProfile,
} = await import('../src/browser/plain-launch.js')

let failures = 0
const step = (name: string, ok: boolean, detail = ''): void => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail === '' ? '' : ` — ${detail}`}`)
  if (!ok) failures++
}

const userDir = fs.mkdtempSync(path.join(os.tmpdir(), 'plain-selftest-'))
let browser: import('playwright-core').Browser | undefined
try {
  const chromePath = resolveChromeExecutable()
  step('resolve chrome.exe', chromePath.includes('chrome.exe'), chromePath)

  const port = await allocateDebugPort()
  step('allocate free debug port', port > 0, String(port))

  const spawned = await spawnPlainChrome({ chromePath, userDir, port })
  step('spawnPlainChrome (C# helper compiled + CreateProcessW)', spawned.pid > 0, `pid ${spawned.pid}`)

  const version = await waitForCdp(port, 20_000)
  step('CDP /json/version answers', version.userAgent !== undefined, version.browserGuid ?? '')

  browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { timeout: 10_000 })
  const page = browser.contexts()[0]?.pages()[0] ?? await browser.contexts()[0]!.newPage()
  const webdriver = await page.evaluate('navigator.webdriver')
  step('navigator.webdriver === false on the plain route', webdriver === false, `got ${String(webdriver)}`)

  const census = await chromeProcessCensus()
  const key = userDir.toLowerCase()
  const mine = [...census.entries()].find(([udd]) => udd.replaceAll('/', '\\') === key.replaceAll('/', '\\'))
  step('census sees the profile with summed working set', mine !== undefined && mine[1].procs > 0,
    mine === undefined ? 'not found' : `${mine[1].procs} procs, ${Math.round(mine[1].totalWsBytes / 1_048_576)} MB`)

  const resolved = await resolveChromeByDebugPort(port)
  step('resolveChromeByDebugPort returns this browser', resolved !== undefined && resolved.pid === spawned.pid,
    resolved === undefined ? 'not resolved' : `pid ${resolved.pid}, dir tail …${resolved.userDir.slice(-28)}`)

  const killed = await killChromeByProfile(userDir)
  step('exact-match kill reaps the tree', killed > 0, `${killed} process(es)`)
  await new Promise(resolve => setTimeout(resolve, 1500))
  const census2 = await chromeProcessCensus()
  const still = [...census2.entries()].find(([udd]) => udd.replaceAll('/', '\\') === key.replaceAll('/', '\\'))
  step('census confirms the profile is gone', still === undefined || still[1].procs === 0)
} catch (error) {
  step('unhandled error', false, error instanceof Error ? `${error.message}\n${error.stack?.split('\n').slice(0, 4).join('\n')}` : String(error))
} finally {
  try { await browser?.close() } catch { /* already gone */ }
  try { fs.rmSync(userDir, { recursive: true, force: true }) } catch { /* best effort */ }
}

console.log(failures === 0 ? 'PLAIN-SELFTEST: ALL PASS' : `PLAIN-SELFTEST: ${failures} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
