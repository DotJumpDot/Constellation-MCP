import test from 'node:test'
import { createRequire } from 'node:module'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { evaluateScope, entryMatches, ScopeGuard, type ScopeRule } from '../src/scope.js'
import { canTouchTab } from '../src/browser/session.js'
import { extractCodes, extractLinks, mailConfig } from '../src/tools/mail.js'
import { interpolateSecretRefs, interpolateDeep, secretNames } from '../src/tools/secrets.js'
import { renderCommitMessage, type CommitDraft } from '../src/tools/git.js'
import { JarStore } from '../src/tools/http.js'
import { OobStore } from '../src/tools/oob.js'
import { applyCliArgs, defaultConfig } from '../src/config.js'
import http from 'node:http'
import { evaluateScope } from '../src/scope.js'

test('scope: unrestricted when no rule set', () => {
  const decision = evaluateScope(null, 'https://example.com/x')
  assert.equal(decision.allowed, true)
})

test('scope: exact host + wildcard + path prefix', () => {
  const rule: ScopeRule = { engagement: 'acme', in_scope: ['acme.com', '*.api.acme.com', 'acme.com/api/'], out_scope: [] }
  assert.equal(evaluateScope(rule, 'https://acme.com/').allowed, true)
  assert.equal(evaluateScope(rule, 'https://v2.api.acme.com/x').allowed, true)
  assert.equal(evaluateScope(rule, 'https://acme.com/api/v1/users').allowed, true)
  assert.equal(evaluateScope(rule, 'https://evil-acme.com/').allowed, false)
  assert.equal(evaluateScope(rule, 'https://acme.com/admin/').allowed, true, 'host entry covers whole host')
})

test('scope: out_scope wins over in_scope', () => {
  const rule: ScopeRule = { engagement: 'x', in_scope: ['acme.com'], out_scope: ['mail.acme.com'] }
  assert.equal(evaluateScope(rule, 'https://mail.acme.com/').allowed, false)
  const decision = evaluateScope(rule, 'https://mail.acme.com/')
  assert.match(decision.reason, /out of scope/)
})

test('scope: unparseable URL denied', () => {
  assert.equal(evaluateScope({ engagement: 'e', in_scope: [], out_scope: [] }, 'http://').allowed, false)
})

test('scope: missing scheme is normalized to https', () => {
  const rule: ScopeRule = { engagement: 'e', in_scope: ['acme.com'], out_scope: [] }
  assert.equal(evaluateScope(rule, 'acme.com/login').allowed, true)
})

test('scope guard audits allow and deny decisions', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-'))
  const guard = new ScopeGuard(path.join(dir, 'scope.json'), path.join(dir, 'audit.jsonl'))
  guard.set({ engagement: 'acme', in_scope: ['acme.com'], out_scope: [] })
  guard.assert('https://acme.com/', 'recon', 'browser_navigate')
  assert.throws(() => guard.assert('https://nope.com/', 'ynab-worker', 'http_request'), /SCOPE DENIED/)
  const lines = guard.auditLines(10)
  assert.equal(lines.length, 2)
  assert.equal(lines[0]!.owner, 'ynab-worker', 'newest first')
  assert.equal(lines[0]!.allowed, false)
  assert.equal(lines[1]!.owner, 'recon')
  assert.equal(lines[1]!.allowed, true)
  // scope_set persists
  const reloaded = new ScopeGuard(path.join(dir, 'scope.json'), path.join(dir, 'audit.jsonl'))
  assert.equal(reloaded.current()?.engagement, 'acme')
})

test('tab leases: session owner always ok, others blocked by lease, release frees', () => {
  const meta = { id: 1, openedBy: 'lead', openedAt: 0, leasedBy: 'ynab-worker', purpose: 'signup' }
  assert.equal(canTouchTab(meta, 'ynab-worker', 'shared').ok, true, 'lease holder may act')
  const denied = canTouchTab(meta, 'klaviyo-worker', 'shared')
  assert.equal(denied.ok, false)
  assert.match(denied.reason ?? '', /leased by "ynab-worker"/)
  assert.equal(canTouchTab(meta, 'klaviyo-worker', 'klaviyo-worker').ok, true, 'session owner overrides')
  assert.equal(canTouchTab(undefined, 'a', 'shared').ok, false)
  const free = { id: 2, openedBy: 'human', openedAt: 0 }
  assert.equal(canTouchTab(free, 'anyone', 'shared').ok, true, 'unleased tabs are first-come')
})

test('otp + link extraction', () => {
  const mail = 'Your verification code is 481923. Or use ABC7D2. Visit https://example.com/verify?token=1 to confirm. Thanks!'
  assert.deepEqual(extractCodes(mail), ['481923', 'ABC7D2'])
  assert.deepEqual(extractLinks(mail), ['https://example.com/verify?token=1'])
  assert.deepEqual(extractCodes('no codes here'), [])
})

test('secrets: interpolation resolves and reports missing', () => {
  process.env.CONSTELLATION_SECRET_TEST_KEY = 's3cret'
  try {
    const out = interpolateSecretRefs('Bearer $secret:test_key and $secret:nope_one')
    assert.equal(out.text, 'Bearer s3cret and $secret:nope_one')
    assert.deepEqual(out.missing, ['nope_one'])
    const deep = interpolateDeep({ headers: { a: '$secret:test_key' }, nested: { b: ['$secret:test_key'] } })
    assert.equal(JSON.stringify(deep.missing), '[]')
    assert.equal((deep.value as { headers: { a: string } }).headers.a, 's3cret')
    assert.ok(secretNames().includes('test_key'))
  } finally {
    delete process.env.CONSTELLATION_SECRET_TEST_KEY
  }
})

test('mail: config comes from env only', () => {
  process.env.CONSTELLATION_MAIL_HOST = 'imap.example.com'
  process.env.CONSTELLATION_MAIL_USER = 'team@example.com'
  process.env.CONSTELLATION_MAIL_PASS = 'app-password'
  try {
    const config = mailConfig()!
    assert.equal(config.host, 'imap.example.com')
    assert.equal(config.port, 993)
    assert.equal(config.folder, 'INBOX')
  } finally {
    delete process.env.CONSTELLATION_MAIL_HOST
    delete process.env.CONSTELLATION_MAIL_USER
    delete process.env.CONSTELLATION_MAIL_PASS
  }
})

test('commit message renders the AGENTS.md convention', () => {
  const draft: CommitDraft = {
    type: 'Fix',
    subject: 'tab select now refuses leases held by another owner',
    bullets: ['Lease table persisted to the session file', 'Select denial text now names the lease owner and purpose'],
    verification: '12 unit tests green, build clean.',
  }
  const message = renderCommitMessage(draft)
  assert.match(message, /^Fix: tab select now refuses leases held by another owner\n/)
  assert.match(message, /- \[x\] Lease table persisted to the session file\n- \[x\] Select denial/)
  assert.match(message, /\nVerified: 12 unit tests green, build clean\.\n$/)
  assert.ok(!message.split('\n').some(l => l.length > 78), 'no runaway lines')
})

test('jar store roundtrips through disk', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'jars-'))
  const config = { rootDir: dir } as never
  const a = new JarStore(config)
  const jar = a.jar('ynab')
  jar.setCookieSync('session=abc123; Path=/', 'https://app.ynab.com/')
  a.persist('ynab', jar)
  const b = new JarStore(config)
  const restored = b.jar('ynab')
  assert.match(restored.getCookieStringSync('https://app.ynab.com/'), /session=abc123/)
  assert.deepEqual(b.list(), ['ynab'])
})

test('oob tokens: creation, url shaping, live receiver capture', async () => {
  const store = new OobStore(18787, 'https://oob.example.test')
  try {
    const entry = store.newToken('probe')
    const urls = store.urls(entry.token)
    assert.equal(urls.public, `https://oob.example.test/oob/${entry.token}`)
    assert.match(urls.local, /^http:\/\/127\.0\.0\.1:18787\/oob\//)
    await store.ensureServer()
    await fetch(urls.local + '/hit?x=1', { method: 'POST', body: 'probe-body' })
    // regression: query string DIRECTLY after the token (no trailing slash) —
    // the live-run probe found these hits were dropped by the old token regex
    await fetch(urls.local + '?probe=1&x=y')
    await new Promise(r => setTimeout(r, 150))
    const events = store.events(entry.token)!
    assert.equal(events.length, 2)
    assert.equal(events[1]!.method, 'GET')
    assert.match(events[1]!.path, /\/oob\/[a-f0-9]+\?probe=1&x=y/)
    assert.equal(events[1]!.query, 'probe=1&x=y')
    assert.equal(events[0]!.method, 'POST')
    assert.match(events[0]!.path, /\/oob\/[a-f0-9]+\/hit\?x=1/)
    assert.equal(events[0]!.body, 'probe-body')
    assert.equal(store.list()[0]!.label, 'probe')
  } finally {
    await store.dispose()
  }
})

test('cli args override config', () => {
  const config = defaultConfig()
  applyCliArgs(config, ['--browser', 'msedge', '--headless', '--oob-port=9999', 'extra'])
  assert.equal(config.channel, 'msedge')
  assert.equal(config.headless, true)
  assert.equal(config.oobPort, 9999)
})

test('entryMatches path prefix semantics', () => {
  assert.equal(entryMatches('acme.com/api/', new URL('https://acme.com/api/v1')), true)
  assert.equal(entryMatches('acme.com/api/', new URL('https://acme.com/apix')), false)
})

test('oob: tokens and events survive a server restart via the JSONL log', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oob-persist-'))
  const file = path.join(dir, 'oob-log.jsonl')
  const first = new OobStore(18801, undefined, file)
  const entry = first.newToken('survivor')
  await first.ensureServer()
  await fetch(first.urls(entry.token).local + '/cb?a=1', { method: 'POST', body: 'kept' })
  await new Promise(r => setTimeout(r, 150))
  await first.dispose()
  // "restart": a fresh store reading the same persist file
  const second = new OobStore(18801, undefined, file)
  const revived = second.events(entry.token)
  assert.ok(revived !== undefined, 'token restored from disk')
  assert.equal(revived.length, 1)
  assert.equal(revived[0]!.body, 'kept')
  assert.equal(second.list()[0]!.label, 'survivor')
  // and the restarted store still records NEW hits for the old token
  await second.ensureServer()
  await fetch(second.urls(entry.token).local + '/after-restart')
  await new Promise(r => setTimeout(r, 150))
  assert.equal(second.events(entry.token)!.length, 2)
  await second.dispose()
  fs.rmSync(dir, { recursive: true, force: true })
})

test('oob: a second instance falls back to an ephemeral port instead of dying', async () => {
  const a = new OobStore(18802)
  const b = new OobStore(18802)
  try {
    const portA = await a.ensureServer()
    const portB = await b.ensureServer()
    assert.equal(portA, 18802)
    assert.notEqual(portB, 18802, 'second instance must not reuse the taken port')
    const ta = a.newToken('a')
    const tb = b.newToken('b')
    await fetch(b.urls(tb.token).local)
    await new Promise(r => setTimeout(r, 150))
    assert.equal(b.events(tb.token)!.length, 1, 'hit landed on the fallback instance')
    assert.equal(a.events(ta.token)!.length, 0, 'first instance untouched')
  } finally {
    await a.dispose()
    await b.dispose()
  }
})

test('run-code compiler: accepts async (page, require) and rejects junk', async () => {
  const { makeUserFn } = await import('../src/browser/tools.js')
  const fn = makeUserFn('async (page, require) => ({ title: await page.title(), fs: typeof require("node:fs").writeFileSync })')
  const fakePage = { title: async () => 'smoke page' }
  const result = await fn(fakePage, createRequire(import.meta.url)) as { title: string; fs: string }
  assert.equal(result.title, 'smoke page')
  assert.equal(result.fs, 'function', 'Node require is injected server-side')
  assert.throws(() => makeUserFn('not a function at all'), /must be a function expression/)
})

test('scope: file/view-source/javascript schemes are denied even unrestricted', () => {
  assert.match(evaluateScope(null, 'file:///C:/Windows/win.ini').reason, /never allowed/)
  assert.match(evaluateScope(null, 'view-source:https://x.test/').reason, /never allowed/)
  assert.equal(evaluateScope(null, 'data:text/html,hi').allowed, true)
})

test('scope: REQUIRE_SCOPE denies non-local hosts when no scope is set', () => {
  assert.equal(evaluateScope(null, 'https://acme.com/', { requireScope: true }).allowed, false)
  assert.equal(evaluateScope(null, 'https://acme.com/', { requireScope: false }).allowed, true)
})

test('scope tools: scope_set arms the guard end-to-end through the registrar', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scopetools-'))
  const { ScopeGuard } = await import('../src/scope.js')
  const { registerScopeTools } = await import('../src/tools/scope.js')
  const guard = new ScopeGuard(path.join(dir, 's.json'), path.join(dir, 'a.jsonl'))
  const calls = new Map<string, (args: any) => Promise<any>>()
  const registrar = { registerTool: (name: string, _i: unknown, _s: unknown, handler: (a: any) => Promise<any>) => { calls.set(name, handler) } } as never
  registerScopeTools(registrar, guard, false)
  const set = await calls.get('scope_set')!({ engagement: 'acme-mbb', in_scope: ['acme.com'], out_scope: ['mail.acme.com'] })
  assert.match(set.content[0].text, /scope ARMED for acme-mbb/)
  assert.equal(guard.check('https://acme.com/').allowed, true)
  assert.equal(guard.check('https://app.acme.com/').allowed, false, 'bare host entry is exact — subdomains need *.acme.com')
  assert.equal(guard.check('https://mail.acme.com/').allowed, false)
  const got = await calls.get('scope_get')!({})
  assert.match(got.content[0].text, /acme-mbb/)
  guard.assert('https://acme.com/', 'w1', 'http_request')
  guard.assert('https://acme.com/', 'w2', 'browser_navigate')
  const audit = await calls.get('scope_audit')!({ owner: 'w1' })
  assert.match(audit.content[0].text, /ALLOW .*w1 http_request acme\.com/)
})

test('http: non-http scheme rejected before any fetch; body preview capped but sha covers full body', async () => {
  const { JarStore, performRequest } = await import('../src/tools/http.js')
  const { ScopeGuard } = await import('../src/scope.js')
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'httptools-'))
  const guard = new ScopeGuard(path.join(dir, 's.json'), path.join(dir, 'a.jsonl'))
  const jars = new JarStore({ rootDir: dir } as never)
  await assert.rejects(() => performRequest(jars, guard, { url: 'file:///C:/Windows/win.ini' } as never, 't', 'http_request'), /scheme "file:" is not allowed/)
  // local http server: big body, small preview
  const body = 'x'.repeat(50_000)
  const server = http.createServer((_req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(body) })
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  try {
    const port = (server.address() as { port: number }).port
    const result = await performRequest(jars, guard, { url: `http://127.0.0.1:${port}/`, max_body_bytes: 1000 } as never, 't', 'http_request')
    assert.ok(result.body.length < 2000, 'preview capped')
    assert.match(result.body, /preview of 50000 bytes/)
    const crypto = (await import('node:crypto')).default
    assert.equal(result.body_sha256, crypto.createHash('sha256').update(body).digest('hex'), 'sha covers the FULL body')
    // jar forget clears disk + memory
    jars.persist('probejar', jars.jar('probejar'))
    assert.ok(jars.list().includes('probejar'))
    assert.equal(jars.forget('probejar'), true)
    assert.ok(!jars.list().includes('probejar'))
  } finally {
    server.close()
    fs.rmSync(dir, { recursive: true, force: true })
  }
})
