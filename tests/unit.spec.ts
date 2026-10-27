import test from 'node:test'
import { createRequire } from 'node:module'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { evaluateScope, entryMatches, ScopeGuard, type ScopeRule } from '../src/scope.js'
import { canTouchTab } from '../src/browser/session.js'
import { extractCodes, extractCodesFor, extractLinks, mailConfig } from '../src/tools/mail.js'
import { describeErrorChain } from '../src/browser/tools.js'
import { interpolateSecretRefs, interpolateDeep, secretNames } from '../src/tools/secrets.js'
import { renderCommitMessage, type CommitDraft } from '../src/tools/git.js'
import { JarStore } from '../src/tools/http.js'
import { OobStore } from '../src/tools/oob.js'
import { applyCliArgs, defaultConfig } from '../src/config.js'
import http from 'node:http'

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

test('otp: subject-first ordering + palette-hex false positives dropped (run-4 §8d)', () => {
  // Atlassian's shape: 6 alphanumeric chars in the SUBJECT, body full of
  // palette hex like #0052CC that used to drown the list.
  const subject = 'Your Atlassian verification code is 7K2Q9F'
  const body = '<style>.btn{background:#0052CC}.link{color:#253858}</style><p>Enter the code</p>'
  assert.deepEqual(extractCodesFor(subject, body), ['7K2Q9F'])
  // The palette hex alone (when the subject carries nothing) is filtered:
  assert.deepEqual(extractCodesFor('Your code', body).includes('0052CC'), false)
  // Digits-only codes pass untouched even when the body has hex.
  assert.deepEqual(extractCodesFor('code 481923', 'footer #253858'), ['481923'])
  // Subject codes lead body codes in the ordering.
  assert.equal(extractCodesFor('code 111222', 'verify 999888')[0], '111222')
})

test('errors: cause chain is disclosed (run-4 §3 fetch failed)', () => {
  const cause = new Error('getaddrinfo ENOTFOUND delivery.mp.microsoft.com')
  const wrapped = new TypeError('fetch failed', { cause })
  assert.match(describeErrorChain(wrapped), /fetch failed/)
  assert.match(describeErrorChain(wrapped), /ENOTFOUND/)
  assert.equal(describeErrorChain(new Error('plain')), 'plain')
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

test('http: auth basic/bearer sets the Authorization header server-side', async () => {
  const { JarStore, performRequest } = await import('../src/tools/http.js')
  const { ScopeGuard } = await import('../src/scope.js')
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'httpauth-'))
  const guard = new ScopeGuard(path.join(dir, 's.json'), path.join(dir, 'a.jsonl'))
  const jars = new JarStore({ rootDir: dir } as never)
  const seen: string[] = []
  const server = http.createServer((req, res) => {
    seen.push(String(req.headers.authorization ?? ''))
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('ok')
  })
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  try {
    const port = (server.address() as { port: number }).port
    await performRequest(jars, guard, {
      url: `http://127.0.0.1:${port}/b2_authorize_account`,
      auth: { type: 'basic', username: 'keyId', password: 'appKey' },
    } as never, 't', 'http_request')
    assert.equal(seen.at(-1), `Basic ${Buffer.from('keyId:appKey').toString('base64')}`)
    await performRequest(jars, guard, {
      url: `http://127.0.0.1:${port}/v1/whoami`,
      auth: { type: 'bearer', token: 'tok123' },
    } as never, 't', 'http_request')
    assert.equal(seen.at(-1), 'Bearer tok123')
    await assert.rejects(
      () => performRequest(jars, guard, { url: `http://127.0.0.1:${port}/`, auth: { type: 'basic' } } as never, 't', 'http_request'),
      /auth\.type "basic" needs username and password/,
    )
  } finally {
    server.close()
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('http_download: saves server-side, transcript sees metadata only, sha256_expected verifies', async () => {
  const { JarStore, performDownload } = await import('../src/tools/http.js')
  const { ScopeGuard } = await import('../src/scope.js')
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'httpdl-'))
  const guard = new ScopeGuard(path.join(dir, 's.json'), path.join(dir, 'a.jsonl'))
  const jars = new JarStore({ rootDir: dir } as never)
  const config = { rootDir: dir, outputDir: path.join(dir, 'out') } as never
  const blob = '<html>' + 'evidence '.repeat(40_000) + '</html>'
  const server = http.createServer((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(blob) })
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r))
  try {
    const port = (server.address() as { port: number }).port
    const crypto = (await import('node:crypto')).default
    const sha = crypto.createHash('sha256').update(blob).digest('hex')
    const result = await performDownload(jars, guard, config, { url: `http://127.0.0.1:${port}/page.html` } as never, 'scout', undefined, sha)
    assert.equal(result.status, 200)
    assert.equal(result.bytes, Buffer.byteLength(blob))
    assert.equal(result.sha256, sha)
    assert.ok(result.file.includes(path.join('scout', 'downloads', 'page.html')), `derived name from URL path: ${result.file}`)
    assert.equal(fs.readFileSync(result.file, 'utf8'), blob)
    await assert.rejects(
      () => performDownload(jars, guard, config, { url: `http://127.0.0.1:${port}/page.html` } as never, 'scout', undefined, 'deadbeef'),
      /sha256 mismatch/,
    )
  } finally {
    server.close()
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('owner labels persist and re-seed a session (info tab survives resets)', async () => {
  const { loadOwnerLabels, saveOwnerLabel, BrowserSession } = await import('../src/browser/session.js')
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ownerlabels-'))
  try {
    assert.deepEqual(loadOwnerLabels(dir), {})
    saveOwnerLabel(dir, 'scout', { job: 'klaviyo lane: signup + MCP', engagement: 'klaviyo-vdp' })
    saveOwnerLabel(dir, 'clayton', { engagement: 'flourish-vdp' })
    const labels = loadOwnerLabels(dir)
    assert.equal(labels.scout!.job, 'klaviyo lane: signup + MCP')
    assert.equal(labels.scout!.engagement, 'klaviyo-vdp')
    assert.equal(labels.clayton!.job, undefined)
    // A fresh session (post-reset/restart) seeds its label from disk.
    const session = new BrowserSession('scout', path.join(dir, 'profiles', 'scout'), { rootDir: dir } as never)
    assert.equal(session.infoJob, 'klaviyo lane: signup + MCP')
    assert.equal(session.infoEngagement, 'klaviyo-vdp')
    await session.setOwnerInfo('klaviyo lane: round 2')
    assert.equal(loadOwnerLabels(dir).scout!.job, 'klaviyo lane: round 2')
    assert.equal(loadOwnerLabels(dir).scout!.engagement, 'klaviyo-vdp', 'unspecified fields persist')
    // The shared human session never loads or seeds labels.
    const shared = new BrowserSession('shared', path.join(dir, 'profiles', 'shared'), { rootDir: dir } as never)
    assert.equal(shared.infoJob, undefined)
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})

test('mail: config trims pasted app-password spaces; anchors pair hrefs with text', async () => {
  const { mailConfig, extractAnchors } = await import('../src/tools/mail.js')
  const previous = { ...process.env }
  try {
    process.env.CONSTELLATION_MAIL_HOST = ' imap.gmail.com '
    process.env.CONSTELLATION_MAIL_USER = ' user@gmail.com '
    process.env.CONSTELLATION_MAIL_PASS = 'abcd efgh ijkl mnop'  // Google renders app passwords with spaces
    const config = mailConfig()
    assert.ok(config !== undefined)
    assert.equal(config.host, 'imap.gmail.com')
    assert.equal(config.user, 'user@gmail.com')
    assert.equal(config.pass, 'abcdefghijklmnop', 'pasted app password keeps working without hand-trimming')
  } finally {
    for (const key of ['CONSTELLATION_MAIL_HOST', 'CONSTELLATION_MAIL_USER', 'CONSTELLATION_MAIL_PASS'])
      if (previous[key as keyof typeof previous] === undefined) delete process.env[key]
      else process.env[key] = previous[key as keyof typeof previous] as string
  }
  const html = '<a href="https://v.example/verify?t=1&amp;x=2">Verify your email</a> <A HREF="https://u.example/unsub">unsubscribe</a>'
  const anchors = extractAnchors(html)
  assert.equal(anchors.length, 2)
  assert.equal(anchors[0]!.href, 'https://v.example/verify?t=1&x=2')
  assert.equal(anchors[0]!.text, 'Verify your email')
  assert.equal(anchors[1]!.text, 'unsubscribe')
})

test('scope: per-owner (per-lane) rules win for that owner; others keep the global rule', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scope-owner-'))
  const guard = new ScopeGuard(path.join(dir, 's.json'), path.join(dir, 'a.jsonl'))
  guard.set({ engagement: 'global-mbb', in_scope: ['global.com'], out_scope: [] })
  guard.set({ engagement: 'ynab-mbb', in_scope: ['ynab.com'], out_scope: [] }, 'ynab-worker')
  assert.equal(guard.check('https://ynab.com/', 'ynab-worker').allowed, true)
  assert.equal(guard.check('https://global.com/', 'ynab-worker').allowed, false, 'owner rule replaces, not extends')
  assert.equal(guard.check('https://global.com/', 'other-worker').allowed, true, 'others fall back to global')
  // persistence: per-owner rules survive reload (the v2 file shape)
  const reloaded = new ScopeGuard(path.join(dir, 's.json'), path.join(dir, 'a.jsonl'))
  assert.equal(reloaded.check('https://ynab.com/', 'ynab-worker').allowed, true)
  assert.deepEqual(reloaded.owners(), ['ynab-worker'])
  // targeted clear drops one lane, keeps the rest
  reloaded.clear('ynab-worker')
  assert.equal(reloaded.check('https://ynab.com/', 'ynab-worker').allowed, false, 'lane rule gone; global fallback denies ynab')
  assert.equal(reloaded.check('https://global.com/', 'ynab-worker').allowed, true)
  reloaded.clear()
  assert.equal(reloaded.current(), null)
})

test('scope tools: scope_clear clears the stale-rule surprise; repo default is sticky', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'scopetools2-'))
  const { ScopeGuard } = await import('../src/scope.js')
  const { registerScopeTools } = await import('../src/tools/scope.js')
  const guard = new ScopeGuard(path.join(dir, 's.json'), path.join(dir, 'a.jsonl'))
  guard.set({ engagement: 'stale-engagement', in_scope: ['old.com'], out_scope: [] })
  const calls = new Map<string, (args: any) => Promise<any>>()
  const registrar = { registerTool: (name: string, _i: unknown, _s: unknown, handler: (a: any) => Promise<any>) => { calls.set(name, handler) } } as never
  registerScopeTools(registrar, guard, false)
  const cleared = await calls.get('scope_clear')!({})
  assert.match(cleared.content[0].text, /scope CLEARED/)
  assert.equal(guard.current(), null)
  guard.set({ engagement: 'one-lane', in_scope: ['a.com'], out_scope: [] }, 'lane-a')
  const clearedOne = await calls.get('scope_clear')!({ owner: 'lane-a' })
  assert.match(clearedOne.content[0].text, /owner "lane-a"/)
  assert.equal(guard.owners().length, 0)
  // per-owner set through the tool
  const set = await calls.get('scope_set')!({ engagement: 'ynab', in_scope: ['ynab.com'], owner: 'ynab-worker' })
  assert.match(set.content[0].text, /owner "ynab-worker"/)
  assert.equal(guard.check('https://ynab.com/', 'ynab-worker').allowed, true)
})

test('redact: header values, bearer/JWT/base64 runs are masked (run-5 §1)', async () => {
  const { redactSecrets } = await import('../src/redact.js')
  // Playwright-style call log echo of an app access token
  assert.match(redactSecrets('request.headers.authorization: Bearer sk-proj-abcdefghij0123456789ABCDEFGHIJKLMNOP'), /authorization: Bearer sk-pro…\[redacted\]/)
  // JSON body style — quoted key/value pair and a bare key inside a message
  assert.match(redactSecrets('{"api_key": "sk-live-abcdef123456"}'), /"api_key": "sk-liv…\[redacted\]"/)
  assert.match(redactSecrets('{"error":{"message":"invalid api_key: sk-live-abcdef123456"}}'), /api_key: sk-liv…\[redacted\]/)
  // Query param
  assert.match(redactSecrets('GET https://x.test/oauth?access_token=SuperSecretValue123&foo=bar'), /access_token=SuperS…\[redacted\]/)
  assert.match(redactSecrets('GET https://x.test/oauth?access_token=SuperSecretValue123&foo=bar'), /foo=bar/)
  // JWT
  assert.match(redactSecrets('token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c rejected'), /\[redacted-jwt\]/)
  // Long base64-ish run (48+)
  assert.match(redactSecrets('got response 7f4d9c2a1b8e5f3a6c0d9e2f4a7b8c1d5e9f0a3b6c8d2e4f6a8b0c2d4e6f8a0b'), /\[redacted\]/)
  // URL path segments and prose survive
  assert.equal(redactSecrets('GET https://x.test/api/tokens/abc123 returned 404'), 'GET https://x.test/api/tokens/abc123 returned 404')
  assert.equal(redactSecrets('token authentication failed for the lane'), 'token authentication failed for the lane')
})

test('redact: describeErrorChain output passes through redactSecrets at the boundary', async () => {
  const { redactSecrets } = await import('../src/redact.js')
  const redacted = redactSecrets(describeErrorChain(new Error('POST /api failed: authorization: Bearer sk-proj-abcdefghij0123456789ABCDEFGHIJKLMNOP')))
  assert.match(redacted, /authorization: Bearer sk-pro…\[redacted\]/)
})

test('mask: password values are replaced, short values skipped (run-5 §6)', async () => {
  const { maskSecrets } = await import('../src/redact.js')
  const snapshot = '- textbox: correct-horse-battery\n- textbox: MyMaster!PW42\n- textbox: ab\n- heading "Login"'
  const masked = maskSecrets(snapshot, ['MyMaster!PW42', 'ab'])
  assert.match(masked, /••••••/)
  assert.doesNotMatch(masked, /MyMaster!PW42/)
  assert.match(masked, /correct-horse-battery/, 'non-secret text survives')
  assert.match(masked, /- textbox: ab/, 'sub-4-char values are not replaced')
})

test('mail: fallback folders pick Spam/Junk + Trash by special-use (run-5 §9)', async () => {
  const { fallbackFoldersFrom } = await import('../src/tools/mail.js')
  const boxes = [
    { path: 'INBOX', specialUse: ['\\inbox'] },
    { path: '[Gmail]/All Mail', specialUse: ['\\all'] },
    { path: '[Gmail]/Spam', specialUse: ['\\junk'] },
    { path: '[Gmail]/อีเมลขยะ', flags: ['\\Junk'] },
    { path: '[Gmail]/Trash', specialUse: '\\trash' },
  ]
  assert.deepEqual(fallbackFoldersFrom(boxes), ['[Gmail]/Spam', '[Gmail]/Trash'])
  assert.deepEqual(fallbackFoldersFrom([{ path: 'INBOX' }]), [])
})
