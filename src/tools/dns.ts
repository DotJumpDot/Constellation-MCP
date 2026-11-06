/**
 * dns_takeover_check (advice 2026-11-06 #2): mechanise the dangling-DNS /
 * subdomain-takeover sweep that the first T0 pass hand-rolled with
 * Resolve-DnsName + an eyeball judgement per host. Per host: the CNAME
 * chain, a terminal-provider guess from a VERSIONED fingerprint table, and a
 * claimable: true|false|unknown verdict naming the fingerprint that produced
 * it. Optional fetch:true GETs the origin page (scope-guarded, 1 req/s) —
 * many unclaimed providers (S3 NoSuchBucket, GitHub Pages, Heroku) RESOLVE
 * fine and only betray themselves in HTTP. NO claiming, ever: read-only,
 * same rule as Methods/75 C1.
 */

import dnsDefault from 'node:dns/promises'
import { z } from 'zod'
import { errorResult, textResult, type ToolResult, type ToolRegistrar } from '../browser/tools.js'
import type { ScopeGuard } from '../scope.js'
import type { BudgetGuard } from './budget.js'

export const FINGERPRINT_TABLE_VERSION = '2026-11-07.1'

/** One provider entry in the takeover fingerprint table. Derived from the
 *  can-i-take-over-xyz project's statuses; `takeoverable` means "when this
 *  provider's record is dangling, can just anyone re-register the name" —
 *  NXDOMAIN providers (Azure) are detected by the missing record, page
 *  providers by their unclaimed-page body. */
export interface TakeoverFingerprint {
  provider: string
  /** Matches the CNAME/A terminal target that identifies the provider. */
  host: RegExp
  /** Unclaimed-page body fingerprint (only meaningful with fetch:true). */
  body?: RegExp
  /** The status the unclaimed page is served with, when stable. */
  status?: number
  takeoverable: 'yes' | 'no'
  note: string
}

export const TAKEOVER_FINGERPRINTS: readonly TakeoverFingerprint[] = [
  { provider: 'AWS S3 static site', host: /(^|\.)s3([-.][a-z0-9-]+)?\.amazonaws\.com$|\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$/i, body: /NoSuchBucket|The specified bucket does not exist/i, status: 404, takeoverable: 'yes', note: 're-register the bucket name in any AWS account' },
  { provider: 'GitHub Pages', host: /(^|\.)github\.io$/i, body: /There isn't a GitHub Pages site here/i, status: 404, takeoverable: 'yes', note: 'create the matching pages repo' },
  { provider: 'Heroku', host: /(^|\.)herokuapp\.com$|(^|\.)herokudns\.com$/i, body: /No such app|There's nothing here, yet/i, status: 404, takeoverable: 'yes', note: 'create an app with that name' },
  { provider: 'Fastly', host: /(^|\.)fastly\.(net|io)$/i, body: /Fastly error: unknown domain/i, status: 503, takeoverable: 'yes', note: 'add the domain to a Fastly service you control' },
  { provider: 'Pantheon', host: /(^|\.)pantheonsite\.io$/i, body: /The gods are wise/i, status: 404, takeoverable: 'yes', note: 'claim the site name' },
  { provider: 'Shopify', host: /(^|\.)myshopify\.com$/i, body: /Sorry, this shop is currently unavailable/i, status: 404, takeoverable: 'yes', note: 'register the shop subdomain' },
  { provider: 'WordPress.com', host: /(^|\.)wordpress\.com$/i, body: /Do you want to register/i, status: 404, takeoverable: 'yes', note: 'register the subdomain' },
  { provider: 'Tumblr', host: /(^|\.)tumblr\.com$/i, body: /There's nothing here/i, status: 404, takeoverable: 'yes', note: 'claim the blog name in Tumblr settings' },
  { provider: 'Zendesk', host: /(^|\.)zendesk\.com$/i, body: /Help Center Closed|this help center does not exist/i, status: 404, takeoverable: 'yes', note: 'claim the subdomain on any Zendesk plan' },
  { provider: 'Surge.sh', host: /(^|\.)surge\.sh$/i, body: /project not found/i, status: 404, takeoverable: 'yes', note: 'publish to that hostname' },
  { provider: 'Cargo Collective', host: /(^|\.)cargocollective\.com$/i, body: /404 Not Found/i, status: 404, takeoverable: 'yes', note: 'claim the URL in Cargo' },
  { provider: 'Azure Cloudapp', host: /(^|\.)cloudapp\.(net|azure\.com)$/i, takeoverable: 'yes', note: 'Azure deletes the record with the resource — NXDOMAIN here means the cloud service is gone; re-register it' },
  { provider: 'Azure Web Apps', host: /(^|\.)azurewebsites\.net$/i, takeoverable: 'yes', note: 'NXDOMAIN at the zone = the app is deleted; re-register the name' },
  { provider: 'Azure Traffic Manager', host: /(^|\.)trafficmanager\.net$/i, takeoverable: 'no', note: 'Microsoft protects dangling trafficmanager names — NXDOMAIN here is a dead end' },
  { provider: 'Azure Edge (CDN)', host: /(^|\.)azureedge\.net$/i, takeoverable: 'no', note: 'protected — NXDOMAIN is not claimable' },
]

export function fingerprintForHost(host: string, table: readonly TakeoverFingerprint[] = TAKEOVER_FINGERPRINTS): TakeoverFingerprint | undefined {
  const clean = host.toLowerCase().replace(/\.+$/, '')
  return table.find(fp => fp.host.test(clean))
}

/** Does a fetched origin page match a provider's unclaimed-page fingerprint? */
export function fingerprintForBody(
  host: string, status: number, body: string, table: readonly TakeoverFingerprint[] = TAKEOVER_FINGERPRINTS,
): TakeoverFingerprint | undefined {
  const provider = fingerprintForHost(host, table)
  if (provider === undefined || provider.body === undefined) return undefined
  if (provider.status !== undefined && provider.status !== status) return undefined
  return provider.body.test(body) ? provider : undefined
}

/** DNS surface injected everywhere so tests run offline. */
export interface DnsLike {
  resolveCname(host: string): Promise<string[]>
  resolve4(host: string): Promise<string[]>
}

export const realDns: DnsLike = {
  resolveCname: host => dnsDefault.resolveCname(host),
  resolve4: host => dnsDefault.resolve4(host),
}

export interface CnameChain {
  /** The queried host first, then each CNAME hop. */
  chain: string[]
  /** Last CNAME target, or the host itself when there is no CNAME. */
  terminal: string
  hasCname: boolean
  /** Why CNAME walking stopped (ENOTFOUND/ENODATA/loop/depth) — data, not a verdict. */
  cnameStop?: string
  /** A records at the terminal (empty when NXDOMAIN). */
  addresses: string[]
  aStop?: string
}

const errCode = (error: unknown): string => {
  const code = (error as { code?: unknown })?.code
  return typeof code === 'string' ? code : (error instanceof Error ? error.message : String(error))
}

/** Walk CNAMEs to the terminal target, then resolve it — pure given a DnsLike. */
export async function resolveTakeoverHost(host: string, dnsLike: DnsLike, maxDepth = 8): Promise<CnameChain> {
  const chain = [host.toLowerCase().replace(/\.+$/, '')]
  let cnameStop: string | undefined
  for (let depth = 0; depth < maxDepth; depth++) {
    const current = chain[chain.length - 1]!
    try {
      const next = (await dnsLike.resolveCname(current)).map(h => h.toLowerCase().replace(/\.+$/, ''))
      if (next.length === 0) { cnameStop = 'no CNAME record'; break }
      const unseen = next.find(h => !chain.includes(h))
      if (unseen === undefined) { cnameStop = `CNAME loop at ${current}`; break }
      chain.push(unseen)
    } catch (error) {
      cnameStop = errCode(error)
      break
    }
  }
  if (cnameStop === undefined && chain.length > maxDepth) cnameStop = `chain deeper than ${maxDepth}`
  const terminal = chain[chain.length - 1]!
  let addresses: string[] = []
  let aStop: string | undefined
  try {
    addresses = (await dnsLike.resolve4(terminal)).slice(0, 4)
  } catch (error) {
    aStop = errCode(error)
  }
  return { chain, terminal, hasCname: chain.length > 1, cnameStop, addresses, aStop }
}

export interface TakeoverVerdict {
  claimable: 'true' | 'false' | 'unknown'
  provider?: string
  why: string
}

/** The per-host verdict — pure so tests pin every branch. Claimable TRUE only
 *  when a fingerprint (NXDOMAIN at a takeoverable provider, or an unclaimed
 *  page fetched) actually says so; UNKNOWN keeps the lane honest when the
 *  signal needs a fetch that was not performed. */
export function takeoverVerdict(input: { chain: CnameChain; fetch?: { status: number; body: string } | null }): TakeoverVerdict {
  const { chain, fetch } = input
  const provider = fingerprintForHost(chain.terminal)
  if (!chain.hasCname)
    return { claimable: 'false', why: 'no CNAME record — a bare hostname has nothing dangling to take over (an apex NS delegation is out of this tool\'s shape)' }
  const bodyMatch = fetch !== undefined && fetch !== null ? fingerprintForBody(chain.terminal, fetch.status, fetch.body) : undefined
  if (bodyMatch !== undefined)
    return bodyMatch.takeoverable === 'yes'
      ? { claimable: 'true', provider: bodyMatch.provider, why: `fingerprint: ${bodyMatch.provider} unclaimed page (HTTP ${fetch!.status}, body matched) — ${bodyMatch.note}` }
      : { claimable: 'false', provider: bodyMatch.provider, why: `${bodyMatch.provider} serves its unclaimed page but is protected — ${bodyMatch.note}` }
  if (provider !== undefined && provider.body !== undefined && fetch === undefined)
    return { claimable: 'unknown', provider: provider.provider, why: `${chain.terminal} (${provider.provider}) resolves — its kind only betrays a dangling record in HTTP; re-run with fetch: true to confirm` }
  if (chain.addresses.length === 0) {
    if (provider === undefined)
      return { claimable: 'unknown', why: `${chain.terminal} is NXDOMAIN (${chain.aStop ?? 'no A record'}) but matches no provider in the fingerprint table — manual check` }
    return provider.takeoverable === 'yes'
      ? { claimable: 'true', provider: provider.provider, why: `${chain.terminal} is NXDOMAIN (${chain.aStop ?? 'no A record'}) at ${provider.provider} — ${provider.note}` }
      : { claimable: 'false', provider: provider.provider, why: `NXDOMAIN but ${provider.provider} is protected — ${provider.note}` }
  }
  return { claimable: 'false', provider: provider?.provider, why: `terminal resolves to ${chain.addresses.length} A record(s)${fetch !== undefined ? ' and served no known unclaimed page' : ''}${provider === undefined ? '' : ` (${provider.provider})`}` }
}

export interface DnsToolEnv {
  scope: ScopeGuard
  budget: BudgetGuard
  /** Injectable for offline tests. */
  dns?: DnsLike
}

export function registerDnsTools(server: ToolRegistrar, env: DnsToolEnv): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('dns_takeover_check', `Read-only dangling-DNS / subdomain-takeover sweep (advice 2026-11-06 #2): per host the CNAME chain, a terminal-provider guess from fingerprint table v${FINGERPRINT_TABLE_VERSION} (can-i-take-over-xyz derived), and claimable: TRUE|FALSE|UNKNOWN naming the exact signal. \`fetch: true\` also GETs each origin page (scope-guarded, 1 req/s, stops on 429) — S3 NoSuchBucket / GitHub Pages / Heroku only show their unclaimed state in HTTP. NO claiming, ever: a TRUE verdict is a finding to report, not an action to take.`,
    {
      hosts: z.array(z.string().min(1)).min(1).max(8).describe('Hostnames to check (must be in scope)'),
      fetch: z.boolean().optional().describe('Also GET https://host/ (http fallback) to read the origin page — needed to confirm resolving providers'),
      ...{ owner: z.string().optional().describe('Agent owner name (for scope rule + audit; omitted = shared)') },
    },
    async ({ hosts, fetch, owner }: any) => {
      const who = owner === undefined || owner.trim() === '' ? 'shared' : owner.trim()
      // Scope guard FIRST, on every host, DNS or not (hard constraint: scope
      // guard first on every network call — a DNS lookup is a network call).
      for (const host of hosts) env.scope.assert(host.startsWith('http') ? host : `https://${host}/`, who, 'dns_takeover_check')
      const dnsLike = env.dns ?? realDns
      const out: string[] = []
      let yes = 0, no = 0, unknown = 0, rateLimited = false
      for (let at = 0; at < hosts.length; at++) {
        const host = hosts[at]!.toLowerCase().replace(/^https?:\/\//, '').split('/')[0]!
        const chain = await resolveTakeoverHost(host, dnsLike)
        let fetched: { status: number; body: string } | null = null
        let fetchNote = ''
        if (fetch === true && !rateLimited) {
          if (at > 0) await new Promise(resolve => setTimeout(resolve, 1_000))
          try {
            env.budget.spend(who)
          } catch (error) {
            fetchNote = ` — fetch skipped: ${error instanceof Error ? error.message.split('\n')[0] : String(error)}`
          }
          if (fetchNote === '') {
            const controller = new AbortController()
            const timer = setTimeout(() => controller.abort(), 8_000)
            try {
              let response = await fetch(`https://${host}/`, { redirect: 'manual', signal: controller.signal })
              if (response.type === 'opaqueredirect' || response.status === 0) {
                response = await fetch(`http://${host}/`, { redirect: 'manual', signal: controller.signal })
              }
              if (response.status === 429 || response.status === 403) {
                rateLimited = true
                fetchNote = ` — origin returned ${response.status}: further fetches stopped (remaining hosts are DNS-only)`
              } else {
                fetched = { status: response.status, body: (await response.text()).slice(0, 2_048) }
              }
            } catch {
              try {
                const response = await fetch(`http://${host}/`, { redirect: 'manual', signal: controller.signal })
                if (response.status === 429 || response.status === 403) {
                  rateLimited = true
                  fetchNote = ` — origin returned ${response.status}: further fetches stopped`
                } else {
                  fetched = { status: response.status, body: (await response.text()).slice(0, 2_048) }
                }
              } catch { fetchNote = ' — origin fetch failed (no HTTP listener / TLS refused); DNS-only verdict' }
            } finally {
              clearTimeout(timer)
            }
          }
        }
        const verdict = takeoverVerdict({ chain, fetch: fetched })
        if (verdict.claimable === 'true') yes++
        else if (verdict.claimable === 'false') no++
        else unknown++
        const provider = fingerprintForHost(chain.terminal)
        out.push(
          `${host}${fetchNote}`,
          `  CNAME: ${chain.chain.join(' → ')}`,
          `  terminal: ${chain.terminal} — ${chain.addresses.length > 0 ? `${chain.addresses.length} A record(s)` : `no A record (${chain.aStop ?? chain.cnameStop ?? '?'})`}`,
          `  provider guess: ${provider === undefined ? '(none in the fingerprint table)' : `${provider.provider} [takeoverable: ${provider.takeoverable}]`}`,
          `  claimable: ${verdict.claimable.toUpperCase()} — ${verdict.why}`,
          ...(fetched !== null ? [`  origin: HTTP ${fetched.status}, first bytes: ${JSON.stringify(fetched.body.slice(0, 80))}`] : []),
        )
      }
      out.push(
        '',
        `verdicts: ${yes} claimable / ${no} not / ${unknown} unknown — fingerprint table v${FINGERPRINT_TABLE_VERSION} (can-i-take-over-xyz derived).`,
        'NO claiming, ever: a claimable:TRUE host is a P1 finding to record (evidence_capture) and report — do not register anything.',
      )
      return textResult(out.join('\n'))
    })
}
