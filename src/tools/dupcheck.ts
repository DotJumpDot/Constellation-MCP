/**
 * Duplicate-risk pre-check (run-8 proposals §7): a LaunchDarkly candidate
 * died as a duplicate of a 5-month-old report — one call BEFORE the deep
 * work would have said so. Public sources only: NVD keyword search (no key
 * needed at low rates) plus an optional fetch of the program's known-issues
 * page scanning for CVE/GHSA ids.
 */

import { z } from 'zod'
import { errorResult, textResult, type ToolResult, type ToolRegistrar } from '../browser/tools.js'

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi
const GHSA_RE = /GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}/g

export interface NvdHit {
  id: string
  published: string
  description: string
  /** CISA KEV date from the NVD record (`cisaExploitAdd`), when present —
   *  the zero-extra-request KEV fast path (run 2026-11-05, A1). */
  kev?: string
}

/** Parse an NVD 2.0 keyword-search response — pure so tests pin it. */
export function parseNvdResponse(payload: unknown): NvdHit[] {
  if (payload === null || typeof payload !== 'object') return []
  const vulnerabilities = (payload as { vulnerabilities?: unknown }).vulnerabilities
  if (!Array.isArray(vulnerabilities)) return []
  return vulnerabilities.map((row: unknown) => {
    const cve = ((row as { cve?: { id?: unknown; published?: unknown; descriptions?: Array<{ lang?: unknown; value?: unknown }>; cisaExploitAdd?: unknown } }).cve ?? {}) as { id?: unknown; published?: unknown; descriptions?: Array<{ lang?: unknown; value?: unknown }>; cisaExploitAdd?: unknown }
    const found = (cve.descriptions ?? []).find(d => d.lang === 'en')?.value
    const description = typeof found === 'string' ? found : ''
    const kev = typeof cve.cisaExploitAdd === 'string' ? cve.cisaExploitAdd.slice(0, 10) : undefined
    return {
      id: typeof cve.id === 'string' ? cve.id : '?',
      published: typeof cve.published === 'string' ? cve.published.slice(0, 10) : '?',
      description: description.slice(0, 220),
      ...(kev !== undefined ? { kev } : {}),
    }
  }).filter(hit => hit.id !== '?')
}

/** Merge per-keyword hit lists into one deduped list, newest first — pure so
 *  tests pin it. NVD ANDs a joined keyword string (run-11 D13: a joined
 *  "zendesk support portal" query returned 0 while "zendesk" alone returns
 *  15), so keywords are queried INDEPENDENTLY and unioned here. */
export function mergeNvdHits(hitLists: NvdHit[][]): NvdHit[] {
  const byId = new Map<string, NvdHit>()
  for (const hits of hitLists) {
    for (const hit of hits) {
      if (hit.id !== '?' && !byId.has(hit.id)) byId.set(hit.id, hit)
    }
  }
  return [...byId.values()].sort((a, b) => (a.published < b.published ? 1 : a.published > b.published ? -1 : a.id.localeCompare(b.id)))
}

/** Extract candidate dupe ids from a known-issues page's text — pure. */
export function extractAdvisoryIds(text: string): { cves: string[]; ghsas: string[] } {
  return {
    cves: [...new Set(text.match(CVE_RE) ?? [])].slice(0, 20),
    ghsas: [...new Set(text.match(GHSA_RE) ?? [])].slice(0, 20),
  }
}

// ── A1: KEV + sightings + bundles + affected product (2026-11-05) ──────────
// The research pass showed the difference between "a CVE exists" and "the
// vendor already patched this and it is being exploited" is four cheap
// signals. NVD carries cisaExploitAdd (KEV, 0 extra requests); Circl's
// vulnerability-lookup API carries sightings/bundles/affected per CVE.

export interface CirclEnrichment {
  id: string
  /** e.g. ["BerriAI / litellm"] */
  affected: string[]
  sightings: number
  bundles: number
  /** Multi-catalog KEV (CISA/CIRCL/EUVD) — only with kev_deep. */
  kev: boolean
  error?: string
}

/** One enrichment line for a hit — pure so tests pin the exact tokens. */
export function formatEnrichment(hit: NvdHit, enr?: CirclEnrichment): string {
  if (enr === undefined) return hit.kev !== undefined ? `[KEV ${hit.kev}]` : ''
  const bits = [
    enr.kev || hit.kev !== undefined ? `[KEV${hit.kev !== undefined ? ' ' + hit.kev : ''}]` : '',
    enr.sightings > 0 ? `[sightings ${enr.sightings}]` : '',
    enr.bundles > 0 ? `[bundles ${enr.bundles}]` : '',
    enr.error !== undefined ? `[enrich failed: ${enr.error}]` : '',
  ].filter(Boolean).join(' ')
  return bits
}

/** Affected products out of a Circl vulnerability record: prefer the CVE
 *  container's affected array ("vendor / product" strings, the same shape
 *  VulnMCP's extract_summary reads); accept a summary's affected_products. */
export function affectedOf(record: unknown): string[] {
  if (record === null || typeof record !== 'object') return []
  const obj = record as Record<string, unknown>
  if (Array.isArray(obj.affected_products)) {
    return (obj.affected_products as unknown[]).filter((p): p is string => typeof p === 'string' && p !== '').slice(0, 4)
  }
  const containers = obj.containers as Record<string, unknown> | undefined
  const cna = containers?.cna as Record<string, unknown> | undefined
  if (!Array.isArray(cna?.affected)) return []
  const out: string[] = []
  for (const row of cna.affected as unknown[]) {
    if (row === null || typeof row !== 'object') continue
    const a = row as Record<string, unknown>
    const vendor = typeof a.vendor === 'string' ? a.vendor : ''
    const product = typeof a.product === 'string' ? a.product : ''
    const joined = [vendor, product].filter(Boolean).join(' / ')
    if (joined !== '') out.push(joined)
    if (out.length >= 4) break
  }
  return out
}

/** Entries out of a KEV listing response: the API returns an array or an
 *  object with an array member; both shapes mean "count > 0 = in KEV". */
function kevEntriesOf(payload: unknown): unknown[] {
  if (Array.isArray(payload)) return payload
  if (payload !== null && typeof payload === 'object') {
    for (const value of Object.values(payload as Record<string, unknown>)) {
      if (Array.isArray(value)) return value
    }
  }
  return []
}

const VL_BASE = (): string => process.env.CONSTELLATION_VL_BASE ?? 'https://vulnerability.circl.lu'

/** Bounded enricher: at most `max` hits, one vulnerability request each
 *  (+ one kev listing each when deep), 200 ms apart, 8 s abort, sequential.
 *  Any failure degrades to {error} on that line — never aborts the tool. */
export async function enrichWithCircl(hits: NvdHit[], options: { deep?: boolean; max?: number } = {}): Promise<Map<string, CirclEnrichment>> {
  const out = new Map<string, CirclEnrichment>()
  const max = options.max ?? 5
  const base = VL_BASE()
  const slice = hits.slice(0, max)
  for (let i = 0; i < slice.length; i++) {
    const hit = slice[i]!
    const enr: CirclEnrichment = { id: hit.id, affected: [], sightings: 0, bundles: 0, kev: false }
    try {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), 8_000)
      try {
        const response = await fetch(`${base}/api/vulnerability/${encodeURIComponent(hit.id)}?with_sightings=true&with_bundles=true`, { signal: controller.signal })
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        const record = await response.json() as unknown
        enr.affected = affectedOf(record)
        const obj = record as Record<string, unknown>
        enr.sightings = Array.isArray(obj.sightings) ? obj.sightings.length : 0
        enr.bundles = Array.isArray(obj.bundles) ? obj.bundles.length : 0
        if (options.deep === true) {
          const kevResponse = await fetch(`${base}/api/kev?vuln_id=${encodeURIComponent(hit.id)}&per_page=100`, { signal: controller.signal })
          if (kevResponse.ok) enr.kev = kevEntriesOf(await kevResponse.json()).length > 0
          else throw new Error(`kev HTTP ${kevResponse.status}`)
        }
      } finally {
        clearTimeout(timer)
      }
    } catch (error) {
      enr.error = error instanceof Error ? error.message : String(error)
    }
    out.set(hit.id, enr)
    if (i < slice.length - 1) await new Promise(resolve => setTimeout(resolve, 200))
  }
  return out
}

export function registerDupeTools(server: ToolRegistrar): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('dupe_check', 'Duplicate-risk pre-check (run-8 §7): NVD keyword search (public, no key) + optional scan of the program\'s known-issues page for CVE/GHSA ids. Keywords are queried INDEPENDENTLY and merged — never as one joined string (NVD ANDs it and under-reports; run-11 D13), max 4 per call (anonymous rate limit). The newest merged hits are ENRICHED with KEV (CISA exploit date from the NVD record), sightings/bundles and affected products from vulnerability.circl.lu (bounded, best-effort) — exploited-in-the-wild is a very different dupe signal than merely-filed. Run this BEFORE deep work — a run-7 candidate died as a duplicate of a 5-month-old report that one call would have surfaced. A high dupe score is a STOP: read the prior reports, then either differentiate or drop.',
    {
      keywords: z.array(z.string()).min(1).describe('Product/feature terms, e.g. ["klaviyo", "tracking snippet XSS"]'),
      known_issues_url: z.string().optional().describe('The program\'s known-issues page (fetches and extracts CVE/GHSA ids)'),
      kev_deep: z.boolean().optional().describe('Also query every KEV catalog via Circl (adds one request per enriched CVE; default off — the NVD record already carries the CISA date)'),
    },
    async ({ keywords, known_issues_url, kev_deep }: any) => {
      const lines: string[] = []
      // Run-11 D13: keywords are queried INDEPENDENTLY and merged (union) —
      // NVD ANDs a joined keyword string, so "zendesk support portal"
      // returned 0 published CVEs while "zendesk" alone returns 15. Capped at
      // 4 queries because the anonymous rate limit is 5 per 30 s.
      const terms = [...new Set(
        (Array.isArray(keywords) ? keywords : [keywords])
          .filter((k: unknown): k is string => typeof k === 'string' && k.trim() !== '')
          .map((k: string) => k.trim()),
      )].slice(0, 4)
      const perTerm: string[] = []
      const hitLists: NvdHit[][] = []
      let rateLimited = false
      for (const term of terms) {
        if (rateLimited) { perTerm.push(`"${term}": skipped (rate limited)`); continue }
        try {
          const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(term)}&resultsPerPage=10`)
          if (response.ok) {
            const hits = parseNvdResponse(await response.json() as unknown)
            hitLists.push(hits)
            perTerm.push(`"${term}": ${hits.length}`)
          } else {
            perTerm.push(`"${term}": HTTP ${response.status}`)
            if (response.status === 403 || response.status === 429) rateLimited = true
          }
        } catch (error) {
          perTerm.push(`"${term}": ${error instanceof Error ? error.message : String(error)}`)
        }
      }
      const merged = mergeNvdHits(hitLists)
      lines.push(`NVD keyword search — ${terms.length} keyword(s) queried INDEPENDENTLY and merged (NVD ANDs a joined string; run-11 D13):`)
      lines.push(`  per keyword: ${perTerm.join(' · ')}`)
      const shown = merged.slice(0, 15)
      lines.push(`  merged: ${merged.length} unique CVE(s)${shown.length < merged.length ? ` (showing ${shown.length}, newest first)` : ' (newest first)'}`)
      // A1: enrich the newest merged hits with KEV/sightings/bundles/affected
      // from vulnerability.circl.lu (bounded, degrade-never-fail) and render
      // the signals inline on each hit line.
      const enrichment = merged.length > 0 ? await enrichWithCircl(merged, { deep: kev_deep === true }) : new Map<string, CirclEnrichment>()
      const enrichedCount = enrichment.size
      for (const hit of shown) {
        const enr = enrichment.get(hit.id)
        const tags = formatEnrichment(hit, enr)
        const affected = enr !== undefined && enr.affected.length > 0 ? ` {affected: ${enr.affected.join('; ')}}` : ''
        lines.push(`  ${hit.id} (${hit.published})${tags === '' ? '' : ` ${tags}`}${affected} — ${hit.description.slice(0, 140)}`)
      }
      const kevCount = merged.filter(hit => hit.kev !== undefined || enrichment.get(hit.id)?.kev === true).length
      if (merged.length > 0) {
        lines.push(`  KEV: ${kevCount} of ${merged.length} CVE(s) flagged (CISA, from the NVD record); sightings/bundles from vulnerability.circl.lu (${enrichedCount} of ${merged.length} enriched)`)
        lines.push('  NOTE: enrichment is a signal, not proof of a duplicate — read the prior report before deciding.')
      }
      if (keywords.length > terms.length) {
        lines.push(`  WARNING: only the first ${terms.length} keyword(s) were queried (anonymous NVD rate limit is 5 per 30 s) — ${keywords.length - terms.length} dropped`)
      }
      if (merged.length === 0) {
        lines.push('  NOTE: 0 CVEs is UNCONFIRMED — run the raw NVD query yourself before treating a dupe risk as clear')
      }
      if (known_issues_url !== undefined && known_issues_url !== '') {
        try {
          const response = await fetch(known_issues_url, { headers: { 'user-agent': 'Mozilla/5.0 (constellation dupe pre-check)' } })
          const text = await response.text()
          const { cves, ghsas } = extractAdvisoryIds(text)
          lines.push(`Known-issues page (HTTP ${response.status}): ${cves.length} CVE id(s), ${ghsas.length} GHSA id(s)`)
          if (cves.length > 0) lines.push(`  CVEs: ${cves.join(', ')}`)
          if (ghsas.length > 0) lines.push(`  GHSAs: ${ghsas.join(', ')}`)
        } catch (error) {
          lines.push(`Known-issues fetch failed: ${error instanceof Error ? error.message : String(error)}`)
        }
      }
      return textResult(lines.join('\n'))
    })
}
