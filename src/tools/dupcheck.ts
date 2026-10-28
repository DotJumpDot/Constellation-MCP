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
}

/** Parse an NVD 2.0 keyword-search response — pure so tests pin it. */
export function parseNvdResponse(payload: unknown): NvdHit[] {
  if (payload === null || typeof payload !== 'object') return []
  const vulnerabilities = (payload as { vulnerabilities?: unknown }).vulnerabilities
  if (!Array.isArray(vulnerabilities)) return []
  return vulnerabilities.map((row: unknown) => {
    const cve = ((row as { cve?: { id?: unknown; published?: unknown; descriptions?: Array<{ lang?: unknown; value?: unknown }> } }).cve ?? {}) as { id?: unknown; published?: unknown; descriptions?: Array<{ lang?: unknown; value?: unknown }> }
    const found = (cve.descriptions ?? []).find(d => d.lang === 'en')?.value
    const description = typeof found === 'string' ? found : ''
    return {
      id: typeof cve.id === 'string' ? cve.id : '?',
      published: typeof cve.published === 'string' ? cve.published.slice(0, 10) : '?',
      description: description.slice(0, 220),
    }
  }).filter(hit => hit.id !== '?')
}

/** Extract candidate dupe ids from a known-issues page's text — pure. */
export function extractAdvisoryIds(text: string): { cves: string[]; ghsas: string[] } {
  return {
    cves: [...new Set(text.match(CVE_RE) ?? [])].slice(0, 20),
    ghsas: [...new Set(text.match(GHSA_RE) ?? [])].slice(0, 20),
  }
}

export function registerDupeTools(server: ToolRegistrar): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('dupe_check', 'Duplicate-risk pre-check (run-8 §7): NVD keyword search (public, no key) + optional scan of the program\'s known-issues page for CVE/GHSA ids. Run this BEFORE deep work — a run-7 candidate died as a duplicate of a 5-month-old report that one call would have surfaced. A high dupe score is a STOP: read the prior reports, then either differentiate or drop.',
    {
      keywords: z.array(z.string()).min(1).describe('Product/feature terms, e.g. ["klaviyo", "tracking snippet XSS"]'),
      known_issues_url: z.string().optional().describe('The program\'s known-issues page (fetches and extracts CVE/GHSA ids)'),
    },
    async ({ keywords, known_issues_url }: any) => {
      const lines: string[] = []
      const query = keywords.join(' ').slice(0, 200)
      try {
        const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=10`)
        if (response.ok) {
          const hits = parseNvdResponse(await response.json() as unknown)
          lines.push(`NVD keyword search ("${query}"): ${hits.length} published CVE(s)`)
          for (const hit of hits) lines.push(`  ${hit.id} (${hit.published}) — ${hit.description.slice(0, 140)}`)
        } else {
          lines.push(`NVD keyword search: HTTP ${response.status} (rate limit is 5/30s without a key — retry shortly)`)
        }
      } catch (error) {
        lines.push(`NVD keyword search failed: ${error instanceof Error ? error.message : String(error)}`)
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
