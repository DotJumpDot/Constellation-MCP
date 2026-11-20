import fs from 'node:fs'
import path from 'node:path'
import { z } from 'zod'
import { errorResult, textResult, type ToolRegistrar, type ToolResult } from '../browser/tools.js'
import { readChain } from './evidence.js'
import {
  POE_MEANINGS, assessFinding, findingIsStale, loadFindings, nextFindingId, saveFindings,
  sha256File, type BindingRole, type EvidenceBinding, type Finding, type FindingStatus, type PoeLevel,
} from '../findings.js'
import type { ConstellationConfig } from '../config.js'

/** The agent-facing arm of the findings index (ARTEX-mining mechanisms
 *  2+3): add candidates bound to pinned evidence, list them as MACHINE-
 *  READABLE state for the Lead's gate, and freeze export packs that move
 *  lane → validator → report without re-capture. */

const ROLE_SCHEMA = z.enum(['baseline', 'proof', 'verification', 'supporting'])
const POE_SCHEMA = z.number().int().min(1).max(4)

function poeLine(poe: PoeLevel): string {
  return `L${poe} (${POE_MEANINGS[poe]})`
}

/** One binding spec from the agent → a pinned EvidenceBinding (file must
 *  exist; optional chain anchor validated against the live chain). */
function resolveBinding(config: ConstellationConfig, spec: { path: string; role: BindingRole; note?: string; chain_seq?: number }): EvidenceBinding {
  const resolved = spec.path.startsWith('~/')
    ? path.join(process.env.USERPROFILE ?? process.env.HOME ?? '.', spec.path.slice(2))
    : spec.path
  let stat: fs.Stats
  try { stat = fs.statSync(resolved) } catch { throw new Error(`binding path does not exist: ${resolved}`) }
  if (!stat.isFile()) throw new Error(`binding path is not a file: ${resolved} — bind the artifact file (evidence_file copies land under the owner's evidence dir)`)
  if (stat.size > 64 * 1024 * 1024) throw new Error(`binding too large (${stat.size} bytes): ${resolved} — bind a decisive extract, not a dump`)
  const binding: EvidenceBinding = { path: resolved, sha256: sha256File(resolved), role: spec.role, ...(spec.note !== undefined ? { note: spec.note } : {}) }
  if (spec.chain_seq !== undefined) {
    const entry = readChain(config).find(e => e.seq === spec.chain_seq)
    if (entry === undefined) throw new Error(`chain_seq ${spec.chain_seq} does not exist in evidence-chain.jsonl — evidence_log lists real entries`)
    binding.chain_seq = spec.chain_seq
    binding.chain_hash = entry.entry_hash
  }
  return binding
}

function reverify(config: ConstellationConfig, finding: Finding): void {
  const assessment = assessFinding(config, finding)
  finding.verification = assessment.status
  finding.verification_note = assessment.note
  finding.receipts = assessment.receipts
}

function listLine(finding: Finding): string {
  const stale = findingIsStale(finding)
  return `${finding.id}  ${finding.verification === 'verified' ? '✔' : finding.verification === 'not_assessed' ? '?' : '·'}  poe L${finding.poe}  ${finding.status.padEnd(9)} [${finding.owner}] ${finding.quotes.length}q/${finding.bindings.length}b  v${finding.evidence_version}${stale ? ` (STALE — report written against v${finding.report_evidence_version})` : ''}  ${finding.title}`
}

export function registerFindingsTools(server: ToolRegistrar, config: ConstellationConfig): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('findings_add', 'Register a FINDING (candidate) with machine-checkable proof (ARTEX-mining #2+#3): binds evidence files sha256-pinned with ROLES (baseline = the unaffected control, proof = the body carrying the finding, verification = an independent re-check, supporting = context), optionally anchored to an evidence-chain entry (chain_seq from evidence_log). POE declares the demonstrated depth — 1 observed anomaly/timing, 2 structural manipulation, 3 data extracted, 4 critical impact. `quotes` are the EXACT response fragments that carry the finding: the SERVER (not you) decides `verified` — it requires ≥1 proof/verification binding, POE ≥3, and every quote ≥8 chars found VERBATIM (whitespace-normalized) inside a bound body whose sha256 still matches. Missing/drifted evidence ⇒ not_assessed (fail closed). The Lead\'s candidate gate reads findings_list, not chat prose.',
    {
      title: z.string().min(1).describe('One-line finding title (what + where)'),
      poe: POE_SCHEMA.describe('Demonstrated depth 1-4 — declare what you PROVED, not what you suspect'),
      owner: z.string().optional().describe('Lane attribution (default "unknown")'),
      bindings: z.array(z.object({
        path: z.string().describe('Artifact file to pin (an evidence_file copy, an http body_file, a download, a screenshot)'),
        role: ROLE_SCHEMA.describe('baseline = control, proof = carries the finding, verification = independent re-check, supporting = context'),
        note: z.string().optional(),
        chain_seq: z.number().int().optional().describe('Anchor to this evidence-chain entry (evidence_log shows seq numbers)'),
      })).min(1).describe('At least one binding — a finding without pinned evidence is prose'),
      quotes: z.array(z.string()).optional().describe('Exact fragments from the bound bodies that carry the finding (verbatim receipt check)'),
      note: z.string().optional().describe('Context the validator needs (impact, preconditions)'),
    },
    async ({ title, poe, owner, bindings, quotes, note }: any) => {
      const findings = loadFindings(config)
      const now = new Date().toISOString()
      const finding: Finding = {
        id: nextFindingId(findings),
        title: String(title),
        owner: owner ?? 'unknown',
        created_ts: now,
        updated_ts: now,
        poe: poe as PoeLevel,
        status: 'open',
        verification: 'unverified',
        verification_note: '',
        bindings: (bindings as Array<{ path: string; role: BindingRole; note?: string; chain_seq?: number }>).map(spec => resolveBinding(config, spec)),
        quotes: (quotes ?? []) as string[],
        evidence_version: 1,
        ...(note !== undefined ? { note: String(note) } : {}),
      }
      reverify(config, finding)
      findings.push(finding)
      saveFindings(config, findings)
      return textResult([
        `${finding.id} registered — ${poeLine(finding.poe)}, ${finding.bindings.length} binding(s) pinned${finding.quotes.length > 0 ? `, ${finding.quotes.length} quote(s)` : ''}`,
        `verification: ${finding.verification.toUpperCase()} — ${finding.verification_note}`,
        ...(finding.receipts ?? []).map(r =>
          `  ${r.foundIn !== undefined ? `✔ "${r.quote.slice(0, 60)}${r.quote.length > 60 ? '…' : ''}" ← ${r.foundIn}` : `✖ "${r.quote.slice(0, 60)}${r.quote.length > 60 ? '…' : ''}" — ${r.miss}`}`),
        'next: findings_list for the gate; findings_export freezes the pack when the candidate moves on.',
      ].join('\n'), finding.verification !== 'verified')
    })

  t('findings_list', 'Machine-readable findings index — the Lead\'s candidate gate (reads STATE, not chat). One line per finding: id, verification mark (✔ verified / · unverified / ? not_assessed), POE level, human status (open/confirmed/rejected/duplicate), owner, quotes/bindings counts, evidence version (+ STALE when a report was exported against older evidence). Filter by owner/verification/status. `verbose:true` adds per-finding verification notes, binding hashes and the quote receipts.',
    {
      owner: z.string().optional(),
      verification: z.enum(['verified', 'unverified', 'not_assessed']).optional(),
      status: z.enum(['open', 'confirmed', 'rejected', 'duplicate']).optional(),
      verbose: z.boolean().optional(),
    },
    async ({ owner, verification, status, verbose }: any) => {
      let findings = loadFindings(config)
      if (owner !== undefined) findings = findings.filter(f => f.owner === owner)
      if (verification !== undefined) findings = findings.filter(f => f.verification === verification)
      if (status !== undefined) findings = findings.filter(f => f.status === status)
      if (findings.length === 0) return textResult('(no findings match — findings_add registers candidates with pinned evidence)')
      const head = `${findings.length} finding(s): ${findings.filter(f => f.verification === 'verified').length} verified, ${findings.filter(f => f.verification === 'not_assessed').length} not_assessed, ${findings.filter(f => findingIsStale(f)).length} stale`
      if (verbose !== true) return textResult([head, ...findings.map(listLine)].join('\n'))
      const blocks = findings.map(f => [
        listLine(f),
        `  verification: ${f.verification} — ${f.verification_note}`,
        ...f.bindings.map(b => `  [${b.role}] ${path.basename(b.path)} sha256 ${b.sha256.slice(0, 16)}…${b.chain_seq !== undefined ? ` (chain #${b.chain_seq} ${b.chain_hash!.slice(0, 12)}…)` : ''}${b.note !== undefined ? ` — ${b.note}` : ''}`),
        ...(f.receipts ?? []).map(r => `  ${r.foundIn !== undefined ? `✔ ${r.foundIn}` : `✖ ${r.miss}`}: "${r.quote.slice(0, 80)}"`),
      ].join('\n'))
      return textResult([head, ...blocks].join('\n\n'))
    })

  t('findings_update', 'Update a finding: poe (a STRONGER demonstration you just ran), status (the human disposition: confirmed/rejected/duplicate — the Lead owns this), add_quotes / add_bindings (pin more evidence; the same sha256 + optional chain anchor rules as findings_add), or retitle. Bumps evidence_version and re-runs the machine verifier every time.',
    {
      id: z.string().describe('Finding id (F-###)'),
      poe: POE_SCHEMA.optional(),
      status: z.enum(['open', 'confirmed', 'rejected', 'duplicate']).optional(),
      title: z.string().optional(),
      add_quotes: z.array(z.string()).optional(),
      add_bindings: z.array(z.object({ path: z.string(), role: ROLE_SCHEMA, note: z.string().optional(), chain_seq: z.number().int().optional() })).optional(),
    },
    async ({ id, poe, status, title, add_quotes, add_bindings }: any) => {
      const findings = loadFindings(config)
      const finding = findings.find(f => f.id === id)
      if (finding === undefined) throw new Error(`no finding "${String(id)}" — findings_list shows ids`)
      if (poe !== undefined) finding.poe = poe as PoeLevel
      if (status !== undefined) finding.status = status as FindingStatus
      if (title !== undefined) finding.title = String(title)
      if (add_quotes !== undefined) finding.quotes.push(...(add_quotes as string[]).filter(q => !finding.quotes.includes(q)))
      if (add_bindings !== undefined)
        for (const spec of add_bindings as Array<{ path: string; role: BindingRole; note?: string; chain_seq?: number }>)
          finding.bindings.push(resolveBinding(config, spec))
      finding.evidence_version += 1
      finding.updated_ts = new Date().toISOString()
      reverify(config, finding)
      saveFindings(config, findings)
      return textResult(`${finding.id} updated → ${poeLine(finding.poe)}, status ${finding.status}, evidence v${finding.evidence_version}\nverification: ${finding.verification.toUpperCase()} — ${finding.verification_note}`)
    })

  t('findings_export', 'Freeze an EVIDENCE PACK (ARTEX-mining #2): a self-contained directory under artifacts/findings-export/<stamp>/ — one sanitized .md per finding (title, POE, verification with the honest gap, bindings with hashes, quote receipts) + manifest.json (the full records) + hash-verified COPIES of every bound file under evidence/<finding-id>/. The copies are re-hashed after writing (a corrupt copy fails the export). Exporting records the evidence_version each report was written against — later findings_list flags STALE when evidence moved on. Pass id for one finding, owner for a lane, or nothing for every finding.',
    {
      id: z.string().optional().describe('One finding (F-###)'),
      owner: z.string().optional().describe('Every finding of one lane'),
    },
    async ({ id, owner }: any) => {
      let findings = loadFindings(config)
      if (id !== undefined) findings = findings.filter(f => f.id === id)
      else if (owner !== undefined) findings = findings.filter(f => f.owner === owner)
      if (findings.length === 0) return textResult('no findings match — nothing to export', true)
      const all = loadFindings(config)
      const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
      const dir = path.join(config.outputDir, 'findings-export', stamp)
      fs.mkdirSync(dir, { recursive: true })
      const manifest: Array<Record<string, unknown>> = []
      for (const finding of findings) {
        const slug = finding.title.replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 50)
        // Freeze copies FIRST (hash-verified), then write the md citing them.
        const evidenceDir = path.join(dir, 'evidence', finding.id)
        fs.mkdirSync(evidenceDir, { recursive: true })
        const copied: Array<{ role: string; file: string; sha256: string; bytes: number }> = []
        for (const binding of finding.bindings) {
          const bytes = fs.readFileSync(binding.path)
          const dest = path.join(evidenceDir, `${binding.role}-${path.basename(binding.path)}`)
          fs.writeFileSync(dest, bytes)
          const after = sha256File(dest)
          if (after !== binding.sha256)
            throw new Error(`export copy corrupt: ${dest} sha ${after.slice(0, 12)}… != pinned ${binding.sha256.slice(0, 12)}…`)
          copied.push({ role: binding.role, file: `evidence/${finding.id}/${binding.role}-${path.basename(binding.path)}`, sha256: binding.sha256, bytes: bytes.length })
        }
        const receipts = finding.receipts ?? []
        const md = [
          `# ${finding.id} — ${finding.title}`,
          '',
          `- owner: ${finding.owner} · status: ${finding.status} · poe: ${poeLine(finding.poe)}`,
          `- verification: **${finding.verification}** — ${finding.verification_note}`,
          `- evidence_version: ${finding.evidence_version} (this report was written against it)`,
          '',
          '## Evidence (frozen copies, sha-verified)',
          ...(copied.length > 0
            ? copied.map(c => `- [${c.role}] ${c.file} — ${c.bytes} bytes — sha256 ${c.sha256}`)
            : ['- (none)']),
          '',
          '## Quote receipts (verbatim check against the bound bodies)',
          ...(receipts.length > 0
            ? receipts.map(r => `- ${r.foundIn !== undefined ? `FOUND in ${r.foundIn}` : `MISSING — ${r.miss}`}: "${r.quote.length > 120 ? `${r.quote.slice(0, 120)}…` : r.quote}"`)
            : ['- (no quotes recorded)']),
          '',
        ].join('\n')
        fs.writeFileSync(path.join(dir, `${finding.id}-${slug || 'finding'}.md`), md)
        const record = all.find(f => f.id === finding.id)!
        record.report_evidence_version = finding.evidence_version
        manifest.push({ ...record, receipts })
      }
      saveFindings(config, all)
      fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({ exported_at: new Date().toISOString(), findings: manifest }, null, 2) + '\n')
      return textResult(`Evidence pack frozen: ${dir}\n${findings.length} finding(s), every bound file copied + re-hashed, manifest.json carries the full records. Report written against evidence v${findings.map(f => f.evidence_version).join('/')}.`)
    })
}
