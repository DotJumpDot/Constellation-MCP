import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import type { ConstellationConfig } from './config.js'
import { readChain, type ChainEntry } from './tools/evidence.js'

/**
 * Findings index with POE levels + machine verification (ARTEX-mining
 * round 2026-11-20, mechanisms 2+3 — clean-room; see
 * docs/research/artex-mining-2026-11-20.md §2+3).
 *
 * Findings used to live in chat prose: the Lead's candidate gate read the
 * conversation, "verified" was a word a lane typed, and evidence sat in the
 * tamper-evident chain unlinked to any candidate. Now a finding is a
 * first-class record at <rootDir>/findings.json that BINDS evidence files
 * (sha256-pinned, optionally anchored to an evidence-chain entry) and
 * carries:
 *
 * - poe 1–4: the lane's DECLARED depth — 1 observed anomaly/timing
 *   variation, 2 structural manipulation, 3 data extracted, 4 critical
 *   impact. The agent commits; the server checks.
 * - status: the HUMAN disposition (open/confirmed/rejected/duplicate).
 * - verification: the MACHINE verdict (unverified/verified/not_assessed)
 *   — set only by assessFinding, never by the agent. Mirrors ARTEX's
 *   assessFindingVerification: "verified" requires a proof/verification-
 *   role binding, declared POE ≥3, and every quote ≥8 chars found
 *   VERBATIM (whitespace-normalized) inside a bound file whose sha256
 *   still matches. Unreadable/drifted/oversized evidence ⇒ not_assessed
 *   (fail closed — an infrastructure error is never a claim about the
 *   finding).
 * - evidence_version: bumps on every mutation; exports record the version
 *   they were written against (report_evidence_version) so a later list
 *   can flag staleness — the report was written against OLDER evidence.
 */

export type PoeLevel = 1 | 2 | 3 | 4
export type FindingStatus = 'open' | 'confirmed' | 'rejected' | 'duplicate'
export type VerificationStatus = 'unverified' | 'verified' | 'not_assessed'
export type BindingRole = 'baseline' | 'proof' | 'verification' | 'supporting'

export const POE_MEANINGS: Record<PoeLevel, string> = {
  1: 'observed anomaly / timing variation',
  2: 'structural manipulation (the response shape changed on purpose)',
  3: 'data extracted (the payload came back)',
  4: 'critical impact (other tenants / admin-level effect)',
}

export interface EvidenceBinding {
  /** Absolute path of the artifact file at bind time. */
  path: string
  /** sha256 of the file bytes at bind time — drift ⇒ not_assessed. */
  sha256: string
  role: BindingRole
  note?: string
  /** Optional anchor into the tamper-evident chain (evidence_capture /
   *  evidence_file entry). seq + the entry hash recorded at bind time. */
  chain_seq?: number
  chain_hash?: string
}

export interface Finding {
  id: string
  title: string
  owner: string
  created_ts: string
  updated_ts: string
  poe: PoeLevel
  status: FindingStatus
  verification: VerificationStatus
  verification_note: string
  bindings: EvidenceBinding[]
  quotes: string[]
  evidence_version: number
  report_evidence_version?: number
  /** Validator context the lane attached (impact, preconditions). */
  note?: string
  /** Last verifier receipt per quote — where each was found, or why not. */
  receipts?: Array<{ quote: string; foundIn?: string; miss?: string }>
}

export const VERIFICATION_MIN_POE: PoeLevel = 3
export const VERIFICATION_MIN_QUOTE_CHARS = 8
/** A bound body larger than this is not_assessed, same cap class as ARTEX. */
export const VERIFICATION_READ_CAP = 4 * 1024 * 1024

export function sha256File(file: string): string {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex')
}

/** Collapse ALL whitespace runs to single spaces — the verbatim-check
 *  normalization (HTML pretty-printing and minified JSON both match). */
export function normalizeWs(text: string): string {
  return text.replace(/\s+/g, ' ')
}

export function findingsFile(config: ConstellationConfig): string {
  return path.join(config.rootDir, 'findings.json')
}

export function loadFindings(config: ConstellationConfig): Finding[] {
  try {
    const rows = JSON.parse(fs.readFileSync(findingsFile(config), 'utf8')) as Finding[]
    return Array.isArray(rows) ? rows : []
  } catch { /* first use or unreadable — start empty */ }
  return []
}

/** Atomic write (temp + rename in the same dir): a crash leaves the old or
 *  the new whole index, never a truncated one. */
export function saveFindings(config: ConstellationConfig, findings: Finding[]): void {
  const file = findingsFile(config)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  const temp = `${file}.tmp-${process.pid}`
  fs.writeFileSync(temp, JSON.stringify(findings, null, 2) + '\n')
  fs.renameSync(temp, file)
}

export function nextFindingId(findings: Finding[]): string {
  const max = findings.reduce((acc, f) => {
    const n = /^F-(\d+)$/.exec(f.id)
    return n === null ? acc : Math.max(acc, Number.parseInt(n[1]!, 10))
  }, 0)
  return `F-${String(max + 1).padStart(3, '0')}`
}

export interface Assessment {
  status: VerificationStatus
  note: string
  /** Per-quote receipt: where each quote was found (file basename) or why
   *  not — the export pack prints exactly this. */
  receipts: Array<{ quote: string; foundIn?: string; miss?: string }>
}

/**
 * The receipt check. Reads the bound bodies ITSELF (never the agent's
 * memory of them) and decides verified/unverified/not_assessed:
 *
 * - verified ⇔ ≥1 proof|verification binding ∧ poe ≥3 ∧ ≥1 quote ∧ every
 *   quote ≥8 chars found (whitespace-normalized) in a bound, sha-matching
 *   body. Chain anchors, when given, must still match the chain.
 * - not_assessed = fail closed: a bound file missing/unreadable/over the
 *   read cap, or its sha256 drifted since binding. An infrastructure
 *   problem is never a claim about the finding.
 * - unverified = the finding is fine but the proof bar is not met (no
 *   proof role, low POE, no quotes, short quote, quote absent, chain
 *   mismatch). The note always says WHICH bar.
 */
export function assessFinding(config: ConstellationConfig, finding: Finding, chain?: ChainEntry[]): Assessment {
  const chainEntries = chain ?? readChain(config)
  const receipts: Assessment['receipts'] = []

  // Chain anchors are checked first and hard: a mismatched anchor means the
  // binding cites an entry the chain does not contain as claimed.
  for (const binding of finding.bindings) {
    if (binding.chain_seq === undefined || binding.chain_hash === undefined) continue
    const entry = chainEntries.find(e => e.seq === binding.chain_seq)
    if (entry === undefined)
      return { status: 'unverified', note: `CHAIN MISMATCH: binding cites chain entry #${binding.chain_seq} which does not exist — re-bind against a real evidence_capture/evidence_file entry`, receipts }
    if (entry.entry_hash !== binding.chain_hash)
      return { status: 'unverified', note: `CHAIN MISMATCH: chain entry #${binding.chain_seq} hash is ${entry.entry_hash.slice(0, 12)}… but the binding recorded ${binding.chain_hash.slice(0, 12)}… — the chain changed after binding`, receipts }
  }

  const proofBindings = finding.bindings.filter(b => b.role === 'proof' || b.role === 'verification')
  if (proofBindings.length === 0)
    return { status: 'unverified', note: 'no proof/verification-role evidence bound (roles: baseline/proof/verification/supporting — a candidate needs at least one proof or verification binding)', receipts }
  if (finding.poe < VERIFICATION_MIN_POE)
    return { status: 'unverified', note: `declared POE L${finding.poe} (${POE_MEANINGS[finding.poe]}) is below the L${VERIFICATION_MIN_POE} minimum for verified — upgrade the demonstration, not the label`, receipts }
  if (finding.quotes.length === 0)
    return { status: 'unverified', note: 'no quotes to check — pass the exact response fragments that carry the finding (they must appear verbatim in a bound body)', receipts }

  // Load each proof/verification body once (sha-checked, size-capped).
  const bodies: Array<{ name: string; normalized: string }> = []
  for (const binding of proofBindings) {
    let stat: fs.Stats
    try { stat = fs.statSync(binding.path) } catch {
      return { status: 'not_assessed', note: `bound evidence is missing: ${path.basename(binding.path)} — re-capture before verifying (fail closed, not a claim about the finding)`, receipts }
    }
    if (!stat.isFile())
      return { status: 'not_assessed', note: `bound evidence is not a file: ${binding.path}`, receipts }
    if (stat.size > VERIFICATION_READ_CAP)
      return { status: 'not_assessed', note: `bound evidence ${path.basename(binding.path)} is ${stat.size} bytes (over the ${VERIFICATION_READ_CAP} read cap) — bind a sliced extract of the decisive fragment`, receipts }
    let actual: string
    try { actual = sha256File(binding.path) } catch {
      return { status: 'not_assessed', note: `bound evidence unreadable: ${path.basename(binding.path)}`, receipts }
    }
    if (actual !== binding.sha256)
      return { status: 'not_assessed', note: `EVIDENCE DRIFT: ${path.basename(binding.path)} sha256 is now ${actual.slice(0, 12)}… but the binding pinned ${binding.sha256.slice(0, 12)}… — the file changed after binding; re-capture and re-bind`, receipts }
    bodies.push({ name: path.basename(binding.path), normalized: normalizeWs(fs.readFileSync(binding.path, 'utf8')) })
  }

  let misses = 0
  for (const quote of finding.quotes) {
    if (quote.length < VERIFICATION_MIN_QUOTE_CHARS) {
      receipts.push({ quote, miss: `short quote (${quote.length} < ${VERIFICATION_MIN_QUOTE_CHARS} chars) — quote the decisive fragment, not a token` })
      misses++
      continue
    }
    const needle = normalizeWs(quote)
    const hit = bodies.find(b => b.normalized.includes(needle))
    if (hit === undefined) {
      receipts.push({ quote, miss: 'not found in any bound body (whitespace-normalized verbatim check)' })
      misses++
    } else {
      receipts.push({ quote, foundIn: hit.name })
    }
  }
  if (misses > 0)
    return { status: 'unverified', note: `${misses} of ${finding.quotes.length} quote(s) failed the verbatim receipt check — the verifier reads the BOUND bodies, not the lane's memory`, receipts }
  return { status: 'verified', note: `${finding.quotes.length} quote(s) found verbatim in ${bodies.length} sha-pinned bound body/bodies; POE L${finding.poe}; ≥1 ${proofBindings.map(b => b.role).join('/')} binding`, receipts }
}

/** Whether the recorded report was written against older evidence. */
export function findingIsStale(finding: Finding): boolean {
  return finding.report_evidence_version !== undefined && finding.report_evidence_version !== finding.evidence_version
}
