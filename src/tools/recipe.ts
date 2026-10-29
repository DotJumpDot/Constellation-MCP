/**
 * Fixture recipe registry + executor (run-8 proposals §1c, the deliberately
 * unbuilt piece — shipped browser-driven so it needs NO product API clients).
 *
 * The repeated work of every engagement cell — two identities → org → shared
 * object → marker → revoke stage — is exactly what a NAMED recipe encodes,
 * and it is where the "tester is always the admin who created the object"
 * bias keeps creeping back into fixtures. The executor enforces the lesson
 * structurally: steps carry an optional per-step `owner`, so the GRANT stage
 * runs in the granting identity's browser and the read/revoke stages run in
 * the tester's — hold-then-lose by construction, not by memory.
 *
 * Recipes persist as JSON; a run executes in the target owner's browser with
 * per-step evidence, captures object ids from page text into variables, and
 * stops with diagnostics at the first failed verification.
 */

import fs from 'node:fs'
import path from 'node:path'
import { z } from 'zod'
import { errorResult, textResult, type ToolResult, type ToolRegistrar } from '../browser/tools.js'
import type { BrowserSession } from '../browser/session.js'
import type { ConstellationConfig } from '../config.js'
import type { JarStore } from './http.js'
import { performLeg, type RequestResult, type RequestSpec } from './http.js'
import { verdictOf, type AuthzVerdict } from './diff.js'
import { appendVerdictEntry } from './evidence.js'
import type { BudgetGuard } from './budget.js'
import type { ScopeGuard } from '../scope.js'

export interface RecipeStep {
  action: 'navigate' | 'click' | 'type' | 'capture' | 'verify' | 'wait' | 'expect'
  /** Which identity's browser runs this step — the grant/revoke stages
   *  SHOULD name the granting identity (the anti-admin-bias mechanism). */
  owner?: string
  url?: string
  selector?: string
  deep_text?: string
  text?: string
  press?: string
  /** capture: first regex match on the page text, stored as a variable. */
  label?: string
  regex?: string
  must_contain?: string[] | string
  must_not_contain?: string[] | string
  /** Case-INsensitive by default (smoke round 5, defect 2) — text assertions
   *  are almost always case-insensitive by intent; opt in with true. */
  case_sensitive?: boolean
  /** Authorization assertion (smoke round 5 suggestion): run probe vs miss
   *  control through diff_pair semantics and require the boundary verdict.
   *  Each leg is an http_request-shaped spec; `browser: '<owner>'` (or true =
   *  the step owner) rides that owner's LIVE browser session — its cookie
   *  state — instead of a jar (round 6, browser-login identities). */
  expect?: 'deny' | 'allow'
  probe?: Record<string, unknown>
  miss?: Record<string, unknown>
  own?: Record<string, unknown>
  ms?: number
  note?: string
}

/** Accept the natural forms: a bare string is one needle (smoke round 5,
 *  defect 1 — a string crashed the step with a TypeError). */
export function normalizeStringArray(value: unknown): string[] {
  if (typeof value === 'string') return [value]
  if (Array.isArray(value)) return value.filter((entry): entry is string => typeof entry === 'string')
  return []
}

/** Pure authorization-assertion matcher (smoke round 5 suggestion): expect
 *  "deny" passes on a real AUTHORIZATION_DENIAL; expect "allow" passes on
 *  DATA_LEAK or SOFT_ALLOW. NOT_FOUND never passes either way — it means the
 *  fixture lookup missed and the cell proves nothing. */
export function expectPasses(verdict: AuthzVerdict, expect: 'deny' | 'allow'): boolean {
  return expect === 'deny'
    ? verdict === 'AUTHORIZATION_DENIAL'
    : verdict === 'DATA_LEAK' || verdict === 'SOFT_ALLOW'
}

/** Pure case-aware contains + the verify verdict, so tests pin the semantics. */
export function evaluateVerify(text: string, step: { must_contain?: string[] | string; must_not_contain?: string[] | string; case_sensitive?: boolean }): { ok: boolean; why: string[]; hints: string[] } {
  const mustContain = normalizeStringArray(step.must_contain)
  const mustNotContain = normalizeStringArray(step.must_not_contain)
  const caseSensitive = step.case_sensitive === true
  const contains = (needle: string): boolean =>
    caseSensitive ? text.includes(needle) : text.toLowerCase().includes(needle.toLowerCase())
  const missing = mustContain.filter(needle => !contains(needle))
  const forbidden = mustNotContain.filter(needle => contains(needle))
  // "found SEEK — differs only by case": only possible in the opt-in
  // case-sensitive mode; the default mode already matches any case.
  const hints = caseSensitive
    ? [...missing.filter(needle => text.toLowerCase().includes(needle.toLowerCase())).map(needle => `found a case-only difference for "${needle}" — the page text differs only by case`)]
    : []
  const why = [
    ...missing.map(needle => `expected "${needle}" — NOT on the page${caseSensitive ? ' (exact-case match)' : ''}`),
    ...forbidden.map(needle => `"${needle}" IS visible (should not be)`),
  ]
  return { ok: why.length === 0, why, hints }
}

export interface Recipe {
  name: string
  description?: string
  /** Default owner for steps without one (usually the tester identity). */
  owner?: string
  steps: RecipeStep[]
}

export function recipesFile(config: ConstellationConfig): string {
  return path.join(config.rootDir, 'fixture-recipes.json')
}

/** ---------------- recipe baselines + drift (round-7 gap list §4) ----------
 *  A boundary that denied last week and allows today is a candidate, and that
 *  TRANSITION is invisible unless something remembers the last verdict. The
 *  runner writes a baseline after every expect resolution; NOT_FOUND never
 *  touches it (a broken fixture must not poison the memory). */

export type RecipeTransition = 'DENY→ALLOW' | 'ALLOW→DENY' | 'UNCHANGED' | 'INCONCLUSIVE'

export interface RecipeBaselineRun {
  verdict: AuthzVerdict
  deciding_field: string
  expect: string
  passed: boolean
  at: string
  statuses: { probe: number; miss: number; own?: number }
  shas: { probe: string; miss: string; own?: string }
}

interface BaselineFile {
  [recipe: string]: {
    current: RecipeBaselineRun
    /** Newest last, capped — the drift table reads the last two. */
    history: RecipeBaselineRun[]
  }
}

const ALLOW_FAMILY: ReadonlySet<AuthzVerdict> = new Set(['DATA_LEAK', 'SOFT_ALLOW'])

/** Pure: the transition between two verdicts. Either side NOT_FOUND (or a
 *  missing previous) is INCONCLUSIVE — never a claim. */
export function classifyTransition(previous: AuthzVerdict | undefined, current: AuthzVerdict): RecipeTransition {
  if (previous === undefined || previous === 'NOT_FOUND' || current === 'NOT_FOUND') return 'INCONCLUSIVE'
  const prevAllow = ALLOW_FAMILY.has(previous)
  const curAllow = ALLOW_FAMILY.has(current)
  if (prevAllow === curAllow) return 'UNCHANGED'
  return prevAllow ? 'ALLOW→DENY' : 'DENY→ALLOW'
}

function loadBaselines(config: ConstellationConfig): BaselineFile {
  try {
    return JSON.parse(fs.readFileSync(path.join(config.rootDir, 'recipe-baselines.json'), 'utf8')) as BaselineFile
  } catch { return {} }
}

/** Record one expect resolution. Returns the transition from the previous
 *  baseline (undefined when nothing comparable: first reading, or the current
 *  verdict is NOT_FOUND — which must NOT poison the baseline). */
export function recordBaseline(config: ConstellationConfig, recipe: string, run: Omit<RecipeBaselineRun, 'at'>): { transition?: RecipeTransition; skipped?: boolean } {
  if (run.verdict === 'NOT_FOUND') return { skipped: true }
  const file = loadBaselines(config)
  const previous = file[recipe]?.current
  const full: RecipeBaselineRun = { ...run, at: new Date().toISOString() }
  const entry = file[recipe] ?? { current: full, history: [] }
  entry.current = full
  entry.history.push(full)
  if (entry.history.length > 20) entry.history.shift()
  file[recipe] = entry
  try {
    fs.mkdirSync(config.rootDir, { recursive: true })
    fs.writeFileSync(path.join(config.rootDir, 'recipe-baselines.json'), JSON.stringify(file, null, 2) + '\n')
  } catch { /* best effort — the run's verdict still returns */ }
  const transition = classifyTransition(previous?.verdict, run.verdict)
  return { transition }
}

/** The stored baseline + recent history for one recipe (or all, for the drift table). */
export function readBaselines(config: ConstellationConfig, recipe?: string): BaselineFile {
  const all = loadBaselines(config)
  if (recipe === undefined) return all
  return recipe in all ? { [recipe]: all[recipe]! } : {}
}

/** Drop one recipe's baseline (recipe_baseline {recipe, reset: true}). */
export function clearBaseline(config: ConstellationConfig, recipe: string): boolean {
  const file = loadBaselines(config)
  if (!(recipe in file)) return false
  delete file[recipe]
  try { fs.writeFileSync(path.join(config.rootDir, 'recipe-baselines.json'), JSON.stringify(file, null, 2) + '\n') } catch { /* best effort */ }
  return true
}

export function loadRecipes(config: ConstellationConfig): Record<string, Recipe> {
  try {
    const parsed = JSON.parse(fs.readFileSync(recipesFile(config), 'utf8')) as Record<string, unknown>
    const out: Record<string, Recipe> = {}
    for (const [name, value] of Object.entries(parsed)) {
      if (value === null || typeof value !== 'object') continue
      const raw = value as { description?: unknown; owner?: unknown; steps?: unknown; remove?: unknown }
      if (raw.remove === true) continue
      if (!Array.isArray(raw.steps)) continue
      out[name] = {
        name,
        ...(typeof raw.description === 'string' ? { description: raw.description } : {}),
        ...(typeof raw.owner === 'string' ? { owner: raw.owner } : {}),
        steps: raw.steps as RecipeStep[],
      }
    }
    return out
  } catch { return {} }
}

/** Substitute `$var:NAME` occurrences from the captured variables. Pure. */
export function interpolateVars(input: string, vars: Record<string, string>): string {
  return input.replace(/\$var:([A-Za-z0-9_-]+)/g, (_, name: string) => vars[name] ?? `$var:${name}`)
}

/** Extract the first regex match group from page text. Pure. */
export function captureFromText(text: string, pattern: string): string | undefined {
  try {
    const match = new RegExp(pattern).exec(text)
    if (match === null) return undefined
    return match[1] ?? match[0]
  } catch {
    return undefined
  }
}

const MAX_STEPS = 40
/** Every action the executor knows. Validation AND the runner's default arm
 *  both key off this — a step that matches nothing must never pass silently
 *  (round-7 D1: {expect, probe, miss} without action:"expect" ran NOTHING and
 *  reported COMPLETE; a recipe that asserts nothing must not report green). */
const STEP_ACTIONS: ReadonlySet<string> = new Set(['navigate', 'click', 'type', 'capture', 'verify', 'wait', 'expect'])

export function validateRecipe(name: string, recipe: Recipe): string | undefined {
  if (recipe.steps.length === 0) return 'recipe has no steps'
  if (recipe.steps.length > MAX_STEPS) return `recipe has ${recipe.steps.length} steps (max ${MAX_STEPS})`
  for (const [index, step] of recipe.steps.entries()) {
    if (typeof step.action !== 'string' || !STEP_ACTIONS.has(step.action))
      return `step ${index + 1} needs a known action (navigate|click|type|capture|verify|wait|expect) — got ${JSON.stringify(step.action) ?? 'undefined'}`
    switch (step.action) {
      case 'navigate':
        if (step.url === undefined || step.url === '') return `step ${index + 1} (navigate) needs url`
        break
      case 'click':
        if ((step.selector === undefined || step.selector === '') && (step.deep_text === undefined || step.deep_text === ''))
          return `step ${index + 1} (click) needs selector or deep_text`
        break
      case 'type':
        if (step.selector === undefined || step.selector === '' || step.text === undefined) return `step ${index + 1} (type) needs selector + text`
        break
      case 'capture':
        if (step.label === undefined || step.label === '' || step.regex === undefined) return `step ${index + 1} (capture) needs label + regex`
        try { new RegExp(step.regex) } catch (error) { return `step ${index + 1} (capture) regex invalid: ${error instanceof Error ? error.message : String(error)}` }
        break
      case 'verify': {
        const mustContain = normalizeStringArray(step.must_contain)
        const mustNotContain = normalizeStringArray(step.must_not_contain)
        if (mustContain.length === 0 && mustNotContain.length === 0)
          return `step ${index + 1} (verify) needs must_contain or must_not_contain (a string or a string array)`
        break
      }
      case 'expect': {
        if (step.expect !== 'deny' && step.expect !== 'allow') return `step ${index + 1} (expect) needs expect: "deny" | "allow"`
        const isSpec = (spec: unknown): boolean => spec !== null && typeof spec === 'object' && typeof (spec as { url?: unknown }).url === 'string'
        if (!isSpec(step.probe) || !isSpec(step.miss)) return `step ${index + 1} (expect) needs probe + miss request specs ({url, jar? | browser?, ...} — http_request shape)`
        break
      }
      case 'wait':
        break
    }
  }
  return undefined
}

export interface RecipeEnv {
  config: ConstellationConfig
  sessionFor: (owner: string) => BrowserSession
  jars: JarStore
  scope: ScopeGuard
  budget?: BudgetGuard
}

/** Structured recipe outcome (the fixture_recipe_run handler formats it;
 *  cell_run reads it — `failedAction: 'expect'` means an AUTHORIZATION
 *  outcome failed, any other action means the fixture/session broke). */
export interface RecipeRunOutcome {
  ok: boolean
  failedAtStep?: number
  failedAction?: string
  failedOwner?: string
  reason?: string
  lines: string[]
  vars: Record<string, string>
  seconds: number
}

/** The recipe executor, shared by fixture_recipe_run and cell_run (round-7
 *  §1): per-step owner switching, $var capture, baseline/drift recording in
 *  the expect arm, run audit, first-failure diagnostics. */
export async function executeRecipe(env: RecipeEnv, recipe: Recipe, owner: string): Promise<RecipeRunOutcome> {
  const name = recipe.name
  const vars: Record<string, string> = {}
  const lines: string[] = []
  let session: BrowserSession | undefined
  let sessionOwner = ''
  let lastStepOwner = owner
  const start = Date.now()
  const audit = (record: Record<string, unknown>): void => {
    try { fs.appendFileSync(recipesFile(env.config).replace('fixture-recipes.json', 'fixture-recipe-runs.jsonl'), JSON.stringify({ ts: new Date().toISOString(), recipe: name, owner, ...record }) + '\n') } catch { /* best effort */ }
  }
  for (const [index, rawStep] of recipe.steps.entries()) {
    const step = rawStep as RecipeStep
    const stepOwner = (step.owner !== undefined && step.owner !== '' ? step.owner : (recipe.owner ?? owner)).trim()
    lastStepOwner = stepOwner
    if (sessionOwner !== stepOwner) {
      session = env.sessionFor(stepOwner)
      sessionOwner = stepOwner
      lines.push(`[step ${index + 1}] → switching to "${stepOwner}"'s browser`)
    }
    const active = session!
    const page = await active.currentPage()
    try {
      switch (step.action) {
        case 'navigate': {
          const url = interpolateVars(step.url!, vars)
          await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 45_000 })
          lines.push(`[step ${index + 1}] navigate ${url}`)
          break
        }
        case 'click': {
          const locator = step.selector !== undefined && step.selector !== ''
            ? page.locator(interpolateVars(step.selector, vars)).first()
            : page.locator(`text=${JSON.stringify(interpolateVars(step.deep_text!, vars))}`).first()
          await locator.click({ timeout: 10_000 })
          lines.push(`[step ${index + 1}] click ${step.selector ?? `text "${step.deep_text}"`}`)
          break
        }
        case 'type': {
          const text = interpolateVars(step.text!, vars)
          await page.locator(interpolateVars(step.selector!, vars)).first().fill(text, { timeout: 10_000 })
          if (step.press !== undefined && step.press !== '') await page.locator(interpolateVars(step.selector!, vars)).first().press(step.press)
          lines.push(`[step ${index + 1}] type ${text.length} chars into ${step.selector}`)
          break
        }
        case 'capture': {
          const text = await page.evaluate(() => document.body?.innerText ?? '')
          const value = captureFromText(text, step.regex!)
          if (value === undefined) {
            lines.push(`[step ${index + 1}] capture ${step.label}: NOT FOUND`)
            throw new Error(`capture "${step.label}" failed: /${step.regex}/ matched nothing on ${page.url()}. Page text head: ${text.slice(0, 600).replace(/\s+/g, ' ')}`)
          }
          vars[step.label!] = value
          lines.push(`[step ${index + 1}] captured ${step.label} = ${value}`)
          break
        }
        case 'verify': {
          await page.waitForTimeout(800)
          const text = await page.evaluate(() => document.body?.innerText ?? '')
          const verdict = evaluateVerify(text, step)
          if (!verdict.ok) {
            const detail = [...verdict.why, ...verdict.hints].join('; ')
            throw new Error(`verification FAILED at step ${index + 1}: ${detail}. Page text head: ${text.slice(0, 600).replace(/\s+/g, ' ')}`)
          }
          lines.push(`[step ${index + 1}] verify OK (${[...normalizeStringArray(step.must_contain).map(needle => `"${needle}" present`), ...normalizeStringArray(step.must_not_contain).map(needle => `"${needle}" absent`)].join(', ')})${step.case_sensitive === true ? ' [exact case]' : ''}`)
          break
        }
        case 'expect': {
          // Authorization assertion: probe vs miss control through diff_pair
          // semantics (smoke round 5). A leg with `browser: '<owner>'` (or
          // true = the step owner) rides that owner's LIVE browser session
          // (round 6): the same identity the grant/revoke clicks used, so
          // browser-login products stay testable without a jar.
          const leg = (raw: Record<string, unknown>): Promise<RequestResult> =>
            performLeg(env, raw as unknown as RequestSpec & { browser?: unknown }, stepOwner, 'fixture_recipe')
          const [probe, miss, own] = await Promise.all([
            leg(step.probe!),
            leg(step.miss!),
            step.own !== undefined ? leg(step.own) : Promise.resolve(undefined),
          ])
          const verdict = verdictOf({ probe, miss, ...(own !== undefined ? { own } : {}) })
          // Baseline + drift (round-7 §4): remember what the boundary DID, so
          // a later run can name the transition. NOT_FOUND never records (a
          // broken fixture must not poison the baseline), and a DENY→ALLOW
          // opening cites itself in the evidence chain.
          const baseline = recordBaseline(env.config, name, {
            verdict: verdict.verdict,
            deciding_field: verdict.deciding_field,
            expect: step.expect!,
            passed: expectPasses(verdict.verdict, step.expect!),
            statuses: { probe: probe.status, miss: miss.status, ...(own !== undefined ? { own: own.status } : {}) },
            shas: { probe: probe.body_sha256, miss: miss.body_sha256, ...(own !== undefined ? { own: own.body_sha256 } : {}) },
          })
          if (baseline.transition === 'DENY→ALLOW') {
            try {
              appendVerdictEntry(env.config, stepOwner, 'recipe_drift', {
                verdict: verdict.verdict,
                deciding_field: verdict.deciding_field,
                probe: { status: probe.status, sha: probe.body_sha256 },
                miss: { status: miss.status, sha: miss.body_sha256 },
                transition: 'DENY→ALLOW',
                object: name,
              })
            } catch { /* the chain must never fail the run */ }
            lines.push(`[step ${index + 1}] ⚠ TRANSITION DENY→ALLOW — this boundary OPENED since its last baseline: candidate (the transition is cited in the evidence chain)`)
          }
          if (!expectPasses(verdict.verdict, step.expect!)) {
            const wanted = step.expect === 'deny'
              ? 'the boundary to DENY the other identity'
              : 'the other identity to have access'
            throw new Error(`authorization assertion FAILED at step ${index + 1}: expected ${wanted}, but diff_pair said ${verdict.verdict} (deciding: ${verdict.deciding_field}) — ${verdict.note}`)
          }
          lines.push(`[step ${index + 1}] expect ${step.expect} OK — ${verdict.verdict} (deciding: ${verdict.deciding_field})`)
          break
        }
        case 'wait': {
          await page.waitForTimeout(Math.min(step.ms ?? 1000, 30_000))
          lines.push(`[step ${index + 1}] wait ${Math.min(step.ms ?? 1000, 30_000)} ms`)
          break
        }
        default: {
          // Round-7 D1: an unknown/missing action must FAIL the run, never
          // skip silently — loadRecipes trusts the file on disk, and a step
          // that matches no arm asserts nothing.
          throw new Error(`unknown step action ${JSON.stringify(step.action) ?? '(missing)'} at step ${index + 1} — valid: navigate|click|type|capture|verify|wait|expect`)
        }
      }
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error)
      audit({ step: index + 1, action: step.action, ok: false, reason, vars })
      return { ok: false, failedAtStep: index + 1, failedAction: step.action, failedOwner: lastStepOwner, reason, lines, vars, seconds: Math.round((Date.now() - start) / 1000) }
    }
  }
  audit({ step: recipe.steps.length, action: 'complete', ok: true, vars })
  return { ok: true, lines, vars, seconds: Math.round((Date.now() - start) / 1000) }
}

export function registerRecipeTools(server: ToolRegistrar, env: RecipeEnv): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('fixture_recipe_set', 'Save or replace a NAMED FIXTURE RECIPE (run-8 §1c, the registry): the repeatable object graph of an engagement cell — two identities → org → shared object → marker → revoke stage — as ordered browser steps. Per-step `owner` is the anti-bias mechanism: the grant/revoke stages run in the GRANTING identity\'s browser, the read stages in the tester\'s, so "tester is the admin who created the object" cannot creep back in. Steps: navigate {url}, click {selector|deep_text}, type {selector, text}, capture {label, regex}, verify {must_contain|must_not_contain}, expect {expect: deny|allow, probe, miss, own?}, wait {ms}. Text fields interpolate $var:NAME from captured variables. expect legs are http_request-shaped and accept `browser: "<owner>"` (or true = step owner) to ride that identity\'s LIVE browser session instead of a jar — the bridge for browser-login products. `remove: true` deletes.',
    {
      name: z.string().describe('Recipe name, e.g. "klaviyo-shared-page-revoke"'),
      description: z.string().optional(),
      owner: z.string().optional().describe('Default owner (usually the TESTER identity); per-step owner overrides'),
      steps: z.array(z.record(z.string(), z.unknown())).optional().describe('Ordered steps (see description)'),
      remove: z.boolean().optional(),
    },
    async ({ name, description, owner, steps, remove }: any) => {
      const file = recipesFile(env.config)
      let parsed: Record<string, unknown> = {}
      try { parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, unknown> } catch { /* first recipe */ }
      if (remove === true) {
        parsed[name] = { remove: true }
        fs.mkdirSync(env.config.rootDir, { recursive: true })
        fs.writeFileSync(file, JSON.stringify(parsed, null, 2) + '\n')
        return textResult(`Recipe "${name}" removed (known: ${Object.keys(loadRecipes(env.config)).join(', ') || 'none'}).`)
      }
      if (steps === undefined) throw new Error('steps is required (an ordered array of step objects)')
      const recipe: Recipe = { name, ...(description !== undefined ? { description } : {}), ...(owner !== undefined ? { owner } : {}), steps }
      const invalid = validateRecipe(name, recipe)
      if (invalid !== undefined) return textResult(`Refusing to save: ${invalid}.`, true)
      parsed[name] = recipe
      fs.mkdirSync(env.config.rootDir, { recursive: true })
      fs.writeFileSync(file, JSON.stringify(parsed, null, 2) + '\n')
      return textResult(`Recipe "${name}" saved — ${steps.length} step(s)${owner !== undefined ? `, default owner "${owner}"` : ''}. Run it with fixture_recipe_run {name, owner}.`)
    })

  t('fixture_recipe_list', 'List saved fixture recipes with their step counts and descriptions.',
    {},
    async () => {
      const recipes = loadRecipes(env.config)
      const names = Object.keys(recipes)
      if (names.length === 0) return textResult('(no recipes saved — fixture_recipe_set creates one)')
      return textResult(names.map(name => {
        const recipe = recipes[name]!
        return `${name} — ${recipe.steps.length} step(s)${recipe.owner !== undefined ? `, default owner ${recipe.owner}` : ''}${recipe.description !== undefined ? ` — ${recipe.description}` : ''}`
      }).join('\n'))
    })

  t('fixture_recipe_run', 'Execute a named fixture recipe (run-8 §1c): runs the steps in the target owner\'s browser with per-step evidence, captures object ids via capture steps into $var:NAME variables, and STOPS at the first failed verification with the page\'s own text as the diagnostic. Steps with their own `owner` switch browsers — the grant stage runs in the granting identity\'s session, the reads in yours (hold-then-lose by construction). expect steps assert the authorization verdict; a leg with `browser: "<owner>"` (or true) sends it through that identity\'s LIVE browser session, so browser-login identities need no jar. Every run appends to fixture-recipe-runs.jsonl.',
    {
      name: z.string().describe('Recipe name from fixture_recipe_set'),
      owner: z.string().describe('Default owner for steps without one (usually YOUR lane name = the tester identity)'),
    },
    async ({ name, owner }: any) => {
      const recipes = loadRecipes(env.config)
      const recipe = recipes[name]
      if (recipe === undefined) {
        const known = Object.keys(recipes).join(', ')
        return textResult(`unknown recipe "${name}"${known !== '' ? ` (known: ${known})` : ' — none saved yet; fixture_recipe_set creates one'}`, true)
      }
      // Re-validate at run time too: loadRecipes trusts the JSON on disk, and
      // a hand-edited recipe must fail HERE, not mid-run or (round-7 D1)
      // silently skip a step whose action is missing.
      const invalid = validateRecipe(name, recipe)
      if (invalid !== undefined) return textResult(`Refusing to run "${name}": ${invalid} — fix it with fixture_recipe_set.`, true)
      const outcome = await executeRecipe(env, recipe, owner)
      if (!outcome.ok) {
        return textResult([
          `RECIPE FAILED at step ${outcome.failedAtStep}/${recipe.steps.length} (${outcome.failedAction}) as "${outcome.failedOwner}":`,
          outcome.reason,
          // Round-8 D6: the tail of the step log too — the ⚠ TRANSITION
          // DENY→ALLOW line is pushed BEFORE a failing expect throws, and it
          // is the one thing a lane must not miss mid-run (the opening IS the
          // candidate even when the run then fails the assertion).
          ...(outcome.lines.length > 0 ? ['', ...outcome.lines.slice(-6)] : []),
          '',
          `Variables captured so far: ${Object.entries(outcome.vars).map(([key, value]) => `${key}=${value}`).join(', ') || '(none)'}`,
          'Fix the step or the session and re-run — the recipe is unchanged.',
        ].join('\n'), true)
      }
      return textResult([
        `RECIPE "${name}" COMPLETE — ${recipe.steps.length} step(s) in ${outcome.seconds} s.`,
        ...outcome.lines,
        `Variables captured: ${Object.entries(outcome.vars).map(([key, value]) => `${key}=${value}`).join(', ') || '(none)'}`,
      ].join('\n'))
    })

  t('recipe_baseline', 'Show one recipe\'s stored baseline (round-7 §4): the verdict, deciding field, statuses and body shas of its last expect resolution, plus recent history. The runner records a baseline after EVERY expect step (never on NOT_FOUND — a broken fixture must not poison the memory); `reset: true` drops it so the next run becomes a fresh first reading.',
    {
      recipe: z.string().describe('Recipe name'),
      reset: z.boolean().optional().describe('Drop the stored baseline'),
    },
    async ({ recipe, reset }: any) => {
      if (reset === true) {
        return textResult(clearBaseline(env.config, recipe)
          ? `Baseline for "${recipe}" dropped — the next expect resolution becomes a fresh first reading.`
          : `No baseline stored for "${recipe}".`, )
      }
      const stored = readBaselines(env.config, recipe)[recipe]
      if (stored === undefined) return textResult(`No baseline stored for "${recipe}" yet — run the recipe; the expect step records it automatically.`)
      const render = (run: RecipeBaselineRun) =>
        `${run.at} — ${run.verdict} (deciding: ${run.deciding_field}, expect ${run.expect} ${run.passed ? 'HELD' : 'BROKE'}; probe ${run.statuses.probe}/miss ${run.statuses.miss}${run.statuses.own !== undefined ? `/own ${run.statuses.own}` : ''}; sha ${run.shas.probe.slice(0, 8)}…/${run.shas.miss.slice(0, 8)}…)`
      return textResult([
        `BASELINE "${recipe}":`,
        render(stored.current),
        ...(stored.history.length > 1 ? ['', `history (${stored.history.length}, oldest first):`, ...stored.history.slice(0, -1).map(render)] : []),
        '',
        'recipe_drift names the transition between the last two readings.',
      ].join('\n'))
    })

  t('recipe_drift', 'The transition is the finding (round-7 §4): a boundary that DENIED last week and ALLOWS today is a candidate, and nothing remembered that. This table compares each recipe\'s last two baseline readings — DENY→ALLOW (opening = candidate; the runner already cited it in the evidence chain), ALLOW→DENY, UNCHANGED, INCONCLUSIVE (a NOT_FOUND on either side: the fixture broke, prove nothing). Omit `recipe` for every recipe with a baseline.',
    { recipe: z.string().optional() },
    async ({ recipe }: any) => {
      const stored = readBaselines(env.config, recipe)
      const names = Object.keys(stored)
      if (names.length === 0) return textResult(recipe !== undefined
        ? `No baseline for "${recipe}" — run the recipe first (expect steps record automatically).`
        : '(no baselines yet — run any recipe with an expect step)')
      return textResult(names.map(name => {
        const entry = stored[name]!
        if (entry.history.length < 2) return `${name}: first reading ${entry.current.verdict} at ${entry.current.at} — no comparison yet`
        const prev = entry.history[entry.history.length - 2]!
        const transition = classifyTransition(prev.verdict, entry.current.verdict)
        const marker = transition === 'DENY→ALLOW' ? ' ⚠ OPENING — candidate' : transition === 'ALLOW→DENY' ? ' (boundary tightened)' : ''
        return `${name}: ${transition} (${prev.verdict} at ${prev.at} → ${entry.current.verdict} at ${entry.current.at})${marker}`
      }).join('\n'))
    })
}
