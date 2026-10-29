/**
 * Structural body diff (round-7 gap list §3): `http_diff` reported the first
 * diverging LINE, which on minified JSON is the entire document. This module
 * walks two parsed JSON bodies into `path -> (a, b)` leaf pairs, so the
 * deciding FIELD is named instead of a 200 KB one-line blob.
 *
 * Volatile noise (csrf nonces, timestamps, trace ids) is SUPPRESSED — but
 * always LISTED, never silently dropped. Honest limitation, by design: a
 * volatile VALUE SHAPE (UUID/hex/ISO) can hide the deciding field when the
 * leaked value itself has that shape, so suppress-by-shape is opt-in per
 * call site and probe-vs-owner verdict paths use NO suppression at all.
 */

/** Keys whose values are expected to differ between any two responses. */
const VOLATILE_KEYS = new Set([
  'nonce', 'csrf', 'csrftoken', 'token', 'accesstoken', 'timestamp', 'ts',
  'requestid', 'trace', 'traceid', 'expires', 'date', 'etag', 'session',
  'sessionid', 'updatedat', 'createdat', 'lastmodified',
])

export interface StructuralChange {
  path: string
  a: string
  b: string
}

export interface StructuralSuppression {
  path: string
  reason: string
}

export interface StructuralDiffResult {
  kind: 'json' | 'not-json'
  changed: StructuralChange[]
  suppressed: StructuralSuppression[]
  truncated: boolean
}

const MAX_CHANGES = 50
const MAX_VALUE_CHARS = 200

function isVolatileKey(key: string): boolean {
  return VOLATILE_KEYS.has(key.toLowerCase().replace(/[_\s-]/g, ''))
}

/** Values that differ between any two responses by shape, not key. */
export function isVolatileValueShape(value: string): boolean {
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(value)) return true // ISO-8601
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return true // UUID
  if (/^[0-9a-f]{32,}$/i.test(value)) return true // hex token
  return false
}

function render(value: unknown): string {
  const text = typeof value === 'string' ? value : JSON.stringify(value) ?? String(value)
  return text.length > MAX_VALUE_CHARS ? text.slice(0, MAX_VALUE_CHARS) + `…[${text.length} chars]` : text
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Walk two parsed JSON values into leaf changes. `path` is dotted-rooted
 * (`role`, `items[0].id`). Added/removed keys render the present side and
 * `(added)`/`(removed)` in the path. `suppressVolatile` skips leaf pairs whose
 * KEY is volatile or whose values are volatile-shaped — recording each one.
 * Pure.
 */
export function structuralJsonDiff(a: unknown, b: unknown, options: { suppressVolatile?: boolean } = {}): StructuralDiffResult {
  const changed: StructuralChange[] = []
  const suppressed: StructuralSuppression[] = []
  let truncated = false

  const leaf = (path: string, av: unknown, bv: unknown, key: string): void => {
    if (options.suppressVolatile === true && av !== bv
      && (isVolatileKey(key) || (typeof av === 'string' && typeof bv === 'string' && isVolatileValueShape(av) && isVolatileValueShape(bv)))) {
      suppressed.push({ path, reason: isVolatileKey(key) ? `volatile key "${key}"` : 'volatile value shape (UUID/hex/ISO on both sides)' })
      return
    }
    if (changed.length >= MAX_CHANGES) {
      truncated = true
      return
    }
    changed.push({ path, a: render(av), b: render(bv) })
  }

  const walk = (av: unknown, bv: unknown, path: string, key: string): void => {
    if (av === bv) return
    if (Array.isArray(av) && Array.isArray(bv)) {
      if (av.length !== bv.length) {
        leaf(`${path}.length`, av.length, bv.length, 'length')
      }
      const common = Math.min(av.length, bv.length)
      for (let i = 0; i < common && !truncated; i++) walk(av[i], bv[i], `${path}[${i}]`, key)
      return
    }
    if (isPlainObject(av) && isPlainObject(bv)) {
      const keys = [...new Set([...Object.keys(av), ...Object.keys(bv)])].sort()
      for (const k of keys) {
        if (truncated) return
        if (!(k in av)) { leaf(`${path}.${k} (added)`, undefined, bv[k], k); continue }
        if (!(k in bv)) { leaf(`${path}.${k} (removed)`, av[k], undefined, k); continue }
        walk(av[k], bv[k], path === '' ? k : `${path}.${k}`, k)
      }
      return
    }
    leaf(path === '' ? '$' : path, av, bv, key)
  }

  walk(a, b, '', '')
  return { kind: 'json', changed, suppressed, truncated }
}

/** One-line rendering of a StructuralDiffResult (used by http_diff output). */
export function renderStructuralDiff(result: StructuralDiffResult): string {
  const lines: string[] = [`json diff: ${result.changed.length} changed field(s), ${result.suppressed.length} suppressed volatile`]
  for (const change of result.changed) lines.push(`  ${change.path}: ${change.a} → ${change.b}`)
  for (const s of result.suppressed) lines.push(`  (suppressed) ${s.path}: ${s.reason}`)
  if (result.truncated) lines.push(`  …more than ${MAX_CHANGES} changes — diff the body_file pair for the rest`)
  return lines.join('\n')
}

/**
 * The deliberately small JSONPath subset for http_extract (round-7 §2): `.key`,
 * `[n]`, `[*]`, chained (`data.items[0].id`, `items[*].id`). No dependency, no
 * wildcard predicates — a full engine returns unpredictable sizes and this
 * tool's whole point is bounded output. Returns EVERY match ([*] fans out);
 * callers cap.
 */
export function queryJsonPath(value: unknown, query: string): unknown[] {
  const tokens = query.match(/\.?([A-Za-z0-9_$-]+)|\[(\*|\d+)\]/g)
  if (tokens === null) return []
  let current: unknown[] = [value]
  for (const token of tokens) {
    const keyMatch = /^\.?([A-Za-z0-9_$-]+)$/.exec(token)
    const indexMatch = /^\[(\*|\d+)\]$/.exec(token)
    if (keyMatch !== null) {
      current = current.flatMap(node => isPlainObject(node) && keyMatch[1]! in node ? [node[keyMatch[1]!]] : [])
    } else if (indexMatch !== null) {
      if (indexMatch[1] === '*') {
        current = current.flatMap(node => Array.isArray(node) ? node : [])
      } else {
        const index = Number.parseInt(indexMatch[1]!, 10)
        current = current.flatMap(node => Array.isArray(node) && index < node.length ? [node[index]!] : [])
      }
    }
    if (current.length === 0) return []
  }
  return current
}
