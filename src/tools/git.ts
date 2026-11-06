import { execFile } from 'node:child_process'
import fs from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { z } from 'zod'
import { errorResult, textResult, type ToolResult, type ToolRegistrar } from '../browser/tools.js'

const exec = promisify(execFile)
const joinPath = path.join
const COMMIT_TYPES = ['Feat', 'Fix', 'Test', 'Docs', 'Chore', 'Release', 'Hunt', 'Report'] as const
export type CommitType = (typeof COMMIT_TYPES)[number]

export interface CommitDraft {
  type: CommitType
  subject: string
  bullets: string[]
  verification: string
}

/** The AGENTS.md message format, rendered — pure so tests pin it. */
export function renderCommitMessage(draft: CommitDraft): string {
  const body = draft.bullets.map(b => `- [x] ${wrap(b, 72)}`).join('\n')
  return `${draft.type}: ${draft.subject}\n\n${body}\n\nVerified: ${draft.verification}\n`
}

function wrap(line: string, width: number): string {
  const words = line.split(/\s+/)
  const out: string[] = []
  let current = ''
  for (const word of words) {
    if (current !== '' && current.length + 1 + word.length > width) { out.push(current); current = word } else {
      current = current === '' ? word : `${current} ${word}`
    }
  }
  if (current !== '') out.push(current)
  return out.join('\n      ')
}

/** Parse the `## branch...remote [ahead N, behind M]` line of
 *  `git status --porcelain=v1 -b` — pure so tests pin it. A branch with NO
 *  upstream is never "synced" (advice 2026-11-06 #4: repo_commit claimed
 *  "Pushed." even when the push silently needed a retry). */
export interface BranchSync {
  branch: string
  remote?: string
  ahead: number
  behind: number
  synced: boolean
}

export function parseBranchSync(line: string): BranchSync {
  const trimmed = line.trim()
  const head = /^##\s+(\S+)/.exec(trimmed)
  const branch = head === null ? '' : head[1]!.split('...')[0]!
  const remoteMatch = /\.\.\.(\S+)/.exec(trimmed)
  const remote = remoteMatch === null ? undefined : remoteMatch[1]!.replace(/\s*\[.*$/, '')
  const aheadMatch = /ahead (\d+)/.exec(trimmed)
  const behindMatch = /behind (\d+)/.exec(trimmed)
  const ahead = aheadMatch === null ? 0 : Number.parseInt(aheadMatch[1]!, 10)
  const behind = behindMatch === null ? 0 : Number.parseInt(behindMatch[1]!, 10)
  return { branch, remote, ahead, behind, synced: remote !== undefined && ahead === 0 && behind === 0 }
}

async function git(cwd: string, ...args: string[]): Promise<string> {
  try {
    const { stdout } = await exec('git', args, { cwd, windowsHide: true, maxBuffer: 16 * 1024 * 1024 })
    return stdout
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new Error(`${message.trim()}\n(ran in "${cwd}" — the MCP server's own cwd, not your session cwd. Pass repo: "<absolute path>" for your repo.)`)
  }
}

/** The MCP server's process cwd is NOT the session workspace, and dsh sets
 *  no workspace env for MCP children — so remember the last repo the team
 *  named explicitly: the first repo_status/repo_commit with `repo:` seeds
 *  the default for every later call in the run (workers stop passing it). */
let lastRepo: string | undefined
function defaultRepo(): string {
  return lastRepo
    ?? process.env.DSH_WORKSPACE
    ?? process.env.DSH_SESSION_CWD
    ?? process.env.DSH_CWD
    ?? process.cwd()
}

export function registerGitTools(server: ToolRegistrar): void {
  const t = (name: string, description: string, schema: Record<string, z.ZodTypeAny>, handler: (args: any) => Promise<ToolResult>) =>
    server.registerTool(name, { title: name, description }, schema, async args => {
      try { return await handler(args) } catch (error) { return errorResult(error) }
    })

  t('repo_status', 'Git status + branch + ahead/behind for a repo. Pass `repo` once per run — later calls reuse it.',
    { repo: z.string().optional().describe('Repo path (defaults to the last repo used this run, else the server cwd)') },
    async ({ repo }: any) => {
      if (repo !== undefined) lastRepo = repo
      const cwd = repo ?? defaultRepo()
      const status = await git(cwd, 'status', '--porcelain=v1', '-b')
      return textResult(status === '' ? '(clean)' : status.trimEnd())
    })

  t('repo_commit', 'Commit with the DST-Comet message convention (Type: subject + [x] bullets + Verified line). Stages ONLY the given paths and refuses if the index already holds other changes. Paths are validated VERBATIM before staging (run-7 P1-11: the secret scrubber mangled a long repo-relative filename into "[redacted].py" inside a git pathspec error, and the agent could not tell which path was wrong) — a missing file fails with the real path.',
    {
      type: z.enum(COMMIT_TYPES),
      subject: z.string().min(1),
      bullets: z.array(z.string()).min(1).describe('What the commit actually did, one per change'),
      verification: z.string().describe('Checks that ran and their results'),
      paths: z.array(z.string()).min(1).describe('Repo-relative paths to stage'),
      repo: z.string().optional(),
      push: z.boolean().optional().describe('Push after committing'),
    },
    async ({ type, subject, bullets, verification, paths, repo, push }: any) => {
      if (repo !== undefined) lastRepo = repo
      const cwd = repo ?? defaultRepo()
      const staged = (await git(cwd, 'diff', '--cached', '--name-only')).split('\n').map(s => s.trim()).filter(s => s !== '')
      // Rename support (advice 2026-11-06 #4): `git mv old new` stages BOTH the
      // deletion of `old` and the add of `new`, so a caller passing only the
      // NEW path was refused for "staged changes outside your paths" — and
      // committing one side of a rename would split it. A staged path counts
      // as inside the caller's paths when it EQUALS one or lives UNDER a
      // given directory; when a staged rename's destination is inside, its
      // SOURCE joins the commit set.
      const covered = (stagedPath: string, list: readonly string[]): boolean =>
        list.some(p => stagedPath === p || stagedPath.startsWith(`${p.replace(/[\\/]+$/, '')}/`))
      const renameRows = (await git(cwd, 'diff', '--cached', '--name-status', '-M'))
        .split('\n').map(s => s.trim()).filter(s => s !== '')
      const renameSources = new Set<string>()
      for (const row of renameRows) {
        const cols = row.split('\t')
        if (cols.length === 3 && /^R/.test(cols[0]!) && covered(cols[2]!, paths)) renameSources.add(cols[1]!)
      }
      const effective = [...paths, ...renameSources]
      const extraneous = staged.filter(s => !covered(s, effective))
      if (extraneous.length > 0)
        return textResult(`Refusing: the index already holds staged changes outside your paths: ${extraneous.join(', ')}. Coordinate with their owner first.`, true)
      // Validate paths against the worktree BEFORE git add: git's own error
      // text round-trips through the secret scrubber, which mangles long
      // path-shaped strings. This message names the real paths verbatim.
      const tracked = new Set((await git(cwd, 'ls-files', '--', ...paths)).split('\n').map(s => s.trim()).filter(s => s !== ''))
      const missing = paths.filter((p: string) => !tracked.has(p) && !fs.existsSync(joinPath(cwd, p)))
      if (missing.length > 0) {
        return textResult([
          `Refusing: ${missing.length} path(s) do not exist in "${cwd}" (checked verbatim, unredacted):`,
          ...missing.map((p: string) => `  - ${p}`),
          'git status the repo and fix the path list; the remaining paths were not staged.',
        ].join('\n'), true)
      }
      // Stage the CALLER's paths only — the rename sources are ALREADY in
      // the index (that is why they looked extraneous), and `git add` on a
      // path that exists in neither worktree nor index is fatal. `-A` so a
      // deliberately-passed deleted path still stages its deletion.
      await git(cwd, 'add', '-A', '--', ...paths)
      const message = renderCommitMessage({ type, subject, bullets, verification })
      const file = path.join(tmpdir(), `constellation-commit-${Date.now()}.txt`)
      const { writeFileSync, unlinkSync } = await import('node:fs')
      writeFileSync(file, message)
      try {
        await git(cwd, 'commit', '-F', file)
      } finally {
        try { unlinkSync(file) } catch { /* fine */ }
      }
      const hash = (await git(cwd, 'rev-parse', '--short', 'HEAD')).trim()
      // Truthful push (advice 2026-11-06 #4): GitHub flaked twice in one
      // night with `fatal error in commit_refs` AFTER the commit, and the
      // tool still said "Pushed." — the claim is now verified against
      // `git status -sb`, with one retry, and an unverified push is an ERROR.
      let pushLine: string | undefined
      let pushFailed = false
      if (push === true) {
        let pushed = false
        let lastError = ''
        for (let attempt = 1; attempt <= 2 && !pushed; attempt++) {
          try {
            await git(cwd, 'push')
            pushed = true
          } catch (error) {
            lastError = error instanceof Error ? error.message.split('\n')[0]!.trim() : String(error)
          }
          if (!pushed && attempt === 1) await new Promise(resolve => setTimeout(resolve, 1_500))
        }
        const statusLine = (await git(cwd, 'status', '--porcelain=v1', '-b')).split('\n')[0] ?? ''
        const sync = parseBranchSync(statusLine)
        if (pushed && sync.synced) {
          pushLine = `Pushed and VERIFIED — ${sync.branch} matches ${sync.remote}.`
        } else {
          pushFailed = true
          pushLine = `PUSH UNVERIFIED — ${pushed ? 'the push command succeeded' : `push failed: ${lastError}`} but git status reads "${statusLine.trim()}" (${sync.ahead} ahead, ${sync.behind} behind${sync.remote === undefined ? ', NO upstream configured' : ''}). Run repo_status before claiming "pushed".`
        }
      }
      return textResult([
        `Committed ${hash} — ${type}: ${subject}`,
        ...(renameSources.size > 0 ? [`Included staged rename source(s): ${[...renameSources].join(', ')}`] : []),
        ...(pushLine !== undefined ? [pushLine] : []),
        message.trimEnd(),
      ].join('\n'), pushFailed)
    })
}
