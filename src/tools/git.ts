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
      const wanted = new Set(paths)
      const extraneous = staged.filter(s => !wanted.has(s))
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
      await git(cwd, 'add', '--', ...paths)
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
      const pushed = push === true ? await git(cwd, 'push') : undefined
      return textResult([
        `Committed ${hash} — ${type}: ${subject}`,
        ...(pushed !== undefined ? ['Pushed.'] : []),
        message.trimEnd(),
      ].join('\n'))
    })
}
