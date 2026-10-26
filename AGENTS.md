# AGENTS.md — working rules for Constellation-MCP

## What this repo is

Constellation-MCP: an orchestration-aware MCP server for agent teams — per-agent
browser isolation, tab leases, a harness-level ownership map, and the
engagement-tooling surface (mail/OTP, HTTP with cookie jars, scope guard, OOB
receiver, secrets, git helper). Built for DST-Comet (`C:\Code\Dsh_Tui_Comet`),
which loads it as the `playwright` MCP server.

The repository started as a clone of microsoft/playwright-mcp (Apache-2.0,
kept in `LICENSE` and git history). The upstream MCP implementation lives
inside the Playwright monorepo and is not forked here; Constellation-MCP is a
clean implementation on Playwright's public API (`playwright-core`). Do not
re-introduce upstream internals.

## Layout

- `src/` — TypeScript sources. `src/browser/` = per-owner session registry +
  browser tools; `src/tools/` = mail/http/scope/oob/secrets/git.
- `src/scope.ts` — the scope guard shared by browser and HTTP tools.
- `lib/` — build output (tsc). `cli.js` — bin shim → `lib/cli.js`.
- `tests/` — `node --import tsx/esm --test tests/*.spec.ts` (no browser
  needed). `scripts/smoke.ts` — real-Chrome smoke, run via `npm run smoke`.

Build: `npm install && npm run verify` (= build + tests). Smoke needs Google
Chrome installed: `npm run smoke`.

## House rules

- **Per-owner isolation is structural.** Browser state must never leak across
  owners: every owner gets its own browser process + user-data-dir. The
  `shared` session exists for the human's logged-in profile only. Any new
  browser tool must take `owner` and route through `OwnerRegistry` — never
  touch a global page.
- **Scope guard first.** Navigation and HTTP tools call `ScopeGuard.assert()`
  before any request. When a scope is set, out-of-scope = refusal, not a
  warning. Every decision (allow and deny) is appended to the audit log.
- **Secrets never enter transcripts by design.** No credential literals in
  source; secrets come from env (`CONSTELLATION_SECRET_*` / `DSH_SECRET_*`)
  and are consumed server-side via `$secret:<name>` interpolation. Plain
  `secrets_get` masks by default.
- **Tab leases.** A tab with a lease may only be selected/closed by its
  lease owner; refusals name the owner and purpose. `tab_open` is the
  lease-and-create path.
- Windows is the primary platform (Git Bash + PowerShell). Test rendering and
  paths on Windows first; forward slashes in shell commands.
- Keep the MCP tool surface backward-compatible: tool names and arg shapes
  that exist (`browser_navigate`, `browser_snapshot`, …) may gain optional
  params but must not change meaning — team prompts and skills depend on them.

## Commit & push style (every commit, no exceptions)

Subject: `Type: summary (extra detail in parens)` — Type ∈ `Feat | Fix | Test |
Docs | Chore | Release`. Body: a `- [x]` checklist of what the commit actually
did (one item per real change, wrapped ~72 cols). Close with a `Verified:`
paragraph naming the checks that ran and their results. One push = one or more
whole commits of this shape; never mix types in one commit.

```
Fix: tab select now refuses leases held by another owner
- [x] Lease table survived restarts by persisting to the session file
- [x] Select denial text now names the lease owner and purpose

Verified: 12 unit tests green, build clean, smoke on chrome channel green.
```

Tip: write the message to a file and `git commit -F <file>` — inline heredocs
through Git Bash can flatten newlines.
