# Constellation-MCP

Orchestration-aware MCP server for agent teams — born from the DST-Comet
agent-team bug-bounty runs (see `Advice/agent-team-hunt-run-2026-10-26.md` in
DST-Comet): one shared browser across six teammates meant tab races, cookie
collisions, Gmail OTP hopping, and windows nobody could map.

Constellation fixes the layer, not the symptoms:

- **Per-agent browser isolation** — every `owner` gets its own Chrome process
  and user-data-dir (`profiles/<owner>`), so cookies and sessions for target
  accounts stay separated structurally. No more `select` races: owner A can
  never touch owner B's browser.
- **Tab leases** — `tab_open`/`tab_lease` hold a tab with a purpose; other
  owners' selects and closes are refused and told who holds it and why.
- **Window-per-teammate with labels** — each owner's window title is prefixed
  `[<owner>] ` and `browser_map` gives the Lead the full ownership view:
  sessions, windows, tabs, leases, scope status.
- **Lane hygiene** — `browser_reset({keep: ["shared"]})` closes every
  harness-owned session at lane end while the human's logged-in profile
  (`shared`) survives; idle owner sessions auto-close.
- **Scope guard** — `scope_set` declares the engagement's in/out hosts;
  `http_request` and every navigation are then enforced and audited
  (`scope_audit`), so the run can *prove* it stayed in bounds.
- **Engagement tooling** — `mail_search` / `mail_latest_otp` / `mail_wait`
  (IMAP plus-addressing, codes + links extracted), `http_request` /
  `http_diff` with persistent cookie jars and `$secret:` interpolation,
  `oob_new` / `oob_events` for SSRF/blind-XSS proof, `secrets_list` /
  `secrets_get`, and `repo_commit` with the DST-Comet message convention.
- **Escape hatch** — `browser_force_action` dispatches real CDP input events
  for pages that ignore automation (MUI selects, `isTrusted` sniffs).

Familiar tool names (`browser_navigate`, `browser_snapshot`, `browser_click`,
`browser_tabs`, …) are kept so team prompts and skills keep working; DST-Comet
loads it with `serverName: playwright`.

## Run

```
npm install && npm run verify     # build + 15 unit tests + MCP handshake smoke
npm run smoke                     # real-Chrome browser smoke (offline, data: URLs)
node cli.js                       # stdio MCP server
```

Config: CLI flags (`--browser chrome`, `--headless`, `--shared-user-data-dir`,
`--output-dir`, `--oob-port`, `--oob-public-base`, `--idle-timeout-min`) or
`CONSTELLATION_*` env. Secrets come from `CONSTELLATION_SECRET_*` /
`DSH_SECRET_*` env only — never files, never literals in source.

## Origin

Started as a clone of microsoft/playwright-mcp (Apache-2.0, see `LICENSE` and
git history). The upstream MCP implementation lives inside the Playwright
monorepo and is not forked here — Constellation is a clean implementation on
Playwright's public API (`playwright-core`). Agent names, the lease model, the
scope guard, and the engagement tooling are original to this project.
