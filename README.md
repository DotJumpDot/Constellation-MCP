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

## Session handoff lifetimes (measured — run-50 §12, three runs)

Different login routes on the same tenant decay at very different speeds;
build lane sequences that do not outlive their seed identity:

| Route | Measured lifetime | Use for |
| --- | --- | --- |
| Password sign-in in the lane's own browser | stable for the whole lane (~hours) | any lane longer than 5 minutes |
| Cookie handoff (`browser_cookies_export` → `import`) onto a DBSC-bound tenant (Atlassian) | **~4 minutes** (3–4 min, two lanes) — the same cookies stayed valid in their origin profile; a device/session binding, not cookie expiry | one short leg only |
| Lead's plain-profile Bugcrowd session | **~40 minutes** (died twice in one run) | board-watch legs need a lane-owned session, not the Lead's window |

Template rule: **prefer a real sign-in over a cookie handoff for any lane
longer than 5 minutes.** `browser_cookies_import`'s description carries the
same numbers. For board-watch legs that must outlive the Lead's ~40-minute
window, hand the session into a dedicated `board-watch` owner
(`browser_cookies_export` → import) instead of polling from the Lead's own
window. Shared per-run fixture JSON (tenant identity pools) belongs in
`secrets_file_patch` — atomic merge under a lock, never two lanes
hand-rolling read-modify-write — and event-driven fixtures belong under a
`fixture_lease`.

## Disk budget (rootDir cap — 2026-11-20)

The root (`%LOCALAPPDATA%\constellation-mcp`) accumulated **60+ GB** across
hunt runs: retained per-owner profile dirs plus artifact files are only
reaped when a Lead remembers to call `browser_profiles_reap`. The root is
now **capped at 10 GB by default** (`CONSTELLATION_DISK_BUDGET_MB`, 0 =
off), enforced automatically ~2 s after server start and then every 30
minutes (`CONSTELLATION_DISK_BUDGET_CHECK_MIN`, 0 = startup only). When
over the cap, the **oldest safe items are deleted first**: retained profile
dirs with no live session and no running chrome.exe (whole dir), then
artifact files under `artifacts/` (screenshots, downloads, response bodies,
evidence dirs — per file, oldest first; emptied dirs are pruned). **Never
deleted:** the shared profile (human logins), `plain-shared`, dirs of live
sessions or chromes (fresh census right before each deletion), and the
small state files (scope/jars/injectlab/fixture records). If the protected
mass alone exceeds the cap, the server says so instead of silently sitting
over budget. `storage_reap` (no arguments) is the on-demand status report —
breakdown, protection list, oldest evictable — and `dry_run:false` enforces
immediately.

## Noise governor (request pacing — 2026-11-20)

Every outbound target touch — `browser_navigate`, `browser_fetch`,
`browser_tabs new`, `tab_open`, `http_request`/`http_replay`/`http_download`,
diff/recipe/cell legs, `dns_takeover_check` fetches, `mcp_auth_gate` probes —
is now **paced** by three token buckets: per-owner, per-host (shared across
owners), and global, plus uniform send jitter (≤250 ms). Calls **queue
(sleep) until a token frees** — nothing is dropped; only a wait beyond 120 s
refuses with a `NOISE GOVERNOR` error (a same-instant flood, not normal
work). The hard tier stays separate: `budget_set` still refuses past a
per-owner TOTAL cap. Default profile **quiet** (owner/host/global 6/12/21
rpm, burst 3 — noise only gets harder); `CONSTELLATION_NOISE_PROFILE` or
`--noise-profile` picks `off|quiet|balanced|aggressive` at start, and the
Lead can switch at runtime with `noise_profile`. `noise_report` shows rpm
now / peak / throttle waits per owner and per host. Every paced request
appends one line to `noise-audit.jsonl`. Chrome subresource traffic inside
a page is invisible to this (same class of limitation ARTEX documents) —
the buckets cover every request the tools themselves issue.

## Findings index + machine verification (POE — 2026-11-20)

Candidates used to live in chat prose: "verified" was a word a lane typed,
and evidence sat in the tamper-evident chain unlinked to any finding. Now a
finding is a first-class record (`findings.json` at the root) that **binds
evidence files sha256-pinned with roles** (`baseline` = the unaffected
control, `proof` = the body carrying the finding, `verification` = an
independent re-check, `supporting` = context), optionally anchored to an
evidence-chain entry. It carries **POE 1–4** — the lane's *declared*
demonstrated depth (1 anomaly/timing, 2 structural manipulation, 3 data
extracted, 4 critical impact) — and a **machine `verification`** the agent
never sets: `verified` requires ≥1 proof/verification binding, POE ≥3, and
**every quote ≥8 chars found verbatim (whitespace-normalized) inside a
bound body whose sha256 still matches** — the server reads the bodies
itself, never the lane's memory of them. Missing/drifted/oversized
evidence ⇒ `not_assessed` (fail closed). `status` stays the human
disposition. `findings_list` is the Lead's machine-readable gate;
`findings_export` freezes an **evidence pack** (per-finding markdown +
manifest.json + hash-re-verified copies of every bound file) that moves
lane → validator → report without re-capture, and flags STALE when a
report was exported against older evidence.

## Escape-hatch fence + untrusted framing (2026-11-20)

`browser_run_code_unsafe` (the escape hatch with Node `require`) is now
**fenced before its code is ever compiled**: built-in denies refuse
`child_process` (the whole shell/scanner-binary class), `process.exit`
(killing the MCP server), `window.open` (windows invisible to the tab
registry/leases/ownership label), and bare busy-waits (a timeout never
stops escape-hatch code). These can never be exempted.
`CONSTELLATION_UNSAFE_DENY` adds operator regex rules (semicolon-separated);
`CONSTELLATION_UNSAFE_ALLOW` may exempt **only** operator rules — allow
matches less, deny matches more. Every decision appends `fence-audit.jsonl`
(code sha256 + size, never the code text), and refusals use platform-control
framing so a lane does not mistake them for a target defense to bypass.

Target-derived tool output — page/a11y snapshots, HTTP body previews,
escape-hatch results — is wrapped in **UNTRUSTED TARGET CONTENT** markers
carrying a standing ignore-directives line; marker-shaped text inside the
content is neutralized so a page cannot forge or close a frame
(prompt-injection defense, advisory by design — same honesty as ARTEX).
`CONSTELLATION_UNTRUSTED_FRAMING=0` opts out.

## Origin

Started as a clone of microsoft/playwright-mcp (Apache-2.0, see `LICENSE` and
git history). The upstream MCP implementation lives inside the Playwright
monorepo and is not forked here — Constellation is a clean implementation on
Playwright's public API (`playwright-core`). Agent names, the lease model, the
scope guard, and the engagement tooling are original to this project.
