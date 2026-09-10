# jumpserver-mcp

JumpServer (KoKo) bastion connector for WorkBuddy as an MCP stdio server. Ported from `dsh-jumpserver` (v0.3.1) core. From v0.4.0 it is no longer just "AI safely executes JumpServer commands" — it is an **AI infrastructure investigation / fault-analysis platform**: fixed read-only probes, structured host inventory, evidence-annotated topology, streaming job model, and an embedded ops console (7 tabs). v0.4.1 adds the fleet layer: bounded-concurrency surveys, config-driven runbooks, multi-host diffing, baseline drift detection, an assets tab, and console access tokens. v0.4.2 adds assertions (runbooks return a verdict), scope checks at session entry, and console-token expiry + rotation. **v0.4.3 is a correctness/security release**: profile-step assertions aggregate instead of false-failing, `jumpserver_job_start` runs through the shared permission gate, `commandStatus` separates "exchange completed" from "command succeeded", the console token is no longer written to disk, `maxSessions` is actually enforced, and target scope matches exactly unless it declares otherwise. v0.4.4 makes the job stop path correct (one Ctrl+C, PTY held through recovery, `maxDuration` via `stop()`) and adds deferred approval for job start. **v0.4.5 is the job-lifecycle / isolation release**: one interrupt entry point (no more double Ctrl+C), concurrent-safe and idempotent `stop()`, PTY ownership bound to the session lifecycle (no ghost `SESSION_BUSY` after a reconnect), a real cursor for `jumpserver_job_read`, per-conversation job isolation, a corrected `sessionScope`, and one shared `commandStatus` → error mapping.

## Tools (23)

| Tool | Purpose |
|---|---|
| `jumpserver_status` | Session state / gateway / current target / permission mode / runtime version / conversation scope; live console URL + token expiry. Strictly read-only |
| `jumpserver_console_rotate_token` | Invalidate the console access token and mint a new URL (the old link dies immediately). Side-effecting, so it is its own tool |
| `jumpserver_connect` | Establish the persistent SSH/PTY session, wait for the KoKo menu |
| `jumpserver_enter` | Enter an asset through the KoKo menu (verified by probe) |
| `jumpserver_assets` | List authorized assets (`p` only — read-only, footer-verified, cached) |
| `jumpserver_exec` | Execute one simple command on the currently-entered asset |
| `jumpserver_run` | Auto-navigate + verify + execute (one target, one command) |
| `jumpserver_batch` | Multi-target multi-command batch (target affinity) |
| `jumpserver_leave` | Leave the current asset, return to the KoKo menu |
| `jumpserver_close` | Close the session, release resources |
| `jumpserver_snapshot` | Terminal mirror: read the recent PTY event stream |
| `jumpserver_audit` | Read recent audit entries (in-chat; time displayed in the configured zone) |
| `jumpserver_inspect` | Fixed read-only profile probes -> structured HostInventory |
| `jumpserver_topology` | Build an evidence-annotated relationship graph between hosts |
| `jumpserver_profile_run` | Run a NAMED runbook (config `runbooks`) across targets — same steps, every host; `expect` assertions yield PASS/FAIL |
| `jumpserver_compare` | Run one command/profile on N hosts and report the DIFF (groups + outliers) |
| `jumpserver_baseline_capture` | Snapshot a named baseline to `data/baselines/<name>.json` |
| `jumpserver_baseline_compare` | Re-inspect and report DRIFT vs a saved baseline |
| `jumpserver_interrupt` | Ctrl+C the remote shell NOW, re-verify, out-of-band (does not wait for the running op) |
| `jumpserver_job_start` | Start a streaming job (`tail -f` / `journalctl -f` / `tcpdump`) |
| `jumpserver_job_read` | Cursor read of a job: what arrived since the last read + `nextSeq` to resume (or `full:true`) |
| `jumpserver_job_stop` | Ctrl+C the job, release the shell |
| `jumpserver_jobs` | List this conversation's jobs |

When `requireArm: true`, `jumpserver_arm` / `jumpserver_disarm` (30-minute authorization window) are also registered.

## Architecture highlights

- **Explicit state machine** (V0.1): illegal transitions always collapse to `UNKNOWN`; never guess.
- **Command classifier** (V0.3.1, 5 risks: READ / PRIVILEGED_READ / UNKNOWN / MODIFY / DANGEROUS); DANGEROUS always requires human approval, even in `FULL_ACCESS`.
- **Abort fix (V0.4.0 P0)**: MCP cancellation / `jumpserver_interrupt` / the console's "Interrupt current command" button all send Ctrl+C to the remote shell and re-run the probe — the connector never declares the asset usable while a foreground job is still running.
- **Structured inspection (V0.4.0 P0)**: `jumpserver_inspect` runs fixed read-only profiles (`basic / network / process / service / web / java / database / container / full`). A probe that regresses to a non-READ rule is skipped, not silently downgraded. `jumpserver_topology` builds a graph with per-edge `confidence` (HIGH/MEDIUM/LOW) and `evidence` (nginx upstream / `ESTABLISHED …` / `/etc/hosts` / same upstream cluster).
- **Streaming jobs (V0.4.0)**: `jumpserver_job_*` covers `tail -f` / `journalctl -f` / `tcpdump` style commands that never end on their own. Output is harvested from the `TerminalObserver` stream, `maxDuration` enforces an upper bound.
- **Job lifecycle & isolation (V0.4.5)**: one PTY owner, always. `jumpserver_interrupt` and the console's 中断 button go through a single entry point, so a streaming job is interrupted by exactly ONE Ctrl+C (V0.4.4 sent `manager.interrupt()` and then `jobs.stop()` = two). `JobStore.stop()` is idempotent and concurrent-safe: a `maxDuration` stop racing a manual `jumpserver_job_stop` shares one probe and one verdict, so a failed verify can no longer be masked as STOPPED. PTY ownership is bound to the session lifecycle — `close()`, transport loss and a reconnect all release it, so a reconnected conversation is not permanently `SESSION_BUSY`; a job whose shell is gone is reported `LOST` even when the reconnect completed within one pump interval. Jobs are scoped to their conversation (list / read / stop / the RUNNING cap), so a multiplexing host cannot let one conversation read or stop another's job. `jumpserver_job_read` is a real cursor read (`nextSeq` → `sinceSeq`), not a tail of the buffer.
- **Incremental audit (V0.4.0)**: async append + bounded memory ring (5000) + file-offset incremental tail. The console no longer `readFileSync`s the whole JSONL every second.
- **Audit timezone (V0.4.0)**: JSONL stays UTC; display uses `timeZone` (default `Asia/Shanghai`).
- **Target scope (V0.4.0)**: `allowedTargets` / `deniedTargets`; deny always wins; every navigation and every `exec` against an already-entered asset is checked. From V0.4.2 the check runs at the ENTRY of `jumpserver_connect` / `jumpserver_enter` too, so a denied target never gets an SSH/PTY session opened at all. From V0.4.3 entries declare their intent — exact (`192.168.79.10`), prefix (trailing `.`/`-`/`:`), glob (`oa-*`) or CIDR (`192.168.79.0/24`); a bare entry is EXACT, so `192.168.79.10` no longer also matches `192.168.79.100`.
- **Version single source (V0.4.0)**: `package.json` is the only truth; runtime `PLUGIN_VERSION` reads from there. `npm version` and the runtime can no longer drift.
- **Bounded-concurrency surveys (V0.4.1)**: `batchConcurrency` (default 1 = strictly sequential) lets inspect / topology / compare / profile_run visit several targets at once. Result order always matches input order; one target's failure never aborts its siblings. **One conversation still owns ONE bastion PTY** — raising `batchConcurrency` interleaves target turns on that single session, it does not open N sessions. A process-wide `Semaphore` (`maxSessions`, default 4) caps how many targets are entered simultaneously, which only binds when `batchConcurrency > 1`.
- **Runbooks (V0.4.1)**: `jumpserver_profile_run` executes a named, reviewed recipe from config `runbooks`. Each step is an inspect profile or an explicit READ command; a non-READ step (or a typo'd profile) is SKIPPED and reported — never silently executed.
- **Runbook assertions (V0.4.2)**: a step may carry `expect` (`contains` / `notContains` / `matches` / `exitCode` / `notEmpty` / `minLines` / `message`, all AND). The runbook then reports PASS/FAIL per step, per target, and overall — turning a survey into a verdict. An unreachable target auto-fails any assertion it carried. **V0.4.3 fixes how a profile step is judged**: a `profile` step is ONE logical step reported once (its per-probe detail stays in `commands[]` / `probes[]`), and its `expect` is evaluated against the AGGREGATE of every probe — so `expect: { contains: "LISTEN" }` no longer FAILs a healthy host just because only the `ss -lntp` probe prints it. To assert one specific probe use `expect: { probe: "listen", contains: "LISTEN" }`; a probe name that does not exist is a config error and skips the step.
- **Command outcome (V0.4.3)**: `executionState` says whether the transport exchange completed; `commandStatus` says what happened to the COMMAND — `SUCCESS` / `EXIT_NONZERO` / `TIMEOUT` / `INTERRUPTED` / `CONNECTION_LOST` / `UNKNOWN`. A completed exchange with a non-zero exit is **`ok: false`**, and the audit/console report it as a failure (`jps -lv` exiting 127 reads `READ / EXIT_NONZERO`, never `READ / COMPLETED`). **V0.4.5** decodes it through ONE shared mapping, so `TIMEOUT` / `CONNECTION_LOST` / `UNKNOWN` keep their own error code in exec, batch AND compare (V0.4.4 reported every compare failure as `COMMAND_EXIT_NONZERO`).
- **Conversation scope (V0.4.3)**: the scope id is resolved as transport `sessionId` → `JUMPSERVER_MCP_SESSION` → process isolation. WorkBuddy's stdio model spawns one server per conversation, so process isolation IS the boundary; `jumpserver_status` reports which mode is active. A host that multiplexes conversations over one process MUST supply a sessionId, otherwise they share one bastion session — the startup log says so explicitly rather than pretending otherwise. **V0.4.5** reports the scope the CALLER is actually on: `transport` only when the transport itself supplied a sessionId, otherwise the runtime mode (`env` / `process`) — V0.4.4 asked whether the resolved scope ID was non-empty, which is always true, so a plain stdio conversation claimed `transport`.
- **Multi-host diff (V0.4.1)**: `jumpserver_compare` runs the SAME read-only command/profile on every target and groups them by signature, reporting each outlier's missing/extra lines versus the majority. Order-insensitive, so `ss`/`ps` line ordering does not create false diffs.
- **Baseline drift (V0.4.1)**: `jumpserver_baseline_capture` persists a compact state snapshot to `data/baselines/<name>.json`; `jumpserver_baseline_compare` re-inspects and reports real drift (ports, disks, services, roles, kernel, cores; load/memory jitter is suppressed). An unreachable host is reported as unreachable, never as "unchanged".
- **Console access token (V0.4.1)**: the embedded console binds to 127.0.0.1 but every request must present a per-process random token (`/?token=…` or the `X-Console-Token` header) — otherwise 403. The token is handed over only in the model's console URL.
- **Token expiry + rotation (V0.4.2)**: the console token now expires (default 12h; `auditViewer.tokenTtlMinutes`, 0 = never). A stale token gets 403 plus an `x-console-token-expired: 1` marker, so the page shows a "token expired — ask the model to reopen the console" overlay instead of retrying forever. `jumpserver_status` returns the live `consoleUrl` + expiry, and `jumpserver_console_rotate_token` mints a new token on demand (the old link dies immediately).

## Configuration

Copy `config.example.json` to `config.json`, fill `host` / `username`. The password must come from an environment variable (`passwordEnv`, default `JUMPSERVER_PASSWORD`) — never put it in `config.json`.

| Field | Default | Description |
|---|---|---|
| `host` / `port` / `username` | required | Bastion SSH gateway |
| `passwordEnv` | `JUMPSERVER_PASSWORD` | Env-var name holding the password |
| `permissionMode` | `READ_ONLY` | `READ_ONLY` / `AUTO` / `FULL_ACCESS` |
| `timeZone` | `Asia/Shanghai` | Display zone for audit timestamps (storage is still UTC) |
| `allowedTargets` | `[]` | Allow-list; each entry is exact (`192.168.79.10`), prefix (trailing `.` / `-` / `:`), glob (`oa-*`) or CIDR (`192.168.79.0/24`) — see target scope |
| `deniedTargets` | `[]` | Deny-list (checked first, always wins); same exact / prefix / glob / CIDR syntax |
| `batchConcurrency` | `1` | Targets interleaved per batch/inspect/compare call (1..8; 1 = sequential). One conversation = one PTY; this does not multiply sessions |
| `maxSessions` | `4` | Cap on targets entered simultaneously (1..16); only binds when `batchConcurrency > 1` |
| `assetGroups` | `{}` | Named group -> keywords, used by `jumpserver_assets` |
| `runbooks` | `{}` | Named runbook -> `{ title, steps[] }`; each step is a `profile` or a READ `command`, optionally with `expect` assertions |
| `auditPath` | `<root>/data/audit.jsonl` | JSONL audit sink |
| `auditViewer.{enabled,port,autoOpen,portFallback}` | `true/8765/true/true` | Embedded console |
| `auditViewer.tokenTtlMinutes` | `720` | Console access-token lifetime in minutes (0 = never expires) |
| `requireArm` | `false` | Require `jumpserver_arm` before any tool runs |

## Register with WorkBuddy

```json
{
  "mcpServers": {
    "jumpserver": {
      "type": "stdio",
      "command": "node",
      "args": ["C:/path/to/jumpserver-mcp/lib/server.js"],
      "env": { "JUMPSERVER_PASSWORD": "..." },
      "description": "JumpServer MCP v0.4.5: fixed probes, host inventory, evidence topology, streaming jobs, runbooks+assertions, compare, baselines"
    }
  }
}
```

## Embedded ops console

Once the MCP process starts it serves a local page on `127.0.0.1:<port>/?token=<random>` (default 8765; if taken it auto-falls back to an ephemeral port so every conversation gets its own console). Every request must carry the token, so a stray local process cannot read the audit trail or drive the interrupt API. The model receives the tokenized URL in the first tool response and must open it with `present_files` (WorkBuddy's built-in preview panel) — **do not** use the system browser. Each conversation has its own port; closing the conversation invalidates the page.

Tabs:

- **Live terminal** — real-time PTY mirror, input echo, state-transition markers; "Interrupt current command (Ctrl+C)" / Clear / Auto-scroll.
- **Assets** — last `jumpserver_assets` listing with search, group/platform/status filters, and name/IP/platform/node/role/status columns; roles come from the last topology, status from the last 30 minutes of audit activity. Also lists saved baselines.
- **Topology** — last `jumpserver_topology` result: node cards + edge list (with confidence + evidence) + per-node detail (roles, OS, ports, IPs, in/out edges, memory, load).
- **Jobs** — streaming jobs (`jsjob_xxxx`) of this conversation: progress bar, Stop button, output tail.
- **Audit log** — `AuditStore` memory ring (5000) in the configured timezone; supports `callId` / `batchId`; JSONL / CSV export.
- **Stats** — risk / target / operation / 14-day activity bars.
- **Sessions** — active sessions + Interrupt / Disconnect buttons.

## Approval flow

`READ_ONLY` auto-runs reads. `MODIFY` / `DANGEROUS` / `UNKNOWN` return `COMMAND_APPROVAL_REQUIRED` with a redacted reason on the first attempt; the model shows it to the user and retries the same call with `confirm: true` only after explicit agreement. `requireArm: true` adds the 30-minute `jumpserver_arm` / `jumpserver_disarm` window on top.

`allowedTargets` / `deniedTargets` are an independent gate: even with a human-approved READ, a target outside the allow-list still gets `TARGET_DENIED`.

## Development

```bash
npm install
npm run typecheck   # tsc --noEmit
npm run build       # tsc -p tsconfig.json
npm test            # builds + runs tests/**/*.test.mjs (node:test)
npm run smoke       # MCP stdio JSON-RPC smoke
```

Test coverage (`tests/`):

- `security/command-classifier.test.mjs` — the classifier matrix (incl. every fixed case from the review).
- `security/permission-gate.test.mjs` — 3 modes x 5 risks + target allow/deny.
- `security/target-scope.test.mjs` — deny beats allow, exact / prefix / glob / CIDR matching, blank targets never gated.
- `security/job-start-gate.test.mjs` — the streaming-job tool shares the permission gate: READ_ONLY cannot be bypassed with confirm, AUTO asks, FULL_ACCESS still gates DANGEROUS, an unverified target is refused.
- `jumpserver/state-machine.test.mjs` — legal/illegal transitions.
- `jumpserver/session-abort.test.mjs` — AbortSignal and out-of-band interrupt() must Ctrl+C + re-verify.
- `jumpserver/asset-list.test.mjs` — `p` parse / footer / filter / groups.
- `jumpserver/host-parse.test.mjs` — every parser.
- `jumpserver/topology.test.mjs` — edge construction and evidence.
- `inspect/profile-safety.test.mjs` — every profile command is still READ.
- `jumpserver/concurrency.test.mjs` — bounded concurrency order/limit, abort, `Semaphore`.
- `jumpserver/session-gate.test.mjs` — the `maxSessions` gate really caps concurrent holders.
- `jumpserver/runbook.test.mjs` — non-READ / unknown-profile steps are skipped; `evaluateExpect` PASS/FAIL matrix; `runRunbook` integration (profile step reported ONCE, aggregated assertion, `expect.probe`).
- `jumpserver/compare.test.mjs` — order-insensitive grouping, count-aware (multiset) outliers, failed hosts excluded.
- `runtime/baseline.test.mjs` — baseline save/load, name safety, drift diff, jitter suppression.
- `runtime/console-token.test.mjs` — 403 without token, 200 with token / header, TTL expiry marker, rotation, and the discovery file never leaking the token.
- `runtime/command-status.test.mjs` — exit 0 vs exit 127 (`jps -lv` must not be ok=true), timeout, connection lost.
- `runtime/conversation-lifecycle.test.mjs` — two conversations never share a bundle/grant; transport sessionId wins; a shared process is reported honestly.
- `runtime/job-lifecycle-v045.test.mjs` — one Ctrl+C per interrupt (job vs bare shell), concurrent `stop()` shares one verdict, PTY ownership released on close / transport loss / reconnect, per-conversation job isolation + cap, cursor `job_read` (`nextSeq` / `sinceSeq` / `droppedChars`).
- `runtime/session-scope.test.mjs` — `jumpserver_status.sessionScope` projection: a stdio conversation (or the `ANONYMOUS_SESSION` / env fallback) must never report `transport`.
- `runtime/job-stop-correctness.test.mjs` — one Ctrl+C, PTY held through recovery, `maxDuration` through `stop()`.
- `runtime/compare-command-status.test.mjs` — a failed probe is excluded from the diff and keeps its own error code.
- `runtime/terminal-markers.test.mjs` — connector-internal markers are hidden from the live terminal view.
- `runtime/audit-store.test.mjs` — async append, ring cap, incremental tail.
- `runtime/time.test.mjs` — timezone formatting.

CI: `.github/workflows/ci.yml` (typecheck -> build -> smoke -> test on Node 22).
