# jumpserver-mcp

JumpServer (KoKo) bastion connector for WorkBuddy as an MCP stdio server. Ported from `dsh-jumpserver` (v0.3.1) core. From v0.4.0 it is no longer just "AI safely executes JumpServer commands" — it is an **AI infrastructure investigation / fault-analysis platform**: fixed read-only probes, structured host inventory, evidence-annotated topology, streaming job model, and an embedded ops console (8 tabs). v0.4.1 adds the fleet layer: bounded-concurrency surveys, config-driven runbooks, multi-host diffing, baseline drift detection, an assets tab, and console access tokens. v0.4.2 adds assertions (runbooks return a verdict), scope checks at session entry, and console-token expiry + rotation. **v0.4.3 is a correctness/security release**: profile-step assertions aggregate instead of false-failing, `jumpserver_job_start` runs through the shared permission gate, `commandStatus` separates "exchange completed" from "command succeeded", the console token is no longer written to disk, `maxSessions` is actually enforced, and target scope matches exactly unless it declares otherwise. v0.4.4 makes the job stop path correct (one Ctrl+C, PTY held through recovery, `maxDuration` via `stop()`) and adds deferred approval for job start. **v0.4.5 is the job-lifecycle / isolation release**: one interrupt entry point (no more double Ctrl+C), concurrent-safe and idempotent `stop()`, PTY ownership bound to the session lifecycle (no ghost `SESSION_BUSY` after a reconnect), a real cursor for `jumpserver_job_read`, per-conversation job isolation, a corrected `sessionScope`, and one shared `commandStatus` → error mapping. **v0.5.0 is the distribution / configuration release**: the connection four-tuple (host / port / username / password) can come from the WorkBuddy connector form as environment variables (`ENV > config.json > default`), `config.json` became OPTIONAL and now carries policy only, the SSH handshake verifies the bastion's host key (TOFU + optional pinned fingerprint), the console gained a 设置 tab showing where every value came from, CI covers Windows × Node 20/22, and the command-classifier corpus was extended to the operator's real command surface. **v0.5.1 is the console-stability / distribution-tooling release**: the console address is fixed at `http://127.0.0.1:8765/` with the access token injected into the page rather than the URL, so it is short, bookmarkable and identical in every process — a second MCP process now *adopts* that address instead of falling back to a random port whose URL died with it, an already-open tab self-heals after a restart, the handover hint repeats until the page has actually been fetched once, and the listener is released exactly once on shutdown. It also adds the connector package toolchain (`validate:connector` incl. a de-identification scan, `pack:connector`) and a local-market verification path so the install-by-form flow can be exercised before submitting for review.

## Tools (23)

| Tool | Purpose |
|---|---|
| `jumpserver_status` | Session state / gateway / current target / permission mode / runtime version / conversation scope; live console URL + token expiry. Strictly read-only |
| `jumpserver_console_rotate_token` | Invalidate the console access token. In stable mode (default) the address is unchanged — the open page picks up a fresh token on its next reload; set `auditViewer.stableUrl: false` to get the old "new URL, old link dies" behaviour. Side-effecting, so it is its own tool |
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
- **SSH host-key verification (V0.5.0)**: the handshake no longer trusts whoever answers. With `hostFingerprint` set, only a byte-identical host key is accepted; without it the first contact is recorded in `data/known_hosts.json` (TOFU) and every later contact must match. A contradiction is refused as `HOST_KEY_MISMATCH` carrying both fingerprints — never auto-re-trusted. The old `algorithms.serverHostKey` override (RSA variants only) is gone, so an ed25519 / ecdsa host key negotiates again.
- **Connection provenance (V0.5.0)**: every resolved connection value carries the layer it came from (`env` / `config` / `default`), reported in the console's 设置 tab and in the startup log — "which config am I actually running with" is answerable without opening a file.
- **Console access token (V0.4.1)**: the embedded console binds to 127.0.0.1 but every request must present a per-process random token (`/?token=…` or the `X-Console-Token` header) — otherwise 403. The token is handed over only in the model's console URL.
- **Token expiry + rotation (V0.4.2)**: the console token now expires (default 12h; `auditViewer.tokenTtlMinutes`, 0 = never). A stale token gets 403 plus an `x-console-token-expired: 1` marker, so the page shows a "token expired — ask the model to reopen the console" overlay instead of retrying forever. `jumpserver_status` returns the live `consoleUrl` + expiry, and `jumpserver_console_rotate_token` mints a new token on demand (the old link dies immediately).

## Configuration

V0.5.0 splits configuration into two layers.

**Connection — owned by the WorkBuddy connector form.** Installing the connector pops a form (address / port / username / password); the values are stored on this machine and injected into the stdio process as environment variables, so there is nothing to hand-edit. Resolution order:

```text
ENV  >  config.json  >  built-in default
```

| Env var | Default | Description |
|---|---|---|
| `JUMPSERVER_HOST` | — | Bastion gateway host (falls back to `config.json` `host`) |
| `JUMPSERVER_PORT` | `2222` | Bastion SSH port |
| `JUMPSERVER_USERNAME` | — | Bastion login (falls back to `config.json` `username`) |
| `JUMPSERVER_PASSWORD` | — | Password, resolved per connect; never written to `config.json` |
| `JUMPSERVER_MCP_CONFIG` | `<root>/config.json` | Config file path |
| `JUMPSERVER_MCP_SESSION` | — | Pin one session scope per process |

**Policy — still in `config.json`.** Permission mode, target scope, concurrency, asset groups, runbooks and console settings live here. `config.json` is now OPTIONAL: when the connector form supplies the connection, the file may be absent and every policy field falls back to its default. Copy `config.example.json` to `config.json` only when you need those fields.

| Field | Default | Description |
|---|---|---|
| `host` / `port` / `username` | see ENV | Bastion SSH gateway (overridden by ENV) |
| `hostFingerprint` | — | Pinned SSH host key, e.g. `SHA256:AbCdEf…`. When set, only a byte-identical key is accepted; otherwise the first contact is recorded and checked afterwards (TOFU) |
| `knownHostsPath` | `<root>/data/known_hosts.json` | TOFU store used when no fingerprint is pinned |
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

Two paths. They differ in who has to edit a file.

**Connector package — for other people.** Install from `connector/`. `connector/token-schema.json` declares the four connection fields, so a user fills a form once and never touches a config file. `connector/mcp.json` pins no machine paths — it declares a Node runtime and runs the published package:

```json
{
  "mcpServers": {
    "jumpserver": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "jumpserver-mcp"],
      "runtime": { "type": "node", "version": "20" },
      "env": {
        "JUMPSERVER_HOST": "${JUMPSERVER_HOST}",
        "JUMPSERVER_PORT": "${JUMPSERVER_PORT}",
        "JUMPSERVER_USERNAME": "${JUMPSERVER_USERNAME}",
        "JUMPSERVER_PASSWORD": "${JUMPSERVER_PASSWORD}"
      }
    }
  }
}
```

Two prerequisites must be met before this path works on anyone else's machine:

- **The package has to be on npm.** `mcp.json` launches `npx -y jumpserver-mcp`; until `npm publish` has run, that name resolves to nothing and the server dies at startup. Confirm with `npm view jumpserver-mcp version`.
- **The connector has to pass review.** WorkBuddy provides no local install entry for `auth_mode: "token"` connectors — zip `connector/` and submit it to the WorkBuddy team; it shows up in the connector market once approved. `npm run validate:connector` checks the package against the submission rules (required manifest fields, `${VAR}` placeholders that must match a form field key exactly, `minWorkbuddyVersion` high enough for the features used, no hardcoded credentials, no machine-specific paths or internal addresses) and exits non-zero on any failure. To exercise the install-by-form flow on your own machine before review, see [Verifying the connector locally](#verifying-the-connector-locally).

**Local checkout — while developing.** Point `command` / `args` at `node <repo>/lib/server.js` and put the connection values directly in `env`. Works immediately, but never ship this form: an absolute path only works on the machine it was written on.

## Embedded ops console

Once the MCP process starts it serves a local ops page at a **stable address** — `http://127.0.0.1:8765/` by default (V0.5.1). `/api/*` still requires the per-process access token, but the server injects it into the page instead of the URL, so the address is short, bookmarkable and byte-identical in every process. Consequences:

- **No ephemeral fallback.** If another MCP process already holds the port, this one *adopts* the same address (instead of inventing a random port whose URL dies with it) and takes the listener over the moment the owner exits.
- **The page self-heals.** A restarted process re-binds the same address and an already-open tab resumes polling by itself; the 工作台已失效 overlay clears on the first successful poll.
- **Token expiry is transparent.** A 403 marked expired makes the page reload once to pick up a freshly injected token.
- **Cross-origin requests are refused**, so a web page in the local browser cannot read the audit trail or drive `/api/interrupt`.

The model receives the URL in a tool response and must open it with `present_files` (WorkBuddy's built-in preview panel) — **do not** use the system browser. The hint repeats on every response until the page has actually been fetched once, because a single first-response handover got parked until the end of the task in practice.

Set `auditViewer.stableUrl: false` to restore the v0.5.0 form: `127.0.0.1:<random>/?token=…`, one console per conversation, invalidated when the conversation ends.

Tabs:

- **Live terminal** — real-time PTY mirror, input echo, state-transition markers; "Interrupt current command (Ctrl+C)" / Clear / Auto-scroll.
- **Assets** — last `jumpserver_assets` listing with search, group/platform/status filters, and name/IP/platform/node/role/status columns; roles come from the last topology, status from the last 30 minutes of audit activity. Also lists saved baselines.
- **Topology** — last `jumpserver_topology` result: node cards + edge list (with confidence + evidence) + per-node detail (roles, OS, ports, IPs, in/out edges, memory, load).
- **Jobs** — streaming jobs (`jsjob_xxxx`) of this conversation: progress bar, Stop button, output tail.
- **Audit log** — `AuditStore` memory ring (5000) in the configured timezone; supports `callId` / `batchId`; JSONL / CSV export.
- **Stats** — risk / target / operation / 14-day activity bars.
- **Sessions** — active sessions + Interrupt / Disconnect buttons.
- **Settings** (V0.5.0) — the live connection and where every value came from (WorkBuddy environment / `config.json` / default), the policy knobs that only `config.json` can set, and the recorded `known_hosts` entries. The password appears as "configured / not configured" — its value is never rendered.

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

Connector package toolchain (V0.5.1):

```bash
npm run validate:connector   # submission rules + de-identification scan; non-zero on failure
npm run pack:connector       # validate, then build .workbuddy/artifacts/jumpserver-connector-v<version>.zip
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
- `config/config-env.test.mjs` — `ENV > config.json > default` resolution, per-value provenance, `config.json` optional, blank ENV never overriding a real value.
- `jumpserver/host-key.test.mjs` — pinned fingerprint accepted / rejected, TOFU first-contact record, a contradiction surfaces as `HOST_KEY_MISMATCH` instead of re-trusting.
- `runtime/console-stable-url.test.mjs` — the console address is byte-identical across processes, a second process adopts the port instead of falling back, the page self-heals after a restart, `/api/*` stays token-gated, cross-origin refused.
- `runtime/console-exit-listener.test.mjs` — the console listener is released exactly once and survives a restart (a leaked `exit` listener used to keep the port bound).
- `security/command-classifier-corpus/*.test.mjs` — a wider classifier corpus (SAP / databases, containers / services, filesystem / process / storage, network / dangerous) guarding the READ / MODIFY / DANGEROUS boundary.

CI: `.github/workflows/ci.yml` — typecheck → build → `validate:connector` → smoke → test, on **Ubuntu and Windows** × Node 20/22.

## Verifying the connector locally

A `auth_mode: "token"` connector has no local install button — it reaches the market only after review. To exercise the form-and-install path on your own machine first, point WorkBuddy's connector market at a locally served zip:

```bash
npm run market:build     # inject connector/ into a copy of the official market index
npm run market:serve     # serve it on 127.0.0.1
npm run market:enable    # write ~/.workbuddy/connectors/connector-marketplace.json
# restart WorkBuddy, then install "JumpServer" from the connector list
npm run market:status    # what is currently overridden
npm run market:disable   # restore the official market (also removes the override file)
```

`market:enable` backs up whatever it overwrites and `market:disable` restores it. Do not put files directly into `~/.workbuddy/connectors/connectors-marketplace/` — the client rebuilds that directory on every sync (every 10 minutes) and will delete them.
