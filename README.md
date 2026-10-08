# jumpserver-mcp

JumpServer (KoKo) bastion connector for WorkBuddy as an MCP stdio server. Ported from `dsh-jumpserver` (v0.3.1) core. From v0.4.0 it is no longer just "AI safely executes JumpServer commands" — it is an **AI infrastructure investigation / fault-analysis platform**: fixed read-only probes, structured host inventory, evidence-annotated topology, streaming job model, and an embedded ops console (8 tabs). v0.4.1 adds the fleet layer: bounded-concurrency surveys, config-driven runbooks, multi-host diffing, baseline drift detection, an assets tab, and console access tokens. v0.4.2 adds assertions (runbooks return a verdict), scope checks at session entry, and console-token expiry + rotation. **v0.4.3 is a correctness/security release**: profile-step assertions aggregate instead of false-failing, `jumpserver_job_start` runs through the shared permission gate, `commandStatus` separates "exchange completed" from "command succeeded", the console token is no longer written to disk, `maxSessions` is actually enforced, and target scope matches exactly unless it declares otherwise. v0.4.4 makes the job stop path correct (one Ctrl+C, PTY held through recovery, `maxDuration` via `stop()`) and adds deferred approval for job start. **v0.4.5 is the job-lifecycle / isolation release**: one interrupt entry point (no more double Ctrl+C), concurrent-safe and idempotent `stop()`, PTY ownership bound to the session lifecycle (no ghost `SESSION_BUSY` after a reconnect), a real cursor for `jumpserver_job_read`, per-conversation job isolation, a corrected `sessionScope`, and one shared `commandStatus` → error mapping. **v0.5.0 is the distribution / configuration release**: the connection four-tuple (host / port / username / password) can come from the WorkBuddy connector form as environment variables (`ENV > config.json > default`), `config.json` became OPTIONAL and now carries policy only, the SSH handshake verifies the bastion's host key (TOFU + optional pinned fingerprint), the console gained a 设置 tab showing where every value came from, CI covers Windows × Node 20/22, and the command-classifier corpus was extended to the operator's real command surface. **v0.5.1 is the console-stability / distribution-tooling release**: the console address is fixed at `http://127.0.0.1:8765/` with the access token injected into the page rather than the URL, so it is short, bookmarkable and identical in every process — a second MCP process now *adopts* that address instead of falling back to a random port whose URL died with it, an already-open tab self-heals after a restart, the handover hint repeats until the page has actually been fetched once, and the listener is released exactly once on shutdown. It also adds the connector package toolchain (`validate:connector` incl. a de-identification scan, `pack:connector`) and a local-market verification path so the install-by-form flow can be exercised before submitting for review.

**v0.5.2 is the honesty / diagnosability release.** Every tool now declares real MCP `annotations` (a write tool can no longer advertise `readOnlyHint`), an incomplete connection no longer kills the process before the handshake — it is reported as `CONFIG_INCOMPLETE` by the tools that actually need the bastion, while `jumpserver_status` stays answerable and says WHAT is missing, a new `--doctor` self-check answers "why is this not working" without starting the server, per-target progress notifications reach the host during long multi-host surveys, the ops console stops polling a hidden/backgrounded page, and the command classifier recognises SAP HANA `hdbsql` read-only queries. **v0.5.3 teaches the connector KoKo's multi-username `ID>` selection screen**: assets with more than one authorised bastion user no longer fail with `ASSET_ENTER_TIMEOUT` — pass `accountIndex` to `jumpserver_enter` / `jumpserver_run` / `jumpserver_batch` (per task) / `jumpserver_job_start`, or `accountByTarget: { "<ip>": <index> }` to `jumpserver_inspect` / `jumpserver_topology` / `jumpserver_compare` / `jumpserver_baseline_*` / `jumpserver_profile_run`. Omit and the connector fails with `ACCOUNT_SELECTION_REQUIRED` carrying the parsed `accounts=0:admin | 1:ops | 2:deploy` list in `detail` — fail-closed, never auto-picks. **v0.5.4 makes the ops console multi-instance aware**: the stable address is shared by every MCP process of a workspace, so a process that loses the port race used to serve nothing — two WorkBuddy conversations showed one terminal and the 中断 button hit the wrong process. Now the loser binds its own private loopback port and publishes `{ role, port, summary }` in its discovery file, the page's instance picker lists every live console and embeds the selected one (each embedded page injects its own token, so no shared secret is introduced), and the handover URL carries `?inst=<pid>` so a conversation opens **its own** sessions. The error `detail` field is also rendered now — a swallowed `detail` had hidden every `ASSET_ENTER_TIMEOUT` / `ACCOUNT_SELECTION_REQUIRED` diagnosis from the model.

**v0.5.5 is the stop-don't-spin release.** An asset the bastion cannot dial used to cost far more than the failure itself. KoKo answers a dead dial with `开始连接到 root(root)@10.0.0.10 error: 网络不通（连接超时）` and re-paints its own prompt one line below; the connector read that as a generic failure, reported `detail: error` (the regex token, not the banner), and collapsed the session to `UNKNOWN`. The model could not tell a dead network from a wrong `accountIndex`, and every retry needed a full reconnect — measured on a real conversation: **8 enter/connect cycles, 2m53s, 8.32 tokens**, for one unreachable asset. Now: the network banner is classified `ASSET_UNREACHABLE` with the **whole banner line** in `detail` plus a `retryAfterMs` cooldown, the session stays at the (real) KoKo menu so no reconnect is needed, a repeat enter on that target is **refused before a single byte reaches the PTY**, the result carries an explicit `next: STOP` line, and the failure detection is scoped to the current attempt so a stale banner is never re-matched against a healthy new one. Fixable failures (`ACCOUNT_SELECTION_REQUIRED`, a non-network `ASSET_ENTER_TIMEOUT`) stay retryable and get no STOP line.

**v0.5.6 closes the loop V0.5.3 opened: raising the account prompt worked, answering it did not.** `enter()` collapsed the session to `UNKNOWN` on `ACCOUNT_SELECTION_REQUIRED`, so the very next call — the one carrying the `accountIndex` the connector had just asked for — was refused with `CONNECTION_LOST`: a live PTY reported as a lost connection, and no way forward except reconnecting before it could type one character. Measured on a real conversation (console pid 36612, one asset, 3m56s): `enter` → `ACCOUNT_SELECTION_REQUIRED` → `enter(accountIndex=1)` → `CONNECTION_LOST` → `connect` → `enter` → and only *then* the asset's actual failure (the SSH reconnect and a second KoKo dial, ~40 s, spent on a session that was never dead). Now the session **stays live at the prompt** (state `ENTERING_ASSET`, so the console shows no misleading `→ UNKNOWN` marker), the follow-up call answers it in place — same transport, one target line, exactly the displayed ID, **no reconnect** — `jumpserver_run` / `jumpserver_batch` / `jumpserver_job_start` resume through the same path, and `canResumeAccountSelection()` fails closed: prompt gone → `ACCOUNT_SELECTION_EXPIRED`, transport dead → the normal reconnect. The ops console also now lands on **实时终端** (`#terminal`) instead of 审计日志 — the page exists to be watched while the agent works, and the audit table is a lookup, not the reason to open it. **v0.5.8 is the identity / collection-speed release.** Two fixes, one per half of "why is this slow / why does this look wrong": (1) the console no longer calls your own conversation a stranger — the handover URL is the *shared* stable address plus `?inst=<pid>`, and with two conversations open the process that owns 8765 answers it, so the page used to label the process that *asked* for the console 「另一个实例」 and offer a 「切回本实例」 button pointing at somebody else's session. Now `?inst=` is the authority: the page hands the browser over to that instance's own listener (probed first, so a dead port keeps the wrapper), the asking conversation is 「本实例」, the process that happened to answer is 「本页服务进程」, and a vanished instance is reported instead of silently showing another conversation's console. (2) Jev can now *shorten* a collection run: `riskJudge.autoAllow` lets an unambiguously read-only verdict skip the per-host confirm cycle on commands the rule classifier cannot name — behind six thresholds, three structural vetoes (no composition, no opaque shell syntax, no interpreter/remote head), an honest "自动放行未通过：…" line when it refuses, and an `AUTO_ALLOWED` audit record when it does not. **v0.5.9 is the audit-completeness release.** (1) **Refusals are now audited.** Until now the JSONL only ever contained commands that RAN — one the rules blocked, or one nobody approved, left no record at all, so "who tried to run `rm -rf /var` and was stopped" was unanswerable. Every refusal path now writes exactly one entry: `BLOCKED` when the deterministic gate refused it (the rule's own reason in `refusalReason`), `DENIED` when approval was not granted — across `exec`, `run`, `batch` and `job`. The console renders them as 「已拦截」 / 「未批准」, deliberately distinct from the red failures, because a refusal is the policy working rather than a crash; `jumpserver_audit` returns the reason as a trailing `why=` column (absent on entries that ran, so nothing downstream has to learn a new column for the common case); and because the write is best-effort, a broken audit sink can never turn a refusal into an execution. (2) **Five verb-aware classifier rules close the KNOWN GAPs** the corpus had recorded: `sapcontrol -function Get*`, `HDB info|version|status|proc`, `lsnrctl status|services|version|show`, `showmount`, and `jstack` (plain form only — `-F` force-attaches and is `MODIFY`, `-m` stays `UNKNOWN`). Each is fail-closed: an unrecognised verb returns `UNKNOWN` instead of guessing, and the mutating forms (`HDB stop`, `sapcontrol … Stop`, `lsnrctl reload`) are never READ.

**v0.5.10 / v0.5.11 are the long-session hygiene release**, built from three field complaints. (1) *The console got slower the longer a conversation ran, and the audit log only ever grew.* The audit tab now reads through an absolute-index cursor and renders only the newest 300 rows, and `POST /api/audit/archive` rotates the JSONL atomically — the rotated file is kept, never deleted. (2) *The console showed eight tabs whether or not they were wanted.* `auditViewer.tabs` now hides the unused ones. It is a visibility switch, not a permission switch: the audit sink keeps writing, every `/api/*` keeps its access token and same-origin guard, and `settings` cannot be hidden. (3) *The connector form's single credential could not be changed after binding, and only one bastion login could exist.* The console's 设置 tab now stores and switches several accounts, AES-256-GCM encrypted under `~/.workbuddy/jumpserver-mcp/`; the selected account takes precedence over the injected credential and falls back safely when it is missing or cannot be decrypted, so an account problem can never be the reason a connection fails. Switching accounts tears down existing sessions and asset caches, because a PTY authenticated with the previous credential no longer represents the identity the operator selected.

**v0.5.12 makes every failure renderer carry its diagnostic.** A saved account whose password was wrong reached the model as `code: AUTH_FAILED` / `JumpServer authentication failed` and nothing else, so the only possible next step was to guess. The transport was not at fault — `guardValue()` attaches `JumpServerError.detail` correctly — but three hand-written projections dropped it: the assets renderer, the ops text tools, and the nested errors inside `renderBatchResult()`. The batch case had a second, quieter cause: `BatchCommandResult.error` / `TargetBatchResult.error` were *declared* `{ code, message }` while `errorDetail()` actually returned a `detail`, so the compiler blessed a shape that was incapable of carrying the diagnostic. All three now delegate to `renderResult()` (plus a shared `NestedFailure` type), which also restores the `connection: INCOMPLETE — missing …` line those tools had been dropping. `--doctor` learned the same lesson from the other end: it inspected only `config.json` and the environment, so on a machine with a healthy account selected it declared the credential *"NOT found in any layer"* and could print a host the connector was never going to dial — it now reads the account layer first (redacted `ProfileView`, never the token), and the harness pins `HOME`/`USERPROFILE` to a throwaway directory in `spawnServer()`, because a single saved account on the developer's machine was enough to turn "no configuration at all" into `connection: complete` and fail a suite whose code was correct.

**v0.5.13 makes the tab switches real.** V0.5.10 answered "can I switch these tabs off" with `auditViewer.tabs` in `config.json` and a read-only report in the 设置 tab — which is a *file the operator owns and the connector form rewrites*, not a control, and the report named the rule without saying how to use it. Reported as "I can't find where to turn this off". The 设置 tab now renders one checkbox per tab, persisted to the console's own `~/.workbuddy/jumpserver-mcp/console-prefs.json`, and a write returns the **authoritative** new list (nav, router and switches all redraw from it, so the nav that was rendered can never disagree with the router that guards it). Precedence is one rule: an explicit value in `config.json` wins, so those rows render **locked and disabled** rather than offering a click that cannot win; `settings` can never be hidden by either layer, and the store refuses such a write instead of accepting-and-ignoring it. Still a visibility switch and nothing more — no credential is written and no permission is granted, so it is not behind `allowCredentialWrite`. A corrupt preference file degrades to defaults (it is read while rendering a page) and refuses further writes (so recoverable data is not replaced).

## Tools (23)

| Tool | Purpose |
|---|---|
| `jumpserver_status` | Session state / gateway / current target / permission mode / runtime version / conversation scope; live console URL + token expiry. Strictly read-only |
| `jumpserver_console_rotate_token` | Invalidate the console access token. In stable mode (default) the address is unchanged — the open page picks up a fresh token on its next reload; set `auditViewer.stableUrl: false` to get the old "new URL, old link dies" behaviour. Side-effecting, so it is its own tool |
| `jumpserver_connect` | Establish the persistent SSH/PTY session, wait for the KoKo menu |
| `jumpserver_enter` | Enter an asset through the KoKo menu (verified by probe). Pass `accountIndex` for multi-user assets |
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
- **Advisory risk judge** (V0.5.7, opt-in, `riskJudge.enabled`): when a command lands on `UNKNOWN`, the connector can ask a TypeSafe AI *System One* model (Jev) for a typed second opinion — read-only probability, impact, a rubric score plus its distribution, and a confidence — and prints it into the approval prompt. By default it is **advisory only**: it never allows, denies or downgrades anything, `MODIFY` / `DANGEROUS` / `READ` commands are never sent anywhere, and every failure (disabled, no credential, timeout, non-2xx, malformed payload) silently falls back to today's prompt. Commands leave the process redacted. Off by default.
- **Jev auto-allow for collection** (V0.5.8, opt-in, `riskJudge.autoAllow.enabled`): during a multi-host survey almost every probe the classifier cannot name (`lsnrctl status`, `showmount -e`, `hdb info`, …) costs one confirmation **per host**. With auto-allow on, a verdict that clears every threshold lets that command run without the round-trip. It is the only path by which the judge can change an outcome, and it is narrow by construction: only where the deterministic gate had already decided to *ask a human* (never where it decided to block), only `UNKNOWN`, only a single non-composed command whose head is not an interpreter/remote tool, and only when read-only probability, confidence, rubric position, distribution mass, privilege probability and impact band all pass. A miss is reported in the prompt (`自动放行未通过：…`) and every auto-allowed command is written to the audit with an `AUTO_ALLOWED` line — visible in the console's audit tab and in the tool result. Default off.
- **Every refusal is recorded** (V0.5.9): the audit trail used to contain only what actually ran — a command the rules blocked, or one nobody approved, vanished without a trace. All four execution paths (`exec` / `run` / `batch` / `job`) now write exactly one entry per refusal: `BLOCKED` when the deterministic gate refused it, carrying the rule's own reason in `refusalReason`; `DENIED` when approval was not granted. The records satisfy the storage schema, are searchable with `jumpserver_audit`, and the console shows them as 「已拦截」 / 「未批准」 rather than as red failures. The write is best-effort by design: a broken audit sink can never turn a refusal into an execution.
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
- **Paged audit reads + rotation (V0.5.10)**: the console audit tab used to fetch the whole 5000-record window every second and re-render every matching row, and once the ring hit its cap the table stopped updating at all because the page only re-rendered when the array *length* changed. Reads now go through an absolute-index cursor (`page(since, limit)`, O(limit)), the page fetches only what is new and renders the newest 300 rows with a "matched / showing / total" line, and `POST /api/audit/archive` rotates the JSONL: it flushes queued appends, atomically renames the file to `<name>.<UTC>.jsonl` in the same directory, then resets the tail offset. The rotated file is **never deleted** — archiving moves the evidence, it does not destroy it.
- **Configurable console tabs (V0.5.10)**: `auditViewer.tabs` decides which of the eight tabs the console shows. Hiding a tab removes its nav button and its client-side polling, but the section markup stays (the page script binds handlers inside it) and the hash router refuses to select it, so it is unreachable rather than absent. It is a visibility switch, not a permission switch: the audit sink keeps writing and every `/api/*` keeps its token + same-origin guard. `settings` cannot be hidden.
- **Multiple bastion accounts (V0.5.11)**: several JumpServer logins can be stored locally and switched from the console's 设置 tab. A selected account supplies the whole identity — **host, port, username and password** — and takes precedence over the connector form's single injected credential; if the account is missing, its port is out of range, or its secret cannot be decrypted, resolution falls back per field to the original `ENV → config.json → default` chain, so an account problem can never be the reason a connection fails. Secrets are AES-256-GCM encrypted under `~/.workbuddy/jumpserver-mcp/profiles.json` (key `vault.key`) and are never echoed to the page; a corrupt store is reported and **refused** for writing instead of being silently overwritten. Switching accounts tears down every existing session, asset cache and pending grant, because a PTY authenticated with the previous credential no longer represents the identity the operator selected. `jumpserver_status` reports where the live credential and host came from (`env` / `config` / `profile`) without ever printing a value. Console write routes require an **same-origin** request as well as a valid token: a cross-origin POST is refused outright, because a leaked token (which `stableUrl=false` puts in the URL) must not be enough on its own to switch accounts or interrupt sessions.

- **Honest annotations (V0.5.2)**: every registered tool declares MCP `annotations`, and the values are treated as a **contract, not decoration** — a tool that writes anything may not claim `readOnlyHint`. `jumpserver_baseline_capture` (writes `data/baselines/<name>.json`) used to advertise read-only, the same class of bug V0.4.3 fixed for `jumpserver_status`; it now declares `readOnlyHint: false`. `jumpserver_interrupt` / `jumpserver_job_start` / `jumpserver_job_stop` declare `destructiveHint: true`. A test freezes the whole table, so a tool cannot quietly change its contract — or be added without one.
- **Diagnosable startup (V0.5.2)**: an incomplete connection no longer calls `process.exit(1)` — the MCP handshake completes, and only the tools that actually need the bastion refuse, with `CONFIG_INCOMPLETE` carrying the same wording the startup log uses. `jumpserver_status` stays answerable and reports `connection: INCOMPLETE — missing host, username`, because "ask what is wrong" is exactly what a user does first. A **malformed** config is still fatal: a missing value is recoverable at runtime, a broken file is an operator mistake. `--doctor` covers the rest — see [Diagnosing a broken setup](#diagnosing-a-broken-setup).
- **Progress notifications (V0.5.2)**: the long multi-target tools (`inspect` / `topology` / `compare` / `profile_run` / `baseline_*` / `batch`) emit `notifications/progress` per finished target when the host supplies a `progressToken`. A 20-host survey is no longer indistinguishable from a hang.
- **Tool-table budget (V0.5.2)**: the `tools/list` payload is a permanent tax on EVERY conversation, including ones that never touch JumpServer. It is now measured (`npm run measure:context`) and gated by a test at 23 KB (~5.4 k tokens). The remaining large lever — merging the six multi-target survey tools behind one `mode` parameter — would save ~3-4 KB but renames the public tool surface, so it is left as a deliberate decision rather than taken silently.
- **Idle console is idle (V0.5.2)**: each console poller already self-gated on its own tab, but a page hidden in a background tab kept fetching every second and re-reading `audit.jsonl` with nobody looking. One visibility gate now covers all six pollers, and returning to the page refreshes the active tab immediately.
- **`hdbsql` read-only queries (V0.5.2)**: SAP HANA has no `-e`, so `hdbsql -n host:30013 -u SYSTEM -d SAPHANADB "SELECT ..."` — the query a BASIS actually runs — was an unknown executable and prompted on every call. A narrow HANA rule now confirms `SELECT` / `EXPLAIN PLAN FOR SELECT` / read-only meta-commands, while `-o` / `-I` / `-L` (file targets), `CALL` / `DO` / `WITH` (opaque semantics) and every unproven statement type stay `UNKNOWN`. `mysql` / `mariadb` keep their existing verdicts, and the classifier now has tests.

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
| `maxSessions` | `4` | Cap on targets entered simultaneously (1..16). Enforced process-wide by one `Semaphore` shared by every conversation in the process; only binds when `batchConcurrency > 1` |
| `assetGroups` | `{}` | Named group -> keywords, used by `jumpserver_assets` |
| `runbooks` | `{}` | Named runbook -> `{ title, steps[] }`; each step is a `profile` or a READ `command`, optionally with `expect` assertions |
| `auditPath` | `<root>/data/audit.jsonl` | JSONL audit sink |
| `auditViewer.{enabled,port,autoOpen,portFallback}` | `true/8765/true/true` | Embedded console |
| `auditViewer.stableUrl` | `true` | Serve one token-free, restart-stable address (`http://127.0.0.1:<port>/`, token injected into the page) instead of a per-process `?token=` URL on a possibly-ephemeral port. Set `false` only for the legacy behaviour |
| `auditViewer.tokenTtlMinutes` | `720` | Console access-token lifetime in minutes (0 = never expires) |
| `auditViewer.tabs` | `{}` (all on) | Per-tab visibility of the console navigation, e.g. `{"stats": false}`. Hiding a tab removes its nav button and stops its client-side polling; it does NOT stop the audit sink, does NOT reduce any permission check (every `/api/*` keeps its console token + same-origin guard), and the section markup stays in the page because the script binds handlers inside it. `settings` is always-on — it is the only diagnostics entry point and documents this very switch. Since V0.5.13 the 设置 tab also offers these as checkboxes, persisted to `~/.workbuddy/jumpserver-mcp/console-prefs.json`; precedence is **an explicit value here > the console checkbox > visible**, so a tab pinned in this file is rendered locked in the UI |
| `auditViewer.allowCredentialWrite` | `true` | Whether the local console may add / edit / delete bastion account credentials. The console binds to 127.0.0.1 and every request carries the per-process access token, and secrets are stored AES-256-GCM encrypted under `~/.workbuddy/jumpserver-mcp/profiles.json` (key `vault.key`) and never echoed back — set `false` to reduce the settings tab to a read-only list and have every write route refuse |
| `requireArm` | `false` | Require `jumpserver_arm` before any tool runs |
| `riskJudge.{enabled,endpoint,apiKeyEnv,apiKeyFile,model,timeoutMs,cacheTtlSeconds,redactNetwork}` | `false` / `https://api.typesafe.ai/v1/systemone` / `TYPESAFE_API_KEY` / `~/.workbuddy/typesafe/api_key` / `jev-latest` / `1500` / `3600` / `true` | Semantic second opinion for `UNKNOWN` commands (V0.5.7) — only `UNKNOWN` commands are ever sent; `MODIFY` / `DANGEROUS` / `READ` / `PRIVILEGED_READ` never are. The key is resolved per call: env var `apiKeyEnv` first, then the file `apiKeyFile` (empty or unreadable = judge silently off). Only the env-var name and the path live in the config object, never the secret. The state is redacted first: credentials always, IP / FQDN / home account by default, system paths deliberately kept |
| `riskJudge.autoAllow.{enabled,minReadOnly,minConfidence,maxRiskScore,minSafeProbability,maxNeedsPrivilege}` | `false` / `0.9` / `0.7` / `1` / `0.85` / `0.3` | V0.5.8, opt-in: let a verdict that clears every threshold skip the human prompt for an `UNKNOWN` command the gate had already sent to approval — the friction that dominates multi-host collection. `maxRiskScore` is the expected rubric position on the API's 0..4 scale (1 = the two safest bands only); `minSafeProbability` is the mass the rubric distribution must put on those two bands, so an average cannot hide a fat tail. Everything else is unchanged: the guard refuses composed commands, opaque shell syntax, interpreter/remote heads, a missing distribution and every non-finite value, and `MODIFY` / `DANGEROUS` / a hard block are never eligible. Default off |

## Diagnosing a broken setup

Run the self-check before reading any source. It starts **no** MCP server, opens **no** SSH connection, binds **no** port, prints **no** credential value, and exits non-zero when something must be fixed:

```bash
npx -y jumpserver-mcp --doctor      # or: npm run doctor
```

```text
jumpserver-mcp 0.5.2 — self-check

[OK  ] node runtime: v22.22.2 on linux/x64
[OK  ] config file: none at /opt/jumpserver-mcp/config.json — the connector form alone can supply the connection
[FAIL] connection: INCOMPLETE — missing host / username
           jumpserver-mcp: no JumpServer host / username configured.
           Provide it in either place — ENV wins over config.json:
             1. WorkBuddy → 连接器 → JumpServer: fill 地址 / 端口 / 用户名 / 密码
             2. config.json: copy config.example.json and set "host", "username"
           Environment keys read at startup: JUMPSERVER_HOST, JUMPSERVER_PORT, JUMPSERVER_USERNAME, JUMPSERVER_PASSWORD
[WARN] credential: NOT found in any layer — the value itself is never read by this command
[OK  ] audit sink: /opt/jumpserver-mcp/data/audit.jsonl — writable
[OK  ] baseline store: /opt/jumpserver-mcp/data/baselines — writable
[OK  ] ops console: port 8765 is already serving a console (expected while another conversation is open — reload the page)
[OK  ] effective policy: READ_ONLY, requireArm=false, maxSessions=4, batchConcurrency=1, ...
[OK  ] ssh2 transport: module loads

Result: 1 problem must be fixed before the connector can reach the bastion
```

What each verdict maps to:

| Check | A failure here means |
|---|---|
| `node runtime` | The host is running an older Node than `engines` requires |
| `config file` | `config.json` is not valid JSON, or violates the schema. Both are **fatal at startup** (unlike a missing value) |
| `connector env` | A `JUMPSERVER_*` variable is malformed (e.g. a non-numeric port). Blamed on the environment, not on the file |
| `connection` | `host` / `username` are missing from every layer. The fix text is byte-identical to the one the tools return as `CONFIG_INCOMPLETE` |
| `credential` | No password in any layer (`WARN`, not `FAIL` — the connection itself may still be complete) |
| `audit sink` / `baseline store` | The install directory is not writable (read-only mount, no space, discarded container layer) |
| `ops console` | Reported for information: an occupied port is **expected**, since a stable address outlives any one process |
| `ssh2 transport` | The only non-trivial dependency does not load |

`config file` and `connection` are deliberately separate checks: a file that parses but violates the schema used to surface as a raw zod dump, and a bad `JUMPSERVER_PORT` used to look like a config problem.

### When an asset is unreachable (V0.5.5)

A reachable bastion does not imply reachable assets. When KoKo cannot dial the target it prints the reason and returns to its own menu:

```text
开始连接到 root(root)@192.168.138.56  0.0 … 14.4
开始连接到 root(root)@192.168.138.56 error: 网络不通（连接超时）
[Host]>
```

The connector answers:

| Field | Value |
|---|---|
| `code` | `ASSET_UNREACHABLE` |
| `message` | names the target and states it is **not** a configuration / credential / `accountIndex` problem |
| `detail` | `koko=<the full banner line> retryAfterMs=<cooldown>` |
| `next` | `STOP — do not retry …; report to the user that the server is temporarily unreachable` |

What the connector does with that knowledge:

- **The session survives.** KoKo is back at its own prompt, so the state is `JUMPSERVER_MENU`, not `UNKNOWN` — the next `jumpserver_enter`/`jumpserver_run` for a *different* asset needs no reconnect. The check is tail-anchored and refuses to accept an `ID>` prompt, where an asset name would be read as an account choice.
- **The target is refused for 2 minutes** (`retryAfterMs`), before any byte reaches the PTY: KoKo would otherwise spend its own ~15 s dial timeout to fail identically. The cooldown is per-target, and an explicit `jumpserver_close` clears it (the usual reason to close is that the network was just fixed).
- **Failures are scoped to one attempt.** The detector tail is reset when a dial starts, so a banner left over from a previous attempt is never re-matched against a healthy new one.
- **Only network failures stop.** A non-network banner (e.g. `资产不存在`) still returns `ASSET_ENTER_TIMEOUT` and stays retryable — a wrong guess must not be turned into a dead end.
- **Multi-target tools keep the reason.** `errorDetail()` now forwards `detail` (V0.5.5: it used to drop it between the session and the tool result), so `jumpserver_batch` / `inspect` / `topology` / `compare` / `profile_run` / `baseline_*` print the banner **and** the STOP line per target instead of a bare `code: message`.

For multi-host surveys this means the unreachable host is reported once with its banner and the rest of the fleet is surveyed normally; repeated entries for the same host are refused instantly instead of re-dialling.

### Answering KoKo's account prompt (V0.5.6)

When a target has more than one authorised bastion user, KoKo paints a numbered list and waits at `ID>`. The connector never picks for you — without `accountIndex` it answers `ACCOUNT_SELECTION_REQUIRED` with the parsed list in `detail`:

```text
ACCOUNT_SELECTION_REQUIRED: target 192.168.138.56 has 2 accounts; pass accountIndex in
jumpserver_enter/jumpserver_run/jumpserver_batch — the session stays live at the KoKo ID>
prompt: call again with accountIndex to answer it (no reconnect needed)
  detail: accounts=1) root | 2) 手动输入
```

At that moment the session is deliberately **still live and still mid-entry** (`ENTERING_ASSET`, not `UNKNOWN`), parked on the prompt that asked the question. What happens to the answer:

| Situation | Behaviour |
|---|---|
| `accountIndex` is one of the displayed IDs | the ID is written, KoKo dials, the shell is verified — same transport, same target line, no reconnect |
| `accountIndex` is not in the list | `ACCOUNT_SELECTION_REQUIRED` naming the bad choice; the prompt is **still answerable**, so retry with a valid ID |
| the caller omits `accountIndex` again | the selection is re-raised (previously this answer was `NOT_AT_MENU`) |
| the prompt is gone — KoKo timed the selection out, or the transport died | `ACCOUNT_SELECTION_EXPIRED` → reconnect and enter again; nothing is typed into a screen the connector no longer recognises |
| an explicit `jumpserver_close` | the parked prompt is dropped, like the unreachable cooldown |

No byte reaches the `ID>` prompt except an explicit `accountIndex` from the caller, and `canResumeAccountSelection()` requires the list to still be on screen — `looksLikeMenuPrompt()` keeps refusing `ID>` for the same reason, so a parked prompt can never be mistaken for navigable menu.

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
- **Every instance is reachable (V0.5.4).** A process that loses the port race binds its own private loopback port and publishes `{ role, port, summary }` in `data/consoles/<pid>.json`. The header's instance picker lists every live console of the workspace (pid · role · target · sessions · state) and embeds the selected one in full; the embedded page injects *its own* token, so no secret is shared and the per-process token model is unchanged.
- **The handover URL is per-instance.** Each process hands the model `http://127.0.0.1:8765/?inst=<pid>`, so opening the console from a second conversation lands on **that** conversation's sessions. The bare address (no `?inst=`) keeps showing whichever process owns the port. Before V0.5.4 both conversations showed one terminal and the 中断 button acted on the *other* process's sessions — a real cross-conversation side effect.
- **…and it is followed (V0.5.8).** Whoever owns 8765 answers the handover request, which is often *not* the conversation that asked: a fresh conversation is a follower on a private port, so the page it received was served by another conversation's process. The page read that as "this is me" and labelled its own author 「另一个实例」 — correct terminal, inverted identity, and a 「切回本实例」 button that led somewhere else. Now the requesting pid (`?inst=`) is the authority: `SELFPID` is reported as **本页服务进程**, `OPENPID` as **本实例**, and the page probes that instance's own address (`/ping`, 204, token-free) before handing the browser over — so the tabs, audit and terminal all belong to the right conversation. It stays put (and says 「本对话实例（pid X）已退出」) when the instance is gone, instead of quietly displaying another conversation's console as yours.
- **The page self-heals.** A restarted process re-binds the same address and an already-open tab resumes polling by itself; the 工作台已失效 overlay clears on the first successful poll.
- **Token expiry is transparent.** A 403 marked expired makes the page reload once to pick up a freshly injected token.
- **Cross-origin requests are refused**, so a web page in the local browser cannot read the audit trail or drive `/api/interrupt`.

The model receives the URL in a tool response and must open it with `present_files` (WorkBuddy's built-in preview panel) — **do not** use the system browser. The hint repeats on every response until the page has actually been fetched once, because a single first-response handover got parked until the end of the task in practice.

Set `auditViewer.stableUrl: false` to restore the v0.5.0 form: `127.0.0.1:<random>/?token=…`, one console per conversation, invalidated when the conversation ends. That form has no shared address, hence no instance picker — each conversation simply owns its own console.

Tabs:

- **Instance picker (header)** — switch between this workspace's live MCP instances (one per conversation). Selecting another instance embeds its whole console behind a warning bar; its 中断 / 断开 buttons act on that instance, never on yours.

- **Live terminal** — real-time PTY mirror, input echo, state-transition markers; "Interrupt current command (Ctrl+C)" / Clear / Auto-scroll. This is the **landing tab** (V0.5.6): a bare/bookmarked address and any unknown `#hash` open here, since the console is normally opened to be *watched* while the agent works. Deep links still work — `#audit`, `#assets`, `#topology`, `#jobs`, `#stats`, `#sessions`, `#settings`.
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
npm run doctor      # self-check; no server, no SSH, no port bound (see above)
npm run measure:context   # tools/list payload size + per-tool breakdown
```

Connector package toolchain (V0.5.1):

```bash
npm run validate:connector   # submission rules + de-identification scan; non-zero on failure
npm run pack:connector       # validate, then build .workbuddy/artifacts/jumpserver-connector-v<version>.zip
npm run verify:entry         # do the registry AND every install source still point at a live server?
npm run link:stable          # pin ~/WorkBuddy/jumpserver-mcp at this checkout (see below)
```

**When the connector shows as enabled but no tool appears in the list**, run `npm run verify:entry` before anything else. The host caches the absolute path of the checkout that was installed, so moving the project folder (this repo used to live under `~/WorkBuddy`) or switching the managed node version leaves a registry entry that spawns a process which dies at startup — and MCP reports the empty tool list without saying why. The script boots that exact command line, completes a handshake and prints the server version and tool count; when a path is gone it names the file and the line to fix. Fix it, then reconnect the connector — a stale path is cached per session.

Two places freeze that path, and fixing only the registry is not enough:

- the connector registry (`~/.workbuddy/connectors/<account>/mcp.json`), and
- **any install source the host can re-copy from** — the marketplace cache and a locally built package. A dev-mode marketplace package bakes the absolute checkout path in at *build* time, so "reconnect from the connector centre" pushes the old path straight back and silently undoes a manual fix. `verify:entry` checks both sides and fails with `LATENT FAILURE` when only the registry is currently fine.

`npm run link:stable` is the durable answer to the same problem: it creates a directory junction at `~/WorkBuddy/jumpserver-mcp` (the path the original package was built against) pointing at wherever the checkout lives now, so frozen artifacts keep resolving without a rebuild. It is idempotent, never deletes the checkout, and `--status` / `--remove` are there for inspection. `npm run market:build` prints the path it just froze, because the artifact is location-bound by design.

Test coverage (`tests/`):

- `security/command-classifier.test.mjs` — the classifier matrix (incl. every fixed case from the review).
- `security/permission-gate.test.mjs` — 3 modes x 5 risks + target allow/deny.
- `security/risk-judge.test.mjs` (V0.5.7) — the advisory judge against a mock System One endpoint: disabled / missing credential / timeout / non-2xx / malformed payload all degrade to the plain UNKNOWN prompt, credentials and target IPs proven absent from the outgoing state, a `MODIFY` command proven never to leave the process, and only a cached repeat avoiding a second call.
- `security/risk-judge-autoallow.test.mjs` (V0.5.8) — the ONE path by which the judge may change an outcome: the guard refuses a missing number, a composed command, an interpreter head and every unmet threshold, an auto-allowed command still verifies its target, and the thresholds are asserted against verdicts measured from the live model.
- `security/refusal-audit.test.mjs` (V0.5.9) — every refusal path (`exec` / `run` / `batch`, `BLOCKED` and `DENIED`) writes exactly one audit record carrying the reason, an approved command writes none, the record satisfies the storage schema, and a broken audit sink cannot turn a refusal into an execution. Sample UNKNOWN commands come from `tests/helpers/unknown-command.mjs`, which fails on import the moment a rule makes one of them classified — a classifier improvement must never look like a gate regression.
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
- `runtime/console-instances.test.mjs` (V0.5.4) — a process that loses the stable-port race still binds its own loopback console and publishes `role: follower`; `/api/instances` lists every live instance with `self` marked and puts yours first; a stale discovery file is not offered; the endpoint stays token-gated; the handover URL carries `?inst=<pid>`; the page exposes the picker + embed target and no longer labels a PTY session 「当前对话」.
- `runtime/console-instance-identity.test.mjs` (V0.5.8) — `?inst=` is the authority, not the process that answers: `OPENPID` is 「本实例」 and `SELFPID` is 「本页服务进程」, the page hands over to that instance's own listener, and a vanished instance is reported instead of showing another conversation's console.
- `security/command-classifier-corpus/*.test.mjs` — a wider classifier corpus (SAP / databases, containers / services, filesystem / process / storage, network / dangerous) guarding the READ / MODIFY / DANGEROUS boundary.
- `security/sql-command-classifier.test.mjs` (V0.5.2) — the database-CLI chain (`mysql` / `mariadb` + SAP HANA `hdbsql`) through the AUTHORITATIVE classifier: read-only forms confirmed, `-o` / `-I` / `-L` file targets and `CALL` / `DO` / `WITH` held at `UNKNOWN`, shell chaining unable to smuggle a second command past the rule, and the HANA rule proven to run before the generic one.
- `runtime/tool-annotations.test.mjs` (V0.5.2) — freezes the annotation table for all 23 tools (+ the `requireArm` arm/disarm pair), asserts no write tool claims `readOnlyHint`, that every annotation key is one the MCP spec defines, and that the README tool table matches what is registered.
- `runtime/audit-refusal-render.test.mjs` (V0.5.9) — the refusal survives the projection: `jumpserver_audit` (real server over MCP stdio, fabricated sink) lists a `BLOCKED` / `DENIED` entry with its `why=` reason, while an entry that ran keeps its previous shape byte-for-byte.
- `runtime/config-incomplete.test.mjs` (V0.5.2) — boots with no configuration at all, asserts `jumpserver_status` names what is missing, that connect-needing tools refuse with `CONFIG_INCOMPLETE` and actionable text, that local-only tools keep working, and that a MALFORMED config is still fatal.
- `runtime/context-budget.test.mjs` (V0.5.2) — gates the `tools/list` payload at 23 KB and every individual tool at 1.7 KB, so context cost cannot drift one description at a time.
- `runtime/doctor.test.mjs` (V0.5.2) — `--doctor` never throws on the input it diagnoses, attributes a bad `JUMPSERVER_*` variable to the environment rather than the file, translates zod issues into `path: message`, and never renders a credential value.
- `jumpserver/enter-unreachable.test.mjs` (V0.5.5) — a real `网络不通（连接超时）` banner yields `ASSET_UNREACHABLE` with the **full banner** in `detail` (not the matched token), the session lands back at the menu so the next asset needs no reconnect, a repeat enter on the same target is refused with **zero PTY writes** and the cooldown restated, the cooldown is per-target and cleared by an explicit close, a stale banner is not re-matched, a non-network failure stays retryable, `looksLikeMenuPrompt` accepts `[Host]>` / `Opt>` but refuses `ID>`, and `renderResult` prints the STOP line for `ASSET_UNREACHABLE` only, and one fleet-level case drives `SessionManager.runTargetBatch` over three hosts (the middle one down) to pin that the down host reports once with its banner while the other two are surveyed normally — the fleet wire answers the *target line*, not a timer, because `runTargetBatch` leaves the previous asset first and a pre-timed banner is wiped by the attempt-scoped detector reset.
- `jumpserver/session-account-selection.test.mjs` (V0.5.3, extended in V0.5.6) — the `ID>` screen answered with the displayed ID, `ACCOUNT_SELECTION_REQUIRED` carrying the parsed list when it is omitted, an out-of-range index refused at the boundary, and a single-user asset left untouched. V0.5.6 adds the part V0.5.3 got wrong: the session stays **live** at the prompt so the answer lands on the same PTY — one transport, one target line, exactly one digit written, asserted at both the session and the `SessionManager.runTargetBatch` level (the manager had its own fail-closed guards, and those are what rejected the answer before); a rejected index keeps the prompt answerable; re-asking without an index re-raises the selection instead of `NOT_AT_MENU`; and a prompt that is gone (`ACCOUNT_SELECTION_EXPIRED`) or a closed session puts nothing on the wire.

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
