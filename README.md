# jumpserver-mcp

JumpServer (KoKo) bastion connector for WorkBuddy as an MCP stdio server. Ported from `dsh-jumpserver` (v0.3.1) core. From v0.4.0 it is no longer just "AI safely executes JumpServer commands" — it is an **AI infrastructure investigation / fault-analysis platform**: fixed read-only probes, structured host inventory, evidence-annotated topology, streaming job model, and an embedded ops console (6 tabs).

## Tools (18)

| Tool | Purpose |
|---|---|
| `jumpserver_status` | Session state / gateway / current target / permission mode / runtime version |
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
| `jumpserver_interrupt` | Ctrl+C the remote shell NOW, re-verify, out-of-band (does not wait for the running op) |
| `jumpserver_job_start` | Start a streaming job (`tail -f` / `journalctl -f` / `tcpdump`) |
| `jumpserver_job_read` | Read the buffered + new output of a job |
| `jumpserver_job_stop` | Ctrl+C the job, release the shell |
| `jumpserver_jobs` | List this conversation's jobs |

When `requireArm: true`, `jumpserver_arm` / `jumpserver_disarm` (30-minute authorization window) are also registered.

## Architecture highlights

- **Explicit state machine** (V0.1): illegal transitions always collapse to `UNKNOWN`; never guess.
- **Command classifier** (V0.3.1, 5 risks: READ / PRIVILEGED_READ / UNKNOWN / MODIFY / DANGEROUS); DANGEROUS always requires human approval, even in `FULL_ACCESS`.
- **Abort fix (V0.4.0 P0)**: MCP cancellation / `jumpserver_interrupt` / the console's "Interrupt current command" button all send Ctrl+C to the remote shell and re-run the probe — the connector never declares the asset usable while a foreground job is still running.
- **Structured inspection (V0.4.0 P0)**: `jumpserver_inspect` runs fixed read-only profiles (`basic / network / process / service / web / java / database / container / full`). A probe that regresses to a non-READ rule is skipped, not silently downgraded. `jumpserver_topology` builds a graph with per-edge `confidence` (HIGH/MEDIUM/LOW) and `evidence` (nginx upstream / `ESTABLISHED …` / `/etc/hosts` / same upstream cluster).
- **Streaming jobs (V0.4.0)**: `jumpserver_job_*` covers `tail -f` / `journalctl -f` / `tcpdump` style commands that never end on their own. Output is harvested from the `TerminalObserver` stream, `maxDuration` enforces an upper bound.
- **Incremental audit (V0.4.0)**: async append + bounded memory ring (5000) + file-offset incremental tail. The console no longer `readFileSync`s the whole JSONL every second.
- **Audit timezone (V0.4.0)**: JSONL stays UTC; display uses `timeZone` (default `Asia/Shanghai`).
- **Target scope (V0.4.0)**: `allowedTargets` / `deniedTargets` (substring match); deny always wins; every navigation and every `exec` against an already-entered asset is checked.
- **Version single source (V0.4.0)**: `package.json` is the only truth; runtime `PLUGIN_VERSION` reads from there. `npm version` and the runtime can no longer drift.

## Configuration

Copy `config.example.json` to `config.json`, fill `host` / `username`. The password must come from an environment variable (`passwordEnv`, default `JUMPSERVER_PASSWORD`) — never put it in `config.json`.

| Field | Default | Description |
|---|---|---|
| `host` / `port` / `username` | required | Bastion SSH gateway |
| `passwordEnv` | `JUMPSERVER_PASSWORD` | Env-var name holding the password |
| `permissionMode` | `READ_ONLY` | `READ_ONLY` / `AUTO` / `FULL_ACCESS` |
| `timeZone` | `Asia/Shanghai` | Display zone for audit timestamps (storage is still UTC) |
| `allowedTargets` | `[]` | Substring allow-list, e.g. `["192.168.79.", "oa-"]` |
| `deniedTargets` | `[]` | Substring deny-list (checked first) |
| `assetGroups` | `{}` | Named group -> keywords, used by `jumpserver_assets` |
| `auditPath` | `<root>/data/audit.jsonl` | JSONL audit sink |
| `auditViewer.{enabled,port,autoOpen,portFallback}` | `true/8765/true/true` | Embedded console |
| `requireArm` | `false` | Require `jumpserver_arm` before any tool runs |

## Register with WorkBuddy

```json
{
  "mcpServers": {
    "jumpserver": {
      "type": "stdio",
      "command": "node",
      "args": ["C:/Users/114976/WorkBuddy/jumpserver-mcp/lib/server.js"],
      "env": { "JUMPSERVER_PASSWORD": "..." },
      "description": "JumpServer MCP v0.4.0: fixed probes, host inventory, evidence topology, streaming jobs"
    }
  }
}
```

## Embedded ops console

Once the MCP process starts it serves a local page on `127.0.0.1:<port>/` (default 8765; if taken it auto-falls back to an ephemeral port so every conversation gets its own console). The model receives the URL in the first tool response and must open it with `present_files` (WorkBuddy's built-in preview panel) — **do not** use the system browser. Each conversation has its own port; closing the conversation invalidates the page.

Tabs:

- **Live terminal** — real-time PTY mirror, input echo, state-transition markers; "Interrupt current command (Ctrl+C)" / Clear / Auto-scroll.
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
- `jumpserver/state-machine.test.mjs` — legal/illegal transitions.
- `jumpserver/session-abort.test.mjs` — AbortSignal and out-of-band interrupt() must Ctrl+C + re-verify.
- `jumpserver/asset-list.test.mjs` — `p` parse / footer / filter / groups.
- `jumpserver/host-parse.test.mjs` — every parser.
- `jumpserver/topology.test.mjs` — edge construction and evidence.
- `inspect/profile-safety.test.mjs` — every profile command is still READ.
- `runtime/audit-store.test.mjs` — async append, ring cap, incremental tail.
- `runtime/time.test.mjs` — timezone formatting.

CI: `.github/workflows/ci.yml` (typecheck -> build -> smoke -> test on Node 22).
