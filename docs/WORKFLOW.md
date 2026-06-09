# AI Recon Agent - Workflow

Input -> worker scheduler -> tool -> parser -> analysis -> state -> dashboard -> report.

## Defaults

- Mode: aggressive recon for authorized CTF/lab/challenge targets.
- Profile flow: `port-surface` -> `web-surface` / `service-surface` -> `js-hunter` -> `fuzz-hunter` -> `api-hunter` -> service hunters -> `artifact-hunter` -> `report-writer`.
- Port-first: `rustscan 1-65535` -> fallback `nc_scan 1-65535` if needed -> `nmap -sC -sV` on discovered ports only.
- Web chain: `whatweb` -> `redirect_check` -> optional `hosts_add` -> optional `subfinder` -> `ffuf_vhost` -> `httpx` -> `curl_headers` -> `cms_detect` (pass 1, root only) -> `katana` -> JavaScript dump/deobfuscate/mine -> adaptive fuzz (`ffuf_dir`/`ffuf_recursive`/`ffuf_ext`) -> read discovered directory listings with `curl_body` -> `cms_detect` (pass 2, with fuzz-discovered paths) -> generic `cve_search` for detected tech/service versions -> API phase -> artifact capture -> `nuclei_general`. Inspect index HTML, headers, cookies, meta generator tags, comments, and assets for CMS/framework detection; exposed versions are at least medium severity.
- Adaptive fuzzing: run 6-second calibration probe, tune filters, then expand directory, recursive, extension, and parameter fuzzing only where signal exists.
- API phase: mine API bases from HTML/JS/routes, probe docs and schemas, use `arjun` for parameter discovery, and save safe unauthenticated responses. `kiterunner` is registered but not wired into the default worker chain yet.
- Service chain: non-web open ports get matching `*_check` via global tool-name tracking (port-level granularity not yet implemented); FTP/SMB/Redis get deep hunter profiles when supported.
- Artifacts: exposed interesting files are saved under `outputs/<target>/artifacts/`, recorded in SQLite, and shown in reports.
- Suspicious readable text artifacts are reviewed at runtime with `artifact_analyze`; secrets/proof-like values are redacted in DB/UI/report and kept raw only in local artifacts.
- Dashboard: each tool result is followed by live analysis summary, severity, evidence preview, high-value targets, tech, services, and RTK savings when `rtk gain` is available.
- Not default: brute force, exploit modules, shells, upload, delete, overwrite, destructive writes.

## Runtime Loop

```text
target
  -> ReconOrchestrator
  -> PortWorker / WebWorker / ServiceWorker / ReportWorker
  -> ToolExecutor
  -> parser
  -> LLM analysis
  -> ReconStateStore
  -> ConsoleUI/Textual dashboard
  -> Reporter
```

## Step 1 - Build Context

The orchestrator builds context from:

- target and step count
- active skill profile
- recent findings
- tech stack
- attack surface
- pending service checks
- known web targets
- JavaScript/API/fuzz queues
- artifact queue
- required worker action
- available tools

## Step 2 - Worker Action

Workers force required profile flow first in fixed order (Port -> Web -> Service -> Report). If no worker has a required action, the scan completes and generates a report. The generated action uses this JSON shape:

```json
{
  "tool": "tool_name",
  "target": "target_string",
  "params": {},
  "reason": "why this action",
  "done": false
}
```

Report generation is handled by `ReconOrchestrator` after the required worker flow completes or max_steps is reached. There is no `generate_report` tool.

## Step 3 - Execute Tool

`ToolExecutor` builds a command from `register_tools.py`, runs it with timeout, captures stdout/stderr, and applies the registered parser.

## Step 4 - Analyze Result

The analysis model returns concise JSON:

```json
{
  "summary": "short finding",
  "severity": "critical|high|medium|low|info",
  "tech_discovered": [{"name": "...", "version": "..."}],
  "service_detected": [{"host": "...", "port": 0, "service": "..."}],
  "high_value_targets": ["..."],
  "evidence": "key lines"
}
```

## Step 5 - Save State

SQLite tables:

- `sessions`
- `findings`
- `tech_stack`
- `attack_surface`
- `service_queue`
- `artifacts`
- `tool_actions` — action identity dedup with `UNIQUE(session_id, action_key)`; key = hash of `(tool, target, params_json)`

Artifact-producing tools return `parsed.artifacts`; orchestrator saves each item and emits a live finding. After each artifact save, orchestrator auto-runs `artifact_analyze` (non-blocking, deduped via `tool_actions`).

## Step 6 - Report

Reporter writes:

- `outputs/<target>/recon-report.md`
- `outputs/<target>/recon-report.json`

Reports include summary, findings by severity, service map, web/JS/API routes, artifact table, recommendations, and ranked next actions.

## Skill Profiles

Profiles live under `agent/skills/boot2root-recon/agents/`:

- `port-surface.md`
- `web-surface.md`
- `fuzz-hunter.md`
- `js-hunter.md`
- `api-hunter.md`
- `artifact-hunter.md`
- `service-surface.md`
- `redis-hunter.md`
- `ftp-hunter.md`
- `smb-hunter.md`
- `report-writer.md`

## Artifact Rules

Download/list/read exposed files when access is public, anonymous, guest, or no-auth.

Prioritize credentials, configs, database dumps, backups, VCS leaks, cloud/CI files, logs, source/package files, proof-like sensitive files, and high-signal documents.

Mandatory suspicious text review applies to `.txt`, `.log`, `.conf`, `.cfg`, `.ini`, `.env`, `.bak`, `.old`, and small text-like files with names such as `note`, `readme`, `todo`, `hint`, `backup`, `users`, `creds`, `credentials`, `password`, `secret`, `token`, `key`, `admin`, `config`, `db`, `database`, `dump`, `private`, `internal`, or `debug`.

Review content for credentials, usernames, emails, internal hosts/IPs/URLs, paths, database strings, commands, deployment notes, debug traces, private keys, hashes, JWTs, bearer tokens, cloud keys, and proof-like sensitive values. Redact raw secrets/proofs in dashboard/report; raw content remains only in saved local artifacts.

Default limits: 50 files per service, 10MB per file, 100MB per target, depth 7.

## Dashboard

Textual dashboard shows:

- progress
- pseudo-agent statuses: Port, Web, Service, Report
- active worker/tool/profile
- findings
- live analysis after each tool result
- artifact paths
- final recon summary after report generation
- RTK token-savings line from `rtk gain` when available
- live activity log

In a real TTY, the dashboard stays open after completion; press `q` to quit. During an active scan, `q` is disabled to avoid accidental abort. Console fallback prints the summary and exits normally.

Use console fallback for CI/non-TTY:

```bash
AI_RECON_TUI=0 python3 agent/main.py --target 10.49.147.137 --max-steps 25 --verbose
```
