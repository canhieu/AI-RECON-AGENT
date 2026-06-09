# AI Recon Agent - Architecture And Workflow

`ai-recon-agent` is an aggressive autonomous reconnaissance agent for authorized CTF, lab, challenge, and boot2root targets. It maps attack surface, enumerates services, collects exposed artifacts, correlates evidence, and produces ranked attack leads without default exploitation.

## Architecture

```text
agent/main.py
  -> ReconOrchestrator
      -> PortWorker / WebWorker / ServiceWorker / ReportWorker
      -> ToolExecutor
      -> ReconStateStore SQLite
      -> ConsoleUI/Textual dashboard
      -> Reporter
```

## Core Files

| File | Purpose |
|---|---|
| `agent/main.py` | CLI entry point |
| `agent/orchestrator.py` | Manager loop, worker scheduling, analysis calls, state save |
| `agent/workers/port.py` | `rustscan 1-65535`, fallback `nc_scan`, then `nmap -sC -sV` |
| `agent/workers/web.py` | Web fingerprint/crawl/JS/fuzz/API/artifact chain |
| `agent/workers/service.py` | Non-web checks and deep probes |
| `agent/executor.py` | Command execution and parser dispatch |
| `agent/state.py` | SQLite sessions/findings/surface/artifacts |
| `agent/artifacts.py` | Artifact storage/index helper |
| `agent/reporter.py` | Markdown/JSON report generation |
| `agent/cli.py` | Console and Textual UI |
| `agent/skills/boot2root-recon/SKILL.md` | Skill index and global policy |
| `agent/skills/boot2root-recon/agents/*.md` | Profile definitions for phased recon |
| `agent/skills/boot2root-recon/scripts/register_tools.py` | Tool registry |
| `AGENT.md` | System behavior prompt |

## Required Flow

1. Port surface: `agents/port-surface.md` runs `rustscan 1-65535` -> fallback `nc_scan 1-65535` if needed -> `nmap -sC -sV` on discovered ports.
2. Web surface: `agents/web-surface.md` runs fingerprinting, redirects/hosts, vhost/subdomain checks, `httpx`, headers, `cms_detect` (pass 1, root only), `katana`, JS tooling, and fuzzing. After adaptive fuzz discovers directory URLs, `curl_body` reads those directory bodies; then `cms_detect` runs again (pass 2) on fuzz-discovered paths. This catches cases like `/app/` directory listing linking to `/app/pluck-4.7.13/`.
3. JavaScript: `agents/js-hunter.md` dumps scripts, deobfuscates or normalizes packed/minified files, mines endpoints, source maps, secrets, API bases, and feature routes.
4. Adaptive fuzz: `agents/fuzz-hunter.md` starts with 6-second calibration probe, tunes filters, then expands directory, recursive, extension, and parameter fuzzing where signal exists.
5. API phase: `agents/api-hunter.md` probes docs, OpenAPI/Swagger, GraphQL, versioned routes, schemas, parameters, and safe unauthenticated data exposure. Current worker uses `arjun`; `kiterunner` is registered but not in the default chain.
6. Service surface: `agents/service-surface.md` runs matching `*_check` for non-web services (by global tool-name, not per-port).
7. Deep probes: `agents/ftp-hunter.md`, `agents/smb-hunter.md`, `agents/redis-hunter.md`, and future service profiles collect public/no-auth evidence and artifacts safely.
8. Artifacts: `agents/artifact-hunter.md` classifies, downloads, hashes, indexes, and saves exposed files in SQLite.
9. Report: `agents/report-writer.md` documents the report phase, but `ReconOrchestrator.run()` directly calls `Reporter`; no `generate_report` tool is registered.

Detected CMS/service/technology versions trigger `cve_search` with generic `<name/service> <version> cve` queries. CVE/exploit references come from `searchsploit --json` evidence, not hardcoded writeup logic.

## Profile Directory

```text
agent/skills/boot2root-recon/agents/
  port-surface.md
  web-surface.md
  fuzz-hunter.md
  js-hunter.md
  api-hunter.md
  artifact-hunter.md
  service-surface.md
  redis-hunter.md
  ftp-hunter.md
  smb-hunter.md
  report-writer.md
```

## State Model

SQLite tables:

- `sessions`: scan metadata.
- `findings`: evidence and severity.
- `tech_stack`: detected technology.
- `attack_surface`: ports/services/routes.
- `service_queue`: pending service/profile follow-up.
- `artifacts`: saved exposed files and metadata.
- `tool_actions`: exact action identity dedup for repeated tools with different params, e.g. `cms_detect` pass 1 vs pass 2 or `cve_search` per version.

## Artifact Model

Artifacts live under:

```text
outputs/<target>/artifacts/
```

Each artifact records:

- source URL/service path
- local path
- category
- service
- reason
- size
- SHA-256
- created time

Default limits: 50 files per service, 10MB per file, 100MB per target, depth 7.

Suspicious readable text artifacts are reviewed before reporting by the runtime `artifact_analyze` tool. This includes `.txt`, logs, configs, backups, notes, and small text-like files from exposed web/FTP/SMB/NFS/Redis contexts when names, paths, or service context suggest value. Findings extract useful indicators and redact raw passwords, tokens, private key bodies, and proof-like values in DB/UI/report; raw content stays only in local artifact files.

## Deep Service Behavior

- FTP: anonymous login, recursive listing, interesting file download, no upload/delete.
- SMB: null/guest share listing, interesting file download, no upload/delete.
- Redis: `INFO`, `CONFIG GET`, capped `SCAN`, key types, capped value samples, no writes.
- NFS: planned read-only exports/list/download behavior.

## Dashboard

The UI shows:

- active worker/tool/profile
- stable pseudo-agent statuses for Port/Web/Service/Report
- progress
- findings
- live analysis summaries after each tool result
- artifact save events
- final recon summary with report paths
- RTK token-savings line from `rtk gain` when available
- live activity log at `outputs/<target>/live-activity.log`

Textual requires a real TTY and `textual`. Console fallback is automatic in non-TTY runs or when `AI_RECON_TUI=0`. On successful Textual runs, the dashboard remains open after completion and exits when the user presses `q`; console fallback prints the summary and exits normally.

## Run

```bash
python3 agent/main.py --target 10.49.147.137 --max-steps 25 --verbose
AI_RECON_TUI=0 python3 agent/main.py --target 10.49.147.137 --max-steps 25 --verbose
```

## Current Limitations

- `WebWorker` uses the first HTTP-like target from `web_targets[0]`; full multi-web-target scheduling is not implemented yet.
- `ServiceWorker` mostly dedups by global tool name, so identical check tools on multiple ports need future per-port action identity.
- `scope.yaml` documents policy but is not enforced before execution yet.
- Legacy `_build_decision_prompt()` / `_llm_decision()` code still exists but is not used by the current worker-driven loop.

## Boundaries

Default recon mode does not brute force, exploit, upload, delete, overwrite, spawn shells, or make destructive writes. Those belong in a separate explicit exploit mode if added later.
