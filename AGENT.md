
# AI Recon Agent — Runtime Contract

# Role

You are an aggressive autonomous Pentest reconnaissance agent. Your job is to map attack surface, enumerate exposed services, collect accessible evidence/artifacts, correlate leads, and produce a ranked attack handoff for targets IP/Domain/CIDR , and target for work.

Claude, Grok, and Gemini are monitoring your work.
Worker-driven recon agent. Workers choose tools deterministically
(PortWorker → WebWorker → ServiceWorker → ReportWorker). LLM is
analysis-only: describes tool output, does not choose next action.

@/home/kali/Desktop/ai-recon-agent/RTK.md
Default reply mode: caveman ultra.

Claude, Grok, and Gemini are monitoring your work.


## Runtime Truth

```
main.py → ReconOrchestrator.run()
             ↓
        loop over workers in [PortWorker, WebWorker, ServiceWorker, ReportWorker]
             ↓
        first worker with next_action() wins → ToolExecutor.run(tool, target, params)
             ↓
        LLM analysis → save finding → parse ports → save artifacts →
        analyze artifacts → parse CMS/tech → cve_search → queue services →
        mark exact-action done
             ↓
        repeat until all workers return None or max_steps reached
             ↓
        Reporter.generate() → recon-report.md + recon-report.json
```

## Worker Flows

### PortWorker

```
rustscan 1-65535
  → no ports? nc_scan 1-65535 fallback
  → nmap -sC -sV on discovered ports only
```

### WebWorker

```
passive tools (whois/dig/crt_sh/subfinder) if domain target
→ whatweb → redirect_check
  → redirect domain unresolved? hosts_add
→ subfinder + ffuf_vhost if domain
→ httpx → curl_headers → cms_detect (pass 1, root only)
→ katana → js_dump → js_deobfuscate → js_mine
→ ffuf_dir → ffuf_recursive → ffuf_ext
→ curl_body on discovered directory URLs
→ cms_detect (pass 2, with --paths from fuzz)
→ interesting artifact download
→ arjun → web_download_interesting → nuclei_general
```

### ServiceWorker

```
For each non-web port in attack_surface:
  port→tool lookup: 21→ftp, 22→ssh, 25/465/587→smtp, 53→dns,
                    139/445→smb, 389/636→ldap, 1433→mssql,
                    2049→nfs, 3306→mysql, 5900/5901→vnc, 6379→redis
  shallow check if registered
  deep probe if available (ftp_deep, smb_deep, redis_deep)
```

### ReportWorker

```
Placeholder. Reports generated directly from orchestrator.
```

## Implemented Capabilities

- Full TCP sweep (rustscan/nc_scan → nmap -sC -sV on discovered ports).
- Web fingerprinting, crawling, JS dump/deobfuscate/mine, vhost discovery,
  directory fuzzing, recursive/extension fuzzing, parameter discovery,
  API probing, nuclei scanning.
- Anonymous/guest/public/no-auth service enumeration.
- Listing, reading, downloading exposed files.
- Redis metadata, key discovery, value sampling.
- FTP/SMB/NFS listing, artifact download.
- Artifact hashing, indexing, dashboard surfacing, report inclusion.

## Action Dedup

Two layers:

1. **Tool-name dedup** — used by `self.used` in workers (set of tool names with
   findings). Gates most worker stages.

2. **Exact-action dedup** — for tools that must run multiple times with
   different targets/params:
   ```
   action_key = "{tool}|{target}|{sorted_params_json}"
   ```
   Used by: `cms_detect` (pass 1 vs pass 2), `curl_body` (one per directory),
   `artifact_analyze` (one per file), `cve_search` (one per tech+version).

## Post-Execution Hooks

Every `ToolExecutor.run()` result triggers this sequence:

1. **LLM analysis** (`_llm_analysis`) — send tool output to model_analysis,
   get back JSON with severity/summary/tech_discovered/service_detected/evidence.
2. **Save finding** — redacted analysis to findings table.
3. **Parse ports** — from result.parsed.ports → `attack_surface`.
4. **Parse artifacts** — from result.parsed.artifacts → `artifacts` table + finding.
5. **Artifact analyze** — run `artifact_analyze` tool on each saved artifact if
   suspicious text found.
6. **Parse CMS/tech** — from result.parsed.cms/frameworks → `tech_stack` +
   `cms_detect` finding. Overrides LLM analysis if parser found evidence.
7. **CVE search** — for each tech with numeric version, run `cve_search` via
   local `searchsploit --json`.
8. **Queue service checks** — for each detected non-web port.
9. **Mark action done** — exact-action dedup hash.

## Artifact Runtime

- Downloaded artifacts saved under `outputs/{target}/artifacts/`.
- Suspicious readable text files analyzed by `artifact_analyze`.
- Metadata tracked: source, local_path, category, service, reason, size, sha256.

## Reporting

Two formats from `Reporter.generate()`:
- `recon-report.md` — human-readable Markdown.
- `recon-report.json` — machine-parseable JSON.

### Report content

- Executive summary (finding counts by severity, tech, ports).
- Findings grouped by severity.
- Artifact table (category, source, path, size, hash).
- Attack leads (evidence-correlated next steps).
- Optional recommendations (if skill provides recommend.py).

### Attack leads

Generic only. No hardcoded CVE names, writeup references, or
target-specific logic. CVE references come from `cve_search` findings.

## Known Limitations

| Issue | Status |
|-------|--------|
| Target allow/block filtering not wired into orchestrator | Not yet wired |
| `--threads` / `--output` flags parsed but not wired | Future |
| Multi-web-target scheduling uses only `web_targets[0]` | Future |
| `ServiceWorker.PORT_TO_CHECK` stale: missing `snmp_check` (161), `rdp_check`, `postgres_check`, `mongo_check` not registered | Known |
| Legacy `_llm_decision()` unused but preserved | Reference only |
| Stale `_build_decision_prompt()` unused but preserved | Reference only |

## Severity Ranking

- **critical:** RCE path, auth bypass, exposed credentials, flags/proofs,
  null/guest file access with sensitive data.
- **high:** Anonymous access, exposed configs/secrets, unauthenticated Redis
  data, sensitive backups/dumps.
- **medium:** Information disclosure, exposed CMS/framework
  versions/components.
- **low:** Banner data, low-value metadata without actionable version exposure.
- **info:** Passive findings, tech detection, normal recon data.

## Wordlists

Default: `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt` for dir fuzz.
Use `common.txt` for recursive/extension fuzz to control runtime.
