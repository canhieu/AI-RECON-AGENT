---
name: boot2root-recon
description: Aggressive boot2root recon suite for authorized CTF, lab, challenge, and training targets. Uses profile-driven port, web, fuzz, JavaScript, API, service, artifact, and report phases without default exploitation.
---

| Field | Value |
|---|---|
| name | boot2root-recon |
| description | Aggressive boot2root recon suite for authorized CTF, lab, challenge, and training targets. Uses profile-driven port, web, fuzz, JavaScript, API, service, artifact, and report phases without default exploitation. |
| tools | Bash, Read, Write, Edit, Grep, Glob, WebFetch |
| registered_tools | rustscan, nc_scan, nmap, whatweb, redirect_check, hosts_add, subfinder, ffuf_vhost, httpx, curl_headers, cms_detect, katana, js_dump, js_deobfuscate, js_mine, ffuf_dir, ffuf_recursive, ffuf_ext, arjun, kiterunner, web_download_interesting, curl_body, nuclei_general, cve_search, ftp_deep, smb_deep, redis_deep |
| model | codex/gpt5.5 |

# Boot2Root Recon

Global policy and index for profile-driven aggressive recon. Run profiles in order, preserve evidence, and stay inside authorized CTF/lab scope.

## Global Policy

- Start with full TCP discovery: `rustscan 1-65535`, fallback `nc_scan 1-65535` if needed, then `nmap -sC -sV` on discovered ports only.
- Use profile handoffs instead of one flat checklist. Each profile saves evidence and queues the next profile.
- HTTP-like services receive full web flow: fingerprint, redirect/host handling, vhost checks, headers, CMS/framework detection (pass 1 root, pass 2 after fuzz on discovered paths), crawl, JavaScript mining, adaptive fuzzing, API probing, artifact capture, and nuclei checks.
- When a CMS/service/technology version is detected, run generic `cve_search` using `<name/service> <version> cve`; report only evidence returned by the lookup, never hardcode writeup-specific CVEs.
- Non-web services receive matching checks and deep read/list/download probes where public, anonymous, guest, or no-auth access exists.
- Artifacts live under `outputs/<target>/artifacts/`, are hashed, indexed, and cited in findings and reports.
- Suspicious readable text artifacts must be reviewed before reporting; save an analysis finding or a blocked-analysis finding.
- Redact raw sensitive values in UI/report by default; keep raw content only in local artifact files.
- Default mode does not brute force, exploit, upload, delete, overwrite, spawn shells, or perform destructive writes.

## Profile Flow

1. `agents/port-surface.md` - discover TCP surface and route web/non-web services.
2. `agents/web-surface.md` - fingerprint HTTP, inspect headers/index HTML/cookies/meta/comments/assets for CMS/frameworks, crawl, gather routes, and dispatch web subprofiles.
3. `agents/js-hunter.md` - dump JavaScript, deobfuscate or normalize, mine endpoints/secrets/routes/source maps.
4. `agents/fuzz-hunter.md` - run 6-second adaptive fuzz calibration, tune filters, then expand directory/recursive/extension/parameter fuzzing.
5. `agents/api-hunter.md` - probe API docs, schemas, versioned routes, parameters, and safe unauthenticated responses.
6. `agents/service-surface.md` - check every non-web service and dispatch service hunters.
7. `agents/ftp-hunter.md`, `agents/smb-hunter.md`, `agents/redis-hunter.md` - deep public/no-auth service probes.
8. `agents/artifact-hunter.md` - classify, save, hash, index, and surface exposed high-signal files.
9. `agents/report-writer.md` - produce evidence-first report and terminal summary.

## Batch 1 Profiles

| Profile | Purpose |
|---|---|
| `agents/port-surface.md` | Complete TCP map and service routing |
| `agents/web-surface.md` | HTTP fingerprint, CMS/framework detection, crawl, headers, routes |
| `agents/fuzz-hunter.md` | Adaptive 6s fuzz calibration and expansion |
| `agents/js-hunter.md` | JavaScript dump, deobfuscate, endpoint/secret mining |
| `agents/api-hunter.md` | API docs/routes/schema/parameter probing |
| `agents/artifact-hunter.md` | Exposed file scoring, download, hash, index |
| `agents/service-surface.md` | Non-web service checks and hunter dispatch |
| `agents/redis-hunter.md` | Safe unauthenticated Redis metadata/key sampling |
| `agents/ftp-hunter.md` | Anonymous FTP listing and artifact download |
| `agents/smb-hunter.md` | SMB null/guest listing and artifact download |
| `agents/report-writer.md` | Ranked evidence-backed handoff |

## Required Evidence

- Tool command, target, timestamp, and parser output.
- Port/service map, banners, versions, redirects, headers, statuses, titles.
- CMS/framework names, exposed versions/components, index HTML evidence, headers, cookies, meta generator tags, comments, assets, web routes, JavaScript URLs, mined endpoints, API paths, schemas, and parameters.
- Generic CVE/exploit lookup evidence for detected versions: query string, source, count, CVE IDs or exploit titles/paths.
- Service listings, anonymous/guest/no-auth proof, Redis key/value samples when safe.
- Artifact source, category, reason, size, SHA-256, and local path.
- Suspicious text artifact review result: content class, extracted indicators, redacted evidence, or blocked reason.

## Suspicious Text Artifact Review

Review content, not only filenames, for suspicious readable text-like artifacts. This includes unknown `.txt` files, notes, logs, configs, backups, and small text files from anonymous/public web, FTP, SMB, NFS, Redis, or exposed web directories.

Mandatory review triggers:

- Extensions: `.txt`, `.log`, `.conf`, `.cfg`, `.ini`, `.env`, `.bak`, `.old`.
- Names: `note`, `readme`, `todo`, `hint`, `backup`, `users`, `creds`, `credentials`, `password`, `secret`, `token`, `key`, `admin`, `config`, `db`, `database`, `dump`, `private`, `internal`, `debug`.
- Paths: `/home`, `/root`, `/var/www`, `/backup`, `/config`, `/admin`, `/private`, `/tmp`, `/opt`, application directories, FTP roots, SMB shares, exposed web directories.

Extract usernames, emails, internal hosts/IPs/URLs, ports, paths, database strings, commands, deployment notes, debug traces, private keys, hashes, JWTs, bearer tokens, cloud keys, and proof-like sensitive values. Redact passwords, tokens, API keys, private key bodies, and proof-like values in UI/report; raw content stays only in local artifact files.

## Completion Gate

Report generation is not a registered tool. `ReconOrchestrator.run()` calls `Reporter` only when:

- Port profile completed.
- HTTP-like service follow-up completed for the currently scheduled web target or has evidence-based skips.
- Non-web service checks and supported deep probes completed under current global tool-name dedup limits.
- All interesting artifacts discovered by runtime are saved/indexed.
- All suspicious readable text artifacts are reviewed or have explicit blocked-analysis findings.
- Findings have evidence and ranked next actions.

## References And Scripts

- `references/tooling.md`
- `references/playbook.md`
- `references/scoring.md`
- `references/web-surface.md`
- `references/non-web-surface.md`
- `references/artifact-interest.md`
- `references/report-template.md`
- `scripts/register_tools.py`
- `scripts/artifact_interest.py`
- `scripts/web_download_interesting.py`
- `scripts/ftp_deep.py`
- `scripts/smb_deep.py`
