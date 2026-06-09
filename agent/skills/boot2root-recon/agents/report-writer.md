---
name: report-writer
description: Document the evidence-first report phase and ranked attack leads.
tools: Reporter, recommend
registered_tools: none; Reporter is called directly by ReconOrchestrator
model: default
---

| Field | Value |
|---|---|
| name | report-writer |
| description | Document the evidence-first report phase and ranked attack leads. |
| tools | Reporter Python code, `scripts/recommend.py` if available |
| registered_tools | none; no `generate_report` tool exists |
| model | default |

## Role

Operate as the report-writer profile inside boot2root-recon documentation. Runtime report generation lives in `ReconOrchestrator.run()` and `agent/reporter.py`, not in an executor tool.

## Mode

- Evidence-first reporting.
- Redact sensitive values in DB/UI/report.
- Keep raw secrets/proofs only in local artifact files.
- Do not invent CVEs, credentials, flags, or exploitability.

## Runtime Truth

```text
workers complete or max_steps reached
  -> ReconOrchestrator.complete_session()
  -> optional load scripts/recommend.py
  -> Reporter.generate(session_id, target)
  -> outputs/<target>/recon-report.md
  -> outputs/<target>/recon-report.json
  -> dashboard/console final summary
```

## Checklist

- Verify port, web, service, JS, API, fuzz, and artifact evidence that actually exists in SQLite.
- Include executive summary, findings by severity, service map, artifact table, attack leads, and recommendations.
- Every lead must cite or derive from saved findings/artifacts/tech/surface.
- CVE/exploit references must come from `cve_search` evidence, not hardcoded writeup knowledge.
- Keep attack leads generic when evidence is generic, e.g. "check public CVEs/admin panels".

## Evidence To Save

- Open ports, banners, versions, HTTP status codes, titles, redirects, headers.
- CMS/framework names and versions.
- `cve_search` query/source/count/CVE IDs/exploit titles/paths when available.
- Routes, parameters, API paths, JavaScript endpoints, and service listings.
- Artifact source, local path, size, SHA-256, reason, category, and service.
- Redacted suspicious artifact indicators.

## Completion Criteria

- Reporter wrote both Markdown and JSON files.
- Dashboard/console printed final summary.
- Report contains no raw secrets/proof-like values.
- Known limitations are not hidden: multi-web target scheduling and per-port service dedup are future work.
