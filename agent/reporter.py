#!/usr/bin/env python3
"""
Reporter — generates markdown + JSON reports from findings.
"""

import json
import os
from datetime import datetime
from redaction import redact_text, redact_mapping


class Reporter:
    def __init__(self, state, output_dir: str, recommend_fn=None):
        self.state = state
        self.output_dir = output_dir
        self.recommend_fn = recommend_fn
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, session_id: str, target: str) -> dict:
        findings = self.state.get_all_findings(session_id)
        severity_counts = self.state.count_by_severity(session_id)
        tech = self.state.get_tech_summary(session_id)
        surface = self.state.get_surface_summary(session_id)
        artifacts = self.state.get_artifacts(session_id)

        markdown = self._build_markdown(target, findings, severity_counts, tech, surface, artifacts)
        json_data = self._build_json(target, findings, severity_counts, tech, surface, artifacts)

        md_path = os.path.join(self.output_dir, "recon-report.md")
        json_path = os.path.join(self.output_dir, "recon-report.json")

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(markdown)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=2)

        return {"markdown": md_path, "json": json_path}

    def _build_markdown(self, target, findings, counts, tech, surface, artifacts) -> str:
        lines = [
            f"# Recon Report: {target}",
            f"**Generated**: {datetime.now().isoformat()}",
            "",
            "## Executive Summary",
            f"- **Total findings**: {len(findings)}",
            f"- Critical: {counts['critical']} | High: {counts['high']} | Medium: {counts['medium']} | Low: {counts['low']} | Info: {counts['info']}",
            "",
        ]

        if tech:
            lines.append(f"- **Tech stack**: {tech}")
        if surface and surface["ports"]:
            lines.append(f"- **Open ports**: {', '.join(surface['ports'][:15])}")

        # Findings by severity
        for sev in ["critical", "high", "medium", "low", "info"]:
            sev_findings = [f for f in findings if f["severity"] == sev]
            if not sev_findings:
                continue
            lines.append(f"\n## {sev.upper()} Findings")
            for f in sev_findings:
                lines.append(f"\n### {f['tool']}")
                lines.append(f"- **Summary**: {redact_text(f['summary'])}")
                if f.get("evidence"):
                    lines.append(f"- **Evidence**: `{redact_text(f['evidence'])[:300]}`")
                lines.append(f"- **Time**: {f.get('created_at', '')}")

        if artifacts:
            lines.append("\n## Artifacts")
            lines.append("| Category | Service | Size | Source | Local Path | Reason |")
            lines.append("|---|---:|---:|---|---|---|")
            for item in artifacts:
                safe = redact_mapping(item)
                lines.append(
                    f"| {safe.get('category', '')} | {safe.get('service', '')} | {safe.get('size', 0)} | "
                    f"`{safe.get('source', '')}` | `{safe.get('local_path', '')}` | {safe.get('reason', '')} |"
                )

        leads = self._build_attack_leads(findings, tech, surface, artifacts)
        if leads:
            lines.append("\n## Attack Leads")
            for lead in leads:
                lines.append(f"- **{lead['severity'].upper()}**: {lead['summary']}")

        # Recommendations
        if self.recommend_fn:
            recs = self.recommend_fn(
                {"by_severity": counts, "tech_stack": tech, "ports": surface.get("ports", [])},
                findings
            )
            if recs:
                lines.append("\n## Recommendations")
                for r in recs:
                    lines.append(f"- {r}")

        return "\n".join(lines)

    def _build_attack_leads(self, findings, tech, surface, artifacts) -> list[dict]:
        """Correlate generic next-step leads from saved evidence only.

        Keep this generic: CVE names and exploit references must come from
        cve_search findings, not hardcoded target/writeup knowledge.
        """
        blob = "\n".join(str(x) for x in findings + artifacts).lower() + "\n" + str(tech).lower()
        ports = set(surface.get("ports", []) if surface else [])
        leads = []
        if "cms/framework version exposed" in blob or "cms made simple" in blob or "pluck cms" in blob:
            leads.append({"severity": "medium", "summary": "CMS technology/version found; check public CVEs, admin panels, exposed modules, and login surfaces."})
        if any(str(p).startswith("21/") for p in ports) and "anonymous" in blob:
            leads.append({"severity": "high", "summary": "Anonymous FTP evidence plus open FTP; review downloaded artifacts for credentials or web paths."})
        if "artifact_analyze" in blob and any(x in blob for x in ("credential", "private_key", "connection_string")):
            leads.append({"severity": "high", "summary": "Reviewed artifact contains credential-like data; correlate with SSH/web/CMS/database services."})
        if any(str(p).startswith("6379/") for p in ports) and "redis" in blob:
            leads.append({"severity": "high", "summary": "Redis exposure detected; review INFO/config/key evidence for sensitive data and unsafe deployment."})
        return leads[:8]

    def _build_json(self, target, findings, counts, tech, surface, artifacts) -> dict:
        leads = self._build_attack_leads(findings, tech, surface, artifacts)
        data = {
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "total": len(findings),
                "by_severity": counts,
                "tech_stack": tech,
                "ports": surface.get("ports", []),
            },
            "findings": [
                {
                    "severity": f["severity"],
                    "tool": f["tool"],
                    "summary": redact_text(f["summary"]),
                    "evidence": redact_text(f.get("evidence", "")),
                    "created_at": f.get("created_at", ""),
                }
                for f in findings
            ],
            "artifacts": [redact_mapping(item) for item in artifacts],
            "attack_leads": leads,
        }
        if self.recommend_fn:
            data["recommendations"] = self.recommend_fn(data["summary"], data["findings"])
        return data




