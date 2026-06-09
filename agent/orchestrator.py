#!/usr/bin/env python3
"""
Orchestrator - main worker-driven recon loop.

Runtime flow per step:
1. Ask workers, in fixed order, for the next required action.
2. Execute the registered tool through ToolExecutor.
3. Ask the LLM only to analyze tool output, not to choose tools.
4. Save redacted findings, ports, services, tech, artifacts, and action identity.
5. Trigger evidence-based follow-up hooks such as artifact_analyze and cve_search.
6. Generate Markdown/JSON reports directly with Reporter when workers finish or max_steps is reached.
"""

import json
import os
import time
import logging
from collections import Counter
from urllib.parse import urlparse
from typing import Optional

from openai import OpenAI

from state import ReconStateStore
from executor import ToolExecutor
from reporter import Reporter
from cli import ConsoleUI
from skills import list_skills, load_skill_tools, get_skill
from workers import PortWorker, WebWorker, ServiceWorker, ReportWorker
from artifacts import ArtifactStore
from redaction import redact_text, redact_mapping
import importlib.util

logger = logging.getLogger("orchestrator")


class ReconOrchestrator:
    def __init__(
        self,
        target: str,
        max_steps: int = 50,
        passive_only: bool = False,
        no_service: bool = False,
        verbose: bool = False,
        resume_session_id: Optional[str] = None,
        config: Optional[dict] = None,
    ):
        self.target = target
        self.max_steps = max_steps
        self.passive_only = passive_only
        self.no_service = no_service
        self.verbose = verbose

        # Config
        self.config = config or self._load_config()

        # Output dir
        safe_target = target.replace("/", "_").replace(":", "_")
        self.output_dir = os.path.join("outputs", safe_target)
        os.makedirs(self.output_dir, exist_ok=True)
        self.artifacts = ArtifactStore(self.output_dir)

        # State
        db_path = os.path.join(self.output_dir, "recon.db")
        self.state = ReconStateStore(db_path)

        # Session
        if resume_session_id:
            self.session_id = resume_session_id
            session = self.state.get_session(resume_session_id)
            if not session:
                raise ValueError(f"Session not found: {resume_session_id}")
        else:
            self.session_id = self.state.create_session(target, max_steps)

        # Executor
        self.executor = ToolExecutor(config={
            "max_output_chars": self.config.get("executor", {}).get("max_output_chars", 5000)
        })

        # Register tools from all discovered skills
        for name in list_skills():
            load_skill_tools(name, self.executor)

        # LLM client
        self.llm = OpenAI(
            api_key=os.getenv("SHINE_API_KEY"),
            base_url=os.getenv("SHINE_BASE_URL", "https://api.shineshop.dev/v1"),
        )

        # Models
        self.model_decision = self.config.get("orchestrator", {}).get("model_decision", "codex/gpt5.5")
        self.model_analysis = self.config.get("orchestrator", {}).get("model_analysis", "codex/gpt-5.4-mini")

        # CLI
        self.ui = ConsoleUI(verbose=verbose)
        self.ui.set_log_path(os.path.join(self.output_dir, "live-activity.log"))

        # System prompt
        self.system_prompt = self._load_system_prompt()

        # Sequential manager/worker model. Workers propose required actions;
        # manager executes, asks LLM for analysis only, and saves state.
        self.workers = [
            PortWorker(self),
            WebWorker(self),
            ServiceWorker(self),
            ReportWorker(self),
        ]
        self.worker_labels = {
            "port": "Port Agent",
            "web": "Web Agent",
            "service": "Service Agent",
            "report": "Report Agent",
        }

    def _load_config(self) -> dict:
        import yaml
        try:
            with open("config/settings.yaml") as f:
                return yaml.safe_load(f) or {}
        except FileNotFoundError:
            return {}

    def _load_system_prompt(self) -> str:
        try:
            with open("AGENT.md") as f:
                return f.read()
        except FileNotFoundError:
            return "You are a recon agent."

    # --- Main Loop ---

    def run(self) -> Optional[dict]:
        self.ui.show_banner(self.target, self.max_steps)
        if hasattr(self.ui, "init_workers"):
            self.ui.init_workers(self.workers)
        if hasattr(self.ui, "show_rtk_savings"):
            self.ui.show_rtk_savings()

        all_tools = self.executor.list_tools()

        try:
            done = False
            while not done:
                step = self.state.get_session(self.session_id)["steps"]
                if step >= self.max_steps:
                    logger.info("Max steps reached")
                    break

                self.state.increment_steps(self.session_id)
                self.ui.show_step(step + 1, self.max_steps)

                # Tool choice is deterministic: workers encode the required
                # recon order and return a tool/target/params action.
                forced = self._next_required_action()
                if forced:
                    decision = forced
                else:
                    logger.info("Required worker flow complete")
                    break

                # Legacy guard: old prompts could ask for generate_report, but
                # current reports are created directly after workers are done.
                if decision.get("tool") == "generate_report":
                    forced = self._next_required_action()
                    if not forced:
                        break
                    decision = forced

                tool = decision.get("tool")
                target = decision.get("target", "")
                params = decision.get("params", {})
                if tool in {"web_download_interesting", "ftp_deep", "smb_deep", "js_dump", "js_deobfuscate", "js_mine"}:
                    params.setdefault("output_dir", self.output_dir)

                if tool and tool not in all_tools:
                    logger.warning("Unknown tool: %s", tool)
                    self.ui.print_error(f"Unknown tool: {tool}")
                    continue

                self.ui.show_tool(tool, target)

                result = self.executor.run(tool, target=target, **params)

                self.ui.show_result(result)

                analysis = self._llm_analysis(result, tool, target)

                if analysis:
                    if hasattr(self.ui, "show_analysis"):
                        self.ui.show_analysis(tool, target, analysis, result)
                    self._save_analysis(analysis, tool, target, result)
                self.mark_action_done(tool, target, params)

                done = decision.get("done", False)
                time.sleep(0.5)
        except Exception:
            self.ui.close()
            raise

        self.state.complete_session(self.session_id)

        recommend_fn = None
        skill = get_skill("boot2root-recon")
        if skill:
            rec_path = os.path.join(skill["path"], "scripts", "recommend.py")
            if os.path.isfile(rec_path):
                try:
                    spec = importlib.util.spec_from_file_location("skill_recommend", rec_path)
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    if hasattr(mod, "generate_recommendations"):
                        recommend_fn = mod.generate_recommendations
                except Exception:
                    pass

        if hasattr(self.ui, "show_worker"):
            self.ui.show_worker("report", "generating report", self.worker_labels.get("report", "Report Agent"))
        reporter = Reporter(self.state, self.output_dir, recommend_fn=recommend_fn)
        report_paths = reporter.generate(self.session_id, self.target)
        if hasattr(self.ui, "show_worker"):
            self.ui.show_worker("report", "done", self.worker_labels.get("report", "Report Agent"))
        summary = self._build_final_summary(report_paths)

        self.ui.show_complete(report_paths, summary)
        return report_paths


    def _cap_list(self, items: list, limit: int = 8) -> dict:
        clean = [item for item in items if item]
        return {"items": clean[:limit], "total": len(clean), "truncated": max(0, len(clean) - limit)}

    def _build_final_summary(self, report_paths: dict) -> dict:
        findings = self.state.get_all_findings(self.session_id)
        counts = self.state.count_by_severity(self.session_id)
        surface = self.state.get_surface_summary(self.session_id)
        artifacts = self.state.get_artifacts(self.session_id)
        tech = self.state.get_tech_summary(self.session_id)
        web_targets = self._web_targets()
        non_web = self._non_web_ports() if not self.no_service else []

        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        ranked = sorted(
            findings,
            key=lambda f: (severity_rank.get(str(f.get("severity", "info")).lower(), 5), str(f.get("created_at") or "")),
        )
        high_value = []
        seen = set()
        for item in ranked:
            sev = str(item.get("severity") or "info").lower()
            text = str(item.get("summary") or "").strip()
            if sev not in {"critical", "high"} and not any(
                word in text.lower() for word in ("credential", "flag", "secret", "admin", "config", "database", "artifact")
            ):
                continue
            key = (sev, item.get("tool"), text)
            if key in seen:
                continue
            seen.add(key)
            high_value.append({"severity": sev, "tool": item.get("tool", ""), "summary": text})

        services = []
        for item in surface.get("items", []):
            port = item.get("port")
            service = item.get("service") or "unknown"
            services.append(f"{port}/{service}" if port else service)

        artifact_rows = []
        for item in artifacts:
            label = item.get("category") or "artifact"
            path = item.get("local_path") or ""
            size = item.get("size") or 0
            artifact_rows.append(f"{label}: {path} ({size} bytes)")

        return {
            "target": self.target,
            "findings_total": len(findings),
            "severity_counts": counts,
            "surface_ports": self._cap_list(services, 12),
            "web_targets": self._cap_list(web_targets, 8),
            "non_web_services": self._cap_list(
                [f"{i.get('port')}/{i.get('service') or 'unknown'}" for i in non_web], 10
            ),
            "tech": self._cap_list([x.strip() for x in tech.split(",") if x.strip()], 10),
            "top_findings": self._cap_list(high_value, 8),
            "artifacts": self._cap_list(artifact_rows, 8),
            "artifact_count": len(artifacts),
            "report_paths": report_paths,
            "live_log": self.ui.log_path,
            "service_counts": dict(Counter(str(i.get("service") or "unknown") for i in surface.get("items", []))),
        }

    # --- Recon Policy Helpers ---

    # ── Recon phases ──────────────────────────────────────────────
    WEB_CHAIN = ["httpx", "curl_headers", "cms_detect", "katana", "js_dump", "js_deobfuscate", "js_mine"]
    FUZZ_CHAIN = ["ffuf_dir", "ffuf_recursive", "ffuf_ext"]
    CMS_FOLLOW_CHAIN = ["cms_detect"]
    DEEP_CHAIN = ["arjun", "web_download_interesting", "nuclei_general"]
    PASSIVE_TOOLS = ["whois", "dig", "crt_sh", "subfinder"]

    def _clean_target_host(self, target: str) -> str:
        value = str(target or self.target).strip()
        if "://" in value:
            parsed = urlparse(value)
            value = parsed.hostname or value
        value = value.split("/", 1)[0]
        if value.count(":") == 1 and value.rsplit(":", 1)[1].isdigit():
            value = value.rsplit(":", 1)[0]
        return value.strip("[]")

    def _is_domain(self, host: str) -> bool:
        return "." in host and not host.replace(".", "").isdigit()

    def _web_targets(self) -> list[str]:
        surface = self.state.get_surface_summary(self.session_id)
        host = self._clean_target_host(self.target)
        targets = []
        for item in surface.get("items", []):
            port = int(item.get("port") or 0)
            service = (item.get("service") or "").lower()
            if port in (80, 443, 8080, 8000, 8443, 8888) or service.startswith("http"):
                scheme = "https" if port in (443, 8443) or "ssl" in service or service == "https" else "http"
                suffix = "" if (scheme == "http" and port == 80) or (scheme == "https" and port == 443) else f":{port}"
                targets.append(f"{scheme}://{host}{suffix}")
        return list(dict.fromkeys(targets))

    def _non_web_ports(self) -> list[dict]:
        surface = self.state.get_surface_summary(self.session_id)
        results = []
        WEB_PORTS = {80, 443, 8080, 8000, 8443, 8888}
        for item in surface.get("items", []):
            port = int(item.get("port") or 0)
            service = (item.get("service") or "").lower()
            if port not in WEB_PORTS and not service.startswith("http"):
                results.append(item)
        return results

    def _used_tools(self) -> set[str]:
        return {f.get("tool", "") for f in self.state.get_all_findings(self.session_id)}

    def action_key(self, tool: str, target: str = "", params: Optional[dict] = None) -> str:
        """Build exact action identity for tools that run multiple times.

        Tool-name-only dedup would skip valid second passes such as cms_detect
        with paths, curl_body on many directories, or cve_search per version.
        """
        params_json = json.dumps(params or {}, sort_keys=True, default=str)
        return f"{tool}|{target or ''}|{params_json}"

    def action_done(self, tool: str, target: str = "", params: Optional[dict] = None) -> bool:
        return self.state.has_tool_action(self.session_id, self.action_key(tool, target, params))

    def mark_action_done(self, tool: str, target: str = "", params: Optional[dict] = None):
        self.state.add_tool_action(self.session_id, self.action_key(tool, target, params), tool, target, params or {})

    def _get_redirect_domain(self) -> Optional[str]:
        import re
        for f in self.state.get_all_findings(self.session_id):
            if f.get("tool") == "redirect_check":
                ev = (f.get("evidence") or "") + "\n" + (f.get("detail") or "")
                # Raw output has REDIRECT:URL format
                m = re.search(r'REDIRECT:https?://([^/\s?]+)', ev)
                if m:
                    d = m.group(1).lower().removeprefix("www.")
                    if "." in d and not d.replace(".", "").isdigit():
                        return d
        return None

    def _resolve_domain(self, domain: str) -> bool:
        try:
            import socket
            socket.getaddrinfo(domain, 80, socket.AF_INET, socket.SOCK_STREAM)
            return True
        except Exception:
            return False

    def _crawl_urls(self, base_url: str) -> list[str]:
        import re
        urls = []
        for f in self.state.get_all_findings(self.session_id):
            if f.get("tool") not in {"katana", "ffuf_dir", "ffuf_recursive", "ffuf_ext"}:
                continue
            blob = "\n".join(str(f.get(k) or "") for k in ("summary", "detail", "evidence"))
            urls.extend(re.findall(r'https?://[^\s"\'<>]+', blob))
            for path in re.findall(r'(?<![A-Za-z0-9_])/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+', blob):
                urls.append(base_url.rstrip("/") + "/" + path.lstrip("/"))
        return list(dict.fromkeys(u.rstrip('.,;\"\'') for u in urls))[:200]

    def _next_interesting_web_url(self, base_url: str) -> Optional[str]:
        import re
        sensitive = (
            "robots.txt", "sitemap.xml", ".env", "config", "secret", "backup",
            "admin", "login", "db", "sql", "key", "token", "passwd", "shadow",
            "users", "api", "debug", ".git", "server-status"
        )
        candidates = []
        for f in self.state.get_all_findings(self.session_id):
            if f.get("tool") not in {"katana", "ffuf_dir", "ffuf_recursive", "ffuf_ext"}:
                continue
            blob = "\n".join(str(f.get(k) or "") for k in ("summary", "detail", "evidence"))
            candidates.extend(re.findall(r'https?://[^\s"\'<>]+', blob))
            candidates.extend(re.findall(r'(?<![A-Za-z0-9_])/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+', blob))
        for item in candidates:
            url = item if item.startswith("http") else base_url.rstrip("/") + "/" + item.lstrip("/")
            low = url.lower()
            if any(s in low for s in sensitive):
                return url.rstrip('.,;\"\'')
        return None

    def _worker_label(self, worker) -> str:
        return self.worker_labels.get(worker.name, f"{worker.name.title()} Agent")

    def _next_required_action(self) -> Optional[dict]:
        for worker in self.workers:
            action = worker.next_action()
            if action:
                if hasattr(self.ui, "show_worker"):
                    self.ui.show_worker(worker.name, f"running {action.tool}", self._worker_label(worker))
                return action.as_decision()
            if hasattr(self.ui, "show_worker"):
                self.ui.show_worker(worker.name, "done", self._worker_label(worker))
        return None

    # --- LLM Methods ---

    # Legacy decision helpers remain for reference, but run() no longer calls
    # them. Workers now own tool selection; LLM is analysis-only.
    def _build_decision_prompt(self) -> str:
        findings = self.state.get_recent_findings(self.session_id, limit=8)
        tech = self.state.get_tech_summary(self.session_id)
        surface = self.state.get_surface_summary(self.session_id)
        pending = self.state.get_pending_checks(self.session_id)
        tools_list = self.executor.list_tools()

        parts = [
            f"Target: {self.target}",
            f"Step: {self.state.get_session(self.session_id)['steps']}/{self.max_steps}",
        ]

        if pending:
            parts.append("\nPending service checks:")
            for p in pending[:3]:
                parts.append(f"  - {p['service'] or '?'} on {p['host']}:{p['port']}")

        if findings:
            parts.append("\nRecent findings:")
            for f in findings:
                parts.append(f"  [{f['severity']}] {f['tool']} → {f['summary']}")

        if tech:
            parts.append(f"\nTech stack: {tech}")

        web_targets = self._web_targets()
        non_web = self._non_web_ports() if not self.no_service else []
        required_action = self._next_required_action()

        if surface and surface["ports"]:
            parts.append(f"Ports: {', '.join(surface['ports'][:10])}")

        if non_web:
            parts.append("\nNon-web ports pending service checks:")
            for p in non_web[:5]:
                parts.append(f"  - port {p['port']}/{p.get('service','?')}")

        if web_targets:
            parts.append("\nWEB TARGETS from open HTTP ports:")
            for url in web_targets[:5]:
                parts.append(f"  - {url}")

        parts.append("\nRecon phases (orchestrator forces Phase 0→2, LLM free in Phase 3):")
        parts.append("Phase 0: Port discovery — rustscan 1-65535 → nc_scan fallback if needed → nmap -sC -sV on discovered ports only")
        parts.append("Phase 1: Passive recon (domain target) — whois → dig → crt_sh → subfinder")
        parts.append("Phase 2a: Web chain - whatweb -> redirect_check -> hosts_add(optional) -> subfinder(if domain) -> ffuf_vhost(if domain) -> httpx -> curl_headers -> cms_detect -> katana -> js_dump -> js_deobfuscate -> js_mine -> ffuf_dir -> ffuf_recursive -> ffuf_ext -> curl_body(on sensitive paths) -> arjun -> web_download_interesting -> nuclei_general")
        parts.append("Phase 2b: Non-web service checks — smb/ftp/ssh/redis/...")
        parts.append("Phase 3: Deep analysis — nuclei_tech, deeper fuzz, passive enrichment, optional checks")
        parts.append("Phase 4: Report — generate_report + done")

        if required_action:
            parts.append(
                f"\nNEXT REQUIRED ACTION ({required_action.get('reason','?')}): "
                f"run `{required_action['tool']}` on `{required_action['target']}`. "
                "Do NOT generate_report until phases 0-2 are complete."
            )

        parts.append(f"\nAvailable tools ({len(tools_list)} total):")
        parts.append(", ".join(tools_list))

        parts.append("""
\nChoose next action. Return JSON:
{
  "tool": "tool_name",
  "target": "target",
  "params": {},
  "reason": "why this action",
  "done": false
}
Use "tool": "generate_report" to finish only after required port/service/web follow-up is complete.""")
        return "\n".join(parts)

    def _llm_decision(self, prompt: str) -> Optional[dict]:
        try:
            response = self.llm.chat.completions.create(
                model=self.model_decision,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": prompt},
                ],
                temperature=float(
                    self.config.get("orchestrator", {}).get("temperature_decision", 0.0)
                ),
                max_tokens=1024,
                response_format={"type": "json_object"},
                timeout=30,
            )
            raw = response.choices[0].message.content
            return json.loads(raw, strict=False)
        except Exception as e:
            logger.error(f"LLM decision failed: {e}")
            self.ui.print_error(f"LLM decision error: {e}")
            return None

    def _llm_analysis(self, result: dict, tool: str, target: str) -> Optional[dict]:
        prompt = f"""
Tool: {tool}
Target: {target}
Success: {result['success']}
Raw output:
{result.get('raw', '')[:3000]}

Analyze this output. Return JSON. Human-readable fields must be concise caveman style:
{{
  "summary": "1-2 short caveman-style sentences",
  "severity": "critical|high|medium|low|info",
  "tech_discovered": [{{"name": "...", "version": "..."}}],
  "service_detected": [{{"host": "...", "port": 0, "service": "..."}}],
  "high_value_targets": ["..."],
  "evidence": "key lines from raw output"
}}
"""
        try:
            response = self.llm.chat.completions.create(
                model=self.model_analysis,
                messages=[
                    {"role": "system", "content": "You are a security analysis assistant. Return JSON only. Human-readable values must be concise caveman style."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,
                max_tokens=2048,
                response_format={"type": "json_object"},
                timeout=30,
            )
            raw = response.choices[0].message.content
            return json.loads(raw, strict=False)
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return {
                "summary": f"Ran {tool} on {target}",
                "severity": "info",
                "tech_discovered": [],
                "service_detected": [],
                "high_value_targets": [],
                "evidence": result.get("raw", "")[:500],
            }

    # --- Save Results ---

    def _analyze_artifact(self, item: dict):
        """Review saved files locally and store only redacted evidence."""
        path = item.get("local_path", "")
        if not path or "artifact_analyze" not in self.executor.list_tools():
            return
        params = {"path": path}
        if self.action_done("artifact_analyze", path, params):
            return
        result = self.executor.run("artifact_analyze", target=path, **params)
        self.mark_action_done("artifact_analyze", path, params)
        parsed = result.get("parsed") or {}
        if not isinstance(parsed, dict) or not parsed.get("suspicious"):
            return
        severity = parsed.get("risk", "medium") if parsed.get("risk") in {"critical", "high", "medium", "low", "info"} else "medium"
        summary = f"Suspicious artifact reviewed: {os.path.basename(path)}"
        detail = redact_text(json.dumps({k: parsed.get(k) for k in ("path", "risk", "indicators", "size", "sha256")}))
        evidence = redact_text(parsed.get("redacted_preview", ""))
        self.state.add_finding(self.session_id, "recon", "artifact_analyze", severity, summary, detail, evidence)
        self.ui.show_finding(severity, summary)

    def _search_cves_for_tech(self, tech: dict):
        """Run generic CVE/exploit lookup for evidence-backed versions.

        This intentionally uses the local cve_search tool/searchsploit instead
        of report-time hardcoding, so results stay generic across CTF targets.
        """
        if not isinstance(tech, dict) or "cve_search" not in self.executor.list_tools():
            return
        name = str(tech.get("name") or tech.get("technology") or tech.get("service") or "").strip()
        version = str(tech.get("version") or "").strip()
        if not name or not version or version.lower() in {"unknown", "n/a", "none"} or not any(ch.isdigit() for ch in version):
            return
        target = f"{name} {version}".strip()
        params = {"name": name, "version": version}
        if self.action_done("cve_search", target, params):
            return
        result = self.executor.run("cve_search", target=target, **params)
        self.mark_action_done("cve_search", target, params)
        parsed = result.get("parsed") or {}
        if not isinstance(parsed, dict):
            return
        hits = parsed.get("hits") or []
        if not hits:
            return
        safe_hits = hits[:5]
        summary = f"Public CVE/exploit references found for {target}"
        evidence = redact_text(json.dumps({"query": parsed.get("query"), "count": parsed.get("count"), "cves": parsed.get("cves", [])[:10], "hits": safe_hits}))
        self.state.add_finding(self.session_id, "recon", "cve_search", "medium", summary, json.dumps({"source": parsed.get("source", "searchsploit")}), evidence)
        self.ui.show_finding("medium", summary)

    def _save_analysis(self, analysis: dict, tool: str, target: str, result: Optional[dict] = None):
        severity = analysis.get("severity", "info")
        summary = redact_text(analysis.get("summary", f"Ran {tool} on {target}"))
        detail = redact_text(json.dumps(analysis.get("tech_discovered", [])))
        evidence = analysis.get("evidence", "")
        if isinstance(evidence, list):
            evidence = json.dumps(evidence)
        elif not isinstance(evidence, str):
            evidence = str(evidence)
        evidence = redact_text(evidence)

        self.state.add_finding(
            session_id=self.session_id,
            skill="recon",
            tool=tool,
            severity=severity,
            summary=summary,
            detail=detail,
            evidence=evidence,
        )

        self.ui.show_finding(severity, summary)

        # Parsed port map from tools, independent of LLM analysis.
        parsed = (result or {}).get("parsed") or {}
        parsed_ports = []
        if isinstance(parsed, dict):
            raw_ports = parsed.get("ports", [])
            if isinstance(raw_ports, list):
                parsed_ports = [p for p in raw_ports if isinstance(p, dict)]
        for port_item in parsed_ports:
            if str(port_item.get("state", "open")).lower() != "open":
                continue
            try:
                port = int(port_item.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if not port:
                continue
            self.state.add_surface_item(
                self.session_id,
                host=self._clean_target_host(target),
                port=port,
                protocol=port_item.get("protocol", "tcp"),
                service=port_item.get("service", ""),
            )

        # Artifacts emitted by deep tools.
        if isinstance(parsed, dict):
            artifacts = parsed.get("artifacts", [])
            if isinstance(artifacts, list):
                for item in artifacts:
                    if not isinstance(item, dict) or not item.get("local_path"):
                        continue
                    self.state.add_artifact(self.session_id, item)
                    safe_item = redact_mapping(item)
                    self.state.add_finding(
                        self.session_id,
                        "recon",
                        tool,
                        "high" if item.get("category") in {"flag", "credential", "config", "database"} else "medium",
                        redact_text(f"Artifact saved: {item.get('category', 'artifact')} from {item.get('source', target)}"),
                        json.dumps(safe_item),
                        redact_text(item.get("reason", "interesting exposed artifact")),
                    )
                    self.ui.show_finding("high", f"Artifact saved: {item.get('local_path')}")
                    self._analyze_artifact(item)

        # Prefer parser-extracted CMS/framework evidence even if LLM analysis
        # misses it; parser data also feeds automatic cve_search below.
        parsed_cms = []
        if isinstance(parsed, dict):
            for key in ("cms", "frameworks", "tech_discovered"):
                value = parsed.get(key)
                if isinstance(value, dict):
                    parsed_cms.append(value)
                elif isinstance(value, list):
                    parsed_cms.extend(item for item in value if isinstance(item, dict))

        if parsed_cms:
            existing = analysis.get("tech_discovered", [])
            if not isinstance(existing, list):
                existing = []
            seen_tech = {
                (str(item.get("name", "")).lower(), str(item.get("version", "")))
                for item in existing
                if isinstance(item, dict)
            }
            for item in parsed_cms:
                name = str(item.get("name") or item.get("cms") or item.get("technology") or "").strip()
                version = str(item.get("version") or "").strip()
                if name and (name.lower(), version) not in seen_tech:
                    existing.append({"name": name, "version": version})
                    seen_tech.add((name.lower(), version))
            analysis["tech_discovered"] = existing

            emitted = set()
            for item in parsed_cms:
                name = str(item.get("name") or item.get("cms") or item.get("technology") or "").strip()
                version = str(item.get("version") or "").strip()
                if not name:
                    continue
                key = (name.lower(), version)
                if key in emitted:
                    continue
                emitted.add(key)
                cms_summary = f"CMS/framework version exposed: {name} {version}".strip() if version else f"CMS/framework detected: {name}"
                cms_severity = "medium" if version else "info"
                cms_evidence = item.get("evidence") or item.get("source") or evidence
                if isinstance(cms_evidence, list):
                    cms_evidence = "; ".join(str(x) for x in cms_evidence[:5])
                self.state.add_finding(
                    self.session_id,
                    "recon",
                    "cms_detect",
                    cms_severity,
                    cms_summary,
                    json.dumps(item),
                    str(cms_evidence),
                )
                self.ui.show_finding(cms_severity, cms_summary)

        # Tech stack
        tech_items = analysis.get("tech_discovered", [])
        if not isinstance(tech_items, list):
            tech_items = []
        for tech in tech_items:
            if not isinstance(tech, dict):
                continue
            self.state.update_tech_stack(
                self.session_id, target,
                tech.get("name", ""),
                tech.get("version", ""),
            )
            self._search_cves_for_tech(tech)

        open_ports = set()
        for p in parsed_ports:
            try:
                open_ports.add(int(p.get("port") or 0))
            except (TypeError, ValueError):
                pass

        # Attack surface + service queue
        services = analysis.get("service_detected", [])
        if not isinstance(services, list):
            services = []
        for svc in services:
            if not isinstance(svc, dict):
                continue
            try:
                port = int(svc.get("port") or 0)
            except (TypeError, ValueError):
                continue
            if open_ports and port not in open_ports:
                continue
            service = svc.get("service", "")
            host = svc.get("host", target)
            if port:
                self.state.add_surface_item(
                    self.session_id,
                    host=host,
                    port=port,
                    protocol=svc.get("protocol", "tcp"),
                    service=service,
                )
            if port and not self.no_service:
                self.state.queue_service_check(
                    self.session_id,
                    host=host,
                    port=port,
                    service=service,
                )
