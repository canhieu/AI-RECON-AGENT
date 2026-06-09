#!/usr/bin/env python3
"""
CLI - fullscreen Textual UI with scrollable logs.
"""

import os
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Optional

from rich.console import Console
from rich.table import Table

try:
    from textual.app import App as TextualApp, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.widgets import Footer, Header, RichLog, Static
    HAS_TEXTUAL = True
except Exception:  # pragma: no cover - fallback for missing optional UI dep
    TextualApp = object
    HAS_TEXTUAL = False
    ComposeResult = None
    Horizontal = Vertical = Footer = Header = RichLog = Static = None


class ReconDashboard(TextualApp if HAS_TEXTUAL else object):
    CSS = """
    Screen {
        background: #071013;
    }
    #root {
        height: 100%;
    }
    #top {
        height: 7;
        border: round #2dd4bf;
        padding: 0 1;
    }
    #main {
        height: 1fr;
    }
    #activity_box {
        width: 2fr;
        border: round #38bdf8;
        padding: 0 1;
    }
    #agent_box {
        width: 1fr;
        border: round #84cc16;
        padding: 0 1;
    }
    #activity, #agentlog {
        height: 1fr;
        scrollbar-size-vertical: 1;
    }
    .box_title {
        text-style: bold;
        color: #e5e7eb;
    }
    """
    BINDINGS = [
        ("tab", "focus_next", "Next panel"),
        ("shift+tab", "focus_previous", "Prev panel"),
        ("q", "quit_when_idle", "Quit when complete"),
    ]

    def __init__(self, *, ready: threading.Event):
        super().__init__()
        self.ready = ready
        self.progress = ""
        self.agent = ""
        self.scan_active = True
        self.completed = threading.Event()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="root"):
            yield Static("Starting...", id="top")
            with Horizontal(id="main"):
                with Vertical(id="activity_box"):
                    yield Static("Agent Activity (mouse wheel / PgUp / PgDn / arrows)", classes="box_title")
                    yield RichLog(id="activity", markup=True, wrap=True, auto_scroll=True, max_lines=5000)
                with Vertical(id="agent_box"):
                    yield Static("Agent / Findings (Tab focus, scrollable)", classes="box_title")
                    yield RichLog(id="agentlog", markup=True, wrap=True, auto_scroll=True, max_lines=5000)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#activity", RichLog).focus()
        self.ready.set()

    def set_progress(self, text: str) -> None:
        self.progress = text
        self.query_one("#top", Static).update(text)

    def write_activity(self, text: str) -> None:
        self.query_one("#activity", RichLog).write(text)

    def set_agent(self, text: str) -> None:
        self.agent = text
        log = self.query_one("#agentlog", RichLog)
        log.clear()
        log.write(text)

    def write_agent(self, text: str) -> None:
        self.query_one("#agentlog", RichLog).write(text)

    def mark_complete(self, message: str = "Scan complete. Press q to quit.") -> None:
        self.scan_active = False
        self.completed.set()
        self.query_one("#top", Static).update(f"{self.progress}\n[bold green]{message}[/bold green]")
        self.notify(message, timeout=4)

    def action_quit_when_idle(self) -> None:
        if self.scan_active:
            self.notify("Scan still running. q disabled until complete.", timeout=2)
            return
        self.exit()


class ConsoleUI:
    """Console/Textual adapter used by orchestrator without UI-specific logic."""

    def __init__(self, verbose: bool = False):
        self.console = Console()
        self.verbose = verbose
        self.target = ""
        self.max_steps = 0
        self.current_step = 0
        self.current_tool = "idle"
        self.current_target = ""
        self.status = "idle"
        self.last_result = ""
        self.last_error = ""
        self.started_at = time.time()
        self.findings = []
        self.analyses = []
        self.worker_status = {}
        self.worker_labels = {}
        self._last_worker_activity = {}
        self.log_path = ""
        self.app: Optional[ReconDashboard] = None
        self.thread: Optional[threading.Thread] = None
        self._worker_error: Optional[BaseException] = None
        self.ready = threading.Event()
        self.textual_enabled = HAS_TEXTUAL
        self._complete_report_paths: Optional[dict] = None
        self._final_summary_text = ""

    def set_log_path(self, path: str):
        self.log_path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("AI Recon Agent live activity\n")

    def _plain(self, text: str) -> str:
        # Strip Rich markup tags without deleting literal list/dict evidence like [] or ['port'].
        return re.sub(r"\[/?(?:bold|dim|italic|underline|red|green|yellow|blue|cyan|magenta|white|black)(?:\s+[^\]]+)?\]|\[/\]", "", text)

    def _append_log(self, text: str):
        if not self.log_path:
            return
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(self._plain(text) + "\n")

    def _elapsed(self) -> str:
        seconds = int(time.time() - self.started_at)
        mins, secs = divmod(seconds, 60)
        return f"{mins:02d}:{secs:02d}"

    def _progress_bar(self) -> str:
        if not self.max_steps:
            return "[----------] 0%"
        pct = min(1.0, self.current_step / self.max_steps)
        filled = int(pct * 30)
        bar = "#" * filled + "-" * (30 - filled)
        return f"[{bar}] {int(pct * 100)}%"

    def _progress_text(self) -> str:
        lines = [
            "[bold cyan]AI Recon Agent[/bold cyan]",
            f"[yellow]Target[/yellow]: {self.target}",
            f"Step: {self.current_step}/{self.max_steps}  [green]{self._progress_bar()}[/green]",
            f"Status: {self.status}  Elapsed: {self._elapsed()}",
            f"Current: {self.current_tool} -> {self.current_target or self.target}",
        ]
        if self.log_path:
            lines.append(f"Full log: {self.log_path}")
        return "\n".join(lines)

    def _agent_text(self) -> str:
        lines = [
            "[bold]Mode[/bold]: recon",
            f"[bold]Tool[/bold]: {self.current_tool}",
            f"[bold]Target[/bold]: {self.current_target or self.target}",
            f"[bold]Findings[/bold]: {len(self.findings)}",
            "[bold]Style[/bold]: caveman",
        ]
        if self.last_result:
            lines.extend(["", f"[bold]Last[/bold]: {self.last_result}"])
        if self.last_error:
            lines.extend(["", f"[red]Error[/red]: {self.last_error}"])
        if self.worker_status:
            lines.extend(["", "[bold]Workers[/bold]"])
            for name, status in self.worker_status.items():
                label = self.worker_labels.get(name, name)
                lines.append(f"{label}: {status}")
        if self.analyses:
            lines.extend(["", "[bold]Latest analysis[/bold]"])
            lines.extend(self.analyses[-6:])
        if self.findings:
            lines.extend(["", "[bold]Latest findings[/bold]"])
            lines.extend(self.findings[-12:])
        return "\n".join(lines)

    def _call(self, method: str, *args):
        if not self.app:
            return
        try:
            fn = getattr(self.app, method)
            self.app.call_from_thread(fn, *args)
        except Exception:
            pass

    def _refresh(self):
        if self.app:
            self._call("set_progress", self._progress_text())
            self._call("set_agent", self._agent_text())
        else:
            self.console.print(self._plain(self._progress_text()))

    def _push_activity(self, text: str):
        now = time.strftime("%H:%M:%S")
        line = f"[dim]{now}[/dim] {text}"
        self._append_log(f"{now} {text}")
        if self.app:
            self._call("write_activity", line)
        else:
            self.console.print(self._plain(line))

    def run_textual(self, worker):
        if (
            not self.textual_enabled
            or os.getenv("AI_RECON_TUI", "1") == "0"
            or not sys.stdin.isatty()
            or not sys.stdout.isatty()
        ):
            return worker()

        result = {"value": None, "complete_shown": False}
        self.ready.clear()
        app = ReconDashboard(ready=self.ready)
        self.app = app

        def runner():
            self.ready.wait(timeout=5)
            try:
                result["value"] = worker()
            except BaseException as exc:
                self._worker_error = exc
            finally:
                if self._worker_error is None:
                    try:
                        app.call_from_thread(app.mark_complete)
                    except Exception:
                        pass
                else:
                    try:
                        app.call_from_thread(app.exit)
                    except Exception:
                        pass

        worker_thread = threading.Thread(target=runner, name="recon-worker", daemon=True)
        self.thread = worker_thread
        worker_thread.start()
        app.run(mouse=True)
        if app.completed.is_set():
            result["complete_shown"] = True
        if worker_thread.is_alive():
            worker_thread.join(timeout=2)
        self.app = None
        self.thread = None
        if self._worker_error:
            exc = self._worker_error
            self._worker_error = None
            raise exc
        if result["complete_shown"] and self._complete_report_paths:
            self.console.print()
            self._print_complete_table(self._complete_report_paths)
        return result["value"]

    def show_banner(self, target: str, max_steps: int):
        self.target = target
        self.max_steps = max_steps
        self.current_step = 0
        self.current_tool = "idle"
        self.current_target = target
        self.status = "starting"
        self.last_result = ""
        self.last_error = ""
        self.started_at = time.time()

        self._refresh()
        self._push_activity("Session start")

    def show_step(self, step: int, total: int, skill: str = "recon"):
        self.current_step = step
        self.max_steps = total
        self.status = "deciding next tool"
        self._refresh()
        self._push_activity(f"Step {step}/{total}: decide next tool")

    def init_workers(self, workers):
        self.worker_status = {}
        self.worker_labels = {}
        self._last_worker_activity = {}
        for worker in workers:
            name = getattr(worker, "name", str(worker))
            label = getattr(worker, "label", f"{name.title()} Agent")
            self.worker_status[name] = "pending"
            self.worker_labels[name] = label
        self._refresh()
        if self.worker_status:
            labels = ", ".join(self.worker_labels[name] for name in self.worker_status)
            self._push_activity(f"Agents ready: {labels}")

    def show_worker(self, worker: str, status: str, label: Optional[str] = None):
        if label:
            self.worker_labels[worker] = label
        label = self.worker_labels.get(worker, worker)
        if self.worker_status.get(worker) == status:
            self._refresh()
            return
        self.worker_status[worker] = status
        self._refresh()
        activity = f"{label}: {status}"
        if self._last_worker_activity.get(worker) != activity:
            self._last_worker_activity[worker] = activity
            self._push_activity(activity)

    def show_tool(self, tool: str, target: str):
        self.current_tool = tool or "unknown"
        self.current_target = target or self.target
        self.status = "running tool"
        self.last_result = ""
        self.last_error = ""
        self._refresh()
        self._push_activity(f"Run [bold]{self.current_tool}[/bold] -> {self.current_target}")

    def show_result(self, result: dict):
        ok = bool(result.get("success"))
        status = "OK" if ok else "FAIL"
        runtime = result.get("runtime", 0)
        self.status = f"tool {status}"
        self.last_result = f"{self.current_tool}: {status} ({runtime}s)"
        if not ok:
            self.last_error = str(result.get("error", "?"))
        self._refresh()
        self._push_activity(f"{self.current_tool}: [{'green' if ok else 'red'}]{status}[/] ({runtime}s)")

        if self.verbose and result.get("parsed"):
            self._push_activity(f"Parsed: {str(result['parsed'])[:500]}")

        if result.get("waf_detected"):
            self._push_activity(f"[yellow]WAF detected: {result['waf_detected']}[/yellow]")

    def show_analysis(self, tool: str, target: str, analysis: dict, result: Optional[dict] = None):
        severity = str(analysis.get("severity") or "info").lower()
        summary = str(analysis.get("summary") or f"Ran {tool} on {target}")[:300]
        hv = analysis.get("high_value_targets") or []
        tech = analysis.get("tech_discovered") or []
        services = analysis.get("service_detected") or []
        evidence = analysis.get("evidence") or ""
        if isinstance(evidence, list):
            evidence = "; ".join(str(x) for x in evidence[:4])
        evidence = str(evidence).replace("\n", " | ")[:240]
        line = f"{tool} [{severity}]: {summary}"
        extras = []
        if hv:
            extras.append("targets=" + ", ".join(str(x) for x in hv[:3]))
        if tech:
            extras.append("tech=" + ", ".join(str(x.get("name", x)) for x in tech[:3] if isinstance(x, dict)))
        if services:
            extras.append("services=" + ", ".join(f"{x.get('port','?')}/{x.get('service','?')}" for x in services[:4] if isinstance(x, dict)))
        if evidence:
            extras.append("evidence=" + evidence)
        if extras:
            line = f"{line} | " + " | ".join(extras)
        self.analyses.append(line)
        self._append_log(f"ANALYSIS {line}")
        self.status = "analysis ready"
        self._refresh()
        self._push_activity(f"Analysis {tool}: [{severity.upper()}] {summary}")
        if self.app:
            self._call("write_agent", line)

    def show_rtk_savings(self):
        if shutil.which("rtk") is None:
            self._push_activity("RTK token savings: unavailable (rtk not found)")
            return
        try:
            proc = subprocess.run(
                ["rtk", "gain"],
                text=True,
                capture_output=True,
                timeout=8,
                check=False,
            )
        except Exception as exc:
            self._push_activity(f"RTK token savings: unavailable ({exc})")
            return
        out = (proc.stdout or proc.stderr or "").strip()
        saved = re.search(r"Tokens saved:\s+([^\n]+)", out)
        commands = re.search(r"Total commands:\s+([^\n]+)", out)
        if saved:
            msg = f"RTK token savings: {saved.group(1).strip()}"
            if commands:
                msg += f" across {commands.group(1).strip()} commands"
        else:
            msg = "RTK token savings: unavailable"
        self._push_activity(f"[green]{msg}[/green]")

    def show_finding(self, severity: str, summary: str):
        color_map = {
            "critical": "red",
            "high": "yellow",
            "medium": "blue",
            "low": "dim",
            "info": "green",
        }
        color = color_map.get(severity, "white")
        prefix = f"[{severity.upper()}]" if severity else "[FINDING]"
        line = f"[{color}]{prefix}[/{color}] {summary[:240]}"
        self.findings.append(line)
        self._append_log(f"FINDING {prefix} {summary}")
        self.status = "finding saved"
        self._refresh()
        self._push_activity(f"Save finding [{color}]{prefix}[/{color}]")
        if self.app:
            self._call("write_agent", line)

    def print_error(self, msg: str):
        self.last_error = msg
        self.status = "error"
        self._refresh()
        self._push_activity(f"[red]Error:[/red] {msg}")

    def close(self):
        if self.app:
            try:
                self.app.call_from_thread(self.app.exit)
            except Exception:
                pass
            if self.thread and threading.current_thread() is not self.thread:
                self.thread.join(timeout=2)
            self.app = None
            self.thread = None

    def _format_cap_list(self, value) -> list[str]:
        if isinstance(value, dict):
            items = value.get("items") or []
            truncated = int(value.get("truncated") or 0)
            lines = [str(item) for item in items]
            if truncated:
                lines.append(f"... +{truncated} more")
            return lines
        if isinstance(value, list):
            return [str(item) for item in value]
        return []

    def _format_final_summary(self, summary: Optional[dict]) -> str:
        if not summary:
            return ""
        lines = ["[bold green]Final Recon Summary[/bold green]"]
        lines.append(f"Target: {summary.get('target', self.target)}")
        lines.append(f"Findings: {summary.get('findings_total', 0)}")
        counts = summary.get("severity_counts") or {}
        if counts:
            order = ("critical", "high", "medium", "low", "info")
            parts = [f"{key}={counts[key]}" for key in order if key in counts]
            extra = [f"{key}={val}" for key, val in counts.items() if key not in order]
            lines.append("Severity: " + ", ".join(parts + extra))
        ports = self._format_cap_list(summary.get("surface_ports"))
        lines.extend(["", "[bold]Ports / Services[/bold]"])
        lines.extend(ports or ["none found"])
        web = self._format_cap_list(summary.get("web_targets"))
        if web:
            lines.extend(["", "[bold]Web Targets[/bold]"])
            lines.extend(web)
        non_web = self._format_cap_list(summary.get("non_web_services"))
        if non_web:
            lines.extend(["", "[bold]Non-Web Services[/bold]"])
            lines.extend(non_web)
        tech = self._format_cap_list(summary.get("tech"))
        if tech:
            lines.extend(["", "[bold]Tech[/bold]"])
            lines.extend(tech)
        findings = self._format_cap_list(summary.get("top_findings"))
        if findings:
            lines.extend(["", "[bold]High-Value Findings[/bold]"])
            for item in summary.get("top_findings", {}).get("items", []):
                if isinstance(item, dict):
                    lines.append(f"[{str(item.get('severity', 'info')).upper()}] {item.get('tool', '?')}: {item.get('summary', '')}")
                else:
                    lines.append(str(item))
            truncated = int((summary.get("top_findings") or {}).get("truncated") or 0)
            if truncated:
                lines.append(f"... +{truncated} more")
        artifacts = self._format_cap_list(summary.get("artifacts"))
        if artifacts:
            lines.extend(["", f"[bold]Artifacts ({summary.get('artifact_count', len(artifacts))})[/bold]"])
            lines.extend(artifacts)
        report_paths = summary.get("report_paths") or {}
        lines.extend(["", "[bold]Reports[/bold]"])
        if report_paths.get("markdown"):
            lines.append(f"Markdown: {report_paths['markdown']}")
        if report_paths.get("json"):
            lines.append(f"JSON: {report_paths['json']}")
        if summary.get("live_log"):
            lines.append(f"Live log: {summary['live_log']}")
        lines.append("")
        lines.append("[bold green]Complete.[/bold green]")
        return "\n".join(lines)

    def _print_complete_table(self, report_paths: dict):
        table = Table(title="Session Complete", border_style="green")
        table.add_column("Report", style="cyan")
        table.add_column("Path", style="white")
        if "markdown" in report_paths:
            table.add_row("Markdown", report_paths["markdown"])
        if "json" in report_paths:
            table.add_row("JSON", report_paths["json"])
        if self.log_path:
            table.add_row("Live log", self.log_path)
        self.console.print(table)

    def show_complete(self, report_paths: dict, summary: Optional[dict] = None):
        self._complete_report_paths = report_paths
        self._final_summary_text = self._format_final_summary(summary)
        self.status = "complete - press q to quit" if self.app else "complete"
        self._refresh()
        self._push_activity("Session complete")
        if self._final_summary_text:
            self._append_log("FINAL SUMMARY\n" + self._final_summary_text)
        if self.app:
            if self._final_summary_text:
                self._call("write_agent", "\n" + self._final_summary_text)
                self._call("write_activity", "[bold green]Final summary ready in Agent / Findings panel[/bold green]")
            self._call("mark_complete", "Scan complete. Press q to quit.")
            return
        self.console.print()
        if self._final_summary_text:
            self.console.print(self._plain(self._final_summary_text))
            self.console.print()
        self._print_complete_table(report_paths)
