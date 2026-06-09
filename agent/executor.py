#!/usr/bin/env python3
"""
Tool Executor — runs tools as subprocess, parses output, handles errors.

Tool Registry:
- Tools are registered with name, command builder, parser, timeout.
- Skills register their tools via decorator or explicit registration.
- Built-in parsers for common output formats (JSON, JSON lines, lines).

Usage:
    executor = ToolExecutor()
    result = executor.run("whois", target="example.com")
    # result = {success, raw, parsed, error, returncode}
"""

import os
import subprocess
import json
import time
import re
from typing import Optional


class ToolExecutor:
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self._registry = {}
        self._builtin_parsers()

    def _builtin_parsers(self):
        self._parsers = {
            "json": self._parse_json,
            "json_lines": self._parse_json_lines,
            "lines": self._parse_lines,
            "text": self._parse_text,
        }

    # --- Registry ---

    def register(self, name: str, builder, parser=None,
                 timeout: int = 120, output_format: str = "text"):
        """Register a tool.
        Args:
            name: tool identifier (e.g. 'whois', 'nmap')
            builder: callable(target, **params) → list[str] (command)
            parser: callable(stdout: str) → dict|list (optional)
            timeout: max execution seconds
            output_format: 'text', 'json', 'json_lines', 'lines', or custom callable
        """
        self._registry[name] = {
            "builder": builder,
            "parser": parser or self._parsers.get(output_format, self._parse_text),
            "timeout": timeout,
        }

    def list_tools(self) -> list[str]:
        return list(self._registry.keys())

    def get_tool(self, name: str) -> Optional[dict]:
        return self._registry.get(name)

    # --- Execution ---

    def run(self, tool: str, target: str = "", **params) -> dict:
        """Run a registered tool.

        Returns:
            dict with keys: success, raw, parsed, error, returncode, runtime
        """
        entry = self._registry.get(tool)
        if not entry:
            return {
                "success": False,
                "error": f"Unknown tool: {tool}",
                "raw": "", "parsed": {}, "returncode": -1, "runtime": 0
            }

        # Builders are the safety boundary between worker intent and shell
        # execution: workers pass params, builders return argv lists.
        try:
            cmd = entry["builder"](target=target, **params)
        except Exception as e:
            return {
                "success": False,
                "error": f"Command build failed: {e}",
                "raw": "", "parsed": {}, "returncode": -1, "runtime": 0
            }

        # Validate: cmd must be list of strings
        if not isinstance(cmd, list) or not all(isinstance(c, str) for c in cmd):
            return {
                "success": False,
                "error": "Command must be list of strings",
                "raw": "", "parsed": {}, "returncode": -1, "runtime": 0
            }

        # Execute
        env = os.environ.copy()
        env["PATH"] = f"{env.get('HOME', '')}/go/bin:{env.get('HOME', '')}/.local/bin:{env['PATH']}"
        start = time.time()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=entry["timeout"],
                env=env,
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            returncode = result.returncode
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Timeout after {entry['timeout']}s",
                "raw": "", "parsed": {}, "returncode": -1,
                "runtime": time.time() - start
            }
        except FileNotFoundError:
            return {
                "success": False,
                "error": f"Tool not found: {cmd[0]}. Install it first.",
                "raw": "", "parsed": {}, "returncode": -1,
                "runtime": time.time() - start
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "raw": "", "parsed": {}, "returncode": -1,
                "runtime": time.time() - start
            }

        runtime = time.time() - start

        # Parse output. Some tools (nc, nmap warnings) write useful data to stderr.
        max_chars = self.config.get("max_output_chars", 5000)
        combined = stdout if not stderr else f"{stdout}\n{stderr}".strip()
        truncated = combined[:max_chars]

        parsed = {}
        try:
            parsed = entry["parser"](truncated)
        except Exception as e:
            parsed = {"_parse_error": str(e), "_raw_truncated": truncated[:500]}

        # Detect rate limiting / WAF
        waf_detected = self._detect_waf(combined)

        return {
            "success": returncode == 0,
            "raw": truncated,
            "full_raw_length": len(combined),
            "parsed": parsed,
            "error": stderr if returncode != 0 else None,
            "returncode": returncode,
            "runtime": round(runtime, 2),
            "waf_detected": waf_detected,
        }

    # --- Built-in Parsers ---

    def _parse_text(self, stdout: str) -> dict:
        return {"raw": stdout[:2000]}

    def _parse_lines(self, stdout: str) -> list:
        return [line.strip() for line in stdout.splitlines()
                if line.strip()]

    def _parse_json(self, stdout: str) -> dict:
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {"_parse_error": "invalid JSON"}

    def _parse_json_lines(self, stdout: str) -> list:
        results = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results

    # --- WAF / Rate-limit Detection ---

    def _detect_waf(self, stdout: str) -> Optional[str]:
        patterns = [
            (r"429 Too Many Requests", "rate_limit"),
            (r"503 Service Unavailable", "rate_limit"),
            (r"Cloudflare", "cloudflare"),
            (r"Attention Required", "cloudflare"),
            (r"blocked", "waf_block"),
            (r"Access Denied", "waf_block"),
        ]
        for pattern, name in patterns:
            if re.search(pattern, stdout, re.IGNORECASE):
                return name
        return None
