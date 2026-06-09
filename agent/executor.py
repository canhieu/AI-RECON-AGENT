#!/usr/bin/env python3
"""Tool Executor — runs tools as subprocess, parses output, handles errors.

Central execution layer. Tools are registered with:
  - name: unique identifier (e.g. 'nmap', 'curl_body')
  - builder: callable(target, **params) → list[str] (argv)
  - parser: callable(stdout) → dict|list
  - timeout: max execution seconds
  - output_format: 'text', 'json', 'json_lines', 'lines', or custom callable

Builders are the safety boundary: workers pass high-level params, builders
return a validated argv list. No shell=True — only subprocess with argv.

WAF/rate-limit detection: scans tool output for 429, 503, Cloudflare, etc.

Usage:
    executor = ToolExecutor(config={"max_output_chars": 5000})
    executor.register("whois", builder_fn, parser_fn, timeout=15)
    result = executor.run("whois", target="example.com")
    # result == {
    #   "success": True/False, "raw": "...", "parsed": {},
    #   "error": None/"...", "returncode": 0, "runtime": 1.2,
    #   "waf_detected": None/"rate_limit"/"cloudflare"/"waf_block"
    # }
"""

import os
import subprocess
import json
import time
import re
from typing import Optional


class ToolExecutor:
    """Registry + subprocess runner for recon tools.

    Key design:
      - All tools are registered upfront by skill scripts (register_tools.py).
      - Workers never build commands — they request tool+params, executor
        calls the registered builder.
      - Parsers convert stdout to structured dict/list for downstream hooks.
      - Timeout and output truncation prevent runaway/large-output issues.
    """

    def __init__(self, config: Optional[dict] = None):
        """Init executor with empty registry + built-in parsers.

        Args:
            config: Optional dict, supports max_output_chars (default 5000).
        """
        self.config = config or {}
        self._registry = {}
        self._builtin_parsers()

    def _builtin_parsers(self):
        """Register built-in parser callables by format name."""
        self._parsers = {
            "json": self._parse_json,
            "json_lines": self._parse_json_lines,
            "lines": self._parse_lines,
            "text": self._parse_text,
        }

    # --- Registry ---

    def register(self, name: str, builder, parser=None,
                 timeout: int = 120, output_format: str = "text"):
        """Register a tool for later execution.

        Args:
            name: Tool identifier (e.g. 'whois', 'nmap'). Must be unique.
            builder: Callable(target, **params) → list[str] (command argv).
                Must return a list of strings (no shell=True).
            parser: Callable(stdout: str) → dict|list. Optional; falls back
                to built-in parser matching output_format.
            timeout: Max execution time in seconds. Subprocess.TimeoutExpired
                caught and returned as error dict.
            output_format: 'text', 'json', 'json_lines', 'lines', or a custom
                callable with same signature as parser.
        """
        self._registry[name] = {
            "builder": builder,
            "parser": parser or self._parsers.get(output_format, self._parse_text),
            "timeout": timeout,
        }

    def list_tools(self) -> list[str]:
        """Return all registered tool names."""
        return list(self._registry.keys())

    def get_tool(self, name: str) -> Optional[dict]:
        """Look up a tool registration entry.

        Args:
            name: Tool identifier.

        Returns:
            Registration dict with keys: builder, parser, timeout.
            None if not found.
        """
        return self._registry.get(name)

    # --- Execution ---

    def run(self, tool: str, target: str = "", **params) -> dict:
        """Run a registered tool as subprocess.

        Flow:
          1. Lookup tool in registry
          2. Call builder(target, **params) → argv list
          3. Validate argv is list[str]
          4. subprocess.run with capture_output, timeout, extended PATH
          5. Parse stdout via registered parser
          6. Run WAF/rate-limit detection
          7. Return result dict

        Args:
            tool: Registered tool name.
            target: Primary target (domain, IP, URL) passed to builder.
            **params: Additional params forwarded to builder.

        Returns:
            Dict with keys:
              success (bool): returncode == 0
              raw (str): truncated stdout+stderr (max max_output_chars)
              full_raw_length (int): actual output length before truncation
              parsed (dict|list): parser output or {"_parse_error": ...}
              error (str|None): stderr if returncode != 0
              returncode (int): subprocess return code
              runtime (float): wall-clock seconds
              waf_detected (str|None): WAF type if detected
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

        # Execute with custom PATH (go/bin, .local/bin prepended)
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
        """Return raw text as dict. Truncated to 2000 chars."""
        return {"raw": stdout[:2000]}

    def _parse_lines(self, stdout: str) -> list:
        """Split stdout into non-empty stripped lines."""
        return [line.strip() for line in stdout.splitlines()
                if line.strip()]

    def _parse_json(self, stdout: str) -> dict:
        """Parse stdout as single JSON object.

        Returns error dict if JSON invalid.
        """
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {"_parse_error": "invalid JSON"}

    def _parse_json_lines(self, stdout: str) -> list:
        """Parse stdout as newline-delimited JSON (NDJSON).

        Each line is parsed independently; invalid lines are silently skipped.
        """
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
        """Detect WAF, rate limiting, or blocks in tool output.

        Matches known patterns:
          - 429/503 → rate_limit
          - Cloudflare / Attention Required → cloudflare
          - blocked / Access Denied → waf_block

        Args:
            stdout: Full raw output (not truncated).

        Returns:
            WAF type string or None.
        """
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
