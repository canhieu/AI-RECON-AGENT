#!/usr/bin/env python3
"""Adaptive ffuf wrapper with short calibration and JSON output."""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import tempfile
import time
import uuid
from collections import Counter


def load_json(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return json.load(fh)
    except Exception:
        return {}


def run_ffuf(args: list[str], timeout: int) -> tuple[int, str, str, float]:
    start = time.time()
    proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, proc.stdout or "", proc.stderr or "", time.time() - start


def dominant(values: list[int], ratio: float = 0.80, min_count: int = 20) -> list[int]:
    if not values:
        return []
    counts = Counter(values)
    total = len(values)
    return sorted(v for v, c in counts.items() if c >= min_count and (c / total) >= ratio)


def ffuf_base(cmd_args: argparse.Namespace, output_path: str, extra: list[str] | None = None) -> list[str]:
    cmd = ["ffuf", "-u", cmd_args.url, "-w", cmd_args.wordlist, "-of", "json", "-o", output_path]
    if cmd_args.header:
        for h in cmd_args.header:
            cmd.extend(["-H", h])
    if cmd_args.extensions:
        cmd.extend(["-e", cmd_args.extensions])
    if cmd_args.recursion:
        cmd.append("-recursion")
        cmd.extend(["-recursion-depth", str(cmd_args.recursion_depth)])
    if cmd_args.match_codes:
        cmd.extend(["-mc", cmd_args.match_codes])
    if cmd_args.filter_codes:
        cmd.extend(["-fc", cmd_args.filter_codes])
    if extra:
        cmd.extend(extra)
    return cmd


def build_filters(results: list[dict]) -> tuple[list[str], dict]:
    lengths = dominant([int(r.get("length") or 0) for r in results if r.get("length") is not None])
    words = dominant([int(r.get("words") or 0) for r in results if r.get("words") is not None])
    lines = dominant([int(r.get("lines") or 0) for r in results if r.get("lines") is not None])
    filters: list[str] = []
    if lengths:
        filters.extend(["-fs", ",".join(map(str, lengths))])
    if words:
        filters.extend(["-fw", ",".join(map(str, words))])
    if lines:
        filters.extend(["-fl", ",".join(map(str, lines))])
    meta = {"dominant_lengths": lengths, "dominant_words": words, "dominant_lines": lines}
    return filters, meta


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--wordlist", required=True)
    p.add_argument("--header", action="append", default=[])
    p.add_argument("--extensions", default="")
    p.add_argument("--recursion", action="store_true")
    p.add_argument("--recursion-depth", default="2")
    p.add_argument("--match-codes", default="")
    p.add_argument("--filter-codes", default="404")
    p.add_argument("--calibration-seconds", type=int, default=6)
    p.add_argument("--max-restarts", type=int, default=3)
    p.add_argument("--timeout", type=int, default=210)
    args = p.parse_args()

    calibration_payloads = [f"__cal_{uuid.uuid4().hex}_{i}__" for i in range(24)]
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as cal_wl:
        cal_wl.write("\n".join(calibration_payloads) + "\n")
        cal_wordlist = cal_wl.name
    calibration = {"seconds": args.calibration_seconds, "max_restarts": args.max_restarts, "runs": []}
    filters: list[str] = []
    final = {}
    stdout = stderr = ""
    rc = 1
    try:
        original_wl = args.wordlist
        args.wordlist = cal_wordlist
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            cal_out = tmp.name
        cal_cmd = ffuf_base(args, cal_out)
        rc_cal, so_cal, se_cal, runtime_cal = run_ffuf(cal_cmd, args.calibration_seconds)
        cal_json = load_json(cal_out)
        os.unlink(cal_out)
        results = cal_json.get("results") or []
        filters, dom = build_filters(results)
        calibration.update(dom)
        calibration["runs"].append({"returncode": rc_cal, "runtime": round(runtime_cal, 2), "result_count": len(results)})
        args.wordlist = original_wl

        for restart in range(args.max_restarts + 1):
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                out = tmp.name
            cmd = ffuf_base(args, out, filters)
            rc, stdout, stderr, runtime = run_ffuf(cmd, args.timeout)
            final = load_json(out)
            os.unlink(out)
            count = len(final.get("results") or [])
            calibration["runs"].append({"restart": restart, "returncode": rc, "runtime": round(runtime, 2), "result_count": count, "filters": filters})
            if rc == 0 or count or restart >= args.max_restarts:
                break
    except subprocess.TimeoutExpired as exc:
        stderr = str(exc)
        rc = 124
    finally:
        try:
            os.unlink(cal_wordlist)
        except OSError:
            pass

    if not isinstance(final, dict):
        final = {}
    final.setdefault("results", [])
    final["calibration"] = calibration
    if stderr and not final.get("stderr"):
        final["stderr"] = stderr[-2000:]
    print(json.dumps(final))
    return 0 if rc in (0, 1) else rc


if __name__ == "__main__":
    raise SystemExit(main())
