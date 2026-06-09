#!/usr/bin/env python3
"""Static JS beautifier/decoder. No eval."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path


def beautify(src: str) -> str:
    out = []
    indent = 0
    in_str = ""
    esc = False
    for ch in src:
        out.append(ch)
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == in_str:
                in_str = ""
            continue
        if ch in "'\"`":
            in_str = ch
        elif ch in "{[":
            indent += 1; out.append("\n" + "  " * indent)
        elif ch in "}]":
            indent = max(0, indent - 1); out[-1] = "\n" + "  " * indent + ch
        elif ch == ";":
            out.append("\n" + "  " * indent)
    return "".join(out)


def decode_strings(src: str) -> list[dict]:
    decoded = []
    for s in set(re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", src)):
        try:
            raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
            text = raw.decode("utf-8", "ignore")
            if sum(c.isprintable() for c in text) >= 12:
                decoded.append({"encoding": "base64", "input": s[:80], "decoded": text[:500]})
        except Exception:
            pass
    for s in set(re.findall(r"(?:\\x[0-9a-fA-F]{2}){4,}", src)):
        try:
            decoded.append({"encoding": "hex_escape", "input": s[:80], "decoded": bytes.fromhex(s.replace("\\x", "")).decode("utf-8", "ignore")[:500]})
        except Exception:
            pass
    return decoded[:200]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="")
    ap.add_argument("--output-dir", required=True)
    args = ap.parse_args()
    js_root = Path(args.output_dir) / "artifacts" / "js"
    artifacts = []
    decoded_all = []
    for path in js_root.glob("*.js"):
        src = path.read_text("utf-8", "ignore")
        pretty = beautify(src)
        out = path.with_suffix(path.suffix + ".beautified.js")
        out.write_text(pretty, "utf-8")
        sha = hashlib.sha256(pretty.encode()).hexdigest()
        artifacts.append({"source": str(path), "local_path": str(out), "category": "source", "service": "web", "reason": "static javascript beautified", "size": out.stat().st_size, "sha256": sha})
        decoded_all.extend({"file": str(path), **x} for x in decode_strings(src))
    print(json.dumps({"decoded": decoded_all, "artifacts": artifacts}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
