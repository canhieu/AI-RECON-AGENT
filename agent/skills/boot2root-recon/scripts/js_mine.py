#!/usr/bin/env python3
"""Static JS endpoint/secret/source-map miner. No eval."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urljoin
from urllib.request import Request, urlopen

ENDPOINT_RE = re.compile(r"(?:https?://[^\s'\"<>`]+|['\"](/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{2,})['\"])")
SECRET_PATTERNS = {
    "generic_token": re.compile(r"(?i)(api[_-]?key|token|secret|bearer|authorization)['\"\s:=]{0,12}([A-Za-z0-9._\-]{16,})"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
}
SM_RE = re.compile(r"//# sourceMappingURL=([^\s]+)")


def fetch(url: str, limit: int = 4_000_000) -> bytes:
    req = Request(url, headers={"User-Agent": "ai-recon-agent"})
    with urlopen(req, timeout=12) as resp:
        return resp.read(limit + 1)[:limit]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--download-maps", action="store_true")
    args = ap.parse_args()
    js_root = Path(args.output_dir) / "artifacts" / "js"
    js_root.mkdir(parents=True, exist_ok=True)
    endpoints = set()
    secrets = []
    source_maps = []
    artifacts = []
    for path in sorted(set(js_root.glob("*.js")) | set(js_root.glob("*.beautified.js"))):
        src = path.read_text("utf-8", "ignore")
        for m in ENDPOINT_RE.finditer(src):
            endpoints.add(m.group(0).strip("'\"") if m.group(0).startswith("http") else urljoin(args.target, m.group(1) or ""))
        for name, pat in SECRET_PATTERNS.items():
            for m in pat.finditer(src):
                val = m.group(0)[:200]
                secrets.append({"file": str(path), "type": name, "match": val})
        for m in SM_RE.finditer(src):
            sm_url = urljoin(args.target, m.group(1))
            source_maps.append({"file": str(path), "url": sm_url})
            if args.download_maps:
                try:
                    data = fetch(sm_url)
                    sha = hashlib.sha256(data).hexdigest()
                    out = js_root / f"sourcemap_{sha[:12]}.map"
                    out.write_bytes(data)
                    artifacts.append({"source": sm_url, "local_path": str(out), "category": "source", "service": "web", "reason": "javascript source map", "size": len(data), "sha256": sha})
                except Exception:
                    pass
    print(json.dumps({"endpoints": sorted(endpoints)[:500], "secrets": secrets[:200], "source_maps": source_maps[:100], "artifacts": artifacts}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
