#!/usr/bin/env python3
"""Download one interesting web URL and emit artifact JSON."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from artifact_interest import classify, should_download


def safe_name(value: str) -> str:
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in value)[:120] or "artifact"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--output-dir", required=True)
    args = ap.parse_args()

    category, reason, score = classify(args.url)
    if not should_download(args.url):
        print(json.dumps({"artifacts": [], "skipped": reason or "not interesting", "score": score}))
        return 0

    req = Request(args.url, headers={"User-Agent": "ai-recon-agent/ctf"})
    with urlopen(req, timeout=20) as resp:
        data = resp.read(10 * 1024 * 1024 + 1)
        final_url = resp.geturl()
    if len(data) > 10 * 1024 * 1024:
        print(json.dumps({"artifacts": [], "skipped": "file too large"}))
        return 0

    root = Path(args.output_dir) / "artifacts" / safe_name(category or "web")
    root.mkdir(parents=True, exist_ok=True)
    path_part = os.path.basename(urlparse(final_url).path) or "index.html"
    digest = hashlib.sha256(data).hexdigest()
    local = root / f"{digest[:12]}_{safe_name(path_part)}"
    local.write_bytes(data)
    item = {
        "source": final_url,
        "local_path": str(local),
        "category": category or "web",
        "service": "web",
        "reason": reason,
        "size": len(data),
        "sha256": digest,
    }
    print(json.dumps({"artifacts": [item]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
