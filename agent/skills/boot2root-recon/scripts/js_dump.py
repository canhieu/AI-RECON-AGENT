#!/usr/bin/env python3
"""Static JS downloader from crawl/target URLs. No eval."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

JS_RE = re.compile(r'https?://[^\s"\'<>]+?\.js(?:\?[^\s"\'<>]*)?|["\']([^"\']+?\.js(?:\?[^"\']*)?)["\']', re.I)
SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


def safe_name(url: str) -> str:
    p = urlparse(url)
    base = (p.netloc + p.path).strip("/").replace("/", "_") or "script.js"
    return re.sub(r"[^A-Za-z0-9._-]", "_", base)[:160]


def fetch(url: str, limit: int = 2_000_000) -> bytes:
    req = Request(url, headers={"User-Agent": "ai-recon-agent"})
    with urlopen(req, timeout=12) as resp:
        return resp.read(limit + 1)[:limit]


def discover(base: str, text: str) -> list[str]:
    urls = set()
    for m in SRC_RE.finditer(text):
        urls.add(urljoin(base, m.group(1)))
    for m in JS_RE.finditer(text):
        val = m.group(1) or m.group(0)
        urls.add(urljoin(base, val))
    return sorted(u for u in urls if urlparse(u).scheme in {"http", "https"})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--urls", default="")
    ap.add_argument("--output-dir", required=True)
    args = ap.parse_args()
    root = Path(args.output_dir) / "artifacts" / "js"
    root.mkdir(parents=True, exist_ok=True)
    seeds = [args.target] + [u for u in re.split(r"[\s,]+", args.urls or "") if u]
    js_urls = set(u for u in seeds if urlparse(u).path.lower().endswith(".js"))
    pages = []
    for seed in seeds[:50]:
        try:
            data = fetch(seed).decode("utf-8", "ignore")
        except Exception:
            continue
        pages.append(seed)
        js_urls.update(discover(seed, data))
    artifacts = []
    for url in sorted(js_urls)[:100]:
        try:
            data = fetch(url)
        except Exception:
            continue
        sha = hashlib.sha256(data).hexdigest()
        path = root / f"{safe_name(url)}.{sha[:8]}.js"
        path.write_bytes(data)
        artifacts.append({"source": url, "local_path": str(path), "category": "source", "service": "web", "reason": "javascript discovered from crawl/target", "size": len(data), "sha256": sha})
    print(json.dumps({"pages": pages, "js_urls": sorted(js_urls), "artifacts": artifacts}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
