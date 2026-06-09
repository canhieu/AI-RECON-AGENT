#!/usr/bin/env python3
"""Small read-only CMS/framework detector."""

from __future__ import annotations

import argparse
import json
import re
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

TIMEOUT = 4
MAX_BODY = 512 * 1024
MARKER_PATHS = [
    "/wp-login.php",
    "/wp-includes/",
    "/core/CHANGELOG.txt",
    "/CHANGELOG.txt",
    "/administrator/",
    "/media/system/js/core.js",
    "/static/",
    "/assets/",
    "/admin/",
    "/modules/",
    "/tmp/cache/",
    "/login.php",
    "/data/styleadmin.css",
]


class MarkerParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.meta_generators = []
        self.assets = []

    def handle_starttag(self, tag, attrs):
        attr = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "meta" and attr.get("name", "").lower() == "generator":
            if attr.get("content"):
                self.meta_generators.append(attr["content"])
        for key in ("href", "src"):
            if attr.get(key):
                self.assets.append(attr[key])


def normalize_url(target: str) -> str:
    target = (target or "").strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    parsed = urlparse(target)
    path = parsed.path or "/"
    return parsed._replace(path=path, params="", query="", fragment="").geturl()


def fetch(url: str, timeout: int = TIMEOUT) -> dict:
    req = Request(url, headers={"User-Agent": "ai-recon-agent/ctf", "Accept": "text/html,*/*;q=0.8"}, method="GET")
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read(MAX_BODY + 1)[:MAX_BODY]
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {"url": resp.geturl(), "status": resp.status, "headers": headers, "body": body.decode("utf-8", "ignore")}
    except Exception as exc:
        return {"url": url, "error": str(exc), "headers": {}, "body": ""}


def add_hit(found: dict, name: str, evidence: str, version: str = "") -> None:
    item = found.setdefault(name, {"name": name, "version": "", "evidence": []})
    if version and not item["version"]:
        item["version"] = version
    if evidence and evidence not in item["evidence"]:
        item["evidence"].append(evidence)


def version_after(text: str, name: str) -> str:
    patterns = [
        rf"{re.escape(name)}\s*(?:version|v)?\s*([0-9]+(?:\.[0-9A-Za-z_-]+)+)",
        rf"(?:version|ver|v)\s*[:=]?\s*([0-9]+(?:\.[0-9A-Za-z_-]+)+).{{0,80}}{re.escape(name)}",
        rf"{re.escape(name)}.{{0,80}}(?:version|ver|v)\s*[:=]?\s*([0-9]+(?:\.[0-9A-Za-z_-]+)+)",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.I | re.S)
        if m:
            return m.group(1)
    return ""


def pluck_version(text: str) -> str:
    for pat in (r"pluck[-\s]+([0-9]+(?:\.[0-9A-Za-z_-]+)+)", r"generator[\"'\s=]+content=[\"']pluck\s+([0-9]+(?:\.[0-9A-Za-z_-]+)+)"):
        m = re.search(pat, text, re.I | re.S)
        if m:
            return m.group(1)
    return version_after(text, "pluck")


def linked_cms_urls(responses: list[dict]) -> list[str]:
    """Follow CMS-looking links exposed by directory listings or index pages."""
    urls = []
    for resp in responses:
        base = resp.get("url", "")
        body = resp.get("body", "") or ""
        for href in re.findall(r"href=[\"']([^\"']+)[\"']", body, re.I):
            low = href.lower()
            if any(marker in low for marker in ("pluck", "wp-", "administrator", "joomla", "drupal")):
                urls.append(urljoin(base, href))
    return list(dict.fromkeys(urls))[:12]


def parse_cms_tech(responses: list[dict]) -> dict:
    """Extract CMS/framework evidence from headers, cookies, HTML, and assets."""
    cms = {}
    frameworks = {}
    interesting_paths = []
    parser = MarkerParser()
    combined = []

    for resp in responses:
        url = resp.get("url", "")
        headers = resp.get("headers", {}) or {}
        body = resp.get("body", "") or ""
        low = body.lower()
        combined.append("\n".join([json.dumps(headers), body[:200000]]))
        if resp.get("status") and urlparse(url).path not in ("", "/"):
            interesting_paths.append({"url": url, "status": resp["status"]})
        try:
            parser.feed(body)
        except Exception:
            pass

        server = " ".join(headers.get(k, "") for k in ("server", "x-powered-by", "x-generator", "x-drupal-cache", "x-runtime"))
        cookie = headers.get("set-cookie", "")
        cookies = SimpleCookie()
        try:
            cookies.load(cookie)
        except Exception:
            pass
        cookie_names = " ".join(cookies.keys()).lower() + " " + cookie.lower()

        if "wp-content/" in low or "wp-includes/" in low or "wordpress" in low:
            add_hit(cms, "WordPress", "wordpress body/assets", version_after(body, "WordPress"))
        if "drupal-settings-json" in low or "drupal" in low or headers.get("x-drupal-cache"):
            add_hit(cms, "Drupal", "drupal markers", version_after(body, "Drupal"))
        if "content=\"joomla" in low or "/media/system/" in low or "joomla" in low:
            add_hit(cms, "Joomla", "joomla markers", version_after(body, "Joomla"))
        if "cms made simple" in low or "cmsmadesimple" in low or "cmsms" in low:
            add_hit(cms, "CMS Made Simple", "cms made simple body markers", version_after(body, "CMS Made Simple"))
        if "pluck" in low and ("meta name=\"generator\"" in low or "pluck-" in low or "styleadmin.css" in low or "data/themes" in low or "login.php" in low):
            add_hit(cms, "Pluck CMS", "pluck body/assets/directory markers", pluck_version(body))
        if "mage/cookies" in low or "magento" in low or "x-magento" in server.lower():
            add_hit(cms, "Magento", "magento markers", version_after(body, "Magento"))
        if "laravel_session" in cookie_names or "laravel" in server.lower() or "csrf-token" in low:
            add_hit(frameworks, "Laravel", "laravel cookie/header/body", version_after(server + body, "Laravel"))
        if "csrftoken" in cookie_names or "django" in server.lower() or "__admin_media_prefix__" in low:
            add_hit(frameworks, "Django", "django cookie/header/body", version_after(server + body, "Django"))
        if "_session_id" in cookie_names or "x-runtime" in headers or "rails" in server.lower():
            add_hit(frameworks, "Rails", "rails cookie/header", version_after(server + body, "Rails"))
        if "jsessionid" in cookie_names or "spring" in server.lower() or "x-application-context" in headers:
            add_hit(frameworks, "Spring", "spring/java markers", version_after(server + body, "Spring"))
        if "sf_redirect" in cookie_names or "symfony" in server.lower() or "_fragment" in low:
            add_hit(frameworks, "Symfony", "symfony markers", version_after(server + body, "Symfony"))

    for gen in parser.meta_generators:
        for name, bucket in (("WordPress", cms), ("Drupal", cms), ("Joomla", cms), ("Magento", cms), ("CMS Made Simple", cms), ("Pluck CMS", cms), ("Laravel", frameworks), ("Django", frameworks), ("Rails", frameworks), ("Spring", frameworks), ("Symfony", frameworks)):
            gen_low = gen.lower()
            if name.lower() in gen_low or (name == "Pluck CMS" and "pluck" in gen_low):
                add_hit(bucket, name, f"meta generator: {gen}", pluck_version(gen) if name == "Pluck CMS" else version_after(gen, name))

    asset_text = "\n".join(parser.assets).lower()
    asset_rules = [("WordPress", cms, "wp-content/|wp-includes/"), ("Drupal", cms, "/sites/default/|drupal"), ("Joomla", cms, "/media/system/|/templates/"), ("Magento", cms, "/static/version|/skin/frontend/"), ("CMS Made Simple", cms, "cmsms|cmsmadesimple|/modules/|/tmp/cache/"), ("Pluck CMS", cms, "pluck|/data/themes/|styleadmin\\.css"), ("Symfony", frameworks, "/bundles/")]
    for name, bucket, pattern in asset_rules:
        if re.search(pattern, asset_text):
            add_hit(bucket, name, "asset path marker")

    tech_discovered = [*cms.values(), *frameworks.values()]
    return {"cms": list(cms.values()), "frameworks": list(frameworks.values()), "interesting_paths": interesting_paths, "tech_discovered": tech_discovered}


def detect(target: str, extra_urls: Optional[list[str]] = None) -> dict:
    root = normalize_url(target)
    responses = [fetch(root)]
    base = root if root.endswith("/") else root + "/"
    for path in MARKER_PATHS:
        responses.append(fetch(urljoin(base, path.lstrip("/"))))
    if extra_urls:
        for u in extra_urls:
            if u.strip():
                responses.append(fetch(u.strip()))
    for u in linked_cms_urls(responses):
        responses.append(fetch(u))
    parsed = parse_cms_tech(responses)
    parsed["target"] = target
    parsed["root_url"] = root
    return parsed


def main() -> int:
    global TIMEOUT
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--timeout", type=int, default=TIMEOUT)
    ap.add_argument("--paths", type=str, default="", help="Comma-separated extra URLs to probe")
    args = ap.parse_args()
    TIMEOUT = max(1, min(args.timeout, 10))
    extra = [u for u in args.paths.split(",") if u.strip()] if args.paths else None
    print(json.dumps(detect(args.target, extra_urls=extra), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
