"""Web reconnaissance worker."""

from __future__ import annotations

from typing import Optional

from .base import ReconWorker, WorkerAction


class WebWorker(ReconWorker):
    """Schedule the default single-target HTTP recon chain.

    Current limitation: only the first HTTP-like URL from manager._web_targets()
    is expanded; future work should schedule each web target separately.
    """

    name = "web"

    def _next_action(self) -> Optional[WorkerAction]:
        used = self.used
        host = self.manager._clean_target_host(self.manager.target)
        is_domain = self.manager._is_domain(host)
        web_targets = self.manager._web_targets()
        if not web_targets:
            return None
        web_url = web_targets[0]

        if is_domain:
            for tool in self.manager.PASSIVE_TOOLS:
                if tool not in used:
                    return WorkerAction(tool, host, {}, f"WebWorker: passive recon - {tool}")

        if "whatweb" not in used:
            return WorkerAction("whatweb", web_url, {}, "WebWorker: fingerprint web service")
        if "redirect_check" not in used:
            return WorkerAction("redirect_check", web_url, {}, "WebWorker: check redirect to domain")

        redirect_domain = self.manager._get_redirect_domain()
        if redirect_domain and "hosts_add" not in used:
            if not self.manager._resolve_domain(redirect_domain):
                return WorkerAction(
                    "hosts_add",
                    f"{host} {redirect_domain}",
                    {},
                    f"WebWorker: add unresolved redirect domain {redirect_domain} to /etc/hosts",
                )
            self.manager.state.add_finding(
                self.manager.session_id,
                "recon",
                "hosts_add",
                "info",
                f"Domain {redirect_domain} resolves OK, no hosts edit needed",
            )

        domain_to_scan = redirect_domain or (host if is_domain else None)
        if domain_to_scan and "subfinder" not in used:
            return WorkerAction("subfinder", domain_to_scan, {}, f"WebWorker: subdomain enum - {domain_to_scan}")
        if domain_to_scan and "ffuf_vhost" not in used:
            return WorkerAction(
                "ffuf_vhost",
                web_url,
                {"domain": domain_to_scan},
                f"WebWorker: vhost discovery - {domain_to_scan}",
            )

        for tool in self.manager.WEB_CHAIN:
            if tool not in used:
                params = {}
                if tool in {"js_dump", "js_deobfuscate", "js_mine"}:
                    params["output_dir"] = self.manager.output_dir
                    if tool == "js_dump":
                        params["urls"] = "\n".join(self.manager._crawl_urls(web_url))
                return WorkerAction(tool, web_url, params, f"WebWorker: web probe - {tool}")

        for tool in self.manager.FUZZ_CHAIN:
            if tool not in used:
                return WorkerAction(tool, web_url, {}, f"WebWorker: web fuzz - {tool}")

        # After fuzz, read discovered directories before CMS follow-up. Many CTF apps
        # expose the real app via Apache directory listing (for example /app/ -> pluck-4.7.13/).
        all_fuzz_used = all(t in used for t in self.manager.FUZZ_CHAIN)
        if all_fuzz_used:
            dir_target = self._next_directory_body_url(web_url)
            if dir_target:
                return WorkerAction(
                    "curl_body",
                    dir_target,
                    {},
                    f"WebWorker: read discovered directory listing - {dir_target}",
                )

        # After directory reads, probe discovered paths for CMS/framework.
        if all_fuzz_used and "cms_follow_done" not in self._flags:
            self._flags.add("cms_follow_done")
            fuzz_paths = self._fuzz_discovered_urls(web_url)
            if fuzz_paths:
                for tool in self.manager.CMS_FOLLOW_CHAIN:
                    params = {"paths": fuzz_paths, "timeout": 6}
                    if not self.manager.action_done(tool, web_url, params):
                        return WorkerAction(
                            tool,
                            web_url,
                            params,
                            f"WebWorker: CMS detect on fuzz paths - {len(fuzz_paths)} URLs",
                        )

        fetch_target = self.manager._next_interesting_web_url(web_url)
        if fetch_target and "web_download_interesting" not in used and "web_download_interesting" in self.manager.executor.list_tools():
            return WorkerAction("web_download_interesting", fetch_target, {"output_dir": self.manager.output_dir}, f"WebWorker: save interesting artifact - {fetch_target}")
        if fetch_target and "curl_body" not in used:
            return WorkerAction("curl_body", fetch_target, {}, f"WebWorker: fetch interesting path - {fetch_target}")

        for tool in self.manager.DEEP_CHAIN:
            if tool not in used:
                params = {"output_dir": self.manager.output_dir} if tool == "web_download_interesting" else {}
                return WorkerAction(tool, web_url, params, f"WebWorker: deep web - {tool}")

        return None

    def _next_directory_body_url(self, base_url: str) -> Optional[str]:
        """Return an unfetched discovered directory URL for body inspection."""
        for url in self._fuzz_discovered_urls(base_url):
            clean = url.rstrip('.,;\"\'')
            if not clean.endswith("/"):
                continue
            if self.manager.action_done("curl_body", clean, {}):
                continue
            return clean
        return None

    def _fuzz_discovered_urls(self, base_url: str) -> list[str]:
        """Collect non-trivial endpoint URLs discovered by ffuf/katana tools."""
        import re
        urls = set()
        for f in self.manager.state.get_all_findings(self.manager.session_id):
            if f.get("tool") not in {"ffuf_dir", "ffuf_recursive", "ffuf_ext"}:
                continue
            blob = "\n".join(str(f.get(k) or "") for k in ("summary", "detail", "evidence"))
            found = re.findall(r'https?://[^\s"\'<>]+', blob)
            found.extend(re.findall(r'(?<![A-Za-z0-9_])/[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]+', blob))
            for item in found:
                url = item if item.startswith("http") else base_url.rstrip("/") + "/" + item.lstrip("/")
                u = url.rstrip('.,;\"\'')
                if u != base_url.rstrip("/") and "/." not in u:
                    urls.add(u)
        # Only return if we found substantive paths (not just /, /index.html)
        result = sorted(u for u in urls if not u.rstrip("/").endswith(("/", "/index.html")))
        return result[:10]

    def next_action(self) -> Optional[WorkerAction]:
        return self._next_action()
