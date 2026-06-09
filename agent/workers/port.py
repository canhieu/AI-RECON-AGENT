"""Port discovery worker."""

from __future__ import annotations

from typing import Optional

from .base import ReconWorker, WorkerAction


class PortWorker(ReconWorker):
    """Run port discovery before any web/service follow-up.

    The worker scans all TCP ports, falls back when needed, then limits nmap to
    discovered ports so service detection is useful but not unnecessarily broad.
    """

    name = "port"

    def next_action(self) -> Optional[WorkerAction]:
        if self.manager.passive_only:
            return None
        used = self.used
        host = self.manager._clean_target_host(self.manager.target)
        tools = set(self.manager.executor.list_tools())

        if "rustscan" in tools and "rustscan" not in used and "nc_scan" not in used and "nmap" not in used:
            return WorkerAction(
                tool="rustscan",
                target=host,
                params={"ports": "1-65535", "timeout": "1500", "batch_size": "4500", "ulimit": "5000"},
                reason="PortWorker: rustscan full TCP sweep over 1-65535",
            )

        if "rustscan" not in tools and "nc_scan" not in used and "nmap" not in used:
            return WorkerAction(
                tool="nc_scan",
                target=host,
                params={"ports": "1-65535", "timeout": "1", "parallel": "200"},
                reason="PortWorker: nc_scan fallback sweep over 1-65535",
            )

        surface = self.manager.state.get_surface_summary(self.manager.session_id)
        found_ports = []
        for item in surface.get("items", []):
            port = int(item.get("port") or 0)
            if port > 0:
                found_ports.append(str(port))
        ports = ",".join(dict.fromkeys(found_ports))

        if "rustscan" in used and not ports and "nc_scan" not in used:
            return WorkerAction(
                tool="nc_scan",
                target=host,
                params={"ports": "1-65535", "timeout": "1", "parallel": "200"},
                reason="PortWorker: rustscan found no ports; fallback nc_scan sweep",
            )

        if "nmap" not in used:
            if not ports:
                self.manager.state.add_finding(
                    self.manager.session_id,
                    "recon",
                    "port_flow",
                    "info",
                    "No open ports found by rustscan/nc_scan; skipping nmap discovered-only follow-up",
                )
                return None
            return WorkerAction(
                tool="nmap",
                target=host,
                params={"ports": ports},
                reason=f"PortWorker: nmap -sC -sV on discovered ports ({ports})",
            )
        return None
