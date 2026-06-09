"""Non-web service worker."""

from __future__ import annotations

from typing import Optional

from .base import ReconWorker, WorkerAction


class ServiceWorker(ReconWorker):
    """Schedule read-only checks for non-web ports.

    Current limitation: used-tool tracking is global by tool name, so a check
    like smb_check runs once even if multiple ports map to it. Some mapped
    tools are not registered yet; those entries are skipped by tool lookup.
    """

    name = "service"

    # Port-to-tool intent map. The runtime checks executor.list_tools() before
    # returning an action, so unregistered tools do not execute.
    PORT_TO_CHECK = {
        21: "ftp_check", 22: "ssh_check", 25: "smtp_check",
        53: "dns_check", 139: "smb_check", 389: "ldap_check",
        445: "smb_check", 465: "smtp_check", 587: "smtp_check",
        636: "ldap_check", 1433: "mssql_check", 2049: "nfs_check",
        3306: "mysql_check", 3389: "rdp_check", 5432: "postgres_check",
        5900: "vnc_check", 5901: "vnc_check", 6379: "redis_check",
        27017: "mongo_check",
    }
    PORT_TO_DEEP = {
        21: "ftp_deep",
        139: "smb_deep",
        445: "smb_deep",
        6379: "redis_deep",
    }

    def next_action(self) -> Optional[WorkerAction]:
        if self.manager.no_service:
            return None
        used = self.used
        host = self.manager._clean_target_host(self.manager.target)
        tools = self.manager.executor.list_tools()
        for port_info in self.manager._non_web_ports():
            port_num = int(port_info.get("port") or 0)
            raw_service = port_info.get("service", "")
            check = self.PORT_TO_CHECK.get(port_num)
            if check and check not in used and check in tools:
                return WorkerAction(
                    check,
                    host,
                    {"port": port_num},
                    f"ServiceWorker: service check port {port_num} ({raw_service})",
                )
            deep = self.PORT_TO_DEEP.get(port_num)
            if deep and check in used and deep not in used and deep in tools:
                return WorkerAction(
                    deep,
                    host,
                    {"port": port_num},
                    f"ServiceWorker: aggressive deep {raw_service or port_num} probe on port {port_num}",
                )
        return None
