"""Base worker helpers for manager/worker recon."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class WorkerAction:
    """Normalized action shape passed from worker to orchestrator."""

    tool: str
    target: str
    params: dict
    reason: str
    done: bool = False

    def as_decision(self) -> dict:
        return {
            "tool": self.tool,
            "target": self.target,
            "params": self.params,
            "reason": self.reason,
            "done": self.done,
        }


class ReconWorker:
    name = "worker"

    def __init__(self, manager):
        self.manager = manager
        self._flags: set[str] = set()

    @property
    def used(self) -> set[str]:
        return self.manager._used_tools()

    def next_action(self) -> Optional[WorkerAction]:
        raise NotImplementedError
