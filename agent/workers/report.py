"""Report worker placeholder.

Report generation still lives in ReconOrchestrator.run() so existing behavior and
CLI summary stay stable. This class exists to make the manager/worker split
explicit and gives dashboard a named report phase.
"""

from __future__ import annotations

from typing import Optional

from .base import ReconWorker, WorkerAction


class ReportWorker(ReconWorker):
    name = "report"

    def next_action(self) -> Optional[WorkerAction]:
        return None
