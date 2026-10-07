"""QThread owns computation only; widgets are updated through queued signals."""

import logging
from threading import Event

from PySide6.QtCore import QObject, QThread, Signal

from .analysis import AnalysisTask


class AnalysisJob(QThread):
    progress = Signal(int, int)
    result = Signal(object)
    failed = Signal(str)

    def __init__(self, tag: str, task: AnalysisTask, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.tag = tag
        self.task = task
        self.cancellation = Event()

    def run(self) -> None:
        try:
            self.result.emit(
                self.task(progress=self.progress.emit, cancelled=self.cancellation.is_set)
            )
        except Exception as error:
            logging.exception("Analysis %s failed", self.tag)
            self.failed.emit(f"任务失败：{error}")
