"""Four-page desktop lab; every displayed cipher is produced by the shared core."""

import logging
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Literal

from PySide6.QtCore import QTimer, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .analysis import (
    AnalysisResult,
    AnalysisTask,
    CollisionResult,
    FullAnalysisResult,
    SearchResult,
    analyze_all_plaintexts,
    analyze_plaintext,
    brute_force,
    validate_pairs,
)
from .codecs import ascii_bytes, parse_bits, parse_hex, preview_bytes
from .core import decrypt_bytes, encrypt_bytes, trace_block
from .export import export_csv, export_json
from .workers import AnalysisJob

STYLE = """
QWidget { font-family: 'PingFang SC', 'Microsoft YaHei', sans-serif; font-size: 14px;
          color: #20354b; background: #f5f7fb; }
QLabel#title { font-size: 27px; font-weight: 700; color: #123b67; }
QLabel#subtitle { color: #64768a; padding-bottom: 8px; }
QTabWidget::pane { border: 1px solid #d6dfe9; border-radius: 8px; }
QTabBar::tab { padding: 12px 22px; background: #e8edf5; }
QTabBar::tab:selected { background: #ffffff; color: #155a9c; font-weight: 600; }
QLineEdit, QPlainTextEdit, QTableWidget { background: #ffffff; border: 1px solid #cbd6e4;
    border-radius: 5px; padding: 7px; selection-background-color: #2468a5; }
QPushButton { background: #1e5f9b; color: white; border: none; border-radius: 5px;
              padding: 9px 17px; min-height: 18px; }
QPushButton:hover { background: #174b7c; }
QPushButton:disabled { background: #b6c4d4; color: #f5f7fb; }
QProgressBar { border: 1px solid #cbd6e4; border-radius: 4px; text-align: center; }
QProgressBar::chunk { background: #277c94; }
"""


def _edit(name: str, default: str = "", readonly: bool = False) -> QLineEdit:
    widget = QLineEdit(default)
    widget.setAccessibleName(name)
    widget.setReadOnly(readonly)
    return widget


def _text(name: str, readonly: bool = False) -> QPlainTextEdit:
    widget = QPlainTextEdit()
    widget.setAccessibleName(name)
    widget.setReadOnly(readonly)
    return widget


def _button(label: str, callback: Callable[[], object], layout: QHBoxLayout) -> QPushButton:
    button = QPushButton(label)
    button.clicked.connect(callback)
    layout.addWidget(button)
    return button


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("S-DES 实验室")
        self.resize(1000, 790)
        self.setStyleSheet(STYLE)
        self.jobs: set[AnalysisJob] = set()
        self.search_result: SearchResult | None = None
        self.collision_result: CollisionResult | FullAnalysisResult | None = None
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(25, 20, 25, 20)
        title = QLabel("S-DES 实验室")
        title.setObjectName("title")
        subtitle = QLabel("8 位分组 · 10 位密钥 · 加解密 / 密钥搜索 / 碰撞分析")
        subtitle.setObjectName("subtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        self._build_binary()
        self._build_text()
        self._build_search()
        self._build_collision()
        footer = QLabel("算法：文档公式直接 LS2；组间兼容性待核对。SBox2 使用作业指定表。")
        footer.setWordWrap(True)
        layout.addWidget(footer)
        self.setCentralWidget(root)

    def _page(self, title: str, note: str) -> QVBoxLayout:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        explanation = QLabel(note)
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        self.tabs.addTab(page, title)
        return layout

    def _build_binary(self) -> None:
        layout = self._page("01  二进制", "输入固定宽度的二进制数据；加密和解密均保留前导零。")
        form = QFormLayout()
        self.binary_data = _edit("8 位数据", "11010111")
        self.binary_key = _edit("二进制页密钥", "1010000010")
        self.binary_result = _edit("二进制结果", readonly=True)
        form.addRow("8 位数据", self.binary_data)
        form.addRow("10 位密钥", self.binary_key)
        form.addRow("运算结果", self.binary_result)
        layout.addLayout(form)
        buttons = QHBoxLayout()
        self.encrypt_button = _button("加密", partial(self.process_binary, "encrypt"), buttons)
        self.decrypt_button = _button("解密", partial(self.process_binary, "decrypt"), buttons)
        _button(
            "复制结果", lambda: QApplication.clipboard().setText(self.binary_result.text()), buttons
        )
        layout.addLayout(buttons)
        self.binary_status = QLabel("准备就绪")
        layout.addWidget(self.binary_status)
        layout.addWidget(QLabel("轮密钥与运算过程"))
        self.binary_trace = _text("轮运算过程", True)
        layout.addWidget(self.binary_trace)

    def process_binary(self, operation: Literal["encrypt", "decrypt"]) -> None:
        try:
            block = parse_bits(self.binary_data.text(), 8)
            key = parse_bits(self.binary_key.text(), 10)
            trace = trace_block(block, key, operation)
            self.binary_result.setText(f"{trace.output:08b}")
            lines = [
                f"K1 = {trace.subkeys[0]:08b}   K2 = {trace.subkeys[1]:08b}",
                f"IP = {trace.initial:08b}",
            ]
            for number, step in enumerate(trace.rounds, 1):
                lines += [
                    f"\n第 {number} 轮：子密钥 {step.subkey:08b}",
                    f"EP = {step.expanded:08b}    XOR = {step.mixed:08b}",
                    f"S0 = {step.s0:02b}   S1 = {step.s1:02b}   P4 = {step.p4:04b}",
                    f"轮输出 = {step.output:08b}",
                ]
                if number == 1:
                    lines.append(f"SW = {trace.swapped:08b}")
            lines.append(f"\nIP⁻¹ / 结果 = {trace.output:08b}")
            self.binary_trace.setPlainText("\n".join(lines))
            self.binary_status.setText("加密完成" if operation == "encrypt" else "解密完成")
        except ValueError as error:
            self.binary_result.clear()
            self.binary_trace.clear()
            self.binary_status.setText(str(error))

    def _build_text(self) -> None:
        layout = self._page(
            "02  字符串", "加密输入 ASCII 文本；解密输入 Hex。密文字符预览使用转义表示控制字节。"
        )
        self.text_key = _edit("字符串页密钥", "1010000010")
        form = QFormLayout()
        form.addRow("10 位密钥", self.text_key)
        layout.addLayout(form)
        self.text_input = _text("ASCII 或 Hex 输入")
        self.text_input.setPlainText("Hello, S-DES!")
        self.text_input.setMaximumHeight(110)
        layout.addWidget(self.text_input)
        buttons = QHBoxLayout()
        _button("加密 ASCII", partial(self.process_text, "encrypt"), buttons)
        _button("解密 Hex", partial(self.process_text, "decrypt"), buttons)
        _button(
            "复制 Hex",
            lambda: QApplication.clipboard().setText(self.text_hex.toPlainText()),
            buttons,
        )
        layout.addLayout(buttons)
        self.text_status = QLabel("准备就绪")
        layout.addWidget(self.text_status)
        layout.addWidget(QLabel("结果字节 · Hex"))
        self.text_hex = _text("Hex 输出", True)
        layout.addWidget(self.text_hex)
        layout.addWidget(QLabel("密文预览 / 恢复明文"))
        self.text_plain = _text("文本输出", True)
        layout.addWidget(self.text_plain)

    def process_text(self, operation: str) -> None:
        try:
            key = parse_bits(self.text_key.text(), 10)
            raw = self.text_input.toPlainText()
            if operation == "encrypt":
                result = encrypt_bytes(ascii_bytes(raw), key)
                display = preview_bytes(result)
                message = "加密完成"
            else:
                result = decrypt_bytes(parse_hex(raw), key)
                try:
                    display = result.decode("ascii")
                    message = "解密完成"
                except UnicodeDecodeError:
                    display = preview_bytes(result)
                    message = "解密完成，但结果包含非 ASCII 字节；请核对密钥"
            self.text_hex.setPlainText(result.hex(" ").upper())
            self.text_plain.setPlainText(display)
            self.text_status.setText(f"{message} · {len(result)} 字节")
        except ValueError as error:
            self.text_hex.clear()
            self.text_plain.clear()
            self.text_status.setText(str(error))

    def _build_search(self) -> None:
        layout = self._page(
            "03  暴力破解", "每行输入一对 8 位明文和密文，用空格分隔。完整枚举 1024 个密钥。"
        )
        self.pairs_input = _text("明密文对")
        self.pairs_input.setPlainText("11010111 11101000")
        self.pairs_input.setMaximumHeight(120)
        layout.addWidget(self.pairs_input)
        buttons = QHBoxLayout()
        self.search_start = _button("开始破解", self.start_search, buttons)
        self.search_cancel = _button("取消", partial(self.cancel_job, "search"), buttons)
        self.search_cancel.setEnabled(False)
        self.search_export = _button(
            "导出 JSON / CSV", partial(self.save_result, "search"), buttons
        )
        self.search_export.setEnabled(False)
        layout.addLayout(buttons)
        self.search_progress = QProgressBar()
        layout.addWidget(self.search_progress)
        self.search_status = QLabel("准备就绪")
        self.search_status.setWordWrap(True)
        layout.addWidget(self.search_status)
        self.search_output = _text("候选密钥", True)
        layout.addWidget(self.search_output)

    def start_search(self) -> None:
        try:
            pairs = []
            for number, line in enumerate(self.pairs_input.toPlainText().splitlines(), 1):
                if not line.strip():
                    continue
                columns = line.split()
                if len(columns) != 2:
                    raise ValueError(f"第 {number} 行必须包含一组明文和密文")
                pairs.append((parse_bits(columns[0], 8), parse_bits(columns[1], 8)))
            pairs = validate_pairs(pairs)
            if any(job.tag == "search" for job in self.jobs):
                return
            self.search_result = None
            self.search_output.clear()
            self._start_job("search", partial(brute_force, pairs))
        except ValueError as error:
            self.search_result = None
            self.search_output.clear()
            self.search_export.setEnabled(False)
            self.search_status.setText(str(error))

    def _build_collision(self) -> None:
        layout = self._page(
            "04  碰撞分析", "将密钥按密文分桶；全部明文模式覆盖 256 × 1024 个组合。"
        )
        form = QFormLayout()
        self.collision_plain = _edit("碰撞分析明文", "11010111")
        form.addRow("8 位明文", self.collision_plain)
        layout.addLayout(form)
        self.all_plaintexts = QCheckBox("遍历全部 256 个明文")
        layout.addWidget(self.all_plaintexts)
        buttons = QHBoxLayout()
        self.collision_start = _button("开始分析", self.start_collision, buttons)
        self.collision_cancel = _button("取消", partial(self.cancel_job, "collision"), buttons)
        self.collision_cancel.setEnabled(False)
        self.collision_export = _button(
            "导出 JSON / CSV", partial(self.save_result, "collision"), buttons
        )
        self.collision_export.setEnabled(False)
        layout.addLayout(buttons)
        self.collision_progress = QProgressBar()
        layout.addWidget(self.collision_progress)
        self.collision_status = QLabel("准备就绪")
        self.collision_status.setWordWrap(True)
        layout.addWidget(self.collision_status)
        self.collision_table = QTableWidget()
        self.collision_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.collision_table.setAccessibleName("碰撞统计表")
        self.collision_table.cellClicked.connect(self.show_bucket)
        layout.addWidget(self.collision_table)
        self.collision_detail = _text("碰撞密钥详情", True)
        self.collision_detail.setMaximumHeight(130)
        layout.addWidget(self.collision_detail)

    def start_collision(self) -> None:
        try:
            if any(job.tag == "collision" for job in self.jobs):
                return
            task = (
                analyze_all_plaintexts
                if self.all_plaintexts.isChecked()
                else partial(analyze_plaintext, parse_bits(self.collision_plain.text(), 8))
            )
            self.collision_result = None
            self.collision_table.setRowCount(0)
            self.collision_detail.clear()
            self._start_job("collision", task)
        except ValueError as error:
            self.collision_result = None
            self.collision_table.setRowCount(0)
            self.collision_detail.clear()
            self.collision_export.setEnabled(False)
            self.collision_status.setText(str(error))

    def _busy(self, tag: str, busy: bool) -> None:
        getattr(self, f"{tag}_start").setEnabled(not busy)
        getattr(self, f"{tag}_cancel").setEnabled(busy)
        getattr(self, f"{tag}_export").setEnabled(
            not busy and getattr(self, f"{tag}_result") is not None
        )
        if tag == "search":
            self.pairs_input.setEnabled(not busy)
        else:
            self.collision_plain.setEnabled(not busy)
            self.all_plaintexts.setEnabled(not busy)

    def _start_job(self, tag: str, task: AnalysisTask) -> None:
        setattr(self, f"{tag}_result", None)
        job = AnalysisJob(tag, task, self)
        self.jobs.add(job)
        job.progress.connect(self.update_progress)
        job.result.connect(self.receive_result)
        job.failed.connect(self.job_failed)
        job.finished.connect(self.job_finished)
        getattr(self, f"{tag}_progress").setValue(0)
        getattr(self, f"{tag}_status").setText("计算中…")
        self._busy(tag, True)
        job.start()

    @Slot(int, int)
    def update_progress(self, checked: int, total: int) -> None:
        tag = self.sender().tag
        bar = getattr(self, f"{tag}_progress")
        bar.setRange(0, total)
        bar.setValue(checked)

    @Slot(object)
    def receive_result(self, result: AnalysisResult) -> None:
        tag = self.sender().tag
        setattr(self, f"{tag}_result", result)
        state = "完整完成" if result.status == "complete" else "已取消 · 结果未完成"
        timing = (
            f"{state} · 检查 {result.checked} · 耗时 {result.elapsed_s * 1000:.3f} ms\n"
            f"开始 {result.started_at}    结束 {result.finished_at}"
        )
        if isinstance(result, SearchResult):
            count = len(result.candidates)
            if result.status != "complete":
                conclusion = f"当前发现 {count} 个候选，尚未完整枚举"
            elif not count:
                conclusion = "无匹配密钥，请检查输入对或算法参数"
            elif count == 1:
                conclusion = "给定数据下唯一候选密钥"
            else:
                conclusion = f"共 {count} 个候选，当前数据无法唯一确定密钥"
            self.search_status.setText(f"{timing}\n{conclusion}")
            self.search_output.setPlainText(
                "\n".join(f"{k:010b}  （{k}）" for k in result.candidates)
            )
        else:
            self.collision_status.setText(timing)
            self._show_collisions(result)

    def _show_collisions(self, result: CollisionResult | FullAnalysisResult) -> None:
        if isinstance(result, CollisionResult):
            headers = ["密文", "密钥数", "是否碰撞"]
            rows = [
                (f"{cipher:08b}", len(keys), "是" if len(keys) > 1 else "否")
                for cipher, keys in result.buckets.items()
            ]
            self.collision_detail.setPlainText(
                f"可达密文 {len(result.buckets)}；碰撞桶 {result.collision_buckets}；"
                f"最大桶 {result.max_bucket}。点击一行查看全部密钥。"
            )
        else:
            headers = ["明文", "可达密文", "碰撞桶", "最大桶"]
            rows = [
                (
                    f"{row['plaintext']:08b}",
                    row["reachable"],
                    row["collision_buckets"],
                    row["max_bucket"],
                )
                for row in result.rows
            ]
            self.collision_detail.setPlainText("点击一行查看可复现的碰撞实例。")
        self.collision_table.setColumnCount(len(headers))
        self.collision_table.setHorizontalHeaderLabels(headers)
        self.collision_table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            for column, value in enumerate(row):
                self.collision_table.setItem(index, column, QTableWidgetItem(str(value)))
        self.collision_table.horizontalHeader().setStretchLastSection(True)
        self.collision_table.resizeColumnsToContents()

    @Slot(int, int)
    def show_bucket(self, row: int, column: int) -> None:
        result = self.collision_result
        if isinstance(result, CollisionResult):
            cipher = list(result.buckets)[row]
            self.collision_detail.setPlainText(
                f"密文 {cipher:08b} 的全部密钥：\n"
                + "  ".join(f"{k:010b}" for k in result.buckets[cipher])
            )
        elif isinstance(result, FullAnalysisResult):
            record = result.rows[row]
            keys = "、".join(f"{k:010b}" for k in record["sample_keys"])
            self.collision_detail.setPlainText(
                f"明文 {record['plaintext']:08b}，不同密钥 {keys} "
                f"均得到密文 {record['sample_cipher']:08b}"
            )

    @Slot(str)
    def job_failed(self, message: str) -> None:
        getattr(self, f"{self.sender().tag}_status").setText(message)

    @Slot()
    def job_finished(self) -> None:
        job = self.sender()
        self.jobs.discard(job)
        self._busy(job.tag, False)
        job.deleteLater()

    def cancel_job(self, tag: str) -> None:
        for job in self.jobs:
            if job.tag == tag:
                job.cancellation.set()

    def save_result(self, tag: str) -> None:
        result = getattr(self, f"{tag}_result")
        if result is None:
            return
        filename, selected = QFileDialog.getSaveFileName(
            self,
            "导出分析结果",
            str(
                Path.cwd()
                / "evidence"
                / ("bruteforce" if tag == "search" else "collision")
                / f"{tag}.json"
            ),
            "JSON (*.json);;CSV (*.csv)",
            options=QFileDialog.Option.DontUseNativeDialog,
        )
        if not filename:
            return
        path = Path(filename)
        try:
            if selected.startswith("CSV"):
                if path.suffix.lower() != ".csv":
                    path = path.with_suffix(".csv")
                export_csv(result, path)
            else:
                if path.suffix.lower() != ".json":
                    path = path.with_suffix(".json")
                export_json(result, path)
            getattr(self, f"{tag}_status").setText(f"已保存：{path}")
        except (OSError, ValueError) as error:
            logging.exception("Export failed")
            getattr(self, f"{tag}_status").setText(f"保存失败：{error}")

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.jobs:
            for job in self.jobs:
                job.cancellation.set()
            event.ignore()
            QTimer.singleShot(100, self.close)
        else:
            event.accept()
