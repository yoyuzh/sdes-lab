from PySide6.QtCore import Qt

from sdes.gui import MainWindow


def test_binary_text_and_errors(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)
    window.show()
    window.binary_data.setText("11010111")
    window.binary_key.setText("1010000010")
    qtbot.mouseClick(window.encrypt_button, Qt.MouseButton.LeftButton)
    assert window.binary_result.text() == "11101000"
    window.binary_data.setText("11101000")
    qtbot.mouseClick(window.decrypt_button, Qt.MouseButton.LeftButton)
    assert window.binary_result.text() == "11010111"
    window.binary_data.setText("bad")
    qtbot.mouseClick(window.encrypt_button, Qt.MouseButton.LeftButton)
    assert "8" in window.binary_status.text()
    window.text_input.setPlainText("Hello\n")
    window.text_key.setText("1010000010")
    window.process_text("encrypt")
    window.text_input.setPlainText(window.text_hex.toPlainText())
    window.process_text("decrypt")
    assert window.text_plain.toPlainText() == "Hello\n"


def test_background_search(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)
    window.pairs_input.setPlainText("11010111 11101000")
    window.start_search()
    qtbot.waitUntil(lambda: window.search_result is not None, timeout=10000)
    assert window.search_result.checked == 1024
    assert "1010000010" in window.search_output.toPlainText()
    qtbot.waitUntil(lambda: not window.jobs, timeout=10000)


def test_collision_cancellation_and_failure(qtbot):
    from sdes.analysis import FullAnalysisResult

    window = MainWindow()
    qtbot.addWidget(window)
    window.all_plaintexts.setChecked(True)
    window.start_collision()
    window.cancel_job("collision")
    qtbot.waitUntil(lambda: window.collision_result is not None, timeout=10000)
    assert window.collision_result.status == "cancelled"
    assert "未完成" in window.collision_status.text()
    qtbot.waitUntil(lambda: not window.jobs, timeout=10000)
    window.start_collision()
    qtbot.waitUntil(lambda: isinstance(window.collision_result, FullAnalysisResult), timeout=10000)
    qtbot.waitUntil(lambda: not window.jobs, timeout=10000)
    assert window.collision_result.status == "complete"
    assert window.collision_table.rowCount() == 256
    window.show_bucket(0, 0)
    assert "均得到密文" in window.collision_detail.toPlainText()

    def failing_task(**kwargs):
        raise RuntimeError("test failure")

    window._start_job("collision", failing_task)
    qtbot.waitUntil(lambda: "test failure" in window.collision_status.text(), timeout=10000)
    qtbot.waitUntil(lambda: not window.jobs, timeout=10000)


def test_single_collision_and_invalid_retry(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)
    window.start_collision()
    qtbot.waitUntil(lambda: window.collision_result is not None, timeout=10000)
    qtbot.waitUntil(lambda: not window.jobs, timeout=10000)
    window.show_bucket(0, 0)
    assert "全部密钥" in window.collision_detail.toPlainText()
    window.collision_plain.setText("bad")
    window.start_collision()
    assert window.collision_result is None
    assert not window.collision_export.isEnabled()
    window.pairs_input.setPlainText("11010111 11101000")
    window.start_search()
    qtbot.waitUntil(lambda: window.search_result is not None, timeout=10000)
    qtbot.waitUntil(lambda: not window.jobs, timeout=10000)
    window.pairs_input.setPlainText("bad")
    window.start_search()
    assert window.search_result is None
    assert not window.search_export.isEnabled()
