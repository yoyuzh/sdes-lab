"""Launch the desktop application."""

import logging
import sys

from PySide6.QtWidgets import QApplication

from .gui import MainWindow


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    app = QApplication(sys.argv)
    app.setApplicationName("S-DES 实验室")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
