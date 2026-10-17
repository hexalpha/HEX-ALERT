"""Secret-redacted Docker log viewer."""
from __future__ import annotations

from PySide6.QtWidgets import QComboBox, QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout


class LogViewer(QDialog):
    def __init__(self, docker, parent=None):
        super().__init__(parent)
        self.docker = docker
        self.setWindowTitle("HEX ALERT Logs")
        self.resize(900, 600)
        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Service"))
        self.service = QComboBox()
        self.service.addItems(["All services", "Bot / backend", "Local AI", "PostgreSQL"])
        controls.addWidget(self.service)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        controls.addWidget(refresh)
        layout.addLayout(controls)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("font-family:Consolas,monospace")
        layout.addWidget(self.output)
        self.refresh()

    def refresh(self):
        service = {"Bot / backend": "bot", "Local AI": "llm", "PostgreSQL": "db"}.get(self.service.currentText(), "")
        try:
            self.output.setPlainText(self.docker.logs(service) or "No logs available.")
        except Exception as exc:
            self.output.setPlainText(str(exc))
