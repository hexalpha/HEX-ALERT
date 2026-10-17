"""HEX ALERT Control Center for Windows."""
from __future__ import annotations

import ctypes
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
import winreg
from pathlib import Path

# Python 3.8+ uses explicit DLL search directories for extension-module
# dependencies. Keep Qt's frozen runtime directories registered before loading
# any PySide6 extension module; this also avoids resolving Qt from another app.
_DLL_DIRECTORY_HANDLES = []
if getattr(sys, "frozen", False):
    for _dll_dir in (Path(sys._MEIPASS), Path(sys._MEIPASS) / "PySide6", Path(sys._MEIPASS) / "shiboken6"):
        if _dll_dir.is_dir():
            _DLL_DIRECTORY_HANDLES.append(os.add_dll_directory(str(_dll_dir)))
            os.environ["PATH"] = str(_dll_dir) + os.pathsep + os.environ.get("PATH", "")

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal
from PySide6.QtGui import QAction, QCloseEvent, QFont
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QFileDialog, QFormLayout, QGridLayout,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox,
    QPushButton, QSpinBox, QStyle, QSystemTrayIcon, QVBoxLayout, QWidget,
)

from launcher.docker_manager import DockerManager, redact
from launcher.health import read_health
from launcher.log_viewer import LogViewer
from launcher.settings import load as load_preferences, save as save_preferences


APP_NAME = "HEX ALERT"
APP_VERSION = "2.0.0"
URL = "http://127.0.0.1:8080"
MUTEX_NAME = "Local\\HEX_ALERT_CONTROL_CENTER_SINGLE_INSTANCE"


def discover_project_root() -> Path:
    explicit = os.environ.get("HEX_ALERT_HOME")
    if explicit:
        return Path(explicit).expanduser().resolve()
    base = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve()
    base = base.parent
    for candidate in (base, *base.parents):
        if (candidate / "docker-compose.yml").is_file() or (candidate / "compose.yml").is_file():
            return candidate.resolve()
    return base.resolve()


def ensure_config(root: Path) -> bool:
    """Create first-run configuration without displaying or logging generated secrets."""
    env_file = root / ".env"
    if env_file.exists():
        return False
    example = root / ".env.example"
    if not example.is_file():
        raise RuntimeError("Configuration template .env.example is missing from the project folder.")
    values = example.read_text(encoding="utf-8")
    password = secrets.token_urlsafe(32)
    api_key = secrets.token_urlsafe(48)
    session_secret = secrets.token_urlsafe(48)
    values = values.replace("POSTGRES_PASSWORD=change-me", f"POSTGRES_PASSWORD={password}")
    values = values.replace("hexalert:change-me@db", f"hexalert:{password}@db")
    values = values.replace("DASHBOARD_API_KEY=replace-with-a-long-random-value", f"DASHBOARD_API_KEY={api_key}")
    values = values.replace("SESSION_SECRET=replace-with-a-different-long-random-value", f"SESSION_SECRET={session_secret}")
    if "TEST_MODE=" not in values:
        values += "\nTEST_MODE=true\n"
    env_file.write_text(values, encoding="utf-8")
    return True


class UiBridge(QObject):
    result = Signal(str, bool, str)
    progress = Signal(str)


class StatusPoller(QThread):
    updated = Signal(dict)

    def __init__(self, docker: DockerManager, interval: int = 7, parent=None):
        super().__init__(parent)
        self.docker = docker
        self.interval = min(10, max(5, int(interval)))
        self.stopping = threading.Event()

    def run(self):
        while not self.stopping.is_set():
            docker_up = False
            rows: list[dict] = []
            try:
                docker_up = self.docker.engine_ready()
                if docker_up:
                    rows = self.docker.compose_rows()
            except Exception:
                docker_up = False
            self.updated.emit({"docker": docker_up, "containers": rows, "health": read_health()})
            self.stopping.wait(self.interval)

    def stop(self):
        self.stopping.set()


class PreferencesDialog(QDialog):
    saved = Signal(dict)

    def __init__(self, values: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("HEX ALERT Launcher Settings")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.path = QLineEdit(values["project_root"])
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        path_line = QHBoxLayout()
        path_line.addWidget(self.path)
        path_line.addWidget(browse)
        form.addRow("Project folder", path_line)
        self.open_dashboard = QCheckBox("Open Dashboard after successful start")
        self.open_dashboard.setChecked(bool(values.get("open_dashboard_after_start", True)))
        form.addRow("", self.open_dashboard)
        self.close_to_tray = QCheckBox("Minimize to system tray when closing the window")
        self.close_to_tray.setChecked(bool(values.get("close_to_tray", True)))
        form.addRow("", self.close_to_tray)
        self.auto_start = QCheckBox("Start HEX ALERT services when the launcher opens")
        self.auto_start.setChecked(bool(values.get("auto_start_services", False)))
        form.addRow("", self.auto_start)
        self.poll = QSpinBox()
        self.poll.setRange(5, 10)
        self.poll.setSuffix(" seconds")
        self.poll.setValue(int(values.get("health_poll_seconds", 7)))
        form.addRow("Health polling", self.poll)
        form.addRow(QLabel("TEST_MODE is shown from the live health endpoint. The launcher has no Production Mode switch."))
        layout.addLayout(form)
        shortcut = QPushButton("Create Desktop Shortcut")
        shortcut.clicked.connect(self.parent().create_desktop_shortcut)
        layout.addWidget(shortcut)
        row = QHBoxLayout()
        row.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        save = QPushButton("Save Settings")
        save.setObjectName("primary")
        save.clicked.connect(self._save)
        row.addWidget(cancel)
        row.addWidget(save)
        layout.addLayout(row)

    def _browse(self):
        chosen = QFileDialog.getExistingDirectory(self, "Select HEX ALERT project folder", self.path.text())
        if chosen:
            self.path.setText(chosen)

    def _save(self):
        values = {
            "project_root": str(Path(self.path.text().strip()).expanduser().resolve()),
            "open_dashboard_after_start": self.open_dashboard.isChecked(),
            "close_to_tray": self.close_to_tray.isChecked(),
            "start_with_windows": bool(self.parent().startup.isChecked()),
            "auto_start_services": self.auto_start.isChecked(),
            "health_poll_seconds": self.poll.value(),
        }
        root = Path(values["project_root"])
        if not (root / ".env.example").is_file() or not any((root / n).is_file() for n in ("docker-compose.yml", "compose.yml")):
            QMessageBox.warning(self, "Project folder not found", "Choose the existing HEX ALERT folder containing docker-compose.yml and .env.example.")
            return
        save_preferences(values)
        self.saved.emit(values)
        self.accept()


class Launcher(QMainWindow):
    REGISTRY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    REGISTRY_VALUE = "HexAlertLauncher"

    def __init__(self):
        super().__init__()
        self.preferences = load_preferences(discover_project_root())
        self.root = Path(self.preferences["project_root"])
        self.docker = DockerManager(self.root)
        self.bridge = UiBridge(self)
        self.bridge.progress.connect(self.set_status)
        self.bridge.result.connect(self._operation_finished)
        self._busy = False
        self._close_after_stop = False
        self._exit_services_after_stop = False
        self._last_snapshot: dict = {}
        self._single_instance_handle = None
        self.setWindowTitle("HEX ALERT Control Center")
        self.setMinimumSize(660, 660)
        self.resize(720, 760)
        self.setWindowIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        self._build_ui()
        self._build_tray()
        self.startup_toggle.blockSignals(True)
        self.startup_toggle.setChecked(self.startup_enabled())
        self.startup_toggle.blockSignals(False)
        self.startup_action.setChecked(self.startup_toggle.isChecked())
        self.poller = StatusPoller(self.docker, self.preferences["health_poll_seconds"], self)
        self.poller.updated.connect(self._update_status)
        self.poller.start()
        if self.preferences.get("auto_start_services"):
            QTimer.singleShot(900, self.start_stack)

    def _build_ui(self):
        self.setStyleSheet("""
          QMainWindow,QWidget{background:#0b1320;color:#e5edf8;font-family:'Segoe UI';font-size:10pt}
          QLabel#brand{font-size:25pt;font-weight:700;color:#dceaff}
          QLabel#developer{color:#6dd8c1;font-size:9pt;font-weight:700;letter-spacing:2px}
          QLabel#sub{color:#91a5bd;font-size:9pt}
          QWidget#statusPanel{background:#111d2e;border:1px solid #27384e;border-radius:12px}
          QLabel.statusName{color:#a9bad0;font-weight:600}
          QLabel.statusValue{font-weight:700;color:#e5edf8}
          QLabel#mode{background:#163d35;color:#8ff0c6;padding:7px 12px;border-radius:9px;font-weight:800}
          QLabel#prod{background:#3b2730;color:#ffb5c0;padding:7px 12px;border-radius:9px;font-weight:800}
          QPushButton{background:#1a2a40;color:#e8eef8;border:1px solid #2a3e58;border-radius:7px;padding:10px 12px}
          QPushButton:hover{background:#263c57} QPushButton:disabled{color:#637188;background:#131e2e}
          QPushButton#primary{background:#69dfbf;color:#082018;border:0;font-weight:800;padding:13px}
          QPushButton#primary:hover{background:#8cedd1}
          QCheckBox{spacing:8px} QLineEdit,QSpinBox{background:#101c2d;border:1px solid #31445d;border-radius:5px;padding:7px}
        """)
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(28, 22, 28, 22)
        layout.setSpacing(12)
        brand = QLabel("🛡  HEX ALERT")
        brand.setObjectName("brand")
        brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
        developer = QLabel("HEX SECURITY")
        developer.setObjectName("developer")
        developer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle = QLabel("Cyber Intelligence Control Center")
        subtitle.setObjectName("sub")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(brand)
        layout.addWidget(developer)
        layout.addWidget(subtitle)

        badges = QHBoxLayout()
        self.test_badge = QLabel("TEST_MODE · CHECKING")
        self.test_badge.setObjectName("mode")
        self.production_badge = QLabel("PRODUCTION · CHECKING")
        self.production_badge.setObjectName("prod")
        badges.addStretch(1)
        badges.addWidget(self.test_badge)
        badges.addWidget(self.production_badge)
        badges.addStretch(1)
        layout.addLayout(badges)

        panel = QWidget()
        panel.setObjectName("statusPanel")
        grid = QGridLayout(panel)
        grid.setContentsMargins(20, 18, 20, 18)
        grid.setHorizontalSpacing(30)
        grid.setVerticalSpacing(14)
        names = ("Docker", "Database", "Bot", "Dashboard", "Local AI", "Scheduler", "Discord")
        self.indicators: dict[str, QLabel] = {}
        for index, name in enumerate(names):
            row, col = divmod(index, 2)
            label = QLabel(name)
            label.setProperty("class", "statusName")
            value = QLabel("Checking…")
            value.setProperty("class", "statusValue")
            grid.addWidget(label, row, col * 2, 1, 1)
            grid.addWidget(value, row, col * 2 + 1, 1, 1)
            self.indicators[name] = value
        layout.addWidget(panel)

        self.status_label = QLabel("Ready. Start HEX ALERT when you are ready.")
        self.status_label.setWordWrap(True)
        self.status_label.setMinimumHeight(42)
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color:#a9bad0;padding:4px")
        layout.addWidget(self.status_label)

        self.startup_toggle = QCheckBox("Start HEX ALERT when Windows starts (current user)")
        self.startup_toggle.toggled.connect(self.toggle_startup)
        layout.addWidget(self.startup_toggle)

        grid_buttons = QGridLayout()
        grid_buttons.setSpacing(8)
        self.start_button = QPushButton("START HEX ALERT")
        self.start_button.setObjectName("primary")
        self.start_button.clicked.connect(self.start_stack)
        grid_buttons.addWidget(self.start_button, 0, 0, 1, 2)
        controls = (
            ("STOP HEX ALERT", self.stop_stack), ("RESTART HEX ALERT", self.restart_stack),
            ("OPEN DASHBOARD", self.open_dashboard), ("OPEN LOGS", self.view_logs),
            ("AI STATUS", self.ai_status), ("DISCORD STATUS", self.discord_status),
            ("REFRESH STATUS", self.refresh_status), ("SETTINGS", self.open_settings),
        )
        self.dashboard_button = None
        for index, (title, callback) in enumerate(controls):
            button = QPushButton(title)
            button.clicked.connect(callback)
            row = 1 + index // 2
            col = index % 2
            grid_buttons.addWidget(button, row, col)
            if title == "OPEN DASHBOARD":
                self.dashboard_button = button
                button.setEnabled(False)
        layout.addLayout(grid_buttons)

        self.about = QLabel()
        self.about.setWordWrap(True)
        self.about.setStyleSheet("color:#71849e;font-size:8pt;padding-top:5px")
        layout.addWidget(self.about)
        self._update_about()

    def _build_tray(self):
        self.tray = QSystemTrayIcon(self.windowIcon(), self)
        self.tray.setToolTip("HEX ALERT Control Center — TEST_MODE")
        menu = QMenu()
        open_center = QAction("Open Control Center", self)
        open_center.triggered.connect(self.show_center)
        menu.addAction(open_center)
        for title, callback in (("Open Dashboard", self.open_dashboard), ("Start", self.start_stack),
                                ("Stop", self.stop_stack), ("Restart", self.restart_stack),
                                ("Status", self.show_status)):
            action = QAction(title, self)
            action.triggered.connect(callback)
            menu.addAction(action)
        menu.addSeparator()
        self.startup_action = QAction("Start with Windows", self, checkable=True)
        self.startup_action.toggled.connect(self._sync_startup_from_tray)
        menu.addAction(self.startup_action)
        quit_action = QAction("Exit…", self)
        quit_action.triggered.connect(self.exit_app)
        menu.addAction(quit_action)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_activated)
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

    def _tray_activated(self, reason):
        if reason in (QSystemTrayIcon.ActivationReason.DoubleClick, QSystemTrayIcon.ActivationReason.Trigger):
            self.show_center()

    def show_center(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _update_about(self):
        branch, commit, dirty = "unavailable", "unavailable", "unknown"
        git = shutil.which("git")
        if git:
            try:
                branch = subprocess.run([git, "-C", str(self.root), "branch", "--show-current"], capture_output=True, text=True, timeout=3, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout.strip() or "detached"
                commit = subprocess.run([git, "-C", str(self.root), "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=3, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout.strip() or "unavailable"
                dirty = "dirty" if subprocess.run([git, "-C", str(self.root), "status", "--porcelain"], capture_output=True, text=True, timeout=3, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout.strip() else "clean"
            except Exception:
                pass
        build = "source" if not getattr(sys, "frozen", False) else time.strftime("%Y-%m-%d %H:%M")
        self.about.setText(f"HEX ALERT by HEX SECURITY · Version {APP_VERSION} · Build {build}\nProject: {self.root}\nGit: {branch} · {commit} · {dirty}")

    def set_status(self, text: str):
        self.status_label.setText(text)

    def _update_status(self, snapshot: dict):
        self._last_snapshot = snapshot
        health = snapshot.get("health") or {}
        rows = snapshot.get("containers", [])
        by_service = {str(row.get("Service", row.get("service", ""))).lower(): row for row in rows}

        def container_state(service: str) -> str:
            row = by_service.get(service, {})
            state = str(row.get("State", row.get("state", ""))).lower()
            status = str(row.get("Status", row.get("status", ""))).lower()
            container_health = str(row.get("Health", row.get("health", ""))).lower()
            if "unhealthy" in status or container_health == "unhealthy" or state == "exited":
                return "Unhealthy" if service == "db" else "Offline"
            if container_health == "healthy" or "(healthy)" in status:
                return "Healthy"
            if state in ("running", "restarting") or status.startswith("up"):
                return "Loading" if service == "llm" else "Starting"
            return "Stopped"

        docker_state = "Running" if snapshot.get("docker") else "Stopped"
        if not health:
            app = container_state("bot")
            dashboard = app if app in ("Starting", "Offline") else "Offline"
            db = container_state("db")
            ai = "Model not found" if not (self.root / "CyberSecurity.gguf").is_file() else container_state("llm")
            scheduler = "Stopped"
            discord = "Disconnected"
        else:
            db = "Healthy" if health.get("database") == "online" else "Unhealthy"
            app = "Online" if health.get("bot") == "online" else "Offline"
            dashboard = "Online" if health.get("backend") == "online" and health.get("frontend") == "online" else "Offline"
            ai_info = health.get("ai") or {}
            ai_status = str(ai_info.get("status", "offline")).lower()
            ai = "Ready" if ai_status in ("ready", "online") else "Loading" if ai_status in ("loading", "starting", "warming_up", "warming") else "Error" if ai_status == "error" else ("Model not found" if not (self.root / "CyberSecurity.gguf").is_file() else "Offline")
            scheduler = "Running" if health.get("scheduler") == "running" else "Stopped"
            discord = "Connected" if health.get("discord") == "connected" else "Disconnected"
            mode_test = bool(health.get("test_mode", True))
            self.test_badge.setText("TEST_MODE · ON" if mode_test else "TEST_MODE · OFF")
            self.production_badge.setText("PRODUCTION · OFF" if not health.get("production_mode", not mode_test) else "PRODUCTION · ON")
        if not health:
            self.test_badge.setText("TEST_MODE · UNKNOWN")
            self.production_badge.setText("PRODUCTION · UNKNOWN")
        values = {"Docker": docker_state, "Database": db, "Bot": app, "Dashboard": dashboard,
                  "Local AI": ai, "Scheduler": scheduler, "Discord": discord}
        for name, value in values.items():
            label = self.indicators[name]
            label.setText(value)
            good = value.lower() in {"running", "healthy", "online", "ready", "connected"}
            loading = value.lower() in {"starting", "loading"}
            label.setStyleSheet(f"font-weight:700;color:{'#69dfbf' if good else '#f4c76b' if loading else '#ff8998'}")
        self.dashboard_button.setEnabled(dashboard == "Online")
        if not self._busy:
            self.status_label.setText("HEX ALERT READY" if dashboard == "Online" and db == "Healthy" else "Refresh status or start HEX ALERT.")
        self.tray.setToolTip(f"HEX ALERT — Dashboard {dashboard} · AI {ai} · TEST_MODE")

    def _run_operation(self, title: str, operation, *, open_dashboard: bool = False, exit_after: bool = False):
        if self._busy:
            self.set_status("Another launcher operation is still running.")
            return
        self._busy = True
        self._exit_services_after_stop = exit_after
        self.set_status(title)

        def worker():
            try:
                message = operation(lambda value: self.bridge.progress.emit(value))
                action = "exit" if exit_after else "dashboard" if open_dashboard else ""
                self.bridge.result.emit(message or "Operation complete.", True, action)
            except Exception as exc:
                message = str(exc) or type(exc).__name__
                self.bridge.result.emit(redact(message), False, "")

        threading.Thread(target=worker, name="HexAlertControlOperation", daemon=True).start()

    def _operation_finished(self, message: str, success: bool, action: str):
        self._busy = False
        self.set_status(message)
        self.refresh_status()
        if success and action == "dashboard" and self.preferences.get("open_dashboard_after_start", True):
            import webbrowser
            webbrowser.open(URL)
        elif success and action == "exit":
            self._finish_exit()
        elif not success:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Critical)
            box.setWindowTitle("HEX ALERT could not complete the operation")
            box.setText(message)
            box.setDetailedText(redact(message))
            box.exec()

    @staticmethod
    def _port_occupied() -> bool:
        import socket
        with socket.socket() as probe:
            probe.settimeout(0.4)
            return probe.connect_ex(("127.0.0.1", 8080)) == 0

    def _port_conflict_detail(self) -> str:
        try:
            output = subprocess.run(["netstat", "-ano", "-p", "tcp"], capture_output=True, text=True, timeout=4, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
            for line in output.splitlines():
                columns = line.split()
                if len(columns) >= 5 and columns[1].endswith(":8080") and columns[3].upper() == "LISTENING":
                    return f"Port 8080 is already in use by PID {columns[4]}. Close that application or change its port, then retry."
        except Exception:
            pass
        return "Port 8080 is already in use. Close the application using it, then retry."

    def start_stack(self):
        def operation(progress):
            progress("Checking project files and Docker Desktop…")
            created = ensure_config(self.root)
            if created:
                progress("Created private first-run configuration with generated secrets.")
            self.docker.set_root(self.root)
            self.docker.ensure_engine(progress, 120)
            current_health = read_health()
            if self._port_occupied() and not current_health:
                raise RuntimeError(self._port_conflict_detail())
            model_present = (self.root / "CyberSecurity.gguf").is_file()
            progress("Starting PostgreSQL and HEX ALERT services…")
            self.docker.start(progress)
            if not model_present:
                progress("Local AI model not found. Starting the dashboard, bot, database, and scheduler without Local AI.")
            else:
                progress("Local AI is loading CyberSecurity.gguf in the background; other services remain available.")
            db_deadline = time.monotonic() + 60
            backend_deadline = time.monotonic() + 60
            database_ready = False
            last = {}
            while time.monotonic() < max(db_deadline, backend_deadline):
                last = read_health()
                if last.get("database") == "online":
                    if not database_ready:
                        progress("PostgreSQL healthy.")
                    database_ready = True
                if database_ready and last.get("backend") == "online" and last.get("frontend") == "online":
                    if last.get("scheduler") == "running":
                        progress("Dashboard and scheduler healthy. Discord connection is shown separately.")
                        return "HEX ALERT ready. Local AI status continues updating while the model loads."
                time.sleep(2)
            if not database_ready:
                raise RuntimeError("PostgreSQL failed its health check within 60 seconds. Open Logs for details.")
            raise RuntimeError("HEX ALERT backend/dashboard did not become healthy within 60 seconds. Open Logs for details.")

        self._run_operation("Checking Docker…", operation, open_dashboard=True)

    def stop_stack(self):
        self._run_operation("Gracefully stopping containers without deleting them or their volumes…",
                            lambda _progress: (self.docker.stop(), "HEX ALERT stopped. Containers, volumes, and data were preserved.")[1])

    def restart_stack(self):
        def operation(progress):
            self.docker.set_root(self.root)
            self.docker.ensure_engine(progress, 120)
            progress("Restarting HEX ALERT services; PostgreSQL volumes are untouched…")
            self.docker.restart()
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                state = read_health()
                if state.get("backend") == "online" and state.get("database") == "online" and state.get("scheduler") == "running":
                    return "HEX ALERT restarted. Local AI may continue loading in the background."
                time.sleep(2)
            raise RuntimeError("Services restarted, but backend/database health did not recover within 60 seconds.")
        self._run_operation("Restarting HEX ALERT…", operation, open_dashboard=True)

    def refresh_status(self):
        try:
            self._update_status({"docker": self.docker.engine_ready(), "containers": self.docker.compose_rows(), "health": read_health()})
        except Exception:
            self._update_status({"docker": False, "containers": [], "health": read_health()})

    def open_dashboard(self):
        state = read_health()
        if state.get("backend") == "online" and state.get("frontend") == "online":
            import webbrowser
            webbrowser.open(URL)
        else:
            QMessageBox.information(self, "Dashboard unavailable", "Start HEX ALERT and wait until Dashboard shows Online.")

    def view_logs(self):
        self.docker.set_root(self.root)
        LogViewer(self.docker, self).exec()

    def ai_status(self):
        health = read_health()
        ai = health.get("ai", {})
        status = str(ai.get("status", "offline")).title()
        mode = "Local AI" if ai.get("provider") == "local_gguf" else str(ai.get("provider", "Unavailable"))
        QMessageBox.information(self, "HEX ALPHA · Local AI Status",
                                f"AI: {mode}\nModel: {ai.get('model', 'CyberSecurity.gguf')}\nStatus: {status}\nBackend: {ai.get('backend', 'llama.cpp')}\n\nThe Local AI service may take up to about two minutes to load after a cold start.")

    def discord_status(self):
        health = read_health()
        value = "Connected" if health.get("discord") == "connected" else "Disconnected"
        QMessageBox.information(self, "HEX ALERT · Discord Status", f"Discord: {value}\nTEST_MODE: {'ON' if health.get('test_mode', True) else 'OFF'}\nProduction Mode: {'ON' if health.get('production_mode', False) else 'OFF'}\n\nConfigure the bot token and server inside Dashboard → Discord → Connection. The launcher never displays credentials.")

    def show_status(self):
        self.refresh_status()
        lines = [f"{name}: {label.text()}" for name, label in self.indicators.items()]
        lines += [self.test_badge.text(), self.production_badge.text()]
        QMessageBox.information(self, "HEX ALERT System Status", "\n".join(lines))

    def open_settings(self):
        dialog = PreferencesDialog(self.preferences, self)
        dialog.saved.connect(self._apply_preferences)
        dialog.exec()

    def create_desktop_shortcut(self):
        target = Path(sys.executable).resolve() if getattr(sys, "frozen", False) else self.root / "launcher" / "launcher.py"
        script = (
            "$w=New-Object -ComObject WScript.Shell; "
            "$p=[Environment]::GetFolderPath('Desktop'); "
            "$s=$w.CreateShortcut((Join-Path $p 'HEX ALERT.lnk')); "
            f"$s.TargetPath='{str(target).replace(chr(39), chr(39)*2)}'; "
            f"$s.WorkingDirectory='{str(self.root).replace(chr(39), chr(39)*2)}'; "
            "$s.Save()"
        )
        import base64
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        try:
            result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                   capture_output=True, text=True, timeout=12,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode:
                raise RuntimeError(redact((result.stderr or "Windows could not create the shortcut.").strip()))
            self.set_status("Desktop shortcut created.")
        except Exception as exc:
            QMessageBox.warning(self, "Desktop Shortcut", redact(str(exc)))

    def _apply_preferences(self, values):
        self.preferences = values
        self.root = Path(values["project_root"])
        self.docker.set_root(self.root)
        self.poller.interval = values["health_poll_seconds"]
        self._update_about()
        self.set_status("Launcher settings saved. Secrets remain in the protected project configuration.")

    def startup_command(self) -> str:
        if getattr(sys, "frozen", False):
            return f'"{Path(sys.executable).resolve()}" --start'
        pythonw = Path(sys.executable).with_name("pythonw.exe")
        entry = self.root / "launcher" / "launcher.py"
        return f'"{pythonw if pythonw.exists() else sys.executable}" "{self.root / "launcher" / "launcher.py"}" --start'

    @classmethod
    def startup_enabled(cls) -> bool:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, cls.REGISTRY_KEY, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, cls.REGISTRY_VALUE)
                return "--start" in value
        except OSError:
            return False

    def toggle_startup(self, enabled: bool):
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.REGISTRY_KEY) as key:
                if enabled:
                    winreg.SetValueEx(key, self.REGISTRY_VALUE, 0, winreg.REG_SZ, self.startup_command())
                else:
                    try:
                        winreg.DeleteValue(key, self.REGISTRY_VALUE)
                    except FileNotFoundError:
                        pass
            self.preferences["start_with_windows"] = enabled
            save_preferences(self.preferences)
            self.startup_action.setChecked(enabled)
            self.set_status("Per-user Windows startup setting updated.")
        except OSError as exc:
            self.startup_toggle.blockSignals(True)
            self.startup_toggle.setChecked(not enabled)
            self.startup_toggle.blockSignals(False)
            QMessageBox.warning(self, "Windows startup setting", redact(str(exc)))

    def _sync_startup_from_tray(self, enabled: bool):
        self.startup_toggle.setChecked(enabled)

    def closeEvent(self, event: QCloseEvent):
        if self.preferences.get("close_to_tray", True) and self.tray.isVisible():
            self.hide()
            self.tray.showMessage("HEX ALERT", "Control Center is minimized to the system tray. Services continue running.", QSystemTrayIcon.MessageIcon.Information, 2500)
            event.ignore()
            return
        self.exit_app()
        event.ignore()

    def exit_app(self):
        box = QMessageBox(self)
        box.setWindowTitle("Exit HEX ALERT Control Center")
        box.setText("Do you want to stop HEX ALERT services too?")
        only = box.addButton("Exit launcher only", QMessageBox.ButtonRole.AcceptRole)
        stop = box.addButton("Stop services and exit", QMessageBox.ButtonRole.DestructiveRole)
        cancel = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(only)
        box.exec()
        choice = box.clickedButton()
        if choice == cancel:
            return
        if choice == stop:
            def operation(_progress):
                self.docker.stop()
                return "HEX ALERT services stopped; persistent data was preserved."
            self._run_operation("Stopping services before exit…", operation, exit_after=True)
            return
        self._finish_exit()

    def _finish_exit(self):
        if self.poller.isRunning():
            self.poller.stop()
            self.poller.wait(3000)
        self.tray.hide()
        QApplication.quit()


def focus_existing_instance() -> bool:
    if os.name != "nt":
        return False
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    if not handle:
        return False
    if ctypes.get_last_error() != 183:
        # Keep the handle alive for the application lifetime.
        global _MUTEX_HANDLE
        _MUTEX_HANDLE = handle
        return False
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetWindowTextW.argtypes = (wintypes.HWND, wintypes.LPWSTR, ctypes.c_int)
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.ShowWindow.argtypes = (wintypes.HWND, ctypes.c_int)
    user32.SetForegroundWindow.argtypes = (wintypes.HWND,)
    EnumWindows = user32.EnumWindows
    EnumWindows.argtypes = [ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p), ctypes.c_void_p]
    GetWindowTextW = user32.GetWindowTextW
    ShowWindow = user32.ShowWindow
    SetForegroundWindow = user32.SetForegroundWindow
    SW_RESTORE = 9
    found = {"hwnd": None}
    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def callback(hwnd, _):
        buffer = ctypes.create_unicode_buffer(256)
        GetWindowTextW(hwnd, buffer, 256)
        if "HEX ALERT Control Center" in buffer.value:
            found["hwnd"] = hwnd
            return False
        return True
    EnumWindows(callback, None)
    if found["hwnd"]:
        ShowWindow(found["hwnd"], SW_RESTORE)
        SetForegroundWindow(found["hwnd"])
    kernel32.CloseHandle(handle)
    return True


def main() -> int:
    if focus_existing_instance():
        return 0
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("HEX SECURITY")
    app.setFont(QFont("Segoe UI", 9))
    app.setQuitOnLastWindowClosed(False)
    window = Launcher()
    window.show()
    if "--start" in sys.argv:
        QTimer.singleShot(800, window.start_stack)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
