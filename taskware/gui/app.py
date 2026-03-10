"""
Taskware Manager - Main Application Window (Linux Only)
The primary PyQt6 application that assembles all panels
into a tabbed SOC-style interface.
"""

import sys
import os
import logging
import time

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
    QHBoxLayout, QLabel, QStatusBar, QMenuBar, QMenu, QMessageBox,
    QFileDialog, QSplitter
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QFont, QIcon

from taskware import __version__, __app_name__
from taskware.gui.styles import get_main_stylesheet, COLORS
from taskware.gui.dashboard import ProcessDashboard
from taskware.gui.network_panel import NetworkPanel
from taskware.gui.file_panel import FilePanel
from taskware.gui.yara_panel import YaraPanel
from taskware.gui.process_detail import ProcessDetailPanel
from taskware.gui.settings_panel import SettingsPanel
from taskware.core.process_monitor import ProcessMonitor
from taskware.core.network_monitor import NetworkMonitor
from taskware.core.file_monitor import FileMonitor
from taskware.core.yara_scanner import YaraScanner
from taskware.core.memory_dumper import MemoryDumper
from taskware.core.ml_engine import MLEngine
from taskware.detection.rule_engine import RuleEngine
from taskware.database.hash_db import HashDatabase
from taskware.config import AppSettings

logger = logging.getLogger("taskware.app")


class TaskwareApp(QMainWindow):
    """
    Main application window for Taskware Manager.
    Combines all monitoring panels into a tabbed SOC dashboard.
    """

    def __init__(self):
        super().__init__()

        # ── Check Linux ──────────────────────────────────────────────────
        if sys.platform == "win32":
            QMessageBox.critical(
                None, "Platform Error",
                "Taskware Manager is designed for Linux only.\n"
                "Please run this application on a Linux system."
            )
            sys.exit(1)

        # ── Load persistent settings ─────────────────────────────────────
        self._settings = AppSettings()

        # ── Initialize core engines ──────────────────────────────────────
        self._proc_mon = ProcessMonitor()
        self._net_mon = NetworkMonitor()
        self._file_mon = FileMonitor()
        self._yara_scanner = YaraScanner()
        self._memory_dumper = MemoryDumper()
        self._hash_db = HashDatabase()
        self._rule_engine = RuleEngine(
            self._proc_mon, self._net_mon,
            self._yara_scanner, self._hash_db,
            self._settings
        )

        # Start file monitoring
        if self._file_mon.is_available:
            self._file_mon.start()

        # Load YARA rules
        if self._yara_scanner.is_available:
            self._yara_scanner.load_rules()

        # ── Setup UI ─────────────────────────────────────────────────────
        self._setup_window()
        self._setup_menubar()
        self._setup_tabs()
        self._setup_statusbar()
        self._setup_clock()

    def _setup_window(self):
        """Configure main window properties."""
        self.setWindowTitle(
            f"🛡️ {__app_name__} v{__version__} — "
            f"Malware-Centric Process Monitor [Linux]"
        )
        self.setMinimumSize(1280, 800)
        self.resize(1600, 950)
        self.setStyleSheet(get_main_stylesheet())

        # Center on screen
        screen = QApplication.primaryScreen()
        if screen:
            screen_geo = screen.availableGeometry()
            x = (screen_geo.width() - self.width()) // 2
            y = (screen_geo.height() - self.height()) // 2
            self.move(x, y)

    def _setup_menubar(self):
        """Create the menu bar."""
        menubar = self.menuBar()

        # ── File Menu ─────────────────────────────────────────────────────
        file_menu = menubar.addMenu("&File")

        import_hashes = QAction("📥  Import Hash Database", self)
        import_hashes.triggered.connect(self._import_hashes)
        file_menu.addAction(import_hashes)

        import_yara = QAction("📂  Import YARA Rules", self)
        import_yara.triggered.connect(self._import_yara_rules)
        file_menu.addAction(import_yara)

        file_menu.addSeparator()

        settings_action = QAction("⚙️  Settings", self)
        settings_action.setShortcut("Ctrl+,")
        settings_action.triggered.connect(
            lambda: self._tabs.setCurrentWidget(self._settings_panel)
        )
        file_menu.addAction(settings_action)

        file_menu.addSeparator()

        exit_action = QAction("❌  Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # ── View Menu ─────────────────────────────────────────────────────
        view_menu = menubar.addMenu("&View")

        refresh_action = QAction("🔄  Force Refresh", self)
        refresh_action.setShortcut("F5")
        view_menu.addAction(refresh_action)

        # ── Tools Menu ────────────────────────────────────────────────────
        tools_menu = menubar.addMenu("&Tools")

        dump_list = QAction("💾  View Memory Dumps", self)
        dump_list.triggered.connect(self._show_dump_list)
        tools_menu.addAction(dump_list)

        ml_status = QAction("🤖  ML Model Status", self)
        ml_status.triggered.connect(self._show_ml_status)
        tools_menu.addAction(ml_status)

        ha_lookup = QAction("🔗  Hybrid Analysis Lookup", self)
        ha_lookup.triggered.connect(self._show_ha_lookup)
        tools_menu.addAction(ha_lookup)

        # ── Help Menu ─────────────────────────────────────────────────────
        help_menu = menubar.addMenu("&Help")

        about_action = QAction("ℹ️  About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    def _setup_tabs(self):
        """Create the main tabbed interface."""
        self._tabs = QTabWidget()

        # Tab 1: Process Dashboard
        self._dashboard = ProcessDashboard(
            self._proc_mon, self._net_mon, self._rule_engine)
        self._dashboard.yara_scan_requested.connect(
            self._on_yara_scan_from_dashboard)
        self._tabs.addTab(self._dashboard, "⚡  PROCESSES")

        # Tab 2: Network Monitor
        self._network_panel = NetworkPanel(self._net_mon)
        self._tabs.addTab(self._network_panel, "🌐  NETWORK")

        # Tab 3: File System Monitor
        self._file_panel = FilePanel(self._file_mon)
        self._tabs.addTab(self._file_panel, "📁  FILE SYSTEM")

        # Tab 4: YARA Scanner
        self._yara_panel = YaraPanel(self._yara_scanner)
        self._tabs.addTab(self._yara_panel, "🎯  YARA SCANNER")

        # Tab 5: Process Detail (Forensics)
        self._detail_panel = ProcessDetailPanel(self._proc_mon)
        self._dashboard.process_selected.connect(self._on_process_selected)
        self._tabs.addTab(self._detail_panel, "🔬  FORENSICS")

        # Tab 6: Settings
        self._settings_panel = SettingsPanel(self._settings)
        self._settings_panel.settings_changed.connect(self._on_settings_changed)
        self._tabs.addTab(self._settings_panel, "⚙️  SETTINGS")

        self.setCentralWidget(self._tabs)

    def _setup_statusbar(self):
        """Configure the status bar."""
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)

        ml_status = "Loaded" if self._rule_engine.ml_engine.is_available \
            else "Not available"
        ha_status = "Enabled" if self._settings.hybrid_analysis_enabled \
            else "Disabled"

        app_label = QLabel(
            f"  🛡️ {__app_name__} v{__version__}  |  "
            f"🐧 Linux Only  |  "
            f"🤖 ML: {ml_status}  |  "
            f"🔗 Hybrid Analysis: {ha_status}  |  "
            f"📊 Hash DB: {self._hash_db.get_total_count()} entries  |  "
            f"🎯 YARA: {'Loaded' if self._yara_scanner.rules_loaded else 'No rules'}  |  "
            f"📁 File Monitor: {'Active' if self._file_mon.is_available else 'Disabled'}"
        )
        app_label.setStyleSheet(f"""
            color: {COLORS['text_secondary']};
            font-size: 10px;
            background: transparent;
        """)
        self._statusbar.addWidget(app_label)
        self._app_status_label = app_label

        # Right: Clock
        self._clock_label = QLabel()
        self._clock_label.setStyleSheet(f"""
            color: {COLORS['accent_cyan']};
            font-size: 10px;
            font-weight: bold;
            background: transparent;
            padding-right: 8px;
        """)
        self._statusbar.addPermanentWidget(self._clock_label)

    def _setup_clock(self):
        """Setup the status bar clock."""
        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(self._update_clock)
        self._clock_timer.start(1000)
        self._update_clock()

    def _update_clock(self):
        now = time.strftime("%Y-%m-%d  %H:%M:%S")
        self._clock_label.setText(f"⏱ {now}")

    # ─── Actions ──────────────────────────────────────────────────────────

    def _on_process_selected(self, pid: int):
        """Handle process selection from dashboard."""
        snapshot = self._dashboard._current_data
        if pid in snapshot:
            self._detail_panel.show_process(pid, snapshot[pid])

    def _on_yara_scan_from_dashboard(self, pid: int):
        """Handle YARA scan request from dashboard."""
        self._tabs.setCurrentWidget(self._yara_panel)
        self._yara_panel.scan_pid(pid)

    def _on_settings_changed(self):
        """Handle settings change — reload components."""
        self._settings.load()
        logger.info("Settings reloaded")

    def _import_hashes(self):
        """Import hashes from a text file."""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Import Hash Database",
            "", "Text Files (*.txt *.csv);;All Files (*.*)"
        )
        if filepath:
            count = self._hash_db.import_hashes_from_file(filepath)
            QMessageBox.information(
                self, "Import Complete",
                f"Imported {count} hash(es) into the database."
            )

    def _import_yara_rules(self):
        """Import YARA rule files."""
        from taskware.config import YARA_RULES_DIR
        files, _ = QFileDialog.getOpenFileNames(
            self, "Import YARA Rules",
            "", "YARA Rules (*.yar *.yara);;All Files (*.*)"
        )
        if files:
            import shutil
            for f in files:
                dest = os.path.join(YARA_RULES_DIR, os.path.basename(f))
                shutil.copy2(f, dest)
            self._yara_scanner.load_rules()
            QMessageBox.information(
                self, "Import Complete",
                f"Imported {len(files)} YARA rule file(s)."
            )

    def _show_dump_list(self):
        """Show list of memory dumps."""
        dumps = self._memory_dumper.get_dump_list()
        if not dumps:
            QMessageBox.information(self, "Memory Dumps",
                                  "No memory dumps found.")
            return

        dump_text = "Memory Dumps:\n\n"
        for d in dumps:
            size_mb = d['size'] / (1024 * 1024)
            mod_time = time.strftime("%Y-%m-%d %H:%M:%S",
                                    time.localtime(d['modified']))
            dump_text += f"• {d['filename']} ({size_mb:.1f} MB) — {mod_time}\n"

        QMessageBox.information(self, "Memory Dumps", dump_text)

    def _show_ml_status(self):
        """Show ML model status."""
        ml = self._rule_engine.ml_engine
        status = "✅ Loaded and ready" if ml.is_available \
            else "❌ Not available"

        QMessageBox.information(
            self, "ML Model Status",
            f"Status: {status}\n\n"
            f"Model directory: {os.path.join(os.path.dirname(os.path.dirname(__file__)), 'model')}\n"
            f"Enabled in settings: {self._settings.ml_enabled}\n"
            f"Max syscalls: {self._settings.get('ml_model', 'max_syscalls', 4000)}\n"
            f"Low threshold: {self._settings.get('ml_model', 'low_syscall_warning_threshold', 600)}"
        )

    def _show_ha_lookup(self):
        """Prompt for hash and do Hybrid Analysis lookup."""
        from PyQt6.QtWidgets import QInputDialog

        if not self._settings.hybrid_analysis_enabled:
            QMessageBox.warning(
                self, "Hybrid Analysis",
                "Hybrid Analysis API is not enabled.\n"
                "Go to Settings → Hybrid Analysis to configure it."
            )
            return

        sha256, ok = QInputDialog.getText(
            self, "Hybrid Analysis Lookup",
            "Enter SHA256 hash to look up:"
        )
        if ok and sha256.strip():
            ha = self._rule_engine.ha_client
            result = ha.lookup_and_summarize(sha256.strip())
            if result.get("available"):
                info = (
                    f"Verdict: {result.get('verdict', 'Unknown')}\n"
                    f"Threat Score: {result.get('threat_score', 0)}\n"
                    f"Threat Level: {result.get('threat_level', 'N/A')}\n"
                    f"Malware Family: {result.get('malware_family', 'N/A')}\n"
                    f"Tags: {', '.join(result.get('tags', []))}\n"
                    f"Submissions: {result.get('submissions_count', 0)}"
                )
                QMessageBox.information(
                    self, "Hybrid Analysis Result", info)
            else:
                QMessageBox.warning(
                    self, "Hybrid Analysis",
                    f"Lookup failed: {result.get('reason', 'Unknown error')}")

    def _show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self, f"About {__app_name__}",
            f"""
            <h2>🛡️ {__app_name__}</h2>
            <p><b>Version:</b> {__version__}</p>
            <p><b>Platform:</b> Linux Only 🐧</p>
            <p><b>Privacy:</b> 100% Offline (unless Hybrid Analysis API enabled)</p>
            <hr>
            <p>A security operations center (SOC) tool for
            live malware analysis and threat hunting.</p>
            <p><b>Developed by Zierax:</b> <a href="https://github.com/Zierax" style="color: #39d2e0;">https://github.com/Zierax</a></p>
            <p>Features:</p>
            <ul>
                <li>Real-time suspicion scoring</li>
                <li>ML-based malware classification (syscall analysis)</li>
                <li>Process hollowing detection via /proc</li>
                <li>Parent-child anomaly detection</li>
                <li>YARA rule scanning</li>
                <li>Network DNS analysis</li>
                <li>File system monitoring</li>
                <li>Memory dumping via /proc/pid/mem</li>
                <li>Local hash database</li>
                <li>Hybrid Analysis API integration</li>
                <li>Persistent settings (~/.config/taskware/)</li>
            </ul>
            """
        )

    def closeEvent(self, event):
        """Clean up on close."""
        logger.info("Shutting down Taskware Manager...")
        self._file_mon.stop()
        self._hash_db.close()
        event.accept()


def run_app():
    """Launch the Taskware Manager application."""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
        datefmt='%H:%M:%S'
    )
    logger.info(f"Starting {__app_name__} v{__version__}")

    app = QApplication(sys.argv)
    app.setApplicationName(__app_name__)
    app.setApplicationVersion(__version__)

    # Set default font
    font = QFont("Cascadia Code", 10)
    font.setStyleHint(QFont.StyleHint.Monospace)
    app.setFont(font)

    window = TaskwareApp()
    window.show()

    sys.exit(app.exec())
