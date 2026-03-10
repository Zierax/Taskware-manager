"""
Taskware Manager - YARA Scanner Panel
Interface for loading YARA rules and scanning processes/files.
"""

import os
import logging

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton,
    QLabel, QFileDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QGroupBox, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QColor, QFont

from taskware.gui.styles import COLORS
from taskware.gui.widgets import StatCard, SectionHeader
from taskware.core.yara_scanner import YaraScanner, YaraMatch

logger = logging.getLogger("taskware.yara_panel")


class YaraScanWorker(QThread):
    """Background YARA scan worker."""
    scan_complete = pyqtSignal(list)   # List[YaraMatch]
    progress = pyqtSignal(str)

    def __init__(self, scanner: YaraScanner, target_pid: int = None,
                 target_file: str = None):
        super().__init__()
        self._scanner = scanner
        self._pid = target_pid
        self._file = target_file

    def run(self):
        matches = []
        try:
            if self._pid:
                self.progress.emit(f"Scanning PID {self._pid}...")
                matches = self._scanner.scan_process_executable(self._pid)
                self.progress.emit(f"Scanning memory of PID {self._pid}...")
                matches.extend(self._scanner.scan_process_memory(self._pid))
            elif self._file:
                self.progress.emit(f"Scanning {self._file}...")
                matches = self._scanner.scan_file(self._file)
        except Exception as e:
            self.progress.emit(f"Error: {e}")

        self.scan_complete.emit(matches)


class YaraPanel(QWidget):
    """
    YARA scanning interface.
    Load rules, scan processes or files, view results.
    """

    def __init__(self, yara_scanner: YaraScanner, parent=None):
        super().__init__(parent)
        self._scanner = yara_scanner
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Stats
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(8)

        available = "YES" if self._scanner.is_available else "NO (install yara-python)"
        self._stat_available = StatCard("YARA Available", available,
                                         COLORS['accent_green'] if self._scanner.is_available
                                         else COLORS['accent_red'])
        self._stat_rules = StatCard("Rules Loaded", "0", COLORS['accent_cyan'])
        self._stat_matches = StatCard("Total Matches", "0", COLORS['accent_orange'])

        stats_layout.addWidget(self._stat_available)
        stats_layout.addWidget(self._stat_rules)
        stats_layout.addWidget(self._stat_matches)
        stats_layout.addStretch()

        layout.addLayout(stats_layout)

        # Controls
        controls = QHBoxLayout()
        controls.setSpacing(8)

        load_btn = QPushButton("📂  LOAD RULES")
        load_btn.setProperty("accent", True)
        load_btn.clicked.connect(self._load_rules)
        controls.addWidget(load_btn)

        reload_btn = QPushButton("🔄  RELOAD")
        reload_btn.clicked.connect(self._reload_rules)
        controls.addWidget(reload_btn)

        controls.addSpacing(16)

        scan_file_btn = QPushButton("📄  SCAN FILE")
        scan_file_btn.clicked.connect(self._scan_file)
        controls.addWidget(scan_file_btn)

        scan_dir_btn = QPushButton("📁  SCAN DIRECTORY")
        scan_dir_btn.clicked.connect(self._scan_directory)
        controls.addWidget(scan_dir_btn)

        controls.addStretch()

        layout.addLayout(controls)

        # Progress
        self._progress_label = QLabel("Ready")
        self._progress_label.setStyleSheet(f"""
            color: {COLORS['text_secondary']};
            font-size: 11px;
            background: transparent;
        """)
        layout.addWidget(self._progress_label)

        # Results Table
        results_header = SectionHeader("🎯", "SCAN RESULTS")
        layout.addWidget(results_header)

        self._results_table = QTableWidget()
        self._results_table.setColumnCount(5)
        self._results_table.setHorizontalHeaderLabels([
            "Rule Name", "Namespace", "Tags", "Target", "Strings Matched"
        ])
        self._results_table.setAlternatingRowColors(True)
        self._results_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)

        header = self._results_table.horizontalHeader()
        self._results_table.setColumnWidth(0, 180)
        self._results_table.setColumnWidth(1, 120)
        self._results_table.setColumnWidth(2, 120)
        self._results_table.setColumnWidth(3, 200)
        header.setStretchLastSection(True)

        layout.addWidget(self._results_table)

        # Log
        log_header = SectionHeader("📝", "SCAN LOG")
        layout.addWidget(log_header)

        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setMaximumHeight(120)
        layout.addWidget(self._log)

    def _load_rules(self):
        if not self._scanner.is_available:
            self._log_message("❌ yara-python is not installed. Install with: pip install yara-python")
            return

        success = self._scanner.load_rules()
        if success:
            count = self._scanner.rule_count
            self._stat_rules.set_value(str(count))
            self._log_message(f"✅ Loaded {count} YARA rule file(s)")
        else:
            self._log_message("⚠️ No YARA rules found. Add .yar files to taskware/yara_rules/")

    def _reload_rules(self):
        self._load_rules()

    def _scan_file(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Select File to Scan", "",
            "All Files (*.*)")
        if filepath:
            self._run_scan(target_file=filepath)

    def _scan_directory(self):
        dirpath = QFileDialog.getExistingDirectory(
            self, "Select Directory to Scan")
        if dirpath:
            self._log_message(f"Scanning directory: {dirpath}")
            results = self._scanner.scan_directory(dirpath)
            all_matches = []
            for file_path, matches in results.items():
                all_matches.extend(matches)
            self._display_results(all_matches)

    def scan_pid(self, pid: int):
        """Scan a specific process (called from dashboard)."""
        self._run_scan(target_pid=pid)

    def _run_scan(self, target_pid=None, target_file=None):
        if not self._scanner.rules_loaded:
            self._load_rules()
            if not self._scanner.rules_loaded:
                self._log_message("❌ Cannot scan — no YARA rules loaded")
                return

        self._progress_label.setText("Scanning...")
        self._progress_label.setStyleSheet(f"""
            color: {COLORS['accent_yellow']};
            font-weight: bold;
            background: transparent;
        """)

        self._worker = YaraScanWorker(
            self._scanner, target_pid=target_pid, target_file=target_file)
        self._worker.progress.connect(self._on_progress)
        self._worker.scan_complete.connect(self._on_scan_complete)
        self._worker.start()

    @pyqtSlot(str)
    def _on_progress(self, msg: str):
        self._progress_label.setText(msg)
        self._log_message(msg)

    @pyqtSlot(list)
    def _on_scan_complete(self, matches: list):
        self._display_results(matches)
        self._progress_label.setText(f"Scan complete — {len(matches)} match(es) found")
        self._progress_label.setStyleSheet(f"""
            color: {COLORS['accent_green'] if not matches else COLORS['accent_red']};
            font-weight: bold;
            background: transparent;
        """)
        self._stat_matches.set_value(str(len(matches)))

        if matches:
            self._log_message(f"🔴 {len(matches)} YARA match(es) found!")
        else:
            self._log_message("🟢 No matches found — clean")

    def _display_results(self, matches: list):
        self._results_table.setRowCount(len(matches))
        for row, match in enumerate(matches):
            # Rule Name
            name_item = QTableWidgetItem(match.rule_name)
            name_item.setForeground(QColor(COLORS['accent_red']))
            name_item.setFont(QFont("Cascadia Code", 11, QFont.Weight.Bold))
            self._results_table.setItem(row, 0, name_item)

            # Namespace
            self._results_table.setItem(row, 1,
                QTableWidgetItem(match.namespace))

            # Tags
            self._results_table.setItem(row, 2,
                QTableWidgetItem(", ".join(match.tags)))

            # Target
            self._results_table.setItem(row, 3,
                QTableWidgetItem(match.target))

            # Strings
            strings_str = "; ".join(match.strings_matched[:5])
            self._results_table.setItem(row, 4,
                QTableWidgetItem(strings_str))

            self._results_table.setRowHeight(row, 26)

    def _log_message(self, msg: str):
        import time
        ts = time.strftime("%H:%M:%S")
        self._log.append(f"<span style='color: {COLORS['text_muted']};'>[{ts}]</span> {msg}")
