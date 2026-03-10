"""
Taskware Manager - Main Process Dashboard
The primary view showing all running processes with suspicion scores,
resource usage, and action buttons. Implements real-time filtering,
sorting, and color-coded threat levels.
"""

import time
import logging
from typing import Dict, Optional

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QLineEdit, QLabel, QComboBox, QPushButton, QMenu,
    QAbstractItemView, QMessageBox, QSplitter, QFrame, QTextEdit
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread, pyqtSlot
from PyQt6.QtGui import QColor, QAction, QFont, QIcon

from taskware.gui.styles import COLORS
from taskware.gui.widgets import StatCard, RiskBadge, ScoreBar, SectionHeader, PulsingDot
from taskware.core.process_monitor import ProcessMonitor, ProcessInfo
from taskware.core.network_monitor import NetworkMonitor
from taskware.detection.rule_engine import RuleEngine
from taskware.detection.suspicion_scorer import SuspicionScorer

logger = logging.getLogger("taskware.dashboard")


# ─── Worker Thread ────────────────────────────────────────────────────────────

class ProcessWorker(QThread):
    """Background thread that collects process telemetry."""
    data_ready = pyqtSignal(dict)   # Dict[int, ProcessInfo]
    error = pyqtSignal(str)

    def __init__(self, proc_monitor: ProcessMonitor,
                 rule_engine: RuleEngine):
        super().__init__()
        self._proc_mon = proc_monitor
        self._rule_engine = rule_engine
        self._running = False

    def run(self):
        self._running = True
        try:
            enriched = self._rule_engine.analyze_all_processes()
            self.data_ready.emit(enriched)
        except Exception as e:
            self.error.emit(str(e))

    def stop(self):
        self._running = False


# ─── Dashboard Widget ─────────────────────────────────────────────────────────

class ProcessDashboard(QWidget):
    """
    Main process monitoring dashboard with real-time table,
    stats cards, filtering, and process actions.
    """

    process_selected = pyqtSignal(int)   # PID
    yara_scan_requested = pyqtSignal(int)  # PID

    # Table column definitions
    COLUMNS = [
        ("Score", 60),
        ("Risk", 65),
        ("PID", 60),
        ("Name", 160),
        ("CPU %", 60),
        ("Memory", 80),
        ("Threads", 60),
        ("Net", 45),
        ("Parent", 120),
        ("User", 120),
        ("Path", 300),
        ("Flags", 250),
    ]

    def __init__(self, proc_monitor: ProcessMonitor,
                 net_monitor: NetworkMonitor,
                 rule_engine: RuleEngine,
                 parent=None):
        super().__init__(parent)
        self._proc_mon = proc_monitor
        self._net_mon = net_monitor
        self._rule_engine = rule_engine
        self._current_data: Dict[int, ProcessInfo] = {}
        self._filter_text = ""
        self._filter_risk = "ALL"
        self._sort_col = 0
        self._sort_order = Qt.SortOrder.DescendingOrder
        self._paused = False

        self._setup_ui()
        self._setup_refresh_timer()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # ── Stats Bar ─────────────────────────────────────────────────────
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(8)

        self._stat_total = StatCard("Total Processes", "0",
                                     COLORS['accent_cyan'])
        self._stat_suspicious = StatCard("Suspicious", "0",
                                          COLORS['accent_orange'])
        self._stat_critical = StatCard("Critical", "0",
                                        COLORS['accent_red'])
        self._stat_network = StatCard("Network Active", "0",
                                       COLORS['accent_blue'])
        self._stat_memory = StatCard("Total Memory", "0 MB",
                                      COLORS['accent_purple'])

        for card in [self._stat_total, self._stat_suspicious,
                     self._stat_critical, self._stat_network,
                     self._stat_memory]:
            stats_layout.addWidget(card)

        layout.addLayout(stats_layout)

        # ── Toolbar ───────────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        # Live indicator
        live_layout = QHBoxLayout()
        live_layout.setSpacing(4)
        self._live_dot = PulsingDot(COLORS['accent_green'])
        live_label = QLabel("LIVE")
        live_label.setStyleSheet(f"""
            color: {COLORS['accent_green']};
            font-weight: bold;
            font-size: 11px;
            letter-spacing: 1px;
            background: transparent;
        """)
        live_layout.addWidget(self._live_dot)
        live_layout.addWidget(live_label)
        toolbar.addLayout(live_layout)

        toolbar.addSpacing(12)

        # Search
        search_icon = QLabel("🔍")
        search_icon.setStyleSheet("background: transparent;")
        toolbar.addWidget(search_icon)

        self._search_box = QLineEdit()
        self._search_box.setPlaceholderText("Filter processes by name, PID, or path...")
        self._search_box.setFixedHeight(32)
        self._search_box.setMinimumWidth(300)
        self._search_box.textChanged.connect(self._on_filter_changed)
        toolbar.addWidget(self._search_box)

        # Risk filter
        risk_label = QLabel("RISK:")
        risk_label.setStyleSheet(f"""
            color: {COLORS['text_secondary']};
            font-weight: bold;
            font-size: 10px;
            background: transparent;
        """)
        toolbar.addWidget(risk_label)

        self._risk_combo = QComboBox()
        self._risk_combo.addItems(["ALL", "HIGH", "MEDIUM", "LOW", "CLEAN"])
        self._risk_combo.setFixedWidth(100)
        self._risk_combo.currentTextChanged.connect(self._on_risk_filter_changed)
        toolbar.addWidget(self._risk_combo)

        toolbar.addStretch()

        # Pause/Resume
        self._pause_btn = QPushButton("⏸  PAUSE")
        self._pause_btn.setProperty("accent", True)
        self._pause_btn.setFixedWidth(100)
        self._pause_btn.clicked.connect(self._toggle_pause)
        toolbar.addWidget(self._pause_btn)

        # Refresh
        refresh_btn = QPushButton("🔄  REFRESH")
        refresh_btn.setFixedWidth(110)
        refresh_btn.clicked.connect(self._force_refresh)
        toolbar.addWidget(refresh_btn)

        layout.addLayout(toolbar)

        # ── Main Splitter (Table + Detail) ────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Process Table
        self._table = QTableWidget()
        self._table.setColumnCount(len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels([c[0] for c in self.COLUMNS])
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setSortingEnabled(True)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.selectionModel().selectionChanged.connect(self._on_selection_changed)
        self._table.horizontalHeader().sectionClicked.connect(self._on_sort_changed)

        # Set column widths
        header = self._table.horizontalHeader()
        for i, (name, width) in enumerate(self.COLUMNS):
            self._table.setColumnWidth(i, width)
        header.setStretchLastSection(True)

        splitter.addWidget(self._table)

        # Detail Panel
        detail_frame = QFrame()
        detail_layout = QVBoxLayout(detail_frame)
        detail_layout.setContentsMargins(0, 4, 0, 0)

        detail_header = SectionHeader("📋", "PROCESS DETAILS")
        detail_layout.addWidget(detail_header)

        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setMaximumHeight(150)
        self._detail_text.setPlaceholderText("Select a process to view details...")
        detail_layout.addWidget(self._detail_text)

        # Action buttons
        actions_layout = QHBoxLayout()
        actions_layout.setSpacing(8)

        self._btn_kill = QPushButton("☠  KILL")
        self._btn_kill.setProperty("danger", True)
        self._btn_kill.clicked.connect(self._on_kill)
        self._btn_kill.setEnabled(False)
        actions_layout.addWidget(self._btn_kill)

        self._btn_suspend = QPushButton("⏸  SUSPEND")
        self._btn_suspend.setProperty("accent", True)
        self._btn_suspend.clicked.connect(self._on_suspend)
        self._btn_suspend.setEnabled(False)
        actions_layout.addWidget(self._btn_suspend)

        self._btn_resume = QPushButton("▶  RESUME")
        self._btn_resume.setProperty("success", True)
        self._btn_resume.clicked.connect(self._on_resume)
        self._btn_resume.setEnabled(False)
        actions_layout.addWidget(self._btn_resume)

        self._btn_dump = QPushButton("💾  DUMP MEMORY")
        self._btn_dump.clicked.connect(self._on_dump_memory)
        self._btn_dump.setEnabled(False)
        actions_layout.addWidget(self._btn_dump)

        self._btn_yara = QPushButton("🎯  YARA SCAN")
        self._btn_yara.setProperty("accent", True)
        self._btn_yara.clicked.connect(self._on_yara_scan)
        self._btn_yara.setEnabled(False)
        actions_layout.addWidget(self._btn_yara)

        actions_layout.addStretch()
        detail_layout.addLayout(actions_layout)

        splitter.addWidget(detail_frame)
        splitter.setSizes([500, 200])

        layout.addWidget(splitter)

    def _setup_refresh_timer(self):
        from taskware.config import PROCESS_REFRESH_INTERVAL_MS
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._refresh_data)
        self._refresh_timer.start(PROCESS_REFRESH_INTERVAL_MS)
        # Initial load
        QTimer.singleShot(100, self._refresh_data)

    def _refresh_data(self):
        """Trigger background data collection."""
        if self._paused:
            return
            
        if hasattr(self, '_worker') and self._worker.isRunning():
            return

        self._worker = ProcessWorker(self._proc_mon, self._rule_engine)
        self._worker.data_ready.connect(self._on_data_ready)
        self._worker.error.connect(self._on_worker_error)
        self._worker.start()

    @pyqtSlot(dict)
    def _on_data_ready(self, data: Dict[int, ProcessInfo]):
        """Handle new process data from worker thread."""
        self._current_data = data
        self._update_stats()
        self._update_table()

    @pyqtSlot(str)
    def _on_worker_error(self, error: str):
        logger.error(f"Worker error: {error}")

    def _update_stats(self):
        """Update the stats cards."""
        total = len(self._current_data)
        suspicious = sum(1 for p in self._current_data.values()
                        if 50 < p.suspicion_score <= 75)
        critical = sum(1 for p in self._current_data.values()
                      if p.suspicion_score > 75)
        net_active = sum(1 for p in self._current_data.values()
                        if p.num_connections > 0)
        total_mem = sum(p.memory_rss for p in self._current_data.values())

        self._stat_total.set_value(str(total))
        self._stat_suspicious.set_value(str(suspicious))
        self._stat_critical.set_value(str(critical))
        self._stat_network.set_value(str(net_active))
        self._stat_memory.set_value(f"{total_mem / (1024**3):.1f} GB")

        # Color critical stat if > 0
        if critical > 0:
            self._stat_critical.set_accent(COLORS['accent_red'])
        else:
            self._stat_critical.set_accent(COLORS['accent_green'])

    def _update_table(self):
        """Update the process table with current data."""
        # Remember selection
        selected_pid = self._get_selected_pid()

        self._table.setSortingEnabled(False)

        # Filter data
        filtered = self._apply_filters()

        self._table.setRowCount(len(filtered))

        for row, proc in enumerate(filtered):
            score_color = SuspicionScorer.get_risk_color(proc.suspicion_score)

            # Score
            score_item = QTableWidgetItem()
            score_item.setData(Qt.ItemDataRole.DisplayRole, proc.suspicion_score)
            score_item.setForeground(QColor(score_color))
            score_item.setFont(QFont("Cascadia Code", 11, QFont.Weight.Bold))
            score_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 0, score_item)

            # Risk Level
            risk = SuspicionScorer.get_risk_level(proc.suspicion_score)
            risk_item = QTableWidgetItem(risk)
            risk_item.setForeground(QColor(score_color))
            risk_item.setFont(QFont("Cascadia Code", 9, QFont.Weight.Bold))
            risk_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 1, risk_item)

            # PID
            pid_item = QTableWidgetItem()
            pid_item.setData(Qt.ItemDataRole.DisplayRole, proc.pid)
            pid_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 2, pid_item)

            # Name
            name_item = QTableWidgetItem(proc.name)
            if proc.suspicion_score > 75:
                name_item.setForeground(QColor(COLORS['accent_red']))
                name_item.setFont(QFont("Cascadia Code", 11, QFont.Weight.Bold))
            self._table.setItem(row, 3, name_item)

            # CPU
            cpu_item = QTableWidgetItem(f"{proc.cpu_percent:.1f}")
            cpu_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            if proc.cpu_percent > 50:
                cpu_item.setForeground(QColor(COLORS['accent_orange']))
            self._table.setItem(row, 4, cpu_item)

            # Memory
            mem_str = f"{proc.memory_rss_mb:.1f} MB"
            mem_item = QTableWidgetItem(mem_str)
            mem_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._table.setItem(row, 5, mem_item)

            # Threads
            thread_item = QTableWidgetItem()
            thread_item.setData(Qt.ItemDataRole.DisplayRole, proc.num_threads)
            thread_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 6, thread_item)

            # Network connections
            net_item = QTableWidgetItem()
            net_item.setData(Qt.ItemDataRole.DisplayRole, proc.num_connections)
            net_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if proc.num_connections > 0:
                net_item.setForeground(QColor(COLORS['accent_blue']))
            self._table.setItem(row, 7, net_item)

            # Parent
            parent_str = f"{proc.parent_name} ({proc.parent_pid})" if proc.parent_pid else "N/A"
            self._table.setItem(row, 8, QTableWidgetItem(parent_str))

            # User
            self._table.setItem(row, 9, QTableWidgetItem(proc.username))

            # Path
            self._table.setItem(row, 10, QTableWidgetItem(proc.exe_path))

            # Flags
            flags_str = " | ".join(proc.flags[:3]) if proc.flags else ""
            flags_item = QTableWidgetItem(flags_str)
            if proc.flags:
                flags_item.setForeground(QColor(COLORS['accent_orange']))
            self._table.setItem(row, 11, flags_item)

            # Row height
            self._table.setRowHeight(row, 28)

        self._table.setSortingEnabled(True)

        # Restore selection
        if selected_pid:
            self._select_pid(selected_pid)

    def _apply_filters(self) -> list:
        """Apply search text and risk level filters."""
        filtered = []
        for proc in self._current_data.values():
            # Text filter
            if self._filter_text:
                search = self._filter_text.lower()
                searchable = f"{proc.pid} {proc.name} {proc.exe_path} {proc.username}".lower()
                if search not in searchable:
                    continue

            # Risk filter
            if self._filter_risk != "ALL":
                risk = SuspicionScorer.get_risk_level(proc.suspicion_score)
                if risk != self._filter_risk:
                    continue

            filtered.append(proc)

        # Sort by suspicion score descending by default
        filtered.sort(key=lambda p: p.suspicion_score, reverse=True)
        return filtered

    def _on_filter_changed(self, text: str):
        self._filter_text = text
        self._update_table()

    def _on_risk_filter_changed(self, risk: str):
        self._filter_risk = risk
        self._update_table()

    def _on_sort_changed(self, col: int):
        self._sort_col = col

    def _on_selection_changed(self):
        pid = self._get_selected_pid()
        if pid and pid in self._current_data:
            proc = self._current_data[pid]
            self._show_process_detail(proc)
            self._btn_kill.setEnabled(True)
            self._btn_suspend.setEnabled(True)
            self._btn_resume.setEnabled(True)
            self._btn_dump.setEnabled(True)
            self._btn_yara.setEnabled(True)
            self.process_selected.emit(pid)
        else:
            self._btn_kill.setEnabled(False)
            self._btn_suspend.setEnabled(False)
            self._btn_resume.setEnabled(False)
            self._btn_dump.setEnabled(False)
            self._btn_yara.setEnabled(False)

    def _show_process_detail(self, proc: ProcessInfo):
        """Show detailed info for selected process."""
        risk_emoji = SuspicionScorer.get_risk_emoji(proc.suspicion_score)
        risk_level = SuspicionScorer.get_risk_level(proc.suspicion_score)

        detail = f"""<pre style="color: {COLORS['text_primary']}; font-family: 'Cascadia Code', monospace;">
<span style="color: {COLORS['accent_cyan']}; font-weight: bold;">═══ PROCESS DETAIL ═══</span>

{risk_emoji} <b>Suspicion Score:</b> <span style="color: {SuspicionScorer.get_risk_color(proc.suspicion_score)};">{proc.suspicion_score}/100 ({risk_level})</span>

<span style="color: {COLORS['accent_blue']};">PID:</span>         {proc.pid}
<span style="color: {COLORS['accent_blue']};">Name:</span>        {proc.name}
<span style="color: {COLORS['accent_blue']};">Path:</span>        {proc.exe_path or 'N/A'}
<span style="color: {COLORS['accent_blue']};">Command:</span>     {proc.cmdline or 'N/A'}
<span style="color: {COLORS['accent_blue']};">Parent:</span>      {proc.parent_name} (PID: {proc.parent_pid})
<span style="color: {COLORS['accent_blue']};">User:</span>        {proc.username}
<span style="color: {COLORS['accent_blue']};">Status:</span>      {proc.status}
<span style="color: {COLORS['accent_blue']};">CPU:</span>         {proc.cpu_percent:.1f}%
<span style="color: {COLORS['accent_blue']};">Memory:</span>      {proc.memory_rss_mb:.1f} MB (RSS) / {proc.memory_vms_mb:.1f} MB (VMS)
<span style="color: {COLORS['accent_blue']};">Threads:</span>     {proc.num_threads}
<span style="color: {COLORS['accent_blue']};">Connections:</span> {proc.num_connections}
<span style="color: {COLORS['accent_blue']};">ML:</span>          {proc.ml_prediction or 'N/A'} {'(' + f'{proc.ml_confidence:.1%}' + ')' if proc.ml_prediction else ''}
<span style="color: {COLORS['accent_blue']};">SHA256:</span>      {proc.sha256[:32] + '...' if proc.sha256 else 'N/A'}

<span style="color: {COLORS['accent_orange']}; font-weight: bold;">Flags:</span> {', '.join(proc.flags) if proc.flags else 'None'}
</pre>"""
        self._detail_text.setHtml(detail)

    def _show_context_menu(self, pos):
        """Show right-click context menu for process actions."""
        pid = self._get_selected_pid()
        if not pid:
            return

        menu = QMenu(self)

        kill_action = menu.addAction("☠  Kill Process")
        kill_action.triggered.connect(self._on_kill)

        suspend_action = menu.addAction("⏸  Suspend Process")
        suspend_action.triggered.connect(self._on_suspend)

        resume_action = menu.addAction("▶  Resume Process")
        resume_action.triggered.connect(self._on_resume)

        menu.addSeparator()

        dump_action = menu.addAction("💾  Dump Memory")
        dump_action.triggered.connect(self._on_dump_memory)

        yara_action = menu.addAction("🎯  YARA Scan")
        yara_action.triggered.connect(self._on_yara_scan)

        menu.exec(self._table.viewport().mapToGlobal(pos))

    def _get_selected_pid(self) -> Optional[int]:
        rows = self._table.selectionModel().selectedRows()
        if rows:
            pid_item = self._table.item(rows[0].row(), 2)
            if pid_item:
                return int(pid_item.data(Qt.ItemDataRole.DisplayRole))
        return None

    def _select_pid(self, pid: int):
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 2)
            if item and int(item.data(Qt.ItemDataRole.DisplayRole)) == pid:
                self._table.selectRow(row)
                break

    def _on_kill(self):
        pid = self._get_selected_pid()
        if pid:
            proc_name = self._current_data.get(pid, ProcessInfo(pid=pid)).name
            reply = QMessageBox.question(
                self, "Kill Process",
                f"Are you sure you want to KILL process {pid} ({proc_name})?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                success = self._proc_mon.kill_process(pid)
                if success:
                    QMessageBox.information(self, "Success",
                                          f"Process {pid} killed successfully.")
                else:
                    QMessageBox.warning(self, "Failed",
                                       f"Failed to kill process {pid}.")

    def _on_suspend(self):
        pid = self._get_selected_pid()
        if pid:
            success = self._proc_mon.suspend_process(pid)
            if success:
                QMessageBox.information(self, "Success",
                                      f"Process {pid} suspended.")

    def _on_resume(self):
        pid = self._get_selected_pid()
        if pid:
            success = self._proc_mon.resume_process(pid)
            if success:
                QMessageBox.information(self, "Success",
                                      f"Process {pid} resumed.")

    def _on_dump_memory(self):
        pid = self._get_selected_pid()
        if pid:
            from taskware.core.memory_dumper import MemoryDumper
            dumper = MemoryDumper()
            result = dumper.dump_process(pid)
            if result:
                QMessageBox.information(self, "Memory Dump",
                                      f"Dump saved to:\n{result}")
            else:
                QMessageBox.warning(self, "Dump Failed",
                                   f"Failed to dump memory for PID {pid}.\n"
                                   "Run as root (sudo) for full access.")

    def _on_yara_scan(self):
        pid = self._get_selected_pid()
        if pid:
            self.yara_scan_requested.emit(pid)

    def _toggle_pause(self):
        self._paused = not self._paused
        if self._paused:
            self._pause_btn.setText("▶  RESUME")
            self._live_dot._color = QColor(COLORS['accent_yellow'])
        else:
            self._pause_btn.setText("⏸  PAUSE")
            self._live_dot._color = QColor(COLORS['accent_green'])
        self._live_dot.update()

    def _force_refresh(self):
        self._paused = False
        self._pause_btn.setText("⏸  PAUSE")
        self._live_dot._color = QColor(COLORS['accent_green'])
        self._live_dot.update()
        self._refresh_data()
