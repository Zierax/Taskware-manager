"""
Taskware Manager - File System Monitor Panel
Displays real-time filesystem events and alerts on suspicious activity.
"""

import os
import time
import logging

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QLabel, QPushButton, QAbstractItemView, QCheckBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QColor, QFont

from taskware.gui.styles import COLORS
from taskware.gui.widgets import StatCard, SectionHeader
from taskware.core.file_monitor import FileMonitor, FileEvent, SUSPICIOUS_EXTENSIONS

logger = logging.getLogger("taskware.file_panel")


class FilePanel(QWidget):
    """
    File system activity monitoring panel.
    Shows recent filesystem events with suspicious extension highlighting.
    """

    COLUMNS = [
        ("Time", 130),
        ("Event", 80),
        ("File Name", 200),
        ("Extension", 70),
        ("Full Path", 400),
        ("🚩", 40),
    ]

    def __init__(self, file_monitor: FileMonitor, parent=None):
        super().__init__(parent)
        self._file_mon = file_monitor
        self._show_only_suspicious = False

        self._setup_ui()
        self._setup_timer()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Stats
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(8)

        self._stat_events = StatCard("Total Events", "0", COLORS['accent_blue'])
        self._stat_suspicious = StatCard("Suspicious Files", "0", COLORS['accent_orange'])
        self._stat_rate = StatCard("Files/sec", "0", COLORS['accent_cyan'])
        self._stat_alert = StatCard("Rapid Creation Alert", "NO", COLORS['accent_green'])

        for card in [self._stat_events, self._stat_suspicious,
                     self._stat_rate, self._stat_alert]:
            stats_layout.addWidget(card)
        stats_layout.addStretch()

        layout.addLayout(stats_layout)

        # Controls
        controls = QHBoxLayout()

        status_label = QLabel("●  WATCHING" if self._file_mon.is_available else "○  DISABLED")
        status_label.setStyleSheet(f"""
            color: {COLORS['accent_green'] if self._file_mon.is_available else COLORS['accent_red']};
            font-weight: bold;
            font-size: 11px;
            background: transparent;
        """)
        controls.addWidget(status_label)

        controls.addSpacing(16)

        self._chk_suspicious = QCheckBox("Show only suspicious extensions")
        self._chk_suspicious.stateChanged.connect(self._on_filter_changed)
        controls.addWidget(self._chk_suspicious)

        controls.addStretch()

        clear_btn = QPushButton("🗑  CLEAR")
        clear_btn.setFixedWidth(90)
        clear_btn.setProperty("danger", True)
        clear_btn.clicked.connect(self._on_clear)
        controls.addWidget(clear_btn)

        layout.addLayout(controls)

        # Table
        self._table = QTableWidget()
        self._table.setColumnCount(len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels([c[0] for c in self.COLUMNS])
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        header = self._table.horizontalHeader()
        for i, (_, width) in enumerate(self.COLUMNS):
            self._table.setColumnWidth(i, width)
        header.setStretchLastSection(True)

        layout.addWidget(self._table)

    def _setup_timer(self):
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(2000)

    def _refresh(self):
        events = self._file_mon.get_recent_events(200)
        suspicious = self._file_mon.get_suspicious_events()

        # Stats
        self._stat_events.set_value(str(len(events)))
        self._stat_suspicious.set_value(str(len(suspicious)))
        self._stat_rate.set_value(str(self._file_mon.creation_rate))

        if self._file_mon.rapid_creation_alert:
            self._stat_alert.set_value("YES ⚠️")
            self._stat_alert.set_accent(COLORS['accent_red'])
        else:
            self._stat_alert.set_value("NO")
            self._stat_alert.set_accent(COLORS['accent_green'])

        # Table
        if self._show_only_suspicious:
            display_events = suspicious
        else:
            display_events = events

        # Reverse to show newest first
        display_events = list(reversed(display_events))

        self._table.setRowCount(len(display_events))

        for row, ev in enumerate(display_events):
            # Time
            ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
            self._table.setItem(row, 0, QTableWidgetItem(ts))

            # Event type
            type_item = QTableWidgetItem(ev.event_type.upper())
            type_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            type_colors = {
                "created": COLORS['accent_green'],
                "modified": COLORS['accent_blue'],
                "deleted": COLORS['accent_red'],
                "moved": COLORS['accent_yellow'],
            }
            type_item.setForeground(QColor(type_colors.get(ev.event_type,
                                                            COLORS['text_primary'])))
            self._table.setItem(row, 1, type_item)

            # File name
            fname = os.path.basename(ev.path)
            self._table.setItem(row, 2, QTableWidgetItem(fname))

            # Extension
            ext = os.path.splitext(ev.path)[1].lower()
            ext_item = QTableWidgetItem(ext)
            ext_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if ext in SUSPICIOUS_EXTENSIONS:
                ext_item.setForeground(QColor(COLORS['accent_red']))
                ext_item.setFont(QFont("Cascadia Code", 11, QFont.Weight.Bold))
            self._table.setItem(row, 3, ext_item)

            # Path
            self._table.setItem(row, 4, QTableWidgetItem(ev.path))

            # Flag
            flag = "⚠️" if ext in SUSPICIOUS_EXTENSIONS else ""
            flag_item = QTableWidgetItem(flag)
            flag_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 5, flag_item)

            self._table.setRowHeight(row, 24)

    def _on_filter_changed(self):
        self._show_only_suspicious = self._chk_suspicious.isChecked()

    def _on_clear(self):
        self._file_mon.clear_events()
        self._table.setRowCount(0)
