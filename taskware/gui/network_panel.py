"""
Taskware Manager - Network Connections Panel
Displays active network connections with DNS resolution status,
highlights no-DNS connections, and provides connection details.
"""

import logging
from typing import List

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QLabel, QCheckBox, QPushButton, QAbstractItemView
)
from PyQt6.QtCore import Qt, QTimer, pyqtSlot, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont

from taskware.gui.styles import COLORS
from taskware.gui.widgets import StatCard, SectionHeader
from taskware.core.network_monitor import NetworkMonitor, ConnectionInfo

logger = logging.getLogger("taskware.network_panel")


class NetworkWorker(QThread):
    """Background thread for network monitoring."""
    data_ready = pyqtSignal(list)

    def __init__(self, net_monitor: NetworkMonitor):
        super().__init__()
        self._net_mon = net_monitor

    def run(self):
        try:
            conns = self._net_mon.get_all_connections()
            self.data_ready.emit(conns)
        except Exception as e:
            logger.error(f"Network worker error: {e}")
            self.data_ready.emit([])


class NetworkPanel(QWidget):
    """
    Network connections monitoring panel.
    Shows all active sockets with DNS resolution status.
    """

    COLUMNS = [
        ("PID", 60),
        ("Process", 140),
        ("Protocol", 70),
        ("Local Address", 160),
        ("Local Port", 80),
        ("Remote Address", 160),
        ("Remote Port", 80),
        ("Status", 100),
        ("DNS", 200),
        ("🚩", 40),
    ]

    def __init__(self, net_monitor: NetworkMonitor, parent=None):
        super().__init__(parent)
        self._net_mon = net_monitor
        self._show_only_no_dns = False
        self._show_only_established = False
        self._current_data: List[ConnectionInfo] = []

        self._setup_ui()
        self._setup_timer()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Stats
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(8)

        self._stat_total = StatCard("Total Connections", "0",
                                     COLORS['accent_blue'])
        self._stat_established = StatCard("Established", "0",
                                           COLORS['accent_green'])
        self._stat_listening = StatCard("Listening", "0",
                                         COLORS['accent_cyan'])
        self._stat_no_dns = StatCard("No DNS (Suspicious)", "0",
                                      COLORS['accent_red'])

        for card in [self._stat_total, self._stat_established,
                     self._stat_listening, self._stat_no_dns]:
            stats_layout.addWidget(card)
        stats_layout.addStretch()

        layout.addLayout(stats_layout)

        # Filters
        filter_layout = QHBoxLayout()

        self._chk_no_dns = QCheckBox("Show only no-DNS connections")
        self._chk_no_dns.stateChanged.connect(self._on_filter_changed)
        filter_layout.addWidget(self._chk_no_dns)

        self._chk_established = QCheckBox("Established only")
        self._chk_established.stateChanged.connect(self._on_filter_changed)
        filter_layout.addWidget(self._chk_established)

        filter_layout.addStretch()

        refresh_btn = QPushButton("🔄  REFRESH")
        refresh_btn.setFixedWidth(110)
        refresh_btn.clicked.connect(self._refresh_data)
        filter_layout.addWidget(refresh_btn)

        layout.addLayout(filter_layout)

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
        from taskware.config import NETWORK_REFRESH_INTERVAL_MS
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh_data)
        self._timer.start(NETWORK_REFRESH_INTERVAL_MS)
        QTimer.singleShot(500, self._refresh_data)

    def _refresh_data(self):
        if hasattr(self, '_worker') and self._worker.isRunning():
            return
            
        self._worker = NetworkWorker(self._net_mon)
        self._worker.data_ready.connect(self._on_data_ready)
        self._worker.start()

    @pyqtSlot(list)
    def _on_data_ready(self, data: List[ConnectionInfo]):
        self._current_data = data
        self._update_stats()
        self._update_table()

    def _update_stats(self):
        total = len(self._current_data)
        established = sum(1 for c in self._current_data if c.status == "ESTABLISHED")
        listening = sum(1 for c in self._current_data if c.status == "LISTEN")
        no_dns = sum(1 for c in self._current_data
                    if c.remote_addr and not c.has_dns
                    and not NetworkMonitor._is_private_ip(c.remote_addr))

        self._stat_total.set_value(str(total))
        self._stat_established.set_value(str(established))
        self._stat_listening.set_value(str(listening))
        self._stat_no_dns.set_value(str(no_dns))

        if no_dns > 0:
            self._stat_no_dns.set_accent(COLORS['accent_red'])

    def _update_table(self):
        filtered = self._apply_filters()
        self._table.setRowCount(len(filtered))

        for row, conn in enumerate(filtered):
            # PID
            pid_item = QTableWidgetItem()
            pid_item.setData(Qt.ItemDataRole.DisplayRole, conn.pid)
            pid_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 0, pid_item)

            # Process
            self._table.setItem(row, 1, QTableWidgetItem(conn.process_name))

            # Protocol
            proto_item = QTableWidgetItem(f"{conn.conn_type}/{conn.family}")
            proto_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 2, proto_item)

            # Local Address
            self._table.setItem(row, 3, QTableWidgetItem(conn.local_addr))

            # Local Port
            port_item = QTableWidgetItem()
            port_item.setData(Qt.ItemDataRole.DisplayRole, conn.local_port)
            port_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 4, port_item)

            # Remote Address
            remote_item = QTableWidgetItem(conn.remote_addr)
            if conn.remote_addr and not conn.has_dns:
                remote_item.setForeground(QColor(COLORS['accent_red']))
                remote_item.setFont(QFont("Cascadia Code", 11, QFont.Weight.Bold))
            self._table.setItem(row, 5, remote_item)

            # Remote Port
            rport_item = QTableWidgetItem()
            rport_item.setData(Qt.ItemDataRole.DisplayRole, conn.remote_port)
            rport_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 6, rport_item)

            # Status
            status_item = QTableWidgetItem(conn.status)
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if conn.status == "ESTABLISHED":
                status_item.setForeground(QColor(COLORS['accent_green']))
            elif conn.status == "LISTEN":
                status_item.setForeground(QColor(COLORS['accent_blue']))
            self._table.setItem(row, 7, status_item)

            # DNS
            dns_item = QTableWidgetItem(conn.dns_resolved)
            if not conn.has_dns and conn.remote_addr:
                dns_item.setForeground(QColor(COLORS['accent_red']))
            self._table.setItem(row, 8, dns_item)

            # Flag
            flag = "⚠️" if (conn.remote_addr and not conn.has_dns
                            and not NetworkMonitor._is_private_ip(conn.remote_addr)) else ""
            flag_item = QTableWidgetItem(flag)
            flag_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 9, flag_item)

            self._table.setRowHeight(row, 26)

    def _apply_filters(self) -> List[ConnectionInfo]:
        filtered = self._current_data
        if self._show_only_no_dns:
            filtered = [c for c in filtered
                       if c.remote_addr and not c.has_dns
                       and not NetworkMonitor._is_private_ip(c.remote_addr)]
        if self._show_only_established:
            filtered = [c for c in filtered if c.status == "ESTABLISHED"]
        return filtered

    def _on_filter_changed(self):
        self._show_only_no_dns = self._chk_no_dns.isChecked()
        self._show_only_established = self._chk_established.isChecked()
        self._update_table()
