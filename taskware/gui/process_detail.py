"""
Taskware Manager - Process Detail Panel
Detailed view of a single process with full telemetry, 
threat analysis, and action capabilities.
"""

import time
import logging

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QGroupBox, QGridLayout, QFrame
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont

from taskware.gui.styles import COLORS
from taskware.gui.widgets import StatCard, ScoreBar, SectionHeader
from taskware.core.process_monitor import ProcessMonitor, ProcessInfo
from taskware.detection.suspicion_scorer import SuspicionScorer

logger = logging.getLogger("taskware.process_detail")


class ProcessDetailPanel(QWidget):
    """
    Detailed process analysis view showing full telemetry,
    threat indicators, and forensic data.
    """

    def __init__(self, proc_monitor: ProcessMonitor, parent=None):
        super().__init__(parent)
        self._proc_mon = proc_monitor
        self._current_pid = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Header
        header = SectionHeader("🔬", "PROCESS FORENSIC ANALYSIS")
        layout.addWidget(header)

        # Score display
        score_layout = QHBoxLayout()
        score_layout.setSpacing(16)

        self._score_label = QLabel("Select a process")
        self._score_label.setStyleSheet(f"""
            font-size: 18px;
            font-weight: bold;
            color: {COLORS['accent_cyan']};
            background: transparent;
        """)
        score_layout.addWidget(self._score_label)

        self._score_bar = ScoreBar()
        self._score_bar.setFixedWidth(200)
        score_layout.addWidget(self._score_bar)

        score_layout.addStretch()
        layout.addLayout(score_layout)

        # Detail text
        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        layout.addWidget(self._detail)

    def show_process(self, pid: int, proc: ProcessInfo):
        """Display detailed info for a process."""
        self._current_pid = pid
        score_color = SuspicionScorer.get_risk_color(proc.suspicion_score)
        risk_level = SuspicionScorer.get_risk_level(proc.suspicion_score)
        risk_emoji = SuspicionScorer.get_risk_emoji(proc.suspicion_score)

        self._score_label.setText(
            f"{risk_emoji} {proc.name} (PID: {proc.pid}) — "
            f"Score: {proc.suspicion_score}/100 [{risk_level}]"
        )
        self._score_label.setStyleSheet(f"""
            font-size: 16px;
            font-weight: bold;
            color: {score_color};
            background: transparent;
        """)
        self._score_bar.setValue(proc.suspicion_score)

        create_time = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(proc.create_time)
        ) if proc.create_time else "N/A"

        flags_html = ""
        for flag in proc.flags:
            flags_html += f'<div style="color: {COLORS["accent_orange"]}; margin: 2px 0;">  • {flag}</div>'

        if not flags_html:
            flags_html = f'<div style="color: {COLORS["accent_green"]};">  ✅ No suspicious indicators detected</div>'

        html = f"""
        <pre style="color: {COLORS['text_primary']}; font-family: 'Cascadia Code', monospace; font-size: 12px; line-height: 1.6;">
<span style="color: {COLORS['accent_cyan']}; font-weight: bold;">
╔══════════════════════════════════════════════════════════════════╗
║  TASKWARE FORENSIC REPORT                                        ║
╚══════════════════════════════════════════════════════════════════╝</span>

<span style="color: {COLORS['accent_blue']}; font-weight: bold;">── IDENTIFICATION ───────────────────────────────────────────</span>
  PID:              {proc.pid}
  Process Name:     {proc.name}
  Executable:       {proc.exe_path or 'N/A'}
  Command Line:     {proc.cmdline or 'N/A'}
  User:             {proc.username}
  Created:          {create_time}
  Status:           {proc.status}

<span style="color: {COLORS['accent_blue']}; font-weight: bold;">── RELATIONSHIPS ────────────────────────────────────────────</span>
  Parent PID:       {proc.parent_pid}
  Parent Name:      {proc.parent_name}
  Children:         {', '.join(str(c) for c in proc.children_pids) if proc.children_pids else 'None'}

<span style="color: {COLORS['accent_blue']}; font-weight: bold;">── RESOURCES ────────────────────────────────────────────────</span>
  CPU Usage:        {proc.cpu_percent:.1f}%
  Memory (RSS):     {proc.memory_rss_mb:.1f} MB
  Memory (VMS):     {proc.memory_vms_mb:.1f} MB
  Memory %:         {proc.memory_percent:.2f}%
  Threads:          {proc.num_threads}
  Connections:      {proc.num_connections}
  Open Files:       {proc.num_open_files}

<span style="color: {COLORS['accent_blue']}; font-weight: bold;">── SECURITY ─────────────────────────────────────────────────</span>
  From /tmp or Susp: {'⚠️ YES' if proc.is_from_temp else '✅ NO'}
  SHA256:           {proc.sha256 or 'N/A'}

<span style="color: {COLORS['accent_blue']}; font-weight: bold;">── ML CLASSIFICATION ────────────────────────────────────────</span>
  Predicted Type:   {proc.ml_prediction or 'N/A'}
  Confidence:       {f'{proc.ml_confidence:.1%}' if proc.ml_prediction else 'N/A'}

<span style="color: {COLORS['accent_orange']}; font-weight: bold;">── THREAT INDICATORS ────────────────────────────────────────</span>
{flags_html}
</pre>"""
        self._detail.setHtml(html)
