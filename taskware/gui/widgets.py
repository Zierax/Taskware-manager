"""
Taskware Manager - Custom Widgets
Reusable SOC-themed widgets for the dashboard.
"""

from PyQt6.QtWidgets import (
    QWidget, QLabel, QVBoxLayout, QHBoxLayout, QFrame,
    QProgressBar, QGraphicsDropShadowEffect
)
from PyQt6.QtCore import Qt, QPropertyAnimation, QEasingCurve, pyqtProperty
from PyQt6.QtGui import QColor, QPainter, QLinearGradient, QFont

from taskware.gui.styles import COLORS


class StatCard(QFrame):
    """
    A styled card widget displaying a single statistic
    with label, value, and optional color accent.
    """

    def __init__(self, title: str, value: str = "0",
                 accent_color: str = None, parent=None):
        super().__init__(parent)
        self._accent = accent_color or COLORS['accent_cyan']

        self.setFixedHeight(90)
        self.setMinimumWidth(160)
        self.setStyleSheet(f"""
            StatCard {{
                background-color: {COLORS['bg_medium']};
                border: 1px solid {COLORS['border_normal']};
                border-left: 3px solid {self._accent};
                border-radius: 8px;
                padding: 8px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        # Title
        self._title_label = QLabel(title)
        self._title_label.setStyleSheet(f"""
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: {COLORS['text_secondary']};
            background: transparent;
        """)
        layout.addWidget(self._title_label)

        # Value
        self._value_label = QLabel(value)
        self._value_label.setStyleSheet(f"""
            font-size: 26px;
            font-weight: bold;
            color: {self._accent};
            background: transparent;
        """)
        layout.addWidget(self._value_label)

    def set_value(self, value: str):
        self._value_label.setText(value)

    def set_accent(self, color: str):
        self._accent = color
        self._value_label.setStyleSheet(f"""
            font-size: 26px;
            font-weight: bold;
            color: {self._accent};
            background: transparent;
        """)
        self.setStyleSheet(f"""
            StatCard {{
                background-color: {COLORS['bg_medium']};
                border: 1px solid {COLORS['border_normal']};
                border-left: 3px solid {self._accent};
                border-radius: 8px;
                padding: 8px;
            }}
        """)


class RiskBadge(QLabel):
    """
    A colored badge showing risk level.
    """

    def __init__(self, score: int = 0, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setFixedSize(60, 24)
        self.set_score(score)

    def set_score(self, score: int):
        if score <= 20:
            bg = COLORS['risk_clean']
            text = "CLEAN"
        elif score <= 50:
            bg = COLORS['risk_low']
            text = "LOW"
        elif score <= 75:
            bg = COLORS['risk_medium']
            text = "MED"
        else:
            bg = COLORS['risk_high']
            text = "HIGH"

        self.setText(text)
        self.setStyleSheet(f"""
            background-color: {bg};
            color: #ffffff;
            font-size: 9px;
            font-weight: bold;
            border-radius: 4px;
            padding: 2px 6px;
            letter-spacing: 1px;
        """)


class ScoreBar(QProgressBar):
    """
    A styled progress bar showing suspicion score
    with color changing based on risk level.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTextVisible(True)
        self.setRange(0, 100)
        self.setValue(0)
        self.setFixedHeight(18)
        self._update_style(0)

    def setValue(self, value):
        super().setValue(value)
        self._update_style(value)

    def _update_style(self, value: int):
        if value <= 20:
            color = COLORS['risk_clean']
        elif value <= 50:
            color = COLORS['risk_low']
        elif value <= 75:
            color = COLORS['risk_medium']
        else:
            color = COLORS['risk_high']

        self.setStyleSheet(f"""
            QProgressBar {{
                background-color: {COLORS['bg_medium']};
                border: 1px solid {COLORS['border_subtle']};
                border-radius: 4px;
                text-align: center;
                color: {COLORS['text_primary']};
                font-size: 10px;
                font-weight: bold;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 3px;
            }}
        """)
        self.setFormat(f"{value}")


class SectionHeader(QFrame):
    """A styled section header with icon and title."""

    def __init__(self, icon: str, title: str, parent=None):
        super().__init__(parent)
        self.setFixedHeight(36)
        self.setStyleSheet(f"""
            SectionHeader {{
                background-color: {COLORS['bg_medium']};
                border: 1px solid {COLORS['border_subtle']};
                border-left: 3px solid {COLORS['accent_cyan']};
                border-radius: 4px;
            }}
        """)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 0, 12, 0)

        icon_label = QLabel(icon)
        icon_label.setStyleSheet(f"""
            font-size: 14px;
            background: transparent;
        """)
        layout.addWidget(icon_label)

        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            font-size: 12px;
            font-weight: bold;
            color: {COLORS['accent_cyan']};
            text-transform: uppercase;
            letter-spacing: 1px;
            background: transparent;
        """)
        layout.addWidget(title_label)
        layout.addStretch()


class PulsingDot(QWidget):
    """A small pulsing dot indicator for live monitoring status."""

    def __init__(self, color: str = "#3fb950", parent=None):
        super().__init__(parent)
        self.setFixedSize(12, 12)
        self._color = QColor(color)
        self._opacity = 1.0

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setOpacity(self._opacity)
        painter.setBrush(self._color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(2, 2, 8, 8)
        painter.end()
