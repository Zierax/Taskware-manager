"""
Taskware Manager - Settings Panel
Configuration UI with Hybrid Analysis API integration,
ML model settings, and general preferences.
Settings persist in ~/.config/taskware/config.json
"""

import logging

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QCheckBox, QGroupBox, QFormLayout, QSpinBox,
    QMessageBox, QFrame, QTextEdit, QStackedWidget,
    QListWidget, QListWidgetItem, QSplitter
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont

from taskware.gui.styles import COLORS
from taskware.gui.widgets import SectionHeader
from taskware.config import AppSettings, CONFIG_FILE

logger = logging.getLogger("taskware.settings_panel")


class SettingsPanel(QWidget):
    """
    Settings panel with sections for:
    - Hybrid Analysis API (key, URL, SSL verification)
    - ML Model (enable/disable, thresholds)
    - General (refresh rates, strace timeout)
    """

    settings_changed = pyqtSignal()

    def __init__(self, settings: AppSettings, parent=None):
        super().__init__(parent)
        self._settings = settings
        self._setup_ui()
        self._load_from_settings()

    def _setup_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(0)

        # ── Left Navigation ──────────────────────────────────────────────
        nav = QListWidget()
        nav.setFixedWidth(200)
        nav.setStyleSheet(f"""
            QListWidget {{
                background: {COLORS['bg_medium']};
                border: 1px solid {COLORS['border_normal']};
                border-radius: 8px;
                padding: 8px;
                font-size: 13px;
            }}
            QListWidget::item {{
                padding: 12px 16px;
                border-radius: 6px;
                color: {COLORS['text_secondary']};
                margin: 2px 0;
            }}
            QListWidget::item:selected {{
                background: {COLORS['bg_elevated']};
                color: {COLORS['accent_cyan']};
                font-weight: bold;
            }}
            QListWidget::item:hover {{
                background: {COLORS['bg_elevated']};
            }}
        """)

        nav.addItem(QListWidgetItem("🔗  Hybrid Analysis"))
        nav.addItem(QListWidgetItem("🤖  ML Model"))
        nav.addItem(QListWidgetItem("⚙️  General"))
        nav.addItem(QListWidgetItem("📁  Config File"))

        nav.currentRowChanged.connect(self._on_nav_change)
        main_layout.addWidget(nav)

        # ── Right Content Stack ───────────────────────────────────────────
        self._stack = QStackedWidget()
        self._stack.setStyleSheet(f"""
            QStackedWidget {{
                background: transparent;
            }}
        """)

        # Page 0: Hybrid Analysis
        self._stack.addWidget(self._build_hybrid_analysis_page())
        # Page 1: ML Model
        self._stack.addWidget(self._build_ml_page())
        # Page 2: General
        self._stack.addWidget(self._build_general_page())
        # Page 3: Config File
        self._stack.addWidget(self._build_config_view_page())

        main_layout.addWidget(self._stack)

        nav.setCurrentRow(0)

    def _on_nav_change(self, index: int):
        self._stack.setCurrentIndex(index)
        if index == 3:
            self._refresh_config_view()

    # ─── Hybrid Analysis Page ─────────────────────────────────────────────

    def _build_hybrid_analysis_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(12)

        header = SectionHeader("🔗", "HYBRID ANALYSIS API")
        layout.addWidget(header)

        desc = QLabel(
            "Connect to Hybrid Analysis (Falcon Sandbox) for cloud-based "
            "malware analysis.\nGet your API key from: "
            "https://www.hybrid-analysis.com/settings\n\n"
            "Settings are saved to: ~/.config/taskware/config.json"
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"""
            color: {COLORS['text_secondary']};
            font-size: 12px;
            padding: 8px;
            background: {COLORS['bg_medium']};
            border: 1px solid {COLORS['border_normal']};
            border-radius: 6px;
        """)
        layout.addWidget(desc)

        # Form
        form_group = QGroupBox("API Configuration")
        form_layout = QFormLayout(form_group)
        form_layout.setSpacing(12)

        self._ha_enabled = QCheckBox("Enable Hybrid Analysis API")
        form_layout.addRow("", self._ha_enabled)

        self._ha_api_key = QLineEdit()
        self._ha_api_key.setPlaceholderText("Enter your Hybrid Analysis API key...")
        self._ha_api_key.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("API Key:", self._ha_api_key)

        self._ha_show_key = QCheckBox("Show API key")
        self._ha_show_key.toggled.connect(
            lambda checked: self._ha_api_key.setEchoMode(
                QLineEdit.EchoMode.Normal if checked
                else QLineEdit.EchoMode.Password
            )
        )
        form_layout.addRow("", self._ha_show_key)

        self._ha_base_url = QLineEdit()
        self._ha_base_url.setPlaceholderText(
            "https://www.hybrid-analysis.com/api/v2"
        )
        form_layout.addRow("Base URL:", self._ha_base_url)

        self._ha_verify_ssl = QCheckBox("Verify SSL certificates")
        self._ha_verify_ssl.setChecked(True)
        form_layout.addRow("", self._ha_verify_ssl)

        layout.addWidget(form_group)

        # Action buttons
        btn_layout = QHBoxLayout()

        test_btn = QPushButton("🧪  Test Connection")
        test_btn.setFixedHeight(36)
        test_btn.clicked.connect(self._test_hybrid_analysis)
        btn_layout.addWidget(test_btn)

        save_btn = QPushButton("💾  Save Settings")
        save_btn.setFixedHeight(36)
        save_btn.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['accent_green']};
                color: #000;
                font-weight: bold;
                border-radius: 6px;
                padding: 0 24px;
            }}
            QPushButton:hover {{
                background: #00c853;
            }}
        """)
        save_btn.clicked.connect(self._save_settings)
        btn_layout.addWidget(save_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        # Status
        self._ha_status = QLabel("")
        self._ha_status.setStyleSheet(f"""
            padding: 8px;
            border-radius: 6px;
            font-size: 12px;
        """)
        layout.addWidget(self._ha_status)

        layout.addStretch()
        return page

    # ─── ML Model Page ────────────────────────────────────────────────────

    def _build_ml_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(12)

        header = SectionHeader("🤖", "ML MODEL SETTINGS")
        layout.addWidget(header)

        desc = QLabel(
            "Configure the malware classification model.\n"
            "The model analyzes syscall sequences (captured via strace) "
            "to predict malware types.\n"
            "Model location: model/artifacts/model.joblib"
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"""
            color: {COLORS['text_secondary']};
            font-size: 12px;
            padding: 8px;
            background: {COLORS['bg_medium']};
            border: 1px solid {COLORS['border_normal']};
            border-radius: 6px;
        """)
        layout.addWidget(desc)

        form_group = QGroupBox("Model Configuration")
        form_layout = QFormLayout(form_group)
        form_layout.setSpacing(12)

        self._ml_enabled = QCheckBox("Enable ML model analysis")
        form_layout.addRow("", self._ml_enabled)

        self._ml_max_syscalls = QSpinBox()
        self._ml_max_syscalls.setRange(500, 50000)
        self._ml_max_syscalls.setSingleStep(500)
        form_layout.addRow("Max syscalls:", self._ml_max_syscalls)

        self._ml_low_threshold = QSpinBox()
        self._ml_low_threshold.setRange(100, 5000)
        self._ml_low_threshold.setSingleStep(100)
        form_layout.addRow("Low confidence threshold:", self._ml_low_threshold)

        layout.addWidget(form_group)

        # Save button
        save_btn = QPushButton("💾  Save ML Settings")
        save_btn.setFixedHeight(36)
        save_btn.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['accent_green']};
                color: #000;
                font-weight: bold;
                border-radius: 6px;
                padding: 0 24px;
            }}
            QPushButton:hover {{
                background: #00c853;
            }}
        """)
        save_btn.clicked.connect(self._save_settings)
        layout.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        layout.addStretch()
        return page

    # ─── General Page ─────────────────────────────────────────────────────

    def _build_general_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(12)

        header = SectionHeader("⚙️", "GENERAL SETTINGS")
        layout.addWidget(header)

        form_group = QGroupBox("Monitoring Configuration")
        form_layout = QFormLayout(form_group)
        form_layout.setSpacing(12)

        self._proc_refresh = QSpinBox()
        self._proc_refresh.setRange(500, 30000)
        self._proc_refresh.setSingleStep(500)
        self._proc_refresh.setSuffix(" ms")
        form_layout.addRow("Process refresh:", self._proc_refresh)

        self._net_refresh = QSpinBox()
        self._net_refresh.setRange(1000, 60000)
        self._net_refresh.setSingleStep(1000)
        self._net_refresh.setSuffix(" ms")
        form_layout.addRow("Network refresh:", self._net_refresh)

        self._strace_timeout = QSpinBox()
        self._strace_timeout.setRange(5, 300)
        self._strace_timeout.setSingleStep(5)
        self._strace_timeout.setSuffix(" sec")
        form_layout.addRow("Strace timeout:", self._strace_timeout)

        self._auto_yara = QCheckBox("Auto-YARA scan new processes")
        form_layout.addRow("", self._auto_yara)

        layout.addWidget(form_group)

        save_btn = QPushButton("💾  Save General Settings")
        save_btn.setFixedHeight(36)
        save_btn.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['accent_green']};
                color: #000;
                font-weight: bold;
                border-radius: 6px;
                padding: 0 24px;
            }}
            QPushButton:hover {{
                background: #00c853;
            }}
        """)
        save_btn.clicked.connect(self._save_settings)
        layout.addWidget(save_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        layout.addStretch()
        return page

    # ─── Config File View Page ────────────────────────────────────────────

    def _build_config_view_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(12)

        header = SectionHeader("📁", "CONFIG FILE")
        layout.addWidget(header)

        path_label = QLabel(f"Location: {CONFIG_FILE}")
        path_label.setStyleSheet(f"""
            color: {COLORS['accent_cyan']};
            font-size: 12px;
            padding: 8px;
            background: {COLORS['bg_medium']};
            border: 1px solid {COLORS['border_normal']};
            border-radius: 6px;
            font-family: 'Cascadia Code', monospace;
        """)
        layout.addWidget(path_label)

        self._config_view = QTextEdit()
        self._config_view.setReadOnly(True)
        self._config_view.setStyleSheet(f"""
            QTextEdit {{
                font-family: 'Cascadia Code', monospace;
                font-size: 12px;
                background: {COLORS['bg_darkest']};
                color: {COLORS['text_primary']};
                border: 1px solid {COLORS['border_normal']};
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        layout.addWidget(self._config_view)

        return page

    # ─── Data Loading / Saving ────────────────────────────────────────────

    def _load_from_settings(self):
        """Populate all form fields from current settings."""
        # Hybrid Analysis
        ha = self._settings.get_section("hybrid_analysis")
        self._ha_enabled.setChecked(ha.get("enabled", False))
        self._ha_api_key.setText(ha.get("api_key", ""))
        self._ha_base_url.setText(
            ha.get("base_url", "https://www.hybrid-analysis.com/api/v2")
        )
        self._ha_verify_ssl.setChecked(ha.get("verify_ssl", True))

        # ML Model
        ml = self._settings.get_section("ml_model")
        self._ml_enabled.setChecked(ml.get("enabled", True))
        self._ml_max_syscalls.setValue(ml.get("max_syscalls", 4000))
        self._ml_low_threshold.setValue(
            ml.get("low_syscall_warning_threshold", 600)
        )

        # General
        gen = self._settings.get_section("general")
        self._proc_refresh.setValue(gen.get("process_refresh_ms", 2000))
        self._net_refresh.setValue(gen.get("network_refresh_ms", 3000))
        self._strace_timeout.setValue(gen.get("strace_timeout", 60))
        self._auto_yara.setChecked(gen.get("auto_yara_scan", False))

    def _save_settings(self):
        """Save all form values to settings and persist to disk."""
        # Hybrid Analysis
        self._settings.set_section("hybrid_analysis", {
            "enabled": self._ha_enabled.isChecked(),
            "api_key": self._ha_api_key.text().strip(),
            "base_url": self._ha_base_url.text().strip()
                        or "https://www.hybrid-analysis.com/api/v2",
            "verify_ssl": self._ha_verify_ssl.isChecked(),
        })

        # ML Model
        self._settings.set_section("ml_model", {
            "enabled": self._ml_enabled.isChecked(),
            "model_dir": self._settings.get("ml_model", "model_dir", ""),
            "max_syscalls": self._ml_max_syscalls.value(),
            "low_syscall_warning_threshold": self._ml_low_threshold.value(),
        })

        # General
        self._settings.set_section("general", {
            "process_refresh_ms": self._proc_refresh.value(),
            "network_refresh_ms": self._net_refresh.value(),
            "strace_timeout": self._strace_timeout.value(),
            "auto_yara_scan": self._auto_yara.isChecked(),
            "max_score": 100,
        })

        if self._settings.save():
            QMessageBox.information(
                self, "Settings Saved",
                f"Configuration saved to:\n{CONFIG_FILE}"
            )
            self.settings_changed.emit()
        else:
            QMessageBox.critical(
                self, "Save Failed",
                "Could not save settings to disk."
            )

    def _test_hybrid_analysis(self):
        """Test the Hybrid Analysis API connection."""
        from taskware.core.hybrid_analysis import HybridAnalysisClient

        # Temporarily apply current form values
        self._settings.set("hybrid_analysis", "enabled", True)
        self._settings.set(
            "hybrid_analysis", "api_key",
            self._ha_api_key.text().strip()
        )
        self._settings.set(
            "hybrid_analysis", "base_url",
            self._ha_base_url.text().strip()
            or "https://www.hybrid-analysis.com/api/v2"
        )
        self._settings.set(
            "hybrid_analysis", "verify_ssl",
            self._ha_verify_ssl.isChecked()
        )

        client = HybridAnalysisClient(self._settings)
        result = client.test_connection()

        if result["success"]:
            self._ha_status.setText(f"✅ {result['detail']}")
            self._ha_status.setStyleSheet(f"""
                color: {COLORS['accent_green']};
                padding: 8px;
                background: rgba(0, 230, 118, 0.1);
                border: 1px solid {COLORS['accent_green']};
                border-radius: 6px;
                font-size: 12px;
            """)
        else:
            self._ha_status.setText(f"❌ {result['detail']}")
            self._ha_status.setStyleSheet(f"""
                color: {COLORS['accent_red']};
                padding: 8px;
                background: rgba(255, 23, 68, 0.1);
                border: 1px solid {COLORS['accent_red']};
                border-radius: 6px;
                font-size: 12px;
            """)

    def _refresh_config_view(self):
        """Display the current config file contents."""
        import json
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                content = f.read()
            self._config_view.setPlainText(content)
        except FileNotFoundError:
            self._config_view.setPlainText(
                "Config file not yet created.\n"
                "Save settings to create it."
            )
        except Exception as e:
            self._config_view.setPlainText(f"Error reading config: {e}")
