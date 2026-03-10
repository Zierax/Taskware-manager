"""
Taskware Manager - SOC Dark Mode Stylesheet
Premium Security Operations Center aesthetic with dark backgrounds,
neon accent colors, and tactical typography.
"""

# ─── Color Palette ────────────────────────────────────────────────────────────
COLORS = {
    "bg_darkest":       "#0a0e14",
    "bg_dark":          "#0d1117",
    "bg_medium":        "#161b22",
    "bg_light":         "#1c2333",
    "bg_elevated":      "#21262d",
    "bg_hover":         "#292e36",
    "bg_selected":      "#1a3a5c",

    "border_subtle":    "#21262d",
    "border_normal":    "#30363d",
    "border_bright":    "#484f58",

    "text_primary":     "#e6edf3",
    "text_secondary":   "#8b949e",
    "text_muted":       "#6e7681",
    "text_accent":      "#58a6ff",

    "accent_blue":      "#58a6ff",
    "accent_cyan":      "#39d2e0",
    "accent_green":     "#3fb950",
    "accent_yellow":    "#d29922",
    "accent_orange":    "#f0883e",
    "accent_red":       "#f85149",
    "accent_purple":    "#bc8cff",
    "accent_pink":      "#f778ba",

    "risk_clean":       "#22c55e",
    "risk_low":         "#f59e0b",
    "risk_medium":      "#f97316",
    "risk_high":        "#ef4444",

    "header_bg":        "#0f1923",
    "header_border":    "#1a3a5c",

    "scrollbar_bg":     "#161b22",
    "scrollbar_handle": "#30363d",
    "scrollbar_hover":  "#484f58",
}


def get_main_stylesheet() -> str:
    """Generate the complete SOC dark-mode QSS stylesheet."""
    c = COLORS
    return f"""
    /* ═══════════════════════════════════════════════════════════════════
       TASKWARE MANAGER — SOC DARK MODE STYLESHEET
       ═══════════════════════════════════════════════════════════════════ */

    /* ─── Global ──────────────────────────────────────────────────────── */
    QMainWindow {{
        background-color: {c['bg_darkest']};
        color: {c['text_primary']};
    }}

    QWidget {{
        background-color: {c['bg_dark']};
        color: {c['text_primary']};
        font-family: 'Cascadia Code', 'Consolas', 'JetBrains Mono', monospace;
        font-size: 12px;
    }}

    /* ─── Menu Bar ────────────────────────────────────────────────────── */
    QMenuBar {{
        background-color: {c['bg_darkest']};
        color: {c['text_primary']};
        border-bottom: 1px solid {c['border_normal']};
        padding: 2px 0px;
    }}

    QMenuBar::item {{
        padding: 4px 12px;
        background: transparent;
        border-radius: 4px;
    }}

    QMenuBar::item:selected {{
        background-color: {c['bg_hover']};
    }}

    QMenu {{
        background-color: {c['bg_elevated']};
        border: 1px solid {c['border_normal']};
        border-radius: 6px;
        padding: 4px;
    }}

    QMenu::item {{
        padding: 6px 24px 6px 12px;
        border-radius: 4px;
    }}

    QMenu::item:selected {{
        background-color: {c['bg_selected']};
    }}

    /* ─── Tab Widget ──────────────────────────────────────────────────── */
    QTabWidget::pane {{
        border: 1px solid {c['border_normal']};
        border-radius: 0px;
        background: {c['bg_dark']};
    }}

    QTabBar::tab {{
        background: {c['bg_medium']};
        color: {c['text_secondary']};
        padding: 8px 20px;
        border: 1px solid {c['border_subtle']};
        border-bottom: none;
        margin-right: 2px;
        font-weight: bold;
        font-size: 11px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }}

    QTabBar::tab:selected {{
        background: {c['bg_dark']};
        color: {c['accent_cyan']};
        border-bottom: 2px solid {c['accent_cyan']};
    }}

    QTabBar::tab:hover {{
        background: {c['bg_hover']};
        color: {c['text_primary']};
    }}

    /* ─── Table Widget ────────────────────────────────────────────────── */
    QTableWidget {{
        background-color: {c['bg_dark']};
        alternate-background-color: {c['bg_medium']};
        gridline-color: {c['border_subtle']};
        border: 1px solid {c['border_normal']};
        border-radius: 6px;
        selection-background-color: {c['bg_selected']};
        selection-color: {c['text_primary']};
    }}

    QTableWidget::item {{
        padding: 4px 8px;
        border-bottom: 1px solid {c['border_subtle']};
    }}

    QTableWidget::item:selected {{
        background-color: {c['bg_selected']};
    }}

    QHeaderView::section {{
        background-color: {c['header_bg']};
        color: {c['accent_cyan']};
        padding: 6px 8px;
        border: none;
        border-right: 1px solid {c['border_subtle']};
        border-bottom: 2px solid {c['header_border']};
        font-weight: bold;
        font-size: 10px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }}

    /* ─── Tree Widget ─────────────────────────────────────────────────── */
    QTreeWidget {{
        background-color: {c['bg_dark']};
        alternate-background-color: {c['bg_medium']};
        border: 1px solid {c['border_normal']};
        border-radius: 6px;
    }}

    QTreeWidget::item {{
        padding: 3px;
        border-bottom: 1px solid {c['border_subtle']};
    }}

    QTreeWidget::item:selected {{
        background-color: {c['bg_selected']};
    }}

    /* ─── Push Buttons ────────────────────────────────────────────────── */
    QPushButton {{
        background-color: {c['bg_elevated']};
        color: {c['text_primary']};
        border: 1px solid {c['border_normal']};
        border-radius: 6px;
        padding: 6px 16px;
        font-weight: bold;
        font-size: 11px;
    }}

    QPushButton:hover {{
        background-color: {c['bg_hover']};
        border-color: {c['accent_blue']};
    }}

    QPushButton:pressed {{
        background-color: {c['bg_selected']};
    }}

    QPushButton:disabled {{
        background-color: {c['bg_medium']};
        color: {c['text_muted']};
        border-color: {c['border_subtle']};
    }}

    /* Danger button */
    QPushButton[danger="true"] {{
        background-color: rgba(248, 81, 73, 0.15);
        color: {c['accent_red']};
        border-color: {c['accent_red']};
    }}

    QPushButton[danger="true"]:hover {{
        background-color: rgba(248, 81, 73, 0.3);
    }}

    /* Success button */
    QPushButton[success="true"] {{
        background-color: rgba(63, 185, 80, 0.15);
        color: {c['accent_green']};
        border-color: {c['accent_green']};
    }}

    QPushButton[success="true"]:hover {{
        background-color: rgba(63, 185, 80, 0.3);
    }}

    /* Accent button */
    QPushButton[accent="true"] {{
        background-color: rgba(57, 210, 224, 0.15);
        color: {c['accent_cyan']};
        border-color: {c['accent_cyan']};
    }}

    QPushButton[accent="true"]:hover {{
        background-color: rgba(57, 210, 224, 0.3);
    }}

    /* ─── Line Edit / Search ──────────────────────────────────────────── */
    QLineEdit {{
        background-color: {c['bg_medium']};
        color: {c['text_primary']};
        border: 1px solid {c['border_normal']};
        border-radius: 6px;
        padding: 6px 12px;
        selection-background-color: {c['accent_blue']};
    }}

    QLineEdit:focus {{
        border-color: {c['accent_cyan']};
    }}

    /* ─── Labels ──────────────────────────────────────────────────────── */
    QLabel {{
        background: transparent;
        color: {c['text_primary']};
    }}

    QLabel[heading="true"] {{
        font-size: 16px;
        font-weight: bold;
        color: {c['accent_cyan']};
    }}

    QLabel[subheading="true"] {{
        font-size: 12px;
        color: {c['text_secondary']};
    }}

    QLabel[stat="true"] {{
        font-size: 22px;
        font-weight: bold;
    }}

    /* ─── Group Box ───────────────────────────────────────────────────── */
    QGroupBox {{
        background-color: {c['bg_medium']};
        border: 1px solid {c['border_normal']};
        border-radius: 8px;
        margin-top: 12px;
        padding-top: 16px;
        font-weight: bold;
        color: {c['accent_cyan']};
    }}

    QGroupBox::title {{
        subcontrol-origin: margin;
        padding: 2px 8px;
        color: {c['accent_cyan']};
    }}

    /* ─── Scrollbar ───────────────────────────────────────────────────── */
    QScrollBar:vertical {{
        background: {c['scrollbar_bg']};
        width: 10px;
        border-radius: 5px;
    }}

    QScrollBar::handle:vertical {{
        background: {c['scrollbar_handle']};
        border-radius: 5px;
        min-height: 30px;
    }}

    QScrollBar::handle:vertical:hover {{
        background: {c['scrollbar_hover']};
    }}

    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0px;
    }}

    QScrollBar:horizontal {{
        background: {c['scrollbar_bg']};
        height: 10px;
        border-radius: 5px;
    }}

    QScrollBar::handle:horizontal {{
        background: {c['scrollbar_handle']};
        border-radius: 5px;
        min-width: 30px;
    }}

    QScrollBar::handle:horizontal:hover {{
        background: {c['scrollbar_hover']};
    }}

    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0px;
    }}

    /* ─── Splitter ────────────────────────────────────────────────────── */
    QSplitter::handle {{
        background-color: {c['border_subtle']};
    }}

    QSplitter::handle:horizontal {{
        width: 2px;
    }}

    QSplitter::handle:vertical {{
        height: 2px;
    }}

    /* ─── Status Bar ──────────────────────────────────────────────────── */
    QStatusBar {{
        background-color: {c['bg_darkest']};
        color: {c['text_secondary']};
        border-top: 1px solid {c['border_normal']};
        padding: 2px;
        font-size: 11px;
    }}

    /* ─── Progress Bar ────────────────────────────────────────────────── */
    QProgressBar {{
        background-color: {c['bg_medium']};
        border: 1px solid {c['border_normal']};
        border-radius: 4px;
        text-align: center;
        color: {c['text_primary']};
        height: 16px;
    }}

    QProgressBar::chunk {{
        background-color: {c['accent_cyan']};
        border-radius: 3px;
    }}

    /* ─── Tooltip ─────────────────────────────────────────────────────── */
    QToolTip {{
        background-color: {c['bg_elevated']};
        color: {c['text_primary']};
        border: 1px solid {c['border_bright']};
        border-radius: 4px;
        padding: 4px 8px;
    }}

    /* ─── Text Edit (Log Panel) ───────────────────────────────────────── */
    QTextEdit {{
        background-color: {c['bg_darkest']};
        color: {c['accent_green']};
        border: 1px solid {c['border_normal']};
        border-radius: 6px;
        padding: 8px;
        font-family: 'Cascadia Code', 'Consolas', monospace;
        font-size: 11px;
    }}

    /* ─── Combo Box ───────────────────────────────────────────────────── */
    QComboBox {{
        background-color: {c['bg_elevated']};
        color: {c['text_primary']};
        border: 1px solid {c['border_normal']};
        border-radius: 6px;
        padding: 4px 8px;
    }}

    QComboBox:hover {{
        border-color: {c['accent_blue']};
    }}

    QComboBox::drop-down {{
        border: none;
        width: 20px;
    }}

    QComboBox QAbstractItemView {{
        background-color: {c['bg_elevated']};
        color: {c['text_primary']};
        border: 1px solid {c['border_normal']};
        selection-background-color: {c['bg_selected']};
    }}

    /* ─── Check Box ───────────────────────────────────────────────────── */
    QCheckBox {{
        color: {c['text_primary']};
        spacing: 8px;
    }}

    QCheckBox::indicator {{
        width: 16px;
        height: 16px;
        border: 2px solid {c['border_normal']};
        border-radius: 4px;
        background-color: {c['bg_medium']};
    }}

    QCheckBox::indicator:checked {{
        background-color: {c['accent_cyan']};
        border-color: {c['accent_cyan']};
    }}

    /* ─── Dialog ──────────────────────────────────────────────────────── */
    QDialog {{
        background-color: {c['bg_dark']};
    }}

    QMessageBox {{
        background-color: {c['bg_dark']};
    }}
    """
