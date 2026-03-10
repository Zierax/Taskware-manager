"""
Taskware Manager - Configuration
Central configuration for all application settings.
Supports persistent settings via ~/.config/taskware/config.json
"""

import os
import sys
import json
import logging

logger = logging.getLogger("taskware.config")

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TASKWARE_DIR = os.path.dirname(os.path.abspath(__file__))
YARA_RULES_DIR = os.path.join(TASKWARE_DIR, "yara_rules")
DATABASE_DIR = os.path.join(TASKWARE_DIR, "database")
DUMPS_DIR = os.path.join(BASE_DIR, "memory_dumps")
MODEL_DIR = os.path.join(BASE_DIR, "model")

# Config file path (~/.config/taskware/config.json)
CONFIG_DIR = os.path.expanduser("~/.config/taskware")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

# Ensure directories exist
for d in [YARA_RULES_DIR, DATABASE_DIR, DUMPS_DIR, CONFIG_DIR]:
    os.makedirs(d, exist_ok=True)

# ─── Monitor Settings ────────────────────────────────────────────────────────
PROCESS_REFRESH_INTERVAL_MS = 2000      # How often to refresh process list (ms)
NETWORK_REFRESH_INTERVAL_MS = 3000      # How often to refresh network connections
FILESYS_WATCH_PATHS = [                 # Directories to watch for file changes
    "/tmp",
    "/var/tmp",
    os.path.expanduser("~/.local"),
    os.path.expanduser("~/Downloads"),
]

# ─── Suspicion Score Weights ──────────────────────────────────────────────────
SCORE_WEIGHTS = {
    "temp_execution":       15,   # Running from /tmp or suspicious dirs
    "unsigned_binary":      0,    # Not applicable on Linux (no Authenticode)
    "high_entropy":         10,   # ELF section entropy > threshold
    "unusual_parent":       15,   # Abnormal parent-child relationship
    "network_no_dns":       10,   # Network connections to raw IPs
    "process_hollowing":    20,   # Hollowing pattern detected
    "known_bad_hash":       25,   # SHA256 in local threat DB
    "yara_match":           25,   # YARA rule hit
    "rapid_file_creation":  10,   # Mass file creation
    "hidden_window":        0,    # Not applicable on Linux
    "ml_malware":           20,   # ML model classifies as malware
    "suspicious_cmdline":   15,   # Suspicious command line patterns
}

# ─── Suspicion Thresholds ─────────────────────────────────────────────────────
SCORE_THRESHOLDS = {
    "clean":    20,
    "low":      50,
    "medium":   75,
    "high":     100,
}

# ─── Entropy Settings ────────────────────────────────────────────────────────
ENTROPY_THRESHOLD = 7.0   # Shannon entropy threshold for suspicious sections

# ─── Suspicious Paths (Linux) ────────────────────────────────────────────────
SUSPICIOUS_PATHS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/user/",
    "/.local/share/",
    "/Downloads/",
]

# ─── Known Legitimate Parent-Child Relationships (Linux) ─────────────────────
LEGITIMATE_PARENTS = {
    "systemd":       ["(none)"],     # PID 1
    "kthreadd":      ["(none)"],     # PID 2
    "sshd":          ["sshd", "systemd"],
    "cron":          ["systemd"],
    "atd":           ["systemd"],
    "dbus-daemon":   ["systemd", "dbus-launch"],
    "polkitd":       ["systemd"],
    "rsyslogd":      ["systemd"],
    "NetworkManager":["systemd"],
}

# ─── Hybrid Analysis API Defaults ────────────────────────────────────────────
DEFAULT_SETTINGS = {
    "hybrid_analysis": {
        "enabled": False,
        "api_key": "",
        "base_url": "https://www.hybrid-analysis.com/api/v2",
        "verify_ssl": True,
    },
    "general": {
        "process_refresh_ms": PROCESS_REFRESH_INTERVAL_MS,
        "network_refresh_ms": NETWORK_REFRESH_INTERVAL_MS,
        "max_score": 100,
        "auto_yara_scan": False,
        "strace_timeout": 60,
    },
    "ml_model": {
        "enabled": True,
        "model_dir": MODEL_DIR,
        "max_syscalls": 4000,
        "low_syscall_warning_threshold": 600,
    }
}


class AppSettings:
    """
    Persistent application settings stored in ~/.config/taskware/config.json.
    Supports Hybrid Analysis API key, ML model config, and general settings.
    """

    def __init__(self, config_path: str = None):
        self._path = config_path or CONFIG_FILE
        self._settings = dict(DEFAULT_SETTINGS)
        self.load()

    def load(self) -> bool:
        """Load settings from disk. Returns True if file existed."""
        if os.path.isfile(self._path):
            try:
                with open(self._path, 'r', encoding='utf-8') as f:
                    saved = json.load(f)
                # Merge saved into defaults (deep merge)
                self._deep_merge(self._settings, saved)
                logger.info(f"Settings loaded from {self._path}")
                return True
            except Exception as e:
                logger.warning(f"Failed to load settings: {e}")
        return False

    def save(self) -> bool:
        """Save current settings to disk."""
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            with open(self._path, 'w', encoding='utf-8') as f:
                json.dump(self._settings, f, indent=2)
            logger.info(f"Settings saved to {self._path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
            return False

    def get(self, section: str, key: str, default=None):
        """Get a setting value."""
        return self._settings.get(section, {}).get(key, default)

    def set(self, section: str, key: str, value):
        """Set a setting value."""
        if section not in self._settings:
            self._settings[section] = {}
        self._settings[section][key] = value

    def get_section(self, section: str) -> dict:
        """Get an entire settings section."""
        return dict(self._settings.get(section, {}))

    def set_section(self, section: str, data: dict):
        """Replace an entire settings section."""
        self._settings[section] = dict(data)

    @property
    def hybrid_analysis_enabled(self) -> bool:
        return self.get("hybrid_analysis", "enabled", False)

    @property
    def hybrid_analysis_api_key(self) -> str:
        return self.get("hybrid_analysis", "api_key", "")

    @property
    def hybrid_analysis_base_url(self) -> str:
        return self.get("hybrid_analysis", "base_url",
                        "https://www.hybrid-analysis.com/api/v2")

    @property
    def ml_enabled(self) -> bool:
        return self.get("ml_model", "enabled", True)

    @property
    def all_settings(self) -> dict:
        return dict(self._settings)

    @staticmethod
    def _deep_merge(base: dict, override: dict):
        """Merge override into base recursively."""
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                AppSettings._deep_merge(base[k], v)
            else:
                base[k] = v
