"""
Taskware Manager - YARA Scanner
On-demand YARA rule scanning for process memory and files.
Fully offline — uses local YARA rules only.
"""

import os
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict

import psutil

from taskware.config import YARA_RULES_DIR

logger = logging.getLogger("taskware.yara_scanner")

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    logger.warning("yara-python not installed — YARA scanning disabled")


@dataclass
class YaraMatch:
    """A single YARA rule match result."""
    rule_name: str
    namespace: str = ""
    tags: List[str] = field(default_factory=list)
    meta: Dict = field(default_factory=dict)
    strings_matched: List[str] = field(default_factory=list)
    target: str = ""  # file path or "PID:XXX"


class YaraScanner:
    """
    YARA-based scanner for on-demand file and process memory scanning.
    All rules are loaded from the local yara_rules directory.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self._rules_dir = rules_dir or YARA_RULES_DIR
        self._compiled_rules = None
        self._loaded = False
        self._rule_files: List[str] = []

    @property
    def is_available(self) -> bool:
        return HAS_YARA

    @property
    def rules_loaded(self) -> bool:
        return self._loaded

    @property
    def rule_count(self) -> int:
        return len(self._rule_files)

    def load_rules(self) -> bool:
        """Load and compile all YARA rules from the rules directory."""
        if not HAS_YARA:
            logger.error("Cannot load YARA rules — yara-python not installed")
            return False

        self._rule_files = []
        rule_sources = {}

        if not os.path.isdir(self._rules_dir):
            logger.warning(f"YARA rules directory not found: {self._rules_dir}")
            return False

        for fname in os.listdir(self._rules_dir):
            if fname.endswith(('.yar', '.yara')):
                fpath = os.path.join(self._rules_dir, fname)
                namespace = os.path.splitext(fname)[0]
                rule_sources[namespace] = fpath
                self._rule_files.append(fpath)

        if not rule_sources:
            logger.info("No YARA rule files found in rules directory")
            return False

        try:
            self._compiled_rules = yara.compile(filepaths=rule_sources)
            self._loaded = True
            logger.info(f"Loaded {len(rule_sources)} YARA rule file(s)")
            return True
        except yara.SyntaxError as e:
            logger.error(f"YARA rule syntax error: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            return False

    def scan_file(self, filepath: str) -> List[YaraMatch]:
        """Scan a file against loaded YARA rules."""
        if not self._loaded or not self._compiled_rules:
            logger.warning("YARA rules not loaded — call load_rules() first")
            return []

        matches = []
        try:
            results = self._compiled_rules.match(filepath)
            for match in results:
                ym = YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta=dict(match.meta),
                    strings_matched=[str(s) for s in (match.strings or [])[:10]],
                    target=filepath
                )
                matches.append(ym)
        except yara.Error as e:
            logger.error(f"YARA scan error on {filepath}: {e}")
        except Exception as e:
            logger.error(f"Error scanning {filepath}: {e}")

        return matches

    def scan_process_memory(self, pid: int) -> List[YaraMatch]:
        """Scan a process's memory against loaded YARA rules."""
        if not self._loaded or not self._compiled_rules:
            logger.warning("YARA rules not loaded — call load_rules() first")
            return []

        matches = []
        try:
            results = self._compiled_rules.match(pid=pid)
            for match in results:
                ym = YaraMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    tags=list(match.tags),
                    meta=dict(match.meta),
                    strings_matched=[str(s) for s in (match.strings or [])[:10]],
                    target=f"PID:{pid}"
                )
                matches.append(ym)
        except yara.Error as e:
            logger.debug(f"YARA memory scan error on PID {pid}: {e}")
        except Exception as e:
            logger.debug(f"Error scanning PID {pid}: {e}")

        return matches

    def scan_process_executable(self, pid: int) -> List[YaraMatch]:
        """Scan a process's executable file on disk."""
        try:
            proc = psutil.Process(pid)
            exe_path = proc.exe()
            if exe_path and os.path.isfile(exe_path):
                return self.scan_file(exe_path)
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            pass
        return []

    def scan_directory(self, dirpath: str,
                       extensions: Optional[List[str]] = None) -> Dict[str, List[YaraMatch]]:
        """Scan all files in a directory."""
        results: Dict[str, List[YaraMatch]] = {}

        if not os.path.isdir(dirpath):
            return results

        for root, dirs, files in os.walk(dirpath):
            for fname in files:
                if extensions:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in extensions:
                        continue
                fpath = os.path.join(root, fname)
                matches = self.scan_file(fpath)
                if matches:
                    results[fpath] = matches

        return results
