"""
Taskware Manager - Rule Engine (Linux Only)
Orchestrates all detection modules and generates enriched process data
with suspicion scores.

Integrates:
- Process telemetry (psutil)
- Heuristic analysis (entropy, hollowing, parent-child, cmdline)
- YARA scanning
- Hash database lookup
- ML model classification
- Hybrid Analysis API (optional)
"""

import logging
from typing import Dict, Optional

from taskware.core.process_monitor import ProcessMonitor, ProcessInfo
from taskware.core.network_monitor import NetworkMonitor
from taskware.core.yara_scanner import YaraScanner
from taskware.core.ml_engine import MLEngine
from taskware.core.hybrid_analysis import HybridAnalysisClient
from taskware.database.hash_db import HashDatabase
from taskware.detection.heuristics import (
    check_file_entropy,
    detect_process_hollowing,
    check_parent_child_anomaly,
    check_suspicious_cmdline,
)
from taskware.detection.suspicion_scorer import SuspicionScorer
from taskware.config import AppSettings

logger = logging.getLogger("taskware.rule_engine")


class RuleEngine:
    """
    Coordinates all detection modules and produces scored results
    for each process.
    """

    def __init__(
        self,
        proc_monitor: ProcessMonitor,
        net_monitor: NetworkMonitor,
        yara_scanner: YaraScanner,
        hash_db: HashDatabase,
        settings: Optional[AppSettings] = None,
    ):
        self._proc_mon = proc_monitor
        self._net_mon = net_monitor
        self._yara = yara_scanner
        self._hash_db = hash_db
        self._settings = settings or AppSettings()
        self._ml_engine = MLEngine(self._settings)
        self._ha_client = HybridAnalysisClient(self._settings)

    @property
    def ml_engine(self) -> MLEngine:
        return self._ml_engine

    @property
    def ha_client(self) -> HybridAnalysisClient:
        return self._ha_client

    def analyze_process(self, proc: ProcessInfo) -> ProcessInfo:
        """
        Run all detection modules on a single process
        and calculate its suspicion score.
        """
        signals = {}
        flags = []

        # ── 1. Suspicious Path ────────────────────────────────────────
        if proc.is_from_temp:
            signals["temp_execution"] = True
            flags.append(
                f"🗂 Running from suspicious path: {proc.exe_path}"
            )

        # ── 2. File Entropy ───────────────────────────────────────────
        # Optimize: Calculating entropy is slow, only do it for temporary/suspicious paths
        if proc.exe_path and proc.is_from_temp:
            is_high_entropy, entropy_val = check_file_entropy(proc.exe_path)
            if is_high_entropy:
                signals["high_entropy"] = True
                flags.append(
                    f"🔐 High entropy: {entropy_val:.2f} (packed/encrypted?)"
                )

        # ── 3. Parent-Child Anomaly ───────────────────────────────────
        if proc.parent_name:
            is_anomaly, anomaly_desc = check_parent_child_anomaly(
                proc.name, proc.parent_name, proc.parent_pid or 0
            )
            if is_anomaly:
                signals["unusual_parent"] = True
                flags.append(f"👪 {anomaly_desc}")

        # ── 4. Process Hollowing ──────────────────────────────────────
        is_hollow, hollow_indicators = detect_process_hollowing(
            proc.pid, proc.exe_path, proc.memory_rss, proc.num_threads
        )
        if is_hollow:
            signals["process_hollowing"] = True
            for indicator in hollow_indicators:
                flags.append(f"💉 {indicator}")

        # ── 5. Suspicious Command Line ─────────────────────────────────
        if proc.cmdline:
            is_sus_cmd, cmd_flags = check_suspicious_cmdline(proc.cmdline)
            if is_sus_cmd:
                signals["suspicious_cmdline"] = True
                for cf in cmd_flags:
                    flags.append(f"⌨️ {cf}")

        # ── 6. Network: raw IP connections ─────────────────────────────
        # Optimize: Avoid per-process psutil.net_connections. Retrieve from global cache.
        conns = [c for c in self._net_mon._last_connections if c.pid == proc.pid]
        proc.num_connections = len(conns)
        
        if proc.num_connections > 0:
            has_raw_ip = any((not c.has_dns and c.remote_addr) for c in conns)
            if has_raw_ip:
                signals["network_no_dns"] = True
                flags.append("🌐 Connection to raw IP without DNS")

        # ── 7. Hash Database Lookup ────────────────────────────────────
        if proc.sha256:
            is_known_bad = self._hash_db.is_known_malicious(proc.sha256)
            if is_known_bad:
                signals["known_bad_hash"] = True
                flags.append(
                    f"🗃 SHA256 found in local threat database: "
                    f"{proc.sha256[:16]}..."
                )

        # ── 8. ML Model Classification ─────────────────────────────────
        if self._settings.ml_enabled and self._ml_engine.is_available:
            try:
                # Try to get syscall data for this process
                # Optimize: Tracing syscalls takes seconds. Only trace processes 
                # that are already highly suspicious based on heuristics!
                is_suspicious_so_far = bool(signals) or proc.is_from_temp
                if proc.pid > 100 and proc.username != "root" and is_suspicious_so_far:
                    prediction = self._ml_engine.predict_from_pid_strace(
                        proc.pid, duration=1
                    )
                    if prediction and not prediction.get('error'):
                        proc.ml_prediction = prediction.get(
                            'predicted_type', '')
                        proc.ml_confidence = prediction.get(
                            'confidence', 0.0)

                        if self._ml_engine.is_malicious_prediction(prediction):
                            signals["ml_malware"] = True
                            flags.append(
                                f"🤖 ML model: {proc.ml_prediction} "
                                f"(confidence: {proc.ml_confidence:.1%})"
                            )
                        if prediction.get('warning'):
                            flags.append(
                                f"⚠️ ML: {prediction['warning']}"
                            )
            except Exception as e:
                logger.debug(f"ML analysis skipped for PID {proc.pid}: {e}")

        # ── Calculate final score ──────────────────────────────────────
        proc.suspicion_score = SuspicionScorer.calculate_score(signals)
        proc.flags = flags

        return proc

    def analyze_all_processes(self) -> Dict[int, ProcessInfo]:
        """
        Collect all processes and run detection on each.
        Returns a dict of pid -> enriched ProcessInfo.
        """
        # Optimize: Pre-fetch global state to avoid doing this O(N) times
        self._net_mon.get_all_connections()
        
        raw_processes = self._proc_mon.get_all_processes()
        analyzed = {}

        for pid, proc in raw_processes.items():
            try:
                analyzed[pid] = self.analyze_process(proc)
            except Exception as e:
                logger.debug(f"Analysis failed for PID {pid}: {e}")
                analyzed[pid] = proc

        return analyzed
