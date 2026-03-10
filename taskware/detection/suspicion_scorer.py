"""
Taskware Manager - Suspicion Scorer
Calculates composite suspicion scores from detection signals.
Includes ML model classification as a scoring signal.
"""

import logging
from typing import Dict, List, Tuple

from taskware.config import SCORE_WEIGHTS, SCORE_THRESHOLDS

logger = logging.getLogger("taskware.suspicion_scorer")


class SuspicionScorer:
    """
    Weighted suspicion scoring engine.
    Combines heuristic, signature, network, YARA, and ML signals
    into a single 0-100 score.
    """

    @staticmethod
    def calculate_score(signals: Dict[str, bool]) -> int:
        """
        Calculate the composite suspicion score.

        Args:
            signals: Dict of signal_name -> True/False
                     Keys should match SCORE_WEIGHTS keys:
                     - temp_execution
                     - high_entropy
                     - unusual_parent
                     - network_no_dns
                     - process_hollowing
                     - known_bad_hash
                     - yara_match
                     - rapid_file_creation
                     - ml_malware
                     - suspicious_cmdline

        Returns:
            Score from 0 to 100
        """
        total = 0
        for signal_name, is_triggered in signals.items():
            if is_triggered and signal_name in SCORE_WEIGHTS:
                total += SCORE_WEIGHTS[signal_name]

        return min(total, 100)

    @staticmethod
    def get_risk_level(score: int) -> str:
        """Map a score to a risk level label."""
        if score < SCORE_THRESHOLDS["clean"]:
            return "CLEAN"
        elif score < SCORE_THRESHOLDS["low"]:
            return "LOW"
        elif score < SCORE_THRESHOLDS["medium"]:
            return "MEDIUM"
        else:
            return "HIGH"

    @staticmethod
    def get_risk_color(score: int) -> str:
        """Map a score to a hex color for display."""
        level = SuspicionScorer.get_risk_level(score)
        colors = {
            "CLEAN":  "#00e676",   # Green
            "LOW":    "#29b6f6",   # Blue
            "MEDIUM": "#ffa726",   # Orange
            "HIGH":   "#ff1744",   # Red
        }
        return colors.get(level, "#9e9e9e")

    @staticmethod
    def get_risk_emoji(score: int) -> str:
        """Map a score to a status emoji."""
        level = SuspicionScorer.get_risk_level(score)
        emojis = {
            "CLEAN":  "✅",
            "LOW":    "🔵",
            "MEDIUM": "🟠",
            "HIGH":   "🔴",
        }
        return emojis.get(level, "❓")

    @staticmethod
    def get_score_breakdown(signals: Dict[str, bool]) -> List[Tuple[str, int]]:
        """
        Return a breakdown of which signals contributed to the score.
        Returns list of (signal_name, weight) for triggered signals.
        """
        breakdown = []
        for signal_name, is_triggered in signals.items():
            if is_triggered and signal_name in SCORE_WEIGHTS:
                weight = SCORE_WEIGHTS[signal_name]
                if weight > 0:
                    breakdown.append((signal_name, weight))
        breakdown.sort(key=lambda x: x[1], reverse=True)
        return breakdown

    @staticmethod
    def format_signal_name(signal_name: str) -> str:
        """Format a signal name for display."""
        names = {
            "temp_execution": "🗂 Execution from /tmp or suspicious path",
            "high_entropy": "🔐 High entropy (packed/encrypted)",
            "unusual_parent": "👪 Unusual parent-child relationship",
            "network_no_dns": "🌐 Network connection without DNS",
            "process_hollowing": "💉 Process hollowing detected",
            "known_bad_hash": "🗃 Known malicious hash",
            "yara_match": "🎯 YARA rule match",
            "rapid_file_creation": "📁 Rapid file creation",
            "ml_malware": "🤖 ML model classifies as malware",
            "suspicious_cmdline": "⌨️ Suspicious command line",
        }
        return names.get(signal_name, signal_name.replace("_", " ").title())
