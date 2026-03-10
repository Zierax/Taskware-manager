"""
Taskware Manager - ML Model Integration
Bridges the syscall-based malware classification model
into the Taskware process monitoring pipeline.

Uses the trained model from model/artifacts/model.joblib
to predict malware type from syscall sequences.
"""

import os
import sys
import logging
from typing import Dict, Optional, List, Tuple
from pathlib import Path

from taskware.config import MODEL_DIR, AppSettings

logger = logging.getLogger("taskware.ml_engine")

# Track whether ML is available
_ML_AVAILABLE = False
_run_prediction = None


def _init_ml():
    """Lazily initialize the ML prediction module."""
    global _ML_AVAILABLE, _run_prediction

    if _run_prediction is not None:
        return _ML_AVAILABLE

    try:
        # Add model directory to sys.path for imports
        if MODEL_DIR not in sys.path:
            sys.path.insert(0, MODEL_DIR)
        if os.path.dirname(MODEL_DIR) not in sys.path:
            sys.path.insert(0, os.path.dirname(MODEL_DIR))

        from model.predict import run_prediction
        _run_prediction = run_prediction
        _ML_AVAILABLE = True
        logger.info("ML model loaded successfully")
    except ImportError as e:
        logger.warning(f"ML model not available: {e}")
        _ML_AVAILABLE = False
    except Exception as e:
        logger.error(f"ML model initialization failed: {e}")
        _ML_AVAILABLE = False

    return _ML_AVAILABLE


class MLEngine:
    """
    Machine Learning engine for malware classification.
    Takes syscall sequences and predicts malware type with confidence.
    """

    def __init__(self, settings: Optional[AppSettings] = None):
        self._settings = settings
        self._available = _init_ml()
        self._prediction_cache: Dict[str, Dict] = {}
        # Max syscall sequence length
        self._max_syscalls = 4000
        self._low_threshold = 600

        if self._settings:
            self._max_syscalls = self._settings.get(
                "ml_model", "max_syscalls", 4000)
            self._low_threshold = self._settings.get(
                "ml_model", "low_syscall_warning_threshold", 600)

    @property
    def is_available(self) -> bool:
        return self._available

    def predict_syscalls(self, syscall_text: str) -> Dict:
        """
        Predict malware type from a syscall sequence string.

        Args:
            syscall_text: Space-separated syscall names
                          (e.g. "execve brk mmap openat fstat")

        Returns:
            Dict with keys:
                - predicted_type: str (e.g. "Trojan", "Worm", "Benign")
                - confidence: float (0.0-1.0)
                - top_predictions: str (formatted top N predictions)
                - syscalls_analyzed: int
                - warning: Optional[str]
                - error: Optional[str]
        """
        if not self._available or _run_prediction is None:
            return {'error': 'ML model not available',
                    'predicted_type': 'Unknown', 'confidence': 0.0}

        if not syscall_text or not syscall_text.strip():
            return {'error': 'Empty syscall sequence',
                    'predicted_type': 'Unknown', 'confidence': 0.0}

        # Cache key: first 200 chars of sequence
        cache_key = syscall_text[:200]
        if cache_key in self._prediction_cache:
            return self._prediction_cache[cache_key]

        try:
            # Truncate if too long
            tokens = syscall_text.split()
            syscall_count = len(tokens)

            if syscall_count > self._max_syscalls:
                syscall_text = " ".join(tokens[:self._max_syscalls])

            results = _run_prediction(
                text=syscall_text,
                proba=True,
                limit=1,
                top_n=3
            )

            if not results:
                return {'error': 'No prediction results',
                        'predicted_type': 'Unknown', 'confidence': 0.0}

            result = results[0]
            prediction = {
                'predicted_type': result.get('Predicted_Malware_Type', 'Unknown'),
                'confidence': result.get('Probability', 0.0),
                'top_predictions': result.get('Top_Predictions', 'N/A'),
                'syscalls_analyzed': syscall_count,
                'warning': None,
                'error': None,
            }

            if syscall_count < self._low_threshold:
                prediction['warning'] = (
                    f"Low confidence: only {syscall_count} syscalls "
                    f"(need {self._low_threshold}+ for reliable results)"
                )

            # Cache
            self._prediction_cache[cache_key] = prediction
            return prediction

        except Exception as e:
            logger.error(f"ML prediction failed: {e}")
            return {'error': str(e),
                    'predicted_type': 'Unknown', 'confidence': 0.0}

    def predict_from_pid_strace(self, pid: int,
                                 duration: int = 5) -> Dict:
        """
        Trace a running process's syscalls and predict malware type.

        Args:
            pid: Process ID to trace
            duration: How long to trace (seconds)

        Returns:
            Prediction dict (same format as predict_syscalls)
        """
        from taskware.core.process_monitor import ProcessMonitor

        try:
            # Get syscalls from the live process
            syscalls = ProcessMonitor.trace_syscalls(pid, duration)
            if not syscalls:
                return {
                    'error': 'No syscalls captured (need root or strace missing)',
                    'predicted_type': 'Unknown', 'confidence': 0.0
                }

            syscall_text = " ".join(syscalls)
            return self.predict_syscalls(syscall_text)

        except Exception as e:
            return {'error': str(e),
                    'predicted_type': 'Unknown', 'confidence': 0.0}

    def predict_from_binary(self, binary_path: str,
                             timeout: int = 60) -> Dict:
        """
        Run a binary, capture its syscalls, and predict malware type.
        WARNING: This actually executes the binary!

        Args:
            binary_path: Path to binary/script to analyze
            timeout: Max execution time in seconds

        Returns:
            Prediction dict
        """
        from taskware.core.process_monitor import ProcessMonitor

        try:
            syscall_text = ProcessMonitor.get_process_syscall_sequence(
                binary_path, timeout=timeout
            )
            if not syscall_text:
                return {
                    'error': 'No syscalls captured from binary',
                    'predicted_type': 'Unknown', 'confidence': 0.0
                }
            return self.predict_syscalls(syscall_text)

        except Exception as e:
            return {'error': str(e),
                    'predicted_type': 'Unknown', 'confidence': 0.0}

    def is_malicious_prediction(self, prediction: Dict) -> bool:
        """
        Determine if a prediction indicates malware.
        Returns True if predicted type is NOT 'Benign' and confidence > 0.5
        """
        pred_type = prediction.get('predicted_type', '').lower()
        confidence = prediction.get('confidence', 0.0)

        benign_labels = {'benign', 'clean', 'normal', 'goodware', 'unknown'}
        return pred_type not in benign_labels and confidence > 0.5

    def clear_cache(self):
        """Clear the prediction cache."""
        self._prediction_cache.clear()
