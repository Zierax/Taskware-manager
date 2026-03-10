"""
Taskware Manager - File System Monitor
Watches configured directories for suspicious file system activity using watchdog.
Tracks rapid file creation, modification of system files, and DLL drops.
"""

import time
import logging
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Callable
from collections import defaultdict

logger = logging.getLogger("taskware.file_monitor")

try:
    from watchdog.observers import Observer
    from watchdog.events import (
        FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent,
        FileDeletedEvent, FileMovedEvent
    )
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False
    logger.warning("watchdog not installed — file monitoring disabled")


@dataclass
class FileEvent:
    """A single filesystem event."""
    timestamp: float
    event_type: str   # created, modified, deleted, moved
    path: str
    is_directory: bool = False
    dest_path: str = ""  # for move events


@dataclass
class ProcessFileActivity:
    """Aggregated file activity stats (used for scoring)."""
    pid: int = 0
    files_created: int = 0
    files_modified: int = 0
    files_deleted: int = 0
    files_moved: int = 0
    rapid_creation_detected: bool = False
    suspicious_extensions: List[str] = field(default_factory=list)


# Suspicious file extensions commonly associated with malware
SUSPICIOUS_EXTENSIONS = {
    '.exe', '.dll', '.scr', '.pif', '.bat', '.cmd', '.vbs',
    '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.psm1',
    '.msi', '.msp', '.com', '.hta', '.cpl', '.inf', '.reg',
    '.lnk', '.tmp', '.drv', '.sys',
}


class FileActivityTracker:
    """
    Tracks file creation rate per directory to detect
    rapid file creation (ransomware-like behavior).
    """

    def __init__(self, window_seconds: int = 5, threshold: int = 50):
        self._window = window_seconds
        self._threshold = threshold
        self._events: List[float] = []
        self._lock = threading.Lock()
        self.rapid_creation_alert = False

    def record_creation(self):
        now = time.time()
        with self._lock:
            self._events.append(now)
            # Prune old events outside window
            cutoff = now - self._window
            self._events = [t for t in self._events if t >= cutoff]
            self.rapid_creation_alert = len(self._events) >= self._threshold

    @property
    def creation_rate(self) -> int:
        """Files created in the current window."""
        now = time.time()
        cutoff = now - self._window
        with self._lock:
            return sum(1 for t in self._events if t >= cutoff)


if HAS_WATCHDOG:
    class _TaskwareEventHandler(FileSystemEventHandler):
        """Internal watchdog event handler that feeds events to the monitor."""

        def __init__(self, callback: Callable[[FileEvent], None],
                     tracker: FileActivityTracker):
            super().__init__()
            self._callback = callback
            self._tracker = tracker

        def on_created(self, event):
            fe = FileEvent(
                timestamp=time.time(),
                event_type="created",
                path=event.src_path,
                is_directory=event.is_directory
            )
            if not event.is_directory:
                self._tracker.record_creation()
            self._callback(fe)

        def on_modified(self, event):
            fe = FileEvent(
                timestamp=time.time(),
                event_type="modified",
                path=event.src_path,
                is_directory=event.is_directory
            )
            self._callback(fe)

        def on_deleted(self, event):
            fe = FileEvent(
                timestamp=time.time(),
                event_type="deleted",
                path=event.src_path,
                is_directory=event.is_directory
            )
            self._callback(fe)

        def on_moved(self, event):
            fe = FileEvent(
                timestamp=time.time(),
                event_type="moved",
                path=event.src_path,
                is_directory=event.is_directory,
                dest_path=event.dest_path
            )
            self._callback(fe)


class FileMonitor:
    """
    Real-time filesystem monitor using watchdog.
    Watches configured paths for creation, modification, deletion, and moves.
    """

    def __init__(self, watch_paths: Optional[List[str]] = None):
        from taskware.config import FILESYS_WATCH_PATHS
        self._watch_paths = watch_paths or FILESYS_WATCH_PATHS
        self._events: List[FileEvent] = []
        self._lock = threading.Lock()
        self._tracker = FileActivityTracker()
        self._observer: Optional[object] = None
        self._running = False
        self._max_events = 5000  # cap stored events

    @property
    def is_available(self) -> bool:
        return HAS_WATCHDOG

    @property
    def rapid_creation_alert(self) -> bool:
        return self._tracker.rapid_creation_alert

    @property
    def creation_rate(self) -> int:
        return self._tracker.creation_rate

    def start(self):
        """Start watching configured directories."""
        if not HAS_WATCHDOG:
            logger.error("Cannot start file monitor — watchdog not installed")
            return

        if self._running:
            return

        self._observer = Observer()
        handler = _TaskwareEventHandler(self._on_event, self._tracker)

        for path in self._watch_paths:
            if path and __import__('os').path.isdir(path):
                try:
                    self._observer.schedule(handler, path, recursive=True)
                    logger.info(f"Watching directory: {path}")
                except Exception as e:
                    logger.warning(f"Cannot watch {path}: {e}")

        self._observer.start()
        self._running = True
        logger.info("File monitor started")

    def stop(self):
        """Stop watching directories."""
        if self._observer and self._running:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._running = False
            logger.info("File monitor stopped")

    def _on_event(self, event: FileEvent):
        """Handle incoming filesystem events."""
        with self._lock:
            self._events.append(event)
            # Trim if over cap
            if len(self._events) > self._max_events:
                self._events = self._events[-self._max_events:]

    def get_recent_events(self, count: int = 100) -> List[FileEvent]:
        """Get the most recent filesystem events."""
        with self._lock:
            return list(self._events[-count:])

    def get_suspicious_events(self) -> List[FileEvent]:
        """Get events involving suspicious file extensions."""
        with self._lock:
            suspicious = []
            for ev in self._events:
                ext = __import__('os').path.splitext(ev.path)[1].lower()
                if ext in SUSPICIOUS_EXTENSIONS:
                    suspicious.append(ev)
            return suspicious

    def clear_events(self):
        """Clear all stored events."""
        with self._lock:
            self._events.clear()
