"""
Taskware Manager - Local Hash Database
SQLite-based local database of known malicious file hashes.
No external API calls — 100% offline.
"""

import os
import sqlite3
import logging
from typing import Optional, List, Tuple

from taskware.config import DATABASE_DIR

logger = logging.getLogger("taskware.hash_db")

DB_PATH = os.path.join(DATABASE_DIR, "known_hashes.db")


class HashDatabase:
    """
    Local SQLite database for storing known malicious file hashes.
    Supports SHA256, MD5, and SHA1 hashes with metadata.
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path or DB_PATH
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self):
        """Initialize the database and create tables if needed."""
        try:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            cursor = self._conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS malicious_hashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sha256 TEXT UNIQUE NOT NULL,
                    md5 TEXT DEFAULT '',
                    sha1 TEXT DEFAULT '',
                    malware_name TEXT DEFAULT 'Unknown',
                    malware_family TEXT DEFAULT '',
                    severity TEXT DEFAULT 'medium',
                    description TEXT DEFAULT '',
                    source TEXT DEFAULT 'manual',
                    added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_sha256
                ON malicious_hashes(sha256)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_md5
                ON malicious_hashes(md5)
            """)

            # Insert some well-known test hashes (EICAR test file)
            cursor.execute("""
                INSERT OR IGNORE INTO malicious_hashes
                (sha256, md5, malware_name, malware_family, severity, description, source)
                VALUES
                (?, ?, ?, ?, ?, ?, ?)
            """, (
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "44d88612fea8a8f36de82e1278abb02f",
                "EICAR-Test-File",
                "Test",
                "info",
                "EICAR Anti-Malware Test File — not a real threat",
                "builtin"
            ))

            self._conn.commit()
            logger.info(f"Hash database initialized: {self._db_path}")

        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {e}")

    def is_known_malicious(self, sha256: str) -> bool:
        """Check if a SHA256 hash is in the malicious hash database."""
        if not self._conn or not sha256:
            return False
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                "SELECT 1 FROM malicious_hashes WHERE sha256 = ?",
                (sha256.lower(),)
            )
            return cursor.fetchone() is not None
        except sqlite3.Error:
            return False

    def get_hash_info(self, sha256: str) -> Optional[dict]:
        """Get full info for a known malicious hash."""
        if not self._conn or not sha256:
            return None
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                "SELECT * FROM malicious_hashes WHERE sha256 = ?",
                (sha256.lower(),)
            )
            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0],
                    'sha256': row[1],
                    'md5': row[2],
                    'sha1': row[3],
                    'malware_name': row[4],
                    'malware_family': row[5],
                    'severity': row[6],
                    'description': row[7],
                    'source': row[8],
                    'added_date': row[9],
                }
        except sqlite3.Error:
            pass
        return None

    def add_hash(self, sha256: str, malware_name: str = "Unknown",
                 md5: str = "", sha1: str = "",
                 malware_family: str = "", severity: str = "medium",
                 description: str = "", source: str = "manual") -> bool:
        """Add a hash to the malicious database."""
        if not self._conn:
            return False
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO malicious_hashes
                (sha256, md5, sha1, malware_name, malware_family,
                 severity, description, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (sha256.lower(), md5.lower(), sha1.lower(),
                  malware_name, malware_family, severity, description, source))
            self._conn.commit()
            logger.info(f"Added hash to DB: {sha256[:16]}... ({malware_name})")
            return True
        except sqlite3.Error as e:
            logger.error(f"Failed to add hash: {e}")
            return False

    def remove_hash(self, sha256: str) -> bool:
        """Remove a hash from the database."""
        if not self._conn:
            return False
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                "DELETE FROM malicious_hashes WHERE sha256 = ?",
                (sha256.lower(),)
            )
            self._conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error:
            return False

    def import_hashes_from_file(self, filepath: str) -> int:
        """
        Import hashes from a text file (one SHA256 per line).
        Lines starting with # are comments.
        Format: sha256,malware_name (comma-separated, name optional)
        Returns count of imported hashes.
        """
        count = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(',', 1)
                    sha256 = parts[0].strip()
                    name = parts[1].strip() if len(parts) > 1 else "Imported"
                    if len(sha256) == 64:  # valid SHA256 length
                        if self.add_hash(sha256, malware_name=name,
                                         source="file_import"):
                            count += 1
            logger.info(f"Imported {count} hashes from {filepath}")
        except Exception as e:
            logger.error(f"Hash import failed: {e}")
        return count

    def get_total_count(self) -> int:
        """Get total number of hashes in database."""
        if not self._conn:
            return 0
        try:
            cursor = self._conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM malicious_hashes")
            return cursor.fetchone()[0]
        except sqlite3.Error:
            return 0

    def search(self, query: str) -> List[dict]:
        """Search hashes by name or family."""
        results = []
        if not self._conn:
            return results
        try:
            cursor = self._conn.cursor()
            cursor.execute("""
                SELECT * FROM malicious_hashes
                WHERE malware_name LIKE ? OR malware_family LIKE ?
                OR sha256 LIKE ?
                LIMIT 100
            """, (f"%{query}%", f"%{query}%", f"%{query}%"))
            for row in cursor.fetchall():
                results.append({
                    'id': row[0], 'sha256': row[1], 'md5': row[2],
                    'sha1': row[3], 'malware_name': row[4],
                    'malware_family': row[5], 'severity': row[6],
                    'description': row[7], 'source': row[8],
                    'added_date': row[9],
                })
        except sqlite3.Error:
            pass
        return results

    def close(self):
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
