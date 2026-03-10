"""
Taskware Manager - Hybrid Analysis API Integration
Provides hash lookup and file submission capabilities
via the Hybrid Analysis REST API (v2).

Settings (API key, base URL) are persisted in
~/.config/taskware/config.json via the Settings panel.
"""

import os
import json
import logging
from typing import Dict, Optional, List

from taskware.config import AppSettings

logger = logging.getLogger("taskware.hybrid_analysis")


class HybridAnalysisClient:
    """
    Client for the Hybrid Analysis public API v2.
    Docs: https://www.hybrid-analysis.com/docs/api/v2
    """

    def __init__(self, settings: AppSettings):
        self._settings = settings

    @property
    def enabled(self) -> bool:
        return self._settings.hybrid_analysis_enabled

    @property
    def api_key(self) -> str:
        return self._settings.hybrid_analysis_api_key

    @property
    def base_url(self) -> str:
        return self._settings.hybrid_analysis_base_url.rstrip('/')

    def _headers(self) -> Dict[str, str]:
        return {
            "api-key": self.api_key,
            "User-Agent": "Taskware Manager (Falcon Sandbox)",
            "Accept": "application/json",
        }

    def _get(self, path: str, params: dict = None) -> Optional[Dict]:
        if not self.enabled or not self.api_key:
            return None
        try:
            import requests
            verify_ssl = self._settings.get(
                "hybrid_analysis", "verify_ssl", True)
            resp = requests.get(
                f"{self.base_url}{path}",
                headers=self._headers(),
                params=params,
                timeout=15,
                verify=verify_ssl,
            )
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.warning(
                    f"Hybrid Analysis API error {resp.status_code}: "
                    f"{resp.text[:200]}"
                )
                return {"error": True, "status": resp.status_code,
                        "detail": resp.text[:512]}
        except ImportError:
            logger.error("requests library not installed")
            return {"error": True, "detail": "requests library not installed"}
        except Exception as e:
            logger.error(f"Hybrid Analysis request failed: {e}")
            return {"error": True, "detail": str(e)}

    def _post(self, path: str, data: dict = None,
              files: dict = None) -> Optional[Dict]:
        if not self.enabled or not self.api_key:
            return None
        try:
            import requests
            verify_ssl = self._settings.get(
                "hybrid_analysis", "verify_ssl", True)
            resp = requests.post(
                f"{self.base_url}{path}",
                headers=self._headers(),
                data=data,
                files=files,
                timeout=30,
                verify=verify_ssl,
            )
            if resp.status_code in (200, 201):
                return resp.json()
            else:
                logger.warning(
                    f"Hybrid Analysis API error {resp.status_code}: "
                    f"{resp.text[:200]}"
                )
                return {"error": True, "status": resp.status_code,
                        "detail": resp.text[:512]}
        except ImportError:
            return {"error": True, "detail": "requests library not installed"}
        except Exception as e:
            logger.error(f"Hybrid Analysis POST failed: {e}")
            return {"error": True, "detail": str(e)}

    # ─── Public API Methods ───────────────────────────────────────────────

    def search_hash(self, sha256: str) -> Optional[Dict]:
        """
        Search for a file hash in Hybrid Analysis.
        Returns analysis results if found.
        """
        return self._post("/search/hash", data={"hash": sha256})

    def get_report(self, report_id: str) -> Optional[Dict]:
        """Get a specific analysis report by ID."""
        return self._get(f"/report/{report_id}/summary")

    def search_terms(self, query: str) -> Optional[Dict]:
        """Search Hybrid Analysis database by terms."""
        return self._post("/search/terms", data={"query": query})

    def quick_scan_file(self, file_path: str) -> Optional[Dict]:
        """
        Submit a file for quick-scan analysis.
        Returns submission result with job_id.
        """
        if not os.path.isfile(file_path):
            return {"error": True, "detail": "File not found"}

        try:
            with open(file_path, 'rb') as f:
                return self._post(
                    "/quick-scan/file",
                    data={"scan_type": "all"},
                    files={"file": (os.path.basename(file_path), f)}
                )
        except Exception as e:
            return {"error": True, "detail": str(e)}

    def get_overview(self, sha256: str) -> Optional[Dict]:
        """Get overview report for a hash."""
        return self._get(f"/overview/{sha256}")

    def test_connection(self) -> Dict:
        """
        Test if the API key is valid and the service is reachable.
        Returns a dict with 'success' bool and 'detail' string.
        """
        if not self.api_key:
            return {"success": False, "detail": "No API key configured"}

        try:
            import requests
            verify_ssl = self._settings.get(
                "hybrid_analysis", "verify_ssl", True)
            resp = requests.get(
                f"{self.base_url}/system/version",
                headers=self._headers(),
                timeout=10,
                verify=verify_ssl,
            )
            if resp.status_code == 200:
                return {"success": True, "detail": "Connected successfully"}
            elif resp.status_code == 401:
                return {"success": False,
                        "detail": "Invalid API key (401 Unauthorized)"}
            elif resp.status_code == 403:
                return {"success": False,
                        "detail": "Access forbidden (403)"}
            else:
                return {"success": False,
                        "detail": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except ImportError:
            return {"success": False,
                    "detail": "requests library not installed — pip install requests"}
        except Exception as e:
            return {"success": False, "detail": str(e)}

    def lookup_and_summarize(self, sha256: str) -> Dict:
        """
        Look up a hash and return a human-readable summary.
        Used by the dashboard to enrich process data.
        """
        result = self.search_hash(sha256)
        if result is None:
            return {"available": False, "reason": "API disabled or no key"}

        if isinstance(result, dict) and result.get("error"):
            return {"available": False,
                    "reason": result.get("detail", "Unknown error")}

        summary = {
            "available": True,
            "verdict": "Unknown",
            "threat_score": 0,
            "threat_level": "N/A",
            "malware_family": "N/A",
            "tags": [],
            "submissions_count": 0,
        }

        try:
            # Hybrid Analysis returns a list of reports
            reports = result if isinstance(result, list) else [result]
            if reports:
                top = reports[0]
                summary["verdict"] = top.get("verdict") or "Unknown"
                summary["threat_score"] = top.get("threat_score") or 0
                summary["threat_level"] = str(
                    top.get("threat_level") or "N/A")
                summary["malware_family"] = (
                    top.get("vx_family") or "N/A")
                summary["tags"] = top.get("tags") or []
                summary["submissions_count"] = top.get(
                    "submissions_count", 0)
                summary["environment"] = top.get(
                    "environment_description", "N/A")
        except Exception as e:
            summary["error"] = str(e)

        return summary
