"""
cve_matcher.py
===============
CVE Database Matcher Module.
Loads a local CVE JSON snapshot and matches detected service versions
against known vulnerabilities using semantic version comparison.

The CVE snapshot is a curated subset of real CVEs for common services.
"""

import json
import logging
from typing import Optional
from packaging import version as pkg_version

logger = logging.getLogger(__name__)


class CVEMatcher:
    """
    Matches detected service versions against a local CVE database
    to identify known vulnerabilities.
    """

    def __init__(self, cve_db_path: str):
        """
        Initialize the CVE matcher and load the database.

        Args:
            cve_db_path: Path to the CVE JSON snapshot file.
        """
        self.cve_db_path = cve_db_path
        self.cve_entries = []
        self.results = []
        self._load_database()

    def _load_database(self):
        """Load the CVE JSON snapshot from disk."""
        try:
            with open(self.cve_db_path, "r", encoding="utf-8") as f:
                self.cve_entries = json.load(f)
            logger.info(
                f"CVE database loaded: {len(self.cve_entries)} entries "
                f"from {self.cve_db_path}"
            )
        except FileNotFoundError:
            logger.error(f"CVE database not found: {self.cve_db_path}")
            self.cve_entries = []
        except json.JSONDecodeError as e:
            logger.error(f"Invalid CVE database JSON: {e}")
            self.cve_entries = []

    def _parse_version(self, version_str: str) -> Optional[pkg_version.Version]:
        """
        Parse a version string into a comparable Version object.
        Handles common version format variations.

        Args:
            version_str: Version string like "2.4.51" or "9.1p1".

        Returns:
            Version object or None if unparseable.
        """
        if not version_str or version_str == "Unknown":
            return None

        # Clean up version string — remove non-version suffixes
        # e.g., "9.1p1" -> "9.1", "2.4.51-ubuntu" -> "2.4.51"
        cleaned = version_str.split("p")[0]  # Handle OpenSSH "pN" suffix
        cleaned = cleaned.split("-")[0]      # Remove distro suffixes
        cleaned = cleaned.split("_")[0]      # Remove underscore suffixes
        cleaned = cleaned.split("+")[0]      # Remove build metadata

        try:
            return pkg_version.Version(cleaned)
        except pkg_version.InvalidVersion:
            logger.debug(f"Could not parse version: '{version_str}'")
            return None

    def _is_version_affected(
        self, detected_version: str, affected_range: dict
    ) -> bool:
        """
        Check if a detected version falls within the affected version range.

        Args:
            detected_version: The version string detected on the target.
            affected_range: Dict with 'min' and 'max' version strings.

        Returns:
            True if the detected version is within the affected range.
        """
        detected = self._parse_version(detected_version)
        min_ver = self._parse_version(affected_range.get("min", "0"))
        max_ver = self._parse_version(affected_range.get("max", "999999"))

        if detected is None or min_ver is None or max_ver is None:
            return False

        return min_ver <= detected <= max_ver

    def match_service(self, service: str, version: str) -> list[dict]:
        """
        Find all CVE entries matching a given service and version.

        Args:
            service: Service name (e.g., "OpenSSH", "Apache HTTP Server").
            version: Detected version string.

        Returns:
            List of matching CVE entry dictionaries.
        """
        matches = []

        for cve in self.cve_entries:
            cve_service = cve.get("service", "")
            affected = cve.get("affected_versions", {})

            # Case-insensitive service name comparison
            if cve_service.lower() != service.lower():
                continue

            # Check if the detected version falls in the affected range
            if self._is_version_affected(version, affected):
                matches.append(cve)
                logger.debug(
                    f"CVE match: {cve['cve_id']} for {service} v{version}"
                )

        return matches

    def match_all(self, services: list[dict]) -> list[dict]:
        """
        Match all detected services against the CVE database.

        Args:
            services: List of dicts with 'service', 'version', 'ip', 'port'.

        Returns:
            List of CVE match finding dictionaries.
        """
        self.results = []

        if not self.cve_entries:
            logger.warning("CVE database is empty. Skipping CVE matching.")
            return self.results

        logger.info(
            f"Matching {len(services)} detected service(s) against "
            f"{len(self.cve_entries)} CVE entries..."
        )

        for svc in services:
            service_name = svc.get("service", "")
            service_version = svc.get("version", "")
            ip = svc.get("ip", "")
            port = svc.get("port", 0)

            if not service_name or not service_version:
                continue

            matches = self.match_service(service_name, service_version)

            for cve in matches:
                finding = {
                    "type": "CVE Vulnerability",
                    "cve_id": cve["cve_id"],
                    "severity": cve.get("severity", "Medium"),
                    "cvss_score": cve.get("cvss_score", 0.0),
                    "target": f"{ip}:{port}",
                    "service": service_name,
                    "version": service_version,
                    "affected_range": (
                        f"{cve['affected_versions']['min']} - "
                        f"{cve['affected_versions']['max']}"
                    ),
                    "description": cve.get("description", ""),
                    "remediation": cve.get("remediation", ""),
                    "evidence": (
                        f"Detected {service_name} v{service_version} at "
                        f"{ip}:{port} — matches {cve['cve_id']} "
                        f"(affects v{cve['affected_versions']['min']} to "
                        f"v{cve['affected_versions']['max']})"
                    ),
                }
                self.results.append(finding)
                logger.warning(
                    f"  [!] {cve['cve_id']} ({cve['severity']}): "
                    f"{service_name} v{service_version} at {ip}:{port}"
                )

        logger.info(
            f"CVE matching complete. {len(self.results)} known "
            f"vulnerability(ies) found."
        )
        return self.results

    def get_summary(self) -> dict:
        """
        Generate a summary of CVE matching results.

        Returns:
            Dictionary with counts by severity and unique CVE IDs.
        """
        summary = {
            "total": len(self.results),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "unique_cves": set(),
        }

        for finding in self.results:
            severity = finding.get("severity", "Info").lower()
            if severity == "critical":
                summary["critical"] += 1
            elif severity == "high":
                summary["high"] += 1
            elif severity == "medium":
                summary["medium"] += 1
            elif severity == "low":
                summary["low"] += 1
            else:
                summary["info"] += 1

            cve_id = finding.get("cve_id", "")
            if cve_id:
                summary["unique_cves"].add(cve_id)

        summary["unique_cves"] = list(summary["unique_cves"])
        return summary
