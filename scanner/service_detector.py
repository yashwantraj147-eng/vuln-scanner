"""
scanner/service_detector.py
============================
Service Version Detection Module.
Analyzes banners captured during port scanning to identify specific
service names and version numbers using regex signature matching.

The detected versions are later matched against the CVE database.
"""

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ServiceDetector:
    """
    Detects service names and versions from captured banners
    by matching against configurable regex signature patterns.
    """

    def __init__(self, config: dict):
        """
        Initialize the service detector.

        Args:
            config: Service detector configuration from config.yaml
                    containing signature patterns.
        """
        self.signatures = config.get("signatures", [])
        self.results = []

        # Compile regex patterns for efficiency
        self._compiled_signatures = []
        for sig in self.signatures:
            try:
                compiled = re.compile(sig["pattern"], re.IGNORECASE)
                self._compiled_signatures.append(
                    {
                        "regex": compiled,
                        "service": sig["service"],
                        "version_group": sig.get("version_group", 1),
                    }
                )
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{sig['pattern']}': {e}")

        logger.info(
            f"Service detector initialized with {len(self._compiled_signatures)} signatures."
        )

    def detect_service(self, banner: str) -> Optional[dict]:
        """
        Attempt to identify the service and version from a banner string.

        Args:
            banner: Raw banner string captured from the target port.

        Returns:
            Dictionary with 'service' and 'version' keys, or None.
        """
        if not banner:
            return None

        for sig in self._compiled_signatures:
            match = sig["regex"].search(banner)
            if match:
                version = ""
                try:
                    version_group = sig["version_group"]
                    if version_group > 0 and version_group <= len(match.groups()):
                        version = match.group(version_group)
                    elif version_group == 0:
                        version = "Unknown"
                except (IndexError, AttributeError):
                    version = "Unknown"

                result = {
                    "service": sig["service"],
                    "version": version,
                    "matched_banner": banner[:200],  # Truncate for readability
                }
                logger.debug(
                    f"Detected: {result['service']} v{result['version']}"
                )
                return result

        # If no signature matched, attempt generic detection from banner
        return self._generic_detect(banner)

    def _generic_detect(self, banner: str) -> Optional[dict]:
        """
        Fallback generic detection when no signature matches.
        Extracts common patterns like 'Server: X/Y' or 'service vX.Y.Z'.

        Args:
            banner: Raw banner string.

        Returns:
            Dictionary with detected service info, or None.
        """
        # Try to match generic "Server: name/version" pattern (HTTP)
        server_match = re.search(r"Server:\s*([^\s/]+)/?(\S*)", banner, re.IGNORECASE)
        if server_match:
            return {
                "service": server_match.group(1),
                "version": server_match.group(2) or "Unknown",
                "matched_banner": banner[:200],
            }

        # Try to match generic version patterns like "ServiceName X.Y.Z"
        version_match = re.search(
            r"(\w[\w\s-]{2,20}?)\s+v?(\d+\.\d+(?:\.\d+)?)", banner, re.IGNORECASE
        )
        if version_match:
            return {
                "service": version_match.group(1).strip(),
                "version": version_match.group(2),
                "matched_banner": banner[:200],
            }

        return None

    def analyze_ports(self, port_results: list[dict]) -> list[dict]:
        """
        Analyze all port scan results to detect services and versions.

        Args:
            port_results: List of open port dictionaries from PortScanner.

        Returns:
            List of enriched dictionaries with service detection info.
        """
        self.results = []

        logger.info(f"Analyzing {len(port_results)} open port(s) for service detection...")

        for port_info in port_results:
            banner = port_info.get("banner", "")
            ip = port_info.get("ip", "")
            port = port_info.get("port", 0)
            guessed_service = port_info.get("service", "Unknown")

            # Attempt banner-based detection
            detection = self.detect_service(banner)

            if detection:
                enriched = {
                    "ip": ip,
                    "port": port,
                    "service": detection["service"],
                    "version": detection["version"],
                    "banner": banner[:300],
                    "detection_method": "banner_signature",
                    "confidence": "high",
                }
            else:
                # Use the port-based guess as fallback
                enriched = {
                    "ip": ip,
                    "port": port,
                    "service": guessed_service,
                    "version": "Unknown",
                    "banner": banner[:300] if banner else "",
                    "detection_method": "port_guess",
                    "confidence": "low",
                }

            self.results.append(enriched)
            logger.info(
                f"  {ip}:{port} -> {enriched['service']} "
                f"v{enriched['version']} [{enriched['confidence']}]"
            )

        logger.info(
            f"Service detection complete. {len(self.results)} service(s) identified."
        )
        return self.results


    def get_services_for_cve_matching(self) -> list[dict]:
        """
        Return a simplified list of detected services suitable for CVE matching.
        Only includes services with a known version.

        Returns:
            List of dicts with 'service', 'version', 'ip', 'port' keys.
        """
        matchable = []
        for svc in self.results:
            if svc["version"] and svc["version"] != "Unknown":
                matchable.append(
                    {
                        "service": svc["service"],
                        "version": svc["version"],
                        "ip": svc["ip"],
                        "port": svc["port"],
                    }
                )
        return matchable
