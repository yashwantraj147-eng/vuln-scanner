"""
report_generator.py
====================
Report Generator Module.
Generates HTML and JSON reports from scan findings using Jinja2
templates with embedded Chart.js visualizations.
"""

import json
import os
import logging
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates HTML reports (with charts) and JSON exports
    from vulnerability scan findings.
    """

    def __init__(self, config: dict, output_dir: str = "./output"):
        """
        Initialize the report generator.

        Args:
            config: Report configuration dictionary.
            output_dir: Directory to write report files.
        """
        self.config = config
        self.output_dir = output_dir
        self.company_name = config.get("company_name", "Security Audit Report")
        self.author = config.get("author", "VulnScanner Automated Tool")
        self.template_path = config.get("template_path", "./templates/report.html")

        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

    def _calculate_risk_score(self, findings: list[dict]) -> dict:
        """
        Calculate an overall risk score from all findings.

        Args:
            findings: List of all finding dictionaries.

        Returns:
            Dictionary with risk metrics and overall score.
        """
        severity_weights = {
            "critical": 40,
            "high": 25,
            "medium": 10,
            "low": 3,
            "info": 0,
        }

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "Info").lower()
            counts[severity] = counts.get(severity, 0) + 1

        # Weighted score (capped at 100)
        total_score = sum(
            counts[sev] * weight for sev, weight in severity_weights.items()
        )
        risk_score = min(total_score, 100)

        # Determine overall risk level
        if counts["critical"] > 0:
            risk_level = "CRITICAL"
        elif counts["high"] > 0:
            risk_level = "HIGH"
        elif counts["medium"] > 0:
            risk_level = "MEDIUM"
        elif counts["low"] > 0:
            risk_level = "LOW"
        else:
            risk_level = "INFORMATIONAL"

        return {
            "score": risk_score,
            "level": risk_level,
            "counts": counts,
            "total_findings": len(findings),
        }

    def _categorize_findings(self, all_findings: dict) -> list[dict]:
        """
        Flatten and categorize all findings from different modules
        into a single sorted list.

        Args:
            all_findings: Dictionary keyed by module name with finding lists.

        Returns:
            Sorted list of all findings (critical first).
        """
        flat_findings = []

        for module_name, findings in all_findings.items():
            for finding in findings:
                finding["module"] = module_name
                flat_findings.append(finding)

        # Sort by severity (critical > high > medium > low > info)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        flat_findings.sort(
            key=lambda f: severity_order.get(f.get("severity", "info").lower(), 5)
        )

        return flat_findings

    def generate_html(
        self,
        target: str,
        all_findings: dict,
        port_results: list[dict],
        service_results: list[dict],
        scan_duration: float,
    ) -> str:
        """
        Generate an HTML report with Chart.js visualizations.

        Args:
            target: Scan target string.
            all_findings: Dict of findings keyed by module name.
            port_results: List of open port scan results.
            service_results: List of service detection results.
            scan_duration: Total scan duration in seconds.

        Returns:
            Path to the generated HTML report file.
        """
        # Flatten and sort findings
        flat_findings = self._categorize_findings(all_findings)
        risk = self._calculate_risk_score(flat_findings)

        # Prepare template data
        now = datetime.now(timezone.utc)
        template_data = {
            "title": self.company_name,
            "author": self.author,
            "target": target,
            "scan_date": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "scan_duration": f"{scan_duration:.1f}",
            "total_findings": len(flat_findings),
            "risk_score": risk["score"],
            "risk_level": risk["level"],
            "severity_counts": risk["counts"],
            "findings": flat_findings,
            "port_results": port_results,
            "service_results": service_results,
            "module_counts": {
                module: len(findings) for module, findings in all_findings.items()
            },
        }

        # Load and render the Jinja2 template
        template_dir = os.path.dirname(os.path.abspath(self.template_path))
        template_file = os.path.basename(self.template_path)

        env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True,
        )
        template = env.get_template(template_file)
        html_content = template.render(**template_data)

        # Write the HTML report
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        report_filename = f"vuln_report_{target.replace('.', '_').replace('/', '_')}_{timestamp}.html"
        report_path = os.path.join(self.output_dir, report_filename)

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"HTML report generated: {report_path}")
        return report_path

    def generate_json(
        self,
        target: str,
        all_findings: dict,
        port_results: list[dict],
        service_results: list[dict],
        scan_duration: float,
    ) -> str:
        """
        Generate a JSON export of all scan findings.

        Args:
            target: Scan target string.
            all_findings: Dict of findings keyed by module name.
            port_results: List of open port scan results.
            service_results: List of service detection results.
            scan_duration: Total scan duration in seconds.

        Returns:
            Path to the generated JSON export file.
        """
        flat_findings = self._categorize_findings(all_findings)
        risk = self._calculate_risk_score(flat_findings)

        now = datetime.now(timezone.utc)

        export_data = {
            "metadata": {
                "tool": "VulnScanner",
                "version": "1.0.0",
                "target": target,
                "scan_date": now.isoformat(),
                "scan_duration_seconds": round(scan_duration, 2),
                "author": self.author,
            },
            "risk_assessment": {
                "score": risk["score"],
                "level": risk["level"],
                "total_findings": risk["total_findings"],
                "severity_breakdown": risk["counts"],
            },
            "open_ports": port_results,
            "detected_services": service_results,
            "findings": flat_findings,
        }

        # Write JSON export
        timestamp = now.strftime("%Y%m%d_%H%M%S")
        json_filename = f"vuln_report_{target.replace('.', '_').replace('/', '_')}_{timestamp}.json"
        json_path = os.path.join(self.output_dir, json_filename)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, default=str)

        logger.info(f"JSON report generated: {json_path}")
        return json_path
