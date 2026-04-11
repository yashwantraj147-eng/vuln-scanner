#!/usr/bin/env python3
"""
main.py
========
VulnScanner — Command-Line Vulnerability Scanner
================================================

A comprehensive, multi-threaded vulnerability scanner with modular
architecture. Supports port scanning, service detection, web
vulnerability testing, SSL/TLS analysis, and default credential checking.

Usage Examples:
    # Full scan against localhost
    python main.py --target 127.0.0.1

    # Scan specific modules only
    python main.py --target 192.168.1.0/24 --modules ports,services,cve

    # Custom thread count and output directory
    python main.py --target testlab.local --threads 20 --output ./reports

    # Scan a domain with all modules
    python main.py --target localhost --modules all --threads 15

LEGAL DISCLAIMER:
    This tool is designed for AUTHORIZED security testing ONLY.
    Unauthorized scanning of networks and systems is ILLEGAL.
    Always obtain written permission before scanning any target.
    The authors assume no liability for misuse of this tool.
"""

import os
import sys
import time
import json
import logging
import argparse
from datetime import datetime, timezone

import yaml
from colorama import init, Fore, Style

from scanner.port_scanner import PortScanner
from scanner.service_detector import ServiceDetector
from scanner.web_scanner import WebScanner
from scanner.ssl_checker import SSLChecker
from scanner.creds_checker import CredsChecker
from cve_matcher import CVEMatcher
from report_generator import ReportGenerator

# Initialize colorama for Windows terminal colors
init(autoreset=True)

# ============================================================================
# Logging Configuration
# ============================================================================

def setup_logging(verbose: bool = False) -> None:
    """Configure logging with colored console output."""
    log_level = logging.DEBUG if verbose else logging.INFO
    log_format = (
        f"{Fore.CYAN}[%(asctime)s]{Style.RESET_ALL} "
        f"%(levelname)s — %(message)s"
    )
    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt="%H:%M:%S",
    )


# ============================================================================
# Banner
# ============================================================================

BANNER = f"""
{Fore.GREEN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗                      ║
║   ██║   ██║██║   ██║██║     ████╗  ██║                      ║
║   ██║   ██║██║   ██║██║     ██╔██╗ ██║    Scanner v1.0      ║
║   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ──────────────    ║
║    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    Vulnerability     ║
║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    Assessment Tool  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
{Fore.YELLOW}⚠  AUTHORIZED USE ONLY — Obtain written permission before scanning.{Style.RESET_ALL}
"""


# ============================================================================
# CLI Argument Parser
# ============================================================================

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="vulnscanner",
        description=(
            "VulnScanner — Multi-module vulnerability scanner for "
            "authorized security assessments."
        ),
        epilog=(
            "Examples:\n"
            "  python main.py --target 127.0.0.1\n"
            "  python main.py --target 192.168.1.0/24 --modules ports,web\n"
            "  python main.py --target testlab.local --threads 20 --output ./reports\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target IP, CIDR range, or domain name (e.g., 127.0.0.1, 10.0.0.0/24, testlab.local)"
    )
    parser.add_argument(
        "--threads", "-T",
        type=int,
        default=None,
        help="Number of concurrent scanning threads (default: from config.yaml)"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output directory for reports (default: ./output)"
    )
    parser.add_argument(
        "--modules", "-m",
        default="all",
        help=(
            "Comma-separated list of modules to run. "
            "Options: ports, services, web, ssl, creds, cve, all "
            "(default: all)"
        )
    )
    parser.add_argument(
        "--config", "-c",
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging output"
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip HTML/JSON report generation"
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Generate JSON report only (no HTML)"
    )

    return parser.parse_args()


# ============================================================================
# Configuration Loader
# ============================================================================

def load_config(config_path: str) -> dict:
    """
    Load the YAML configuration file.

    Args:
        config_path: Path to config.yaml.

    Returns:
        Configuration dictionary.
    """
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
        logging.info(f"Configuration loaded from {config_path}")
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.error(f"Invalid YAML configuration: {e}")
        sys.exit(1)


# ============================================================================
# Main Scanner Orchestrator
# ============================================================================

def main():
    """Main entry point — orchestrates all scanning modules."""
    args = parse_args()

    # Display banner
    print(BANNER)

    # Setup logging
    setup_logging(verbose=args.verbose)
    logger = logging.getLogger(__name__)

    # Load configuration
    config = load_config(args.config)
    general = config.get("general", {})

    # Resolve settings (CLI args override config)
    threads = args.threads or general.get("default_threads", 10)
    output_dir = args.output or general.get("output_dir", "./output")
    os.makedirs(output_dir, exist_ok=True)

    # Parse modules to run
    available_modules = {"ports", "services", "web", "ssl", "creds", "cve"}
    if args.modules.lower() == "all":
        active_modules = available_modules
    else:
        active_modules = set(
            m.strip().lower() for m in args.modules.split(",")
        )
        invalid = active_modules - available_modules
        if invalid:
            logger.error(
                f"Unknown modules: {invalid}. "
                f"Valid: {', '.join(sorted(available_modules))}"
            )
            sys.exit(1)

    # Display scan configuration
    logger.info(f"{'='*60}")
    logger.info(f"Target:     {args.target}")
    logger.info(f"Threads:    {threads}")
    logger.info(f"Modules:    {', '.join(sorted(active_modules))}")
    logger.info(f"Output:     {output_dir}")
    logger.info(f"{'='*60}")

    # Track scan timing
    scan_start = time.time()

    # Result accumulators
    port_results = []
    service_results = []
    all_findings = {}

    # =================================================================
    # MODULE 1: Port Scanner
    # =================================================================
    if "ports" in active_modules:
        logger.info(f"\n{Fore.CYAN}{'─'*60}")
        logger.info(f"MODULE: Port Scanner")
        logger.info(f"{'─'*60}{Style.RESET_ALL}")

        port_config = config.get("port_scanner", {})
        port_config["timeout"] = general.get("timeout", 5)
        scanner = PortScanner(config=port_config, threads=threads)
        port_results = scanner.scan(args.target)

    # =================================================================
    # MODULE 2: Service Detection
    # =================================================================
    if "services" in active_modules and port_results:
        logger.info(f"\n{Fore.CYAN}{'─'*60}")
        logger.info(f"MODULE: Service Detection")
        logger.info(f"{'─'*60}{Style.RESET_ALL}")

        svc_config = config.get("service_detector", {})
        detector = ServiceDetector(config=svc_config)
        service_results = detector.analyze_ports(port_results)

    # =================================================================
    # MODULE 3: CVE Matching
    # =================================================================
    if "cve" in active_modules and service_results:
        logger.info(f"\n{Fore.CYAN}{'─'*60}")
        logger.info(f"MODULE: CVE Matching")
        logger.info(f"{'─'*60}{Style.RESET_ALL}")

        cve_db_path = config.get("cve_database", {}).get(
            "snapshot_path", "./data/cve_snapshot.json"
        )
        cve_matcher = CVEMatcher(cve_db_path=cve_db_path)

        # Get services with known versions
        if "services" in active_modules:
            matchable = detector.get_services_for_cve_matching()
        else:
            matchable = [
                {
                    "service": s.get("service", ""),
                    "version": s.get("version", ""),
                    "ip": s.get("ip", ""),
                    "port": s.get("port", 0),
                }
                for s in service_results
                if s.get("version") and s.get("version") != "Unknown"
            ]

        cve_findings = cve_matcher.match_all(matchable)
        if cve_findings:
            all_findings["CVE Vulnerabilities"] = cve_findings

    # =================================================================
    # MODULE 4: Web Vulnerability Scanner
    # =================================================================
    if "web" in active_modules and port_results:
        logger.info(f"\n{Fore.CYAN}{'─'*60}")
        logger.info(f"MODULE: Web Vulnerability Scanner")
        logger.info(f"{'─'*60}{Style.RESET_ALL}")

        web_config = config.get("web_scanner", {})
        web_config["timeout"] = general.get("timeout", 5)
        web_scanner = WebScanner(config=web_config, threads=threads)
        web_findings = web_scanner.scan(args.target, port_results)
        if web_findings:
            all_findings["Web Vulnerabilities"] = web_findings

    # =================================================================
    # MODULE 5: SSL/TLS Checker
    # =================================================================
    if "ssl" in active_modules and port_results:
        logger.info(f"\n{Fore.CYAN}{'─'*60}")
        logger.info(f"MODULE: SSL/TLS Checker")
        logger.info(f"{'─'*60}{Style.RESET_ALL}")

        ssl_config = config.get("ssl_checker", {})
        ssl_config["timeout"] = general.get("timeout", 5)
        ssl_checker = SSLChecker(config=ssl_config)
        ssl_findings = ssl_checker.scan(args.target, port_results)
        if ssl_findings:
            all_findings["SSL/TLS Issues"] = ssl_findings

    # =================================================================
    # MODULE 6: Default Credentials Checker
    # =================================================================
    if "creds" in active_modules and port_results:
        logger.info(f"\n{Fore.CYAN}{'─'*60}")
        logger.info(f"MODULE: Default Credentials Checker")
        logger.info(f"{'─'*60}{Style.RESET_ALL}")

        creds_config = config.get("creds_checker", {})
        creds_config["timeout"] = general.get("timeout", 5)
        creds_checker = CredsChecker(config=creds_config, threads=min(threads, 5))
        creds_findings = creds_checker.scan(args.target, port_results)
        if creds_findings:
            all_findings["Default Credentials"] = creds_findings

    # =================================================================
    # RESULTS SUMMARY
    # =================================================================
    scan_duration = time.time() - scan_start

    total_findings = sum(len(f) for f in all_findings.values())

    print(f"\n{Fore.GREEN}{'═'*60}")
    print(f"  SCAN COMPLETE")
    print(f"{'═'*60}{Style.RESET_ALL}")
    print(f"  Target:        {args.target}")
    print(f"  Duration:      {scan_duration:.1f} seconds")
    print(f"  Open Ports:    {len(port_results)}")
    print(f"  Services:      {len(service_results)}")
    print(f"  Findings:      {total_findings}")

    # Severity breakdown
    severity_summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for findings_list in all_findings.values():
        for finding in findings_list:
            sev = finding.get("severity", "Info")
            severity_summary[sev] = severity_summary.get(sev, 0) + 1

    if total_findings > 0:
        print(f"\n  Severity Breakdown:")
        if severity_summary["Critical"]:
            print(f"    {Fore.RED}  Critical: {severity_summary['Critical']}{Style.RESET_ALL}")
        if severity_summary["High"]:
            print(f"    {Fore.YELLOW}  High:     {severity_summary['High']}{Style.RESET_ALL}")
        if severity_summary["Medium"]:
            print(f"    {Fore.LIGHTYELLOW_EX}  Medium:   {severity_summary['Medium']}{Style.RESET_ALL}")
        if severity_summary["Low"]:
            print(f"    {Fore.CYAN}  Low:      {severity_summary['Low']}{Style.RESET_ALL}")
        if severity_summary["Info"]:
            print(f"    {Fore.BLUE}  Info:     {severity_summary['Info']}{Style.RESET_ALL}")

    print(f"{'═'*60}")

    # =================================================================
    # REPORT GENERATION
    # =================================================================
    if not args.no_report:
        logger.info(f"\n{Fore.CYAN}Generating reports...{Style.RESET_ALL}")

        report_config = config.get("report", {})
        generator = ReportGenerator(config=report_config, output_dir=output_dir)

        # Generate JSON report
        json_path = generator.generate_json(
            target=args.target,
            all_findings=all_findings,
            port_results=port_results,
            service_results=service_results,
            scan_duration=scan_duration,
        )
        print(f"  📄 JSON Report: {json_path}")

        # Generate HTML report (unless json-only)
        if not args.json_only:
            html_path = generator.generate_html(
                target=args.target,
                all_findings=all_findings,
                port_results=port_results,
                service_results=service_results,
                scan_duration=scan_duration,
            )
            print(f"  📊 HTML Report: {html_path}")

    print(f"\n{Fore.GREEN}✅ All done.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
