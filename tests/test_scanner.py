"""
tests/test_scanner.py
======================
Comprehensive test suite for VulnScanner modules.
Tests cover unit tests for all scanner components, CVE matching,
and report generation using mocks and fixtures.

Run with: pytest tests/test_scanner.py -v
"""

import json
import os
import socket
import tempfile
from unittest.mock import patch, MagicMock, mock_open

import pytest

# ============================================================================
# Test fixtures and helpers
# ============================================================================

@pytest.fixture
def port_scanner_config():
    """Configuration fixture for the port scanner."""
    return {
        "default_ports": [22, 80, 443],
        "scan_type": "connect",
        "banner_timeout": 2,
        "max_retries": 1,
        "timeout": 3,
    }


@pytest.fixture
def service_detector_config():
    """Configuration fixture for the service detector."""
    return {
        "signatures": [
            {
                "pattern": "SSH-([\\d.]+)-OpenSSH_([\\w.]+)",
                "service": "OpenSSH",
                "version_group": 2,
            },
            {
                "pattern": "Server: Apache/([\\d.]+)",
                "service": "Apache HTTP Server",
                "version_group": 1,
            },
            {
                "pattern": "Server: nginx/([\\d.]+)",
                "service": "nginx",
                "version_group": 1,
            },
            {
                "pattern": "220.*vsftpd ([\\d.]+)",
                "service": "vsftpd",
                "version_group": 1,
            },
        ]
    }


@pytest.fixture
def web_scanner_config():
    """Configuration fixture for the web scanner."""
    return {
        "user_agent": "TestAgent/1.0",
        "request_delay": 0,
        "follow_redirects": False,
        "timeout": 3,
        "sqli_payloads": ["' OR '1'='1", "' OR '1'='1' --"],
        "sqli_errors": ["you have an error in your sql syntax", "warning: mysql"],
        "xss_payloads": ["<script>alert('XSS')</script>"],
        "redirect_payloads": ["//evil.com"],
        "traversal_payloads": ["../../../etc/passwd"],
        "common_dirs": ["/admin", "/robots.txt"],
    }


@pytest.fixture
def ssl_checker_config():
    """Configuration fixture for the SSL checker."""
    return {
        "check_expiry": True,
        "check_self_signed": True,
        "check_weak_ciphers": True,
        "check_protocols": True,
        "weak_ciphers": ["RC4", "DES", "3DES", "NULL"],
        "deprecated_protocols": ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"],
        "timeout": 3,
    }


@pytest.fixture
def creds_checker_config():
    """Configuration fixture for the credentials checker."""
    return {
        "timeout": 3,
        "ssh_creds": [{"username": "admin", "password": "admin"}],
        "ftp_creds": [{"username": "anonymous", "password": ""}],
        "telnet_creds": [{"username": "admin", "password": "admin"}],
        "http_creds": [{"username": "admin", "password": "admin"}],
        "http_login_paths": ["/login"],
    }


@pytest.fixture
def sample_port_results():
    """Sample port scan results for testing downstream modules."""
    return [
        {
            "ip": "127.0.0.1",
            "port": 22,
            "state": "open",
            "scan_type": "connect",
            "banner": "SSH-2.0-OpenSSH_9.1",
            "service": "SSH",
        },
        {
            "ip": "127.0.0.1",
            "port": 80,
            "state": "open",
            "scan_type": "connect",
            "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n",
            "service": "HTTP",
        },
        {
            "ip": "127.0.0.1",
            "port": 443,
            "state": "open",
            "scan_type": "connect",
            "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.25.1\r\n",
            "service": "HTTPS",
        },
        {
            "ip": "127.0.0.1",
            "port": 21,
            "state": "open",
            "scan_type": "connect",
            "banner": "220 (vsftpd 3.0.3)",
            "service": "FTP",
        },
    ]


@pytest.fixture
def sample_cve_db(tmp_path):
    """Create a temporary CVE database for testing."""
    cve_data = [
        {
            "cve_id": "CVE-2023-25136",
            "service": "OpenSSH",
            "affected_versions": {"min": "9.1", "max": "9.1"},
            "severity": "Medium",
            "cvss_score": 6.5,
            "description": "Double-free vulnerability in OpenSSH server 9.1.",
            "remediation": "Upgrade to OpenSSH 9.2 or later.",
        },
        {
            "cve_id": "CVE-2023-25690",
            "service": "Apache HTTP Server",
            "affected_versions": {"min": "2.4.0", "max": "2.4.55"},
            "severity": "Critical",
            "cvss_score": 9.8,
            "description": "HTTP request smuggling via mod_proxy.",
            "remediation": "Upgrade to Apache HTTP Server 2.4.56 or later.",
        },
        {
            "cve_id": "CVE-2023-3824",
            "service": "vsftpd",
            "affected_versions": {"min": "2.0.0", "max": "3.0.3"},
            "severity": "High",
            "cvss_score": 7.5,
            "description": "DoS via crafted FTP commands.",
            "remediation": "Upgrade to vsftpd 3.0.5 or later.",
        },
    ]

    cve_path = tmp_path / "test_cve.json"
    with open(cve_path, "w") as f:
        json.dump(cve_data, f)

    return str(cve_path)


# ============================================================================
# Port Scanner Tests
# ============================================================================

class TestPortScanner:
    """Tests for the PortScanner module."""

    def test_init(self, port_scanner_config):
        """Test PortScanner initialization with config."""
        from scanner.port_scanner import PortScanner
        scanner = PortScanner(config=port_scanner_config, threads=5)
        assert scanner.threads == 5
        assert scanner.ports == [22, 80, 443]
        assert scanner.scan_type == "connect"
        assert scanner.timeout == 3

    def test_resolve_target_single_ip(self, port_scanner_config):
        """Test resolving a single IP address."""
        from scanner.port_scanner import PortScanner
        scanner = PortScanner(config=port_scanner_config)
        ips = scanner.resolve_target("127.0.0.1")
        assert "127.0.0.1" in ips

    def test_resolve_target_cidr(self, port_scanner_config):
        """Test resolving a CIDR range."""
        from scanner.port_scanner import PortScanner
        scanner = PortScanner(config=port_scanner_config)
        ips = scanner.resolve_target("192.168.1.0/30")
        # /30 gives 2 usable hosts: .1 and .2
        assert len(ips) == 2
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips

    def test_resolve_target_domain(self, port_scanner_config):
        """Test resolving a domain name."""
        from scanner.port_scanner import PortScanner
        scanner = PortScanner(config=port_scanner_config)
        ips = scanner.resolve_target("localhost")
        assert len(ips) > 0
        assert ips[0] == "127.0.0.1"

    def test_resolve_target_invalid(self, port_scanner_config):
        """Test resolving an invalid target."""
        from scanner.port_scanner import PortScanner
        scanner = PortScanner(config=port_scanner_config)
        ips = scanner.resolve_target("this.domain.does.not.exist.invalid")
        assert len(ips) == 0

    def test_guess_service(self, port_scanner_config):
        """Test port-to-service mapping."""
        from scanner.port_scanner import PortScanner
        scanner = PortScanner(config=port_scanner_config)
        assert scanner._guess_service(22) == "SSH"
        assert scanner._guess_service(80) == "HTTP"
        assert scanner._guess_service(443) == "HTTPS"
        assert scanner._guess_service(3306) == "MySQL"
        assert scanner._guess_service(99999) == "Unknown"

    @patch("socket.socket")
    def test_connect_scan_open_port(self, mock_socket_class, port_scanner_config):
        """Test connect scan detecting an open port."""
        from scanner.port_scanner import PortScanner

        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        scanner = PortScanner(config=port_scanner_config)

        with patch.object(scanner, "_grab_banner", return_value="SSH-2.0-OpenSSH_9.1"):
            result = scanner.connect_scan("127.0.0.1", 22)

        assert result is not None
        assert result["port"] == 22
        assert result["state"] == "open"

    @patch("socket.socket")
    def test_connect_scan_closed_port(self, mock_socket_class, port_scanner_config):
        """Test connect scan detecting a closed port."""
        from scanner.port_scanner import PortScanner

        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1  # Connection refused
        mock_socket_class.return_value = mock_sock

        scanner = PortScanner(config=port_scanner_config)
        result = scanner.connect_scan("127.0.0.1", 12345)
        assert result is None


# ============================================================================
# Service Detector Tests
# ============================================================================

class TestServiceDetector:
    """Tests for the ServiceDetector module."""

    def test_init(self, service_detector_config):
        """Test ServiceDetector initialization."""
        from scanner.service_detector import ServiceDetector
        detector = ServiceDetector(config=service_detector_config)
        assert len(detector._compiled_signatures) == 4

    def test_detect_openssh(self, service_detector_config):
        """Test detecting OpenSSH from banner."""
        from scanner.service_detector import ServiceDetector
        detector = ServiceDetector(config=service_detector_config)
        result = detector.detect_service("SSH-2.0-OpenSSH_9.1")
        assert result is not None
        assert result["service"] == "OpenSSH"
        assert result["version"] == "9.1"

    def test_detect_apache(self, service_detector_config):
        """Test detecting Apache from HTTP banner."""
        from scanner.service_detector import ServiceDetector
        detector = ServiceDetector(config=service_detector_config)
        result = detector.detect_service(
            "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52"
        )
        assert result is not None
        assert result["service"] == "Apache HTTP Server"
        assert result["version"] == "2.4.52"

    def test_detect_nginx(self, service_detector_config):
        """Test detecting nginx from HTTP banner."""
        from scanner.service_detector import ServiceDetector
        detector = ServiceDetector(config=service_detector_config)
        result = detector.detect_service("Server: nginx/1.25.1")
        assert result is not None
        assert result["service"] == "nginx"
        assert result["version"] == "1.25.1"

    def test_detect_vsftpd(self, service_detector_config):
        """Test detecting vsftpd from FTP banner."""
        from scanner.service_detector import ServiceDetector
        detector = ServiceDetector(config=service_detector_config)
        result = detector.detect_service("220 (vsftpd 3.0.3)")
        assert result is not None
        assert result["service"] == "vsftpd"
        assert result["version"] == "3.0.3"

    def test_detect_empty_banner(self, service_detector_config):
        """Test with empty banner string."""
        from scanner.service_detector import ServiceDetector
        detector = ServiceDetector(config=service_detector_config)
        result = detector.detect_service("")
        assert result is None

    def test_detect_unknown_banner(self, service_detector_config):
        """Test with unknown/non-matching banner."""
        from scanner.service_detector import ServiceDetector
        detector = ServiceDetector(config=service_detector_config)
        result = detector.detect_service("SOME RANDOM BANNER")
        # Generic detection may still try to parse it
        # If no match, should return None
        assert result is None or "service" in result

    def test_analyze_ports(self, service_detector_config, sample_port_results):
        """Test analyzing multiple port results."""
        from scanner.service_detector import ServiceDetector
        detector = ServiceDetector(config=service_detector_config)
        results = detector.analyze_ports(sample_port_results)
        assert len(results) == 4  # 4 ports in sample data

        # Verify OpenSSH detection
        ssh_result = next(r for r in results if r["port"] == 22)
        assert ssh_result["service"] == "OpenSSH"
        assert ssh_result["version"] == "9.1"
        assert ssh_result["confidence"] == "high"

    def test_get_services_for_cve_matching(self, service_detector_config, sample_port_results):
        """Test filtering services suitable for CVE matching."""
        from scanner.service_detector import ServiceDetector
        detector = ServiceDetector(config=service_detector_config)
        detector.analyze_ports(sample_port_results)
        matchable = detector.get_services_for_cve_matching()
        # Only services with known versions should be returned
        assert all(s["version"] != "Unknown" for s in matchable)
        assert len(matchable) > 0


# ============================================================================
# CVE Matcher Tests
# ============================================================================

class TestCVEMatcher:
    """Tests for the CVEMatcher module."""

    def test_load_database(self, sample_cve_db):
        """Test loading the CVE database."""
        from cve_matcher import CVEMatcher
        matcher = CVEMatcher(cve_db_path=sample_cve_db)
        assert len(matcher.cve_entries) == 3

    def test_load_missing_database(self, tmp_path):
        """Test loading a non-existent database file."""
        from cve_matcher import CVEMatcher
        matcher = CVEMatcher(cve_db_path=str(tmp_path / "nonexistent.json"))
        assert len(matcher.cve_entries) == 0

    def test_match_openssh_vulnerable(self, sample_cve_db):
        """Test matching a vulnerable OpenSSH version."""
        from cve_matcher import CVEMatcher
        matcher = CVEMatcher(cve_db_path=sample_cve_db)
        matches = matcher.match_service("OpenSSH", "9.1")
        assert len(matches) == 1
        assert matches[0]["cve_id"] == "CVE-2023-25136"

    def test_match_openssh_not_vulnerable(self, sample_cve_db):
        """Test matching a non-vulnerable OpenSSH version."""
        from cve_matcher import CVEMatcher
        matcher = CVEMatcher(cve_db_path=sample_cve_db)
        matches = matcher.match_service("OpenSSH", "9.5")
        assert len(matches) == 0

    def test_match_apache_vulnerable(self, sample_cve_db):
        """Test matching a vulnerable Apache version."""
        from cve_matcher import CVEMatcher
        matcher = CVEMatcher(cve_db_path=sample_cve_db)
        matches = matcher.match_service("Apache HTTP Server", "2.4.52")
        assert len(matches) == 1
        assert matches[0]["cve_id"] == "CVE-2023-25690"
        assert matches[0]["severity"] == "Critical"

    def test_match_vsftpd_vulnerable(self, sample_cve_db):
        """Test matching a vulnerable vsftpd version."""
        from cve_matcher import CVEMatcher
        matcher = CVEMatcher(cve_db_path=sample_cve_db)
        matches = matcher.match_service("vsftpd", "3.0.3")
        assert len(matches) == 1
        assert matches[0]["cve_id"] == "CVE-2023-3824"

    def test_match_no_service(self, sample_cve_db):
        """Test matching an unknown service."""
        from cve_matcher import CVEMatcher
        matcher = CVEMatcher(cve_db_path=sample_cve_db)
        matches = matcher.match_service("UnknownService", "1.0.0")
        assert len(matches) == 0

    def test_match_all(self, sample_cve_db):
        """Test matching multiple services at once."""
        from cve_matcher import CVEMatcher
        matcher = CVEMatcher(cve_db_path=sample_cve_db)

        services = [
            {"service": "OpenSSH", "version": "9.1", "ip": "127.0.0.1", "port": 22},
            {"service": "Apache HTTP Server", "version": "2.4.52", "ip": "127.0.0.1", "port": 80},
            {"service": "vsftpd", "version": "3.0.3", "ip": "127.0.0.1", "port": 21},
        ]

        results = matcher.match_all(services)
        assert len(results) == 3  # Each service has exactly one matching CVE

    def test_get_summary(self, sample_cve_db):
        """Test CVE summary generation."""
        from cve_matcher import CVEMatcher
        matcher = CVEMatcher(cve_db_path=sample_cve_db)

        services = [
            {"service": "OpenSSH", "version": "9.1", "ip": "127.0.0.1", "port": 22},
            {"service": "Apache HTTP Server", "version": "2.4.52", "ip": "127.0.0.1", "port": 80},
        ]
        matcher.match_all(services)

        summary = matcher.get_summary()
        assert summary["total"] == 2
        assert summary["critical"] == 1  # Apache CVE
        assert summary["medium"] == 1    # OpenSSH CVE

    def test_version_parsing_with_suffix(self, sample_cve_db):
        """Test version parsing with p-suffix (e.g., OpenSSH 9.1p1)."""
        from cve_matcher import CVEMatcher
        matcher = CVEMatcher(cve_db_path=sample_cve_db)
        matches = matcher.match_service("OpenSSH", "9.1p1")
        assert len(matches) == 1  # Should match after stripping the p1 suffix

    def test_version_parsing_prefix_and_fallback(self, sample_cve_db):
        """Test version parsing with v-prefix and complex tags."""
        from cve_matcher import CVEMatcher
        matcher = CVEMatcher(cve_db_path=sample_cve_db)
        v1 = matcher._parse_version("v2.4.50")
        assert v1 is not None
        assert str(v1) == "2.4.50"

        v2 = matcher._parse_version("2.4.50-1ubuntu0.1")
        assert v2 is not None
        assert str(v2) == "2.4.50"

    @patch("requests.get")
    def test_cisa_kev_update(self, mock_get, sample_cve_db):
        """Test CISA KEV catalog update with mocks."""
        from cve_matcher import CVEMatcher
        matcher = CVEMatcher(cve_db_path=sample_cve_db)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-9999",
                    "product": "TestServer",
                    "shortDescription": "Critical RCE in wild",
                    "requiredAction": "Patch immediately",
                }
            ]
        }
        mock_get.return_value = mock_resp

        added = matcher.update_from_cisa_kev()
        assert added == 1
        assert any(c["cve_id"] == "CVE-2024-9999" for c in matcher.cve_entries)

    @patch("requests.post")
    def test_osv_api_query(self, mock_post, sample_cve_db):
        """Test OSV.dev vulnerability lookup with mocks."""
        from cve_matcher import CVEMatcher
        matcher = CVEMatcher(cve_db_path=sample_cve_db)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-1234",
                    "aliases": ["CVE-2024-8888"],
                    "summary": "OSV reported vulnerability",
                }
            ]
        }
        mock_post.return_value = mock_resp

        results = matcher.query_osv_api("apache", "2.4.50")
        assert len(results) == 1
        assert results[0]["cve_id"] == "CVE-2024-8888"


# ============================================================================
# Web Scanner Tests
# ============================================================================

class TestWebScanner:
    """Tests for the WebScanner module."""

    def test_init(self, web_scanner_config):
        """Test WebScanner initialization."""
        from scanner.web_scanner import WebScanner
        scanner = WebScanner(config=web_scanner_config, threads=5)
        assert scanner.threads == 5
        assert scanner.user_agent == "TestAgent/1.0"
        assert len(scanner.sqli_payloads) == 2

    def test_build_base_url_http(self, web_scanner_config):
        """Test base URL building for HTTP."""
        from scanner.web_scanner import WebScanner
        scanner = WebScanner(config=web_scanner_config)
        url = scanner._build_base_url("127.0.0.1", 80)
        assert url == "http://127.0.0.1"

    def test_build_base_url_https(self, web_scanner_config):
        """Test base URL building for HTTPS."""
        from scanner.web_scanner import WebScanner
        scanner = WebScanner(config=web_scanner_config)
        url = scanner._build_base_url("127.0.0.1", 443)
        assert url == "https://127.0.0.1"

    def test_build_base_url_custom_port(self, web_scanner_config):
        """Test base URL building for custom port."""
        from scanner.web_scanner import WebScanner
        scanner = WebScanner(config=web_scanner_config)
        url = scanner._build_base_url("127.0.0.1", 8080)
        assert url == "http://127.0.0.1:8080"

    @patch("requests.Session.get")
    def test_sqli_detection(self, mock_get, web_scanner_config):
        """Test SQL injection detection via error-based method."""
        from scanner.web_scanner import WebScanner
        scanner = WebScanner(config=web_scanner_config)
        scanner.request_delay = 0

        # Mock a response that contains a SQL error
        mock_response = MagicMock()
        mock_response.text = "You have an error in your SQL syntax near..."
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        params = [{"url": "http://127.0.0.1/search", "param": "q", "method": "GET"}]
        findings = scanner.test_sqli("http://127.0.0.1", params)
        assert len(findings) > 0
        assert findings[0]["type"] == "SQL Injection"
        assert findings[0]["severity"] == "Critical"

    @patch("requests.Session.get")
    def test_xss_detection(self, mock_get, web_scanner_config):
        """Test XSS detection via reflected payload."""
        from scanner.web_scanner import WebScanner
        scanner = WebScanner(config=web_scanner_config)
        scanner.request_delay = 0

        # Mock a response that reflects the XSS payload
        mock_response = MagicMock()
        mock_response.text = "<html><body><script>alert('XSS')</script></body></html>"
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        params = [{"url": "http://127.0.0.1/page", "param": "q", "method": "GET"}]
        findings = scanner.test_xss("http://127.0.0.1", params)
        assert len(findings) > 0
        assert findings[0]["type"] == "Cross-Site Scripting (XSS)"
        assert findings[0]["severity"] == "High"

    @patch("requests.Session.get")
    def test_check_security_headers(self, mock_get, web_scanner_config):
        """Test missing security headers detection."""
        from scanner.web_scanner import WebScanner
        scanner = WebScanner(config=web_scanner_config)

        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "Apache"}
        mock_get.return_value = mock_resp

        findings = scanner.check_security_headers("https://127.0.0.1")
        assert len(findings) >= 3
        types = [f["type"] for f in findings]
        assert "Missing Security Header - CSP" in types
        assert "Missing Security Header - HSTS" in types

    @patch("requests.Session.get")
    def test_check_cors(self, mock_get, web_scanner_config):
        """Test CORS misconfiguration detection."""
        from scanner.web_scanner import WebScanner
        scanner = WebScanner(config=web_scanner_config)

        mock_resp = MagicMock()
        mock_resp.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        mock_get.return_value = mock_resp

        findings = scanner.check_cors("http://127.0.0.1")
        assert len(findings) == 1
        assert findings[0]["type"] == "Insecure CORS Configuration"
        assert findings[0]["severity"] == "Critical"

    @patch("requests.Session.get")
    def test_check_cookies(self, mock_get, web_scanner_config):
        """Test insecure cookie flags detection."""
        from scanner.web_scanner import WebScanner
        scanner = WebScanner(config=web_scanner_config)

        mock_cookie = MagicMock()
        mock_cookie.name = "session_id"
        mock_cookie.secure = False
        mock_cookie.has_nonstandard_attr.return_value = False
        mock_cookie._rest = {}

        mock_resp = MagicMock()
        mock_resp.cookies = [mock_cookie]
        mock_get.return_value = mock_resp

        findings = scanner.check_cookies("https://127.0.0.1")
        assert len(findings) == 1
        assert findings[0]["type"] == "Insecure Cookie Flags"
        assert "session_id" in findings[0]["evidence"]

    def test_scan_no_http_ports(self, web_scanner_config):
        """Test web scan when no HTTP ports are found."""
        from scanner.web_scanner import WebScanner
        scanner = WebScanner(config=web_scanner_config)

        # Port results without HTTP services
        port_results = [
            {"ip": "127.0.0.1", "port": 22, "service": "SSH", "state": "open"},
        ]
        results = scanner.scan("127.0.0.1", port_results)
        assert len(results) == 0


# ============================================================================
# SSL Checker Tests
# ============================================================================

class TestSSLChecker:
    """Tests for the SSLChecker module."""

    def test_init(self, ssl_checker_config):
        """Test SSLChecker initialization."""
        from scanner.ssl_checker import SSLChecker
        checker = SSLChecker(config=ssl_checker_config)
        assert checker.check_expiry is True
        assert checker.check_self_signed is True
        assert len(checker.weak_ciphers) == 4

    def test_check_cipher_strength_weak(self, ssl_checker_config):
        """Test detection of weak cipher suites."""
        from scanner.ssl_checker import SSLChecker
        checker = SSLChecker(config=ssl_checker_config)

        cipher_info = ("DES-CBC3-SHA", "TLSv1.2", 112)
        findings = checker._check_cipher_strength(cipher_info, "127.0.0.1", 443)
        # Should find DES or 3DES weakness
        assert len(findings) > 0
        assert any("Weak" in f["type"] for f in findings)

    def test_check_cipher_strength_strong(self, ssl_checker_config):
        """Test that strong ciphers pass."""
        from scanner.ssl_checker import SSLChecker
        checker = SSLChecker(config=ssl_checker_config)

        cipher_info = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        findings = checker._check_cipher_strength(cipher_info, "127.0.0.1", 443)
        # Should not find any weak cipher issues
        assert all("Weak Cipher" not in f["type"] for f in findings)

    def test_check_protocol_deprecated(self, ssl_checker_config):
        """Test detection of deprecated TLS protocols."""
        from scanner.ssl_checker import SSLChecker
        checker = SSLChecker(config=ssl_checker_config)

        findings = checker._check_protocol_version("TLSv1.0", "127.0.0.1", 443)
        assert len(findings) > 0
        assert any("Deprecated" in f["type"] for f in findings)

    def test_check_protocol_modern(self, ssl_checker_config):
        """Test that modern TLS protocols pass."""
        from scanner.ssl_checker import SSLChecker
        checker = SSLChecker(config=ssl_checker_config)

        findings = checker._check_protocol_version("TLSv1.3", "127.0.0.1", 443)
        # Should only have informational finding
        assert all(f["severity"] == "Info" for f in findings)

    def test_scan_no_ssl_ports(self, ssl_checker_config):
        """Test SSL scan when no SSL ports are found."""
        from scanner.ssl_checker import SSLChecker
        checker = SSLChecker(config=ssl_checker_config)

        port_results = [
            {"ip": "127.0.0.1", "port": 80, "service": "HTTP", "state": "open"},
        ]
        results = checker.scan("127.0.0.1", port_results)
        assert len(results) == 0


# ============================================================================
# Credentials Checker Tests
# ============================================================================

class TestCredsChecker:
    """Tests for the CredsChecker module."""

    def test_init(self, creds_checker_config):
        """Test CredsChecker initialization."""
        from scanner.creds_checker import CredsChecker
        checker = CredsChecker(config=creds_checker_config, threads=3)
        assert checker.threads == 3
        assert len(checker.ssh_creds) == 1
        assert len(checker.ftp_creds) == 1

    @patch("paramiko.SSHClient")
    def test_ssh_success(self, mock_ssh_class, creds_checker_config):
        """Test SSH credential check with successful login."""
        from scanner.creds_checker import CredsChecker
        checker = CredsChecker(config=creds_checker_config)

        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        # connect() succeeds without raising exception
        mock_client.connect.return_value = None

        result = checker._check_ssh("127.0.0.1", 22, "admin", "admin")
        assert result is not None
        assert result["type"] == "Default Credentials - SSH"
        assert result["severity"] == "Critical"

    @patch("paramiko.SSHClient")
    def test_ssh_failure(self, mock_ssh_class, creds_checker_config):
        """Test SSH credential check with failed login."""
        from scanner.creds_checker import CredsChecker

        # Need to import paramiko for the exception
        import paramiko

        checker = CredsChecker(config=creds_checker_config)

        mock_client = MagicMock()
        mock_ssh_class.return_value = mock_client
        mock_client.connect.side_effect = paramiko.AuthenticationException("Auth failed")

        result = checker._check_ssh("127.0.0.1", 22, "admin", "wrongpass")
        assert result is None

    @patch("socket.create_connection")
    def test_telnet_socket_success(self, mock_create_connection, creds_checker_config):
        """Test socket-based Telnet credential checking."""
        from scanner.creds_checker import CredsChecker
        checker = CredsChecker(config=creds_checker_config)

        mock_sock = MagicMock()
        mock_create_connection.return_value = mock_sock
        # Simulate telnet prompts and successful login response
        mock_sock.recv.side_effect = [
            b"Login: ",
            b"Password: ",
            b"Welcome to Lab Server\r\n# ",
            b"",
        ]

        result = checker._check_telnet("127.0.0.1", 23, "admin", "admin")
        assert result is not None
        assert result["type"] == "Default Credentials - Telnet"
        assert result["severity"] == "Critical"

    @patch("socket.create_connection")
    def test_redis_unauthenticated(self, mock_create_connection, creds_checker_config):
        """Test unauthenticated Redis access detection."""
        from scanner.creds_checker import CredsChecker
        checker = CredsChecker(config=creds_checker_config)

        mock_sock = MagicMock()
        mock_create_connection.return_value = mock_sock
        mock_sock.recv.side_effect = [
            b"+PONG\r\n",
            b"# Server\r\nredis_version:7.2.4\r\n",
        ]

        result = checker._check_redis("127.0.0.1", 6379)
        assert result is not None
        assert result["type"] == "Unauthenticated Access - Redis"
        assert result["severity"] == "Critical"
        assert "7.2.4" in result["evidence"]

    def test_scan_no_applicable_services(self, creds_checker_config):
        """Test creds scan when no applicable services are found."""
        from scanner.creds_checker import CredsChecker
        checker = CredsChecker(config=creds_checker_config)

        # Port results without SSH/FTP/Telnet/HTTP services
        port_results = [
            {"ip": "127.0.0.1", "port": 3306, "service": "MySQL", "state": "open"},
        ]
        results = checker.scan("127.0.0.1", port_results)
        assert len(results) == 0


# ============================================================================
# Report Generator Tests
# ============================================================================

class TestReportGenerator:
    """Tests for the ReportGenerator module."""

    def test_init(self, tmp_path):
        """Test ReportGenerator initialization."""
        from report_generator import ReportGenerator
        config = {
            "company_name": "Test Report",
            "author": "Test Author",
            "template_path": "./templates/report.html",
        }
        gen = ReportGenerator(config=config, output_dir=str(tmp_path))
        assert gen.company_name == "Test Report"
        assert gen.author == "Test Author"

    def test_calculate_risk_score_critical(self):
        """Test risk score calculation with critical findings."""
        from report_generator import ReportGenerator
        gen = ReportGenerator(config={}, output_dir=".")

        findings = [
            {"severity": "Critical"},
            {"severity": "High"},
            {"severity": "Medium"},
        ]
        risk = gen._calculate_risk_score(findings)
        assert risk["level"] == "CRITICAL"
        assert risk["score"] > 0
        assert risk["counts"]["critical"] == 1

    def test_calculate_risk_score_clean(self):
        """Test risk score calculation with no findings."""
        from report_generator import ReportGenerator
        gen = ReportGenerator(config={}, output_dir=".")

        risk = gen._calculate_risk_score([])
        assert risk["level"] == "INFORMATIONAL"
        assert risk["score"] == 0
        assert risk["total_findings"] == 0

    def test_categorize_findings(self):
        """Test finding categorization and sorting."""
        from report_generator import ReportGenerator
        gen = ReportGenerator(config={}, output_dir=".")

        all_findings = {
            "Web": [
                {"type": "XSS", "severity": "High"},
            ],
            "CVE": [
                {"type": "CVE-2023-1234", "severity": "Critical"},
                {"type": "CVE-2023-5678", "severity": "Low"},
            ],
        }

        flat = gen._categorize_findings(all_findings)
        assert len(flat) == 3
        # Critical should be first
        assert flat[0]["severity"] == "Critical"
        assert flat[1]["severity"] == "High"
        assert flat[2]["severity"] == "Low"

    def test_generate_json(self, tmp_path):
        """Test JSON report generation."""
        from report_generator import ReportGenerator
        config = {
            "company_name": "Test Report",
            "author": "Tester",
            "template_path": "./templates/report.html",
        }
        gen = ReportGenerator(config=config, output_dir=str(tmp_path))

        all_findings = {
            "Test Module": [
                {
                    "type": "Test Finding",
                    "severity": "Medium",
                    "description": "Test description",
                }
            ]
        }

        json_path = gen.generate_json(
            target="127.0.0.1",
            all_findings=all_findings,
            port_results=[],
            service_results=[],
            scan_duration=10.5,
        )

        assert os.path.exists(json_path)

        with open(json_path) as f:
            data = json.load(f)

        assert data["metadata"]["target"] == "127.0.0.1"
        assert data["risk_assessment"]["total_findings"] == 1
        assert len(data["findings"]) == 1

    def test_generate_html(self, tmp_path):
        """Test HTML report generation."""
        from report_generator import ReportGenerator

        # Create a minimal template for testing
        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        template_file = template_dir / "report.html"
        template_file.write_text(
            "<html><body>"
            "<h1>{{ title }}</h1>"
            "<p>Target: {{ target }}</p>"
            "<p>Findings: {{ total_findings }}</p>"
            "<p>Risk: {{ risk_level }}</p>"
            "{% for f in findings %}"
            "<div>{{ f.type }} - {{ f.severity }}</div>"
            "{% endfor %}"
            "</body></html>"
        )

        config = {
            "company_name": "Test Report",
            "author": "Tester",
            "template_path": str(template_file),
        }
        gen = ReportGenerator(config=config, output_dir=str(tmp_path))

        all_findings = {
            "Module": [
                {"type": "SQLi", "severity": "Critical", "description": "Test"},
            ]
        }

        html_path = gen.generate_html(
            target="127.0.0.1",
            all_findings=all_findings,
            port_results=[],
            service_results=[],
            scan_duration=5.0,
        )

        assert os.path.exists(html_path)
        content = open(html_path).read()
        assert "Test Report" in content
        assert "127.0.0.1" in content
        assert "CRITICAL" in content

    def test_generate_csv(self, tmp_path):
        """Test CSV report generation."""
        from report_generator import ReportGenerator
        gen = ReportGenerator(config={}, output_dir=str(tmp_path))

        all_findings = {
            "Web Module": [
                {
                    "type": "SQL Injection",
                    "severity": "Critical",
                    "target": "http://127.0.0.1/search",
                    "evidence": "SQL syntax error",
                    "description": "SQLi discovered",
                    "remediation": "Use prepared statements",
                }
            ]
        }

        csv_path = gen.generate_csv(
            target="127.0.0.1",
            all_findings=all_findings,
            port_results=[],
            service_results=[],
            scan_duration=2.5,
        )

        assert os.path.exists(csv_path)
        content = open(csv_path, encoding="utf-8").read()
        assert "Module,Type,Severity,Target,Evidence,Description,Remediation" in content
        assert "SQL Injection" in content
        assert "Critical" in content

    def test_generate_sarif(self, tmp_path):
        """Test SARIF v2.1.0 report generation."""
        from report_generator import ReportGenerator
        gen = ReportGenerator(config={}, output_dir=str(tmp_path))

        all_findings = {
            "CVE Module": [
                {
                    "type": "CVE Vulnerability",
                    "cve_id": "CVE-2024-6387",
                    "severity": "Critical",
                    "target": "127.0.0.1:22",
                    "evidence": "OpenSSH 9.5",
                    "description": "RegreSSHion RCE",
                    "remediation": "Upgrade OpenSSH",
                }
            ]
        }

        sarif_path = gen.generate_sarif(
            target="127.0.0.1",
            all_findings=all_findings,
            port_results=[],
            service_results=[],
            scan_duration=1.2,
        )

        assert os.path.exists(sarif_path)
        with open(sarif_path, encoding="utf-8") as f:
            sarif = json.load(f)

        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "VulnScanner"
        assert len(sarif["runs"][0]["results"]) == 1
        assert sarif["runs"][0]["results"][0]["ruleId"] == "CVE-2024-6387"


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests combining multiple modules."""

    def test_full_pipeline_with_mocks(
        self, service_detector_config, sample_port_results, sample_cve_db, tmp_path
    ):
        """
        Test the full pipeline: port results -> service detection -> CVE matching.
        Uses sample data (no actual network calls).
        """
        from scanner.service_detector import ServiceDetector
        from cve_matcher import CVEMatcher
        from report_generator import ReportGenerator

        # Step 1: Detect services from sample port results
        detector = ServiceDetector(config=service_detector_config)
        service_results = detector.analyze_ports(sample_port_results)
        assert len(service_results) == 4

        # Step 2: Match against CVE database
        matcher = CVEMatcher(cve_db_path=sample_cve_db)
        matchable = detector.get_services_for_cve_matching()
        cve_findings = matcher.match_all(matchable)

        # We should find CVEs for OpenSSH 9.1, Apache 2.4.52, vsftpd 3.0.3
        assert len(cve_findings) >= 3

        # Step 3: Generate JSON report
        all_findings = {"CVE Vulnerabilities": cve_findings}

        # Create temp template
        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        (template_dir / "report.html").write_text(
            "<html>{{ total_findings }} findings</html>"
        )

        config = {
            "company_name": "Integration Test",
            "author": "Test",
            "template_path": str(template_dir / "report.html"),
        }
        gen = ReportGenerator(config=config, output_dir=str(tmp_path))
        json_path = gen.generate_json(
            target="127.0.0.1",
            all_findings=all_findings,
            port_results=sample_port_results,
            service_results=service_results,
            scan_duration=1.0,
        )
        assert os.path.exists(json_path)

        # Verify JSON content
        with open(json_path) as f:
            report_data = json.load(f)
        assert report_data["risk_assessment"]["total_findings"] >= 3
        assert len(report_data["open_ports"]) == 4


# ============================================================================
# Configuration Tests
# ============================================================================

class TestConfiguration:
    """Tests for configuration loading and validation."""

    def test_load_valid_config(self, tmp_path):
        """Test loading a valid YAML config file."""
        config_content = """
general:
  default_threads: 10
  timeout: 5
port_scanner:
  default_ports: [22, 80, 443]
  scan_type: connect
"""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(config_content)

        import yaml
        with open(config_file) as f:
            config = yaml.safe_load(f)

        assert config["general"]["default_threads"] == 10
        assert config["port_scanner"]["scan_type"] == "connect"
