"""
scanner/web_scanner.py
=======================
Web Vulnerability Scanner Module.
Tests HTTP/HTTPS targets for common web vulnerabilities:
  - SQL Injection (SQLi)
  - Cross-Site Scripting (XSS)
  - Open Redirects
  - Directory Traversal / Path Traversal
  - Sensitive directory/file discovery

LEGAL DISCLAIMER: Only use against systems you own or have explicit
written authorization to test.
"""

import re
import time
import logging
import urllib.parse
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError

logger = logging.getLogger(__name__)

# Suppress noisy SSL warnings for self-signed cert targets
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


class WebScanner:
    """
    Scans HTTP/HTTPS targets for common web application vulnerabilities.
    Supports SQLi, XSS, open redirect, and directory traversal detection.
    """

    def __init__(self, config: dict, threads: int = 10):
        """
        Initialize the web vulnerability scanner.

        Args:
            config: Web scanner configuration dictionary.
            threads: Number of concurrent testing threads.
        """
        self.config = config
        self.threads = threads
        self.user_agent = config.get("user_agent", "VulnScanner/1.0 (Security Audit)")
        self.request_delay = config.get("request_delay", 0.5)
        self.follow_redirects = config.get("follow_redirects", False)
        self.timeout = config.get("timeout", 10)

        # Load payloads from config
        self.sqli_payloads = config.get("sqli_payloads", [])
        self.sqli_errors = config.get("sqli_errors", [])
        self.xss_payloads = config.get("xss_payloads", [])
        self.redirect_payloads = config.get("redirect_payloads", [])
        self.traversal_payloads = config.get("traversal_payloads", [])
        self.common_dirs = config.get("common_dirs", [])

        self.results = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        self.session.verify = False  # Allow self-signed certs during scan

    def _build_base_url(self, ip: str, port: int) -> str:
        """
        Build the base URL for a target based on port number.

        Args:
            ip: Target IP or domain.
            port: Target port.

        Returns:
            Base URL string (http:// or https://).
        """
        scheme = "https" if port in (443, 8443) else "http"
        if port in (80, 443):
            return f"{scheme}://{ip}"
        return f"{scheme}://{ip}:{port}"

    def _make_request(
        self, url: str, method: str = "GET", data: Optional[dict] = None
    ) -> Optional[requests.Response]:
        """
        Make an HTTP request with error handling and rate limiting.

        Args:
            url: Full URL to request.
            method: HTTP method (GET/POST).
            data: POST data dictionary.

        Returns:
            Response object or None on failure.
        """
        time.sleep(self.request_delay)
        try:
            if method.upper() == "POST":
                resp = self.session.post(
                    url,
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                )
            else:
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                )
            return resp
        except Timeout:
            logger.debug(f"Request timeout: {url}")
        except ConnectionError:
            logger.debug(f"Connection refused: {url}")
        except RequestException as e:
            logger.debug(f"Request error for {url}: {e}")
        return None

    def _discover_params(self, base_url: str) -> list[dict]:
        """
        Discover injectable parameters by crawling the target homepage.
        Finds form inputs and URL query parameters.

        Args:
            base_url: Base URL of the target.

        Returns:
            List of dicts with 'url', 'param', 'method' keys.
        """
        params = []
        resp = self._make_request(base_url)
        if not resp:
            return params

        body = resp.text

        # Extract form actions and inputs
        form_pattern = re.compile(
            r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*method=["\']?(\w+)["\']?',
            re.IGNORECASE,
        )
        input_pattern = re.compile(
            r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?', re.IGNORECASE
        )

        for form_match in form_pattern.finditer(body):
            action = form_match.group(1)
            method = form_match.group(2).upper()
            action_url = urllib.parse.urljoin(base_url, action) if action else base_url

            # Find inputs within this form region (approximate)
            form_start = form_match.start()
            form_end = body.find("</form>", form_start)
            if form_end == -1:
                form_end = len(body)
            form_html = body[form_start:form_end]

            for input_match in input_pattern.finditer(form_html):
                param_name = input_match.group(1)
                params.append(
                    {"url": action_url, "param": param_name, "method": method}
                )

        # Also extract URL query parameters from links
        link_pattern = re.compile(r'href=["\']?([^"\'>\s]+\?[^"\'>\s]+)', re.IGNORECASE)
        for link_match in link_pattern.finditer(body):
            link_url = urllib.parse.urljoin(base_url, link_match.group(1))
            parsed = urllib.parse.urlparse(link_url)
            query_params = urllib.parse.parse_qs(parsed.query)
            for param_name in query_params:
                params.append({"url": link_url, "param": param_name, "method": "GET"})

        # If no parameters found, test with common parameter names
        if not params:
            common_params = ["id", "q", "search", "page", "url", "redirect", "file", "path"]
            for param in common_params:
                params.append({"url": base_url, "param": param, "method": "GET"})

        logger.info(f"  Discovered {len(params)} injectable parameter(s)")
        return params

    def test_sqli(self, base_url: str, params: list[dict]) -> list[dict]:
        """
        Test for SQL Injection vulnerabilities using error-based detection.

        Args:
            base_url: Base URL of the target.
            params: List of discovered parameters to test.

        Returns:
            List of SQLi finding dictionaries.
        """
        findings = []
        logger.info(f"  Testing SQLi on {base_url}...")

        for param_info in params:
            url = param_info["url"]
            param = param_info["param"]
            method = param_info["method"]

            for payload in self.sqli_payloads:
                if method == "GET":
                    # Inject payload into URL parameter
                    parsed = urllib.parse.urlparse(url)
                    query_params = urllib.parse.parse_qs(parsed.query)
                    query_params[param] = [payload]
                    new_query = urllib.parse.urlencode(query_params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    resp = self._make_request(test_url)
                else:
                    data = {param: payload}
                    resp = self._make_request(url, method="POST", data=data)

                if resp is None:
                    continue

                # Check for time-based blind SQLi if delay payload was sent
                if "delay" in payload.lower() or "sleep" in payload.lower():
                    elapsed = getattr(resp, "elapsed", None)
                    duration = elapsed.total_seconds() if elapsed else 0
                    if duration >= 4.5:
                        finding = {
                            "type": "SQL Injection (Time-Based Blind)",
                            "severity": "Critical",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": f"Response delayed by {duration:.2f}s",
                            "method": method,
                            "description": (
                                f"Time-based blind SQL injection detected in parameter '{param}'. "
                                f"Target response was delayed significantly ({duration:.2f}s)."
                            ),
                            "remediation": (
                                "Use parameterized queries (prepared statements). "
                                "Never concatenate user input directly into SQL queries."
                            ),
                        }
                        findings.append(finding)
                        logger.warning(
                            f"    [!] Blind SQLi (delay) found: {url} param='{param}' ({duration:.2f}s)"
                        )
                        break

                # Check response for SQL error indicators
                response_lower = resp.text.lower()
                for error_sig in self.sqli_errors:
                    if error_sig.lower() in response_lower:
                        finding = {
                            "type": "SQL Injection",
                            "severity": "Critical",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "evidence": error_sig,
                            "method": method,
                            "description": (
                                f"Potential SQL injection detected in parameter "
                                f"'{param}'. The application returned a database "
                                f"error matching signature: '{error_sig}'"
                            ),
                            "remediation": (
                                "Use parameterized queries (prepared statements). "
                                "Implement input validation and sanitization. "
                                "Apply the principle of least privilege to DB accounts."
                            ),
                        }
                        findings.append(finding)
                        logger.warning(
                            f"    [!] SQLi found: {url} param='{param}' "
                            f"payload='{payload}'"
                        )
                        break  # One match per payload is enough

        return findings

    def test_xss(self, base_url: str, params: list[dict]) -> list[dict]:
        """
        Test for reflected Cross-Site Scripting (XSS) vulnerabilities.

        Args:
            base_url: Base URL of the target.
            params: List of discovered parameters.

        Returns:
            List of XSS finding dictionaries.
        """
        findings = []
        logger.info(f"  Testing XSS on {base_url}...")

        for param_info in params:
            url = param_info["url"]
            param = param_info["param"]
            method = param_info["method"]

            for payload in self.xss_payloads:
                if method == "GET":
                    parsed = urllib.parse.urlparse(url)
                    query_params = urllib.parse.parse_qs(parsed.query)
                    query_params[param] = [payload]
                    new_query = urllib.parse.urlencode(query_params, doseq=True)
                    test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                    resp = self._make_request(test_url)
                else:
                    data = {param: payload}
                    resp = self._make_request(url, method="POST", data=data)

                if resp is None:
                    continue

                # Check if the XSS payload is reflected unescaped in response
                if payload in resp.text:
                    finding = {
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "High",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": f"Payload reflected in response body",
                        "method": method,
                        "description": (
                            f"Reflected XSS vulnerability detected. The payload "
                            f"'{payload}' was reflected unescaped in the HTTP "
                            f"response for parameter '{param}'."
                        ),
                        "remediation": (
                            "Implement output encoding/escaping. Use Content "
                            "Security Policy (CSP) headers. Validate and sanitize "
                            "all user inputs on the server side."
                        ),
                    }
                    findings.append(finding)
                    logger.warning(
                        f"    [!] XSS found: {url} param='{param}'"
                    )
                    break  # One proof per parameter is sufficient

        return findings

    def test_open_redirect(self, base_url: str, params: list[dict]) -> list[dict]:
        """
        Test for open redirect vulnerabilities.

        Args:
            base_url: Base URL of the target.
            params: List of discovered parameters.

        Returns:
            List of open redirect finding dictionaries.
        """
        findings = []
        logger.info(f"  Testing open redirects on {base_url}...")

        # Only test parameters that look like redirect candidates
        redirect_param_names = {"url", "redirect", "next", "return", "goto",
                                "dest", "destination", "redir", "return_url",
                                "redirect_uri", "continue", "target"}

        for param_info in params:
            param = param_info["param"].lower()
            url = param_info["url"]

            # Skip params unlikely to be redirect targets
            if param not in redirect_param_names and "url" not in param and "redirect" not in param:
                continue

            for payload in self.redirect_payloads:
                parsed = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed.query)
                query_params[param_info["param"]] = [payload]
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                # Allow redirects to see where it goes
                try:
                    resp = self.session.get(
                        test_url,
                        timeout=self.timeout,
                        allow_redirects=True,
                        verify=False,
                    )
                    time.sleep(self.request_delay)

                    # Check if we were redirected to an external domain
                    final_url = resp.url
                    if "evil.com" in final_url:
                        finding = {
                            "type": "Open Redirect",
                            "severity": "Medium",
                            "url": url,
                            "parameter": param_info["param"],
                            "payload": payload,
                            "evidence": f"Redirected to: {final_url}",
                            "method": "GET",
                            "description": (
                                f"Open redirect vulnerability detected. The "
                                f"parameter '{param_info['param']}' accepts "
                                f"external URLs, redirecting users to "
                                f"attacker-controlled sites."
                            ),
                            "remediation": (
                                "Use a whitelist of allowed redirect URLs. "
                                "Avoid using user input for redirect targets. "
                                "Implement server-side redirect validation."
                            ),
                        }
                        findings.append(finding)
                        logger.warning(
                            f"    [!] Open redirect: {url} param='{param_info['param']}'"
                        )
                        break

                    # Also check for redirect in Location header (3xx without following)
                    if resp.history:
                        for hist_resp in resp.history:
                            location = hist_resp.headers.get("Location", "")
                            if "evil.com" in location:
                                finding = {
                                    "type": "Open Redirect",
                                    "severity": "Medium",
                                    "url": url,
                                    "parameter": param_info["param"],
                                    "payload": payload,
                                    "evidence": f"Location header: {location}",
                                    "method": "GET",
                                    "description": (
                                        f"Open redirect via Location header. "
                                        f"Parameter '{param_info['param']}' used "
                                        f"in redirect target."
                                    ),
                                    "remediation": (
                                        "Use a whitelist of allowed redirect URLs. "
                                        "Validate redirect targets server-side."
                                    ),
                                }
                                findings.append(finding)
                                break

                except RequestException:
                    continue

        return findings

    def test_directory_traversal(self, base_url: str, params: list[dict]) -> list[dict]:
        """
        Test for directory traversal / path traversal vulnerabilities.

        Args:
            base_url: Base URL of the target.
            params: List of discovered parameters.

        Returns:
            List of directory traversal finding dictionaries.
        """
        findings = []
        logger.info(f"  Testing directory traversal on {base_url}...")

        # Indicators of successful traversal
        traversal_indicators = [
            "root:x:0:0",           # /etc/passwd content
            "[boot loader]",         # Windows boot.ini
            "[fonts]",               # Windows win.ini
            "# localhost",           # hosts file
            "127.0.0.1",             # hosts file
        ]

        # Test parameters likely to accept file paths
        file_param_names = {"file", "path", "page", "include", "doc",
                            "document", "folder", "root", "dir", "template",
                            "filename", "filepath", "load", "read"}

        for param_info in params:
            param_lower = param_info["param"].lower()
            url = param_info["url"]

            if param_lower not in file_param_names and "file" not in param_lower and "path" not in param_lower:
                continue

            for payload in self.traversal_payloads:
                parsed = urllib.parse.urlparse(url)
                query_params = urllib.parse.parse_qs(parsed.query)
                query_params[param_info["param"]] = [payload]
                new_query = urllib.parse.urlencode(query_params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                resp = self._make_request(test_url)
                if resp is None:
                    continue

                response_text = resp.text
                for indicator in traversal_indicators:
                    if indicator in response_text:
                        finding = {
                            "type": "Directory Traversal",
                            "severity": "Critical",
                            "url": url,
                            "parameter": param_info["param"],
                            "payload": payload,
                            "evidence": f"Found '{indicator}' in response",
                            "method": "GET",
                            "description": (
                                f"Directory traversal vulnerability detected. "
                                f"The parameter '{param_info['param']}' allows "
                                f"reading arbitrary files from the server."
                            ),
                            "remediation": (
                                "Sanitize file path inputs. Use a whitelist of "
                                "allowed files. Implement chroot/jail. Never pass "
                                "user input directly to file system functions."
                            ),
                        }
                        findings.append(finding)
                        logger.warning(
                            f"    [!] Path traversal: {url} param='{param_info['param']}'"
                        )
                        break

        return findings

    def discover_directories(self, base_url: str) -> list[dict]:
        """
        Brute-force common sensitive directories and files.

        Args:
            base_url: Base URL of the target.

        Returns:
            List of directory discovery finding dictionaries.
        """
        findings = []
        logger.info(f"  Discovering sensitive directories on {base_url}...")

        def check_dir(path: str) -> Optional[dict]:
            url = f"{base_url}{path}"
            resp = self._make_request(url)
            if resp and resp.status_code in (200, 301, 302, 403):
                severity = "Info"
                description = f"Directory/file '{path}' exists (HTTP {resp.status_code})."

                # Elevate severity for particularly sensitive findings
                if path in ("/.git", "/.env", "/backup", "/config"):
                    severity = "High"
                    description = (
                        f"Sensitive path '{path}' is accessible "
                        f"(HTTP {resp.status_code}). This may expose "
                        f"source code, secrets, or configuration data."
                    )
                elif path in ("/phpmyadmin", "/server-status", "/server-info"):
                    severity = "Medium"
                    description = (
                        f"Administrative interface '{path}' found "
                        f"(HTTP {resp.status_code})."
                    )

                return {
                    "type": "Directory Discovery",
                    "severity": severity,
                    "url": url,
                    "parameter": "N/A",
                    "payload": path,
                    "evidence": f"HTTP {resp.status_code} ({len(resp.text)} bytes)",
                    "method": "GET",
                    "description": description,
                    "remediation": (
                        "Restrict access to sensitive paths. Remove unnecessary "
                        "files and directories. Use proper access controls."
                    ),
                }
            return None

        # Use threading for directory brute-forcing
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(check_dir, path): path
                for path in self.common_dirs
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
                    logger.info(
                        f"    Found: {futures[future]} "
                        f"({result['evidence']})"
                    )

        return findings

    def check_security_headers(self, base_url: str) -> list[dict]:
        """
        Check for missing or misconfigured HTTP security headers.

        Args:
            base_url: Base URL of the target.

        Returns:
            List of security header findings.
        """
        findings = []
        resp = self._make_request(base_url)
        if not resp:
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # 1. Content-Security-Policy (CSP)
        if "content-security-policy" not in headers:
            findings.append({
                "type": "Missing Security Header - CSP",
                "severity": "Medium",
                "url": base_url,
                "parameter": "N/A",
                "payload": "Content-Security-Policy",
                "evidence": "Header not present",
                "method": "GET",
                "description": (
                    "Content-Security-Policy (CSP) header is missing. CSP helps prevent "
                    "Cross-Site Scripting (XSS) and data injection attacks by restricting "
                    "resources that the browser is allowed to load."
                ),
                "remediation": "Define and enforce a restrictive Content-Security-Policy header.",
            })

        # 2. Strict-Transport-Security (HSTS) - on HTTPS
        if base_url.startswith("https://") and "strict-transport-security" not in headers:
            findings.append({
                "type": "Missing Security Header - HSTS",
                "severity": "Medium",
                "url": base_url,
                "parameter": "N/A",
                "payload": "Strict-Transport-Security",
                "evidence": "Header not present on HTTPS",
                "method": "GET",
                "description": (
                    "HTTP Strict Transport Security (HSTS) header is missing. "
                    "HSTS ensures browsers only connect via HTTPS, preventing SSL-stripping attacks."
                ),
                "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
            })

        # 3. X-Frame-Options (Clickjacking)
        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            findings.append({
                "type": "Missing Security Header - X-Frame-Options",
                "severity": "Low",
                "url": base_url,
                "parameter": "N/A",
                "payload": "X-Frame-Options",
                "evidence": "Header not present",
                "method": "GET",
                "description": (
                    "X-Frame-Options header is missing. The site may be vulnerable to clickjacking "
                    "if framed in malicious pages."
                ),
                "remediation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'.",
            })

        # 4. X-Content-Type-Options
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append({
                "type": "Missing Security Header - X-Content-Type-Options",
                "severity": "Low",
                "url": base_url,
                "parameter": "N/A",
                "payload": "X-Content-Type-Options",
                "evidence": f"Current value: {headers.get('x-content-type-options', 'missing')}",
                "method": "GET",
                "description": (
                    "X-Content-Type-Options header is missing or not set to 'nosniff'. "
                    "This allows MIME-type sniffing which can lead to script execution."
                ),
                "remediation": "Add 'X-Content-Type-Options: nosniff'.",
            })

        return findings

    def check_cors(self, base_url: str) -> list[dict]:
        """
        Check for insecure Cross-Origin Resource Sharing (CORS) configurations.

        Args:
            base_url: Base URL of the target.

        Returns:
            List of CORS misconfiguration findings.
        """
        findings = []
        try:
            evil_origin = "https://evil.com"
            headers = {"Origin": evil_origin}
            resp = self.session.get(base_url, headers=headers, timeout=self.timeout, verify=False)
            allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
            allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

            if allow_origin == "*" and allow_creds:
                findings.append({
                    "type": "Insecure CORS Configuration",
                    "severity": "Critical",
                    "url": base_url,
                    "parameter": "Origin",
                    "payload": evil_origin,
                    "evidence": "Access-Control-Allow-Origin: * with Allow-Credentials: true",
                    "method": "GET",
                    "description": (
                        "Wildcard Access-Control-Allow-Origin is configured alongside "
                        "Access-Control-Allow-Credentials: true, exposing authenticated data cross-origin."
                    ),
                    "remediation": "Restrict Access-Control-Allow-Origin to trusted domains and avoid wildcards with credentials.",
                })
            elif evil_origin in allow_origin and allow_creds:
                findings.append({
                    "type": "CORS Arbitrary Origin Reflection",
                    "severity": "High",
                    "url": base_url,
                    "parameter": "Origin",
                    "payload": evil_origin,
                    "evidence": f"Reflected Origin {allow_origin} with credentials allowed",
                    "method": "GET",
                    "description": (
                        "The application reflects arbitrary untrusted Origins and permits credentials, "
                        "enabling cross-origin data theft of authenticated sessions."
                    ),
                    "remediation": "Validate the Origin header against a strict server-side whitelist.",
                })
        except Exception:
            pass

        return findings

    def check_cookies(self, base_url: str) -> list[dict]:
        """
        Check session/auth cookies for missing Secure, HttpOnly, and SameSite attributes.

        Args:
            base_url: Base URL of the target.

        Returns:
            List of cookie security findings.
        """
        findings = []
        resp = self._make_request(base_url)
        if not resp or not resp.cookies:
            return findings

        for cookie in resp.cookies:
            missing_flags = []
            if not cookie.secure and base_url.startswith("https://"):
                missing_flags.append("Secure")
            if not getattr(cookie, "_rest", {}).get("HttpOnly") and not cookie.has_nonstandard_attr("HttpOnly"):
                missing_flags.append("HttpOnly")

            if missing_flags:
                findings.append({
                    "type": "Insecure Cookie Flags",
                    "severity": "Low",
                    "url": base_url,
                    "parameter": cookie.name,
                    "payload": cookie.name,
                    "evidence": f"Cookie '{cookie.name}' missing flags: {', '.join(missing_flags)}",
                    "method": "GET",
                    "description": (
                        f"Cookie '{cookie.name}' was set without {', '.join(missing_flags)} flags. "
                        "Missing HttpOnly permits JavaScript access (XSS risk); missing Secure transmits cookies over plaintext."
                    ),
                    "remediation": "Set Secure, HttpOnly, and SameSite=Lax/Strict flags on all sensitive cookies.",
                })

        return findings

    def scan(self, target: str, port_results: list[dict]) -> list[dict]:
        """
        Run all web vulnerability tests against HTTP/HTTPS targets.

        Args:
            target: Original target string.
            port_results: List of open ports from the port scanner.

        Returns:
            List of all web vulnerability findings.
        """
        self.results = []

        # Identify HTTP/HTTPS ports from scan results
        http_ports = []
        for port_info in port_results:
            port = port_info.get("port", 0)
            service = port_info.get("service", "").lower()
            if port in (80, 443, 8080, 8443, 8888, 9090) or "http" in service:
                http_ports.append(port_info)

        if not http_ports:
            logger.info("No HTTP services found. Skipping web scan.")
            return self.results

        logger.info(f"Starting web vulnerability scan on {len(http_ports)} HTTP service(s)...")

        for port_info in http_ports:
            ip = port_info.get("ip", target)
            port = port_info.get("port", 80)
            base_url = self._build_base_url(ip, port)

            logger.info(f"Scanning: {base_url}")

            # Verify connectivity
            resp = self._make_request(base_url)
            if resp is None:
                logger.warning(f"  Cannot reach {base_url}. Skipping.")
                continue

            # Check Security Headers, CORS, and Cookies
            self.results.extend(self.check_security_headers(base_url))
            self.results.extend(self.check_cors(base_url))
            self.results.extend(self.check_cookies(base_url))

            # Discover injectable parameters
            params = self._discover_params(base_url)

            # Run all parameter & path-based web vulnerability tests
            self.results.extend(self.test_sqli(base_url, params))
            self.results.extend(self.test_xss(base_url, params))
            self.results.extend(self.test_open_redirect(base_url, params))
            self.results.extend(self.test_directory_traversal(base_url, params))
            self.results.extend(self.discover_directories(base_url))

        logger.info(
            f"Web scan complete. {len(self.results)} finding(s) identified."
        )
        return self.results
