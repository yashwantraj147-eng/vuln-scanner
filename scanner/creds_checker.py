"""
scanner/creds_checker.py
=========================
Default Credentials Checker Module.
Tests common services for default/weak credentials:
  - SSH (via paramiko)
  - FTP (via ftplib)
  - Telnet (via telnetlib)
  - HTTP admin panels (via requests)

LEGAL DISCLAIMER: Only use against systems you own or have explicit
written authorization to test. Attempting to log in to systems without
authorization is illegal and unethical.
"""

import ftplib
import logging
import socket
import time

# telnetlib was removed in Python 3.13+
try:
    import telnetlib
    TELNETLIB_AVAILABLE = True
except ImportError:
    TELNETLIB_AVAILABLE = False
    logging.getLogger(__name__).warning(
        "telnetlib not available (removed in Python 3.13+). "
        "Telnet credential checking disabled."
    )
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

logger = logging.getLogger(__name__)

# Import paramiko for SSH credential testing
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    logger.warning("Paramiko not available. SSH credential checking disabled.")


class CredsChecker:
    """
    Tests common services (SSH, FTP, Telnet, HTTP) for default
    and commonly-used credentials.
    """

    def __init__(self, config: dict, threads: int = 5):
        """
        Initialize the credentials checker.

        Args:
            config: Credentials checker configuration dictionary.
            threads: Number of concurrent testing threads.
        """
        self.config = config
        self.threads = threads
        self.timeout = config.get("timeout", 5)
        self.ssh_creds = config.get("ssh_creds", [])
        self.ftp_creds = config.get("ftp_creds", [])
        self.telnet_creds = config.get("telnet_creds", [])
        self.http_creds = config.get("http_creds", [])
        self.http_login_paths = config.get("http_login_paths", [])
        self.results = []

    def _check_ssh(self, ip: str, port: int, username: str, password: str) -> Optional[dict]:
        """
        Attempt SSH login with given credentials.

        Args:
            ip: Target IP address.
            port: SSH port (usually 22).
            username: Username to try.
            password: Password to try.

        Returns:
            Finding dictionary if login succeeds, None otherwise.
        """
        if not PARAMIKO_AVAILABLE:
            return None

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                ip,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=self.timeout,
            )
            # Login successful — this is a critical finding
            logger.warning(f"    [!] SSH login success: {ip}:{port} {username}:{password}")
            return {
                "type": "Default Credentials - SSH",
                "severity": "Critical",
                "target": f"{ip}:{port}",
                "evidence": f"Successful login with {username}:{password}",
                "service": "SSH",
                "username": username,
                "password": password,
                "description": (
                    f"SSH service at {ip}:{port} accepts default credentials "
                    f"'{username}:{password}'. This allows unauthorized remote "
                    f"access with potential full system compromise."
                ),
                "remediation": (
                    "Change the password immediately. Disable password-based "
                    "SSH authentication and use key-based auth instead. "
                    "Implement fail2ban or similar brute-force protection."
                ),
            }
        except paramiko.AuthenticationException:
            # Invalid credentials — expected
            logger.debug(f"    SSH auth failed: {ip}:{port} {username}:***")
        except (paramiko.SSHException, socket.timeout, OSError) as e:
            logger.debug(f"    SSH connection error {ip}:{port}: {e}")
        finally:
            client.close()

        return None

    def _check_ftp(self, ip: str, port: int, username: str, password: str) -> Optional[dict]:
        """
        Attempt FTP login with given credentials.

        Args:
            ip: Target IP address.
            port: FTP port (usually 21).
            username: Username to try.
            password: Password to try.

        Returns:
            Finding dictionary if login succeeds, None otherwise.
        """
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=self.timeout)
            ftp.login(username, password)

            # Login successful
            # Try to get directory listing as extra evidence
            try:
                dir_listing = ftp.nlst()
                files_info = f", {len(dir_listing)} files visible"
            except ftplib.error_perm:
                files_info = ""

            ftp.quit()

            cred_display = f"{username}:{password}" if password else f"{username}:(anonymous)"
            logger.warning(f"    [!] FTP login success: {ip}:{port} {cred_display}")

            severity = "High" if username == "anonymous" else "Critical"
            return {
                "type": "Default Credentials - FTP",
                "severity": severity,
                "target": f"{ip}:{port}",
                "evidence": f"Successful login with {cred_display}{files_info}",
                "service": "FTP",
                "username": username,
                "password": password,
                "description": (
                    f"FTP service at {ip}:{port} accepts credentials "
                    f"'{cred_display}'. "
                    + (
                        "Anonymous FTP access is enabled, potentially exposing sensitive files."
                        if username == "anonymous"
                        else "Default credentials allow unauthorized file access."
                    )
                ),
                "remediation": (
                    "Disable anonymous FTP access if not needed. Change default "
                    "passwords. Consider using SFTP instead of plain FTP. "
                    "Restrict FTP access with firewall rules."
                ),
            }
        except ftplib.error_perm:
            logger.debug(f"    FTP auth failed: {ip}:{port} {username}:***")
        except (socket.timeout, OSError, EOFError) as e:
            logger.debug(f"    FTP connection error {ip}:{port}: {e}")

        return None

    def _check_telnet(self, ip: str, port: int, username: str, password: str) -> Optional[dict]:
        """
        Attempt Telnet login with given credentials.

        Args:
            ip: Target IP address.
            port: Telnet port (usually 23).
            username: Username to try.
            password: Password to try.

        Returns:
            Finding dictionary if login succeeds, None otherwise.
        """
        if not TELNETLIB_AVAILABLE:
            return None
        try:
            tn = telnetlib.Telnet(ip, port, timeout=self.timeout)

            # Wait for login prompt
            response = tn.read_until(b"login: ", timeout=self.timeout)
            if b"login" not in response.lower():
                # Try waiting for alternative prompts
                response = tn.read_until(b"Username: ", timeout=self.timeout)

            # Send username
            tn.write(username.encode() + b"\n")
            time.sleep(0.5)

            # Wait for password prompt
            response = tn.read_until(b"Password: ", timeout=self.timeout)
            if b"password" not in response.lower() and b"assword" not in response:
                tn.close()
                return None

            # Send password
            tn.write(password.encode() + b"\n")
            time.sleep(1)

            # Check response for success indicators
            response = tn.read_very_eager().decode("utf-8", errors="replace")
            tn.close()

            # Common failure indicators
            failure_indicators = [
                "login incorrect",
                "access denied",
                "authentication failed",
                "invalid",
                "bad password",
                "login failed",
            ]

            response_lower = response.lower()
            for indicator in failure_indicators:
                if indicator in response_lower:
                    return None

            # Common success indicators
            success_indicators = ["$", "#", ">", "welcome", "last login", "shell"]
            for indicator in success_indicators:
                if indicator in response_lower:
                    logger.warning(
                        f"    [!] Telnet login success: {ip}:{port} "
                        f"{username}:{password}"
                    )
                    return {
                        "type": "Default Credentials - Telnet",
                        "severity": "Critical",
                        "target": f"{ip}:{port}",
                        "evidence": f"Successful login with {username}:{password}",
                        "service": "Telnet",
                        "username": username,
                        "password": password,
                        "description": (
                            f"Telnet service at {ip}:{port} accepts default "
                            f"credentials '{username}:{password}'. Telnet "
                            f"transmits credentials in cleartext, making this "
                            f"doubly dangerous."
                        ),
                        "remediation": (
                            "Disable Telnet entirely and use SSH instead. "
                            "If Telnet must remain, change all default "
                            "credentials and restrict access via firewall."
                        ),
                    }

        except (socket.timeout, ConnectionRefusedError, OSError, EOFError) as e:
            logger.debug(f"    Telnet error {ip}:{port}: {e}")

        return None

    def _check_http(self, ip: str, port: int, username: str, password: str) -> Optional[dict]:
        """
        Attempt HTTP Basic/Form authentication with given credentials.

        Args:
            ip: Target IP address.
            port: HTTP port.
            username: Username to try.
            password: Password to try.

        Returns:
            Finding dictionary if login succeeds, None otherwise.
        """
        scheme = "https" if port in (443, 8443) else "http"
        base_url = f"{scheme}://{ip}" if port in (80, 443) else f"{scheme}://{ip}:{port}"

        for login_path in self.http_login_paths:
            url = f"{base_url}{login_path}"

            try:
                # Test 1: HTTP Basic Authentication
                resp = requests.get(
                    url,
                    auth=(username, password),
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )

                if resp.status_code == 200:
                    # Check if we actually got past authentication
                    # (not just a public 200 page)
                    unauth_resp = requests.get(
                        url, timeout=self.timeout, verify=False
                    )
                    if unauth_resp.status_code == 401:
                        logger.warning(
                            f"    [!] HTTP Basic Auth success: {url} "
                            f"{username}:{password}"
                        )
                        return {
                            "type": "Default Credentials - HTTP",
                            "severity": "Critical",
                            "target": f"{ip}:{port}",
                            "evidence": (
                                f"HTTP Basic Auth login at {login_path} "
                                f"with {username}:{password}"
                            ),
                            "service": "HTTP",
                            "username": username,
                            "password": password,
                            "url": url,
                            "description": (
                                f"HTTP admin panel at {url} accepts default "
                                f"credentials '{username}:{password}' via HTTP "
                                f"Basic Authentication."
                            ),
                            "remediation": (
                                "Change default admin credentials immediately. "
                                "Implement account lockout after failed attempts. "
                                "Use HTTPS to protect credentials in transit. "
                                "Consider multi-factor authentication."
                            ),
                        }

                # Test 2: Form-based login (POST)
                form_data = {
                    "username": username,
                    "password": password,
                    "user": username,
                    "pass": password,
                    "login": "Login",
                }
                resp = requests.post(
                    url,
                    data=form_data,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )

                # Check for signs of successful login
                resp_lower = resp.text.lower()
                success_signs = [
                    "dashboard",
                    "welcome",
                    "logout",
                    "sign out",
                    "admin panel",
                    "control panel",
                ]
                failure_signs = [
                    "invalid",
                    "incorrect",
                    "failed",
                    "error",
                    "wrong password",
                    "try again",
                ]

                if any(s in resp_lower for s in success_signs) and not any(
                    s in resp_lower for s in failure_signs
                ):
                    logger.warning(
                        f"    [!] HTTP Form login success: {url} "
                        f"{username}:{password}"
                    )
                    return {
                        "type": "Default Credentials - HTTP",
                        "severity": "Critical",
                        "target": f"{ip}:{port}",
                        "evidence": (
                            f"Form login at {login_path} "
                            f"with {username}:{password}"
                        ),
                        "service": "HTTP",
                        "username": username,
                        "password": password,
                        "url": url,
                        "description": (
                            f"Web login at {url} accepts default credentials "
                            f"'{username}:{password}' via form-based login."
                        ),
                        "remediation": (
                            "Change default admin credentials. Implement "
                            "account lockout, CAPTCHA, and rate limiting. "
                            "Use HTTPS and consider MFA."
                        ),
                    }

            except requests.RequestException:
                continue

        return None

    def scan(self, target: str, port_results: list[dict]) -> list[dict]:
        """
        Run default credential checks against all applicable services.

        Args:
            target: Original target string.
            port_results: List of open ports from port scanner.

        Returns:
            List of default credential findings.
        """
        self.results = []

        # Categorize open ports by service type
        ssh_targets = []
        ftp_targets = []
        telnet_targets = []
        http_targets = []

        for port_info in port_results:
            port = port_info.get("port", 0)
            service = port_info.get("service", "").lower()
            ip = port_info.get("ip", target)

            if port == 22 or "ssh" in service:
                ssh_targets.append((ip, port))
            if port == 21 or "ftp" in service:
                ftp_targets.append((ip, port))
            if port == 23 or "telnet" in service:
                telnet_targets.append((ip, port))
            if port in (80, 443, 8080, 8443, 8888, 9090) or "http" in service:
                http_targets.append((ip, port))

        total_tests = (
            len(ssh_targets) * len(self.ssh_creds)
            + len(ftp_targets) * len(self.ftp_creds)
            + len(telnet_targets) * len(self.telnet_creds)
            + len(http_targets) * len(self.http_creds)
        )

        if total_tests == 0:
            logger.info("No applicable services for credential checking.")
            return self.results

        logger.info(
            f"Starting credential checks: {total_tests} combination(s) to test "
            f"(SSH:{len(ssh_targets)}, FTP:{len(ftp_targets)}, "
            f"Telnet:{len(telnet_targets)}, HTTP:{len(http_targets)})"
        )

        # Use thread pool for concurrent testing
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []

            # Queue SSH checks
            for ip, port in ssh_targets:
                for cred in self.ssh_creds:
                    future = executor.submit(
                        self._check_ssh, ip, port,
                        cred["username"], cred["password"]
                    )
                    futures.append(future)

            # Queue FTP checks
            for ip, port in ftp_targets:
                for cred in self.ftp_creds:
                    future = executor.submit(
                        self._check_ftp, ip, port,
                        cred["username"], cred["password"]
                    )
                    futures.append(future)

            # Queue Telnet checks
            for ip, port in telnet_targets:
                for cred in self.telnet_creds:
                    future = executor.submit(
                        self._check_telnet, ip, port,
                        cred["username"], cred["password"]
                    )
                    futures.append(future)

            # Queue HTTP checks
            for ip, port in http_targets:
                for cred in self.http_creds:
                    future = executor.submit(
                        self._check_http, ip, port,
                        cred["username"], cred["password"]
                    )
                    futures.append(future)

            # Collect results
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 20 == 0:
                    logger.info(
                        f"  Credential check progress: {completed}/{total_tests}"
                    )
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                except Exception as e:
                    logger.debug(f"  Credential check error: {e}")

        logger.info(
            f"Credential check complete. "
            f"{len(self.results)} default credential(s) found."
        )
        return self.results
