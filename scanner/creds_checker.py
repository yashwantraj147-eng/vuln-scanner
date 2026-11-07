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
        Attempt Telnet login with given credentials using standard sockets
        (compatible with Python 3.10 through Python 3.13+ without telnetlib).

        Args:
            ip: Target IP address.
            port: Telnet port (usually 23).
            username: Username to try.
            password: Password to try.

        Returns:
            Finding dictionary if login succeeds, None otherwise.
        """
        sock = None
        try:
            sock = socket.create_connection((ip, port), timeout=self.timeout)
            sock.settimeout(self.timeout)

            def _recv_filtered(timeout_sec: float) -> str:
                end_time = time.time() + timeout_sec
                buf = bytearray()
                while time.time() < end_time:
                    try:
                        sock.settimeout(max(0.2, end_time - time.time()))
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        # Handle basic Telnet negotiation (IAC sequences)
                        i = 0
                        clean = bytearray()
                        while i < len(chunk):
                            if chunk[i] == 0xFF and i + 2 < len(chunk):
                                cmd = chunk[i + 1]
                                opt = chunk[i + 2]
                                if cmd == 0xFD:  # IAC DO -> send IAC WONT
                                    try:
                                        sock.sendall(bytes([0xFF, 0xFC, opt]))
                                    except OSError:
                                        pass
                                elif cmd == 0xFB:  # IAC WILL -> send IAC DONT
                                    try:
                                        sock.sendall(bytes([0xFF, 0xFE, opt]))
                                    except OSError:
                                        pass
                                i += 3
                            elif chunk[i] == 0xFF and i + 1 < len(chunk):
                                i += 2
                            else:
                                clean.append(chunk[i])
                                i += 1
                        buf.extend(clean)
                        text = buf.decode("utf-8", errors="replace").lower()
                        if any(p in text for p in ("login:", "username:", "user:", "password:", "pass:", "#", "$", ">")):
                            break
                    except (socket.timeout, OSError):
                        break
                return buf.decode("utf-8", errors="replace")

            # 1. Wait for login / username prompt
            initial = _recv_filtered(self.timeout)
            initial_lower = initial.lower()

            if any(p in initial_lower for p in ("login", "username", "user:")) or not initial:
                sock.sendall(f"{username}\r\n".encode("utf-8"))
                time.sleep(0.3)

            # 2. Wait for password prompt
            pass_prompt = _recv_filtered(self.timeout)
            if any(p in pass_prompt.lower() for p in ("password", "pass:")):
                sock.sendall(f"{password}\r\n".encode("utf-8"))
                time.sleep(0.5)

            # 3. Read post-login response
            auth_resp = _recv_filtered(self.timeout)
            auth_resp_lower = auth_resp.lower()

            failure_indicators = [
                "login incorrect",
                "access denied",
                "authentication failed",
                "invalid",
                "bad password",
                "login failed",
            ]
            for indicator in failure_indicators:
                if indicator in auth_resp_lower:
                    return None

            success_indicators = ["$", "#", ">", "welcome", "last login", "shell", "busybox"]
            for indicator in success_indicators:
                if indicator in auth_resp_lower:
                    logger.warning(
                        f"    [!] Telnet login success: {ip}:{port} {username}:{password}"
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
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

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

    def _check_redis(self, ip: str, port: int = 6379) -> Optional[dict]:
        """
        Check for unauthenticated Redis access.

        Args:
            ip: Target IP.
            port: Redis port (usually 6379).

        Returns:
            Finding dict if open without auth, None otherwise.
        """
        sock = None
        try:
            sock = socket.create_connection((ip, port), timeout=self.timeout)
            sock.sendall(b"PING\r\n")
            resp = sock.recv(1024).decode("utf-8", errors="replace")
            if "+PONG" in resp:
                sock.sendall(b"INFO\r\n")
                info_resp = sock.recv(4096).decode("utf-8", errors="replace")
                evidence = "Unauthenticated PING returned +PONG"
                if "redis_version" in info_resp:
                    for line in info_resp.splitlines():
                        if line.startswith("redis_version:"):
                            evidence += f" ({line.strip()})"
                            break
                logger.warning(f"    [!] Redis unauthenticated access: {ip}:{port}")
                return {
                    "type": "Unauthenticated Access - Redis",
                    "severity": "Critical",
                    "target": f"{ip}:{port}",
                    "evidence": evidence,
                    "service": "Redis",
                    "username": "None",
                    "password": "None",
                    "description": (
                        f"Redis server at {ip}:{port} accepts commands without authentication. "
                        "Attackers can read/modify data or achieve Remote Code Execution."
                    ),
                    "remediation": (
                        "Enable authentication with `requirepass` in redis.conf, bind only to localhost, "
                        "and restrict access with firewall rules."
                    ),
                }
        except (socket.timeout, OSError):
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
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
        redis_targets = []

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
            if port == 6379 or "redis" in service:
                redis_targets.append((ip, port))

        total_tests = (
            len(ssh_targets) * len(self.ssh_creds)
            + len(ftp_targets) * len(self.ftp_creds)
            + len(telnet_targets) * len(self.telnet_creds)
            + len(http_targets) * len(self.http_creds)
            + len(redis_targets)
        )

        if total_tests == 0:
            logger.info("No applicable services for credential checking.")
            return self.results

        logger.info(
            f"Starting credential checks: {total_tests} combination(s) to test "
            f"(SSH:{len(ssh_targets)}, FTP:{len(ftp_targets)}, "
            f"Telnet:{len(telnet_targets)}, HTTP:{len(http_targets)}, "
            f"Redis:{len(redis_targets)})"
        )

        # Use thread pool for concurrent testing
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []

            # Queue Redis checks
            for ip, port in redis_targets:
                future = executor.submit(self._check_redis, ip, port)
                futures.append(future)

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
