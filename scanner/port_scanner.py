"""
scanner/port_scanner.py
=======================
TCP Port Scanner with SYN scan (Scapy) and Connect scan fallback.
Includes banner grabbing for service fingerprinting.

LEGAL DISCLAIMER: Only use against systems you own or have explicit
written permission to test. Unauthorized scanning is illegal.
"""

import socket
import ssl
import logging
import ipaddress
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Attempt to import scapy for SYN scanning (requires admin/root privileges)
try:
    from scapy.all import IP, TCP, sr1, conf
    # Suppress scapy's verbose output
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available. SYN scan disabled, using connect scan.")


class PortScanner:
    """
    Multi-threaded TCP port scanner supporting SYN scan (via Scapy)
    and TCP connect scan with banner grabbing capabilities.
    """

    def __init__(self, config: dict, threads: int = 10):
        """
        Initialize the port scanner.

        Args:
            config: Port scanner configuration dictionary from config.yaml.
            threads: Number of concurrent scanning threads.
        """
        self.config = config
        self.threads = threads
        self.ports = config.get("default_ports", list(range(1, 1025)))
        self.scan_type = config.get("scan_type", "connect")
        self.banner_timeout = config.get("banner_timeout", 3)
        self.max_retries = config.get("max_retries", 2)
        self.timeout = config.get("timeout", 5)
        self.results = []

    def resolve_target(self, target: str) -> list[str]:
        """
        Resolve a target string to a list of IP addresses.
        Supports single IPs, CIDR ranges, and domain names.

        Args:
            target: IP address, CIDR notation, or domain name.

        Returns:
            List of IP address strings to scan.
        """
        ips = []
        try:
            # Try CIDR notation first (e.g., 192.168.1.0/24)
            network = ipaddress.ip_network(target, strict=False)
            ips = [str(ip) for ip in network.hosts()]
            if not ips:
                # Single IP like 127.0.0.1/32 returns empty hosts()
                ips = [str(network.network_address)]
            logger.info(f"CIDR range resolved: {len(ips)} host(s)")
        except ValueError:
            # Not a CIDR — try resolving as hostname/domain
            try:
                resolved_ip = socket.gethostbyname(target)
                ips = [resolved_ip]
                logger.info(f"Domain '{target}' resolved to {resolved_ip}")
            except socket.gaierror:
                logger.error(f"Cannot resolve target: {target}")
        return ips

    def syn_scan(self, ip: str, port: int) -> Optional[dict]:
        """
        Perform a TCP SYN scan on a single port using Scapy.
        Requires root/administrator privileges.

        Args:
            ip: Target IP address.
            port: Target port number.

        Returns:
            Dictionary with port scan result, or None if closed/filtered.
        """
        if not SCAPY_AVAILABLE:
            return self.connect_scan(ip, port)

        try:
            # Craft SYN packet
            syn_packet = IP(dst=ip) / TCP(dport=port, flags="S")
            # Send and receive response
            response = sr1(syn_packet, timeout=self.timeout, verbose=0)

            if response is None:
                # No response — port is filtered
                return None

            if response.haslayer(TCP):
                tcp_flags = response[TCP].flags
                if tcp_flags == 0x12:  # SYN-ACK received — port is open
                    # Send RST to close the half-open connection
                    rst_packet = IP(dst=ip) / TCP(
                        dport=port, flags="R", seq=response[TCP].ack
                    )
                    sr1(rst_packet, timeout=1, verbose=0)

                    # Grab banner via connect since SYN scan is done
                    banner = self._grab_banner(ip, port)
                    result = {
                        "ip": ip,
                        "port": port,
                        "state": "open",
                        "scan_type": "syn",
                        "banner": banner,
                        "service": self._guess_service(port),
                    }
                    logger.info(f"  [OPEN] {ip}:{port} ({result['service']})")
                    return result
                elif tcp_flags == 0x14:  # RST-ACK — port is closed
                    return None

        except Exception as e:
            logger.debug(f"SYN scan error on {ip}:{port} — {e}")
            # Fallback to connect scan on error
            return self.connect_scan(ip, port)

        return None

    def connect_scan(self, ip: str, port: int) -> Optional[dict]:
        """
        Perform a full TCP connect scan on a single port.
        Does not require elevated privileges.

        Args:
            ip: Target IP address.
            port: Target port number.

        Returns:
            Dictionary with port scan result, or None if closed.
        """
        for attempt in range(self.max_retries + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                result_code = sock.connect_ex((ip, port))
                if result_code == 0:
                    # Port is open — grab banner
                    banner = self._grab_banner(ip, port)
                    result = {
                        "ip": ip,
                        "port": port,
                        "state": "open",
                        "scan_type": "connect",
                        "banner": banner,
                        "service": self._guess_service(port),
                    }
                    logger.info(f"  [OPEN] {ip}:{port} ({result['service']})")
                    return result
                else:
                    return None
            except socket.timeout:
                if attempt < self.max_retries:
                    logger.debug(f"Timeout on {ip}:{port}, retrying ({attempt+1})...")
                    continue
                return None
            except OSError as e:
                logger.debug(f"Connect scan error on {ip}:{port} — {e}")
                return None
            finally:
                sock.close()
        return None

    def _grab_banner(self, ip: str, port: int) -> str:
        """
        Attempt to grab the service banner from an open port.

        Args:
            ip: Target IP address.
            port: Target port number.

        Returns:
            Banner string or empty string if unavailable.
        """
        banner = ""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.banner_timeout)
        try:
            sock.connect((ip, port))

            # Some services require a probe to trigger a banner response
            if port in (443, 8443):
                # For SSL/TLS web ports, negotiate TLS before sending HTTP HEAD
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(sock, server_hostname=ip) as tls_sock:
                        http_request = (
                            f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n"
                            f"User-Agent: VulnScanner/1.0\r\n"
                            f"Connection: close\r\n\r\n"
                        )
                        tls_sock.sendall(http_request.encode())
                        return tls_sock.recv(4096).decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
            elif port in (80, 8080, 8888, 9090):
                # Send an HTTP HEAD request to elicit server header
                http_request = (
                    f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n"
                    f"User-Agent: VulnScanner/1.0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.send(http_request.encode())
            elif port in (25, 587):
                # SMTP — send EHLO
                sock.send(b"EHLO vulnscanner\r\n")
            else:
                # For most services, just send a newline to trigger response
                sock.send(b"\r\n")

            banner = sock.recv(4096).decode("utf-8", errors="replace").strip()
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f"Banner grab failed for {ip}:{port} — {e}")
        finally:
            sock.close()

        return banner

    def _guess_service(self, port: int) -> str:
        """
        Map a port number to a common service name.

        Args:
            port: Port number.

        Returns:
            Service name string.
        """
        service_map = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPCbind",
            135: "MSRPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1521: "Oracle",
            2049: "NFS",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            8888: "HTTP-Alt",
            9090: "Web-Admin",
            27017: "MongoDB",
        }
        return service_map.get(port, "Unknown")

    def scan(self, target: str) -> list[dict]:
        """
        Execute the full port scan against a target.
        Resolves the target, then scans all configured ports using threading.

        Args:
            target: IP address, CIDR range, or domain name.

        Returns:
            List of dictionaries containing open port information.
        """
        self.results = []
        ips = self.resolve_target(target)

        if not ips:
            logger.error("No valid IPs to scan.")
            return self.results

        # Choose scan function based on configuration
        scan_func = self.syn_scan if self.scan_type == "syn" else self.connect_scan

        total_tasks = len(ips) * len(self.ports)
        logger.info(
            f"Starting port scan: {len(ips)} host(s), "
            f"{len(self.ports)} port(s), {total_tasks} total probes"
        )
        logger.info(f"Scan type: {self.scan_type.upper()}, Threads: {self.threads}")

        # Multi-threaded scan execution
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for ip in ips:
                for port in self.ports:
                    future = executor.submit(scan_func, ip, port)
                    futures[future] = (ip, port)

            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 100 == 0:
                    logger.info(f"  Progress: {completed}/{total_tasks} probes completed")
                try:
                    result = future.result()
                    if result:
                        self.results.append(result)
                except Exception as e:
                    ip, port = futures[future]
                    logger.error(f"Scan error for {ip}:{port} — {e}")

        logger.info(f"Port scan complete. {len(self.results)} open port(s) found.")
        return self.results
