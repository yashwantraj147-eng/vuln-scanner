"""
scanner/ssl_checker.py
=======================
SSL/TLS Security Checker Module.
Analyzes SSL/TLS configurations for security weaknesses:
  - Expired certificates
  - Self-signed certificates
  - Weak cipher suites
  - Deprecated protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
  - Certificate chain validation issues

LEGAL DISCLAIMER: Only use against systems you own or have explicit
written authorization to test.
"""

import ssl
import socket
import logging
import datetime
from typing import Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class SSLChecker:
    """
    Checks SSL/TLS configurations for security weaknesses including
    expired certs, weak ciphers, self-signed certs, and deprecated protocols.
    """

    def __init__(self, config: dict):
        """
        Initialize the SSL/TLS checker.

        Args:
            config: SSL checker configuration dictionary.
        """
        self.config = config
        self.check_expiry = config.get("check_expiry", True)
        self.check_self_signed = config.get("check_self_signed", True)
        self.check_weak_ciphers = config.get("check_weak_ciphers", True)
        self.check_protocols = config.get("check_protocols", True)
        self.weak_ciphers = config.get("weak_ciphers", [])
        self.deprecated_protocols = config.get("deprecated_protocols", [])
        self.timeout = config.get("timeout", 10)
        self.results = []

    def _get_certificate(self, ip: str, port: int) -> Optional[dict]:
        """
        Retrieve the SSL certificate from a target host.

        Args:
            ip: Target IP or hostname.
            port: Target port (usually 443).

        Returns:
            Certificate info dictionary, or None on failure.
        """
        try:
            # Create an unverified context to allow inspection of any cert
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as tls_sock:
                    cert_bin = tls_sock.getpeercert(binary_form=True)
                    cert_dict = tls_sock.getpeercert()
                    cipher_info = tls_sock.cipher()
                    protocol_version = tls_sock.version()

                    # Parse the binary certificate with cryptography lib
                    cert_obj = x509.load_der_x509_certificate(
                        cert_bin, default_backend()
                    )

                    alpn_proto = (
                        tls_sock.selected_alpn_protocol()
                        if hasattr(tls_sock, "selected_alpn_protocol")
                        else None
                    )

                    return {
                        "cert_dict": cert_dict,
                        "cert_obj": cert_obj,
                        "cipher": cipher_info,
                        "protocol": protocol_version,
                        "alpn": alpn_proto,
                        "cert_binary": cert_bin,
                    }

        except ssl.SSLError as e:
            logger.warning(f"SSL error connecting to {ip}:{port} — {e}")
        except socket.timeout:
            logger.warning(f"Connection timeout to {ip}:{port}")
        except ConnectionRefusedError:
            logger.warning(f"Connection refused: {ip}:{port}")
        except OSError as e:
            logger.warning(f"OS error connecting to {ip}:{port} — {e}")

        return None

    def _check_expiry(self, cert_obj, ip: str, port: int) -> list[dict]:
        """
        Check if the certificate is expired or expiring soon.

        Args:
            cert_obj: x509 certificate object.
            ip: Target IP.
            port: Target port.

        Returns:
            List of expiry-related findings.
        """
        findings = []
        now = datetime.datetime.now(datetime.timezone.utc)

        not_after = cert_obj.not_valid_after_utc
        not_before = cert_obj.not_valid_before_utc

        if now > not_after:
            # Certificate is already expired
            days_expired = (now - not_after).days
            findings.append(
                {
                    "type": "SSL/TLS - Expired Certificate",
                    "severity": "Critical",
                    "target": f"{ip}:{port}",
                    "evidence": (
                        f"Certificate expired on {not_after.strftime('%Y-%m-%d')} "
                        f"({days_expired} day(s) ago)"
                    ),
                    "description": (
                        f"The SSL certificate for {ip}:{port} has expired. "
                        f"Expired certificates provide no trust guarantees and "
                        f"will cause browser warnings for users."
                    ),
                    "remediation": (
                        "Renew the SSL certificate immediately. Consider using "
                        "automated certificate management (e.g., Let's Encrypt "
                        "with certbot auto-renewal)."
                    ),
                }
            )
        elif now < not_before:
            # Certificate is not yet valid
            findings.append(
                {
                    "type": "SSL/TLS - Not Yet Valid Certificate",
                    "severity": "High",
                    "target": f"{ip}:{port}",
                    "evidence": (
                        f"Certificate not valid until "
                        f"{not_before.strftime('%Y-%m-%d')}"
                    ),
                    "description": (
                        f"The SSL certificate for {ip}:{port} is not yet valid."
                    ),
                    "remediation": "Check server time synchronization and certificate dates.",
                }
            )
        else:
            # Check if expiring within 30 days
            days_remaining = (not_after - now).days
            if days_remaining <= 30:
                findings.append(
                    {
                        "type": "SSL/TLS - Certificate Expiring Soon",
                        "severity": "Medium",
                        "target": f"{ip}:{port}",
                        "evidence": (
                            f"Certificate expires on "
                            f"{not_after.strftime('%Y-%m-%d')} "
                            f"({days_remaining} day(s) remaining)"
                        ),
                        "description": (
                            f"The SSL certificate for {ip}:{port} will expire "
                            f"within 30 days. Timely renewal is recommended."
                        ),
                        "remediation": (
                            "Renew the certificate before expiration. Set up "
                            "monitoring and auto-renewal if possible."
                        ),
                    }
                )
            else:
                # Certificate validity is fine — informational
                findings.append(
                    {
                        "type": "SSL/TLS - Certificate Validity",
                        "severity": "Info",
                        "target": f"{ip}:{port}",
                        "evidence": (
                            f"Valid until {not_after.strftime('%Y-%m-%d')} "
                            f"({days_remaining} day(s) remaining)"
                        ),
                        "description": (
                            f"The certificate for {ip}:{port} is valid."
                        ),
                        "remediation": "No action required.",
                    }
                )

        return findings

    def _check_self_signed(self, cert_obj, ip: str, port: int) -> list[dict]:
        """
        Check if the certificate is self-signed.

        Args:
            cert_obj: x509 certificate object.
            ip: Target IP.
            port: Target port.

        Returns:
            List of self-signed certificate findings.
        """
        findings = []

        # A self-signed cert has the same issuer and subject
        issuer = cert_obj.issuer
        subject = cert_obj.subject

        if issuer == subject:
            findings.append(
                {
                    "type": "SSL/TLS - Self-Signed Certificate",
                    "severity": "Medium",
                    "target": f"{ip}:{port}",
                    "evidence": (
                        f"Issuer and Subject are identical: "
                        f"{issuer.rfc4514_string()}"
                    ),
                    "description": (
                        f"The certificate for {ip}:{port} is self-signed. "
                        f"Self-signed certificates are not trusted by browsers "
                        f"and cannot be validated against a Certificate Authority."
                    ),
                    "remediation": (
                        "Obtain a certificate from a trusted Certificate "
                        "Authority (CA). Free options include Let's Encrypt."
                    ),
                }
            )

        return findings

    def _check_cipher_strength(
        self, cipher_info: tuple, ip: str, port: int
    ) -> list[dict]:
        """
        Check if the negotiated cipher suite is weak or insecure.

        Args:
            cipher_info: Tuple of (cipher_name, protocol, key_bits).
            ip: Target IP.
            port: Target port.

        Returns:
            List of weak cipher findings.
        """
        findings = []

        if not cipher_info:
            return findings

        cipher_name = cipher_info[0] if cipher_info else ""
        protocol = cipher_info[1] if len(cipher_info) > 1 else ""
        key_bits = cipher_info[2] if len(cipher_info) > 2 else 0

        # Check against known weak ciphers
        for weak in self.weak_ciphers:
            if weak.upper() in cipher_name.upper():
                findings.append(
                    {
                        "type": "SSL/TLS - Weak Cipher Suite",
                        "severity": "High",
                        "target": f"{ip}:{port}",
                        "evidence": (
                            f"Weak cipher in use: {cipher_name} "
                            f"(protocol: {protocol}, bits: {key_bits})"
                        ),
                        "description": (
                            f"The server at {ip}:{port} is using a weak cipher "
                            f"suite '{cipher_name}' which contains '{weak}'. "
                            f"This may allow cryptographic attacks."
                        ),
                        "remediation": (
                            f"Disable the weak cipher '{weak}' and configure "
                            f"the server to use strong cipher suites "
                            f"(AES-256-GCM, ChaCha20-Poly1305)."
                        ),
                    }
                )
                break

        # Check for low key bit strength
        if key_bits and key_bits < 128:
            findings.append(
                {
                    "type": "SSL/TLS - Weak Key Length",
                    "severity": "High",
                    "target": f"{ip}:{port}",
                    "evidence": f"Cipher key length: {key_bits} bits",
                    "description": (
                        f"The cipher negotiated with {ip}:{port} uses only "
                        f"{key_bits}-bit keys, which is below the recommended "
                        f"minimum of 128 bits."
                    ),
                    "remediation": (
                        "Configure the server to require cipher suites with "
                        "at least 128-bit keys (256-bit preferred)."
                    ),
                }
            )

        return findings

    def _check_protocol_version(
        self, protocol: str, ip: str, port: int
    ) -> list[dict]:
        """
        Check if the negotiated TLS protocol version is deprecated.

        Args:
            protocol: Protocol version string (e.g., 'TLSv1.2').
            ip: Target IP.
            port: Target port.

        Returns:
            List of protocol version findings.
        """
        findings = []

        if not protocol:
            return findings

        for deprecated in self.deprecated_protocols:
            if deprecated.lower() in protocol.lower():
                findings.append(
                    {
                        "type": "SSL/TLS - Deprecated Protocol",
                        "severity": "High",
                        "target": f"{ip}:{port}",
                        "evidence": f"Protocol in use: {protocol}",
                        "description": (
                            f"The server at {ip}:{port} supports deprecated "
                            f"protocol version '{protocol}'. Deprecated protocols "
                            f"are vulnerable to known attacks (POODLE, BEAST, etc)."
                        ),
                        "remediation": (
                            f"Disable {protocol} and enforce TLS 1.2 or "
                            f"TLS 1.3 only."
                        ),
                    }
                )
                break

        # Positive finding for modern protocols
        if protocol and "TLSv1.2" in protocol or "TLSv1.3" in protocol:
            findings.append(
                {
                    "type": "SSL/TLS - Protocol Version",
                    "severity": "Info",
                    "target": f"{ip}:{port}",
                    "evidence": f"Protocol: {protocol}",
                    "description": f"Server uses {protocol}, which is current and secure.",
                    "remediation": "No action required.",
                }
            )

        return findings

    def _test_deprecated_protocols(self, ip: str, port: int) -> list[dict]:
        """
        Actively test if the server accepts deprecated protocol versions.
        Supports both modern Python 3.10-3.13+ (ssl.TLSVersion) and legacy fallback.

        Args:
            ip: Target IP.
            port: Target port.

        Returns:
            List of deprecated protocol findings.
        """
        findings = []

        # Modern Python ssl module uses TLSVersion enum
        test_cases = []
        if hasattr(ssl, "TLSVersion"):
            test_cases.append(("TLSv1.0", ssl.TLSVersion.TLSv1))
            test_cases.append(("TLSv1.1", ssl.TLSVersion.TLSv1_1))

        for proto_name, tls_version in test_cases:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = tls_version
                context.maximum_version = tls_version
                try:
                    context.set_ciphers("ALL:@SECLEVEL=0")
                except (ssl.SSLError, ValueError):
                    pass

                with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as tls_sock:
                        findings.append(
                            {
                                "type": "SSL/TLS - Deprecated Protocol Supported",
                                "severity": "High",
                                "target": f"{ip}:{port}",
                                "evidence": f"Server accepts {proto_name}",
                                "description": (
                                    f"The server at {ip}:{port} accepts connections "
                                    f"using deprecated {proto_name}."
                                ),
                                "remediation": (
                                    f"Disable {proto_name} on the server. "
                                    f"Only allow TLS 1.2 and TLS 1.3."
                                ),
                            }
                        )
            except (ssl.SSLError, OSError, ConnectionRefusedError, ValueError):
                pass

        if not test_cases:
            legacy_tests = []
            if hasattr(ssl, "PROTOCOL_TLSv1"):
                legacy_tests.append(("TLSv1.0", ssl.PROTOCOL_TLSv1))
            if hasattr(ssl, "PROTOCOL_TLSv1_1"):
                legacy_tests.append(("TLSv1.1", ssl.PROTOCOL_TLSv1_1))

            for proto_name, proto_const in legacy_tests:
                try:
                    context = ssl.SSLContext(proto_const)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with socket.create_connection(
                        (ip, port), timeout=self.timeout
                    ) as sock:
                        with context.wrap_socket(sock, server_hostname=ip) as tls_sock:
                            findings.append(
                                {
                                    "type": "SSL/TLS - Deprecated Protocol Supported",
                                    "severity": "High",
                                    "target": f"{ip}:{port}",
                                    "evidence": f"Server accepts {proto_name}",
                                    "description": (
                                        f"The server at {ip}:{port} accepts connections "
                                        f"using deprecated {proto_name}."
                                    ),
                                    "remediation": (
                                        f"Disable {proto_name} on the server. "
                                        f"Only allow TLS 1.2 and TLS 1.3."
                                    ),
                                }
                            )
                except (ssl.SSLError, OSError, ConnectionRefusedError, ValueError):
                    pass

        return findings

    def _check_san(self, cert_obj, ip: str, port: int) -> list[dict]:
        """
        Check certificate Subject Alternative Names (SAN).

        Args:
            cert_obj: x509 certificate object.
            ip: Target IP or domain.
            port: Target port.

        Returns:
            List of SAN-related findings.
        """
        findings = []
        try:
            san_ext = cert_obj.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            ip_names = [str(ip_addr) for ip_addr in san_ext.value.get_values_for_type(x509.IPAddress)]
            all_sans = dns_names + ip_names
            if not all_sans:
                findings.append(
                    {
                        "type": "SSL/TLS - Missing Subject Alternative Names",
                        "severity": "Low",
                        "target": f"{ip}:{port}",
                        "evidence": "No SAN entries found in certificate",
                        "description": (
                            "The certificate lacks Subject Alternative Names (SANs). "
                            "Modern browsers require SANs for identity validation."
                        ),
                        "remediation": "Re-issue certificate with proper Subject Alternative Names.",
                    }
                )
        except x509.ExtensionNotFound:
            findings.append(
                {
                    "type": "SSL/TLS - Missing Subject Alternative Names",
                    "severity": "Low",
                    "target": f"{ip}:{port}",
                    "evidence": "No SAN extension found",
                    "description": (
                        "The certificate does not include the Subject Alternative Name extension."
                    ),
                    "remediation": "Re-issue certificate with Subject Alternative Names (SAN).",
                }
            )
        except Exception:
            pass

        return findings

    def scan(self, target: str, port_results: list[dict]) -> list[dict]:
        """
        Run all SSL/TLS checks against HTTPS ports found in scan results.

        Args:
            target: Original target string.
            port_results: List of open ports from port scanner.

        Returns:
            List of all SSL/TLS findings.
        """
        self.results = []

        # Identify SSL/TLS ports
        ssl_ports = []
        for port_info in port_results:
            port = port_info.get("port", 0)
            service = port_info.get("service", "").lower()
            if port in (443, 8443, 993, 995) or "https" in service or "ssl" in service:
                ssl_ports.append(port_info)

        if not ssl_ports:
            logger.info("No SSL/TLS services found. Skipping SSL checks.")
            return self.results

        logger.info(f"Starting SSL/TLS checks on {len(ssl_ports)} service(s)...")

        for port_info in ssl_ports:
            ip = port_info.get("ip", target)
            port = port_info.get("port", 443)

            logger.info(f"Checking SSL/TLS on {ip}:{port}...")

            # Retrieve the certificate
            cert_data = self._get_certificate(ip, port)
            if not cert_data:
                self.results.append(
                    {
                        "type": "SSL/TLS - Connection Failed",
                        "severity": "Medium",
                        "target": f"{ip}:{port}",
                        "evidence": "Unable to establish SSL/TLS connection",
                        "description": (
                            f"Could not retrieve SSL certificate from {ip}:{port}."
                        ),
                        "remediation": "Verify SSL/TLS is properly configured.",
                    }
                )
                continue

            cert_obj = cert_data["cert_obj"]
            cipher_info = cert_data["cipher"]
            protocol = cert_data["protocol"]

            # Run all checks
            if self.check_expiry:
                self.results.extend(self._check_expiry(cert_obj, ip, port))

            if self.check_self_signed:
                self.results.extend(self._check_self_signed(cert_obj, ip, port))

            # Check SAN
            self.results.extend(self._check_san(cert_obj, ip, port))

            if self.check_weak_ciphers and cipher_info:
                self.results.extend(
                    self._check_cipher_strength(cipher_info, ip, port)
                )

            if self.check_protocols:
                self.results.extend(
                    self._check_protocol_version(protocol, ip, port)
                )
                self.results.extend(
                    self._test_deprecated_protocols(ip, port)
                )

        logger.info(
            f"SSL/TLS check complete. {len(self.results)} finding(s) identified."
        )
        return self.results
