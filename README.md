# VulnScanner 🛡️

> **An industry-grade, multi-threaded vulnerability assessment scanner built in Python for authorized security audits.**

![Python 3.10 - 3.13+](https://img.shields.io/badge/python-3.10%20--%203.13%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![CI Pipeline](https://img.shields.io/badge/CI-GitHub%20Actions-brightgreen)
![Docker Ready](https://img.shields.io/badge/docker-ready-blue)
![SARIF v2.1.0](https://img.shields.io/badge/output-SARIF%20%7C%20HTML%20%7C%20CSV%20%7C%20JSON-orange)

---

## ⚖️ Legal Disclaimer

> **WARNING: This tool is designed for AUTHORIZED SECURITY TESTING ONLY.**
>
> - You **MUST** have explicit written permission from the system owner before scanning any target.
> - Unauthorized scanning of networks, systems, or applications is **ILLEGAL** under computer crime laws including the Computer Fraud and Abuse Act (CFAA), UK Computer Misuse Act, and similar legislation worldwide.
> - The developers assume **NO LIABILITY** for any misuse of this tool.
> - Always operate within the scope defined in your written authorization agreement.
> - Use only against **your own systems** or designated test environments (e.g., `localhost`, `127.0.0.1`, lab networks).

---

## 🚀 Features

| Module | Description |
|--------|-------------|
| **Port Scanner** | Multi-threaded TCP Connect & SYN scans with SSL-aware banner grabbing on TLS ports |
| **Service Detector** | Banner fingerprinting with regex signatures (OpenSSH, Apache, Nginx, Redis, Docker, etc.) |
| **CVE Matcher** | Local CVE database, CISA KEV (Known Exploited Vulnerabilities) live feed & OSV.dev lookup |
| **Web Scanner** | SQLi (error & time-based blind), XSS, Traversal, Redirects, Security Headers (CSP/HSTS), CORS, Cookies |
| **SSL/TLS Checker** | Certificate expiration, self-signed detection, SAN validation, weak ciphers, TLS 1.0–1.3 audits |
| **Creds Checker** | Pure socket Telnet (Python 3.13+ ready), SSH, FTP, HTTP forms/basic auth, Redis unauthenticated probes |
| **Report Generator** | Dark-themed HTML reports with offline fallback, JSON export, CSV audit sheets, and SARIF v2.1.0 |

---

## 📦 Installation & Setup

### Prerequisites
- Python 3.10 to 3.13+
- pip (Python package manager) or Docker

### Local Installation

```bash
# Clone the repository
git clone https://github.com/your-username/vuln_scanner.git
cd vuln_scanner

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# Install in editable mode
pip install -r requirements.txt
pip install -e .
```

### Docker Execution (Zero Setup)

```bash
# Build the container
docker build -t vulnscanner .

# Run a scan and mount the output folder for reports
docker run --rm -v $(pwd)/output:/app/output vulnscanner --target 127.0.0.1 --csv --sarif
```

---

## 🔧 Usage

### Basic Scan (localhost)

```bash
# Full scan against localhost (all modules)
python main.py --target 127.0.0.1

# Scan with specific modules only
python main.py --target 127.0.0.1 --modules ports,services,cve

# Custom thread count and output directory
python main.py --target 127.0.0.1 --threads 20 --output ./my_reports
```

### CLI Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--target` | `-t` | *required* | Target IP, CIDR range, or domain |
| `--threads` | `-T` | 10 | Number of scanning threads |
| `--output` | `-o` | `./output` | Report output directory |
| `--modules` | `-m` | `all` | Comma-separated module list |
| `--config` | `-c` | `config.yaml` | Configuration file path |
| `--verbose` | `-v` | false | Enable debug logging |
| `--no-report` | | false | Skip report generation |
| `--json-only` | | false | Generate JSON only (no HTML) |
| `--csv` | | false | Generate CSV export of findings |
| `--sarif` | | false | Generate SARIF v2.1.0 report for CI/CD |

### Available Modules

- `ports` — TCP port scanning with banner grabbing
- `services` — Service version detection
- `cve` — CVE database matching
- `web` — Web vulnerability scanning (SQLi, XSS, etc.)
- `ssl` — SSL/TLS certificate and cipher analysis
- `creds` — Default credential checking
- `all` — Run all modules (default)

### Example Scans

```bash
# Scan a CIDR range (lab network only!)
python main.py --target 192.168.1.0/24 --modules ports,services --threads 50

# Web vulnerability scan only
python main.py --target 127.0.0.1 --modules ports,web

# SSL certificate check
python main.py --target 127.0.0.1 --modules ports,ssl

# Full scan with verbose output
python main.py --target localhost --modules all --verbose

# Generate JSON report only
python main.py --target 127.0.0.1 --json-only
```

---

## 📂 Project Structure

```
vuln_scanner/
├── .github/
│   └── workflows/ci.yml       # Multi-OS matrix CI/CD pipeline
├── main.py                    # CLI entry point with Rich terminal UI
├── config.yaml                # Configuration (ports, payloads, credentials)
├── pyproject.toml             # Modern PEP 517/621 packaging & tool config
├── requirements.txt           # Python dependencies
├── Dockerfile                 # Production multi-stage Docker container
├── Makefile                   # Automation commands (test, lint, coverage)
├── README.md                  # Documentation and quickstart
├── SECURITY.md                # Responsible vulnerability disclosure policy
├── CONTRIBUTING.md            # Contributor guidelines and workflow
├── LICENSE                    # MIT License
│
├── scanner/                   # Scanning modules package
│   ├── __init__.py
│   ├── port_scanner.py        # Multi-threaded TCP port scanner with TLS probing
│   ├── service_detector.py    # Regex banner fingerprinting engine
│   ├── web_scanner.py         # Web vulnerability engine (OWASP, CSP, CORS, SQLi)
│   ├── ssl_checker.py         # SSL/TLS certificate & cipher analyzer (TLS 1.0-1.3)
│   └── creds_checker.py       # Socket Telnet (Python 3.13+), SSH, FTP, Redis checks
│
├── cve_matcher.py             # CVE matcher with CISA KEV & OSV.dev live lookups
├── report_generator.py        # Report engine (HTML, JSON, CSV, SARIF v2.1.0)
│
├── templates/
│   └── report.html            # Jinja2 HTML report with air-gapped CSS fallback
│
├── data/
│   └── cve_snapshot.json      # Local CVE database snapshot
│
├── tests/
│   ├── __init__.py
│   └── test_scanner.py        # Comprehensive test suite (62 test cases)
│
└── output/                    # Generated audit reports (.html, .json, .csv, .sarif)
```

---

## ⚙️ Configuration

Edit `config.yaml` to customize scanning behavior:

- **Port lists**: Define which ports to scan
- **Scan type**: Choose `connect` (default) or `syn` (requires admin)
- **Payloads**: Customize SQLi, XSS, traversal, and redirect payloads
- **Credentials**: Define username/password pairs to test
- **SSL settings**: Configure cipher and protocol checks
- **Service signatures**: Add regex patterns for service detection

---

## 📊 Reports

### HTML Report
- Dark-themed professional layout
- Risk score with severity breakdown
- Interactive Chart.js doughnut and bar charts
- Color-coded finding cards by severity
- Remediation guidance for each finding
- Open port and service detection tables

### JSON Export
- Machine-readable scan results
- Structured metadata, risk assessment, and findings
- Suitable for integration with SIEM/ticketing systems

Reports are saved to the `output/` directory (configurable via `--output`).

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/test_scanner.py -v

# Run with coverage
pytest tests/test_scanner.py -v --cov=scanner --cov=cve_matcher --cov=report_generator

# Run a specific test class
pytest tests/test_scanner.py::TestCVEMatcher -v

# Run a specific test
pytest tests/test_scanner.py::TestPortScanner::test_resolve_target_cidr -v
```

---

## 🔐 Risk Scoring

Findings are classified into 5 severity levels with weighted scoring:

| Severity | Weight | Examples |
|----------|--------|----------|
| **Critical** | 40 | RCE CVEs, default root credentials, SQLi, expired certs |
| **High** | 25 | XSS, weak ciphers, anonymous FTP, deprecated TLS |
| **Medium** | 10 | Self-signed certs, open redirects, expiring certs |
| **Low** | 3 | Informational directory discovery |
| **Info** | 0 | Valid certificates, modern TLS protocols |

The overall risk score (0–100) determines the risk level displayed in reports.

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Commit your changes (`git commit -m 'Add new scanning module'`)
4. Push to the branch (`git push origin feature/new-module`)
5. Open a Pull Request

---

## 📝 License

This project is provided for educational and authorized security testing purposes only.
Use responsibly and ethically.

---

*Built with ❤️ for the security community.*
