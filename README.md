# VulnScanner 🛡️

> **A comprehensive, multi-threaded vulnerability scanner built in Python for authorized security assessments.**

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

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
| **Port Scanner** | TCP SYN scan (Scapy) + TCP Connect scan with banner grabbing |
| **Service Detector** | Regex-based service/version fingerprinting from banners |
| **CVE Matcher** | Local CVE JSON database matching with semantic version comparison |
| **Web Scanner** | SQLi, XSS, Open Redirect, Directory Traversal, sensitive dir discovery |
| **SSL/TLS Checker** | Expired certs, self-signed certs, weak ciphers, deprecated protocols |
| **Creds Checker** | Default credential testing for SSH, FTP, Telnet, HTTP admin panels |
| **Report Generator** | Professional HTML reports with Chart.js charts + JSON data export |

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)
- Administrator/root privileges (for SYN scanning only)

### Setup

```bash
# Clone or download the project
cd vuln_scanner

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
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
├── main.py                    # CLI entry point and orchestrator
├── config.yaml                # Configuration (ports, payloads, credentials)
├── requirements.txt           # Python dependencies
├── README.md                  # This file
│
├── scanner/                   # Scanning modules package
│   ├── __init__.py
│   ├── port_scanner.py        # TCP SYN/Connect port scanner
│   ├── service_detector.py    # Banner-based service fingerprinting
│   ├── web_scanner.py         # Web vulnerability scanner
│   ├── ssl_checker.py         # SSL/TLS configuration checker
│   └── creds_checker.py       # Default credentials checker
│
├── cve_matcher.py             # CVE database matching engine
├── report_generator.py        # HTML + JSON report generator
│
├── templates/
│   └── report.html            # Jinja2 HTML report template (Chart.js)
│
├── data/
│   └── cve_snapshot.json      # Local CVE database snapshot
│
├── tests/
│   ├── __init__.py
│   └── test_scanner.py        # Comprehensive test suite
│
└── output/                    # Generated reports directory
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
