# Contributing to VulnScanner 🤝

Thank you for your interest in contributing to VulnScanner! We welcome contributions that improve scanner capabilities, threat intelligence detection, test coverage, and performance.

---

## 🛠️ Development Setup

1. **Fork and Clone**:
   ```bash
   git clone https://github.com/your-username/vuln_scanner.git
   cd vuln_scanner
   ```

2. **Create a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate       # Linux / macOS
   # venv\Scripts\activate        # Windows
   ```

3. **Install Dependencies & Editable Package**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   pip install -e .
   ```

---

## 🧪 Testing & Quality Standards

Before submitting any Pull Request, ensure that:

1. **All Tests Pass**:
   ```bash
   pytest -v
   ```

2. **Coverage Checks Pass**:
   ```bash
   pytest --cov=scanner --cov=cve_matcher --cov=report_generator tests/
   ```

3. **Linting & Code Style**:
   We adhere to PEP 8 standards enforced via [Ruff](https://astral.sh/ruff):
   ```bash
   ruff check .
   ruff format --check .
   ```

4. **New Features Require Unit Tests**:
   Any new scanning module or detection logic must include unit tests with mocks in `tests/test_scanner.py`.

---

## 🌿 Git Branching & Commit Conventions

- Use feature branches: `git checkout -b feature/your-feature-name` or `bugfix/issue-description`.
- Follow Conventional Commits:
  - `feat: add unauthenticated MongoDB probe`
  - `fix: resolve socket timeout handling in telnet client`
  - `docs: update SARIF export usage documentation`
  - `test: add unit tests for CORS misconfiguration check`

---

## 🚀 Submitting a Pull Request

1. Push your changes: `git push origin feature/your-feature-name`
2. Open a Pull Request against `master` (or `main`).
3. Fill out the PR template describing the problem solved and test evidence.
4. Ensure all automated GitHub Actions CI checks pass.

