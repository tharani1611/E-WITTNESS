# E-WITNESS — Development Environment and Dependency Management Guide

**Document ID:** `EW-DOC-DEV-001`  
**Phase:** Phase 04 — Development Environment and Dependency Management  
**Version:** 1.0.0  
**Status:** Baseline Approved  

---

## 1. Prerequisites

- **Python**: Python `3.12+` (verified on `Python 3.13.1`).
  - On Windows, use `py -3` (Python Launcher for Windows) or a direct Python 3.12+/3.13 installation.
  - On Linux/macOS, use `python3` (`>= 3.12`).
- **Git**: Git `2.40+` (`git version 2.52.0.windows.1` verified locally).
- **No Production Services Required for Unit Testing**: All unit and configuration tests run deterministically offline without requiring live PostgreSQL, Redis, S3, or external AI credentials.

---

## 2. Reproducing the Environment from a Clean Checkout

### 2.1 Windows PowerShell

```powershell
# 1. Navigate to the repository root
Set-Location c:\Users\lenovo\Desktop\E-WITNESS

# 2. Create a project-local virtual environment (.venv)
py -m venv .venv

# 3. Verify the virtual environment Python and pip binaries
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\pip.exe --version

# 4. Install pinned runtime and development/testing dependencies
.\.venv\Scripts\pip.exe install -r requirements-dev.txt

# 5. Verify dependency consistency
.\.venv\Scripts\python.exe -m pip check
```

### 2.2 Linux / macOS (Bash / Zsh)

```bash
# 1. Navigate to the repository root
cd /path/to/E-WITNESS

# 2. Create a project-local virtual environment (.venv)
python3 -m venv .venv

# 3. Activate the virtual environment
source .venv/bin/activate

# 4. Install pinned runtime and development/testing dependencies
python -m pip install -r requirements-dev.txt

# 5. Verify dependency consistency
python -m pip check
```

---

## 3. Dependency Architecture and Separation

Dependencies are explicitly separated into two tiers and pinned to exact verified versions in [`pyproject.toml`](file:///c:/Users/lenovo/Desktop/E-WITNESS/pyproject.toml), [`requirements.txt`](file:///c:/Users/lenovo/Desktop/E-WITNESS/requirements.txt), and [`requirements-dev.txt`](file:///c:/Users/lenovo/Desktop/E-WITNESS/requirements-dev.txt):

### 3.1 Direct Runtime Dependencies (`requirements.txt`)
| Package | Pinned Version | Role |
| :--- | :--- | :--- |
| `fastapi` | `0.143.0` | Asynchronous ASGI web framework |
| `pydantic` | `2.14.1` | Data validation and `SecretStr` schema enforcement |
| `pydantic-settings` | `2.15.0` | Environment and `.env` configuration management |
| `sqlalchemy` | `2.1.4` | Asynchronous 2.x relational ORM |
| `alembic` | `1.20.0` | Database schema migration engine |
| `uvicorn` | `0.54.0` | Production-grade ASGI HTTP server |

### 3.2 Development, Testing & Quality Dependencies (`requirements-dev.txt`)
| Package | Pinned Version | Role |
| :--- | :--- | :--- |
| `pytest` | `9.1.1` | Test runner and assertion framework |
| `pytest-asyncio` | `1.4.0` | Asyncio coroutine test support |
| `pytest-cov` | `7.1.0` | Test coverage integration |
| `coverage` | `7.16.2` | Branch and line coverage measurement |
| `httpx` | `0.28.1` | Async HTTP client for ASGI integration tests |
| `ruff` | `0.17.0` | Fast Python linter, import sorter, and formatter |
| `mypy` | `2.4.0` | Strict static type checker (with `pydantic.mypy` plugin) |
| `pip-audit` | `2.10.1` | Dependency vulnerability scanner |

---

## 4. Quality Gates and Verification Workflow

All quality tools are configured centrally in [`pyproject.toml`](file:///c:/Users/lenovo/Desktop/E-WITNESS/pyproject.toml). Run the complete verification suite before committing any changes:

### 4.1 Windows PowerShell Commands
```powershell
# 1. Check formatting (line-length = 100, double quotes)
.\.venv\Scripts\ruff.exe format --check .

# 2. Run linter and security checks (pycodestyle, pyflakes, isort, bugbear, bandit)
.\.venv\Scripts\ruff.exe check .

# 3. Run strict static type checking
.\.venv\Scripts\mypy.exe

# 4. Run test suite with branch coverage (minimum 90% required)
.\.venv\Scripts\pytest.exe

# 5. Audit installed packages for known CVEs
.\.venv\Scripts\pip-audit.exe

# 6. Or run the all-in-one foundation verification script
.\.venv\Scripts\python.exe scripts/verify_foundation.py
```

### 4.2 Linux / macOS Commands
```bash
.venv/bin/ruff format --check .
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/pytest
.venv/bin/pip-audit
.venv/bin/python scripts/verify_foundation.py
```

---

## 5. Coding Conventions and Standards

1. **Formatting & Line Length**:
   - Line length is standardized at `100` characters (`[tool.ruff] line-length = 100`).
   - Double quotes (`"`) and 4-space indentation are enforced by `ruff format`.
2. **Import Ordering**:
   - Standard library $\rightarrow$ Third-party packages $\rightarrow$ First-party packages (`backend`, `ai_services`), enforced automatically via Ruff's `I` (`isort`) rules.
3. **Static Typing**:
   - All functions, methods, and fixtures must include complete type annotations (`mypy --strict` + `pydantic.mypy` plugin).
4. **File & Symbol Naming**:
   - Modules and packages: `snake_case.py`
   - Classes, Enums, and Pydantic models: `PascalCase`
   - Functions, methods, and variables: `snake_case`
   - Constants and environment setting fields: `UPPER_SNAKE_CASE`
5. **Security Rules**:
   - Never disable TLS verification (`STORAGE_VERIFY_TLS=True` is enforced across all environments).
   - Never commit `.env` files, private keys, or real credentials.
   - Never log raw `SecretStr` values or unredacted connection URLs.
