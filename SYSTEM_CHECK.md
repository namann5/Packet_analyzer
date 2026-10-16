# System Verification & Basic Checks Record

**Generated:** 2026-10-16 11:39:18 UTC  
**Base Revision:** `a66b0e5` on branch `fix/ipc-security-propagation` (checks ran against this revision plus the working tree; this record is not part of the revision it describes)  
**Repository State:** Modified (2 tracked files)  

---

## 1. Environment & Platform

| Attribute | Value | Status |
|---|---|---|
| **Operating System** | Windows 10 (AMD64) | PASS |
| **Python Runtime** | Python 3.11.9 | PASS |
| **Python Binary** | `C:\Users\hp\AppData\Local\Programs\Python\Python311\python.exe` | PASS |
| **Build System (Meson)** | Installed | PASS |
| **Build Backend (Ninja)** | Installed | PASS |
| **C++ Toolchain** | None found in PATH (native build requires MSVC/GCC) | INFO |

---

## 2. Git & Repository Information

| Remote | URL |
|---|---|
| **origin** | `https://github.com/singhanurag0317-bit/Packet_analyzer.git` |
| **upstream** | `https://github.com/namann5/Packet_analyzer.git` |

- **Current Branch:** `fix/ipc-security-propagation`
- **Working Tree:** Modified (2 tracked files)
- **Baseline Alignment:** Not verified by this script (compare against `upstream/main` manually)

---

## 3. Dependency Audit (Dashboard & Testing)

Detected versions are checked against the bounds declared in `dashboard/requirements.txt`.
A `WARN` means the installed version is missing a declared bound or falls outside it;
`FAIL` means the package is not importable.

| Package | Detected Version | Purpose | Audit Result |
|---|---|---|---|
| `fastapi` | 0.141.1 (declared >=0.109.0,<1.0.0) | FastAPI web framework | PASS |
| `uvicorn` | 0.52.1 (declared >=0.27.0,<1.0.0) | ASGI server | PASS |
| `websockets` | 13.1 (declared >=12.0,<14.0) | WebSocket protocol | PASS |
| `reportlab` | 5.0.1 (declared >=4.0.0,<5.0.0) | PDF generation | WARN (outside declared bounds) |
| `pytest` | 9.1.1 (declared >=8.0.0,<9.0.0) | Test runner | WARN (outside declared bounds) |
| `httpx` | 0.28.1 (declared >=0.27.0,<0.28.0) | HTTP client / TestClient | WARN (outside declared bounds) |
| `starlette` | 1.5.0 | ASGI toolkit | INFO (transitive, no declared bound) |
| `pydantic` | 2.13.4 | Data validation | INFO (transitive, no declared bound) |

---

## 4. Subsystem Verification Checks

| Check Item | Description | Result |
|---|---|---|
| **C++ Engine Headers** | All 12 modular headers present in `include/` | PASS |
| **Dashboard Web UI Assets** | `index.html` and `app.js` present in `dashboard/static/` | PASS |
| **Synthetic PCAP Generator** | `generate_test_pcap.py` executes successfully | PASS |
| **Dashboard Test Suite** | 19 automated tests in `dashboard/test_dashboard.py` | PASS |

---

## 5. Test Suite Execution Summary

```text
...................                                                      [100%]
============================== warnings summary ===============================
C:\Users\hp\AppData\Local\Programs\Python\Python311\Lib\site-packages\fastapi\testclient.py:1
  C:\Users\hp\AppData\Local\Programs\Python\Python311\Lib\site-packages\fastapi\testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
19 passed, 1 warning in 1.71s
```

---

## 6. Record Status

This system check record verifies that:
1. All Python core dependencies for the web dashboard and report generator are importable; any version-bound mismatches are reported as `WARN` in section 3.
2. The dashboard test suite (`dashboard/test_dashboard.py`) passes.
3. Synthetic test traffic generation functions cleanly.
4. The tracked codebase files checked above are present (existence only, not content integrity).
