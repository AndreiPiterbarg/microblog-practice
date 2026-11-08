# Security triage report: microblog-practice

Branch: `devin/1794156777-security-triage`. All 39 PRs are merged: #1–#14 add golden tests, #15–#39 are triage.

## Phase 4 verification
| Check | Baseline | Now |
|---|---|---|
| `uvx ruff check --isolated --select S app config.py microblog.py` | 11 | **1** (S113 `app/translate.py:14`) |
| `uvx --python 3.11 pip-audit -r requirements.txt`, raw count | 99 in 17 packages | **57 in 10 packages** |
| pip-audit, unique advisories (aliases merged) | 58 | **36** |
| `python -m unittest discover` | 4 (365 after golden tests) | **365 OK** |
| `python tests.py` | OK | **OK** |

Application diff vs. the manifest commit: 3 files (`app/cli.py`, `app/models.py`, `requirements.txt`), 21 lines changed. Every app-code change is a comment. No golden test was modified.

## Fixed (minimal version bump; golden tests identical)
| Package | Bump | PR |
|---|---|---|
| certifi | 2023.11.17 → 2026.10.19 | #29 |
| Flask-HTTPAuth | 4.8.0 → 4.8.1 | #31 |
| idna | 3.4 → 3.15 | #23 |
| Jinja2 | 3.1.2 → 3.1.6 | #38 |
| Pygments | 2.17.1 → 2.20.0 | #35 |
| requests | 2.31.0 → 2.33.0 | #27 |
| urllib3 | 2.1.0 → 2.8.0 | #36 |

## False positives (inline `# noqa` / `# pip-audit:` comment)
| Finding | Rationale | PR |
|---|---|---|
| C01, C03, C04, C06, C08: S605 `app/cli.py:18,20,29,31,39` | Dev-only `flask translate` CLI. The commands are constant strings; the only interpolated value (`lang` in `init`) is the invoking developer's own argv, so no trust boundary is crossed. | #18 #24 #15 #16 #25 |
| C02, C05, C07, C09: S607 same lines | `pybabel` is meant to resolve from the active venv's PATH; there's no fixed absolute path to use. | #20 #17 #28 #26 |
| C10: S324 `app/models.py:141` | MD5 only builds the Gravatar profile id the Gravatar protocol requires. It isn't a security use. | #22 |
| aiosmtpd (2) | Dev-only local SMTP debug server; never imported by the app. | #19 |
| dnspython (2) | No eventlet, no DNS resolution (`check_deliverability=False`), no wire parsing. | #21 |
| Flask (1) | `before_app_request` reads `current_user` on every request, so `Vary: Cookie` is always set. The fix (3.1.3) needs Werkzeug ≥3.1. | #34 |
| httpie (1) | Dev-only CLI, not imported by the app. | #32 |
| Mako (1) | Windows-only `TemplateLookup` traversal; Alembic uses fixed paths and the app runs on Linux. | #33 |
| python-dotenv (1) | Only `load_dotenv` (read-only) is used. The vulnerable `set_key`/`unset_key` are never called. | #30 |
| setuptools (4) | Build tool, not imported. Vulnerable paths (`PackageIndex`, sdist on macOS, Windows egg) never run. The fix (84.x) removes `pkg_resources`. | #37 |
| PyJWT (15) | Only HS256 encode/decode with the app's own `SECRET_KEY`. No JWK/JWKS, mixed algorithms, `crit` or `b64=false`. PYSEC-2025-183 is disputed and has no fix. | #39 |

pip-audit still counts these commented packages, because comments don't suppress it.

## Behaviour changes flagged by sub-sessions (not applied; awaiting decision)
| Finding | Only fix | Behaviour change |
|---|---|---|
| C11: S113 `app/translate.py:14` (real) | `timeout=10` on `requests.post` | A stalled translator call errors after 10s instead of hanging. Breaks `tests_golden_u05.test_post_called_without_timeout`. |
| gunicorn 21.2.0 (2, request smuggling, real) | 22.0.0 (major) | Stricter HTTP/1.1 parser. All 365 tests pass in a scratch run. |
| Werkzeug 3.0.1 (7; D57 multipart memory-limit bypass is real; D55 debugger; 4 are Windows-only) | ≥3.0.3 (3.0.6 recommended) | `Location` is IRI-encoded, so 2 `tests_golden_u13` tests change: `/\evil.com` → `/%5Cevil.com` (closes an open redirect) and `https:evil.com` → `https:///evil.com`. |
| PyJWT 2.8.0 (optional hardening) | 2.15.0 | `InsecureKeyLengthWarning`, `InvalidKeyError` on an empty `SECRET_KEY`, and changed `TypeError` messages are pinned by u06/u07. |

## Remaining findings
- Ruff: 1 (C11).
- pip-audit: 36 unique. Real and unresolved: gunicorn 2, Werkzeug 7 (3 real/debug, 4 Windows-only). The other 27 are documented false positives (above).
