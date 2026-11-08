# Security findings manifest

Baseline on `main` @ ca0e68b:
- `uvx ruff check --isolated --select S app config.py microblog.py`: **11** findings
- `uvx --python 3.11 pip-audit -r requirements.txt`: "99 known vulnerabilities in 17 packages" raw; **58** unique advisories after merging duplicate/aliased entries

Machine-readable copy: `security-findings.json`.

## Code units (Phase 2 golden-test targets)

| ID | Location | Unit | Covers |
|---|---|---|---|
| U01 | `app/cli.py:16-23` | init (click command `flask translate init LANG`) | C01, C02, C03 |
| U02 | `app/cli.py:26-33` | update (click command `flask translate update`) | C04, C05, C06, C07 |
| U03 | `app/cli.py:36-40` | compile (click command `flask translate compile`) | C08, C09 |
| U04 | `app/models.py:140-142` | User.avatar | C10 |
| U05 | `app/translate.py:6-21` | translate | C11, dep:requests, dep:urllib3, dep:idna, dep:certifi |
| U06 | `app/models.py:181-184` | User.get_reset_password_token | dep:pyjwt |
| U07 | `app/models.py:186-193` | User.verify_reset_password_token (staticmethod) | dep:pyjwt |
| U08 | `app/models.py:134-135` | User.set_password | dep:werkzeug |
| U09 | `app/models.py:137-138` | User.check_password | dep:werkzeug |
| U10 | `app/api/auth.py:7,11-20` | basic_auth (HTTPBasicAuth instance + verify_password + basic_auth_error), exercised via POST /api/tokens | dep:flask-httpauth, dep:werkzeug |
| U11 | `app/api/auth.py:8,23-30` | token_auth (HTTPTokenAuth instance + verify_token + token_auth_error), exercised via DELETE /api/tokens and token-protected /api/users routes | dep:flask-httpauth |
| U12 | `config.py:1-25` | Config class and module-level load_dotenv | dep:python-dotenv |
| U13 | `app/auth/routes.py:14-30` | login view (representative Flask/Werkzeug/Jinja2 request -> form -> flash/redirect/render path) | dep:flask, dep:werkzeug, dep:jinja2 |
| U14 | `app/api/errors.py` | error_response and handle_exception (werkzeug.http.HTTP_STATUS_CODES, werkzeug.exceptions.HTTPException) | dep:werkzeug, dep:flask |

Framework-wide packages (Flask, Werkzeug, Jinja2) have no single enclosing unit; U13/U14 are representative request-path units, and the existing `tests.py` suite also runs.
Packages with no app import (aiosmtpd, gunicorn, httpie, mako, pygments, setuptools, dnspython) have no golden-test unit; their triage relies on the full suite.

## Code findings (ruff S)

| ID | Rule | Location | Enclosing unit | Message |
|---|---|---|---|---|
| C01 | S605 | `app/cli.py:18:8` | U01 `init` | Starting a process with a shell: seems safe, but may be changed in the future; consider rewriting without `shell` |
| C02 | S607 | `app/cli.py:18:18` | U01 `init` | Starting a process with a partial executable path |
| C03 | S605 | `app/cli.py:20:8` | U01 `init` | Starting a process with a shell, possible injection detected |
| C04 | S605 | `app/cli.py:29:8` | U02 `update` | Starting a process with a shell: seems safe, but may be changed in the future; consider rewriting without `shell` |
| C05 | S607 | `app/cli.py:29:18` | U02 `update` | Starting a process with a partial executable path |
| C06 | S605 | `app/cli.py:31:8` | U02 `update` | Starting a process with a shell: seems safe, but may be changed in the future; consider rewriting without `shell` |
| C07 | S607 | `app/cli.py:31:18` | U02 `update` | Starting a process with a partial executable path |
| C08 | S605 | `app/cli.py:39:8` | U03 `compile` | Starting a process with a shell: seems safe, but may be changed in the future; consider rewriting without `shell` |
| C09 | S607 | `app/cli.py:39:18` | U03 `compile` | Starting a process with a partial executable path |
| C10 | S324 | `app/models.py:141:18` | U04 `User.avatar` | Probable use of insecure hash functions in `hashlib`: `md5` |
| C11 | S113 | `app/translate.py:14:9` | U05 `translate` | Probable use of `requests` call without timeout |

## Dependency packages

| Package | Pinned | Unique advisories | App usage |
|---|---|---|---|
| aiosmtpd | 1.4.4.post2 | 2 | not imported: Dev-only SMTP debug server; no app module imports it. |
| certifi | 2023.11.17 | 2 | transitive: CA bundle for requests/urllib3; reached via app/translate.py:translate (requests.post). |
| dnspython | 2.4.2 | 2 | transitive: Dependency of email-validator; WTForms Email() validator in app/auth/forms.py (RegistrationForm, ResetPasswordRequestForm) and app/main/forms.py. |
| urllib3 | 2.1.0 | 8 | transitive: HTTP transport for requests (app/translate.py:translate) and elastic-transport (app/search.py via app/__init__.py Elasticsearch client). |
| flask | 3.0.0 | 1 | direct: Framework for the whole app (app/__init__.py create_app, all blueprints/routes). |
| flask-httpauth | 4.8.0 | 1 | direct: app/api/auth.py: basic_auth (verify_password, basic_auth_error), token_auth (verify_token, token_auth_error); used by app/api/tokens.py and app/api/users.py. |
| gunicorn | 21.2.0 | 2 | not imported: Production WSGI server launched from Procfile and boot.sh; no app module imports it. |
| httpie | 3.2.2 | 1 | not imported: CLI HTTP client used manually to exercise the API; no app module imports it. |
| idna | 3.4 | 2 | transitive: Hostname encoding for requests/urllib3 (app/translate.py:translate) and email-validator. |
| jinja2 | 3.1.2 | 5 | direct (via Flask): Template engine for all render_template calls (app/templates/*, e.g. app/auth/routes.py:login). |
| mako | 1.3.0 | 1 | transitive: Alembic migration script templates (flask db migrate); not used at app runtime. |
| pygments | 2.17.1 | 1 | transitive: Dependency of rich/httpie; no app module imports it. |
| pyjwt | 2.8.0 | 15 | direct: app/models.py: User.get_reset_password_token (jwt.encode), User.verify_reset_password_token (jwt.decode). |
| python-dotenv | 1.0.0 | 1 | direct: config.py module level: load_dotenv(os.path.join(basedir, ".env")) feeding Config. |
| requests | 2.31.0 | 3 | direct: app/translate.py:translate (requests.post to MS Translator). |
| setuptools | 68.2.2 | 4 | not imported: Packaging/build tool; no app module imports it. |
| werkzeug | 3.0.1 | 7 | direct: app/models.py User.set_password/check_password (werkzeug.security); app/api/errors.py error_response/handle_exception (werkzeug.http, werkzeug.exceptions); Flask request/redirect handling (e.g. app/auth/routes.py:login). |

## Dependency findings (pip-audit, deduplicated)

| ID | Package | Pinned | Advisory | Aliases | Fix versions | Golden units |
|---|---|---|---|---|---|---|
| D01 | aiosmtpd | 1.4.4.post2 | PYSEC-2024-221 | CVE-2024-27305, GHSA-pr2m-px7j-xg65 | 1.4.5 | - |
| D02 | aiosmtpd | 1.4.4.post2 | PYSEC-2026-1111 | CVE-2024-34083, GHSA-wgjv-9j3q-jhg8 | 1.4.6 | - |
| D03 | certifi | 2023.11.17 | PYSEC-2024-230 | CVE-2024-39689, GHSA-248v-346w-9cwc | 2024.7.4 | U05 |
| D04 | certifi | 2023.11.17 | PYSEC-2026-4320 | GHSA-6q48-6c7w-9gw2 | 2026.10.18 | U05 |
| D05 | dnspython | 2.4.2 | PYSEC-2026-1307 | CVE-2023-29483, GHSA-3rq5-2g8h-59hc | 2.6.1 | - |
| D06 | dnspython | 2.4.2 | CVE-2026-114605 | GHSA-45c3-73f7-pv4m | 2.9.0 | - |
| D07 | urllib3 | 2.1.0 | PYSEC-2026-141 | CVE-2026-44431, GHSA-qccp-gfcp-xxvc | 2.7.0 | U05 |
| D08 | urllib3 | 2.1.0 | PYSEC-2026-1999 | CVE-2025-50181, GHSA-pq67-6m6q-mj2v | 2.5.0 | U05 |
| D09 | urllib3 | 2.1.0 | PYSEC-2026-1998 | CVE-2025-66418, GHSA-gm62-xv2j-4w53 | 2.6.0 | U05 |
| D10 | urllib3 | 2.1.0 | PYSEC-2026-1995 | CVE-2024-37891, GHSA-34jh-p97f-mpxf | 1.26.19, 2.2.2 | U05 |
| D11 | urllib3 | 2.1.0 | PYSEC-2026-1994 | CVE-2025-66471, GHSA-2xpw-w6gg-jr37 | 2.6.0 | U05 |
| D12 | urllib3 | 2.1.0 | PYSEC-2026-1996 | CVE-2026-21441, GHSA-38jv-5279-wg99 | 2.6.3 | U05 |
| D13 | urllib3 | 2.1.0 | PYSEC-2026-4177 | CVE-2026-97689, GHSA-vxq7-64xx-v4gw | 2.8.0 | U05 |
| D14 | urllib3 | 2.1.0 | PYSEC-2026-4175 | CVE-2026-97687, GHSA-8988-9cw3-xx77 | 2.8.0 | U05 |
| D15 | flask | 3.0.0 | PYSEC-2026-2151 | CVE-2026-27205, GHSA-68rp-wp8r-4726 | 3.1.3 | U13, U14 |
| D16 | flask-httpauth | 4.8.0 | PYSEC-2026-2152 | CVE-2026-34531, GHSA-p44q-vqpr-4xmg | 4.8.1 | U10, U11 |
| D17 | gunicorn | 21.2.0 | PYSEC-2026-1434 | CVE-2024-1135, GHSA-w3h3-4rj7-4ph4 | 22.0.0 | - |
| D18 | gunicorn | 21.2.0 | PYSEC-2026-1433 | CVE-2024-6827, GHSA-hc5x-x2vx-497g | 22.0.0 | - |
| D19 | httpie | 3.2.2 | PYSEC-2023-242 | CVE-2023-48052, GHSA-8r96-8889-qg2x | 3.2.3 | - |
| D20 | idna | 3.4 | PYSEC-2024-60 | CVE-2024-3651, GHSA-jjg7-2v4v-x38h | 3.7 | U05 |
| D21 | idna | 3.4 | PYSEC-2026-215 | CVE-2026-45409, GHSA-65pc-fj4g-8rjx | 3.15 | U05 |
| D22 | jinja2 | 3.1.2 | PYSEC-2026-1473 | CVE-2024-22195, GHSA-h5c8-rqwp-cp95 | 3.1.3 | U13 |
| D23 | jinja2 | 3.1.2 | PYSEC-2026-1471 | CVE-2025-27516, GHSA-cpwx-vrp4-4pq7 | 3.1.6 | U13 |
| D24 | jinja2 | 3.1.2 | PYSEC-2026-1474 | CVE-2024-34064, GHSA-h75v-3vvj-5mfj | 3.1.4 | U13 |
| D25 | jinja2 | 3.1.2 | PYSEC-2026-1475 | CVE-2024-56326, GHSA-q2x7-8rv6-6q7h | 3.1.5 | U13 |
| D26 | jinja2 | 3.1.2 | PYSEC-2026-1472 | CVE-2024-56201, GHSA-gmj6-6f8f-6699 | 3.1.5 | U13 |
| D27 | mako | 1.3.0 | PYSEC-2026-2617 | CVE-2026-44307, GHSA-2h4p-vjrc-8xpq | 1.3.12 | - |
| D28 | pygments | 2.17.1 | PYSEC-2026-2987 | CVE-2026-4539, GHSA-5239-wwwm-4pmq | 2.20.0 | - |
| D29 | pyjwt | 2.8.0 | PYSEC-2026-120 | CVE-2026-32597, GHSA-752w-5fwx-jx9f | 2.12.0 | U06, U07 |
| D30 | pyjwt | 2.8.0 | PYSEC-2025-183 | CVE-2025-45768 | (none) | U06, U07 |
| D31 | pyjwt | 2.8.0 | PYSEC-2026-175 | CVE-2026-48522, GHSA-993g-76c3-p5m4 | 2.13.0 | U06, U07 |
| D32 | pyjwt | 2.8.0 | PYSEC-2026-177 | CVE-2026-48524, GHSA-fhv5-28vv-h8m8 | 2.13.0 | U06, U07 |
| D33 | pyjwt | 2.8.0 | PYSEC-2026-179 | CVE-2026-48526, GHSA-xgmm-8j9v-c9wx | 2.13.0 | U06, U07 |
| D34 | pyjwt | 2.8.0 | PYSEC-2026-178 | CVE-2026-48525, GHSA-w7vc-732c-9m39 | 2.13.0 | U06, U07 |
| D35 | pyjwt | 2.8.0 | PYSEC-2026-4145 | CVE-2026-102268, GHSA-ffc3-869f-jxw9 | 2.14.0 | U06, U07 |
| D36 | pyjwt | 2.8.0 | PYSEC-2026-4149 | CVE-2026-102271, GHSA-p4g4-x82p-q773 | 2.14.0 | U06, U07 |
| D37 | pyjwt | 2.8.0 | PYSEC-2026-4144 | CVE-2026-102267, GHSA-9v7f-9g4p-ffgj | 2.14.0 | U06, U07 |
| D38 | pyjwt | 2.8.0 | PYSEC-2026-4148 | CVE-2026-102270, GHSA-jwrc-g2q2-pq5p | 2.14.0 | U06, U07 |
| D39 | pyjwt | 2.8.0 | PYSEC-2026-4140 | CVE-2026-101917, GHSA-2gx3-rcp4-g85q | 2.14.0 | U06, U07 |
| D40 | pyjwt | 2.8.0 | PYSEC-2026-4141 | CVE-2026-101918, GHSA-42vr-xj54-vc7v | 2.15.0 | U06, U07 |
| D41 | pyjwt | 2.8.0 | PYSEC-2026-4147 | CVE-2026-102269, GHSA-hxm8-2xgr-2p9m | 2.14.0 | U06, U07 |
| D42 | pyjwt | 2.8.0 | PYSEC-2026-4183 | CVE-2026-102275, GHSA-x33g-cr3x-6449 | 2.15.0 | U06, U07 |
| D43 | pyjwt | 2.8.0 | GHSA-pxh4-856f-4h89 |  | 2.14.0 | U06, U07 |
| D44 | python-dotenv | 1.0.0 | PYSEC-2026-2270 | CVE-2026-28684, GHSA-mf9w-mj56-hr94 | 1.2.2 | U12 |
| D45 | requests | 2.31.0 | PYSEC-2026-1873 | CVE-2024-35195, GHSA-9wx4-h78v-vm56 | 2.32.0 | U05 |
| D46 | requests | 2.31.0 | PYSEC-2026-1872 | CVE-2024-47081, GHSA-9hjg-9r4m-mvj7 | 2.32.4 | U05 |
| D47 | requests | 2.31.0 | PYSEC-2026-2275 | CVE-2026-25645, GHSA-gc5v-m9x4-r6x2 | 2.33.0 | U05 |
| D48 | setuptools | 68.2.2 | PYSEC-2025-49 | BIT-setuptools-2025-47273, CVE-2025-47273, GHSA-5rjg-fvgr-3xxf | 78.1.1 | - |
| D49 | setuptools | 68.2.2 | PYSEC-2026-1918 | BIT-setuptools-2024-6345, CVE-2024-6345, GHSA-cx63-2mw6-8hw5 | 70.0.0 | - |
| D50 | setuptools | 68.2.2 | PYSEC-2026-3447 | BIT-setuptools-2026-59890, CVE-2026-59890, GHSA-h35f-9h28-mq5c | 83.0.0 | - |
| D51 | setuptools | 68.2.2 | GHSA-xmj3-9gf7-h52w |  | 84.1.0 | - |
| D52 | werkzeug | 3.0.1 | PYSEC-2026-2045 | CVE-2024-49766, GHSA-f9vj-2wh5-fj8j | 3.0.6 | U08, U09, U10, U13, U14 |
| D53 | werkzeug | 3.0.1 | PYSEC-2026-2046 | CVE-2025-66221, GHSA-hgf8-39gv-g3f2 | 3.1.4 | U08, U09, U10, U13, U14 |
| D54 | werkzeug | 3.0.1 | PYSEC-2026-2044 | CVE-2026-21860, GHSA-87hc-h4r5-73f7 | 3.1.5 | U08, U09, U10, U13, U14 |
| D55 | werkzeug | 3.0.1 | PYSEC-2026-2043 | CVE-2024-34069, GHSA-2g68-c3qc-8985 | 3.0.3 | U08, U09, U10, U13, U14 |
| D56 | werkzeug | 3.0.1 | PYSEC-2026-2320 | CVE-2026-27199, GHSA-29vq-49wr-vm6x | 3.1.6 | U08, U09, U10, U13, U14 |
| D57 | werkzeug | 3.0.1 | PYSEC-2026-3417 | CVE-2024-49767, GHSA-q34m-jh98-gwm2, PYSEC-2026-1860 | 3.0.6 | U08, U09, U10, U13, U14 |
| D58 | werkzeug | 3.0.1 | PYSEC-2026-4312 | CVE-2026-102598, GHSA-g6x2-hccm-hh4m | 3.1.9 | U08, U09, U10, U13, U14 |
