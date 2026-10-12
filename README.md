# Task 03 — Fix OWASP Top 10 Issues in Real Code

A small **Python standard-library** notes app with five documented before/after security fixes and automated tests. No external packages required.

## Requirements
- Python 3.10+

## Run
```bash
python app.py
```
Open `http://127.0.0.1:8000` (local machine only). Register using the command below, then log in through the browser and add notes.

```bash
curl -X POST http://127.0.0.1:8000/register -d "username=alice&password=correct-horse-battery"
```

## Run the security tests
```bash
python -m unittest discover -s tests -v
```

## Security fixes and evidence
| # | Flaw | Fix | Automated test |
|---|---|---|---|
| 1 | SQL injection | Parameterized SQL queries | `test_sql_injection_blocked` |
| 2 | Broken access control / IDOR | Enforce `owner_id` on note lookup | `test_broken_access_control_blocked` |
| 3 | Plaintext password storage | Salted PBKDF2-SHA256, 600k iterations | `test_passwords_are_salted_and_hashed` |
| 4 | Stored cross-site scripting | Context-aware HTML escaping | `test_xss_escaped` |
| 5 | Path traversal | Allowlisted export filename validation | `test_path_traversal_blocked` |

**Before-and-after code and explanations:** [BEFORE_AFTER.md](BEFORE_AFTER.md).

## Design decisions and limitations
- The unsafe code is shown **only in documentation**; the runnable app contains fixes.
- File export is **not implemented**; the filename validator and its tests demonstrate the path traversal mitigation in isolation.
- Demo server binds to `127.0.0.1` and is not production-ready. Use HTTPS, Secure cookies, robust CSRF protection, persistent sessions, and rate limiting before public deployment.
- Use the test output as evidence; do not claim external lab completion.

## Submission
Push the project files to a **public GitHub repository**, then submit that repository URL to your internship portal.
