# Five security flaws: vulnerable versus fixed

The **before** snippets are educational examples only; they are NOT executed by the application. All **after** snippets appear in `app.py`. Tests are in `tests/test_security.py`.

## 1. Injection (SQL injection)
**Before (unsafe):**
```python
query = f"SELECT id FROM users WHERE username='{username}' AND password='{password}'"
conn.execute(query)
```
**After (safe):**
```python
row = conn.execute("SELECT id,salt,password_hash FROM users WHERE username=?", (username,)).fetchone()
```
**Why:** placeholders bind untrusted input as values rather than executable SQL. Password verification happens separately using PBKDF2.
**Proof:** `test_sql_injection_blocked` uses `alice' OR 1=1 --` and verifies login fails.

## 2. Broken access control / IDOR
**Before (unsafe):**
```python
conn.execute("SELECT id,body FROM notes WHERE id=?", (note_id,)).fetchone()
```
**After (safe):**
```python
conn.execute("SELECT id,body FROM notes WHERE id=? AND owner_id=?", (note_id,user_id)).fetchone()
```
**Why:** ownership is enforced by the server on every note lookup, not merely in the UI.
**Proof:** `test_broken_access_control_blocked` shows Bob cannot read Alice's note.

## 3. Cryptographic failures (plaintext password storage)
**Before (unsafe):**
```python
conn.execute("INSERT INTO users(username,password) VALUES (?,?)", (username,password))
```
**After (safe):**
```python
salt = secrets.token_hex(16)
digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 600000).hex()
conn.execute("INSERT INTO users(username,salt,password_hash) VALUES (?,?,?)", (username,salt,digest))
```
**Why:** per-user random salt and a slow password KDF avoid plaintext disclosure and raise offline guessing costs.
**Proof:** `test_passwords_are_salted_and_hashed` inspects the stored hash and checks wrong-password rejection.

## 4. Injection (stored XSS)
**Before (unsafe):**
```python
html_page = '<p>' + note_body + '</p>'
```
**After (safe):**
```python
html_page = '<p class="note">' + html.escape(note_body, quote=True) + '</p>'
```
**Why:** encoding user text before HTML insertion stops markup/script execution in the HTML text context.
**Proof:** `test_xss_escaped` confirms `<script>` is escaped.

## 5. Security misconfiguration / path traversal
**Before (unsafe):**
```python
file_path = os.path.join('exports', filename)
open(file_path).read()
```
**After (safe):**
```python
filename = safe_export_name(filename)
# Only validated simple names may be used under a trusted export directory.
```
**Why:** the validation rejects slashes, dot-dot, hidden names, and other non-allowlisted characters. This is a validated utility, not a live export endpoint.
**Proof:** `test_path_traversal_blocked` rejects `../secrets.txt` and `/etc/passwd`.

## Scope notes
This is a small **demonstration** app, not a production service. It binds only to loopback; cookies omit `Secure` to support local HTTP. For production use HTTPS, `Secure` cookies, durable session storage, CSRF tokens, request throttling, and appropriate logging. Path traversal is demonstrated and tested in a utility; no file export feature is exposed.
