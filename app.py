"""Small intentionally scoped secure notes web application (Python standard library)."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from http.cookies import SimpleCookie
import html
import json
import os
import secrets
import sqlite3
import hashlib
import hmac

DB = os.environ.get("NOTES_DB", "notes.db")
SESSIONS = {}  # Demo only: resets on restart; use a persistent server-side store in production.

def connect(db=DB):
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db=DB):
    with connect(db) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL)")
        conn.execute("CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL, body TEXT NOT NULL, FOREIGN KEY(owner_id) REFERENCES users(id))")

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600000).hex()
    return salt, digest

def create_user(conn, username, password):
    if not (3 <= len(username) <= 40 and username.isalnum() and len(password) >= 12):
        raise ValueError("Username must be 3-40 alphanumeric characters and password at least 12 characters")
    salt, digest = hash_password(password)
    return conn.execute("INSERT INTO users(username,salt,password_hash) VALUES (?,?,?)", (username,salt,digest)).lastrowid

def authenticate(conn, username, password):
    row = conn.execute("SELECT id,salt,password_hash FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        # Equalize the expensive hashing step for unknown users.
        hash_password(password, '00'*16)
        return None
    _, candidate = hash_password(password, row['salt'])
    return row['id'] if hmac.compare_digest(candidate, row['password_hash']) else None

def add_note(conn, user_id, body):
    if not body or len(body) > 2000:
        raise ValueError("Note must be 1-2000 characters")
    return conn.execute("INSERT INTO notes(owner_id,body) VALUES (?,?)", (user_id,body)).lastrowid

def get_note(conn, user_id, note_id):
    return conn.execute("SELECT id,body FROM notes WHERE id=? AND owner_id=?", (note_id,user_id)).fetchone()

def render_note(body):
    return '<p class="note">' + html.escape(body, quote=True) + '</p>'

def safe_export_name(name):
    # Export supports only a simple filename, not arbitrary filesystem paths.
    if not name or len(name)>64 or not all(c.isalnum() or c in '._-' for c in name) or name in ('.','..') or name.startswith('.'):
        raise ValueError("Invalid export filename")
    return name

class Handler(BaseHTTPRequestHandler):
    def respond(self, code, content, content_type='text/html; charset=utf-8', cookie=None):
        payload=content.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(payload)))
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
        self.send_header('Cache-Control','no-store')
        if cookie: self.send_header('Set-Cookie',cookie)
        self.end_headers();self.wfile.write(payload)
    def form(self):
        size=int(self.headers.get('Content-Length','0'))
        if size>8192: raise ValueError('Request too large')
        return {k:v[0] for k,v in parse_qs(self.rfile.read(size).decode('utf-8'),keep_blank_values=True).items()}
    def user(self):
        cookie=SimpleCookie()
        try: cookie.load(self.headers.get('Cookie',''))
        except Exception: return None
        sid=cookie.get('session')
        return SESSIONS.get(sid.value) if sid else None
    def page(self, body):
        self.respond(200, '<!doctype html><meta charset="utf-8"><title>Secure Notes</title><h1>Secure Notes</h1>'+body)
    def do_GET(self):
        url=urlsplit(self.path); user=self.user()
        if url.path=='/':
            if not user:
                return self.page('<form method="post" action="/login"><input name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><button>Log in</button></form><p>Register via POST /register (username, password).</p>')
            with connect() as conn:
                rows=conn.execute('SELECT id,body FROM notes WHERE owner_id=? ORDER BY id',(user,)).fetchall()
            notes=''.join('<article>Note #'+str(r['id'])+': '+render_note(r['body'])+'</article>' for r in rows)
            return self.page(notes+'<form method="post" action="/notes"><textarea name="body"></textarea><button>Add note</button></form><form method="post" action="/logout"><button>Log out</button></form>')
        if url.path=='/note':
            if not user: return self.respond(401,'Login required')
            try: note_id=int(parse_qs(url.query)['id'][0])
            except (ValueError,KeyError,IndexError): return self.respond(400,'Invalid ID')
            with connect() as conn: note=get_note(conn,user,note_id)
            return self.page(render_note(note['body'])) if note else self.respond(404,'Not found')
        self.respond(404,'Not found')
    def do_POST(self):
        path=urlsplit(self.path).path
        try: form=self.form()
        except (ValueError,UnicodeDecodeError): return self.respond(400,'Invalid request')
        if path=='/register':
            try:
                with connect() as conn: create_user(conn,form.get('username',''),form.get('password',''))
            except (ValueError,sqlite3.IntegrityError): return self.respond(400,'Invalid registration')
            return self.respond(201,'Account created')
        if path=='/login':
            with connect() as conn: user=authenticate(conn,form.get('username',''),form.get('password',''))
            if user is None: return self.respond(401,'Invalid credentials')
            sid=secrets.token_urlsafe(32); SESSIONS[sid]=user
            return self.respond(200,'Logged in',cookie='session='+sid+'; HttpOnly; SameSite=Strict; Path=/')
        if path=='/logout':
            cookie=SimpleCookie()
            try: cookie.load(self.headers.get('Cookie',''))
            except Exception: pass
            if cookie.get('session'): SESSIONS.pop(cookie['session'].value,None)
            return self.respond(200,'Logged out',cookie='session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/')
        if path=='/notes':
            user=self.user()
            if not user: return self.respond(401,'Login required')
            # SameSite cookie plus strict Origin validation protects state-changing browser requests.
            origin=self.headers.get('Origin')
            host=self.headers.get('Host','')
            if origin and origin not in ('http://'+host,'https://'+host): return self.respond(403,'Origin rejected')
            try:
                with connect() as conn: note_id=add_note(conn,user,form.get('body',''))
            except ValueError: return self.respond(400,'Invalid note')
            return self.respond(201,'Created note '+str(note_id))
        self.respond(404,'Not found')

if __name__=='__main__':
    init_db()
    print('Open http://127.0.0.1:8000')
    ThreadingHTTPServer(('127.0.0.1',8000),Handler).serve_forever()
