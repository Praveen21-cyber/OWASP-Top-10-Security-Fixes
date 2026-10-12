import sqlite3
import tempfile
import unittest
from pathlib import Path
from app import init_db, connect, create_user, authenticate, add_note, get_note, render_note, safe_export_name

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.db=str(Path(self.temp.name)/'test.db')
        init_db(self.db)
        self.conn=connect(self.db)
        self.alice=create_user(self.conn,'alice','correct-horse-battery')
        self.bob=create_user(self.conn,'bob','another-strong-password')
        self.conn.commit()
    def tearDown(self):
        self.conn.close();self.temp.cleanup()
    def test_sql_injection_blocked(self):
        self.assertIsNone(authenticate(self.conn,"alice' OR 1=1 --",'anything'))
        self.assertEqual(authenticate(self.conn,'alice','correct-horse-battery'),self.alice)
    def test_broken_access_control_blocked(self):
        note_id=add_note(self.conn,self.alice,'private')
        self.assertIsNone(get_note(self.conn,self.bob,note_id))
        self.assertEqual(get_note(self.conn,self.alice,note_id)['body'],'private')
    def test_passwords_are_salted_and_hashed(self):
        row=self.conn.execute('SELECT salt,password_hash FROM users WHERE id=?',(self.alice,)).fetchone()
        self.assertNotEqual(row['password_hash'],'correct-horse-battery')
        self.assertEqual(len(row['salt']),32)
        self.assertIsNone(authenticate(self.conn,'alice','wrong-password'))
    def test_xss_escaped(self):
        value='<script>alert(1)</script>'
        self.assertNotIn('<script>',render_note(value))
        self.assertIn('&lt;script&gt;',render_note(value))
    def test_path_traversal_blocked(self):
        for value in ('../secrets.txt','../../etc/passwd','/etc/passwd','..','hidden/notes'):
            with self.subTest(value=value),self.assertRaises(ValueError): safe_export_name(value)
        self.assertEqual(safe_export_name('notes.txt'),'notes.txt')

if __name__=='__main__': unittest.main()
