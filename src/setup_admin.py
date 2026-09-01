import sqlite3, os
from werkzeug.security import generate_password_hash
def setup_admin():
    conn = sqlite3.connect("/opt/micro-dfir/siem.db")
    cursor = conn.cursor()
    if not cursor.execute("SELECT * FROM users WHERE username='admin'").fetchone():
        print("\n[*] Creating default Administrator account...")
        pwd_hash = generate_password_hash("Admin123!")
        cursor.execute("INSERT INTO users (username, password_hash, role, must_change_password) VALUES ('admin', ?, 'admin', 1)", (pwd_hash,))
        conn.commit()
        print("[+] Admin user created. Username: admin | Password: Admin123! (you'll be required to change it on first login)")
    conn.close()
if __name__ == "__main__": setup_admin()
