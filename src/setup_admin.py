import sqlite3, os
from werkzeug.security import generate_password_hash
def setup_admin():
    conn = sqlite3.connect("/opt/micro-dfir/siem.db")
    cursor = conn.cursor()
    if not cursor.execute("SELECT * FROM users WHERE username='admin'").fetchone():
        print("\n[*] Creating default Administrator account...")
        pwd_hash = generate_password_hash("Admin123!")
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES ('admin', ?, 'admin')", (pwd_hash,))
        conn.commit()
        print("[+] Admin user created. Username: admin | Password: Admin123!")
    conn.close()
if __name__ == "__main__": setup_admin()
