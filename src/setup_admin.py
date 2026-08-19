import sqlite3, getpass, os
from werkzeug.security import generate_password_hash
def setup_admin():
    conn = sqlite3.connect("/opt/micro-dfir/siem.db"); cursor = conn.cursor()
    if not cursor.execute("SELECT * FROM users WHERE username='admin'").fetchone():
        print("\n=== Security Setup ===")
        while True:
            pwd = getpass.getpass("Enter new password for 'admin' user: ")
            if pwd == getpass.getpass("Confirm password: ") and len(pwd) > 4: break
            print("Mismatch or too short. Try again.")
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES ('admin', ?, 'admin')", (generate_password_hash(pwd),))
        conn.commit(); print("[+] Admin user created.\n")
    conn.close()
if __name__ == "__main__": setup_admin()
