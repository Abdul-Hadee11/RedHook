import os
import sys
import sqlite3
from core.config import DB_NAME  # Optional: if you use a config.py to store "redhook_analysis.db"

APP_NAME = "RedHook"
DB_FILENAME = DB_NAME if 'DB_NAME' in globals() else "redhook_analysis.db"

# Determine user data path
def get_user_data_dir():
    if sys.platform == "win32":
        return os.path.join(os.environ.get("APPDATA", os.getcwd()), APP_NAME)
    elif sys.platform == "darwin":
        return os.path.expanduser(f"~/Library/Application Support/{APP_NAME}")
    else:
        return os.path.expanduser(f"~/.{APP_NAME.lower()}")

# Ensure DB exists in a writable location
def ensure_db_exists():
    user_data_dir = get_user_data_dir()
    os.makedirs(user_data_dir, exist_ok=True)
    user_db_path = os.path.join(user_data_dir, DB_FILENAME)

    if not os.path.exists(user_db_path):
        try:
            # If packaged, look inside PyInstaller temp dir
            base_dir = getattr(sys, "_MEIPASS", os.path.abspath("."))
            bundled_db_path = os.path.join(base_dir, DB_FILENAME)
            if os.path.exists(bundled_db_path):
                import shutil
                shutil.copy(bundled_db_path, user_db_path)
                print(f"[✔] Copied bundled DB to: {user_db_path}")
            else:
                print(f"[!] Bundled DB not found. Creating a new empty DB at: {user_db_path}")
        except Exception as e:
            print(f"[!] Failed to prepare DB: {e}")
    
    return user_db_path

# Final DB path used in all connections
DB_PATH = ensure_db_exists()

# Create a DB connection
def get_connection():
    return sqlite3.connect(DB_PATH)

# Initialize the database
def initialize_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT,
            sender TEXT,
            timestamp TEXT,
            verdict TEXT,
            tactics TEXT,
            urls TEXT,
            explanation TEXT
        )
    """)
    conn.commit()
    conn.close()

# Save one email analysis result
def save_analysis(subject, sender, timestamp, verdict, tactics, urls, explanation):
    tactics_str = ", ".join(tactics) if isinstance(tactics, list) else str(tactics)
    urls_str = ", ".join(urls) if isinstance(urls, list) else str(urls)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO analyses (subject, sender, timestamp, verdict, tactics, urls, explanation)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (subject, sender, timestamp, verdict, tactics_str, urls_str, explanation))
    conn.commit()
    conn.close()

# Fetch all records
def fetch_all_analyses():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, subject, sender, timestamp, verdict, tactics, urls, explanation FROM analyses ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

# Delete all records
def delete_all_emails():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM analyses")
    conn.commit()
    conn.close()

# Delete one record by ID
def delete_email_by_id(email_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM analyses WHERE id = ?", (email_id,))
    conn.commit()
    conn.close()

# Ensure initialized
initialize_db()
