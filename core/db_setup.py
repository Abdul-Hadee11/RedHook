import sqlite3

# Connect to the database (creates if it doesn't exist)
conn = sqlite3.connect("redhook_analysis.db")
cursor = conn.cursor()

# Create table for storing email analysis history
cursor.execute("""
CREATE TABLE IF NOT EXISTS email_analysis (
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
print("✅ Database and table created successfully.")
