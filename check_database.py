
from database import get_db

conn = get_db()

tables = conn.execute("""
    SELECT name FROM sqlite_master
    WHERE type='table'
""").fetchall()

print("DATABASE TABLES:")

for table in tables:
    print(" -", table["name"])

conn.close()