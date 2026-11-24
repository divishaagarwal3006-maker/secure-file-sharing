
from logger import log_activity
from database import get_db

# Insert a test activity
log_activity(
    user_id=1,
    action="UPLOAD",
    file_id=1,
    status="Success",
    details="Test file uploaded"
)

print("Activity logged successfully!")

# Check whether the activity was saved
conn = get_db()

logs = conn.execute(
    "SELECT * FROM activity_logs ORDER BY id DESC LIMIT 5"
).fetchall()

print("\nActivity Log Records:")

for log in logs:
    print(dict(log))

conn.close()
