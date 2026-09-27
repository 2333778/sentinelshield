import csv
from datetime import datetime
import os

LOG_FILE = "logs/events.csv"

def log_event(ip, method, path, payload, category, action, reason, status_code):
    os.makedirs("logs", exist_ok=True)
    file_exists = os.path.isfile(LOG_FILE)
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["timestamp", "ip", "method", "path", "payload",
                             "category", "action", "reason", "status_code"])
        writer.writerow([
            datetime.now().isoformat(),
            ip, method, path, payload,
            category, action, reason, status_code
        ])