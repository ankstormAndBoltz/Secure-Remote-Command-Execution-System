"""
UPDATED: Client-side logging implementation.
Logs include timestamp, username, command, and status.
"""

import os
from datetime import datetime


# UPDATED: Logger was empty - now implements write_log with required fields
def write_log(username: str, command: str, status: str, message: str = ""):
    """
    Write log entry with timestamp, username, command, and status.
    Logs are appended to client_logs.txt in the project directory.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"{timestamp} | {username} | {command} | {status} | {message}\n"

    # UPDATED: Use absolute path to avoid fragile relative paths
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    log_dir = os.path.join(base_dir, "logs")
    log_file = os.path.join(log_dir, "client.log")

    try:
        os.makedirs(log_dir, exist_ok=True)
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(entry)
    except OSError as e:
        print(f"[WARN] Could not write log: {e}")
