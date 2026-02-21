from datetime import datetime

LOG_FILE = "client/logs.txt"

def write_log(username, server_ip, command, status):
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = f"{time} | USER={username} | SERVER={server_ip} | CMD={command} | STATUS={status}\n"

    with open(LOG_FILE, "a") as file:
        file.write(log_entry)

