"""
Secure Remote Command Execution System - Server
UPDATED: Full rewrite with SSL/TLS, JSON protocol, message framing,
server-side authentication, PBKDF2, proper logging, and threading.
"""

import json
import hashlib
import os
import secrets
import socket
import ssl
import struct
import subprocess
import threading
import datetime

from ssl_config import create_server_ssl_context

HOST = "0.0.0.0"
PORT = 5000

# UPDATED: Allow only these commands; use shell=False
ALLOWED_COMMANDS = ["ls", "pwd", "date", "whoami"]

# UPDATED: Absolute path for audit log
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_DB = os.path.join(BASE_DIR, "users.txt")
LOG_DIR = os.path.join(BASE_DIR, "..", "logs")
LOG_FILE = os.path.join(LOG_DIR, "audit.log")
SOCKET_TIMEOUT = 60

# --------------- UPDATED: Message framing (length-prefixed protocol) ---------------

def send_message(sock, obj):
    """
    Serialize JSON, send 4-byte length (big-endian), then payload.
    """
    payload = json.dumps(obj).encode("utf-8")
    length = len(payload)
    sock.sendall(struct.pack(">I", length))
    sock.sendall(payload)

def recv_message(sock):
    """
    Read 4-byte length, then read payload, return parsed JSON object.
    Returns None on connection close.
    """
    try:
        length_data = _recv_exact(sock, 4)
        if not length_data:
            return None
        length = struct.unpack(">I", length_data)[0]
        if length > 1024 * 1024:
            return None  # Reject oversized messages
        payload = _recv_exact(sock, length)
        if not payload:
            return None
        return json.loads(payload.decode("utf-8"))
    except (ConnectionResetError, BrokenPipeError, json.JSONDecodeError):
        return None

def _recv_exact(sock, n):
    """Read exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

# --------------- UPDATED: PBKDF2 password hashing ---------------

def hash_password(password: str, salt: bytes = None) -> tuple:
    """Hash password using PBKDF2-HMAC-SHA256 with 100,000 iterations."""
    if salt is None:
        salt = secrets.token_bytes(32)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100000,
    )
    return salt.hex(), key.hex()

def verify_password(input_password: str, stored_salt_hex: str, stored_hash: str) -> bool:
    """Verify input password against stored salt and hash."""
    salt = bytes.fromhex(stored_salt_hex)
    _, computed = hash_password(input_password, salt)
    return secrets.compare_digest(computed, stored_hash)

def ensure_user_db():
    """Create users.txt if missing; add default user."""
    if not os.path.exists(USER_DB):
        os.makedirs(os.path.dirname(USER_DB) or ".", exist_ok=True)
        # UPDATED: Create default user with PBKDF2
        salt_hex, hash_hex = hash_password("admin123")
        with open(USER_DB, "w") as f:
            f.write(f"admin:{salt_hex}:{hash_hex}\n")

def verify_user(username: str, password: str) -> bool:
    """Verify credentials against user database."""
    if not os.path.exists(USER_DB):
        return False
    with open(USER_DB, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(":")
            if len(parts) != 3:
                continue
            stored_user, stored_salt, stored_hash = parts
            if stored_user == username:
                return verify_password(password, stored_salt, stored_hash)
    return False

def register_user(username: str, password: str):
    """Register a new user (for setup)."""
    salt_hex, hash_hex = hash_password(password)
    with open(USER_DB, "a") as f:
        f.write(f"{username}:{salt_hex}:{hash_hex}\n")

# --------------- UPDATED: Logging with absolute path ---------------

def log_audit(username: str, addr, command: str, status: str, message: str = ""):
    """Write audit log with timestamp, username, command, status."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"{timestamp} | {addr} | {username} | {command} | {status} | {message}\n"
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry)
    except OSError as e:
        print(f"[WARN] Audit log write failed: {e}")

# --------------- UPDATED: Command execution (shell=False) ---------------

def execute_command(command: str) -> tuple[str, int]:
    """
    Execute allowed command. Returns (output, exit_code).
    UPDATED: shell=False for security; only ALLOWED_COMMANDS.
    """
    cmd = command.strip().lower()
    # Split for commands like "ls -la" -> ["ls", "-la"]
    parts = command.strip().split()
    base_cmd = parts[0].lower() if parts else ""

    if base_cmd not in ALLOWED_COMMANDS:
        return "Error: Command not allowed", -1

    try:
        # UPDATED: shell=False for security
        # Map Unix commands to Windows equivalents when needed
        if os.name == "nt" and base_cmd in ("ls", "pwd"):
            cmd_list = ["cmd", "/c", "dir"] if base_cmd == "ls" else ["cmd", "/c", "cd"]
        else:
            cmd_list = parts if len(parts) > 1 else [base_cmd]
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            shell=False,
            timeout=10,
            cwd=os.getcwd(),
        )
        output = (result.stdout or result.stderr or b"").decode("utf-8", errors="replace")
        return output or "(no output)", result.returncode
    except FileNotFoundError:
        return f"Error: Command '{base_cmd}' not found (may require Linux/WSL)", -1
    except subprocess.TimeoutExpired:
        return "Error: Command timed out", -1
    except Exception as e:
        return str(e), -1

# --------------- UPDATED: Per-connection session (authenticated state) ---------------

def handle_client(conn: ssl.SSLSocket, addr):
    """
    Handle client connection. UPDATED: Requires login before commands.
    Maintains authenticated session per connection.
    """
    authenticated = False
    username = None

    # UPDATED: Set socket timeout for error handling
    conn.settimeout(SOCKET_TIMEOUT)

    print("[+] Client connected:", addr)

    while True:
        try:
            msg = recv_message(conn)
            if msg is None:
                break

            msg_type = msg.get("type")
            data = msg.get("data") or {}

            # UPDATED: Must login first
            if msg_type == "login":
                user = data.get("username", "").strip()
                password = data.get("password", "")

                if not user or not password:
                    send_message(conn, {"type": "login_failure", "data": {"message": "Missing credentials"}})
                    log_audit("(anonymous)", addr, "LOGIN", "FAILED", "Missing credentials")
                    continue

                if verify_user(user, password):
                    authenticated = True
                    username = user
                    send_message(conn, {"type": "login_success", "data": {"username": username}})
                    log_audit(username, addr, "LOGIN", "SUCCESS")
                    print(f"[AUTH] {username} logged in from {addr}")
                else:
                    send_message(conn, {"type": "login_failure", "data": {"message": "Invalid username or password"}})
                    log_audit(user, addr, "LOGIN", "FAILED", "Invalid credentials")

            elif msg_type == "command":
                if not authenticated:
                    send_message(conn, {
                        "type": "error",
                        "data": {"message": "Not authenticated. Send login first."},
                    })
                    continue

                command = data.get("command", "").strip()
                if not command:
                    send_message(conn, {"type": "command_output", "data": {"output": "", "exit_code": 0}})
                    continue

                output, exit_code = execute_command(command)
                response = {
                    "type": "command_output",
                    "data": {"output": output, "exit_code": exit_code},
                }
                send_message(conn, response)
                log_audit(username, addr, command, "EXECUTED" if exit_code == 0 else "FAILED")
                print(f"[CMD] {username}: {command}")

            else:
                send_message(conn, {"type": "error", "data": {"message": f"Unknown message type: {msg_type}"}})

        except ssl.SSLError as e:
            print("[SSL] Client error:", e)
            break
        except (ConnectionResetError, BrokenPipeError):
            break
        except Exception as e:
            print("Client error:", e)
            if username:
                log_audit(username, addr, "(error)", "ERROR", str(e))
            break

    conn.close()
    print("Client disconnected:", addr)

# --------------- UPDATED: Server startup with SSL ---------------

def start_server():
    """Start TLS server with threading for multiple clients."""
    ensure_user_db()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    # UPDATED: Use ssl_config for context
    context = create_server_ssl_context()

    print(f"[SECURE SERVER] Listening on {HOST}:{PORT} (TLS)")
    print("Waiting for clients...")

    while True:
        try:
            client_socket, addr = server_socket.accept()
            # UPDATED: Wrap with TLS before handling
            try:
                secure_conn = context.wrap_socket(client_socket, server_side=True)
            except ssl.SSLError as e:
                print("[SSL] Handshake failed:", e)
                client_socket.close()
                continue

            print("[SSL] Secure connection established with", addr)
            thread = threading.Thread(target=handle_client, args=(secure_conn, addr), daemon=True)
            thread.start()
        except KeyboardInterrupt:
            print("\nServer shutting down...")
            break
        except Exception as e:
            print("Accept error:", e)

    server_socket.close()


if __name__ == "__main__":
    start_server()
