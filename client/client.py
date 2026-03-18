"""
Secure Remote Command Execution System - Client
UPDATED: Full rewrite with SSL/TLS, JSON protocol, message framing, server-side auth.
"""
import json
from multiprocessing import context
import os
import socket
import ssl
import struct
import sys

# UPDATED: Ensure client/auth is on path when run from project root
_sys_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _sys_path not in sys.path:
    sys.path.insert(0, _sys_path)

from auth.auth import get_credentials
from logger import write_log


SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
SOCKET_TIMEOUT = 30

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
    """
    # Read length prefix (4 bytes, big-endian unsigned int)
    length_data = _recv_exact(sock, 4)
    if not length_data:
        return None
    length = struct.unpack(">I", length_data)[0]
    if length > 1024 * 1024:  # Max 1MB message
        raise ValueError("Message too large")
    payload = _recv_exact(sock, length)
    if not payload:
        return None
    return json.loads(payload.decode("utf-8"))

def _recv_exact(sock, n):
    """Read exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

# --------------- UPDATED: SSL/TLS connection ---------------

def create_secure_socket():
    """
    Create TCP socket, wrap with SSL/TLS.
    UPDATED: Client now uses SSLContext and wrap_socket like server.
    """
    # Create default SSL context for client
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # UPDATED: Load CA/cert for server verification (use cert.pem for self-signed)
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    cert_path = os.path.join(project_root, "server", "cert.pem")
    if os.path.exists(cert_path):
        context.load_verify_locations(cert_path)
    else:
        # Skip cert verification for self-signed (dev only)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.settimeout(SOCKET_TIMEOUT)
    raw_socket.connect((SERVER_IP, SERVER_PORT))
    # UPDATED: Wrap with TLS
    secure_socket = context.wrap_socket(raw_socket, server_hostname="localhost")
    return secure_socket

# --------------- UPDATED: Unified JSON protocol ---------------

def login_and_connect():
    """
    UPDATED: Send login request to server, receive response.
    Returns (secure_socket, username) on success, (None, None) on failure.
    """
    username, password = get_credentials()

    try:
        sock = create_secure_socket()
        print("Connected to server (TLS)")

        # UPDATED: Send login as JSON
        login_msg = {
            "type": "login",
            "data": {
                "username": username,
                "password": password,
            },
        }
        send_message(sock, login_msg)

        # UPDATED: Receive and parse JSON response
        response = recv_message(sock)
        if response is None:
            print("Connection closed by server")
            sock.close()
            write_log(username, "LOGIN", "FAILED", "No response")
            return None, None

        msg_type = response.get("type")
        data = response.get("data", {})

        if msg_type == "login_success":
            print("Login Successful ✅")
            write_log(username, "LOGIN", "SUCCESS", "")
            return sock, username
        elif msg_type == "login_failure":
            reason = data.get("message", "Invalid credentials")
            print(f"Login Failed ❌ {reason}")
            write_log(username, "LOGIN", "FAILED", reason)
            sock.close()
            return None, None
        else:
            print("Unexpected response:", response)
            sock.close()
            return None, None

    except ssl.SSLError as e:
        print("SSL handshake failed:", e)
        write_log(username, "LOGIN", "FAILED", str(e))
        return None, None
    except ConnectionRefusedError:
        print("Connection refused. Is the server running?")
        return None, None
    except OSError as e:
        print("Connection error:", e)
        return None, None

def run_command_loop(sock, username):
    """
    UPDATED: Command loop using JSON protocol and message framing.
    """
    print("Enter commands (ls, pwd, date, whoami). Type 'exit' to quit.")
    while True:
        try:
            command = input("> ").strip()
            if not command:
                continue
            if command.lower() == "exit":
                break

            # UPDATED: Send command as JSON
            cmd_msg = {
                "type": "command",
                "data": {"command": command},
            }
            send_message(sock, cmd_msg)

            # UPDATED: Receive JSON response
            response = recv_message(sock)
            if response is None:
                print("Server closed connection")
                break

            msg_type = response.get("type")
            data = response.get("data", {})

            if msg_type == "command_output":
                output = data.get("output", "")
                exit_code = data.get("exit_code", 0)
                print(output)
                if exit_code == 0:
                    write_log(username, command, "EXECUTED", "success")
                else:
                    write_log(username, command, "FAILED", f"exit_code={exit_code}")
            elif msg_type == "error":
                err_msg = data.get("message", "Unknown error")
                print("Error:", err_msg)
                write_log(username, command, "FAILED", err_msg)

        except (ConnectionResetError, BrokenPipeError):
            print("Connection lost")
            break
        except json.JSONDecodeError as e:
            print("Invalid response from server:", e)
            break

    sock.close()
    print("Disconnected.")

def main():
    # UPDATED: Login happens on server; client sends credentials over TLS
    sock, username = login_and_connect()
    if sock and username:
        run_command_loop(sock, username)
    else:
        print("Exiting program.")
        sys.exit(1)

if __name__ == "__main__":
    main()
