"""
GUI client for secure multi-client remote command execution.
Run this file to use a desktop interface instead of CLI.
"""

import json
import os
import socket
import ssl
import struct
import sys
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter import scrolledtext

# Ensure project root is in sys.path for auth import
_sys_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _sys_path not in sys.path:
    sys.path.insert(0, _sys_path)

from logger import write_log


SOCKET_TIMEOUT = 30
MAX_MESSAGE_SIZE = 1024 * 1024


def send_message(sock, obj):
    payload = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(payload)))
    sock.sendall(payload)


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_message(sock):
    length_data = _recv_exact(sock, 4)
    if not length_data:
        return None
    length = struct.unpack(">I", length_data)[0]
    if length > MAX_MESSAGE_SIZE:
        raise ValueError("Message too large")
    payload = _recv_exact(sock, length)
    if not payload:
        return None
    return json.loads(payload.decode("utf-8"))


class CommandGUIClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Remote Command Client")
        self.root.geometry("980x620")
        self.root.minsize(860, 560)

        self.sock = None
        self.username = ""
        self.connected = False
        self.lock = threading.Lock()
        self.history = []
        self.history_index = 0

        self._build_ui()
        self._set_connected_ui(False)

    def _build_ui(self):
        self.style = ttk.Style()
        if "clam" in self.style.theme_names():
            self.style.theme_use("clam")

        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Server IP").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.server_ip_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(top, textvariable=self.server_ip_var, width=16).grid(row=0, column=1, sticky="w")

        ttk.Label(top, text="Port").grid(row=0, column=2, sticky="w", padx=(12, 6))
        self.port_var = tk.StringVar(value="5000")
        ttk.Entry(top, textvariable=self.port_var, width=8).grid(row=0, column=3, sticky="w")

        self.status_var = tk.StringVar(value="Disconnected")
        self.status_dot = tk.Label(top, text="●", fg="#ef4444")
        self.status_dot.grid(row=0, column=4, sticky="w", padx=(14, 4))
        ttk.Label(top, textvariable=self.status_var).grid(row=0, column=5, sticky="w")

        self.disconnect_btn = ttk.Button(top, text="Disconnect", width=12, command=self.disconnect)
        self.disconnect_btn.grid(row=0, column=6, padx=(12, 0))

        split = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        split.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        left = ttk.Frame(split, padding=10)
        right = ttk.Frame(split, padding=10)
        split.add(left, weight=2)
        split.add(right, weight=5)

        auth_box = ttk.LabelFrame(left, text="Authentication", padding=10)
        auth_box.pack(fill="x")

        self.auth_tabs = ttk.Notebook(auth_box)
        self.auth_tabs.pack(fill="x")

        login_tab = ttk.Frame(self.auth_tabs, padding=8)
        register_tab = ttk.Frame(self.auth_tabs, padding=8)
        self.auth_tabs.add(login_tab, text="Login")
        self.auth_tabs.add(register_tab, text="Register")

        ttk.Label(login_tab, text="Username").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.login_user_var = tk.StringVar(value="admin")
        ttk.Entry(login_tab, textvariable=self.login_user_var, width=26).grid(row=1, column=0, sticky="ew")
        ttk.Label(login_tab, text="Password").grid(row=2, column=0, sticky="w", pady=(10, 4))
        self.login_pass_var = tk.StringVar(value="admin123")
        ttk.Entry(login_tab, textvariable=self.login_pass_var, show="*", width=26).grid(row=3, column=0, sticky="ew")
        self.connect_btn = ttk.Button(login_tab, text="Login & Connect", command=self.connect_to_server)
        self.connect_btn.grid(row=4, column=0, sticky="ew", pady=(12, 0))

        ttk.Label(register_tab, text="Create Username").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.reg_user_var = tk.StringVar()
        ttk.Entry(register_tab, textvariable=self.reg_user_var, width=26).grid(row=1, column=0, sticky="ew")
        ttk.Label(register_tab, text="Create Password").grid(row=2, column=0, sticky="w", pady=(10, 4))
        self.reg_pass_var = tk.StringVar()
        ttk.Entry(register_tab, textvariable=self.reg_pass_var, show="*", width=26).grid(row=3, column=0, sticky="ew")
        ttk.Label(register_tab, text="Confirm Password").grid(row=4, column=0, sticky="w", pady=(10, 4))
        self.reg_confirm_var = tk.StringVar()
        ttk.Entry(register_tab, textvariable=self.reg_confirm_var, show="*", width=26).grid(row=5, column=0, sticky="ew")
        self.register_btn = ttk.Button(register_tab, text="Create Account", command=self.register_user)
        self.register_btn.grid(row=6, column=0, sticky="ew", pady=(12, 0))

        defaults = ttk.Label(left, text="Preloaded: admin/admin123, student/student123")
        defaults.pack(anchor="w", pady=(8, 8))

        quick_box = ttk.LabelFrame(left, text="Quick Commands", padding=10)
        quick_box.pack(fill="x")
        for cmd in ("whoami", "pwd", "date", "dir"):
            ttk.Button(quick_box, text=cmd, command=lambda c=cmd: self.run_quick(c)).pack(fill="x", pady=3)

        output_box = ttk.LabelFrame(right, text="Command Console", padding=8)
        output_box.pack(fill="both", expand=True)

        self.output = scrolledtext.ScrolledText(
            output_box,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="#0f172a",
            fg="#e5e7eb",
            insertbackground="white",
            padx=10,
            pady=10,
        )
        self.output.pack(fill="both", expand=True)
        self.output.configure(state="disabled")

        bottom = ttk.Frame(right, padding=(0, 8, 0, 0))
        bottom.pack(fill="x")

        ttk.Label(bottom, text="Command").pack(side="left")
        self.cmd_var = tk.StringVar()
        self.cmd_entry = ttk.Entry(bottom, textvariable=self.cmd_var, font=("Consolas", 11))
        self.cmd_entry.pack(side="left", fill="x", expand=True, padx=(8, 8))
        self.cmd_entry.bind("<Return>", lambda _e: self.execute_command())
        self.cmd_entry.bind("<Up>", self._history_up)
        self.cmd_entry.bind("<Down>", self._history_down)

        self.run_btn = ttk.Button(bottom, text="Run", width=10, command=self.execute_command)
        self.run_btn.pack(side="left")

        self.clear_btn = ttk.Button(bottom, text="Clear Output", width=12, command=self.clear_output)
        self.clear_btn.pack(side="left", padx=(8, 0))

        help_row = ttk.Frame(right)
        help_row.pack(fill="x", pady=(4, 0))
        ttk.Label(
            help_row,
            text="Allowed commands: ls, dir, pwd, cd, date, whoami",
        ).pack(anchor="w")

    def _set_connected_ui(self, is_connected):
        self.connected = is_connected
        state = "normal" if is_connected else "disabled"

        self.run_btn.configure(state=state)
        self.cmd_entry.configure(state=state)
        self.disconnect_btn.configure(state=state)
        self.connect_btn.configure(state="disabled" if is_connected else "normal")
        self.register_btn.configure(state="disabled" if is_connected else "normal")
        self.status_var.set(f"Connected as {self.username}" if is_connected else "Disconnected")
        self.status_dot.configure(fg="#10b981" if is_connected else "#ef4444")

    def _history_up(self, _event):
        if not self.history:
            return "break"
        self.history_index = max(0, self.history_index - 1)
        self.cmd_var.set(self.history[self.history_index])
        return "break"

    def _history_down(self, _event):
        if not self.history:
            return "break"
        self.history_index = min(len(self.history), self.history_index + 1)
        if self.history_index == len(self.history):
            self.cmd_var.set("")
        else:
            self.cmd_var.set(self.history[self.history_index])
        return "break"

    def _append_output(self, text):
        self.output.configure(state="normal")
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)
        self.output.configure(state="disabled")

    def clear_output(self):
        self.output.configure(state="normal")
        self.output.delete("1.0", tk.END)
        self.output.configure(state="disabled")

    def _create_secure_socket(self, server_ip, server_port):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cert_path = os.path.join(project_root, "server", "cert.pem")
        if os.path.exists(cert_path):
            context.load_verify_locations(cert_path)

        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.settimeout(SOCKET_TIMEOUT)
        raw_socket.connect((server_ip, server_port))
        return context.wrap_socket(raw_socket, server_hostname="localhost")

    def _get_server(self):
        server_ip = self.server_ip_var.get().strip()
        if not server_ip:
            raise ValueError("Server IP is required")
        try:
            server_port = int(self.port_var.get().strip())
        except ValueError as e:
            raise ValueError("Port must be a number") from e
        return server_ip, server_port

    def connect_to_server(self):
        if self.connected:
            return

        username = self.login_user_var.get().strip()
        password = self.login_pass_var.get()

        if not username or not password:
            messagebox.showerror("Missing Info", "Please enter login username and password.")
            return

        try:
            server_ip, server_port = self._get_server()
        except ValueError as e:
            messagebox.showerror("Invalid Server", str(e))
            return

        try:
            sock = self._create_secure_socket(server_ip, server_port)
            send_message(
                sock,
                {"type": "login", "data": {"username": username, "password": password}},
            )
            response = recv_message(sock)
            if response is None:
                sock.close()
                raise ConnectionError("No response from server")

            if response.get("type") != "login_success":
                reason = response.get("data", {}).get("message", "Login failed")
                sock.close()
                messagebox.showerror("Login Failed", reason)
                write_log(username, "LOGIN", "FAILED", reason)
                return

            self.sock = sock
            self.username = username
            self._set_connected_ui(True)
            self._append_output(f"[+] Connected to {server_ip}:{server_port} as {username}")
            self._append_output("[*] You can now execute allowed remote commands.\n")
            write_log(username, "LOGIN", "SUCCESS", "")
            self.cmd_entry.focus_set()
        except ssl.SSLError as e:
            messagebox.showerror("TLS Error", str(e))
        except (OSError, ConnectionError) as e:
            messagebox.showerror("Connection Error", str(e))

    def register_user(self):
        username = self.reg_user_var.get().strip()
        password = self.reg_pass_var.get()
        confirm = self.reg_confirm_var.get()

        if not username or not password:
            messagebox.showerror("Missing Info", "Please enter username and password.")
            return
        if password != confirm:
            messagebox.showerror("Mismatch", "Password and confirm password do not match.")
            return

        try:
            server_ip, server_port = self._get_server()
            sock = self._create_secure_socket(server_ip, server_port)
            send_message(sock, {"type": "register", "data": {"username": username, "password": password}})
            response = recv_message(sock)
            try:
                send_message(sock, {"type": "logout", "data": {}})
            except OSError:
                pass
            sock.close()

            if response and response.get("type") == "register_success":
                messagebox.showinfo("Account Created", "Registration successful. You can now login.")
                self.login_user_var.set(username)
                self.login_pass_var.set(password)
                self.auth_tabs.select(0)
                self.reg_pass_var.set("")
                self.reg_confirm_var.set("")
                self._append_output(f"[+] New user registered: {username}")
                write_log(username, "REGISTER", "SUCCESS", "")
            else:
                reason = (response or {}).get("data", {}).get("message", "Registration failed")
                messagebox.showerror("Registration Failed", reason)
                write_log(username or "(unknown)", "REGISTER", "FAILED", reason)
        except (OSError, ssl.SSLError, ValueError, json.JSONDecodeError) as e:
            messagebox.showerror("Registration Error", str(e))

    def run_quick(self, cmd):
        self.cmd_var.set(cmd)
        self.execute_command()

    def execute_command(self):
        if not self.connected or not self.sock:
            messagebox.showwarning("Not Connected", "Login first to execute commands.")
            return

        command = self.cmd_var.get().strip()
        if not command:
            return
        self.cmd_var.set("")
        if not self.history or self.history[-1] != command:
            self.history.append(command)
        self.history_index = len(self.history)

        self._append_output(f"> {command}")

        def _worker():
            try:
                with self.lock:
                    send_message(self.sock, {"type": "command", "data": {"command": command}})
                    response = recv_message(self.sock)

                if response is None:
                    self.root.after(0, lambda: self._append_output("[!] Server closed connection.\n"))
                    self.root.after(0, self.disconnect)
                    return

                msg_type = response.get("type")
                data = response.get("data", {})
                if msg_type == "command_output":
                    output = data.get("output", "").rstrip() or "(no output)"
                    exit_code = data.get("exit_code", 0)
                    write_log(
                        self.username,
                        command,
                        "EXECUTED" if exit_code == 0 else "FAILED",
                        f"exit_code={exit_code}",
                    )
                    self.root.after(
                        0,
                        lambda: self._append_output(
                            f"{output}\n[exit_code={exit_code}]\n"
                        ),
                    )
                else:
                    err = data.get("message", f"Unexpected response: {response}")
                    write_log(self.username, command, "FAILED", err)
                    self.root.after(0, lambda: self._append_output(f"[!] {err}\n"))
            except (OSError, ssl.SSLError, json.JSONDecodeError) as e:
                self.root.after(0, lambda: self._append_output(f"[!] Error: {e}\n"))

        threading.Thread(target=_worker, daemon=True).start()

    def disconnect(self):
        if self.sock:
            try:
                send_message(self.sock, {"type": "logout", "data": {}})
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.username = ""
        if self.connected:
            self._append_output("[-] Disconnected.\n")
        self._set_connected_ui(False)


def main():
    root = tk.Tk()
    app = CommandGUIClient(root)
    root.protocol("WM_DELETE_WINDOW", lambda: (app.disconnect(), root.destroy()))
    root.mainloop()


if __name__ == "__main__":
    main()
