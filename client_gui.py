import socket
import threading
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText

SERVER_IP = "10.0.0.1"
SERVER_PORT = 5000

AUTH_DELIMITER = "\x1f"   # must match the server's AUTH_DELIMITER
MAX_MESSAGE_LENGTH = 500


class ChatClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure TCP Multi-Client Chat")
        self.root.geometry("760x540")

        self.sock = None
        self.connected = False
        self.username = ""

        self.build_login_screen()
        self.root.protocol("WM_DELETE_WINDOW", self.close_app)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def build_login_screen(self):
        self.clear_window()

        frame = tk.Frame(self.root, padx=30, pady=30)
        frame.pack(expand=True)

        tk.Label(
            frame,
            text="SECURE TCP CHAT APPLICATION",
            font=("Arial", 18, "bold")
        ).grid(row=0, column=0, columnspan=2, pady=20)

        tk.Label(frame, text="Username:").grid(
            row=1, column=0, padx=10, pady=10, sticky="e"
        )

        self.username_entry = tk.Entry(frame, width=30)
        self.username_entry.grid(row=1, column=1, padx=10, pady=10)
        self.username_entry.focus()

        tk.Label(frame, text="Password:").grid(
            row=2, column=0, padx=10, pady=10, sticky="e"
        )

        self.password_entry = tk.Entry(frame, width=30, show="*")
        self.password_entry.grid(row=2, column=1, padx=10, pady=10)

        self.connect_button = tk.Button(
            frame,
            text="Login",
            width=18,
            command=self.connect_to_server
        )
        self.connect_button.grid(row=3, column=0, columnspan=2, pady=15)

        tk.Label(
            frame,
            text="Note: a new username creates a new account automatically.",
            font=("Arial", 8),
            fg="gray"
        ).grid(row=4, column=0, columnspan=2)

        self.login_status = tk.Label(frame, text="Status: Not Connected")
        self.login_status.grid(row=5, column=0, columnspan=2, pady=5)

        self.root.bind("<Return>", lambda event: self.connect_to_server())

    def connect_to_server(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        if username == "":
            messagebox.showerror("Error", "Username cannot be empty.")
            return

        if password == "":
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((SERVER_IP, SERVER_PORT))

            # Send the authentication handshake: username<US>password
            auth_payload = f"{username}{AUTH_DELIMITER}{password}"
            self.sock.sendall(auth_payload.encode("utf-8"))

            response = self.sock.recv(1024).decode("utf-8", errors="replace").strip()

            if response.startswith("AUTH_OK"):
                self.sock.settimeout(None)  # back to blocking mode for normal chat
                self.username = username
                self.connected = True

                self.build_chat_screen()

                threading.Thread(
                    target=self.receive_messages,
                    daemon=True
                ).start()

                self.sock.sendall(b"/list")

                if "REGISTERED" in response:
                    messagebox.showinfo(
                        "Account Created",
                        f"New account created and connected as {username}"
                    )
                else:
                    messagebox.showinfo("Connected", f"Connected as {username}")

            elif response.startswith("AUTH_LOCKED"):
                seconds = response.split(":", 1)[1] if ":" in response else "some time"
                messagebox.showerror(
                    "Account Locked",
                    f"Too many failed attempts. Try again in {seconds} seconds."
                )
                self._reset_after_failed_login()

            elif response.startswith("AUTH_FAIL"):
                reason = response.split(":", 1)[1] if ":" in response else "Authentication failed."
                messagebox.showerror("Login Failed", reason)
                self._reset_after_failed_login()

            else:
                messagebox.showerror("Login Failed", "Unexpected server response.")
                self._reset_after_failed_login()

        except Exception as e:
            self.connected = False
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
            messagebox.showerror("Connection Error", str(e))

    def _reset_after_failed_login(self):
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.password_entry.delete(0, tk.END)

    def build_chat_screen(self):
        self.clear_window()
        self.root.unbind("<Return>")

        top_frame = tk.Frame(self.root, padx=10, pady=8)
        top_frame.pack(fill="x")

        tk.Label(
            top_frame,
            text=f"Logged in as: {self.username}",
            font=("Arial", 12, "bold")
        ).pack(side="left")

        self.status_label = tk.Label(top_frame, text="Status: Connected")
        self.status_label.pack(side="right")

        body_frame = tk.Frame(self.root, padx=10, pady=5)
        body_frame.pack(fill="both", expand=True)

        chat_frame = tk.Frame(body_frame)
        chat_frame.pack(side="left", fill="both", expand=True)

        tk.Label(chat_frame, text="Messages").pack(anchor="w")

        self.chat_area = ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            state="disabled"
        )
        self.chat_area.pack(fill="both", expand=True, padx=(0, 10))

        users_frame = tk.Frame(body_frame, width=180)
        users_frame.pack(side="right", fill="y")
        users_frame.pack_propagate(False)

        tk.Label(
            users_frame,
            text="Online Users",
            font=("Arial", 11, "bold")
        ).pack(pady=5)

        self.users_listbox = tk.Listbox(users_frame)
        self.users_listbox.pack(fill="both", expand=True)

        input_frame = tk.Frame(self.root, padx=10, pady=10)
        input_frame.pack(fill="x")

        self.message_entry = tk.Entry(input_frame)
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.message_entry.bind("<Return>", lambda event: self.send_message())
        self.message_entry.focus()

        tk.Button(
            input_frame,
            text="Send",
            width=10,
            command=self.send_message
        ).pack(side="left", padx=4)

        tk.Button(
            input_frame,
            text="Private",
            width=10,
            command=self.send_private_message
        ).pack(side="left", padx=4)

        tk.Button(
            input_frame,
            text="Refresh Users",
            width=12,
            command=self.request_user_list
        ).pack(side="left", padx=4)

        tk.Button(
            input_frame,
            text="Logout",
            width=12,
            command=self.disconnect
        ).pack(side="left", padx=4)

    def append_message(self, message):
        if not hasattr(self, "chat_area"):
            return
        self.chat_area.config(state="normal")
        self.chat_area.insert(tk.END, message)
        if not message.endswith("\n"):
            self.chat_area.insert(tk.END, "\n")
        self.chat_area.see(tk.END)
        self.chat_area.config(state="disabled")

    def receive_messages(self):
        while self.connected:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break

                text = data.decode("utf-8", errors="replace")

                # TCP may deliver multiple newline-separated messages together.
                for line in text.splitlines():
                    if line.startswith("[SERVER] Online:"):
                        names_text = line.split(":", 1)[1].strip()
                        names = [
                            name.strip()
                            for name in names_text.split(",")
                            if name.strip()
                        ]
                        self.root.after(0, self.update_user_list, names)
                    else:
                        self.root.after(0, self.append_message, line + "\n")

                    # Refresh the online-user panel after join/leave notices.
                    if "has joined the chat!" in line or "has left the chat." in line:
                        self.root.after(100, self.request_user_list)

                    # Server closed the session (timeout / logout confirmation).
                    if "Session timed out" in line or "logged out" in line:
                        self.connected = False

            except Exception:
                break

        self.connected = False
        self.root.after(0, self.handle_server_disconnect)

    def update_user_list(self, names):
        self.users_listbox.delete(0, tk.END)
        for name in names:
            self.users_listbox.insert(tk.END, name)

    def request_user_list(self):
        if self.connected and self.sock:
            try:
                self.sock.sendall(b"/list")
            except Exception:
                pass

    def send_message(self):
        if not self.connected:
            messagebox.showwarning("Warning", "Not connected to server.")
            return

        message = self.message_entry.get().strip()

        if message == "":
            return

        if len(message) > MAX_MESSAGE_LENGTH:
            messagebox.showwarning(
                "Message Too Long",
                f"Messages must be {MAX_MESSAGE_LENGTH} characters or fewer."
            )
            return

        try:
            self.sock.sendall(message.encode("utf-8"))
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    def send_private_message(self):
        if not self.connected:
            return

        selection = self.users_listbox.curselection()
        if not selection:
            messagebox.showwarning(
                "Private Message",
                "Select an online user first."
            )
            return

        target = self.users_listbox.get(selection[0])

        if target == self.username:
            messagebox.showwarning(
                "Private Message",
                "Select another user."
            )
            return

        message = self.message_entry.get().strip()
        if message == "":
            messagebox.showwarning(
                "Private Message",
                "Enter a message first."
            )
            return

        if len(message) > MAX_MESSAGE_LENGTH:
            messagebox.showwarning(
                "Message Too Long",
                f"Messages must be {MAX_MESSAGE_LENGTH} characters or fewer."
            )
            return

        command = f"/msg {target} {message}"

        try:
            self.sock.sendall(command.encode("utf-8"))
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    def disconnect(self):
        if self.connected:
            try:
                self.sock.sendall(b"/logout")
            except Exception:
                pass
            self.connected = False
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.sock.close()
            except Exception:
                pass

        messagebox.showinfo("Logged Out", "You have been logged out.")
        self.build_login_screen()

    def handle_server_disconnect(self):
        if hasattr(self, "status_label"):
            self.status_label.config(text="Status: Disconnected")
        messagebox.showwarning(
            "Disconnected",
            "The server connection was closed (logout or session timeout)."
        )
        self.build_login_screen()

    def close_app(self):
        if self.connected:
            try:
                self.sock.sendall(b"/logout")
            except Exception:
                pass
            self.connected = False
            try:
                self.sock.close()
            except Exception:
                pass
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ChatClientGUI(root)
    root.mainloop()
