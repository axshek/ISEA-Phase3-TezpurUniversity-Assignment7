import socket
import threading
import datetime
import os
import csv
import json
import hashlib
import re
import time

HOST = "0.0.0.0"
PORT = 5000

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------
USERS_FILE = "users.json"          # stores username -> sha256 password hash
SECURITY_LOG = "security_log.txt"  # login / logout / lockout / auth events
CHAT_LOG = "chat_history.csv"      # normal chat history (kept from Assignment 6)

USERNAME_REGEX = re.compile(r"^[A-Za-z0-9_]{3,20}$")
MIN_PASSWORD_LENGTH = 4
MAX_MESSAGE_LENGTH = 500

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 60

SESSION_TIMEOUT = 300        # 5 minutes of inactivity -> auto logout
RECV_TIMEOUT = 30            # how often we wake up to check the timeout

AUTH_DELIMITER = "\x1f"      # unlikely to appear inside a username/password

# ---------------------------------------------------------------------------
# Shared state (all protected by state_lock)
# ---------------------------------------------------------------------------
clients = {}              # socket -> {"username", "ip", "port", "login_time"}
active_usernames = set()  # usernames that currently have an open session
failed_attempts = {}      # username -> {"count": int, "locked_until": epoch}

state_lock = threading.Lock()

stats = {"messages": 0, "broadcasts": 0, "private": 0}


# ---------------------------------------------------------------------------
# Helpers: files / logging
# ---------------------------------------------------------------------------
def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


users = load_users()

if not os.path.exists(CHAT_LOG):
    with open(CHAT_LOG, "w", newline="") as f:
        csv.writer(f).writerow(["timestamp", "sender", "receiver", "message_type", "message"])

if not os.path.exists(SECURITY_LOG):
    open(SECURITY_LOG, "w").close()


def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_security_event(event, username, ip, detail=""):
    """Append an entry to security_log.txt. Never pass a password here."""
    line = f"{timestamp()} | {event} | user={username} | ip={ip} | {detail}\n"
    with open(SECURITY_LOG, "a") as f:
        f.write(line)
    print(f"[SECURITY] {line.strip()}")


def log_chat(sender, receiver, msg_type, message):
    with open(CHAT_LOG, "a", newline="") as f:
        csv.writer(f).writerow([timestamp(), sender, receiver, msg_type, message])


def get_last_messages(username, n=5):
    if not os.path.exists(CHAT_LOG):
        return []
    with open(CHAT_LOG, "r", newline="") as f:
        rows = list(csv.reader(f))[1:]
    sent_by_user = [r for r in rows if len(r) == 5 and r[1] == username]
    return sent_by_user[-n:]


def find_socket_by_username(username):
    with state_lock:
        for sock, info in clients.items():
            if info["username"] == username:
                return sock
    return None


def broadcast(message):
    encoded = message.encode("utf-8")
    with state_lock:
        targets = list(clients.keys())
    for sock in targets:
        try:
            sock.sendall(encoded)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
def is_valid_username(username):
    return bool(USERNAME_REGEX.match(username))


def is_valid_password(password):
    return len(password) >= MIN_PASSWORD_LENGTH


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
def is_locked_out(username):
    """Returns remaining lockout seconds, or 0 if not locked."""
    with state_lock:
        record = failed_attempts.get(username)
        if not record:
            return 0
        remaining = record["locked_until"] - time.time()
        return max(0, remaining)


def register_failed_attempt(username):
    with state_lock:
        record = failed_attempts.setdefault(username, {"count": 0, "locked_until": 0})
        record["count"] += 1
        if record["count"] >= MAX_FAILED_ATTEMPTS:
            record["locked_until"] = time.time() + LOCKOUT_SECONDS
            record["count"] = 0
            return True  # just got locked out
    return False


def clear_failed_attempts(username):
    with state_lock:
        failed_attempts.pop(username, None)


def authenticate(conn, addr):
    """
    Performs the authentication handshake for a freshly connected socket.
    Returns the username on success, or None on failure (connection is
    closed by the caller in both cases if this returns None).
    """
    ip = addr[0]

    raw = conn.recv(1024)
    if not raw:
        return None

    text = raw.decode("utf-8", errors="replace").strip()

    if AUTH_DELIMITER not in text:
        conn.sendall(b"AUTH_FAIL:Malformed login request\n")
        log_security_event("AUTH_MALFORMED", "unknown", ip)
        return None

    username, password = text.split(AUTH_DELIMITER, 1)

    # ---- input validation -------------------------------------------------
    if not is_valid_username(username):
        conn.sendall(b"AUTH_FAIL:Invalid username (3-20 letters/digits/underscore)\n")
        log_security_event("AUTH_INVALID_USERNAME", username, ip)
        return None

    if not is_valid_password(password):
        conn.sendall(f"AUTH_FAIL:Password must be at least {MIN_PASSWORD_LENGTH} characters\n".encode())
        log_security_event("AUTH_INVALID_PASSWORD", username, ip)
        return None

    # ---- lockout check ------------------------------------------------------
    remaining = is_locked_out(username)
    if remaining > 0:
        conn.sendall(f"AUTH_LOCKED:{int(remaining)}\n".encode())
        log_security_event("AUTH_BLOCKED_LOCKED_ACCOUNT", username, ip, f"remaining={int(remaining)}s")
        return None

    # ---- duplicate login check ----------------------------------------------
    with state_lock:
        already_online = username in active_usernames

    if already_online:
        conn.sendall(b"AUTH_FAIL:This user is already logged in elsewhere\n")
        log_security_event("AUTH_DUPLICATE_LOGIN_BLOCKED", username, ip)
        return None

    # ---- new user registration vs existing user verification ---------------
    if username not in users:
        users[username] = hash_password(password)
        save_users(users)
        conn.sendall(b"AUTH_OK:REGISTERED\n")
        log_security_event("ACCOUNT_CREATED", username, ip)
        clear_failed_attempts(username)
    else:
        if users[username] == hash_password(password):
            conn.sendall(b"AUTH_OK\n")
            log_security_event("LOGIN_SUCCESS", username, ip)
            clear_failed_attempts(username)
        else:
            just_locked = register_failed_attempt(username)
            if just_locked:
                conn.sendall(f"AUTH_LOCKED:{LOCKOUT_SECONDS}\n".encode())
                log_security_event("ACCOUNT_LOCKED", username, ip,
                                    f"too many failed attempts, locked for {LOCKOUT_SECONDS}s")
            else:
                conn.sendall(b"AUTH_FAIL:Incorrect password\n")
                log_security_event("LOGIN_FAILED", username, ip)
            return None

    with state_lock:
        active_usernames.add(username)

    return username


# ---------------------------------------------------------------------------
# Client handling
# ---------------------------------------------------------------------------
def handle_client(conn, addr):
    ip = addr[0]
    port = addr[1]
    username = None

    try:
        username = authenticate(conn, addr)
        if username is None:
            conn.close()
            return

        with state_lock:
            clients[conn] = {
                "username": username,
                "ip": ip,
                "port": port,
                "login_time": timestamp(),
            }

        broadcast(f"[SERVER] {username} has joined the chat!\n")

        history = get_last_messages(username, 5)
        if history:
            conn.sendall(b"[SERVER] Your last messages:\n")
            for row in history:
                ts, sender, receiver, mtype, msg = row
                conn.sendall(f"  ({ts}) [{mtype} -> {receiver}] {msg}\n".encode())

        conn.settimeout(RECV_TIMEOUT)
        last_activity = time.time()

        while True:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                if time.time() - last_activity >= SESSION_TIMEOUT:
                    conn.sendall(b"[SERVER] Session timed out due to inactivity.\n")
                    log_security_event("SESSION_TIMEOUT", username, ip)
                    break
                continue

            if not data:
                break

            last_activity = time.time()
            message = data.decode("utf-8", errors="replace").strip()
            if not message:
                continue

            # ---- input validation: message size ----------------------------
            if len(message) > MAX_MESSAGE_LENGTH:
                conn.sendall(
                    f"[SERVER] Message rejected: exceeds {MAX_MESSAGE_LENGTH} characters.\n".encode()
                )
                continue

            stats["messages"] += 1

            if message == "/list":
                with state_lock:
                    names = [info["username"] for info in clients.values()]
                conn.sendall(f"[SERVER] Online: {', '.join(names)}\n".encode())
                continue

            if message == "/logout":
                conn.sendall(b"[SERVER] You have been logged out.\n")
                log_security_event("LOGOUT", username, ip)
                break

            if message.startswith("/msg"):
                parts = message.split(" ", 2)
                if len(parts) < 3 or not parts[1] or not parts[2]:
                    conn.sendall(b"[SERVER] Usage: /msg <username> <message>\n")
                    continue
                target_user, priv_msg = parts[1], parts[2]
                if len(priv_msg) > MAX_MESSAGE_LENGTH:
                    conn.sendall(
                        f"[SERVER] Message rejected: exceeds {MAX_MESSAGE_LENGTH} characters.\n".encode()
                    )
                    continue
                target_sock = find_socket_by_username(target_user)
                if target_sock:
                    target_sock.sendall(f"[PM from {username}] {priv_msg}\n".encode())
                    conn.sendall(f"[PM to {target_user}] {priv_msg}\n".encode())
                    log_chat(username, target_user, "private", priv_msg)
                    stats["private"] += 1
                else:
                    conn.sendall(f"[SERVER] User '{target_user}' not found.\n".encode())
                continue

            if message.startswith("/"):
                conn.sendall(f"[SERVER] Unsupported command: {message.split()[0]}\n".encode())
                continue

            log_chat(username, "ALL", "broadcast", message)
            stats["broadcasts"] += 1
            broadcast(f"[{username}] {message}\n")

    except Exception as e:
        print(f"[ERROR] {username or addr}: {e}")
    finally:
        with state_lock:
            if conn in clients:
                del clients[conn]
            active_usernames.discard(username)
        conn.close()
        if username:
            log_security_event("DISCONNECTED", username, ip)
            broadcast(f"[SERVER] {username} has left the chat.\n")


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[SERVER] Listening on {HOST}:{PORT}")
    try:
        while True:
            conn, addr = server.accept()
            print(f"[SERVER] New connection from {addr}")
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down.")
        with state_lock:
            online = len(clients)
        print(f"[STATS] Online={online} Msgs={stats['messages']} Broadcasts={stats['broadcasts']} Private={stats['private']}")
    finally:
        server.close()


if __name__ == "__main__":
    main()
