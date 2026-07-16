# Secure TCP Multi-Client Chat Application

**Assignment 7 — Secure Network Application Development Using TCP**
Extends the Assignment 6 GUI-based multi-client TCP chat application with practical application-level security: authentication, SHA-256 password hashing, duplicate-login prevention, input validation, failed-login lockout, session timeout, and secure logging.

## Overview

A multi-threaded TCP chat server (`server.py`) and a Tkinter GUI client (`client_gui.py`) that allow multiple users to authenticate, chat over broadcast and private messages, and log out securely — tested over a Mininet-emulated network (`single,5` topology).

## Features

| Feature | Description |
|---|---|
| **User Authentication** | Username/password handshake required before joining the chat |
| **Secure Password Storage** | Passwords hashed with SHA-256 (`hashlib.sha256`) before being saved to `users.json`; plaintext is never stored |
| **Duplicate Login Prevention** | A username already logged in from one session cannot log in again elsewhere |
| **Input Validation** | Username format, minimum password length, max message size, and unsupported commands are all rejected server-side |
| **Failed Login Protection** | Account locked for 60 seconds after 5 consecutive failed login attempts |
| **Session Management** | Manual `/logout` plus automatic session timeout after 5 minutes of inactivity |
| **Secure Logging** | All auth/session events logged to `security_log.txt` with timestamp, event type, username, and IP — passwords are never logged |

## Project Structure

```
├── server.py                # TCP server: auth, session mgmt, validation, logging, message routing
├── client_gui.py             # Tkinter GUI client: login screen + chat screen
├── users.json                 # Username -> SHA-256 password hash (auto-created)
├── security_log.txt           # Auth/session event log (auto-created)
├── chat_history.csv           # Broadcast/private message history (auto-created)
├── report.docx / report.pdf   # Full assignment report
├── handwritten_reflection.pdf # Scanned handwritten reflection answers
└── screenshots/                # GUI, log, and Wireshark evidence
```

## Requirements

- Python 3.8+
- Tkinter (usually bundled with Python; on Linux: `sudo apt install python3-tk`)
- Mininet (for network emulation/testing)
- Wireshark (for traffic verification)

No external Python packages are required — only the standard library (`socket`, `threading`, `hashlib`, `json`, `csv`, `re`, `time`, `tkinter`).

## Network Setup (Mininet)

```bash
sudo mn --topo single,5
```

Inside the Mininet CLI, verify the topology:

```
mininet> nodes
mininet> net
mininet> pingall
```

## Running the Application

1. **Start the server** on one host (e.g. `h1`, IP `10.0.0.1`):
   ```bash
   python3 server.py
   ```
2. **Start a client** on any other host (e.g. `h2`, `h3`, ...):
   ```bash
   python3 client_gui.py
   ```
   Update `SERVER_IP` in `client_gui.py` if your server host's IP differs from `10.0.0.1`.
3. Log in with any username/password — a new username automatically registers a new account (password is hashed and stored). Reusing an existing username requires the correct password.

### Client Commands

| Command | Description |
|---|---|
| `/list` | Show online users |
| `/msg <username> <message>` | Send a private message |
| `/logout` | End the session |
| any other text | Broadcast message to all connected users |

## Security Verification

- **`users.json`** — confirms only SHA-256 hashes are stored, never plaintext passwords.
- **`security_log.txt`** — confirms login success/failure, lockouts, duplicate-login blocks, logouts, and timeouts are logged without ever recording a password.
- **Wireshark** — traffic captured on `tcp.port == 5000` verifies the TCP three-way handshake, successful login, failed login, and duplicate-login rejection at the network level (see `screenshots/`).

## Testing Summary

Tested on a 5-host Mininet topology (`single,5`) with 0% packet loss (`pingall`). Verified scenarios include: new account creation, correct/incorrect login, account lockout after 5 failed attempts, duplicate login rejection, broadcast messaging, private messaging, and session timeout/logout.

## Author

abhishek

## Related Assignments

This repository is a continuing submission — Assignment 7 builds directly on the Assignment 6 multi-client TCP chat application in this same repo.
