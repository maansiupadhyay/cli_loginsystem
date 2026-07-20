# Secure CLI Login System with Optional 2FA

A secure, containerized command-line login system written in Go, featuring user registration, bcrypt-hashed passwords, account lockout, inactivity-based session management, and Google Authenticator compatible TOTP 2FA.

## Features

- **Interactive Shell CLI**: Real-time context-aware terminal interface with command completion and command history.
- **Secure Password Hashing**: Passwords stored securely using bcrypt hashing.
- **Account Lockout**: Locks out accounts after configurable failed login attempts for a customizable duration.
- **Session Persistence**: Persistent session tokens with inactivity-based expiry timeouts.
- **Two-Factor Authentication (2FA)**: Support for Google Authenticator via TOTP. Displays secret keys, provisioning URIs, and ASCII-art terminal QR codes.
- **SQLite Database**: Self-migrating SQLite storage running inside the container.
- **Persistent named Docker Volume**: Persistent application data across container rebuilds.

## Directory Layout

- `cmd/app/main.go` - Application entrypoint (initialization and background cleaners).
- `internal/db/` - SQLite connection, schema migrations, and queries.
- `internal/auth/` - Security logic (bcrypt, sessions, lockouts, TOTP).
- `internal/cli/` - Interactive shell, tab-completion, history, and rendering.
- `Dockerfile` - Multi-stage lightweight build.
- `docker-compose.yml` - Stdin and TTY mapping with named volumes.

---

## Environment Configuration

Configure the system behavior using the following environment variables in `docker-compose.yml`:

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_PATH` | Storage path of the SQLite database. | `/data/db.sqlite` |
| `HISTORY_PATH` | Storage path of the CLI terminal history. | `/data/.cli_history` |
| `LOCKOUT_THRESHOLD` | Max consecutive failed login attempts before locking. | `5` |
| `LOCKOUT_DURATION_MINS` | Account lockout duration in minutes. | `15` |
| `SESSION_TIMEOUT_MINS` | Session inactivity timeout in minutes. | `30` |

---

## Quick Start Guide

### Prerequisites

- Docker
- Docker Compose

### 1. Build and Run the App

Launch the interactive CLI system:

```bash
docker-compose up --build
```

### 2. Connect to the Interactive Shell

Since the compose container runs in interactive mode, attach to it:

```bash
docker attach cli-login-app
```

*Note: Press `Ctrl+C` to detach or exit.*

---

## Usage Guide (End-to-End Session)

When you run the system, you start as a `guest` and see the guest help:

```text
Available commands:
  register - Register a new user
  login    - Authenticate and start a session
  help     - Display help information
  exit     - Exit the application

guest>
```

### 1. Register a User
Type `register` and follow the prompts:

```text
guest> register
Username: Alice
Password: [input masked]
Confirm Password: [input masked]
Registration successful.
```

### 2. Login (Without 2FA)
Type `login` to authenticate:

```text
guest> login
Username: Alice
Password: [input masked]
==================================================
              WELCOME BACK, ALICE              
==================================================
Registration Date  : 2026-07-20 18:00:00 UTC
MFA Status         : DISABLED
Session Expiration : 2026-07-20 18:30:00 UTC
Last Login Time    : 2026-07-20 18:00:00 UTC
==================================================
Alice> 
```

Notice that the prompt changes from `guest>` to `Alice>`.

### 3. Enable 2FA
To set up Google Authenticator 2FA:

```text
Alice> enable-2fa

--- Enable Two-Factor Authentication ---
Secret Key: JBSWY3DPEHPK3PXP
URI: otpauth://totp/SecureCLILogin:Alice?secret=JBSWY3DPEHPK3PXP&issuer=SecureCLILogin

Scan the QR code below using your authenticator app:
[QR Code rendering here]

Enter 2FA Code to verify: 123456
2FA enabled successfully.
```

### 4. Logout and Verify Lockout
Log out from the session:

```text
Alice> logout
Logged out successfully.
guest>
```

Now, try logging in with an invalid password to trigger lockout tracking:

```text
guest> login
Username: Alice
Password: wrongpassword
Invalid credentials.
...
guest> login
Username: Alice
Password: wrongpassword
Invalid credentials. Account has been locked until 2026-07-20 18:45:00 UTC.
```

### 5. Log in with 2FA
Once unlocked or with valid credentials:

```text
guest> login
Username: Alice
Password: correctpassword
Enter 2FA Code: 654321
==================================================
              WELCOME BACK, ALICE              
==================================================
MFA Status         : ENABLED
...
Alice>
```

---

## Running Unit Tests Locally

If you have Go installed on your machine, you can run the test suite directly:

```bash
go test -v ./internal/...
```

Output:
```text
=== RUN   TestHashAndVerifyPassword
--- PASS: TestHashAndVerifyPassword (5.30s)
=== RUN   TestLockoutTracking
--- PASS: TestLockoutTracking (0.14s)
=== RUN   TestSessionExpiration
--- PASS: TestSessionExpiration (0.06s)
PASS
ok      cli-login-system/internal/auth  9.124s
```

---

## Submission Details

**Important**: Send the link to the shared repository or package submission to **hr@osto.one**.
