package db

import (
	"database/sql"
	"time"
	_ "github.com/glebarez/go-sqlite"
)

type User struct {
	ID               int64
	Username         string
	PasswordHash     string
	TOTPSecret       sql.NullString
	TOTPEnabled      bool
	RegistrationDate time.Time
	LastLoginTime    sql.NullTime
}

type Session struct {
	Token     string
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type DB struct {
	Conn *sql.DB
}

func Open(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(); err != nil {
		conn.Close()
		return nil, err
	}
	db := &DB{Conn: conn}
	if err := db.initSchema(); err != nil {
		conn.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) Close() error {
	return db.Conn.Close()
}

func (db *DB) initSchema() error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			totp_secret TEXT,
			totp_enabled INTEGER NOT NULL DEFAULT 0,
			registration_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_login_time DATETIME
		);`,
		`CREATE TABLE IF NOT EXISTS login_attempts (
			username TEXT PRIMARY KEY,
			attempts INTEGER NOT NULL DEFAULT 0,
			last_attempt DATETIME NOT NULL,
			locked_until DATETIME
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			token TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
		);`,
	}
	for _, query := range queries {
		_, err := db.Conn.Exec(query)
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) GetUser(username string) (*User, error) {
	row := db.Conn.QueryRow("SELECT id, username, password_hash, totp_secret, totp_enabled, registration_date, last_login_time FROM users WHERE username = ?", username)
	var user User
	var totpEnabledInt int
	err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.TOTPSecret, &totpEnabledInt, &user.RegistrationDate, &user.LastLoginTime)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	user.TOTPEnabled = totpEnabledInt != 0
	return &user, nil
}

func (db *DB) CreateUser(username, passwordHash string) error {
	_, err := db.Conn.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, passwordHash)
	return err
}

func (db *DB) UpdateUser2FA(username string, secret string, enabled bool) error {
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	var sec interface{}
	if secret == "" {
		sec = nil
	} else {
		sec = secret
	}
	_, err := db.Conn.Exec("UPDATE users SET totp_secret = ?, totp_enabled = ? WHERE username = ?", sec, enabledInt, username)
	return err
}

func (db *DB) UpdateLastLogin(username string) error {
	_, err := db.Conn.Exec("UPDATE users SET last_login_time = ? WHERE username = ?", time.Now(), username)
	return err
}

func (db *DB) GetLoginAttempts(username string) (int, time.Time, time.Time, error) {
	row := db.Conn.QueryRow("SELECT attempts, last_attempt, locked_until FROM login_attempts WHERE username = ?", username)
	var attempts int
	var lastAttempt time.Time
	var lockedUntil sql.NullTime
	err := row.Scan(&attempts, &lastAttempt, &lockedUntil)
	if err == sql.ErrNoRows {
		return 0, time.Time{}, time.Time{}, nil
	}
	if err != nil {
		return 0, time.Time{}, time.Time{}, err
	}
	var lockedUntilVal time.Time
	if lockedUntil.Valid {
		lockedUntilVal = lockedUntil.Time
	}
	return attempts, lastAttempt, lockedUntilVal, nil
}

func (db *DB) UpdateLoginAttempts(username string, attempts int, lockedUntil time.Time) error {
	var lockedVal interface{}
	if lockedUntil.IsZero() {
		lockedVal = nil
	} else {
		lockedVal = lockedUntil
	}
	_, err := db.Conn.Exec(
		"INSERT INTO login_attempts (username, attempts, last_attempt, locked_until) VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET attempts = excluded.attempts, last_attempt = excluded.last_attempt, locked_until = excluded.locked_until",
		username, attempts, time.Now(), lockedVal,
	)
	return err
}

func (db *DB) ResetLoginAttempts(username string) error {
	_, err := db.Conn.Exec("DELETE FROM login_attempts WHERE username = ?", username)
	return err
}

func (db *DB) CreateSession(token, username string, expiresAt time.Time) error {
	_, err := db.Conn.Exec("INSERT INTO sessions (token, username, created_at, expires_at) VALUES (?, ?, ?, ?)", token, username, time.Now(), expiresAt)
	return err
}

func (db *DB) GetSession(token string) (*Session, error) {
	row := db.Conn.QueryRow("SELECT token, username, created_at, expires_at FROM sessions WHERE token = ?", token)
	var session Session
	err := row.Scan(&session.Token, &session.Username, &session.CreatedAt, &session.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func (db *DB) DeleteSession(token string) error {
	_, err := db.Conn.Exec("DELETE FROM sessions WHERE token = ?", token)
	return err
}

func (db *DB) UpdateSessionExpiry(token string, expiresAt time.Time) error {
	_, err := db.Conn.Exec("UPDATE sessions SET expires_at = ? WHERE token = ?", expiresAt, token)
	return err
}

func (db *DB) CleanExpiredSessions() error {
	_, err := db.Conn.Exec("DELETE FROM sessions WHERE expires_at < ?", time.Now())
	return err
}
