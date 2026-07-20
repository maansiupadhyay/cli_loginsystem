package auth

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"cli-login-system/internal/db"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func VerifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func CheckLockout(database *db.DB, username string) (bool, time.Time, error) {
	_, _, lockedUntil, err := database.GetLoginAttempts(username)
	if err != nil {
		return false, time.Time{}, err
	}
	if !lockedUntil.IsZero() && time.Now().Before(lockedUntil) {
		return true, lockedUntil, nil
	}
	return false, time.Time{}, nil
}

func RecordFailedAttempt(database *db.DB, username string, threshold int, duration time.Duration) (bool, time.Time, error) {
	attempts, _, lockedUntil, err := database.GetLoginAttempts(username)
	if err != nil {
		return false, time.Time{}, err
	}
	if !lockedUntil.IsZero() && time.Now().Before(lockedUntil) {
		return true, lockedUntil, nil
	}
	attempts++
	var lockExpiry time.Time
	if attempts >= threshold {
		lockExpiry = time.Now().Add(duration)
	}
	err = database.UpdateLoginAttempts(username, attempts, lockExpiry)
	if err != nil {
		return false, time.Time{}, err
	}
	return attempts >= threshold, lockExpiry, nil
}

func ResetFailedAttempts(database *db.DB, username string) error {
	return database.ResetLoginAttempts(username)
}

func VerifySession(database *db.DB, token string, inactivityTimeout time.Duration) (*db.Session, error) {
	session, err := database.GetSession(token)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, nil
	}
	if time.Now().After(session.ExpiresAt) {
		_ = database.DeleteSession(token)
		return nil, nil
	}
	newExpiry := time.Now().Add(inactivityTimeout)
	err = database.UpdateSessionExpiry(token, newExpiry)
	if err != nil {
		return nil, err
	}
	session.ExpiresAt = newExpiry
	return session, nil
}

func GenerateTOTPSecret(username string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "SecureCLILogin",
		AccountName: username,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

func VerifyTOTP(passcode, secret string) bool {
	return totp.Validate(passcode, secret)
}
