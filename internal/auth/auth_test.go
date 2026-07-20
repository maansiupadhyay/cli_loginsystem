package auth

import (
	"testing"
	"time"

	"cli-login-system/internal/db"
)

func TestHashAndVerifyPassword(t *testing.T) {
	password := "supersecret"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	if !VerifyPassword(password, hash) {
		t.Errorf("expected password to verify successfully")
	}
	if VerifyPassword("wrongpassword", hash) {
		t.Errorf("expected verification to fail for wrong password")
	}
}

func setupTestDB(t *testing.T) *db.DB {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}
	return database
}

func TestLockoutTracking(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	username := "testuser"
	threshold := 3
	duration := 100 * time.Millisecond

	locked, _, err := CheckLockout(database, username)
	if err != nil {
		t.Fatalf("failed to check lockout: %v", err)
	}
	if locked {
		t.Errorf("expected user to not be locked initially")
	}

	locked, _, err = RecordFailedAttempt(database, username, threshold, duration)
	if err != nil {
		t.Fatalf("failed to record attempt: %v", err)
	}
	if locked {
		t.Errorf("expected not locked after 1 attempt")
	}

	locked, _, err = RecordFailedAttempt(database, username, threshold, duration)
	if err != nil {
		t.Fatalf("failed to record attempt: %v", err)
	}
	if locked {
		t.Errorf("expected not locked after 2 attempts")
	}

	locked, lockedUntil, err := RecordFailedAttempt(database, username, threshold, duration)
	if err != nil {
		t.Fatalf("failed to record attempt: %v", err)
	}
	if !locked {
		t.Errorf("expected user to be locked after 3 attempts")
	}
	if lockedUntil.IsZero() {
		t.Errorf("expected lockedUntil to be set")
	}

	locked, _, err = CheckLockout(database, username)
	if err != nil {
		t.Fatalf("failed to check lockout: %v", err)
	}
	if !locked {
		t.Errorf("expected check lockout to return true")
	}

	time.Sleep(120 * time.Millisecond)

	locked, _, err = CheckLockout(database, username)
	if err != nil {
		t.Fatalf("failed to check lockout: %v", err)
	}
	if locked {
		t.Errorf("expected lockout to expire after sleep")
	}

	err = ResetFailedAttempts(database, username)
	if err != nil {
		t.Fatalf("failed to reset: %v", err)
	}

	attempts, _, _, err := database.GetLoginAttempts(username)
	if err != nil {
		t.Fatalf("failed to get attempts: %v", err)
	}
	if attempts != 0 {
		t.Errorf("expected attempts to be 0 after reset, got %d", attempts)
	}
}

func TestSessionExpiration(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	err := database.CreateUser("user1", "hash")
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	token, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	expiresAt := time.Now().Add(10 * time.Millisecond)
	err = database.CreateSession(token, "user1", expiresAt)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	sess, err := VerifySession(database, token, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to verify session: %v", err)
	}
	if sess == nil {
		t.Fatalf("expected session to be valid initially")
	}

	time.Sleep(30 * time.Millisecond)

	sess, err = VerifySession(database, token, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to verify session: %v", err)
	}
	if sess != nil {
		t.Errorf("expected session to be expired")
	}
}
