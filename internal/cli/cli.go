package cli

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"cli-login-system/internal/auth"
	"cli-login-system/internal/db"
	"github.com/chzyer/readline"
	"github.com/mdp/qrterminal/v3"
)

type CLI struct {
	db               *db.DB
	rl               *readline.Instance
	lockoutThreshold int
	lockoutDuration  time.Duration
	sessionDuration  time.Duration
	sessionToken     string
	currentUser      *db.User
}

type MyCompleter struct {
	cli *CLI
}

func (mc *MyCompleter) Do(line []rune, pos int) ([][]rune, int) {
	lineStr := string(line[:pos])
	if strings.Contains(lineStr, " ") {
		return nil, 0
	}
	var cmds []string
	if mc.cli.currentUser == nil {
		cmds = []string{"register", "login", "help", "exit"}
	} else {
		cmds = []string{"whoami", "enable-2fa", "disable-2fa", "logout", "help"}
	}
	var matches [][]rune
	for _, cmd := range cmds {
		if strings.HasPrefix(cmd, lineStr) {
			matches = append(matches, []rune(cmd[len(lineStr):]))
		}
	}
	return matches, len(lineStr)
}

func NewCLI(database *db.DB, lockoutThreshold int, lockoutDuration, sessionDuration time.Duration, historyFile string) (*CLI, error) {
	c := &CLI{
		db:               database,
		lockoutThreshold: lockoutThreshold,
		lockoutDuration:  lockoutDuration,
		sessionDuration:  sessionDuration,
	}
	completer := &MyCompleter{cli: c}
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "guest> ",
		HistoryFile:     historyFile,
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})
	if err != nil {
		return nil, err
	}
	c.rl = rl
	return c, nil
}

func (c *CLI) Close() {
	if c.rl != nil {
		c.rl.Close()
	}
}

func (c *CLI) promptInput(prompt string) (string, error) {
	c.rl.SetPrompt(prompt)
	defer c.updatePrompt()
	line, err := c.rl.Readline()
	if err != nil {
		return "", err
	}
	return line, nil
}

func (c *CLI) promptPassword(prompt string) (string, error) {
	passwd, err := c.rl.ReadPassword(prompt)
	if err != nil {
		return "", err
	}
	return string(passwd), nil
}

func (c *CLI) updatePrompt() {
	if c.currentUser == nil {
		c.rl.SetPrompt("guest> ")
	} else {
		c.rl.SetPrompt(fmt.Sprintf("%s> ", c.currentUser.Username))
	}
}

func (c *CLI) Run() {
	c.handleHelp()
	fmt.Println()
	for {
		if c.currentUser != nil {
			sess, err := auth.VerifySession(c.db, c.sessionToken, c.sessionDuration)
			if err != nil || sess == nil {
				c.currentUser = nil
				c.sessionToken = ""
				c.updatePrompt()
				fmt.Println("\n[Session Expired] Please login again.")
			}
		}
		line, err := c.rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				if len(line) == 0 {
					break
				}
				continue
			}
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		args := strings.Fields(line)
		cmd := args[0]
		if c.currentUser == nil {
			switch cmd {
			case "register":
				c.handleRegister()
			case "login":
				c.handleLogin()
			case "help":
				c.handleHelp()
			case "exit":
				return
			default:
				fmt.Println("Unknown command. Type 'help' for available commands.")
			}
		} else {
			switch cmd {
			case "whoami":
				sess, err := c.db.GetSession(c.sessionToken)
				if err == nil && sess != nil {
					c.showBanner(c.currentUser, sess.ExpiresAt)
				}
			case "enable-2fa":
				c.handleEnable2FA()
			case "disable-2fa":
				c.handleDisable2FA()
			case "logout":
				c.handleLogout()
			case "help":
				c.handleHelp()
			default:
				fmt.Println("Unknown command. Type 'help' for available commands.")
			}
		}
	}
}

func (c *CLI) handleRegister() {
	username, err := c.promptInput("Username: ")
	if err != nil {
		return
	}
	username = strings.TrimSpace(username)
	if username == "" {
		fmt.Println("Username cannot be empty.")
		return
	}
	existing, err := c.db.GetUser(username)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if existing != nil {
		fmt.Println("Username already taken.")
		return
	}
	password, err := c.promptPassword("Password: ")
	if err != nil {
		return
	}
	if len(password) < 6 {
		fmt.Println("Password must be at least 6 characters long.")
		return
	}
	confirm, err := c.promptPassword("Confirm Password: ")
	if err != nil {
		return
	}
	if password != confirm {
		fmt.Println("Passwords do not match.")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Printf("Error hashing password: %v\n", err)
		return
	}
	err = c.db.CreateUser(username, hash)
	if err != nil {
		fmt.Printf("Error creating user: %v\n", err)
		return
	}
	fmt.Println("Registration successful.")
}

func (c *CLI) handleLogin() {
	username, err := c.promptInput("Username: ")
	if err != nil {
		return
	}
	username = strings.TrimSpace(username)
	if username == "" {
		fmt.Println("Username cannot be empty.")
		return
	}
	locked, lockedUntil, err := auth.CheckLockout(c.db, username)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if locked {
		fmt.Printf("Account is locked. Try again after %s.\n", lockedUntil.Format("2006-01-02 15:04:05 UTC"))
		return
	}
	password, err := c.promptPassword("Password: ")
	if err != nil {
		return
	}
	user, err := c.db.GetUser(username)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if user == nil || !auth.VerifyPassword(password, user.PasswordHash) {
		locked, lockedUntil, err = auth.RecordFailedAttempt(c.db, username, c.lockoutThreshold, c.lockoutDuration)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		if locked {
			fmt.Printf("Invalid credentials. Account has been locked until %s.\n", lockedUntil.Format("2006-01-02 15:04:05 UTC"))
		} else {
			fmt.Println("Invalid credentials.")
		}
		return
	}
	if user.TOTPEnabled {
		code, err := c.promptInput("Enter 2FA Code: ")
		if err != nil {
			return
		}
		code = strings.TrimSpace(code)
		if !auth.VerifyTOTP(code, user.TOTPSecret.String) {
			locked, lockedUntil, err = auth.RecordFailedAttempt(c.db, username, c.lockoutThreshold, c.lockoutDuration)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}
			if locked {
				fmt.Printf("Invalid 2FA code. Account has been locked until %s.\n", lockedUntil.Format("2006-01-02 15:04:05 UTC"))
			} else {
				fmt.Println("Invalid 2FA code.")
			}
			return
		}
	}
	err = auth.ResetFailedAttempts(c.db, username)
	if err != nil {
		fmt.Printf("Error resetting attempts: %v\n", err)
	}
	token, err := auth.GenerateSessionToken()
	if err != nil {
		fmt.Printf("Error generating session: %v\n", err)
		return
	}
	expiresAt := time.Now().Add(c.sessionDuration)
	err = c.db.CreateSession(token, username, expiresAt)
	if err != nil {
		fmt.Printf("Error storing session: %v\n", err)
		return
	}
	err = c.db.UpdateLastLogin(username)
	if err != nil {
		fmt.Printf("Error updating last login: %v\n", err)
	}
	freshUser, err := c.db.GetUser(username)
	if err != nil {
		fmt.Printf("Error fetching user details: %v\n", err)
		return
	}
	c.currentUser = freshUser
	c.sessionToken = token
	c.updatePrompt()
	c.showBanner(freshUser, expiresAt)
}

func (c *CLI) handleEnable2FA() {
	if c.currentUser.TOTPEnabled {
		fmt.Println("2FA is already enabled.")
		return
	}
	secret, uri, err := auth.GenerateTOTPSecret(c.currentUser.Username)
	if err != nil {
		fmt.Printf("Error generating TOTP secret: %v\n", err)
		return
	}
	fmt.Println("\n--- Enable Two-Factor Authentication ---")
	fmt.Printf("Secret Key: %s\n", secret)
	fmt.Printf("URI: %s\n\n", uri)
	fmt.Println("Scan the QR code below using your authenticator app:")
	qrterminal.GenerateHalfBlock(uri, qrterminal.L, os.Stdout)
	fmt.Println()
	code, err := c.promptInput("Enter 2FA Code to verify: ")
	if err != nil {
		return
	}
	code = strings.TrimSpace(code)
	if !auth.VerifyTOTP(code, secret) {
		fmt.Println("Verification failed. 2FA not enabled.")
		return
	}
	err = c.db.UpdateUser2FA(c.currentUser.Username, secret, true)
	if err != nil {
		fmt.Printf("Error updating database: %v\n", err)
		return
	}
	c.currentUser.TOTPEnabled = true
	c.currentUser.TOTPSecret = sql.NullString{String: secret, Valid: true}
	fmt.Println("2FA enabled successfully.")
}

func (c *CLI) handleDisable2FA() {
	if !c.currentUser.TOTPEnabled {
		fmt.Println("2FA is not enabled.")
		return
	}
	confirm, err := c.promptInput("Confirm disabling 2FA? (y/n): ")
	if err != nil {
		return
	}
	confirm = strings.ToLower(strings.TrimSpace(confirm))
	if confirm != "y" && confirm != "yes" {
		fmt.Println("Operation cancelled.")
		return
	}
	err = c.db.UpdateUser2FA(c.currentUser.Username, "", false)
	if err != nil {
		fmt.Printf("Error updating database: %v\n", err)
		return
	}
	c.currentUser.TOTPEnabled = false
	c.currentUser.TOTPSecret = sql.NullString{Valid: false}
	fmt.Println("2FA disabled successfully.")
}

func (c *CLI) handleLogout() {
	if c.sessionToken != "" {
		err := c.db.DeleteSession(c.sessionToken)
		if err != nil {
			fmt.Printf("Error deleting session: %v\n", err)
		}
	}
	c.currentUser = nil
	c.sessionToken = ""
	c.updatePrompt()
	fmt.Println("Logged out successfully.")
}

func (c *CLI) handleHelp() {
	if c.currentUser == nil {
		fmt.Println("\nAvailable commands:")
		fmt.Println("  register - Register a new user")
		fmt.Println("  login    - Authenticate and start a session")
		fmt.Println("  help     - Display help information")
		fmt.Println("  exit     - Exit the application")
	} else {
		fmt.Println("\nAvailable commands:")
		fmt.Println("  whoami      - Display user session information")
		fmt.Println("  enable-2fa  - Enable Two-Factor Authentication")
		fmt.Println("  disable-2fa - Disable Two-Factor Authentication")
		fmt.Println("  logout      - Terminate the current session")
		fmt.Println("  help        - Display help information")
	}
}

func (c *CLI) showBanner(u *db.User, expiresAt time.Time) {
	fmt.Println("==================================================")
	fmt.Printf("              WELCOME BACK, %s              \n", strings.ToUpper(u.Username))
	fmt.Println("==================================================")
	fmt.Printf("Registration Date  : %s\n", u.RegistrationDate.Format("2006-01-02 15:04:05 UTC"))
	mfaStatus := "DISABLED"
	if u.TOTPEnabled {
		mfaStatus = "ENABLED"
	}
	fmt.Printf("MFA Status         : %s\n", mfaStatus)
	fmt.Printf("Session Expiration : %s\n", expiresAt.Format("2006-01-02 15:04:05 UTC"))
	lastLogin := "N/A"
	if u.LastLoginTime.Valid {
		lastLogin = u.LastLoginTime.Time.Format("2006-01-02 15:04:05 UTC")
	}
	fmt.Printf("Last Login Time    : %s\n", lastLogin)
	fmt.Println("==================================================")
}
