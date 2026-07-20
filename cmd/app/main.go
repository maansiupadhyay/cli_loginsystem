package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"cli-login-system/internal/cli"
	"cli-login-system/internal/db"
)

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./db.sqlite"
	}
	historyPath := os.Getenv("HISTORY_PATH")
	if historyPath == "" {
		historyPath = "./.cli_history"
	}
	lockoutThreshold := 5
	if ltStr := os.Getenv("LOCKOUT_THRESHOLD"); ltStr != "" {
		if val, err := strconv.Atoi(ltStr); err == nil {
			lockoutThreshold = val
		}
	}
	lockoutDuration := 15 * time.Minute
	if ldStr := os.Getenv("LOCKOUT_DURATION_MINS"); ldStr != "" {
		if val, err := strconv.Atoi(ldStr); err == nil {
			lockoutDuration = time.Duration(val) * time.Minute
		}
	}
	sessionDuration := 30 * time.Minute
	if sdStr := os.Getenv("SESSION_TIMEOUT_MINS"); sdStr != "" {
		if val, err := strconv.Atoi(sdStr); err == nil {
			sessionDuration = time.Duration(val) * time.Minute
		}
	}
	database, err := db.Open(dbPath)
	if err != nil {
		fmt.Printf("Failed to open database: %v\n", err)
		os.Exit(1)
	}
	defer database.Close()
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			_ = database.CleanExpiredSessions()
		}
	}()
	c, err := cli.NewCLI(database, lockoutThreshold, lockoutDuration, sessionDuration, historyPath)
	if err != nil {
		fmt.Printf("Failed to initialize CLI: %v\n", err)
		os.Exit(1)
	}
	defer c.Close()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		c.Close()
		database.Close()
		os.Exit(0)
	}()
	c.Run()
}
