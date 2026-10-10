package login

import (
	"sync"
	"time"
)

const MAX_LOGIN_ATTEMPTS = 3
const LOGIN_ATTEMPTS_WINDOW = 3 * time.Minute

var mu sync.Mutex

type Attempts map[string][]Attempt

type Attempt struct {
	Timestamp time.Time
}

func ClearAttemptsForLogin(attempts Attempts, login string) {
	mu.Lock()
	defer mu.Unlock()
	delete(attempts, login)
}

func RecordAttempt(attempts Attempts, login string) {
	mu.Lock()
	defer mu.Unlock()
	attempts[login] = append(attempts[login], Attempt{Timestamp: time.Now()})
}

// UndoAttempt removes the most recent attempt for a login, used when an attempt
// reserved by CheckAndRecordAttempt turned out not to be a failed login.
func UndoAttempt(attempts Attempts, login string) {
	mu.Lock()
	defer mu.Unlock()
	if n := len(attempts[login]); n > 0 {
		attempts[login] = attempts[login][:n-1]
	}
	if len(attempts[login]) == 0 {
		delete(attempts, login)
	}
}

func CheckTooManyLogins(attempts Attempts, login string) bool {
	mu.Lock()
	defer mu.Unlock()
	return recentAttempts(attempts, login, time.Now()) >= MAX_LOGIN_ATTEMPTS
}

// CheckAndRecordAttempt atomically checks whether the login is rate limited and,
// if not, records an attempt. Recording before authenticating makes sure parallel
// requests can't all pass the check before any of them is recorded.
// Returns true when there are too many login attempts.
func CheckAndRecordAttempt(attempts Attempts, login string) bool {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now()
	pruneAttempts(attempts, now)
	if recentAttempts(attempts, login, now) >= MAX_LOGIN_ATTEMPTS {
		return true
	}
	attempts[login] = append(attempts[login], Attempt{Timestamp: now})
	return false
}

// recentAttempts returns the attempts within the window. Must be called with mu held.
func recentAttempts(attempts Attempts, login string, now time.Time) int {
	count := 0
	for _, attempt := range attempts[login] {
		if now.Sub(attempt.Timestamp) <= LOGIN_ATTEMPTS_WINDOW {
			count++
		}
	}
	return count
}

// pruneAttempts removes attempts outside the window, so the map doesn't grow
// with every login name that is tried. Must be called with mu held.
func pruneAttempts(attempts Attempts, now time.Time) {
	for login, loginAttempts := range attempts {
		recent := loginAttempts[:0]
		for _, attempt := range loginAttempts {
			if now.Sub(attempt.Timestamp) <= LOGIN_ATTEMPTS_WINDOW {
				recent = append(recent, attempt)
			}
		}
		if len(recent) == 0 {
			delete(attempts, login)
		} else {
			attempts[login] = recent
		}
	}
}
