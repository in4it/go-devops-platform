package login

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCheckAndRecordAttempt(t *testing.T) {
	attempts := make(Attempts)
	for i := 0; i < MAX_LOGIN_ATTEMPTS; i++ {
		if CheckAndRecordAttempt(attempts, "john") {
			t.Fatalf("attempt %d: rate limited too early", i)
		}
	}
	if !CheckAndRecordAttempt(attempts, "john") {
		t.Fatalf("expected rate limit after %d attempts", MAX_LOGIN_ATTEMPTS)
	}
	if !CheckTooManyLogins(attempts, "john") {
		t.Fatalf("expected CheckTooManyLogins to report the rate limit")
	}
	if len(attempts["john"]) != MAX_LOGIN_ATTEMPTS {
		t.Fatalf("rate limited attempts should not be recorded, got %d", len(attempts["john"]))
	}
	if CheckAndRecordAttempt(attempts, "jane") {
		t.Fatalf("other logins should not be rate limited")
	}
	ClearAttemptsForLogin(attempts, "john")
	if CheckAndRecordAttempt(attempts, "john") {
		t.Fatalf("expected no rate limit after clearing attempts")
	}
}

func TestUndoAttempt(t *testing.T) {
	attempts := make(Attempts)
	for i := 0; i < MAX_LOGIN_ATTEMPTS*2; i++ {
		if CheckAndRecordAttempt(attempts, "john") {
			t.Fatalf("attempt %d: undone attempts should not count", i)
		}
		UndoAttempt(attempts, "john")
	}
	if _, ok := attempts["john"]; ok {
		t.Fatalf("expected no entry left after undo")
	}
	UndoAttempt(attempts, "nobody") // must not panic
}

func TestPruneOldAttempts(t *testing.T) {
	attempts := make(Attempts)
	old := time.Now().Add(-2 * LOGIN_ATTEMPTS_WINDOW)
	for i := 0; i < 100; i++ {
		attempts[fmt.Sprintf("user%d", i)] = []Attempt{{Timestamp: old}}
	}
	attempts["john"] = []Attempt{{Timestamp: old}, {Timestamp: old}, {Timestamp: old}}
	if CheckAndRecordAttempt(attempts, "john") {
		t.Fatalf("attempts outside the window should not count")
	}
	if len(attempts) != 1 {
		t.Fatalf("expected old entries to be pruned, got %d entries", len(attempts))
	}
	if len(attempts["john"]) != 1 {
		t.Fatalf("expected only the new attempt for john, got %d", len(attempts["john"]))
	}
}

// TestCheckAndRecordAttemptParallel: run with -race. Exactly MAX_LOGIN_ATTEMPTS
// parallel attempts may pass.
func TestCheckAndRecordAttemptParallel(t *testing.T) {
	attempts := make(Attempts)
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed := 0
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !CheckAndRecordAttempt(attempts, "john") {
				mu.Lock()
				passed++
				mu.Unlock()
			}
			CheckTooManyLogins(attempts, "john")
		}()
	}
	wg.Wait()
	if passed != MAX_LOGIN_ATTEMPTS {
		t.Fatalf("expected %d attempts to pass, got %d", MAX_LOGIN_ATTEMPTS, passed)
	}
}
