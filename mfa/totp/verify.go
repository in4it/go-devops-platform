package totp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
)

const INTERVAL = 30

// SKEW is the number of time steps before and after the current one that are
// accepted by Verify, to allow for clock drift between server and client.
const SKEW = 1

func GetToken(secret string, interval int64) (string, error) {
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", fmt.Errorf("base32 decode error: %s", err)
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(interval))
	hmacHash := hmac.New(sha1.New, key)
	hmacHash.Write(buf)
	h := hmacHash.Sum(nil)
	offset := (h[19] & 15)

	var header uint32
	r := bytes.NewReader(h[offset : offset+4])
	err = binary.Read(r, binary.BigEndian, &header)

	if err != nil {
		return "", fmt.Errorf("binary read error: %s", err)
	}

	return fmt.Sprintf("%06d", int((int(header)&0x7fffffff)%1000000)), nil
}

// Verify checks a TOTP code for the given secret. The current time step and
// SKEW steps before/after are accepted. A code that has been accepted once
// for a secret can't be used again (replay protection): any code for the same
// or an earlier time step of that secret is rejected afterwards.
func Verify(secret, code string) (bool, error) {
	return defaultReplayCache.verify(secret, code, time.Now())
}

func VerifyMultipleIntervals(secret, code string, count int) (bool, error) {
	return verifyMultipleIntervals(secret, code, count, time.Now())
}

func verifyMultipleIntervals(secret, code string, count int, now time.Time) (bool, error) {
	matched := false
	for i := 0; i < count; i++ {
		token, err := GetToken(secret, now.Add(time.Duration(i)*time.Duration(-30)*time.Second).Unix()/30)
		if err != nil {
			return false, fmt.Errorf("GetToken error: %s", err)
		}
		if tokenEqual(token, code) {
			matched = true
		}
	}
	return matched, nil
}

func tokenEqual(token, code string) bool {
	return subtle.ConstantTimeCompare([]byte(token), []byte(code)) == 1
}

// matchInterval returns the matching interval within now ± SKEW steps (constant
// amount of work regardless of which step matches).
func matchInterval(secret, code string, now time.Time) (int64, bool, error) {
	current := now.Unix() / INTERVAL
	var matchedInterval int64
	matched := false
	for i := current - SKEW; i <= current+SKEW; i++ {
		token, err := GetToken(secret, i)
		if err != nil {
			return 0, false, fmt.Errorf("GetToken error: %s", err)
		}
		if tokenEqual(token, code) && !matched {
			matched = true
			matchedInterval = i
		}
	}
	return matchedInterval, matched, nil
}

// replayCache keeps, per factor (keyed by a hash of the secret), the last
// interval for which a code was accepted. Entries older than the accepted
// window can't be replayed anyway and are pruned.
type replayCache struct {
	mu   sync.Mutex
	used map[[32]byte]int64
}

var defaultReplayCache = newReplayCache()

func newReplayCache() *replayCache {
	return &replayCache{used: make(map[[32]byte]int64)}
}

func (r *replayCache) verify(secret, code string, now time.Time) (bool, error) {
	interval, ok, err := matchInterval(secret, code, now)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	key := sha256.Sum256([]byte(strings.ToUpper(secret)))
	current := now.Unix() / INTERVAL

	r.mu.Lock()
	defer r.mu.Unlock()
	r.prune(current)
	if last, found := r.used[key]; found && interval <= last {
		return false, nil // replay of an already used (or older) code
	}
	r.used[key] = interval
	return true, nil
}

// prune removes entries that are outside the acceptance window. Must be called with mu held.
func (r *replayCache) prune(current int64) {
	for k, last := range r.used {
		if last < current-SKEW {
			delete(r.used, k)
		}
	}
}
