package totp

import (
	"testing"
	"time"
)

func TestVerify(t *testing.T) { // validated with https://2fa.glitch.me/
	interval := int64(57275699)
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	token, err := GetToken(secret, interval)
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if token != "840823" {
		t.Fatalf("wrong token. Got: %s", token)
	}
}

func TestVerifyWrongSecret(t *testing.T) {
	interval := int64(57275699)
	secret := "wrong secret"
	_, err := GetToken(secret, interval)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestVerifyMultipleIntervals(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	ok, err := verifyMultipleIntervals(secret, "312137", 20, time.Unix(1718272397, 0))
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if !ok {
		t.Fatalf("no token matched")
	}
}

func TestVerifyMultipleIntervalsWrongToken(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	ok, err := verifyMultipleIntervals(secret, "312137", 20, time.Unix(1718272000, 0))
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if ok {
		t.Fatalf("token matched, but shouldn't have")
	}
}

func TestVerifyClockSkew(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	now := time.Unix(1718272397, 0)
	current := now.Unix() / INTERVAL
	for _, offset := range []int64{-1, 0, 1} {
		r := newReplayCache()
		token, err := GetToken(secret, current+offset)
		if err != nil {
			t.Fatalf("GetToken error: %s", err)
		}
		ok, err := r.verify(secret, token, now)
		if err != nil {
			t.Fatalf("verify error: %s", err)
		}
		if !ok {
			t.Fatalf("expected token with offset %d to be accepted", offset)
		}
	}
	for _, offset := range []int64{-2, 2} {
		r := newReplayCache()
		token, err := GetToken(secret, current+offset)
		if err != nil {
			t.Fatalf("GetToken error: %s", err)
		}
		ok, err := r.verify(secret, token, now)
		if err != nil {
			t.Fatalf("verify error: %s", err)
		}
		if ok {
			t.Fatalf("expected token with offset %d to be rejected", offset)
		}
	}
}

func TestVerifyReplay(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	now := time.Unix(1718272397, 0)
	current := now.Unix() / INTERVAL
	r := newReplayCache()
	token, err := GetToken(secret, current)
	if err != nil {
		t.Fatalf("GetToken error: %s", err)
	}
	ok, err := r.verify(secret, token, now)
	if err != nil || !ok {
		t.Fatalf("expected first use to succeed (ok=%v, err=%v)", ok, err)
	}
	ok, err = r.verify(secret, token, now.Add(5*time.Second))
	if err != nil {
		t.Fatalf("verify error: %s", err)
	}
	if ok {
		t.Fatalf("expected replayed token to be rejected")
	}
	// an older code within the skew window can't be used after a newer one
	prevToken, err := GetToken(secret, current-1)
	if err != nil {
		t.Fatalf("GetToken error: %s", err)
	}
	ok, err = r.verify(secret, prevToken, now)
	if err != nil {
		t.Fatalf("verify error: %s", err)
	}
	if ok {
		t.Fatalf("expected older token to be rejected after newer token was used")
	}
	// next interval's code is still accepted
	nextToken, err := GetToken(secret, current+1)
	if err != nil {
		t.Fatalf("GetToken error: %s", err)
	}
	ok, err = r.verify(secret, nextToken, now.Add(30*time.Second))
	if err != nil || !ok {
		t.Fatalf("expected next interval token to be accepted (ok=%v, err=%v)", ok, err)
	}
	// other factor (different secret) isn't affected
	otherSecret := "JBSWY3DPEHPK3PXP"
	otherToken, err := GetToken(otherSecret, current)
	if err != nil {
		t.Fatalf("GetToken error: %s", err)
	}
	ok, err = r.verify(otherSecret, otherToken, now)
	if err != nil || !ok {
		t.Fatalf("expected other secret token to be accepted (ok=%v, err=%v)", ok, err)
	}
}

func TestVerifyReplayCachePruned(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	now := time.Unix(1718272397, 0)
	r := newReplayCache()
	token, err := GetToken(secret, now.Unix()/INTERVAL)
	if err != nil {
		t.Fatalf("GetToken error: %s", err)
	}
	if ok, err := r.verify(secret, token, now); err != nil || !ok {
		t.Fatalf("expected token to be accepted (ok=%v, err=%v)", ok, err)
	}
	later := now.Add(10 * time.Minute)
	otherSecret := "JBSWY3DPEHPK3PXP"
	otherToken, err := GetToken(otherSecret, later.Unix()/INTERVAL)
	if err != nil {
		t.Fatalf("GetToken error: %s", err)
	}
	if ok, err := r.verify(otherSecret, otherToken, later); err != nil || !ok {
		t.Fatalf("expected token to be accepted (ok=%v, err=%v)", ok, err)
	}
	if len(r.used) != 1 {
		t.Fatalf("expected stale entries to be pruned, got %d entries", len(r.used))
	}
}

func TestVerifyWrongCode(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	ok, err := newReplayCache().verify(secret, "", time.Now())
	if err != nil {
		t.Fatalf("verify error: %s", err)
	}
	if ok {
		t.Fatalf("expected empty code to be rejected")
	}
}
