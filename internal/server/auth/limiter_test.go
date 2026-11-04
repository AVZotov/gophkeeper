package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLimiter(t *testing.T) {
	l := newLimiter[loginAttempt](loginBurst, loginInterval)
	alice := loginAttempt{login: "alice", ip: "10.0.0.1"}
	now := time.Now()

	for i := range loginBurst {
		assert.True(t, l.allow(alice, now), "attempt %d", i+1)
	}
	assert.False(t, l.allow(alice, now), "over the burst")
	assert.True(t, l.allow(loginAttempt{login: "alice", ip: "10.0.0.2"}, now), "another IP")
	assert.True(t, l.allow(loginAttempt{login: "bob", ip: "10.0.0.1"}, now), "another login")

	assert.False(t, l.allow(alice, now.Add(loginInterval/2)), "too early for the next attempt")
	assert.True(t, l.allow(alice, now.Add(loginInterval)), "one attempt comes back after the interval")
	assert.False(t, l.allow(alice, now.Add(loginInterval)))
}

func TestLimiterDropsIdleEntries(t *testing.T) {
	l := newLimiter[string](loginBurst, loginInterval)
	refill := loginInterval * loginBurst
	start := time.Now()

	l.allow("idle", start)
	for range loginBurst {
		l.allow("busy", start.Add(refill/2))
	}
	l.allow("new", start.Add(refill))

	assert.NotContains(t, l.entries, "idle", "a full bucket is dropped")
	assert.Contains(t, l.entries, "busy", "a bucket that is not full yet is kept")
}
