package auth

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Requests to the public methods allowed per client IP: a burst of ipBurst,
// then one more every ipInterval, so ipBurst per minute.
const (
	ipBurst    = 30
	ipInterval = time.Minute / ipBurst
)

// Login attempts allowed per login and client IP, on top of the IP limit.
const (
	loginBurst    = 5
	loginInterval = time.Minute / loginBurst
)

// limiter allows a burst of attempts per key, then one more every interval.
// It slows down guessing instead of locking the account: a lock would let
// anyone lock the owner out. It is safe for concurrent use.
type limiter[K comparable] struct {
	burst    int
	interval time.Duration

	mu        sync.Mutex
	entries   map[K]*rate.Limiter
	lastSweep time.Time
}

func newLimiter[K comparable](burst int, interval time.Duration) *limiter[K] {
	return &limiter[K]{burst: burst, interval: interval, entries: make(map[K]*rate.Limiter)}
}

// allow reports whether one more attempt for key is allowed at now. Once per
// refill time it drops the entries whose bucket is full again: dropping them
// changes nothing, and the map does not grow forever.
func (l *limiter[K]) allow(key K, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastSweep) >= l.interval*time.Duration(l.burst) {
		for k, lim := range l.entries {
			if lim.TokensAt(now) >= float64(l.burst) {
				delete(l.entries, k)
			}
		}
		l.lastSweep = now
	}

	lim, ok := l.entries[key]
	if !ok {
		lim = rate.NewLimiter(rate.Every(l.interval), l.burst)
		l.entries[key] = lim
	}
	return lim.AllowN(now, 1)
}
