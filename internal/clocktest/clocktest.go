// Package clocktest provides a clock for tests that moves only when told to.
package clocktest

import (
	"sync"
	"time"
)

// Clock shows a fixed time until it is moved with [Clock.Advance]. It is safe
// for concurrent use.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// New returns a clock that shows start.
func New(start time.Time) *Clock {
	return &Clock{now: start}
}

// Now returns the time the clock shows.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
