package auth

import (
	"sync"
	"time"
)

// Limiter bans source IPs after repeated failed logins and caps concurrent
// unauthenticated connections per IP. It deliberately does not lock out
// usernames, since that would let anyone lock the real owner out.
type Limiter struct {
	mu          sync.Mutex
	maxFailures int
	window      time.Duration
	banFor      time.Duration
	maxPending  int
	ips         map[string]*ipState
}

type ipState struct {
	failures []time.Time
	bannedAt time.Time
	banCount int
	pending  int
}

func NewLimiter(maxFailures int, window, banFor time.Duration, maxPending int) *Limiter {
	l := &Limiter{maxFailures: maxFailures, window: window, banFor: banFor, maxPending: maxPending, ips: map[string]*ipState{}}
	go l.gc()
	return l
}

func (l *Limiter) state(ip string) *ipState {
	s, ok := l.ips[ip]
	if !ok {
		s = &ipState{}
		l.ips[ip] = s
	}
	return s
}

// banDuration doubles with each repeated ban, capped at 24h.
func (l *Limiter) banDuration(s *ipState) time.Duration {
	d := l.banFor
	for i := 1; i < s.banCount && d < 24*time.Hour; i++ {
		d *= 2
	}
	if d > 24*time.Hour {
		d = 24 * time.Hour
	}
	return d
}

// Banned reports whether ip is currently banned and until when.
func (l *Limiter) Banned(ip string) (bool, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.ips[ip]
	if !ok || s.bannedAt.IsZero() {
		return false, time.Time{}
	}
	until := s.bannedAt.Add(l.banDuration(s))
	if time.Now().After(until) {
		s.bannedAt = time.Time{}
		return false, time.Time{}
	}
	return true, until
}

// Acquire registers a new unauthenticated connection; false means too many.
func (l *Limiter) Acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.state(ip)
	if s.pending >= l.maxPending {
		return false
	}
	s.pending++
	return true
}

func (l *Limiter) Release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := l.ips[ip]; ok && s.pending > 0 {
		s.pending--
	}
}

// Fail records a failed attempt; returns true if this triggered a ban.
func (l *Limiter) Fail(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.state(ip)
	now := time.Now()
	kept := s.failures[:0]
	for _, t := range s.failures {
		if now.Sub(t) < l.window {
			kept = append(kept, t)
		}
	}
	s.failures = append(kept, now)
	if len(s.failures) >= l.maxFailures {
		s.failures = nil
		s.bannedAt = now
		s.banCount++
		return true
	}
	return false
}

// Succeed clears the failure history for ip.
func (l *Limiter) Succeed(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := l.ips[ip]; ok {
		s.failures = nil
		s.banCount = 0
	}
}

func (l *Limiter) gc() {
	for range time.Tick(10 * time.Minute) {
		l.mu.Lock()
		now := time.Now()
		for ip, s := range l.ips {
			idle := len(s.failures) == 0 && s.pending == 0 &&
				(s.bannedAt.IsZero() || now.Sub(s.bannedAt) > 48*time.Hour)
			if idle {
				delete(l.ips, ip)
			}
		}
		l.mu.Unlock()
	}
}
