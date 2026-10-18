package httpapi

import (
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/contember/sonda/api"
	"github.com/contember/sonda/internal/apierr"
	"github.com/contember/sonda/internal/authz"
)

// limiters hold the rate and concurrency limits of each identity in memory.
type limiters struct {
	mu         sync.Mutex
	byIdentity map[string]*identityLimiter
}

type identityLimiter struct {
	perMinute  int
	concurrent int
	rate       *rate.Limiter
	slots      chan struct{}
}

func newLimiters() *limiters {
	return &limiters{byIdentity: map[string]*identityLimiter{}}
}

// acquire takes one request from the rate limit and one concurrency slot. Requests over
// either limit are rejected rather than queued, so an agent learns to slow down.
func (l *limiters) acquire(identity *authz.Identity) (release func(), err error) {
	limiter := l.get(identity)
	if !limiter.rate.Allow() {
		return nil, apierr.New(api.CodeRateLimited, "more than %d requests per minute", identity.Limits.RequestsPerMinute)
	}
	select {
	case limiter.slots <- struct{}{}:
		return func() { <-limiter.slots }, nil
	default:
		return nil, apierr.New(api.CodeRateLimited, "more than %d concurrent requests", identity.Limits.ConcurrentQueries)
	}
}

func (l *limiters) get(identity *authz.Identity) *identityLimiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	perMinute, concurrent := identity.Limits.RequestsPerMinute, identity.Limits.ConcurrentQueries
	limiter, ok := l.byIdentity[identity.Name]
	// Limits change in the admin UI at runtime; a new limiter starts with a full budget.
	if !ok || limiter.perMinute != perMinute || limiter.concurrent != concurrent {
		// A burst of ten seconds' worth of requests lets an agent fire a few calls at once.
		burst := max(1, perMinute/6)
		limiter = &identityLimiter{
			perMinute:  perMinute,
			concurrent: concurrent,
			rate:       rate.NewLimiter(rate.Every(time.Minute/time.Duration(perMinute)), burst),
			slots:      make(chan struct{}, concurrent),
		}
		l.byIdentity[identity.Name] = limiter
	}
	return limiter
}
