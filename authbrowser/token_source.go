package authbrowser

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TokenSource is a stateful wrapper around Login. It caches the current user
// token in memory and transparently re-runs Login when the cached token
// enters its refresh window (80% of remaining lifetime by default).
//
// TokenSource satisfies hcloudplus.TokenSource from the parent module:
//
//	func (*TokenSource) Token(ctx context.Context) (string, time.Time, error)
//
// so callers can plug it directly into hcloudplus.WithTokenSource without
// pulling authbrowser into the hcloudplus package itself.
type TokenSource struct {
	creds Credentials
	opts  []Option

	// refreshFraction is the fraction of the remaining token lifetime at
	// which we proactively refresh. Default 0.8. Exposed for tests.
	refreshFraction float64

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewTokenSource builds a TokenSource with the given credentials and Login
// options. The first Token() call triggers the initial Login.
func NewTokenSource(creds Credentials, opts ...Option) *TokenSource {
	return &TokenSource{
		creds:           creds,
		opts:            opts,
		refreshFraction: 0.8,
	}
}

// Token returns a currently-valid user token, re-running Login if the cached
// token is unset or within the refresh window. Concurrent callers share a
// single refresh.
func (s *TokenSource) Token(ctx context.Context) (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.token != "" && !s.needsRefresh(time.Now()) {
		return s.token, s.expires, nil
	}

	token, expires, err := Login(ctx, s.creds, s.opts...)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("authbrowser: refresh login: %w", err)
	}
	s.token = token
	s.expires = expires
	return token, expires, nil
}

// Invalidate drops the cached token, forcing the next Token() call to
// re-login. Useful when the consumer observes an auth failure with the
// current token.
func (s *TokenSource) Invalidate() {
	s.mu.Lock()
	s.token = ""
	s.expires = time.Time{}
	s.mu.Unlock()
}

// needsRefresh reports whether the cached token is close enough to expiry
// that we should refresh proactively.
func (s *TokenSource) needsRefresh(now time.Time) bool {
	if s.expires.IsZero() {
		return false // unknown expiry — cache forever, rely on invalidate
	}
	remaining := s.expires.Sub(now)
	if remaining <= 0 {
		return true
	}
	// Refresh when < (1 - refreshFraction) of the total lifetime is left.
	// We don't know the total lifetime — approximate by saying "refresh when
	// remaining < refreshFraction * <elapsed since cache>" is noisy, so a
	// simpler heuristic: refresh when remaining is below a floor of
	// refreshFraction * cookieLifetimeEstimate (12h).
	const cookieLifetimeEstimate = 12 * time.Hour
	return remaining < time.Duration((1-s.refreshFraction)*float64(cookieLifetimeEstimate))
}
