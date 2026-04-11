//go:build integration

package authbrowser

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Integration test for the full browser login flow.
//
// Run with:
//
//	HETZNER_USERNAME="$(op read op://vault/accounts.hetzner.com/username)" \
//	HETZNER_PASSWORD="$(op read op://vault/accounts.hetzner.com/password)" \
//	HETZNER_TOTP_CMD="op read 'op://vault/accounts.hetzner.com/one-time password?attribute=totp'" \
//	go test -tags=integration -race -timeout=3m ./authbrowser/
//
// To watch the browser:
//
//	HETZNER_HEADLESS=0 go test -tags=integration -v -run TestIT_Login ./authbrowser/
//
// The test performs one real login. It does NOT log, print or persist the
// returned token — only its length and expiry are asserted.

func credsFromEnv(t *testing.T) Credentials {
	t.Helper()
	user := os.Getenv("HETZNER_USERNAME")
	pass := os.Getenv("HETZNER_PASSWORD")
	cmd := os.Getenv("HETZNER_TOTP_CMD")
	if user == "" || pass == "" || cmd == "" {
		t.Skip("HETZNER_USERNAME, HETZNER_PASSWORD and HETZNER_TOTP_CMD must be set")
	}
	return Credentials{
		Username: user,
		Password: pass,
		TOTP: func(ctx context.Context) (string, error) {
			out, err := exec.CommandContext(ctx, "sh", "-c", cmd).Output()
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(out)), nil
		},
	}
}

func TestIT_Login(t *testing.T) {
	creds := credsFromEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var opts []Option
	if os.Getenv("HETZNER_HEADLESS") == "0" {
		opts = append(opts, WithHeadless(false))
	}
	if os.Getenv("HETZNER_DEBUG") == "1" {
		opts = append(opts, WithDebugWriter(os.Stderr))
	}

	token, expires, err := Login(ctx, creds, opts...)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if len(token) != 64 {
		t.Errorf("token length = %d, want 64", len(token))
	}
	if expires.IsZero() {
		t.Error("expires is zero; expected a positive TTL from the cookie")
	}
	if time.Until(expires) < 5*time.Minute {
		t.Errorf("expires is only %s away, want at least 5m", time.Until(expires))
	}
	// Deliberately do not log token.
	t.Logf("login ok; token has %d chars, expires in %s", len(token), time.Until(expires).Round(time.Second))
}

func TestIT_TokenSourceCachesAcrossCalls(t *testing.T) {
	creds := credsFromEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ts := NewTokenSource(creds)
	first, exp1, err := ts.Token(ctx)
	if err != nil {
		t.Fatalf("first Token: %v", err)
	}
	second, exp2, err := ts.Token(ctx)
	if err != nil {
		t.Fatalf("second Token: %v", err)
	}
	if first != second {
		t.Error("TokenSource re-ran Login between calls; expected cache hit")
	}
	if !exp1.Equal(exp2) {
		t.Errorf("expiry changed between cache hits: %v vs %v", exp1, exp2)
	}
}
