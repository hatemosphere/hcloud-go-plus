package authbrowser

import (
	"context"
	"net/url"
	"testing"
	"time"
)

func TestParseTokensCookieUser(t *testing.T) {
	// Simulates what console.hetzner.com sets: URL-encoded JSON map keyed by
	// token id, with user and project_user entries.
	raw := `{
		"170015745": {"id":170015745,"type":"user","token":"user-tok","expires":"2026-04-12T05:14:05Z"},
		"170017180": {"id":170017180,"type":"project_user","token":"pu-tok","expires":"2026-04-12T05:16:24Z"}
	}`
	encoded := url.QueryEscape(raw)
	tok, exp, err := parseTokensCookie(encoded)
	if err != nil {
		t.Fatalf("parseTokensCookie: %v", err)
	}
	if tok != "user-tok" {
		t.Errorf("tok = %q, want user-tok", tok)
	}
	want, _ := time.Parse(time.RFC3339, "2026-04-12T05:14:05Z")
	if !exp.Equal(want) {
		t.Errorf("exp = %v, want %v", exp, want)
	}
}

func TestParseTokensCookieNoUser(t *testing.T) {
	raw := `{"1":{"id":1,"type":"project_user","token":"pu","expires":"2026-01-01T00:00:00Z"}}`
	tok, _, err := parseTokensCookie(url.QueryEscape(raw))
	if err != nil {
		t.Fatalf("parseTokensCookie: %v", err)
	}
	if tok != "" {
		t.Errorf("expected empty token, got %q", tok)
	}
}

func TestParseTokensCookieMalformed(t *testing.T) {
	_, _, err := parseTokensCookie("not json")
	if err == nil {
		t.Error("expected error on malformed cookie")
	}
}

func TestCredentialsValidate(t *testing.T) {
	cases := []struct {
		name    string
		creds   Credentials
		wantErr bool
	}{
		{"empty", Credentials{}, true},
		{"no-password", Credentials{Username: "u"}, true},
		{"no-totp", Credentials{Username: "u", Password: "p"}, true},
		{"ok", Credentials{Username: "u", Password: "p", TOTP: func(context.Context) (string, error) { return "1", nil }}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.creds.validate()
			if (err != nil) != c.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, c.wantErr)
			}
		})
	}
}

func TestTokenSourceCaching(t *testing.T) {
	ts := &TokenSource{
		token:           "cached",
		expires:         time.Now().Add(10 * time.Hour),
		refreshFraction: 0.8,
	}
	if ts.needsRefresh(time.Now()) {
		t.Error("should not need refresh at 10h remaining")
	}
	ts.expires = time.Now().Add(1 * time.Hour)
	if !ts.needsRefresh(time.Now()) {
		t.Error("should need refresh at 1h remaining")
	}
	ts.expires = time.Now().Add(-1 * time.Minute)
	if !ts.needsRefresh(time.Now()) {
		t.Error("should need refresh when already expired")
	}
}

func TestTokenSourceInvalidate(t *testing.T) {
	ts := &TokenSource{token: "x", expires: time.Now().Add(1 * time.Hour), refreshFraction: 0.8}
	ts.Invalidate()
	if ts.token != "" {
		t.Error("Invalidate did not clear token")
	}
}
