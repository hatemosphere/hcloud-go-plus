package authbrowser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// OAuth parameters used by the Hetzner Cloud Console SPA. Mirrors the
// `angular-oauth2-oidc` configuration observable in the live console — do
// not change these without verifying against a fresh browser capture.
const (
	oauthAuthorizeURL = "https://accounts.hetzner.com/oauth/authorize"
	oauthClientID     = "cloud_421"
	oauthRedirectURI  = "https://console.hetzner.com/"
	oauthScope        = "openid"
	consoleDomain     = "console.hetzner.com"
)

// Credentials carries everything Login needs to drive the browser flow. All
// three fields are required.
type Credentials struct {
	// Username is the robot login (client number, e.g. K0247406420) or the
	// email bound to the account.
	Username string

	// Password is the plaintext account password.
	Password string

	// TOTP is invoked just before the TOTP form is submitted. Callers are
	// expected to generate a fresh code (from their secret manager, a local
	// HMAC computation, or an external tool) every time it fires. Stale
	// codes will fail login.
	TOTP func(ctx context.Context) (string, error)
}

func (c Credentials) validate() error {
	if c.Username == "" {
		return errors.New("authbrowser: Credentials.Username is required")
	}
	if c.Password == "" {
		return errors.New("authbrowser: Credentials.Password is required")
	}
	if c.TOTP == nil {
		return errors.New("authbrowser: Credentials.TOTP callback is required")
	}
	return nil
}

// Options tunes Login behaviour. Construct via functional options.
type Options struct {
	headless    bool
	browserPath string
	timeout     time.Duration
	debug       io.Writer
}

// Option configures Options.
type Option func(*Options)

// WithHeadless toggles whether Chromium runs without a visible window.
// Default is true. Pass false to watch the flow while debugging.
func WithHeadless(v bool) Option { return func(o *Options) { o.headless = v } }

// WithBrowserPath sets an explicit path to a Chrome/Chromium binary. If
// unset, chromedp looks for an installed Chrome/Chromium in the usual
// locations. Nothing is downloaded: containers must ship a browser.
func WithBrowserPath(path string) Option { return func(o *Options) { o.browserPath = path } }

// WithTimeout bounds the total time for the full login flow. Default 90s.
func WithTimeout(d time.Duration) Option { return func(o *Options) { o.timeout = d } }

// WithDebugWriter enables verbose tracing of browser actions to the writer.
func WithDebugWriter(w io.Writer) Option { return func(o *Options) { o.debug = w } }

func resolveOptions(opts []Option) Options {
	o := Options{
		headless: true,
		timeout:  90 * time.Second,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// Login drives the full Hetzner OAuth flow and returns a user token (64 char
// bearer) and its absolute expiry as reported by the console's `tokens`
// cookie. The returned token is suitable for
// hcloudplus.WithUserToken / WithTokenSource(StaticToken).
//
// Login is stateless: it launches a fresh Chromium, completes the flow,
// closes the browser, and returns. Callers that want caching + refresh
// should use NewTokenSource instead.
func Login(ctx context.Context, creds Credentials, opts ...Option) (token string, expires time.Time, err error) {
	if err := creds.validate(); err != nil {
		return "", time.Time{}, err
	}
	o := resolveOptions(opts)

	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	// The browser lives as long as ctx: the deadline above kills it too.
	allocOpts := []chromedp.ExecAllocatorOption{
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
	}
	if o.browserPath != "" {
		allocOpts = append(allocOpts, chromedp.ExecPath(o.browserPath))
	}
	if inContainer() {
		// Containers usually run as root, where Chrome refuses to start
		// with the sandbox enabled.
		allocOpts = append(allocOpts, chromedp.NoSandbox)
	}
	ctxOpts := []chromedp.ContextOption{chromedp.WithAllocatorOptions(allocOpts...)}
	if !o.headless {
		ctxOpts = append(ctxOpts, chromedp.WithVisibleWindow())
	}
	ctx, cancelBrowser := chromedp.NewContext(ctx, ctxOpts...)
	defer cancelBrowser()

	if o.debug != nil {
		fmt.Fprintln(o.debug, "[authbrowser] navigating to authorize URL")
	}
	if err := chromedp.Do(ctx, chromedp.Navigate(buildAuthorizeURL())); err != nil {
		return "", time.Time{}, fmt.Errorf("authbrowser: open authorize page: %w", err)
	}

	// Fill username + password. Hetzner's login form uses name="_username"
	// and name="_password" with a single submit button.
	if err := chromedp.Do(ctx, chromedp.SendKeys(chromedp.CSS(`input[name="_username"]`), creds.Username)); err != nil {
		return "", time.Time{}, fmt.Errorf("authbrowser: username: %w", err)
	}
	if err := chromedp.Do(ctx, chromedp.SendKeys(chromedp.CSS(`input[name="_password"]`), creds.Password)); err != nil {
		return "", time.Time{}, fmt.Errorf("authbrowser: password: %w", err)
	}
	if err := clickSubmit(ctx); err != nil {
		return "", time.Time{}, fmt.Errorf("authbrowser: submit credentials: %w", err)
	}
	if o.debug != nil {
		fmt.Fprintln(o.debug, "[authbrowser] submitted credentials")
	}

	// Wait for the TOTP input. If the account uses Yubikey OTP instead of
	// TOTP, the `_auth_code` field won't appear and we'll hit the outer
	// timeout with a clear error.
	if err := chromedp.Do(ctx, chromedp.WaitVisible(totpField)); err != nil {
		return "", time.Time{}, fmt.Errorf("authbrowser: TOTP field not found (is the account using Yubikey OTP instead of TOTP?): %w", err)
	}

	// Retry TOTP up to maxTOTPAttempts times. There are two failure modes
	// we want to survive:
	//
	//  1. The code we generated lands on the wrong side of the 30-second
	//     TOTP window boundary by the time Hetzner processes it. Retrying
	//     with a fresh code fixes it — but only if the callback returns a
	//     *new* code. Most secret managers (1Password, pass-otp, ykman)
	//     generate deterministically from the seed + current time, so
	//     repeated calls inside the same 30s window return the same code.
	//     To avoid pounding the same rejected code three times in a row,
	//     we compare the newly-fetched code against the one we last
	//     submitted; if they match, we wait in small ticks (re-checking
	//     up to ~35s) until the generator starts returning a different
	//     code, signalling a new window.
	//
	//  2. Transient form state: after a rejected submit, Hetzner may
	//     briefly disable the submit button (pointer-events: none) while
	//     it re-renders. We catch this with a bounded wait on the
	//     submit button's clickability before each click.
	const (
		maxTOTPAttempts      = 3
		waitNewCodeTimeout   = 35 * time.Second
		waitNewCodePoll      = 2 * time.Second
		submitButtonReadyTmt = 5 * time.Second
	)
	totpAccepted := false
	var lastCode string
	for attempt := 1; attempt <= maxTOTPAttempts; attempt++ {
		code, err := creds.TOTP(ctx)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("authbrowser: TOTP callback: %w", err)
		}
		code = strings.TrimSpace(code)
		if code == "" {
			return "", time.Time{}, errors.New("authbrowser: TOTP callback returned empty code")
		}

		// On retry, if the callback returned the same code we just
		// submitted, wait for the next 30s window before trying again.
		// Otherwise we'd burn attempts on an already-rejected code.
		if attempt > 1 && code == lastCode {
			if o.debug != nil {
				fmt.Fprintln(o.debug, "[authbrowser] TOTP callback returned same code as previous attempt; waiting for next window")
			}
			waitDeadline := time.Now().Add(waitNewCodeTimeout)
			for time.Now().Before(waitDeadline) {
				select {
				case <-ctx.Done():
					return "", time.Time{}, ctx.Err()
				case <-time.After(waitNewCodePoll):
				}
				next, err := creds.TOTP(ctx)
				if err != nil {
					return "", time.Time{}, fmt.Errorf("authbrowser: TOTP callback: %w", err)
				}
				next = strings.TrimSpace(next)
				if next != "" && next != lastCode {
					code = next
					break
				}
			}
			if code == lastCode {
				return "", time.Time{}, fmt.Errorf("authbrowser: TOTP callback kept returning the same code %q for %s — check that the backing secret manager is actually rolling windows", lastCode, waitNewCodeTimeout)
			}
		}

		// Select any leftover value from a previous rejected attempt so the
		// typed code replaces it. Setting .value directly is refused by the
		// field. chromedp re-resolves the selector on every action, so a
		// re-rendered form after a rejection is fine.
		if _, err := chromedp.Run(ctx, chromedp.Evaluate[bool](
			`(() => { document.querySelector('input[name="_auth_code"]').select(); return true; })()`)); err != nil {
			return "", time.Time{}, fmt.Errorf("authbrowser: select TOTP field: %w", err)
		}
		if err := chromedp.Do(ctx, chromedp.SendKeys(totpField, code)); err != nil {
			return "", time.Time{}, fmt.Errorf("authbrowser: input TOTP: %w", err)
		}
		// Wait for the submit button to be clickable — after a rejected
		// submission Hetzner temporarily disables it (pointer-events: none)
		// while re-rendering the form.
		if err := waitForClickableSubmit(ctx, submitButtonReadyTmt); err != nil {
			return "", time.Time{}, fmt.Errorf("authbrowser: submit button never became clickable: %w", err)
		}
		if err := clickSubmit(ctx); err != nil {
			return "", time.Time{}, fmt.Errorf("authbrowser: submit TOTP: %w", err)
		}
		lastCode = code
		if o.debug != nil {
			fmt.Fprintf(o.debug, "[authbrowser] submitted TOTP (attempt %d/%d)\n", attempt, maxTOTPAttempts)
		}

		// Success = we leave accounts.hetzner.com. Give it a short window.
		if err := waitForHostChange(ctx, "accounts.hetzner.com", 8*time.Second); err == nil {
			totpAccepted = true
			break
		}

		if o.debug != nil {
			fmt.Fprintf(o.debug, "[authbrowser] TOTP attempt %d rejected (still on accounts.hetzner.com)\n", attempt)
		}
		if err := chromedp.Do(ctx, chromedp.WaitVisible(totpField)); err != nil {
			return "", time.Time{}, fmt.Errorf("authbrowser: after TOTP submit, neither redirected nor TOTP form present: %w", err)
		}
	}
	if !totpAccepted {
		return "", time.Time{}, fmt.Errorf("authbrowser: TOTP rejected after %d attempts — verify the TOTP callback produces a current valid code", maxTOTPAttempts)
	}

	// After TOTP, the browser redirects to console.hetzner.com/ with the
	// OAuth fragment. The SPA parses the fragment and stores the token in
	// the `tokens` cookie. Poll until the cookie appears or the context
	// deadline fires.
	token, expires, err = pollForTokenCookie(ctx, o.debug)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

func buildAuthorizeURL() string {
	v := url.Values{}
	v.Set("client_id", oauthClientID)
	v.Set("redirect_uri", oauthRedirectURI)
	v.Set("scope", oauthScope)
	v.Set("response_type", "token")
	return oauthAuthorizeURL + "?" + v.Encode()
}

const (
	totpField    = chromedp.CSS(`input[name="_auth_code"]`)
	submitButton = chromedp.CSS(`button[type="submit"]`)
)

func clickSubmit(ctx context.Context) error {
	return chromedp.Do(ctx, chromedp.Click(submitButton))
}

// inContainer mirrors go-rod's detection, which used to add --no-sandbox
// for us.
func inContainer() bool {
	for _, f := range []string{"/.dockerenv", "/.containerenv"} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

// runWithin runs a with its own timeout so that a poll iteration can't hang
// on a page that is mid-navigation.
func runWithin[T any](ctx context.Context, d time.Duration, a chromedp.Action[T]) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	return chromedp.Run(ctx, a)
}

// waitForClickableSubmit blocks until `button[type="submit"]` has
// `pointer-events: auto` (i.e. is actually clickable) or the timeout
// elapses. Hetzner briefly sets pointer-events: none on the submit
// button after a rejected TOTP while it re-renders the form, and
// clicking during that window is silently swallowed — hence this
// pre-flight check on retries.
func waitForClickableSubmit(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("authbrowser: submit button still disabled after %s", timeout)
		}
		ok, err := runWithin(ctx, time.Second, chromedp.Evaluate[bool](
			`(() => { const b = document.querySelector('button[type="submit"]'); return !!b && getComputedStyle(b).pointerEvents !== 'none'; })()`))
		if err == nil && ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// waitForHostChange polls the page location until its host no longer
// contains `fromHost` (i.e. the page has navigated away), or returns an
// error on timeout. Used to detect "did the form submission succeed"
// without relying on content selectors that vary between error states.
func waitForHostChange(ctx context.Context, fromHost string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("authbrowser: did not leave %s within %s", fromHost, timeout)
		}
		loc, err := runWithin(ctx, time.Second, chromedp.Location())
		if err != nil {
			continue
		}
		u, perr := url.Parse(loc)
		if perr != nil {
			continue
		}
		if !strings.Contains(u.Host, fromHost) {
			return nil
		}
	}
}

// pollForTokenCookie repeatedly reads the browser's cookies for the console
// domain and returns the first entry of type "user" found in the `tokens`
// cookie. It gives up when ctx expires.
func pollForTokenCookie(ctx context.Context, debug io.Writer) (string, time.Time, error) {
	getCookies := chromedp.Action[network.GetCookiesResult](func(ctx context.Context, t *chromedp.Target) (network.GetCookiesResult, error) {
		return cdp.Call(ctx, t, network.GetCookies, network.GetCookiesParams{URLs: []string{"https://" + consoleDomain + "/"}})
	})
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", time.Time{}, fmt.Errorf("authbrowser: timed out waiting for tokens cookie: %w", ctx.Err())
		case <-tick.C:
		}

		res, err := runWithin(ctx, 2*time.Second, getCookies)
		if err != nil {
			if debug != nil {
				fmt.Fprintf(debug, "[authbrowser] cookie read error: %v\n", err)
			}
			continue
		}
		for _, c := range res.Cookies {
			if c.Name != "tokens" || c.Value == "" {
				continue
			}
			tok, exp, err := parseTokensCookie(c.Value)
			if err != nil {
				if debug != nil {
					fmt.Fprintf(debug, "[authbrowser] parse tokens cookie: %v\n", err)
				}
				continue
			}
			if tok != "" {
				return tok, exp, nil
			}
		}
	}
}

// parseTokensCookie extracts the type:"user" entry from a URL-encoded JSON
// `tokens` cookie. Returns empty string if no user token is present yet.
func parseTokensCookie(raw string) (string, time.Time, error) {
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("unescape: %w", err)
	}
	var obj map[string]struct {
		Type    string    `json:"type"`
		Token   string    `json:"token"`
		Expires time.Time `json:"expires"`
	}
	if err := json.Unmarshal([]byte(decoded), &obj); err != nil {
		return "", time.Time{}, fmt.Errorf("unmarshal: %w", err)
	}
	for _, t := range obj {
		if t.Type == "user" && t.Token != "" {
			return t.Token, t.Expires, nil
		}
	}
	return "", time.Time{}, nil
}
