// Package authbrowser drives the Hetzner console OAuth implicit flow in a
// headless Chromium (via go-rod) to obtain a user token from a robot-account
// username + password + TOTP.
//
// Hetzner's OAuth login is gated by HeRay, a browser-side proof-of-work +
// WebAssembly fingerprint challenge, so pure HTTP login is not possible. A
// real browser environment must solve HeRay; we use go-rod to automate one.
//
// Only TOTP 2FA is supported. See docs/2fa.md in the repository for the
// rationale and for guidance on supported configurations (do not use this
// package against a Yubikey-OTP account — it will time out).
//
// Typical use:
//
//	ts := authbrowser.NewTokenSource(authbrowser.Credentials{
//	    Username: os.Getenv("HETZNER_USERNAME"),
//	    Password: os.Getenv("HETZNER_PASSWORD"),
//	    TOTP: func(ctx context.Context) (string, error) {
//	        out, err := exec.CommandContext(ctx, "op", "read",
//	            "op://vault/accounts.hetzner.com/one-time password?attribute=totp").Output()
//	        return strings.TrimSpace(string(out)), err
//	    },
//	})
//	client := hcloudplus.NewClient(hcloudplus.WithTokenSource(ts))
//
// The package exposes both a stateless Login function and a stateful
// TokenSource wrapper that caches the token and re-logs in before expiry.
package authbrowser
