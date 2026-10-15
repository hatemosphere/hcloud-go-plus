// hcgp-login drives an interactive browser login against Hetzner Cloud's
// console and prints the resulting user token to stdout.
//
// Intended to be composed into shell pipelines and test harnesses:
//
//	export HCGP_USER_TOKEN=$(hcgp-login)
//	go test -tags=integration ./hcloudplus/
//
// Credentials come from environment variables. The TOTP code is provided
// either directly as HETZNER_TOTP (a literal 6-digit string — useful for
// one-shot runs where you're reading it off your phone) or as a shell
// command whose stdout is the code (HETZNER_TOTP_CMD — useful for automation
// where a secret manager computes the code on demand). Exactly one of the
// two must be set.
//
//	HETZNER_TOTP="123456"
//	HETZNER_TOTP_CMD="op read 'op://vault/accounts.hetzner.com/one-time password?attribute=totp'"
//
// Required:
//
//	HETZNER_USERNAME        robot login (client number) or account email
//	HETZNER_PASSWORD        account password
//	HETZNER_TOTP or HETZNER_TOTP_CMD   (exactly one)
//
// Optional:
//
//	HETZNER_TIMEOUT         go Duration, default "90s"
//	HETZNER_HEADLESS        "0" for visible browser, default headless
//	HETZNER_BROWSER_PATH    explicit path to Chromium binary
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hatemosphere/hcloud-go-plus/authbrowser"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hcgp-login:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	creds, err := credsFromEnv()
	if err != nil {
		return err
	}

	var opts []authbrowser.Option
	if v := os.Getenv("HETZNER_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("HETZNER_TIMEOUT: %w", err)
		}
		opts = append(opts, authbrowser.WithTimeout(d))
	}
	if os.Getenv("HETZNER_HEADLESS") == "0" {
		opts = append(opts, authbrowser.WithHeadless(false))
	}
	if v := os.Getenv("HETZNER_BROWSER_PATH"); v != "" {
		opts = append(opts, authbrowser.WithBrowserPath(v))
	}
	if os.Getenv("HETZNER_DEBUG") == "1" {
		opts = append(opts, authbrowser.WithDebugWriter(os.Stderr))
	}

	token, _, err := authbrowser.Login(ctx, creds, opts...)
	if err != nil {
		return err
	}

	// Token to stdout, nothing else — so `$(hcgp-login)` is usable.
	fmt.Println(token)
	return nil
}

func credsFromEnv() (authbrowser.Credentials, error) {
	user := os.Getenv("HETZNER_USERNAME")
	pass := os.Getenv("HETZNER_PASSWORD")
	if user == "" || pass == "" {
		return authbrowser.Credentials{}, errors.New("HETZNER_USERNAME and HETZNER_PASSWORD are required")
	}

	literal := os.Getenv("HETZNER_TOTP")
	cmd := os.Getenv("HETZNER_TOTP_CMD")
	switch {
	case literal != "" && cmd != "":
		return authbrowser.Credentials{}, errors.New("set exactly one of HETZNER_TOTP or HETZNER_TOTP_CMD, not both")
	case literal != "":
		return authbrowser.Credentials{
			Username: user,
			Password: pass,
			TOTP: func(context.Context) (string, error) {
				return strings.TrimSpace(literal), nil
			},
		}, nil
	case cmd != "":
		return authbrowser.Credentials{
			Username: user,
			Password: pass,
			TOTP: func(ctx context.Context) (string, error) {
				out, err := exec.CommandContext(ctx, "sh", "-c", cmd).Output() //nolint:gosec // running the user-supplied HETZNER_TOTP_CMD is the point
				if err != nil {
					return "", fmt.Errorf("HETZNER_TOTP_CMD: %w", err)
				}
				return strings.TrimSpace(string(out)), nil
			},
		}, nil
	default:
		return authbrowser.Credentials{}, errors.New("set HETZNER_TOTP or HETZNER_TOTP_CMD")
	}
}
