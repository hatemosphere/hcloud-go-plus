# hcloud-go-plus

[`hcloud-go`](https://github.com/hetznercloud/hcloud-go) wraps the **public**
Hetzner Cloud API. `hcloud-go-plus` wraps everything the public API **refuses
to expose** — the `_`-prefixed console endpoints that actually let you
manage the account itself.

That's the "plus".

## What you can do here that upstream can't

- Create, rename and delete **projects**
- Create and delete **project API tokens**
- Invite, resend, revoke **project members**
- Read **account-wide limits** (for your Prometheus exporter)
- Read **cross-project audit activities** with user attribution, source IP
  and the API-token prefix that fired each action
- Read **current user** / **current token**

All with the same options pattern, resource-client layout, `XxxClient.List /
All / Create / Update / Delete` method shapes and `hcloud.Error`-compatible
error type as upstream `hcloud-go`. If you know `hcloud-go`, you already know
how to use this.

## Why undocumented endpoints

Hetzner's official API only speaks project-scoped tokens. A project-scoped
token cannot list projects, cannot create projects, cannot mint tokens,
cannot see who did what across the account. The console frontend talks to a
set of account-level endpoints that do all of these things. We
reverse-engineered the ones we care about from a logged-in browser session
and built a tiny, faithful Go client on top. Schemas and wire-level details
live in [`docs/private-api.md`](docs/private-api.md).

Hetzner does not document these endpoints and does not promise stability.
If they change, this library breaks. We'll fix it.

## Install

```
go get github.com/hatemosphere/hcloud-go-plus/hcloudplus
```

The `hcloudplus` package is dependency-free — zero transitive packages, just
the Go standard library.

## Quick start — bring your own token

```go
import "github.com/hatemosphere/hcloud-go-plus/hcloudplus"

client := hcloudplus.NewClient(hcloudplus.WithUserToken(os.Getenv("HCGP_USER_TOKEN")))

p, _ := client.Project.Create(ctx, hcloudplus.ProjectCreateOpts{Name: "infra"})
tok, _ := client.ProjectToken.Create(ctx, p.ID, hcloudplus.ProjectTokenCreateOpts{
    Description: "pulumi",
    Readonly:    false,
})
fmt.Println("store this secret NOW, it's only shown once:", tok.Secret)
```

See [`docs/private-api.md`](docs/private-api.md) for the full list of
endpoints, schemas and wire-level caveats.

## Auth that doesn't suck

The account-level token has to come from somewhere. Options:

1. **Paste it from your browser** (one-shot use, human in the loop) — easy,
   useful during development. See the user token extraction steps in
   [`docs/private-api.md`](docs/private-api.md).
2. **Use the `authbrowser` submodule** — drives a headless Chromium (via
   [chromedp](https://github.com/chromedp/chromedp)) through the real
   OAuth + MFA flow so your daemon / CLI / Pulumi provider / Terraform
   provider can mint tokens unattended from robot credentials. Opt-in,
   isolated `go.mod`, so consumers of the main package don't pay for
   Chromium transitively.

   Needs an installed Chrome/Chromium (or `WithBrowserPath`); nothing is
   downloaded at runtime. In containers, bake it into the image
   (`apt-get install chromium` or the `chromedp/headless-shell` base);
   `--no-sandbox` is added automatically when a container is detected.

   ```go
   import "github.com/hatemosphere/hcloud-go-plus/authbrowser"

   ts := authbrowser.NewTokenSource(authbrowser.Credentials{
       Username: os.Getenv("HETZNER_USERNAME"),
       Password: os.Getenv("HETZNER_PASSWORD"),
       TOTP: func(ctx context.Context) (string, error) {
           out, err := exec.CommandContext(ctx, "op", "read",
               "op://vault/accounts.hetzner.com/one-time password?attribute=totp").Output()
           return strings.TrimSpace(string(out)), err
       },
   })
   client := hcloudplus.NewClient(hcloudplus.WithTokenSource(ts))
   ```

   Only TOTP-backed 2FA is supported — see [`docs/2fa.md`](docs/2fa.md) for
   why Yubikey/FIDO is a dead end for unattended use.

3. **`cmd/hcgp-login`** — a 60-line CLI under the `authbrowser` submodule that
   reads `HETZNER_USERNAME` / `HETZNER_PASSWORD` / `HETZNER_TOTP` (or
   `HETZNER_TOTP_CMD`) and prints a fresh user token to stdout. Drop-in for
   shell pipelines:

   ```sh
   export HCGP_USER_TOKEN=$(go run ./authbrowser/cmd/hcgp-login)
   ```

## Testing

```sh
# Unit tests (fast, zero network)
go test ./hcloudplus/... ./authbrowser/...

# Integration tests against real Hetzner (creates + deletes throwaway projects)
HCGP_USER_TOKEN=… go test -tags=integration -race ./hcloudplus/
```

Integration tests only operate on projects whose name starts with `hcgp-it-`
and refuse to delete anything else. Paranoid by design.

## Downstream

- [**terraform-provider-hcloudplus**](https://github.com/hatemosphere/terraform-provider-hcloudplus)
  — Terraform provider built on this library. Drop-in companion to the
  official `hetznercloud/terraform-provider-hcloud`.
- [**pulumi-hcloudplus**](https://github.com/hatemosphere/pulumi-hcloudplus)
  — Pulumi provider bridged from the TF provider via
  `pulumi-terraform-bridge`.

## Status

v0.1. Works. See `docs/private-api.md` for the TODO list of
endpoints we haven't captured yet (most notably the accepted-member
remove/role-change flow).
