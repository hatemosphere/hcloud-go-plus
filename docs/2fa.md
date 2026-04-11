# Two-factor authentication

`authbrowser` automates the Hetzner console login flow (username + password +
2FA) to produce a user token. 2FA is not optional on any real Hetzner account,
so supporting it is a hard requirement.

## Supported: TOTP (Hetzner's "Mobile device" option)

TOTP is the only 2FA method `hcloud-go-plus` supports for programmatic use.
The seed is a shared secret stored by both Hetzner and your authenticator app;
codes are derived from the seed plus the current 30-second UNIX epoch window
(RFC 6238).

Because TOTP is a pure software computation over a known seed, anything
holding the seed can produce a fresh code on demand — 1Password, pass,
hand-rolled HMAC, whatever. `authbrowser.Credentials.TOTP` is a
`func(ctx) (string, error)` callback the caller supplies; we never store,
parse, or import 2FA secrets ourselves. The library stays one hop away from
your secret manager.

Example callback wired into 1Password:

```go
TOTP: func(ctx context.Context) (string, error) {
    out, err := exec.CommandContext(ctx, "op", "read",
        "op://vault/accounts.hetzner.com/one-time password?attribute=totp").Output()
    return strings.TrimSpace(string(out)), err
},
```

If you store the raw seed somewhere other than a secret manager that can
compute codes for you, your callback is responsible for computing the HOTP
value — RFC 6238 is ~30 lines of stdlib code. The library deliberately does
not ship a helper for this, so the seed never lives inside `hcloud-go-plus`.

## Not supported: Yubikey (Hetzner's "Yubikey" option)

Hetzner's Yubikey option is **Yubico OTP** — the Yubikey acts as a USB-HID
keyboard and types a 44-character one-time password when you tap the gold
disc. Each tap increments a monotonic counter; Hetzner validates the OTP
against Yubico's YubiCloud servers.

This does not work for unattended automation:

1. Generating a valid Yubico OTP in software requires the Yubikey's AES
   secret, which factory-shipped keys do not expose — that is literally the
   security property you bought the key for.
2. Self-programming a Yubikey with your own AES key sidesteps YubiCloud, so
   Hetzner's validator rejects the OTPs you generate. Dead end.
3. The only way to produce a valid OTP is a physical tap on the key. A
   daemon / Pulumi provider / Terraform provider / CI job cannot do that.

An attended interactive CLI *could* drive the flow with `WithHeadless(false)`
and a human in the loop tapping the key on every cold login (~every 9.6 h
given the 12 h token lifetime), but this is explicitly not what we optimise
for and will not be documented as a supported path.

## Recommendation

Use a **dedicated Hetzner account** for automation, secure it with a strong
password (stored in your secret manager) and **TOTP-only 2FA**. Keep your
personal Hetzner account on whatever second factor you prefer, including
Yubikey — but do not point your automation at it.

If you try to run `authbrowser.Login` against an account that requires a
Yubikey OTP, the TOTP-code input selector won't be found, the login will
time out, and the function will return a clear error. No silent fallback —
fail fast, surface the reason.
