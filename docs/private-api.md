# Hetzner Cloud Console — Private API (reverse-engineered)

All endpoints under `https://api.hetzner.cloud/v1/` with `_`-prefixed paths.
Not part of the public Hetzner Cloud API. No stability guarantees.

Two token types:

- **`user` token** — account-scoped, obtained from OAuth implicit flow at
  `https://accounts.hetzner.com/oauth/authorize?client_id=cloud_421`.
  The SPA stores both types in a JSON `tokens` cookie.
- **`project_user` token** — project-scoped session token, minted by
  `POST /v1/_tokens {type:"project_user", project:<id>}` with a user token.

Error envelope (same as public API): `{"error":{"code":<int>,"message":"<str>"}}`.

## Projects

### `POST /v1/_projects` — create
Auth: **user**
Request: `{"name":"<str>"}`
Response 200:
```json
{"project":{
  "id":14138093,"name":"hcgp-capture","role":"owner",
  "owner":{"id":305994,"robot_cn":"K024...","email":"...", "first_name":"...","last_name":"...","company_name":"...","features":[...],"blocked_ports":[],"locale":"en_GB","currency":"EUR","vat_rate":"0.00","restriction":"unrestricted","has_billing_details":true,"light_user":false},
  "features":["use-keystone-projects"],"blocked_ports":[],
  "usage_alert_threshold":null,
  "created":"2026-04-11T17:02:59Z",
  "backup_count":0,"firewall_count":0,"floating_ip_count":0,"image_count":0,"load_balancer_count":0,"network_count":0,"primary_ipv4_count":0,"primary_ipv6_count":0,"server_count":0,"user_count":1,"volume_count":0,"bucket_count":0,"storage_box_count":0,"zone_count":0,"kubernetes_clusters_count":0
}}
```

### `GET /v1/_projects` — list
Auth: user
Query: `page`, `per_page` (default 25)
Response: `{"projects":[<Project>…], "meta":{"pagination":{…}}}` (see audit-logs-fetcher doc for full example)

### `GET /v1/_projects/:id` — read
Auth: user
Response: `{"project":<Project>}`

### `PUT /v1/_projects/:id` — update
Auth: user
Request: `{"name":"<str>"}` (only field verified so far; `usage_alert_threshold` may also be writable — not captured via UI)
Response: `{"project":<Project>}`

### `DELETE /v1/_projects/:id` — delete
Auth: user
Response: 204 no body

## Project members

### `GET /v1/_projects/:id/users` — list accepted members
Auth: user
Response:
```json
{"users":[
  {"user":{"id":305994,"robot_cn":"K024...","email":"..."}, "role":"owner"},
  {"user":{"id":953564025,"robot_cn":"K027...","email":"..."}, "role":"admin"}
], "meta":{"pagination":{"page":1,"per_page":50,"total_entries":2,…}}}
```

Roles observed: `owner`, `admin`, `member`, `restricted`.

### TODO — remove accepted member / change role
Not yet captured (requires a second account to accept an invitation).
Likely shape based on REST conventions:
- `DELETE /v1/_projects/:id/users/:user_id`
- `PUT /v1/_projects/:id/users/:user_id  {"role":"<str>"}`
Verify by capture before shipping.

## Project invitations

### `GET /v1/_projects/:id/invitations` — list pending invitations
Auth: user
Response:
```json
{"project_invitations":[
  {"id":1111279,"email":"…","role":"member","created":"2026-04-11T17:21:40Z","accepted":null,"expired":null}
], "meta":{"pagination":{"page":1,"per_page":25,"total_entries":1,…}}}
```

### `POST /v1/_projects/:id/invitations` — invite
Auth: user
Request: `{"email":"<str>","role":"<str>"}`
Response 201: `{"project_invitation":{"id":…,"email":…,"role":…,"created":…,"accepted":null,"expired":null}}`

### `PUT /v1/_projects/:id/invitations/:id/resend` — resend
Auth: user
Request: none
Response 204 no body
Note: the method is **PUT**, not POST.

### `DELETE /v1/_projects/:id/invitations/:id` — revoke pending invite
Auth: user
Response 204 no body

### Not supported by the API (verified)
Changing the role of a pending invitation. The Hetzner UI only offers "Send invitation again" and "Remove" on pending rows.

## API tokens (per project)

### `GET /v1/_tokens` — list
Auth: **project_user** (403 with plain user token)
Query: `page`, `per_page` (default 25, max 50)
Response:
```json
{"tokens":[
  {"id":123,"type":"project","prefix":"fknQ9Ra7…","description":"Pulumi","disabled":false,"readonly":false,"expires":null,
   "project":{"id":…,"name":…,"created":…,"usage_alert_threshold":null}}
], "meta":{"pagination":{…}}}
```

### `POST /v1/_tokens` — create API token
Auth: **project_user** (the project context comes entirely from the token; no project ID in body)
Request: `{"type":"project","description":"<str>","readonly":<bool>}`
Response 201:
```json
{"role":null,
 "secret_token":"<64-char secret — only returned once>",
 "token":{"id":177763691,"type":"project","prefix":"3dHgwphod1A4wqLr00yGoxKEGY7CrtpQ","description":"hcgp-capture-token-r","disabled":false,"expires":null,"project":{"id":14138093,"name":"hcgp-capture2","created":"2026-04-11T17:02:59Z","usage_alert_threshold":null},"user":{…},"readonly":true}}
```
The `secret_token` is the actual bearer token the caller will use against the public API. Store it — there is no way to retrieve it again.

### `DELETE /v1/_tokens/:id` — delete token
Auth: project_user
Response 200 no body

### `GET /v1/_tokens/current` — who am I (token-wise)
Auth: any valid token
Response: `{"token":{…same shape as list item…, "user":{…}}}`

## Session / internal

### `POST /v1/_tokens` with `{type:"project_user", project:<id>}` — mint project_user session
Auth: user
Response 201:
```json
{"role":"owner",
 "secret_token":"<64-char bearer>",
 "token":{"id":…,"type":"project_user","prefix":"…","description":null,"disabled":false,"expires":"…+~12h","project":{"id":…,"name":…,"created":…,"usage_alert_threshold":null},"user":{…},"readonly":false}}
```
This is what `hcloud-go-plus` calls internally when the user invokes a
project-scoped operation (list/create/delete tokens) with only a user token.
Cached per project, refreshed on 401.

## Account-level reads

### `GET /v1/_user`
Auth: user
Response: `{"user":{id, robot_cn, restriction, vat_rate, locale, first_name, last_name, company_name, features[], blocked_ports[], email, has_billing_details, light_user, currency}}`

### `GET /v1/_user/limits`
Auth: user
Response:
```json
{"limits":{
  "server":{"limit":400,"usage":199},
  "snapshot":{"limit":30,"usage":2},
  "project":{"limit":200,"usage":17},
  "primary_ip":{"limit":800,"usage":175},
  "floating_ip":{"limit":10,"usage":2},
  "dedicated_core":{"limit":128,"usage":16},
  "volume_size":{"limit":10000,"usage":6960},
  "network":{"limit":30,"usage":14},
  "servers_per_network":{"limit":100},
  "subnetwork":{"limit":50},
  "network_route":{"limit":100},
  "networks_per_server":{"limit":3},
  "network_alias_ip":{"limit":5},
  "load_balancers":{"limit":100,"usage":71},
  "firewall_effective_rules":{"limit":500},
  "firewall":{"limit":50,"usage":3},
  "firewalls_per_server":{"limit":5},
  "bucket":{"limit":100,"usage":29},
  "zones":{"limit":25,"usage":4},
  "records_per_zone":{"limit":500},
  "storage_box":{"limit":3,"usage":1},
  "kubernetes_clusters":{"limit":2,"usage":0}
},
"permissions":{"extended_support":false,"request_allowed":true}}
```
Some resources only have `limit` (no `usage`). Good source for a Prometheus exporter.

### `GET /v1/_project_owner/limits`
Auth: **project_user** (403 with user token — "access denied")
Shape: not yet captured. Likely similar to `_user/limits` but scoped to the project owner's per-project quotas. TODO.

### `GET /v1/_activities`
Auth: user
See `reference/audit-logs-fetcher/docs/hetzner-undocumented-api.md`.

### `GET /v1/_incidents`
Auth: user
Platform status. See reference doc.

## Auth quirks

- `user` token is short-lived (~5 min `expires_in`). Refresh requires a real
  browser to solve the HeRay PoW + WASM fingerprint challenge on
  `accounts.hetzner.com`. Pure-HTTP login is not possible.
- `project_user` tokens live ~12 h. Mint on demand from a user token via the
  special `POST /_tokens` body.
- The Authorization header is a plain `Bearer <token>`.
- The `tokens` cookie is NOT httpOnly — the SPA reads it with
  `document.cookie`. This is how we extracted tokens during capture; do not
  rely on this in a library.

## OAuth parameters (for reference)

| Param | Value |
|---|---|
| Authorization URL | `https://accounts.hetzner.com/oauth/authorize` |
| Client ID | `cloud_421` |
| Redirect URI | `https://console.hetzner.cloud/` (or `https://console.hetzner.com/`) |
| Scope | `openid` |
| Response type | `token` (implicit) |
| Logout URL | `https://accounts.hetzner.com/logout` |
