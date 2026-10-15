// Package hcloudplus is a client for Hetzner Cloud's undocumented console
// ("private") API. It covers operations the public hcloud-go library cannot
// perform — creating and deleting projects, creating and deleting project API
// tokens, managing project members, and reading account-level data —
// following hcloud-go's conventions wherever possible.
//
// Authentication uses an account-level user token obtained via the Hetzner
// console OAuth flow. Because that flow is gated by a browser-side
// proof-of-work challenge (HeRay), this package does not implement login
// itself: the caller supplies a user token, typically extracted from the
// console's `tokens` cookie or minted out-of-band. Project-scoped operations
// (listing/creating/deleting API tokens, reading project-owner limits)
// require a `project_user` token; the client mints these on demand and
// caches them per project.
package hcloudplus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Endpoint is the default base URL for the private API.
const Endpoint = "https://api.hetzner.cloud/v1"

// UserAgent is prepended to every request's User-Agent header.
const UserAgent = "hcloud-go-plus"

// Version is a rough library version string; bump manually.
const Version = "0.1.1"

// TokenSource produces (and optionally refreshes) an account-level user
// token. Implementations must be safe for concurrent use.
//
// Token returns the current valid user token, its absolute expiry time (or
// the zero value if unknown), and any error encountered. The client caches
// the returned value and only consults the source again after ~80% of the
// advertised lifetime has elapsed, or on the next authentication failure,
// whichever comes first.
//
// For callers who already hold a token (e.g. extracted from a browser
// session), use StaticToken or WithUserToken.
type TokenSource interface {
	Token(ctx context.Context) (token string, expires time.Time, err error)
}

// StaticToken is a TokenSource that always returns the same string.
type StaticToken string

// Token implements TokenSource.
func (s StaticToken) Token(context.Context) (string, time.Time, error) {
	return string(s), time.Time{}, nil
}

// Client is the entry point for the private Hetzner API. Construct it with
// NewClient and use the resource clients exposed as fields.
type Client struct {
	endpoint    string
	tokenSource TokenSource
	httpClient  *http.Client
	application Application
	debugWriter io.Writer

	// cached user token
	userMu     sync.Mutex
	userToken  string
	userExpiry time.Time

	// per-project project_user token cache
	puMu    sync.Mutex
	puCache map[int64]*projectUserToken

	// Resource clients.
	Project           ProjectClient
	ProjectInvitation ProjectInvitationClient
	ProjectMember     ProjectMemberClient
	ProjectToken      ProjectTokenClient
	User              UserClient
	Activity          ActivityClient
}

// Application identifies the calling program in the User-Agent header,
// matching hcloud.Application.
type Application struct {
	Name    string
	Version string
}

type projectUserToken struct {
	secret  string
	expires time.Time
}

// Option configures a Client. Follows the functional-option style used by
// hcloud-go.
type Option func(*Client)

// WithEndpoint overrides the API base URL. Useful for tests.
func WithEndpoint(endpoint string) Option {
	return func(c *Client) { c.endpoint = strings.TrimRight(endpoint, "/") }
}

// WithUserToken sets a static account-level user token. Convenience wrapper
// around WithTokenSource(StaticToken(token)).
func WithUserToken(token string) Option {
	return WithTokenSource(StaticToken(token))
}

// WithTokenSource installs a TokenSource used to obtain and refresh the
// account-level user token. Mutually exclusive with WithUserToken — the last
// option applied wins.
func WithTokenSource(ts TokenSource) Option {
	return func(c *Client) { c.tokenSource = ts }
}

// WithHTTPClient replaces the underlying http.Client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) { c.httpClient = httpClient }
}

// WithApplication sets the application name/version included in User-Agent.
func WithApplication(name, version string) Option {
	return func(c *Client) { c.application = Application{Name: name, Version: version} }
}

// WithDebugWriter enables request/response tracing to the given writer.
func WithDebugWriter(w io.Writer) Option {
	return func(c *Client) { c.debugWriter = w }
}

// NewClient constructs a Client. At minimum, WithUserToken is required for
// any authenticated call.
func NewClient(options ...Option) *Client {
	c := &Client{
		endpoint:   Endpoint,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		puCache:    make(map[int64]*projectUserToken),
	}
	for _, opt := range options {
		opt(c)
	}
	c.Project = ProjectClient{client: c}
	c.ProjectInvitation = ProjectInvitationClient{client: c}
	c.ProjectMember = ProjectMemberClient{client: c}
	c.ProjectToken = ProjectTokenClient{client: c}
	c.User = UserClient{client: c}
	c.Activity = ActivityClient{client: c}
	return c
}

// authKind selects which bearer the request uses.
type authKind int

const (
	authUser authKind = iota
	authProjectUser
	authNone
)

// request describes a single API call.
type request struct {
	method    string
	path      string
	query     url.Values
	body      any // marshaled as JSON if non-nil
	auth      authKind
	projectID int64 // required for authProjectUser
}

// do executes req and, if out is non-nil, decodes the JSON response into
// it. The HTTP response body is drained and closed before returning. On
// 4xx/5xx a hcloudplus.Error is returned with the parsed server envelope.
func (c *Client) do(ctx context.Context, req request, out any) error {
	bearer, err := c.bearerFor(ctx, req.auth, req.projectID)
	if err != nil {
		return err
	}

	var bodyReader io.Reader
	if req.body != nil {
		buf, err := json.Marshal(req.body)
		if err != nil {
			return fmt.Errorf("hcloudplus: marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	u := c.endpoint + req.path
	if len(req.query) > 0 {
		u += "?" + req.query.Encode()
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.method, u, bodyReader)
	if err != nil {
		return err
	}
	httpReq.Header.Set("User-Agent", c.userAgentHeader())
	httpReq.Header.Set("Accept", "application/json")
	if req.body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		httpReq.Header.Set("Authorization", "Bearer "+bearer)
	}

	if c.debugWriter != nil {
		_, _ = fmt.Fprintf(c.debugWriter, "--> %s %s\n", req.method, u)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if c.debugWriter != nil {
		_, _ = fmt.Fprintf(c.debugWriter, "<-- %d %s\n%s\n", resp.StatusCode, u, body)
	}

	if resp.StatusCode >= 400 {
		// Invalidate caches on 401 so the next call refreshes.
		if resp.StatusCode == http.StatusUnauthorized {
			switch req.auth {
			case authUser:
				c.invalidateUserToken()
			case authProjectUser:
				c.invalidateProjectUserToken(req.projectID)
			}
		}
		// project_user specifically also invalidates on 403 — some routes
		// 403 when the project_user session expires instead of 401.
		if req.auth == authProjectUser && resp.StatusCode == http.StatusForbidden {
			c.invalidateProjectUserToken(req.projectID)
		}
		return parseErrorResponse(resp, body)
	}

	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("hcloudplus: decode response: %w", err)
		}
	}
	return nil
}

func (c *Client) userAgentHeader() string {
	base := UserAgent + "/" + Version
	if c.application.Name != "" {
		base = c.application.Name + "/" + c.application.Version + " " + base
	}
	return base
}

// bearerFor returns the bearer token to use for a request. For authProjectUser
// it transparently mints (and caches) a project_user token via the internal
// POST /_tokens bootstrap endpoint.
func (c *Client) bearerFor(ctx context.Context, kind authKind, projectID int64) (string, error) {
	switch kind {
	case authNone:
		return "", nil
	case authUser:
		return c.userBearer(ctx)
	case authProjectUser:
		if projectID == 0 {
			return "", errors.New("hcloudplus: project_user auth requires projectID")
		}
		return c.projectUserBearer(ctx, projectID)
	default:
		return "", fmt.Errorf("hcloudplus: unknown auth kind %d", kind)
	}
}

// userBearer returns a currently-valid user token, refreshing via the
// TokenSource at ~80% of the advertised lifetime. A zero expiry from the
// source is treated as "no expiry known" — the value is cached indefinitely
// and only invalidated on 401.
func (c *Client) userBearer(ctx context.Context) (string, error) {
	if c.tokenSource == nil {
		return "", errors.New("hcloudplus: no token source configured (use WithUserToken or WithTokenSource)")
	}
	c.userMu.Lock()
	if c.userToken != "" && (c.userExpiry.IsZero() || time.Until(c.userExpiry) > 0) {
		tok := c.userToken
		c.userMu.Unlock()
		return tok, nil
	}
	c.userMu.Unlock()

	token, expires, err := c.tokenSource.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("hcloudplus: token source: %w", err)
	}
	if token == "" {
		return "", errors.New("hcloudplus: token source returned empty token")
	}

	c.userMu.Lock()
	c.userToken = token
	if !expires.IsZero() {
		// Refresh at 80% of remaining lifetime.
		remaining := time.Until(expires)
		c.userExpiry = time.Now().Add(remaining * 8 / 10)
	} else {
		c.userExpiry = time.Time{}
	}
	c.userMu.Unlock()
	return token, nil
}

func (c *Client) invalidateUserToken() {
	c.userMu.Lock()
	c.userToken = ""
	c.userExpiry = time.Time{}
	c.userMu.Unlock()
}

func (c *Client) projectUserBearer(ctx context.Context, projectID int64) (string, error) {
	c.puMu.Lock()
	if t, ok := c.puCache[projectID]; ok && time.Until(t.expires) > 30*time.Second {
		secret := t.secret
		c.puMu.Unlock()
		return secret, nil
	}
	c.puMu.Unlock()

	// Mint a fresh one. This call itself requires the user token.
	type mintReq struct {
		Type    string `json:"type"`
		Project int64  `json:"project"`
	}
	type mintResp struct {
		SecretToken string `json:"secret_token"`
		Token       struct {
			Expires time.Time `json:"expires"`
		} `json:"token"`
	}
	var out mintResp
	err := c.do(ctx, request{
		method: http.MethodPost,
		path:   tokensPath,
		body:   mintReq{Type: "project_user", Project: projectID},
		auth:   authUser,
	}, &out)
	if err != nil {
		return "", fmt.Errorf("hcloudplus: mint project_user token for project %d: %w", projectID, err)
	}
	if out.SecretToken == "" {
		return "", fmt.Errorf("hcloudplus: mint project_user token for project %d: empty secret_token", projectID)
	}

	c.puMu.Lock()
	c.puCache[projectID] = &projectUserToken{secret: out.SecretToken, expires: out.Token.Expires}
	c.puMu.Unlock()
	return out.SecretToken, nil
}

func (c *Client) invalidateProjectUserToken(projectID int64) {
	c.puMu.Lock()
	delete(c.puCache, projectID)
	c.puMu.Unlock()
}
