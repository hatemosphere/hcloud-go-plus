package hcloudplus

import (
	"context"
	"net/http"
)

// UserClient exposes account-level reads: current user, limits, current
// token.
type UserClient struct {
	client *Client
}

// Me returns the authenticated user profile from `GET /_user`.
func (c UserClient) Me(ctx context.Context) (*ProjectUser, error) {
	var body struct {
		User *ProjectUser `json:"user"`
	}
	err := c.client.do(ctx, request{
		method: http.MethodGet,
		path:   "/_user",
		auth:   authUser,
	}, &body)
	if err != nil {
		return nil, err
	}
	return body.User, nil
}

// Limits returns the account-wide resource limits and usage for the caller.
//
// The map keys are Hetzner resource names such as "server", "volume_size",
// "bucket", "kubernetes_clusters". Some entries only have Limit populated.
type Limits struct {
	Limits      map[string]LimitEntry `json:"limits"`
	Permissions LimitPermissions      `json:"permissions"`
}

// LimitEntry is a single row of Limits.Limits.
type LimitEntry struct {
	Limit int `json:"limit"`
	Usage int `json:"usage"`
}

// LimitPermissions carries the boolean flags from the same response.
type LimitPermissions struct {
	ExtendedSupport bool `json:"extended_support"`
	RequestAllowed  bool `json:"request_allowed"`
}

// Limits fetches `GET /_user/limits`.
func (c UserClient) Limits(ctx context.Context) (*Limits, error) {
	var body Limits
	err := c.client.do(ctx, request{
		method: http.MethodGet,
		path:   "/_user/limits",
		auth:   authUser,
	}, &body)
	if err != nil {
		return nil, err
	}
	return &body, nil
}

// CurrentToken is the result of GET /_tokens/current.
type CurrentToken struct {
	ID          int64           `json:"id"`
	Type        string          `json:"type"`
	Prefix      string          `json:"prefix"`
	Description string          `json:"description"`
	Disabled    bool            `json:"disabled"`
	Readonly    bool            `json:"readonly"`
	Expires     string          `json:"expires"`
	Project     ProjectTokenRef `json:"project"`
	User        ProjectTokenRef `json:"user"`
}

// CurrentToken fetches `GET /_tokens/current` — metadata about the token
// that authenticated the request.
func (c UserClient) CurrentToken(ctx context.Context) (*CurrentToken, error) {
	var body struct {
		Token *CurrentToken `json:"token"`
	}
	err := c.client.do(ctx, request{
		method: http.MethodGet,
		path:   "/_tokens/current",
		auth:   authUser,
	}, &body)
	if err != nil {
		return nil, err
	}
	return body.Token, nil
}
