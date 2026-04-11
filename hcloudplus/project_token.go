package hcloudplus

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ProjectToken is a project-scoped API token record as returned by
// `GET /_tokens`. The secret string is NOT part of this type; it is only
// returned once, from Create, in ProjectTokenCreateResult.Secret.
type ProjectToken struct {
	ID          int64            `json:"id"`
	Type        string           `json:"type"`
	Prefix      string           `json:"prefix"`
	Description string           `json:"description"`
	Disabled    bool             `json:"disabled"`
	Readonly    bool             `json:"readonly"`
	Expires     *time.Time       `json:"expires"`
	Project     ProjectTokenRef  `json:"project"`
	User        *ProjectTokenRef `json:"user,omitempty"`
}

// ProjectTokenRef is the compact project/user reference embedded in token
// records.
type ProjectTokenRef struct {
	ID                  int64    `json:"id"`
	Name                string   `json:"name,omitempty"`
	Email               string   `json:"email,omitempty"`
	RobotCN             string   `json:"robot_cn,omitempty"`
	Created             string   `json:"created,omitempty"`
	UsageAlertThreshold *float64 `json:"usage_alert_threshold,omitempty"`
}

// ProjectTokenClient handles per-project API tokens. All operations require
// a project_user token internally; the client mints one on demand.
type ProjectTokenClient struct {
	client *Client
}

// ProjectTokenListOpts is the input to List.
type ProjectTokenListOpts struct {
	ListOpts
}

// List returns a page of project API tokens.
func (c ProjectTokenClient) List(ctx context.Context, projectID int64, opts ProjectTokenListOpts) ([]*ProjectToken, *Meta, error) {
	var body struct {
		Tokens []*ProjectToken `json:"tokens"`
		Meta   Meta            `json:"meta"`
	}
	err := c.client.do(ctx, request{
		method:    http.MethodGet,
		path:      "/_tokens",
		query:     opts.values(),
		auth:      authProjectUser,
		projectID: projectID,
	}, &body)
	if err != nil {
		return nil, nil, err
	}
	return body.Tokens, &body.Meta, nil
}

// All walks every page of tokens for a project.
func (c ProjectTokenClient) All(ctx context.Context, projectID int64) ([]*ProjectToken, error) {
	opts := ProjectTokenListOpts{ListOpts: ListOpts{Page: 1, PerPage: 50}}
	var all []*ProjectToken
	for {
		page, meta, err := c.List(ctx, projectID, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if meta.Pagination.NextPage == 0 {
			return all, nil
		}
		opts.Page = meta.Pagination.NextPage
	}
}

// ProjectTokenCreateOpts is the input to Create.
type ProjectTokenCreateOpts struct {
	Description string
	Readonly    bool
}

// Validate returns an error if required fields are missing.
func (o ProjectTokenCreateOpts) Validate() error {
	if o.Description == "" {
		return errors.New("hcloudplus: ProjectTokenCreateOpts.Description is required")
	}
	return nil
}

// ProjectTokenCreateResult is returned from Create. Secret is the only place
// the caller will ever see the full bearer string — store it immediately.
type ProjectTokenCreateResult struct {
	Token  *ProjectToken
	Secret string
}

// Create creates a new project API token. The project is determined by the
// project_user context that the client mints for `projectID`; no project ID
// goes in the request body.
func (c ProjectTokenClient) Create(ctx context.Context, projectID int64, opts ProjectTokenCreateOpts) (*ProjectTokenCreateResult, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	reqBody := struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		Readonly    bool   `json:"readonly"`
	}{Type: "project", Description: opts.Description, Readonly: opts.Readonly}
	var body struct {
		SecretToken string        `json:"secret_token"`
		Token       *ProjectToken `json:"token"`
	}
	err := c.client.do(ctx, request{
		method:    http.MethodPost,
		path:      "/_tokens",
		body:      reqBody,
		auth:      authProjectUser,
		projectID: projectID,
	}, &body)
	if err != nil {
		return nil, err
	}
	if body.SecretToken == "" {
		return nil, errors.New("hcloudplus: Create: empty secret_token in response")
	}
	return &ProjectTokenCreateResult{Token: body.Token, Secret: body.SecretToken}, nil
}

// Delete deletes a project API token.
func (c ProjectTokenClient) Delete(ctx context.Context, projectID, tokenID int64) error {
	err := c.client.do(ctx, request{
		method:    http.MethodDelete,
		path:      fmt.Sprintf("/_tokens/%d", tokenID),
		auth:      authProjectUser,
		projectID: projectID,
	}, nil)
	return err
}
