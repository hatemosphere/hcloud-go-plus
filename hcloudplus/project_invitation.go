package hcloudplus

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// ProjectInvitation is a pending project membership invitation.
type ProjectInvitation struct {
	ID       int64      `json:"id"`
	Email    string     `json:"email"`
	Role     string     `json:"role"`
	Created  time.Time  `json:"created"`
	Accepted *time.Time `json:"accepted"`
	Expired  *time.Time `json:"expired"`
}

// ProjectInvitationClient handles pending invitations.
type ProjectInvitationClient struct {
	client *Client
}

// ProjectInvitationListOpts is the input to List.
type ProjectInvitationListOpts struct {
	ListOpts
}

// List returns a page of pending invitations for the given project.
func (c ProjectInvitationClient) List(ctx context.Context, projectID int64, opts ProjectInvitationListOpts) ([]*ProjectInvitation, *Meta, error) {
	var body struct {
		ProjectInvitations []*ProjectInvitation `json:"project_invitations"`
		Meta               Meta                 `json:"meta"`
	}
	err := c.client.do(ctx, request{
		method:    http.MethodGet,
		path:      fmt.Sprintf("/_projects/%d/invitations", projectID),
		query:     opts.values(),
		auth:      authProjectUser,
		projectID: projectID,
	}, &body)
	if err != nil {
		return nil, nil, err
	}
	return body.ProjectInvitations, &body.Meta, nil
}

// All walks all pages of invitations for a project.
func (c ProjectInvitationClient) All(ctx context.Context, projectID int64) ([]*ProjectInvitation, error) {
	opts := ProjectInvitationListOpts{ListOpts: ListOpts{Page: 1, PerPage: 50}}
	var all []*ProjectInvitation
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

// ProjectInvitationCreateOpts is the input to Create.
type ProjectInvitationCreateOpts struct {
	Email string
	Role  string // one of: admin, member, restricted
}

// Validate returns an error if required fields are missing.
func (o ProjectInvitationCreateOpts) Validate() error {
	if o.Email == "" {
		return errors.New("hcloudplus: ProjectInvitationCreateOpts.Email is required")
	}
	if o.Role == "" {
		return errors.New("hcloudplus: ProjectInvitationCreateOpts.Role is required")
	}
	return nil
}

// Create sends a new invitation for the given project.
func (c ProjectInvitationClient) Create(ctx context.Context, projectID int64, opts ProjectInvitationCreateOpts) (*ProjectInvitation, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	reqBody := struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}(opts)
	var body struct {
		ProjectInvitation *ProjectInvitation `json:"project_invitation"`
	}
	err := c.client.do(ctx, request{
		method:    http.MethodPost,
		path:      fmt.Sprintf("/_projects/%d/invitations", projectID),
		body:      reqBody,
		auth:      authProjectUser,
		projectID: projectID,
	}, &body)
	if err != nil {
		return nil, err
	}
	return body.ProjectInvitation, nil
}

// Resend re-sends the invitation email. Server responds 204.
//
// Note: the private API uses PUT for this action, not POST.
func (c ProjectInvitationClient) Resend(ctx context.Context, projectID, invitationID int64) error {
	err := c.client.do(ctx, request{
		method:    http.MethodPut,
		path:      fmt.Sprintf("/_projects/%d/invitations/%d/resend", projectID, invitationID),
		auth:      authProjectUser,
		projectID: projectID,
	}, nil)
	return err
}

// Delete revokes a pending invitation. Server responds 204.
func (c ProjectInvitationClient) Delete(ctx context.Context, projectID, invitationID int64) error {
	err := c.client.do(ctx, request{
		method:    http.MethodDelete,
		path:      fmt.Sprintf("/_projects/%d/invitations/%d", projectID, invitationID),
		auth:      authProjectUser,
		projectID: projectID,
	}, nil)
	return err
}
