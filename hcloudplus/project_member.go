package hcloudplus

import (
	"context"
	"fmt"
	"net/http"
)

// ProjectMember is an accepted project membership: a project user plus their
// role in the project.
type ProjectMember struct {
	User ProjectUser `json:"user"`
	Role string      `json:"role"`
}

// ProjectMemberClient exposes read access to project members.
//
// Role changes and removal of already-accepted members are not exposed yet:
// the Hetzner UI only allows these flows once a second account has accepted
// an invitation, so we haven't captured the request shape. The endpoints are
// likely `PUT /_projects/:id/users/:user_id` and
// `DELETE /_projects/:id/users/:user_id`, but ship them only after we've
// verified against a real capture.
type ProjectMemberClient struct {
	client *Client
}

// ProjectMemberListOpts is the input to List.
type ProjectMemberListOpts struct {
	ListOpts
}

// List returns a page of accepted members for a project.
func (c ProjectMemberClient) List(ctx context.Context, projectID int64, opts ProjectMemberListOpts) ([]*ProjectMember, *Meta, error) {
	var body struct {
		Users []*ProjectMember `json:"users"`
		Meta  Meta             `json:"meta"`
	}
	err := c.client.do(ctx, request{
		method:    http.MethodGet,
		path:      fmt.Sprintf("/_projects/%d/users", projectID),
		query:     opts.values(),
		auth:      authProjectUser,
		projectID: projectID,
	}, &body)
	if err != nil {
		return nil, nil, err
	}
	return body.Users, &body.Meta, nil
}

// All walks all pages of members for a project.
func (c ProjectMemberClient) All(ctx context.Context, projectID int64) ([]*ProjectMember, error) {
	opts := ProjectMemberListOpts{ListOpts: ListOpts{Page: 1, PerPage: 50}}
	var all []*ProjectMember
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
