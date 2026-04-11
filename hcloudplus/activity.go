package hcloudplus

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Activity is an audit-log entry from `GET /_activities`. It contains fields
// the public actions API does not expose: the acting user, source IP and
// API-token prefix used for the call.
type Activity struct {
	ID                 int64            `json:"id"`
	ActivityType       string           `json:"activity_type"`
	Created            time.Time        `json:"created"`
	Status             string           `json:"status"` // "success" or "error"
	SourceIP           string           `json:"source_ip"`
	Project            *ActivityProject `json:"project"`
	Resources          []ActivityRes    `json:"resources"`
	ActionID           *int64           `json:"action_id"`
	AffectedProperties []string         `json:"affected_properties"`
	APIToken           *ActivityToken   `json:"api_token"`
	User               *ActivityUser    `json:"user"`
}

// ActivityProject is the `project` field of an Activity.
type ActivityProject struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// ActivityRes is one affected resource on an Activity.
type ActivityRes struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// ActivityToken is the API-token prefix that performed the action.
type ActivityToken struct {
	Prefix string `json:"prefix"`
}

// ActivityUser is the user field of an Activity. Only robot_cn + name fields
// are reliably populated.
type ActivityUser struct {
	RobotCN   string `json:"robot_cn"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// ActivityClient exposes the cross-project audit log.
type ActivityClient struct {
	client *Client
}

// ActivityListOpts is the input to List. Either IncludeUserActivities or
// ProjectIDs must be set; otherwise the server returns an error. The time
// window is capped at 31 days by the server.
type ActivityListOpts struct {
	IncludeUserActivities bool
	ProjectIDs            []int64
	Types                 []string // e.g. ["user.login", "server.create"]
	CreatedAfter          time.Time
	CreatedBefore         time.Time
	PerPage               int    // default 25, max 500
	Cursor                string // from previous Meta.Pagination.Cursor
}

func (o ActivityListOpts) values() url.Values {
	v := url.Values{}
	if o.IncludeUserActivities {
		v.Set("include_user_activities", "true")
	}
	for _, id := range o.ProjectIDs {
		v.Add("project_ids", strconv.FormatInt(id, 10))
	}
	for _, t := range o.Types {
		v.Add("types", t)
	}
	if !o.CreatedAfter.IsZero() {
		v.Set("created_after", o.CreatedAfter.UTC().Format(time.RFC3339))
	}
	if !o.CreatedBefore.IsZero() {
		v.Set("created_before", o.CreatedBefore.UTC().Format(time.RFC3339))
	}
	if o.PerPage > 0 {
		v.Set("per_page", strconv.Itoa(o.PerPage))
	}
	if o.Cursor != "" {
		v.Set("cursor", o.Cursor)
	}
	return v
}

// List returns a single page of activities. Use Meta.Pagination.Cursor to
// fetch the next page.
func (c ActivityClient) List(ctx context.Context, opts ActivityListOpts) ([]*Activity, *Meta, error) {
	var body struct {
		Activities []*Activity `json:"activities"`
		Meta       Meta        `json:"meta"`
	}
	err := c.client.do(ctx, request{
		method: http.MethodGet,
		path:   "/_activities",
		query:  opts.values(),
		auth:   authUser,
	}, &body)
	if err != nil {
		return nil, nil, err
	}
	return body.Activities, &body.Meta, nil
}
