package hcloudplus

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Project is an account-scoped project as returned by the private API. It is
// a superset of the per-project summary returned by the public API: it
// includes the owner, role, resource counts and the `usage_alert_threshold`
// field that the public API hides.
type Project struct {
	ID                   int64       `json:"id"`
	Name                 string      `json:"name"`
	Owner                ProjectUser `json:"owner"`
	Role                 string      `json:"role"`
	Features             []string    `json:"features"`
	BlockedPorts         []int       `json:"blocked_ports"`
	UsageAlertThreshold  *float64    `json:"usage_alert_threshold"`
	Created              time.Time   `json:"created"`
	BackupCount          int         `json:"backup_count"`
	FirewallCount        int         `json:"firewall_count"`
	FloatingIPCount      int         `json:"floating_ip_count"`
	ImageCount           int         `json:"image_count"`
	LoadBalancerCount    int         `json:"load_balancer_count"`
	NetworkCount         int         `json:"network_count"`
	PrimaryIPv4Count     int         `json:"primary_ipv4_count"`
	PrimaryIPv6Count     int         `json:"primary_ipv6_count"`
	ServerCount          int         `json:"server_count"`
	UserCount            int         `json:"user_count"`
	VolumeCount          int         `json:"volume_count"`
	BucketCount          int         `json:"bucket_count"`
	StorageBoxCount      int         `json:"storage_box_count"`
	ZoneCount            int         `json:"zone_count"`
	KubernetesClusterCnt int         `json:"kubernetes_clusters_count"`
}

// ProjectUser is the owner/member record embedded in Project.Owner and in
// /_user responses. Only `id`, `email` and `robot_cn` are reliably populated
// in every context; the rest are filled in for the authenticated owner.
type ProjectUser struct {
	ID                int64    `json:"id"`
	RobotCN           string   `json:"robot_cn"`
	Email             string   `json:"email"`
	FirstName         string   `json:"first_name,omitempty"`
	LastName          string   `json:"last_name,omitempty"`
	CompanyName       string   `json:"company_name,omitempty"`
	Locale            string   `json:"locale,omitempty"`
	Currency          string   `json:"currency,omitempty"`
	VATRate           string   `json:"vat_rate,omitempty"`
	Restriction       string   `json:"restriction,omitempty"`
	Features          []string `json:"features,omitempty"`
	BlockedPorts      []int    `json:"blocked_ports,omitempty"`
	HasBillingDetails bool     `json:"has_billing_details,omitempty"`
	LightUser         bool     `json:"light_user,omitempty"`
}

// ProjectClient exposes project CRUD.
type ProjectClient struct {
	client *Client
}

// ProjectListOpts is the input to List.
type ProjectListOpts struct {
	ListOpts
}

// List returns a single page of projects.
func (c ProjectClient) List(ctx context.Context, opts ProjectListOpts) ([]*Project, *Meta, error) {
	var body struct {
		Projects []*Project `json:"projects"`
		Meta     Meta       `json:"meta"`
	}
	err := c.client.do(ctx, request{
		method: http.MethodGet,
		path:   "/_projects",
		query:  opts.values(),
		auth:   authUser,
	}, &body)
	if err != nil {
		return nil, nil, err
	}
	return body.Projects, &body.Meta, nil
}

// All fetches every project by walking pagination.
func (c ProjectClient) All(ctx context.Context) ([]*Project, error) {
	return c.AllWithOpts(ctx, ProjectListOpts{ListOpts: ListOpts{PerPage: 50}})
}

// AllWithOpts fetches every project starting from the given options, walking
// the `next_page` links.
func (c ProjectClient) AllWithOpts(ctx context.Context, opts ProjectListOpts) ([]*Project, error) {
	if opts.Page == 0 {
		opts.Page = 1
	}
	var all []*Project
	for {
		page, meta, err := c.List(ctx, opts)
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

// GetByID fetches a single project. Returns (nil, nil, nil) if the server
// replies 404 — matching hcloud-go's Get behaviour.
func (c ProjectClient) GetByID(ctx context.Context, id int64) (*Project, error) {
	var body struct {
		Project *Project `json:"project"`
	}
	err := c.client.do(ctx, request{
		method: http.MethodGet,
		path:   fmt.Sprintf("/_projects/%d", id),
		auth:   authUser,
	}, &body)
	if err != nil {
		if IsError(err, ErrorCodeNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return body.Project, nil
}

// ProjectCreateOpts is the input to Create.
type ProjectCreateOpts struct {
	Name string
}

// Validate returns an error if the options are missing required fields.
func (o ProjectCreateOpts) Validate() error {
	if o.Name == "" {
		return errors.New("hcloudplus: ProjectCreateOpts.Name is required")
	}
	return nil
}

// Create creates a new project owned by the authenticated user.
func (c ProjectClient) Create(ctx context.Context, opts ProjectCreateOpts) (*Project, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	reqBody := struct {
		Name string `json:"name"`
	}{Name: opts.Name}
	var body struct {
		Project *Project `json:"project"`
	}
	err := c.client.do(ctx, request{
		method: http.MethodPost,
		path:   "/_projects",
		body:   reqBody,
		auth:   authUser,
	}, &body)
	if err != nil {
		return nil, err
	}
	return body.Project, nil
}

// ProjectUpdateOpts is the input to Update. Only the fields that are set are
// sent; other fields keep their current value server-side.
type ProjectUpdateOpts struct {
	Name string
}

// Update renames a project. (The private API PUT endpoint only accepts
// `name` in our captures; other fields are not currently writable through
// this method.)
func (c ProjectClient) Update(ctx context.Context, id int64, opts ProjectUpdateOpts) (*Project, error) {
	reqBody := struct {
		Name string `json:"name,omitempty"`
	}{Name: opts.Name}
	var body struct {
		Project *Project `json:"project"`
	}
	err := c.client.do(ctx, request{
		method: http.MethodPut,
		path:   fmt.Sprintf("/_projects/%d", id),
		body:   reqBody,
		auth:   authUser,
	}, &body)
	if err != nil {
		return nil, err
	}
	return body.Project, nil
}

// Delete permanently deletes a project. The server responds 204 on success.
func (c ProjectClient) Delete(ctx context.Context, id int64) error {
	err := c.client.do(ctx, request{
		method: http.MethodDelete,
		path:   fmt.Sprintf("/_projects/%d", id),
		auth:   authUser,
	}, nil)
	return err
}
