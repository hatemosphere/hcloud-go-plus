//go:build integration

package hcloudplus

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

// Integration tests run against the real Hetzner private API.
//
// Run with:
//
//	HCGP_USER_TOKEN=<64-char user token from tokens cookie> \
//	  go test -tags=integration -race -timeout=10m ./hcloudplus/
//
// Extract HCGP_USER_TOKEN from a logged-in console session:
//
//	DevTools → Application → Cookies → https://console.hetzner.com
//	 → `tokens` → URL-decode value → JSON-parse → find entry with "type":"user"
//	 → copy the `token` field (64 chars).
//
// Every test resource is named with the `integrationPrefix` (currently
// "hcgp-it-") and registered with t.Cleanup on creation, so a crash still
// tears down. The suite refuses to Delete any project whose name does not
// start with the prefix — this protects production projects in the same
// account.

const (
	integrationPrefix = "hcgp-it-"
	integrationEmail  = "hcgp-it-invite@example.invalid"
)

// newIntegrationClient either builds a live-API client from HCGP_USER_TOKEN
// or skips the test. It also rejects tokens whose shape is obviously wrong
// (not 64 hex-ish chars) so you don't waste time hunting for a mystery 403.
func newIntegrationClient(t *testing.T) *Client {
	t.Helper()
	tok := os.Getenv("HCGP_USER_TOKEN")
	if tok == "" {
		t.Skip("HCGP_USER_TOKEN not set; skipping integration test")
	}
	if len(tok) != 64 {
		t.Fatalf("HCGP_USER_TOKEN must be 64 chars (got %d). Paste the `token` field of the user-type entry from the `tokens` cookie — not a public API token.", len(tok))
	}
	endpoint := Endpoint
	if v := os.Getenv("HCGP_ENDPOINT"); v != "" {
		endpoint = v
	}
	return NewClient(
		WithEndpoint(endpoint),
		WithUserToken(tok),
		WithApplication("hcloud-go-plus-integration", Version),
	)
}

func uniqueName(t *testing.T) string {
	t.Helper()
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return integrationPrefix + time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

// safeDeleteProject refuses to delete any project that doesn't match the
// integration prefix. Pass this to t.Cleanup after Create so a panic in the
// middle of a test still tears the project down.
func safeDeleteProject(t *testing.T, client *Client, id int64, name string) {
	t.Helper()
	if !strings.HasPrefix(name, integrationPrefix) {
		t.Fatalf("refusing to delete non-integration project %q (id=%d)", name, id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := client.Project.Delete(ctx, id)
	if err != nil && !IsError(err, ErrorCodeNotFound) {
		t.Logf("cleanup: delete project %d (%s): %v", id, name, err)
	}
}

func TestIT_UserReadOnly(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	me, err := client.User.Me(ctx)
	if err != nil {
		t.Fatalf("User.Me: %v", err)
	}
	if me.ID == 0 || me.Email == "" {
		t.Errorf("Me returned empty user: %+v", me)
	}

	limits, err := client.User.Limits(ctx)
	if err != nil {
		t.Fatalf("User.Limits: %v", err)
	}
	if len(limits.Limits) == 0 {
		t.Error("Limits.Limits is empty")
	}
	if srv, ok := limits.Limits["server"]; !ok || srv.Limit == 0 {
		t.Errorf("limits.server missing or zero: %+v", srv)
	}

	cur, err := client.User.CurrentToken(ctx)
	if err != nil {
		t.Fatalf("User.CurrentToken: %v", err)
	}
	if cur.Type != "user" {
		t.Errorf("CurrentToken.Type = %q, want user", cur.Type)
	}
}

func TestIT_ProjectLifecycle(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	name := uniqueName(t)
	p, err := client.Project.Create(ctx, ProjectCreateOpts{Name: name})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { safeDeleteProject(t, client, p.ID, p.Name) })
	if p.Name != name {
		t.Errorf("Create returned name = %q, want %q", p.Name, name)
	}
	if p.Role != "owner" {
		t.Errorf("Create returned role = %q, want owner", p.Role)
	}

	got, err := client.Project.GetByID(ctx, p.ID)
	if err != nil || got == nil {
		t.Fatalf("GetByID: got=%v err=%v", got, err)
	}
	if got.ID != p.ID {
		t.Errorf("GetByID id = %d, want %d", got.ID, p.ID)
	}

	newName := name + "-renamed"
	updated, err := client.Project.Update(ctx, p.ID, ProjectUpdateOpts{Name: newName})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != newName {
		t.Errorf("Update returned name = %q, want %q", updated.Name, newName)
	}

	// The rename must be visible in the list, too.
	all, err := client.Project.All(ctx)
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	var found bool
	for _, q := range all {
		if q.ID == p.ID {
			found = true
			if q.Name != newName {
				t.Errorf("List shows old name %q for renamed project", q.Name)
			}
		}
	}
	if !found {
		t.Errorf("renamed project %d not in All() result", p.ID)
	}

	if err := client.Project.Delete(ctx, p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// GetByID after delete should be nil, no error (404 swallowed).
	after, err := client.Project.GetByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetByID after delete: %v", err)
	}
	if after != nil {
		t.Errorf("GetByID after delete returned %+v, want nil", after)
	}
}

func TestIT_InvitationLifecycle(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	name := uniqueName(t)
	p, err := client.Project.Create(ctx, ProjectCreateOpts{Name: name})
	if err != nil {
		t.Fatalf("Create project: %v", err)
	}
	t.Cleanup(func() { safeDeleteProject(t, client, p.ID, p.Name) })

	inv, err := client.ProjectInvitation.Create(ctx, p.ID, ProjectInvitationCreateOpts{
		Email: integrationEmail,
		Role:  "member",
	})
	if err != nil {
		t.Fatalf("invitation Create: %v", err)
	}
	if inv.Email != integrationEmail || inv.Role != "member" {
		t.Errorf("invitation = %+v", inv)
	}
	// Register cleanup immediately in case the later asserts fail.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = client.ProjectInvitation.Delete(ctx, p.ID, inv.ID)
	})

	invs, err := client.ProjectInvitation.All(ctx, p.ID)
	if err != nil {
		t.Fatalf("invitation All: %v", err)
	}
	var seen bool
	for _, i := range invs {
		if i.ID == inv.ID {
			seen = true
		}
	}
	if !seen {
		t.Errorf("invitation %d not in All() result", inv.ID)
	}

	if err := client.ProjectInvitation.Resend(ctx, p.ID, inv.ID); err != nil {
		t.Fatalf("invitation Resend: %v", err)
	}

	if err := client.ProjectInvitation.Delete(ctx, p.ID, inv.ID); err != nil {
		t.Fatalf("invitation Delete: %v", err)
	}
}

func TestIT_ProjectTokenLifecycle(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	name := uniqueName(t)
	p, err := client.Project.Create(ctx, ProjectCreateOpts{Name: name})
	if err != nil {
		t.Fatalf("Create project: %v", err)
	}
	t.Cleanup(func() { safeDeleteProject(t, client, p.ID, p.Name) })

	// Create RO token
	ro, err := client.ProjectToken.Create(ctx, p.ID, ProjectTokenCreateOpts{
		Description: "hcgp-it-ro",
		Readonly:    true,
	})
	if err != nil {
		t.Fatalf("Create RO token: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = client.ProjectToken.Delete(ctx, p.ID, ro.Token.ID)
	})
	if ro.Secret == "" || len(ro.Secret) != 64 {
		t.Errorf("RO secret len = %d, want 64", len(ro.Secret))
	}
	if !ro.Token.Readonly {
		t.Error("RO token not marked readonly")
	}

	// Create RW token
	rw, err := client.ProjectToken.Create(ctx, p.ID, ProjectTokenCreateOpts{
		Description: "hcgp-it-rw",
		Readonly:    false,
	})
	if err != nil {
		t.Fatalf("Create RW token: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = client.ProjectToken.Delete(ctx, p.ID, rw.Token.ID)
	})
	if rw.Token.Readonly {
		t.Error("RW token marked readonly")
	}
	if rw.Secret == ro.Secret {
		t.Error("RO and RW secrets collided (should be different)")
	}

	// List should show both
	tokens, err := client.ProjectToken.All(ctx, p.ID)
	if err != nil {
		t.Fatalf("All tokens: %v", err)
	}
	want := map[int64]bool{ro.Token.ID: false, rw.Token.ID: false}
	for _, t := range tokens {
		if _, ok := want[t.ID]; ok {
			want[t.ID] = true
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("token %d missing from list", id)
		}
	}

	// Delete RO, verify list shrinks
	if err := client.ProjectToken.Delete(ctx, p.ID, ro.Token.ID); err != nil {
		t.Fatalf("Delete RO: %v", err)
	}
	tokens, err = client.ProjectToken.All(ctx, p.ID)
	if err != nil {
		t.Fatalf("All after delete: %v", err)
	}
	for _, tok := range tokens {
		if tok.ID == ro.Token.ID {
			t.Errorf("RO token %d still listed after delete", ro.Token.ID)
		}
	}
}

// TestIT_ActivityClosedLoop creates a project + project token + deletes the
// token, then queries /_activities for the same project and asserts that the
// token.create and token.delete events show up. This is the only test we
// have that exercises /_activities against real data.
//
// Activities are written asynchronously on Hetzner's side: we poll for up to
// a minute with a short interval.
func TestIT_ActivityClosedLoop(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	start := time.Now().UTC().Add(-30 * time.Second) // buffer for clock skew

	name := uniqueName(t)
	p, err := client.Project.Create(ctx, ProjectCreateOpts{Name: name})
	if err != nil {
		t.Fatalf("Create project: %v", err)
	}
	t.Cleanup(func() { safeDeleteProject(t, client, p.ID, p.Name) })

	tok, err := client.ProjectToken.Create(ctx, p.ID, ProjectTokenCreateOpts{
		Description: "hcgp-it-activity",
		Readonly:    true,
	})
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}
	if err := client.ProjectToken.Delete(ctx, p.ID, tok.Token.ID); err != nil {
		t.Fatalf("Delete token: %v", err)
	}

	// Poll /_activities. Both events should arrive within ~30s on a healthy
	// platform; give it a minute.
	deadline := time.Now().Add(90 * time.Second)
	var seenCreate, seenDelete bool
	var lastLen int
	for time.Now().Before(deadline) && (!seenCreate || !seenDelete) {
		time.Sleep(3 * time.Second)
		acts, _, err := client.Activity.List(ctx, ActivityListOpts{
			ProjectIDs:   []int64{p.ID},
			Types:        []string{"token.create", "token.delete"},
			CreatedAfter: start,
			PerPage:      100,
		})
		if err != nil {
			t.Fatalf("Activity.List: %v", err)
		}
		lastLen = len(acts)
		for _, a := range acts {
			if a.Project == nil || a.Project.ID != p.ID {
				continue
			}
			switch a.ActivityType {
			case "token.create":
				seenCreate = true
			case "token.delete":
				seenDelete = true
			}
		}
	}
	if !seenCreate {
		t.Errorf("token.create activity never showed up (last poll saw %d entries)", lastLen)
	}
	if !seenDelete {
		t.Errorf("token.delete activity never showed up (last poll saw %d entries)", lastLen)
	}
}

func TestIT_MemberList(t *testing.T) {
	client := newIntegrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	name := uniqueName(t)
	p, err := client.Project.Create(ctx, ProjectCreateOpts{Name: name})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() { safeDeleteProject(t, client, p.ID, p.Name) })

	members, err := client.ProjectMember.All(ctx, p.ID)
	if err != nil {
		t.Fatalf("members All: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("len(members) = %d, want 1 (just the owner)", len(members))
	}
	if len(members) > 0 && members[0].Role != "owner" {
		t.Errorf("first member role = %q, want owner", members[0].Role)
	}
}
