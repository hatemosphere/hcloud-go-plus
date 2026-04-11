package hcloudplus

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testEnv wraps an httptest server + a Client pointed at it. Mirrors the
// hcloud-go testEnv pattern.
type testEnv struct {
	Mux    *http.ServeMux
	Server *httptest.Server
	Client *Client
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := NewClient(
		WithEndpoint(srv.URL),
		WithUserToken("test-user-token"),
	)
	return &testEnv{Mux: mux, Server: srv, Client: client}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func assertBearer(t *testing.T, r *http.Request, want string) {
	t.Helper()
	got := r.Header.Get("Authorization")
	if got != "Bearer "+want {
		t.Errorf("Authorization = %q, want Bearer %s", got, want)
	}
}

func TestProjectCreate(t *testing.T) {
	env := newTestEnv(t)
	env.Mux.HandleFunc("/_projects", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		assertBearer(t, r, "test-user-token")
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Name != "test-proj" {
			t.Errorf("name = %q, want test-proj", body.Name)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(mustJSON(t, map[string]any{
			"project": map[string]any{
				"id":      int64(42),
				"name":    body.Name,
				"role":    "owner",
				"created": "2026-04-11T17:00:00Z",
				"owner":   map[string]any{"id": 1, "email": "a@b", "robot_cn": "K1"},
			},
		}))
	})

	p, err := env.Client.Project.Create(context.Background(), ProjectCreateOpts{Name: "test-proj"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if p.ID != 42 || p.Name != "test-proj" {
		t.Errorf("got %+v", p)
	}
}

func TestProjectCreateValidation(t *testing.T) {
	c := NewClient(WithUserToken("x"))
	_, err := c.Project.Create(context.Background(), ProjectCreateOpts{})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestProjectList(t *testing.T) {
	env := newTestEnv(t)
	env.Mux.HandleFunc("/_projects", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") != "2" {
			t.Errorf("page = %q, want 2", r.URL.Query().Get("page"))
		}
		w.Write(mustJSON(t, map[string]any{
			"projects": []map[string]any{{"id": 1, "name": "one"}, {"id": 2, "name": "two"}},
			"meta":     map[string]any{"pagination": map[string]any{"page": 2, "per_page": 25, "total_entries": 2, "last_page": 2}},
		}))
	})
	projs, meta, err := env.Client.Project.List(context.Background(), ProjectListOpts{ListOpts: ListOpts{Page: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if len(projs) != 2 || meta.Pagination.TotalEntries != 2 {
		t.Errorf("projs=%d meta=%+v", len(projs), meta.Pagination)
	}
}

func TestProjectDelete(t *testing.T) {
	env := newTestEnv(t)
	env.Mux.HandleFunc("/_projects/42", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	if err := env.Client.Project.Delete(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
}

func TestProjectGetNotFound(t *testing.T) {
	env := newTestEnv(t)
	env.Mux.HandleFunc("/_projects/99", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"code":404,"message":"project not found"}}`))
	})
	p, err := env.Client.Project.GetByID(context.Background(), 99)
	if err != nil {
		t.Fatalf("expected nil error for 404, got %v", err)
	}
	if p != nil {
		t.Errorf("expected nil project, got %+v", p)
	}
}

func TestInvitationLifecycle(t *testing.T) {
	env := newTestEnv(t)
	env.Mux.HandleFunc("/_projects/10/invitations", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["email"] != "x@y" || body["role"] != "member" {
			t.Errorf("body = %+v", body)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"project_invitation":{"id":7,"email":"x@y","role":"member","created":"2026-04-11T17:00:00Z"}}`))
	})
	env.Mux.HandleFunc("/_projects/10/invitations/7/resend", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("resend method = %s, want PUT", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	env.Mux.HandleFunc("/_projects/10/invitations/7", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("delete method = %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	ctx := context.Background()
	inv, err := env.Client.ProjectInvitation.Create(ctx, 10, ProjectInvitationCreateOpts{Email: "x@y", Role: "member"})
	if err != nil {
		t.Fatal(err)
	}
	if inv.ID != 7 {
		t.Errorf("inv id = %d", inv.ID)
	}
	if err := env.Client.ProjectInvitation.Resend(ctx, 10, 7); err != nil {
		t.Fatal(err)
	}
	if err := env.Client.ProjectInvitation.Delete(ctx, 10, 7); err != nil {
		t.Fatal(err)
	}
}

func TestProjectTokenCreateMintsProjectUser(t *testing.T) {
	env := newTestEnv(t)
	var mintCount, createCount int
	env.Mux.HandleFunc("/_tokens", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"project_user"`) {
			mintCount++
			assertBearer(t, r, "test-user-token")
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"secret_token":"pu-secret","token":{"id":1,"type":"project_user","expires":"2099-01-01T00:00:00Z"}}`))
			return
		}
		// API token create
		createCount++
		assertBearer(t, r, "pu-secret")
		if !strings.Contains(string(body), `"type":"project"`) {
			t.Errorf("expected type:project, body=%s", body)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"secret_token":"api-secret","token":{"id":99,"type":"project","prefix":"abc","description":"ro","readonly":true}}`))
	})

	res, err := env.Client.ProjectToken.Create(context.Background(), 10, ProjectTokenCreateOpts{
		Description: "ro", Readonly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Secret != "api-secret" || res.Token.ID != 99 {
		t.Errorf("res = %+v", res)
	}
	if mintCount != 1 || createCount != 1 {
		t.Errorf("mintCount=%d createCount=%d", mintCount, createCount)
	}

	// Second call should reuse the cached project_user token (no new mint).
	_, _ = env.Client.ProjectToken.Create(context.Background(), 10, ProjectTokenCreateOpts{Description: "another"})
	if mintCount != 1 {
		t.Errorf("expected cached project_user, mintCount=%d", mintCount)
	}
}

func TestProjectTokenCacheInvalidatesOn401(t *testing.T) {
	env := newTestEnv(t)
	// Seed a bogus cached token that will get 401'd.
	env.Client.puCache[10] = &projectUserToken{secret: "stale", expires: time.Now().Add(1 * time.Hour)}

	var seenStale bool
	env.Mux.HandleFunc("/_tokens/99", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer stale" {
			seenStale = true
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":{"code":401,"message":"expired"}}`))
			return
		}
		t.Errorf("unexpected auth: %s", r.Header.Get("Authorization"))
	})

	err := env.Client.ProjectToken.Delete(context.Background(), 10, 99)
	if !IsError(err, ErrorCodeUnauthorized) {
		t.Errorf("want unauthorized error, got %v", err)
	}
	if !seenStale {
		t.Error("server did not see stale token")
	}
	if _, cached := env.Client.puCache[10]; cached {
		t.Error("stale project_user token was not invalidated")
	}
}

func TestErrorDecodeNumericCode(t *testing.T) {
	env := newTestEnv(t)
	env.Mux.HandleFunc("/_projects/1", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"code":403,"message":"nope"}}`))
	})
	_, err := env.Client.Project.Update(context.Background(), 1, ProjectUpdateOpts{Name: "x"})
	if !IsError(err, ErrorCodeForbidden) {
		t.Errorf("want forbidden, got %v", err)
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("want 'nope' in error message, got %v", err)
	}
}

func TestErrorDecodeStringCode(t *testing.T) {
	env := newTestEnv(t)
	env.Mux.HandleFunc("/_projects", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"code":"not_found","message":"gone"}}`))
	})
	_, _, err := env.Client.Project.List(context.Background(), ProjectListOpts{})
	if !IsError(err, ErrorCodeNotFound) {
		t.Errorf("want not_found, got %v", err)
	}
}

func TestUserMe(t *testing.T) {
	env := newTestEnv(t)
	env.Mux.HandleFunc("/_user", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"user":{"id":1,"email":"a@b","robot_cn":"K1","first_name":"A","last_name":"B"}}`))
	})
	u, err := env.Client.User.Me(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "a@b" {
		t.Errorf("email = %s", u.Email)
	}
}

// fakeSource counts calls and returns a sequence of tokens.
type fakeSource struct {
	calls   int
	tokens  []string
	expires []time.Time
}

func (f *fakeSource) Token(context.Context) (string, time.Time, error) {
	i := f.calls
	f.calls++
	if i >= len(f.tokens) {
		i = len(f.tokens) - 1
	}
	return f.tokens[i], f.expires[i], nil
}

func TestTokenSourceCachedUntilExpiry(t *testing.T) {
	src := &fakeSource{
		tokens:  []string{"tok-a", "tok-b"},
		expires: []time.Time{time.Now().Add(1 * time.Hour), time.Now().Add(1 * time.Hour)},
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := NewClient(WithEndpoint(srv.URL), WithTokenSource(src))

	var sawBearers []string
	mux.HandleFunc("/_user", func(w http.ResponseWriter, r *http.Request) {
		sawBearers = append(sawBearers, r.Header.Get("Authorization"))
		w.Write([]byte(`{"user":{"id":1,"email":"a","robot_cn":"K"}}`))
	})

	ctx := context.Background()
	for range 3 {
		if _, err := client.User.Me(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if src.calls != 1 {
		t.Errorf("TokenSource called %d times, want 1 (cached)", src.calls)
	}
	for _, b := range sawBearers {
		if b != "Bearer tok-a" {
			t.Errorf("saw %q, want Bearer tok-a", b)
		}
	}
}

func TestTokenSourceRefreshedOn401(t *testing.T) {
	src := &fakeSource{
		tokens:  []string{"tok-a", "tok-b"},
		expires: []time.Time{time.Now().Add(1 * time.Hour), time.Now().Add(1 * time.Hour)},
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := NewClient(WithEndpoint(srv.URL), WithTokenSource(src))

	mux.HandleFunc("/_user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer tok-a" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":{"code":401,"message":"expired"}}`))
			return
		}
		w.Write([]byte(`{"user":{"id":1,"email":"a","robot_cn":"K"}}`))
	})

	ctx := context.Background()
	// First call: server rejects tok-a, client returns the error but evicts.
	_, err := client.User.Me(ctx)
	if !IsError(err, ErrorCodeUnauthorized) {
		t.Fatalf("want 401 error, got %v", err)
	}
	// Second call: fresh TokenSource call yields tok-b, which the server accepts.
	if _, err := client.User.Me(ctx); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if src.calls != 2 {
		t.Errorf("TokenSource called %d times, want 2", src.calls)
	}
}

func TestActivityListDecoding(t *testing.T) {
	env := newTestEnv(t)
	env.Mux.HandleFunc("/_activities", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("include_user_activities") != "true" {
			t.Errorf("include_user_activities = %q, want true", q.Get("include_user_activities"))
		}
		if got := q["project_ids"]; len(got) != 2 || got[0] != "10" || got[1] != "20" {
			t.Errorf("project_ids = %v, want [10 20]", got)
		}
		if got := q["types"]; len(got) != 1 || got[0] != "token.create" {
			t.Errorf("types = %v, want [token.create]", got)
		}
		if q.Get("per_page") != "100" {
			t.Errorf("per_page = %q, want 100", q.Get("per_page"))
		}
		if q.Get("cursor") != "next-cursor" {
			t.Errorf("cursor = %q, want next-cursor", q.Get("cursor"))
		}
		w.Write([]byte(`{
			"activities": [
				{
					"id": 946662810,
					"activity_type": "user.login",
					"created": "2026-02-02T09:56:01Z",
					"status": "success",
					"source_ip": "",
					"project": null,
					"resources": [],
					"action_id": null,
					"affected_properties": [],
					"api_token": null,
					"user": {"robot_cn": "K0247406420", "first_name": "Alex", "last_name": "G"}
				},
				{
					"id": 939188006,
					"activity_type": "load_balancer.update_service",
					"created": "2026-01-30T13:59:16Z",
					"status": "success",
					"source_ip": "159.69.127.0/32",
					"project": {"id": 11122090, "name": "proj"},
					"resources": [{"id": 4858066, "name": "lb-a", "type": "load_balancer"}],
					"action_id": 608485210753090,
					"affected_properties": [],
					"api_token": {"prefix": "fknQ9Ra7"},
					"user": {"robot_cn": "K0247406420", "first_name": "Alex", "last_name": "G"}
				}
			],
			"meta": {"pagination": {"cursor": "eyJpZCI6MX0=", "per_page": 100}}
		}`))
	})

	ctx := context.Background()
	after, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	acts, meta, err := env.Client.Activity.List(ctx, ActivityListOpts{
		IncludeUserActivities: true,
		ProjectIDs:            []int64{10, 20},
		Types:                 []string{"token.create"},
		CreatedAfter:          after,
		PerPage:               100,
		Cursor:                "next-cursor",
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(acts) != 2 {
		t.Fatalf("len(acts) = %d, want 2", len(acts))
	}

	// Account-level activity
	a0 := acts[0]
	if a0.ID != 946662810 || a0.ActivityType != "user.login" {
		t.Errorf("a0: id=%d type=%s", a0.ID, a0.ActivityType)
	}
	if a0.Project != nil {
		t.Errorf("a0.Project = %+v, want nil", a0.Project)
	}
	if a0.APIToken != nil {
		t.Errorf("a0.APIToken = %+v, want nil", a0.APIToken)
	}
	if a0.User == nil || a0.User.RobotCN != "K0247406420" {
		t.Errorf("a0.User = %+v", a0.User)
	}

	// Project-scoped activity
	a1 := acts[1]
	if a1.Project == nil || a1.Project.ID != 11122090 || a1.Project.Name != "proj" {
		t.Errorf("a1.Project = %+v", a1.Project)
	}
	if len(a1.Resources) != 1 || a1.Resources[0].Name != "lb-a" || a1.Resources[0].Type != "load_balancer" {
		t.Errorf("a1.Resources = %+v", a1.Resources)
	}
	if a1.ActionID == nil || *a1.ActionID != 608485210753090 {
		t.Errorf("a1.ActionID = %v", a1.ActionID)
	}
	if a1.APIToken == nil || a1.APIToken.Prefix != "fknQ9Ra7" {
		t.Errorf("a1.APIToken = %+v", a1.APIToken)
	}

	if meta.Pagination.Cursor != "eyJpZCI6MX0=" {
		t.Errorf("cursor = %q", meta.Pagination.Cursor)
	}
}

func TestUserLimits(t *testing.T) {
	env := newTestEnv(t)
	env.Mux.HandleFunc("/_user/limits", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"limits":{"server":{"limit":400,"usage":199},"bucket":{"limit":100,"usage":29}},"permissions":{"extended_support":false,"request_allowed":true}}`))
	})
	l, err := env.Client.User.Limits(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if l.Limits["server"].Limit != 400 || l.Limits["server"].Usage != 199 {
		t.Errorf("server limit: %+v", l.Limits["server"])
	}
	if !l.Permissions.RequestAllowed {
		t.Error("request_allowed should be true")
	}
}
