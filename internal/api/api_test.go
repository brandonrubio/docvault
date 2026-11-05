package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/example/docvault/internal/auth"
	"github.com/example/docvault/internal/authz"
	"github.com/example/docvault/internal/store"
)

// fakeAuthz allows exactly the "user relation object" strings in allow.
type fakeAuthz struct {
	allow     map[string]bool
	writes    []authz.Tuple
	failWrite bool
}

func (f *fakeAuthz) Check(_ context.Context, u, r, o string) (bool, error) {
	return f.allow[u+" "+r+" "+o], nil
}
func (f *fakeAuthz) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}
func (f *fakeAuthz) Write(_ context.Context, t ...authz.Tuple) error {
	if f.failWrite {
		return errors.New("boom")
	}
	f.writes = append(f.writes, t...)
	return nil
}
func (f *fakeAuthz) Delete(context.Context, ...authz.Tuple) error { return nil }
func (f *fakeAuthz) DeleteObject(context.Context, string) error   { return nil }
func (f *fakeAuthz) Exists(context.Context, string, string) (bool, error) {
	return false, nil
}

var testSecret = []byte(strings.Repeat("k", 32))

type testEnv struct {
	h      http.Handler
	tokens *auth.Service
	db     *store.Store
}

func newEnv(t *testing.T, a authz.Authorizer) testEnv {
	t.Helper()
	tokens, err := auth.NewService(testSecret, "docvault", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	srv := NewServer(Deps{Authz: a, Store: db, Auth: tokens, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	return testEnv{h: srv.Handler(), tokens: tokens, db: db}
}

// do sends a request. bearer is sent as the Authorization header when non-empty.
func (e testEnv) do(method, path, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// as returns a valid token for user, without going through signup/login.
func (e testEnv) as(user string) string {
	tok, _, _ := e.tokens.Issue(user)
	return tok
}

func TestRequiresValidToken(t *testing.T) {
	e := newEnv(t, &fakeAuthz{})
	other, _ := auth.NewService([]byte(strings.Repeat("z", 32)), "docvault", time.Hour)
	expired, _ := auth.NewService(testSecret, "docvault", -time.Minute)
	forged, _, _ := other.Issue("bob")
	old, _, _ := expired.Issue("bob")

	for name, tok := range map[string]string{"none": "", "garbage": "abc", "forged": forged, "expired": old} {
		if got := e.do("GET", "/documents/d1", tok, "").Code; got != http.StatusUnauthorized {
			t.Errorf("%s: got %d, want 401", name, got)
		}
	}
	if got := e.do("GET", "/healthz", "", "").Code; got != http.StatusOK {
		t.Errorf("healthz should be public, got %d", got)
	}
}

func TestForbiddenIsAudited(t *testing.T) {
	e := newEnv(t, &fakeAuthz{})
	if got := e.do("GET", "/documents/d1", e.as("bob"), "").Code; got != http.StatusForbidden {
		t.Fatalf("got %d, want 403", got)
	}
	entries, err := e.db.ListAudit(context.Background(), "document:d1", 10)
	if err != nil || len(entries) != 1 || entries[0].Outcome != "denied" || entries[0].Actor != "user:bob" {
		t.Fatalf("audit = %+v, %v", entries, err)
	}
}

func TestShareValidationAndWildcardRules(t *testing.T) {
	e := newEnv(t, &fakeAuthz{allow: map[string]bool{"user:bob can_share document:d1": true}})
	cases := []struct {
		body string
		want int
	}{
		{`{"subject":"user:carol","role":"viewer"}`, http.StatusNoContent},
		{`{"subject":"team:eng#member","role":"editor"}`, http.StatusNoContent},
		{`{"subject":"user:*","role":"viewer"}`, http.StatusNoContent},
		{`{"subject":"user:*","role":"editor"}`, http.StatusBadRequest},
		{`{"subject":"team:eng#admin","role":"viewer"}`, http.StatusBadRequest},
		{`{"subject":"user:a#b","role":"viewer"}`, http.StatusBadRequest},
		{`{"subject":"user:carol","role":"owner"}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		if got := e.do("POST", "/documents/d1/shares", e.as("bob"), c.body).Code; got != c.want {
			t.Errorf("%s: got %d, want %d", c.body, got, c.want)
		}
	}
}

func TestOnlyOwnersMintOwners(t *testing.T) {
	e := newEnv(t, &fakeAuthz{allow: map[string]bool{"user:amy can_manage_members organization:acme": true}})
	if got := e.do("POST", "/orgs/acme/members", e.as("amy"), `{"user":"zed","role":"owner"}`).Code; got != http.StatusForbidden {
		t.Fatalf("admin minting owner: got %d, want 403", got)
	}
	if got := e.do("POST", "/orgs/acme/members", e.as("amy"), `{"user":"zed","role":"member"}`).Code; got != http.StatusNoContent {
		t.Fatalf("admin adding member: got %d, want 204", got)
	}
}

func TestCreateDocumentRollsBackWhenGrantFails(t *testing.T) {
	f := &fakeAuthz{allow: map[string]bool{"user:bob can_create_document folder:eng": true}, failWrite: true}
	e := newEnv(t, f)
	body := `{"id":"d1","title":"t","content":"c"}`
	if got := e.do("POST", "/folders/eng/documents", e.as("bob"), body).Code; got != http.StatusBadGateway {
		t.Fatalf("got %d, want 502", got)
	}
	if _, err := e.db.GetDocument(context.Background(), "d1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("orphaned document row left behind: %v", err)
	}
	f.failWrite = false
	if got := e.do("POST", "/folders/eng/documents", e.as("bob"), body).Code; got != http.StatusCreated {
		t.Fatalf("retry: got %d, want 201", got)
	}
}

func TestSignupAndLogin(t *testing.T) {
	e := newEnv(t, &fakeAuthz{})
	creds := func(u, p string) string {
		b, _ := json.Marshal(map[string]string{"username": u, "password": p})
		return string(b)
	}
	const pw = "correct horse battery"

	if got := e.do("POST", "/auth/signup", "", creds("alice", "short")).Code; got != http.StatusBadRequest {
		t.Errorf("short password: %d", got)
	}
	if got := e.do("POST", "/auth/signup", "", creds("al ice", pw)).Code; got != http.StatusBadRequest {
		t.Errorf("bad username: %d", got)
	}
	if got := e.do("POST", "/auth/signup", "", creds("alice", pw)).Code; got != http.StatusCreated {
		t.Fatalf("signup: %d", got)
	}
	if got := e.do("POST", "/auth/signup", "", creds("alice", pw)).Code; got != http.StatusConflict {
		t.Errorf("duplicate signup: %d", got)
	}

	// Wrong password and unknown user are indistinguishable.
	wrong := e.do("POST", "/auth/login", "", creds("alice", "wrong password!"))
	unknown := e.do("POST", "/auth/login", "", creds("nobody", pw))
	if wrong.Code != http.StatusUnauthorized || unknown.Code != http.StatusUnauthorized || wrong.Body.String() != unknown.Body.String() {
		t.Errorf("login failures differ: %d %q vs %d %q", wrong.Code, wrong.Body, unknown.Code, unknown.Body)
	}

	rec := e.do("POST", "/auth/login", "", creds("alice", pw))
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	me := e.do("GET", "/me", resp.AccessToken, "")
	if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), "user:alice") {
		t.Errorf("/me: %d %s", me.Code, me.Body)
	}
	if strings.Contains(rec.Body.String(), "password") {
		t.Error("response leaks password field")
	}
}

func TestLoginIsRateLimited(t *testing.T) {
	e := newEnv(t, &fakeAuthz{})
	body := `{"username":"alice","password":"whatever-password"}`
	var last int
	for i := 0; i < 11; i++ {
		last = e.do("POST", "/auth/login", "", body).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("11th attempt: got %d, want 429", last)
	}
}
