package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/example/docvault/internal/auth"
	"github.com/example/docvault/internal/authz"
	"github.com/example/docvault/internal/store"
)

// TestEndToEnd runs a realistic scenario (real signup/login, real SQLite, real
// OpenFGA server). Skipped unless an OpenFGA server is available:
//
//	make up && OPENFGA_API_URL=http://localhost:8080 go test ./...
func TestEndToEnd(t *testing.T) {
	url := os.Getenv("OPENFGA_API_URL")
	if url == "" {
		t.Skip("OPENFGA_API_URL not set")
	}
	// Fresh store per run so a persistent OpenFGA doesn't leak state between runs.
	fga, err := authz.New(context.Background(), authz.Config{APIURL: url, StoreName: fmt.Sprintf("e2e-%d", time.Now().UnixNano())})
	if err != nil {
		t.Fatal(err)
	}
	tokens, _ := auth.NewService(testSecret, "docvault", time.Hour)
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := testEnv{
		h:      NewServer(Deps{Authz: fga, Store: db, Auth: tokens, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler(),
		tokens: tokens, db: db,
	}

	// Sign everyone up through the public API and log in for real tokens.
	tok := map[string]string{}
	for _, u := range []string{"alice", "bob", "carol", "dave", "mallory"} {
		body := fmt.Sprintf(`{"username":%q,"password":"a-long-test-password"}`, u)
		if rec := e.do("POST", "/auth/signup", "", body); rec.Code != 201 {
			t.Fatalf("signup %s: %d %s", u, rec.Code, rec.Body)
		}
		rec := e.do("POST", "/auth/login", "", body)
		var resp struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.AccessToken == "" {
			t.Fatalf("login %s: %d %s", u, rec.Code, rec.Body)
		}
		tok[u] = resp.AccessToken
	}

	step := func(name, method, path, user, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		rec := e.do(method, path, tok[user], body)
		if rec.Code != want {
			t.Fatalf("%s: %s %s as %s => %d, want %d (%s)", name, method, path, user, rec.Code, want, rec.Body)
		}
		return rec
	}

	// Alice founds acme and adds Bob as a plain member; Carol is an outsider.
	step("create org", "POST", "/orgs", "alice", `{"id":"acme"}`, 201)
	step("org id is taken", "POST", "/orgs", "mallory", `{"id":"acme"}`, 409)
	step("add bob", "POST", "/orgs/acme/members", "alice", `{"user":"bob","role":"member"}`, 204)
	step("member cannot add members", "POST", "/orgs/acme/members", "bob", `{"user":"carol","role":"member"}`, 403)

	// Bob (a member) creates a folder and a document; he owns both.
	step("create folder", "POST", "/orgs/acme/folders", "bob", `{"id":"eng"}`, 201)
	step("outsider cannot create folder", "POST", "/orgs/acme/folders", "carol", `{"id":"x"}`, 403)
	step("create doc", "POST", "/folders/eng/documents", "bob", `{"id":"spec","title":"Spec","content":"v1"}`, 201)
	step("doc id is taken", "POST", "/folders/eng/documents", "bob", `{"id":"spec","title":"x","content":"x"}`, 409)

	// Documents are private by default; org admins inherit access from the org.
	step("outsider denied", "GET", "/documents/spec", "carol", "", 403)
	step("org owner inherits access", "GET", "/documents/spec", "alice", "", 200)

	// Team-based sharing through a userset.
	step("create team", "POST", "/orgs/acme/teams", "alice", `{"id":"platform"}`, 201)
	step("add dave to team", "POST", "/teams/platform/members", "alice", `{"user":"dave"}`, 204)
	step("dave before share", "GET", "/documents/spec", "dave", "", 403)
	share := `{"subject":"team:platform#member","role":"viewer"}`
	step("share with team", "POST", "/documents/spec/shares", "bob", share, 204)
	step("share twice is idempotent", "POST", "/documents/spec/shares", "bob", share, 204)
	step("dave can read", "GET", "/documents/spec", "dave", "", 200)
	step("dave cannot edit", "PUT", "/documents/spec", "dave", `{"title":"Spec","content":"v2"}`, 403)
	step("bob edits", "PUT", "/documents/spec", "bob", `{"title":"Spec","content":"v2"}`, 200)

	// Revocation takes effect immediately.
	step("unshare", "DELETE", "/documents/spec/shares", "bob", share, 204)
	step("dave revoked", "GET", "/documents/spec", "dave", "", 403)

	// Public link via wildcard, and reverse lookup.
	step("make public", "POST", "/documents/spec/shares", "bob", `{"subject":"user:*","role":"viewer"}`, 204)
	rec := step("carol lists", "GET", "/documents", "carol", "", http.StatusOK)
	var docs []store.Document
	if err := json.Unmarshal(rec.Body.Bytes(), &docs); err != nil || len(docs) != 1 || docs[0].ID != "spec" || docs[0].Content != "v2" {
		t.Fatalf("carol should see exactly the public doc, got %s", rec.Body)
	}

	// The audit trail is itself access controlled and shows denials.
	step("outsider cannot read audit", "GET", "/documents/spec/audit", "carol", "", 403)
	rec = step("owner reads audit", "GET", "/documents/spec/audit", "bob", "", 200)
	for _, want := range []string{"user:carol", "denied", "document.share", "document.update"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("audit trail missing %q: %s", want, rec.Body)
		}
	}

	step("non-owner cannot delete", "DELETE", "/documents/spec", "carol", "", 403)
	step("delete", "DELETE", "/documents/spec", "bob", "", 204)
	// All tuples went with it: not even the old public share grants access.
	step("gone", "GET", "/documents/spec", "bob", "", 403)
	step("gone for public", "GET", "/documents/spec", "carol", "", 403)
}
