// Package api is the HTTP layer. Authentication yields a verified identity;
// every protected route then asks the authorization service a Check question
// before touching data. The application contains no role logic of its own.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/example/docvault/internal/auth"
	"github.com/example/docvault/internal/authz"
	"github.com/example/docvault/internal/store"
)

type ctxKey struct{}

var (
	idRe      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	subjectRe = regexp.MustCompile(`^(user:([A-Za-z0-9_-]{1,64}|\*)|team:[A-Za-z0-9_-]{1,64}#member)$`)
)

type Deps struct {
	Authz authz.Authorizer
	Store *store.Store
	Auth  *auth.Service
	Log   *slog.Logger
	// LoginLimiter throttles login attempts per client+username. Optional.
	LoginLimiter *auth.Limiter
}

type Server struct {
	Deps
}

func NewServer(d Deps) *Server {
	if d.LoginLimiter == nil {
		d.LoginLimiter = auth.NewLimiter(10, time.Minute)
	}
	return &Server{Deps: d}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	mux.HandleFunc("POST /auth/signup", s.signup)
	mux.HandleFunc("POST /auth/login", s.login)
	mux.HandleFunc("GET /me", s.me)

	mux.HandleFunc("POST /orgs", s.createOrg)
	mux.HandleFunc("POST /orgs/{org}/members", s.addOrgMember)
	mux.HandleFunc("POST /orgs/{org}/teams", s.createTeam)
	mux.HandleFunc("POST /orgs/{org}/folders", s.createFolder)
	mux.HandleFunc("POST /teams/{team}/members", s.addTeamMember)

	mux.HandleFunc("POST /folders/{folder}/documents", s.createDocument)
	mux.HandleFunc("GET /documents", s.listDocuments)
	mux.HandleFunc("GET /documents/{id}", s.getDocument)
	mux.HandleFunc("PUT /documents/{id}", s.updateDocument)
	mux.HandleFunc("DELETE /documents/{id}", s.deleteDocument)
	mux.HandleFunc("POST /documents/{id}/shares", s.share)
	mux.HandleFunc("DELETE /documents/{id}/shares", s.unshare)
	mux.HandleFunc("GET /documents/{id}/audit", s.documentAudit)

	return s.logRequests(s.authenticate(mux))
}

// ---- middleware & helpers --------------------------------------------------

var publicRoutes = map[string]bool{
	"GET /healthz":      true,
	"POST /auth/signup": true,
	"POST /auth/login":  true,
}

// authenticate verifies the bearer token and stores "user:<sub>" in the context.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicRoutes[r.Method+" "+r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		tok, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !found {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		sub, err := s.Auth.Verify(tok)
		if err != nil || !idRe.MatchString(sub) {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeErr(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, "user:"+sub)))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		s.Log.Info("request", "method", r.Method, "path", r.URL.Path, "status", sw.status,
			"actor", caller(r), "ms", time.Since(start).Milliseconds())
	})
}

// caller returns "user:<id>" for authenticated requests, "" otherwise.
func caller(r *http.Request) string {
	v, _ := r.Context().Value(ctxKey{}).(string)
	return v
}

// audit records a security-relevant event. Failure to audit is logged, not fatal.
func (s *Server) audit(ctx context.Context, actor, action, object, outcome string) {
	err := s.Store.AddAudit(ctx, store.AuditEntry{Actor: actor, Action: action, Object: object, Outcome: outcome})
	if err != nil {
		s.Log.Error("audit write failed", "err", err)
	}
}

// require asks the authorization service whether the caller has `relation` on
// `object`. It writes the error response itself and returns false on denial.
func (s *Server) require(w http.ResponseWriter, r *http.Request, relation, object string) bool {
	ok, err := s.Authz.Check(r.Context(), caller(r), relation, object)
	if err != nil {
		s.Log.Error("authorization check failed", "err", err, "relation", relation, "object", object)
		writeErr(w, http.StatusBadGateway, "authorization service unavailable") // fail closed
		return false
	}
	if !ok {
		s.audit(r.Context(), caller(r), relation, object, "denied")
		writeErr(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func validID(w http.ResponseWriter, id string) bool {
	if !idRe.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "ids must match [A-Za-z0-9_-]{1,64}")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *Server) upstream(w http.ResponseWriter, err error) {
	s.Log.Error("authorization backend error", "err", err)
	writeErr(w, http.StatusBadGateway, "authorization service unavailable")
}

func (s *Server) dbError(w http.ResponseWriter, err error) {
	s.Log.Error("database error", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

// ---- organizations, teams, folders ------------------------------------------

type idBody struct {
	ID string `json:"id"`
}

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request) {
	var b idBody
	if !decode(w, r, &b) || !validID(w, b.ID) {
		return
	}
	obj := "organization:" + b.ID
	if taken, err := s.Authz.Exists(r.Context(), obj, "owner"); err != nil {
		s.upstream(w, err)
		return
	} else if taken {
		writeErr(w, http.StatusConflict, "organization already exists")
		return
	}
	if err := s.Authz.Write(r.Context(), authz.Tuple{User: caller(r), Relation: "owner", Object: obj}); err != nil {
		s.upstream(w, err)
		return
	}
	s.audit(r.Context(), caller(r), "organization.create", obj, "ok")
	writeJSON(w, http.StatusCreated, map[string]string{"id": b.ID, "owner": caller(r)})
}

type memberBody struct {
	User string `json:"user"`
	Role string `json:"role"` // organization: member|admin|owner
}

func (s *Server) addOrgMember(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("org")
	var b memberBody
	if !validID(w, org) || !decode(w, r, &b) || !validID(w, b.User) {
		return
	}
	if b.Role != "member" && b.Role != "admin" && b.Role != "owner" {
		writeErr(w, http.StatusBadRequest, "role must be member, admin or owner")
		return
	}
	obj := "organization:" + org
	if !s.require(w, r, "can_manage_members", obj) {
		return
	}
	// Only owners may mint more owners.
	if b.Role == "owner" && !s.require(w, r, "owner", obj) {
		return
	}
	if err := s.Authz.Write(r.Context(), authz.Tuple{User: "user:" + b.User, Relation: b.Role, Object: obj}); err != nil {
		s.upstream(w, err)
		return
	}
	s.audit(r.Context(), caller(r), "organization.add_member "+b.Role+" user:"+b.User, obj, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createTeam(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("org")
	var b idBody
	if !validID(w, org) || !decode(w, r, &b) || !validID(w, b.ID) {
		return
	}
	if !s.require(w, r, "can_manage_teams", "organization:"+org) {
		return
	}
	obj := "team:" + b.ID
	if taken, err := s.Authz.Exists(r.Context(), obj, "parent"); err != nil {
		s.upstream(w, err)
		return
	} else if taken {
		writeErr(w, http.StatusConflict, "team already exists")
		return
	}
	if err := s.Authz.Write(r.Context(), authz.Tuple{User: "organization:" + org, Relation: "parent", Object: obj}); err != nil {
		s.upstream(w, err)
		return
	}
	s.audit(r.Context(), caller(r), "team.create", obj, "ok")
	writeJSON(w, http.StatusCreated, map[string]string{"id": b.ID, "org": org})
}

func (s *Server) addTeamMember(w http.ResponseWriter, r *http.Request) {
	team := r.PathValue("team")
	var b struct {
		User string `json:"user"`
	}
	if !validID(w, team) || !decode(w, r, &b) || !validID(w, b.User) {
		return
	}
	obj := "team:" + team
	if !s.require(w, r, "admin", obj) {
		return
	}
	if err := s.Authz.Write(r.Context(), authz.Tuple{User: "user:" + b.User, Relation: "member", Object: obj}); err != nil {
		s.upstream(w, err)
		return
	}
	s.audit(r.Context(), caller(r), "team.add_member user:"+b.User, obj, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createFolder(w http.ResponseWriter, r *http.Request) {
	org := r.PathValue("org")
	var b idBody
	if !validID(w, org) || !decode(w, r, &b) || !validID(w, b.ID) {
		return
	}
	if !s.require(w, r, "can_create_folder", "organization:"+org) {
		return
	}
	obj := "folder:" + b.ID
	if taken, err := s.Authz.Exists(r.Context(), obj, "parent"); err != nil {
		s.upstream(w, err)
		return
	} else if taken {
		writeErr(w, http.StatusConflict, "folder already exists")
		return
	}
	err := s.Authz.Write(r.Context(),
		authz.Tuple{User: "organization:" + org, Relation: "parent", Object: obj},
		authz.Tuple{User: caller(r), Relation: "owner", Object: obj},
	)
	if err != nil {
		s.upstream(w, err)
		return
	}
	s.audit(r.Context(), caller(r), "folder.create", obj, "ok")
	writeJSON(w, http.StatusCreated, map[string]string{"id": b.ID, "org": org})
}

// ---- documents ----------------------------------------------------------------

type docBody struct {
	ID      string `json:"id,omitempty"`
	Title   string `json:"title"`
	Content string `json:"content"`
}

func (s *Server) createDocument(w http.ResponseWriter, r *http.Request) {
	folder := r.PathValue("folder")
	var b docBody
	if !validID(w, folder) || !decode(w, r, &b) || !validID(w, b.ID) {
		return
	}
	if !s.require(w, r, "can_create_document", "folder:"+folder) {
		return
	}
	// The primary key reserves the id atomically; grant access only afterwards.
	d, err := s.Store.CreateDocument(r.Context(), store.Document{
		ID: b.ID, Folder: folder, Owner: caller(r), Title: b.Title, Content: b.Content,
	})
	if err == store.ErrConflict {
		writeErr(w, http.StatusConflict, "document already exists")
		return
	} else if err != nil {
		s.dbError(w, err)
		return
	}
	obj := "document:" + b.ID
	err = s.Authz.Write(r.Context(),
		authz.Tuple{User: "folder:" + folder, Relation: "parent", Object: obj},
		authz.Tuple{User: caller(r), Relation: "owner", Object: obj},
	)
	if err != nil {
		_ = s.Store.DeleteDocument(r.Context(), b.ID) // compensate so the id is not stranded
		s.upstream(w, err)
		return
	}
	s.audit(r.Context(), caller(r), "document.create", obj, "ok")
	writeJSON(w, http.StatusCreated, d)
}

func (s *Server) getDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(w, id) || !s.require(w, r, "can_view", "document:"+id) {
		return
	}
	d, err := s.Store.GetDocument(r.Context(), id)
	if err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		s.dbError(w, err)
		return
	}
	s.audit(r.Context(), caller(r), "document.read", "document:"+id, "ok")
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) updateDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var b docBody
	if !validID(w, id) || !s.require(w, r, "can_edit", "document:"+id) || !decode(w, r, &b) {
		return
	}
	d, err := s.Store.UpdateDocument(r.Context(), id, b.Title, b.Content)
	if err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		s.dbError(w, err)
		return
	}
	s.audit(r.Context(), caller(r), "document.update", "document:"+id, "ok")
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) deleteDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(w, id) || !s.require(w, r, "can_delete", "document:"+id) {
		return
	}
	_, err := s.Store.GetDocument(r.Context(), id)
	if err == store.ErrNotFound {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		s.dbError(w, err)
		return
	}
	if err := s.Store.DeleteDocument(r.Context(), id); err != nil {
		s.dbError(w, err)
		return
	}
	// Remove every tuple on the document (parent, owner and all shares) so no
	// access can outlive it and a recycled id starts clean.
	err = s.Authz.DeleteObject(r.Context(), "document:"+id)
	if err != nil {
		s.upstream(w, err)
		return
	}
	s.audit(r.Context(), caller(r), "document.delete", "document:"+id, "ok")
	w.WriteHeader(http.StatusNoContent)
}

// listDocuments shows the "reverse lookup" side of relationship-based access
// control: instead of checking each document, ask which ones the caller can view.
func (s *Server) listDocuments(w http.ResponseWriter, r *http.Request) {
	objs, err := s.Authz.ListObjects(r.Context(), caller(r), "can_view", "document")
	if err != nil {
		s.upstream(w, err)
		return
	}
	ids := make([]string, 0, len(objs))
	for _, o := range objs {
		ids = append(ids, strings.TrimPrefix(o, "document:"))
	}
	docs, err := s.Store.ListDocuments(r.Context(), ids)
	if err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, docs)
}

// documentAudit lets anyone who can manage sharing see who touched a document.
func (s *Server) documentAudit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID(w, id) || !s.require(w, r, "can_share", "document:"+id) {
		return
	}
	entries, err := s.Store.ListAudit(r.Context(), "document:"+id, 100)
	if err != nil {
		s.dbError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// ---- sharing ------------------------------------------------------------------

type shareBody struct {
	Subject string `json:"subject"` // user:bob | user:* | team:eng#member
	Role    string `json:"role"`    // viewer | editor
}

func (s *Server) parseShare(w http.ResponseWriter, r *http.Request) (t authz.Tuple, ok bool) {
	id := r.PathValue("id")
	var b shareBody
	if !validID(w, id) || !decode(w, r, &b) {
		return
	}
	if !subjectRe.MatchString(b.Subject) {
		writeErr(w, http.StatusBadRequest, "subject must be user:<id>, user:* or team:<id>#member")
		return
	}
	if b.Role != "viewer" && b.Role != "editor" {
		writeErr(w, http.StatusBadRequest, "role must be viewer or editor")
		return
	}
	// Public (wildcard) write access is never allowed.
	if b.Subject == "user:*" && b.Role != "viewer" {
		writeErr(w, http.StatusBadRequest, "only viewer can be granted to user:*")
		return
	}
	obj := "document:" + id
	if !s.require(w, r, "can_share", obj) {
		return
	}
	return authz.Tuple{User: b.Subject, Relation: b.Role, Object: obj}, true
}

func (s *Server) share(w http.ResponseWriter, r *http.Request) {
	t, ok := s.parseShare(w, r)
	if !ok {
		return
	}
	if err := s.Authz.Write(r.Context(), t); err != nil {
		s.upstream(w, err)
		return
	}
	s.audit(r.Context(), caller(r), "document.share "+t.Relation+" "+t.User, t.Object, "ok")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) unshare(w http.ResponseWriter, r *http.Request) {
	t, ok := s.parseShare(w, r)
	if !ok {
		return
	}
	if err := s.Authz.Delete(r.Context(), t); err != nil {
		s.upstream(w, err)
		return
	}
	s.audit(r.Context(), caller(r), "document.unshare "+t.Relation+" "+t.User, t.Object, "ok")
	w.WriteHeader(http.StatusNoContent)
}
