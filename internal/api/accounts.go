package api

import (
	"net"
	"net/http"

	"github.com/example/docvault/internal/auth"
	"github.com/example/docvault/internal/store"
)

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) signup(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if !decode(w, r, &c) || !validID(w, c.Username) {
		return
	}
	if len(c.Password) < auth.MinPasswordLen || len(c.Password) > auth.MaxPasswordLen {
		writeErr(w, http.StatusBadRequest, "password must be 10-72 bytes")
		return
	}
	hash, err := auth.HashPassword(c.Password)
	if err != nil {
		s.dbError(w, err)
		return
	}
	switch err := s.Store.CreateUser(r.Context(), c.Username, hash); err {
	case nil:
	case store.ErrConflict:
		writeErr(w, http.StatusConflict, "username already taken")
		return
	default:
		s.dbError(w, err)
		return
	}
	s.audit(r.Context(), "user:"+c.Username, "user.signup", "user:"+c.Username, "ok")
	writeJSON(w, http.StatusCreated, map[string]string{"username": c.Username})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if !decode(w, r, &c) {
		return
	}
	// Bad usernames get the same response as bad passwords.
	if !idRe.MatchString(c.Username) {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !s.LoginLimiter.Allow(ip + "|" + c.Username) {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "too many login attempts")
		return
	}

	actor := "user:" + c.Username
	hash, err := s.Store.PasswordHash(r.Context(), c.Username)
	if err == store.ErrNotFound {
		hash = s.Auth.DummyHash() // spend the same time as a real check
	} else if err != nil {
		s.dbError(w, err)
		return
	}
	if !auth.CheckPassword(hash, c.Password) || err == store.ErrNotFound {
		s.audit(r.Context(), actor, "user.login", actor, "denied")
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	token, exp, err := s.Auth.Issue(c.Username)
	if err != nil {
		s.dbError(w, err)
		return
	}
	s.audit(r.Context(), actor, "user.login", actor, "ok")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_at":   exp.UTC(),
	})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"user": caller(r)})
}
