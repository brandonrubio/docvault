package main

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/docvault/internal/api"
	"github.com/example/docvault/internal/auth"
	"github.com/example/docvault/internal/authz"
	"github.com/example/docvault/internal/store"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Tokens: JWT_SECRET must be set in any real deployment. Without it we
	// generate a throwaway key, which invalidates all tokens on restart.
	secret := []byte(os.Getenv("JWT_SECRET"))
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			log.Error("cannot generate secret", "err", err)
			os.Exit(1)
		}
		log.Warn("JWT_SECRET not set; using an ephemeral signing key")
	}
	tokens, err := auth.NewService(secret, "docvault", time.Hour)
	if err != nil {
		log.Error("auth setup", "err", err)
		os.Exit(1)
	}

	db, err := store.Open(env("DB_PATH", "docvault.db"))
	if err != nil {
		log.Error("open database", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	cfg := authz.Config{
		APIURL:  env("OPENFGA_API_URL", "http://localhost:8080"),
		StoreID: os.Getenv("OPENFGA_STORE_ID"),
	}
	// The authorization service may still be starting (e.g. under docker compose): retry.
	var fga *authz.Client
	for attempt := 1; attempt <= 15; attempt++ {
		fga, err = authz.New(ctx, cfg)
		if err == nil {
			break
		}
		log.Warn("authorization service not ready", "attempt", attempt, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	if err != nil {
		log.Error("giving up connecting to authorization service", "err", err)
		os.Exit(1)
	}
	log.Info("authorization ready", "store_id", fga.StoreID, "model_id", fga.ModelID)

	srv := &http.Server{
		Addr:              env("ADDR", ":8081"),
		Handler:           api.NewServer(api.Deps{Authz: fga, Store: db, Auth: tokens, Log: log}).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()

	log.Info("listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
}
