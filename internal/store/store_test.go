package store

import (
	"context"
	"errors"
	"testing"
)

func TestStore(t *testing.T) {
	ctx := context.Background()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.CreateUser(ctx, "alice", "hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, "alice", "hash"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate user: %v", err)
	}
	if _, err := s.PasswordHash(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}

	d := Document{ID: "d1", Folder: "f", Owner: "user:alice", Title: "t", Content: "c"}
	if _, err := s.CreateDocument(ctx, d); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateDocument(ctx, d); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate doc: %v", err)
	}
	if _, err := s.UpdateDocument(ctx, "d1", "t2", "c2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateDocument(ctx, "zzz", "", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	got, err := s.ListDocuments(ctx, []string{"d1", "nope"})
	if err != nil || len(got) != 1 || got[0].Title != "t2" {
		t.Fatalf("list: %v %v", got, err)
	}
	if err := s.DeleteDocument(ctx, "d1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetDocument(ctx, "d1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}

	_ = s.AddAudit(ctx, AuditEntry{Actor: "user:a", Action: "x", Object: "document:d1", Outcome: "allowed"})
	_ = s.AddAudit(ctx, AuditEntry{Actor: "user:b", Action: "y", Object: "document:d1", Outcome: "denied"})
	entries, err := s.ListAudit(ctx, "document:d1", 10)
	if err != nil || len(entries) != 2 || entries[0].Action != "y" {
		t.Fatalf("audit: %v %v", entries, err)
	}
}
