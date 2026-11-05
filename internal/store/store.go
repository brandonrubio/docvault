// Package store is the application database (SQLite): accounts, document
// contents and the audit log. Who may access what lives in OpenFGA, not here.
package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, no cgo
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("already exists")
)

type Document struct {
	ID        string    `json:"id"`
	Folder    string    `json:"folder"`
	Owner     string    `json:"owner"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type AuditEntry struct {
	ID      int64     `json:"id"`
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Object  string    `json:"object"`
	Outcome string    `json:"outcome"`
}

type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
  id         TEXT PRIMARY KEY,
  folder     TEXT NOT NULL,
  owner      TEXT NOT NULL,
  title      TEXT NOT NULL,
  content    TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts      INTEGER NOT NULL,
  actor   TEXT NOT NULL,
  action  TEXT NOT NULL,
  object  TEXT NOT NULL,
  outcome TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_object ON audit_log(object, id);
`

// Open opens (and migrates) a database. Use ":memory:" for tests.
func Open(path string) (*Store, error) {
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite is single-writer; also keeps :memory: on one connection
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func conflict(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return ErrConflict
	}
	return err
}

// ---- users ----

func (s *Store) CreateUser(ctx context.Context, id, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(id, password_hash, created_at) VALUES(?,?,?)`,
		id, passwordHash, time.Now().Unix())
	return conflict(err)
}

func (s *Store) PasswordHash(ctx context.Context, id string) (string, error) {
	var h string
	err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id=?`, id).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return h, err
}

// ---- documents ----

// CreateDocument inserts a document; the primary key makes ID reservation atomic.
func (s *Store) CreateDocument(ctx context.Context, d Document) (Document, error) {
	now := time.Now().UTC().Truncate(time.Second)
	d.CreatedAt, d.UpdatedAt = now, now
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO documents(id, folder, owner, title, content, created_at, updated_at) VALUES(?,?,?,?,?,?,?)`,
		d.ID, d.Folder, d.Owner, d.Title, d.Content, now.Unix(), now.Unix())
	return d, conflict(err)
}

const docCols = `id, folder, owner, title, content, created_at, updated_at`

func scanDoc(row interface{ Scan(...any) error }) (Document, error) {
	var d Document
	var c, u int64
	if err := row.Scan(&d.ID, &d.Folder, &d.Owner, &d.Title, &d.Content, &c, &u); err != nil {
		return d, err
	}
	d.CreatedAt, d.UpdatedAt = time.Unix(c, 0).UTC(), time.Unix(u, 0).UTC()
	return d, nil
}

func (s *Store) GetDocument(ctx context.Context, id string) (Document, error) {
	d, err := scanDoc(s.db.QueryRowContext(ctx, `SELECT `+docCols+` FROM documents WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

func (s *Store) UpdateDocument(ctx context.Context, id, title, content string) (Document, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE documents SET title=?, content=?, updated_at=? WHERE id=?`,
		title, content, time.Now().Unix(), id)
	if err != nil {
		return Document{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Document{}, ErrNotFound
	}
	return s.GetDocument(ctx, id)
}

func (s *Store) DeleteDocument(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM documents WHERE id=?`, id)
	return err
}

// ListDocuments returns the documents with the given ids, ordered by id.
func (s *Store) ListDocuments(ctx context.Context, ids []string) ([]Document, error) {
	out := []Document{}
	if len(ids) == 0 {
		return out, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	q := `SELECT ` + docCols + ` FROM documents WHERE id IN (?` + strings.Repeat(",?", len(ids)-1) + `) ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		d, err := scanDoc(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---- audit ----

func (s *Store) AddAudit(ctx context.Context, e AuditEntry) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_log(ts, actor, action, object, outcome) VALUES(?,?,?,?,?)`,
		time.Now().Unix(), e.Actor, e.Action, e.Object, e.Outcome)
	return err
}

// ListAudit returns the most recent entries for an object, newest first.
func (s *Store) ListAudit(ctx context.Context, object string, limit int) ([]AuditEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ts, actor, action, object, outcome FROM audit_log WHERE object=? ORDER BY id DESC LIMIT ?`,
		object, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Object, &e.Outcome); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}
