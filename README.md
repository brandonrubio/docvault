# DocVault

A multi-tenant document platform written in Go: accounts and token-based login, organizations/teams/folders/documents, fine-grained sharing, and a per-document audit trail. Authentication is handled in the app; **authorization is delegated to [OpenFGA](https://openfga.dev)** (relationship-based access control, as in Google Zanzibar), so there are no role tables or `if user.isAdmin` checks anywhere in the code.

```
            ┌────────────────────────── DocVault (Go) ──────────────────────────┐
 client ──▶ │ auth: bcrypt + JWT ─▶ api: handlers ─▶ store: SQLite               │
            │                           │            (users, documents, audit)   │
            └───────────────────────────┼───────────────────────────────────────┘
                                        ▼  Check / ListObjects / Write
                                   OpenFGA ──▶ Postgres   (who can do what)
```

## Features

**Identity**
- Signup / login with bcrypt-hashed passwords (10–72 bytes enforced), short-lived HS256 JWT access tokens
- Token verification pins the algorithm, issuer and expiry (tampered, forged, expired and `alg: none` tokens are rejected, and tested)
- Login hardening: identical responses for unknown user vs. wrong password, constant-time-ish dummy hash for unknown users, sliding-window rate limit per client and username (429 + `Retry-After`)

**Access control (OpenFGA)**
- Authorization model in the OpenFGA DSL: [`internal/authz/model.fga`](internal/authz/model.fga)
- Org roles with a hierarchy (`owner → admin → member`), teams, folders, documents
- Inheritance through the resource tree (org admins can edit everything below the org; folder editors can edit its documents)
- Group sharing via usersets (`team:platform#member`) and public links via a type-bound wildcard (`user:*`, read-only)
- `Check` on every request; `ListObjects` to answer "what can I see?" without N+1 checks
- Fails closed: if the authorization service is unreachable the answer is 502, never "allow"
- Model unit tests in the OpenFGA CLI format: [`model.fga.yaml`](internal/authz/model.fga.yaml)

**Data integrity & operations**
- Document IDs are reserved atomically by the database primary key *before* any access is granted; if granting fails the row is rolled back
- Deleting a document deletes **every** tuple on it (ownership, parent link, all shares), so nothing outlives the resource
- Audit trail of logins, creates, edits, shares, reads and *denied* attempts, readable by anyone who can share the document (itself an authorization check)
- Strict input validation on all identifiers and share subjects, so callers cannot inject `#`, `:` or `*` into authorization tuples
- Structured JSON request logging, graceful shutdown, health endpoint

## Run it

Requires Docker (and Go 1.26+ if you want to run the code outside a container).

```bash
docker compose up -d --build     # app on :8081, OpenFGA on :8080 (Playground :3000), Postgres
```

```bash
B=localhost:8081; J='-H Content-Type:application/json'
curl -XPOST $B/auth/signup $J -d '{"username":"alice","password":"correct horse battery"}'
TOKEN=$(curl -s -XPOST $B/auth/login $J -d '{"username":"alice","password":"correct horse battery"}' | jq -r .access_token)
AUTH="Authorization: Bearer $TOKEN"

curl -XPOST $B/orgs $J -H "$AUTH" -d '{"id":"acme"}'
curl -XPOST $B/orgs/acme/folders $J -H "$AUTH" -d '{"id":"eng"}'
curl -XPOST $B/folders/eng/documents $J -H "$AUTH" -d '{"id":"spec","title":"Spec","content":"hello"}'
curl -XPOST $B/documents/spec/shares $J -H "$AUTH" -d '{"subject":"user:carol","role":"viewer"}'
curl $B/documents/spec/audit -H "$AUTH"
```

Set a real `JWT_SECRET` (`openssl rand -base64 48`) outside local development; the compose file ships a dev-only value, and without any secret the server generates an ephemeral one and logs a warning.

## Tests

```bash
make up            # OpenFGA only (needed by the end-to-end test)
make test-docker   # all Go tests in a container (or `make test` if Go is installed)
make model-test    # authorization-model tests via the official OpenFGA CLI image
```

| Layer | What is covered |
|---|---|
| `internal/auth` | token round trip; wrong key / issuer, expired, tampered, `alg: none`, short secret; passwords; rate limiter |
| `internal/store` | uniqueness conflicts, CRUD, `IN` queries, audit ordering |
| `internal/api` (unit) | 401 paths, denials are audited, share validation (no public write, only `#member` usersets), owner-only owner minting, rollback when granting fails, signup/login incl. enumeration resistance and 429 |
| `internal/api` (end to end) | real signup/login + SQLite + a real OpenFGA server: org/folder/doc lifecycle, team sharing, revocation, public link, `ListObjects`, audit access control, delete leaves no residual access |
| model tests | 21 `Check` and 2 `ListObjects` assertions over the authorization model |

## API

| Method & path | Authorization |
|---|---|
| `POST /auth/signup`, `POST /auth/login` | public (login is rate limited) |
| `GET /me` | any valid token |
| `POST /orgs` | any user; becomes owner |
| `POST /orgs/{org}/members` | `can_manage_members` (`owner` role requires `owner`) |
| `POST /orgs/{org}/teams` | `can_manage_teams` |
| `POST /teams/{team}/members` | team `admin` |
| `POST /orgs/{org}/folders` | `can_create_folder` |
| `POST /folders/{folder}/documents` | `can_create_document` |
| `GET /documents` | filtered by `ListObjects(can_view)` |
| `GET` / `PUT` / `DELETE /documents/{id}` | `can_view` / `can_edit` / `can_delete` |
| `POST` / `DELETE /documents/{id}/shares` | `can_share` |
| `GET /documents/{id}/audit` | `can_share` |

## Layout

```
cmd/server        entrypoint and wiring
internal/auth     passwords, JWTs, rate limiter
internal/authz    OpenFGA client wrapper, model + model tests
internal/store    SQLite persistence
internal/api      HTTP handlers and middleware
.devcontainer     VS Code dev container (Go + OpenFGA)
```

## Known limitations

- Single-node SQLite and HS256 with a shared secret; a larger deployment would use Postgres and asymmetric keys (RS256/EdDSA) with key rotation, plus refresh tokens and logout/revocation.
- No email verification, MFA or password reset.
- The login rate limiter is in memory and keyed on the socket address; behind a proxy it needs trusted `X-Forwarded-For` handling and a shared store.
- Orgs, folders and teams exist only as OpenFGA tuples, and their creation does a check-then-write that is not atomic. Documents (which have a database row) do not have this race.
- Natural extensions: OpenFGA conditions (time-boxed or IP-restricted grants), `ListUsers` for "who has access" screens, batch checks, pinning the model ID.
