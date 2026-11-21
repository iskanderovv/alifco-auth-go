# OAuth service (Go)

Sign in with Google, Facebook and Telegram. Go, PostgreSQL, pgx.
A user can link several providers to one profile. Sessions are a short-lived access JWT plus a rotating refresh token in an httpOnly cookie.

This is the Go rewrite of the [NestJS version](https://github.com/iskanderovv/alifco-auth). The schema, endpoints, token rules and error codes are identical.

## Design

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): components, flows and the decisions with the alternatives considered
- [docs/DATABASE.md](docs/DATABASE.md): the schema, its constraints and why (also as [DBML](docs/schema.dbml))
- [docs/SECURITY.md](docs/SECURITY.md): threats, mitigations, and the tests that show them
- [docs/TESTING.md](docs/TESTING.md): test strategy, mutation checks, load test results

## Quick start

```bash
cp .env.example .env              # set JWT_SECRET (see below)
docker compose up -d postgres
make run                          # http://localhost:3000
```

```bash
openssl rand -base64 64           # JWT_SECRET
```

`MIGRATE_ON_START=true` applies the migrations when the server starts. With `DEV_SPA=true` the server also serves a small sign-in page at `/`, so one address is enough to try everything by hand.

API documentation is at `/docs`. Set `SWAGGER_USER` and `SWAGGER_PASSWORD` to protect it with a browser login.

A provider is enabled only when both of its variables are set. The service starts with any subset.

| Provider | Variables | Redirect URI to register |
|---|---|---|
| Google | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | `<API_BASE_URL>/auth/google/callback` |
| Facebook | `FACEBOOK_APP_ID`, `FACEBOOK_APP_SECRET` | `<API_BASE_URL>/auth/facebook/callback` |
| Telegram | `TELEGRAM_CLIENT_ID`, `TELEGRAM_CLIENT_SECRET` | `<API_BASE_URL>/auth/telegram/callback` |

Facebook: request `public_profile` and `email`; the app can stay in development mode.
Telegram: in BotFather open the bot, Login Widget, and switch to OpenID Connect. The values shown there are the client id and secret.

Telegram only accepts https redirect URIs, so locally it needs a tunnel. With `DEV_SPA=true` one tunnel is enough:

```bash
cloudflared tunnel --url http://localhost:3000
API_BASE_URL=https://<tunnel> FRONTEND_URL=https://<tunnel> COOKIE_SECURE=true make run
```

## Configuration

`internal/config` validates everything at startup and names every bad variable without printing its value. See `.env.example`.

| Variable | Default | |
|---|---|---|
| `API_BASE_URL`, `FRONTEND_URL` | `http://localhost:3000`, `http://localhost:5173` | Callback URLs are built from `API_BASE_URL`, never from the request. `FRONTEND_URL` is the CORS origin and the redirect target |
| `DATABASE_URL` | | Add `?search_path=<schema>` to use a schema other than `public` |
| `JWT_SECRET` | | At least 32 characters |
| `JWT_ACCESS_TTL`, `REFRESH_TTL_DAYS` | `15m`, `30` | |
| `COOKIE_SECURE`, `COOKIE_SAME_SITE` | `false`, `lax` | `none` needs `COOKIE_SECURE=true`. Production refuses insecure values |
| `FACEBOOK_GRAPH_VERSION` | `v25.0` | |
| `HTTP_TIMEOUT_MS`, `BODY_LIMIT_BYTES` | `5000`, `10240` | |
| `MIGRATE_ON_START`, `DEV_SPA`, `RATE_LIMIT_OFF` | `false` | `RATE_LIMIT_OFF` is for load tests and is refused in production |

## API

Every error is `{ "error": { "code": "...", "message": "..." } }`. The codes are stable.

| Method | Path | Auth | |
|---|---|---|---|
| GET | `/auth/{provider}` | | Start a login (redirect to the provider) |
| GET | `/auth/{provider}/callback` | | Redirects to `FRONTEND_URL`, with `?error=<code>` on failure (404 for an unknown provider) |
| POST | `/auth/refresh` | cookie | New access token, rotated cookie |
| POST | `/auth/logout` | cookie | Revokes the session. Always 204 |
| GET | `/me` | Bearer | Profile and linked providers |
| POST | `/auth/link/{provider}` | Bearer | Returns the provider URL to navigate to |
| DELETE | `/auth/link/{provider}` | Bearer | Unlink. The last provider cannot be removed |
| GET | `/health` | | Liveness, no database call |

`refresh` and `logout` also need the header `X-Requested-With: fetch`, and the `Origin` header, when present, must equal `FRONTEND_URL`. Rate limits per client: 20 per minute on `/auth/*`, 10 on refresh, 60 elsewhere, `/health` exempt.

## How it works

```
SPA -> GET /auth/google ----------------> sets oauth_tx cookie, 302 to Google
Google -> GET /auth/google/callback ----> checks state, exchanges code (PKCE), verifies the profile,
                                          finds or creates the user, sets the refresh cookie,
                                          302 to FRONTEND_URL/auth/callback   (no token in the URL)
SPA -> POST /auth/refresh --------------> { accessToken }
SPA -> GET /me (Authorization: Bearer) -> profile
```

- **Access token**: HS256 JWT, 15 minutes, claims `sub`, `iss`, `aud`, `iat`, `exp` only. Keep it in memory.
- **Refresh token**: 32 random bytes, stored only as a SHA-256 hash. Each use revokes it and issues the next one in the same family with a single conditional `UPDATE`, so two concurrent uses cannot both succeed. Presenting a revoked token revokes the whole family. The SPA must send refresh calls one at a time: two tabs refreshing together will log the user out.
- **OAuth state**: random `state` and PKCE verifier are stored in the database (`oauth_transactions`, hashed state, 10 minutes, single use) and bound to the browser by a cookie holding only the row id.

## Decisions worth knowing

- Accounts are matched only by `(provider, provider_user_id)`, never by email. Facebook and Telegram do not prove an email, so matching on it would allow taking over an account by registering its address first. `users.email` is filled only when the provider verified it (Google) and is not unique.
- Linking is explicit: a logged-in user attaches another provider. It never touches the session. Unlink locks the user row (`SELECT ... FOR UPDATE`) so two concurrent unlinks cannot remove every sign-in method.
- Concurrent first logins are resolved by the unique index; the loser logs in the winner's user instead of creating a second one.
- Callback failures redirect with a code from a fixed allowlist. Provider messages never reach the URL, and provider response bodies never reach errors or logs.
- The access log records only method, path, status and duration.
- `id_token`s are verified against the provider's JWKS with the algorithm pinned to RS256 (Google, Telegram). The Telegram verifier assumes the BotFather default; do not change the signing algorithm there.
- Cookies are host-only, `HttpOnly`, `SameSite=Lax`, path `/auth`, and cleared with the same options they were set with. The SPA and the API are assumed to share a site.

## Tests

```bash
make check           # golangci-lint and go test -race
```

The tests need a PostgreSQL. Each test creates and drops its own schema in the database named by `TEST_DATABASE_URL` (default `postgresql://oauth:oauth@localhost:5432/oauth_test`), so `docker compose up -d postgres` and one `CREATE DATABASE oauth_test` is all the setup. GitHub Actions runs format, vet, lint, the race-detector tests and the build on every push and pull request.

Providers are replaced by fakes, so no test calls Google, Facebook or Telegram. See [docs/TESTING.md](docs/TESTING.md) for what is covered, the mutation checks and the load test:

```bash
RATE_LIMIT_OFF=true PORT=3100 MIGRATE_ON_START=true JWT_SECRET=<32+ chars> \
  GOOGLE_CLIENT_ID=x GOOGLE_CLIENT_SECRET=x \
  DATABASE_URL='postgresql://oauth:oauth@localhost:5432/oauth_test?search_path=go_stress' make run
STRESS_DATABASE_URL='postgresql://oauth:oauth@localhost:5432/oauth_test?search_path=go_stress' \
  JWT_SECRET=<same> go run ./cmd/stress -url http://localhost:3100
```

## Docker

`docker build -t alifco-auth-go .` builds a static binary into a distroless, non-root image that applies the migrations on start. It needs the same environment variables as a normal start and a reachable PostgreSQL.

## Layout

See `CLAUDE.md` for the conventions and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for why the packages are split by responsibility and not by layer.

```
cmd/server        the binary: wiring only
cmd/stress        load test
internal/config   environment validation
internal/apperr   client-facing errors
internal/store    SQL over pgx
internal/token    access and refresh tokens
internal/oauthtx  state and PKCE transactions
internal/provider one adapter per provider, shared OIDC helpers
internal/identity find or create, link, unlink
internal/httpapi  routes, middleware, handlers, OpenAPI, dev SPA
internal/db       pool and embedded migrations
```

## Not done, and known limits

- Expired `oauth_transactions` and `refresh_tokens` are never deleted. A cleanup job is needed before this runs for long.
- Refresh tokens expire after 30 days of the family's last rotation with no maximum session age.
- Profile picture URLs (Facebook, Telegram) are temporary links to the provider. The avatar is refreshed on every login, but between logins a stored link can stop working. The pictures are not copied to our own storage.
- The display name is set at sign-up and never rewritten by later logins.
- No account merging: an account that already has its own profile cannot be linked to another profile.
- Telegram never returns an email. Facebook returns one only on request, and it is kept on the identity but never trusted.
- The rate limiter is in memory, so it assumes one instance.
- No account deletion, no admin features.
