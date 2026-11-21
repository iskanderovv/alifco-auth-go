# Conventions

Go 1.27, standard library first. The design (schema, flows, security rules) is shared with the NestJS version; see `docs/`.

## Layout

```
cmd/server        the binary: wiring only, no logic
cmd/stress        load test
internal/config   environment, validated once at startup
internal/apperr   the one error type that reaches the client
internal/store    SQL over pgx, one small method per query
internal/token    access JWT and rotating refresh tokens
internal/oauthtx  single-use login/link flows (state, PKCE verifier)
internal/provider Google, Facebook, Telegram behind one interface
internal/identity which user a verified profile belongs to
internal/httpapi  routes, middleware, handlers
internal/db       pool and embedded goose migrations
internal/testutil a throwaway schema per test
```

Dependencies point one way: `httpapi` uses the services, the services use `store`. Nothing in `internal/` imports `httpapi`.

## Rules

- Errors: services return `*apperr.Error` for anything the client may see, plain wrapped errors (`fmt.Errorf("...: %w", err)`) for the rest. Only `httpapi` turns them into responses.
- `context.Context` is the first parameter of anything that does I/O.
- Interfaces are defined where they are used and kept small. No interface without a second implementation or a test double.
- No global state. Constructors take their dependencies.
- SQL is parameterised. Rules that matter for correctness live in the database (unique indexes, conditional `UPDATE`, `FOR UPDATE`), not in application checks.
- Secrets are never logged and never put in a URL. Provider response bodies never reach an error message.
- Comments only for the reason behind something non-obvious. Names and structure carry the rest.
- Tests: table-driven where they share a shape, `-race` always, a real PostgreSQL for anything that depends on a constraint or a lock. A guarantee is only claimed once breaking it makes a test fail.

## Commands

```
make check    # lint and tests
make run      # needs a .env, see .env.example
```
