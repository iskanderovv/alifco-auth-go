# Testing

## Approach

The guarantees this service makes are mostly database behaviour: an atomic update that only one request can win, unique indexes that decide races, a row lock. A mock cannot show any of them, so the tests that matter run against a real PostgreSQL and replace only the outside world.

| Layer | What it covers | Needs |
|---|---|---|
| Unit | Configuration rules, PKCE (against the RFC 7636 vector), hashing, UUID checks, the JWKS cache, and the Google, Facebook and Telegram adapters with local fake servers | nothing |
| Integration | Services and the whole HTTP flow with a real database and fake providers: rotation, reuse, state, linking, concurrency, CORS, rate limits, error format, the OpenAPI document, log content | PostgreSQL |
| Manual, real providers | Each login flow with a real account, including linking | provider apps and a tunnel |
| Load | Throughput and the parallel-refresh guarantee | a running instance |

No automated test calls Google, Facebook or Telegram. `id_token`s are signed in the test with a key pair generated there, and the key endpoint is a local `httptest` server.

Each test that needs a database gets its own throwaway schema (`internal/testutil`), created and dropped around the test, so tests and packages never share rows and can run in parallel. A test skips when no database is reachable.

## Numbers

| | Count |
|---|---|
| Tests | 49 |
| Test cases including subtests | 117 |

```bash
make test      # go test -race -count=1 ./...
make check     # lint and tests
```

`TEST_DATABASE_URL` points at a PostgreSQL the tests may create schemas in. The default is `postgresql://oauth:oauth@localhost:5432/oauth_test`. CI runs format, vet, golangci-lint, the tests with the race detector and the build on every push.

## What the tests are meant to catch

- **Races.** Two concurrent callbacks, concurrent first logins, concurrent refreshes of one token, concurrent unlinks, and an unlink that must wait for a held row lock. Each test starts the competing calls together and asserts that exactly one wins and the data stays consistent.
- **Replay and forgery.** State reuse, wrong provider, expired transaction, forged `state`, an `id_token` with another algorithm (`HS256`, `none`), issuer, audience or key, a key id that does not exist.
- **Leaks.** Provider response bodies and `error_description` must not reach an error or a URL. Secrets must not be in a request URL. Tokens, cookies, `code` and `state` must not be in the log.
- **The linking rules.** No merge by email, `identity_taken`, `already_linked`, the last provider cannot be removed.

## Checking that the tests can fail

A test that has never failed proves little, so each important guarantee was checked by breaking the code on purpose and watching a test fail:

| Mutation | Test that failed |
|---|---|
| Ignore the unique-violation fallback in `Login` | `TestLosingTheFirstLoginRaceLogsInTheWinner` |
| Remove `FOR UPDATE` from `Unlink` | `TestUnlinkHoldsTheUserLock` |
| Let rotation match an already revoked token | `TestRefreshRotation`, `TestParallelRefreshHasExactlyOneWinner` |
| Stop binding a callback to its provider | `TestConsumeRejects` |
| Log the full request URI including the query | `TestAccessLogLeaksNothing` |

Two of these changed the tests. The first version of the first-login race test fired fifteen goroutines and still passed with the fallback removed, because the race window was too small to hit reliably. It was replaced by a deterministic test that creates the identity first and then runs the losing path (`TestLosingTheFirstLoginRaceLogsInTheWinner`); the concurrent test stays as a second line of defence. The lock test used to hang forever when the guarantee was broken, because its helper transaction was never released, and now cleans up on failure.

## Real providers

The NestJS version was exercised with real accounts against real apps through a public tunnel (Telegram refuses `http://localhost`): Google, Facebook and Telegram login, refresh, `/me`, linking and unlinking, including the refusal when an account already has its own profile. Those runs found two bugs the automated tests could not: Telegram's gzip answer to the key request, and picture links that expire. Both are covered by tests here (`TestJWKS` reads a gzip answer, `TestAvatarFollowsLatestLoginButNameDoesNot`).

## Load test

`make stress` (`cmd/stress`) seeds a user and sessions into a `*_test` database (it refuses any other name) and runs the scenarios against a running instance, then fires 100 parallel refreshes of one token. Start the server with `RATE_LIMIT_OFF=true` and the same `JWT_SECRET`. The client does not follow redirects. On a laptop, 50 connections, 8 seconds each:

| Scenario | Result |
|---|---|
| `GET /health` | about 68,600 req/s, p99 1.6 ms |
| `GET /me` (JWT check and a query) | about 21,200 req/s, p99 3.0 ms |
| `POST /auth/refresh`, 300 sessions | all 200 |
| `GET /auth/google` (writes a row) | about 21,800 req/s |
| Callback with a wrong state | about 62,000 req/s |
| 100 parallel refreshes of one token | exactly one 200, 99 rejected, no token left active |

Errors and timeouts were zero in every scenario.

## Not covered

- The picture links are not fetched, so an expired link is not detected by the service. The frontend falls back to the initial when the image fails to load.
- The frontend has its own tests in the [react-auth](https://github.com/iskanderovv/react-auth) project. No test drives a real provider login through a browser.
- Nothing tests more than one instance of the service. The in-memory rate limiter assumes one.
- The OpenAPI document is hand-written. A test checks that every route is listed, not that every schema is exact.
