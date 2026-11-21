# Security

The threats I considered, what stops each one, where in the code it is stopped, and which test shows it. Anything that is not covered by an automated test is marked as such.

## What is protected

| Asset | Why it matters |
|---|---|
| User accounts | Taking one over gives access to everything behind the login |
| Refresh tokens | A 30 day session |
| Access tokens | A 15 minute session |
| `JWT_SECRET` | Whoever has it can issue tokens for any user |
| Provider secrets and the cookie secret | Impersonating the app, forging the `oauth_tx` cookie |
| Email, name, picture | Personal data |

## Trust boundaries

- **Browser to API.** Fully untrusted input: query strings, cookies, headers and bodies.
- **API to provider.** Identity claims are trusted only after they are verified. A provider's response body is never copied into an error or a log.
- **API to PostgreSQL.** Parameterised queries only. Every query, including the row lock, binds its values as parameters. SQL text is never built from input.
- **Environment.** Secrets live in the environment, never in the repository.

## Threats and mitigations

### Spoofing and account takeover

| Threat | Mitigation | Code | Evidence |
|---|---|---|---|
| **Pre-registration takeover.** An attacker signs up through Facebook with the victim's email, and the victim later signs in with Google and is merged into the attacker's account | Accounts are matched only by `(provider, provider_user_id)`. `users.email` is set only for a provider-verified email and is never used to find an account | `identity.Service.Login` | `TestNoMergeByEmail`, `TestUnverifiedEmailIsNotStoredOnTheUser` |
| A forged or substituted `id_token` | Signature checked against the provider's keys, algorithm pinned to RS256, `iss`, `aud` and `exp` checked, `sub` required | `provider/oidc.go` `verifyIDToken` | `TestGoogle`, `TestTelegram`: wrong audience, issuer, key, unknown `kid`, HS256, `alg: none`, no subject, expired |
| JWT forgery: `alg: none`, algorithm confusion | The verifier pins `HS256` and checks issuer, audience and expiry | `token.Service.VerifyAccess` | `TestVerifyAccessRejects`: `alg none`, `HS512`, another secret, wrong claims, no expiry, a subject that is not a uuid |
| Login CSRF: the victim is logged into the attacker's account | `state` is random, stored hashed, bound to the browser by the `oauth_tx` cookie, single use | `oauthtx.Service` | `TestConsumeRejects`, `TestCallbackAlwaysRedirectsWithASafeCode`: forged state, missing cookie, other provider, expired, replay |
| An intercepted authorization code | PKCE (S256) on every provider: the code is useless without the verifier | `provider/*.go` | Authorization URL and token request asserted in the provider tests; the PKCE challenge is checked against the RFC 7636 vector (`TestPKCEChallengeMatchesRFC7636`) |
| Replay of a callback | The transaction is consumed by one conditional `UPDATE`; a second use matches no row | `oauthtx.Service.Consume` | `TestConcurrentCallbacksHaveOneWinner` |

### Session theft and CSRF

| Threat | Mitigation | Code | Evidence |
|---|---|---|---|
| XSS steals the refresh token | `httpOnly` cookie. The access token lives only in memory and is never in `localStorage` | `httpapi/cookies.go` | `TestLoginRefreshMeLogout`: cookie flags |
| A stolen refresh token is used in parallel with the owner | Single-use rotation. Presenting an already used token revokes the whole family | `token.Service.Rotate` | `TestRefreshRotation`, `TestParallelRefreshHasExactlyOneWinner`, `TestRefreshReuseIsDetected`. Load test: 100 parallel refreshes of one token give exactly one success |
| CSRF on refresh and logout | `SameSite=Lax`, a custom header that forces a CORS preflight, an `Origin` check, a strict CORS allowlist | `csrf` and `cors` middleware | `TestCSRFProtection`, `TestCORS` |
| Tokens in URLs, history or `Referer` | The callback redirect carries no token. The SPA calls `/auth/refresh` afterwards | `httpapi` `callback` handler | `TestLoginRefreshMeLogout`: the redirect equals the callback URL with no query |
| A database leak hands out sessions | Refresh tokens and `state` are stored as SHA-256 hashes | `token`, `oauthtx` | `TestRefreshRotation`: the raw token is not in the table |
| Subdomain cookie theft | Cookies are host-only, with no `Domain` | `httpapi/cookies.go` | `TestLoginRefreshMeLogout`: no `Domain` |

### Integrity

| Threat | Mitigation | Code | Evidence |
|---|---|---|---|
| Two first logins at once create two users | The unique index decides, the loser logs in the winner's user | `identity.Service` | `TestLosingTheFirstLoginRaceLogsInTheWinner`, `TestConcurrentFirstLoginCreatesOneUser`. A mutation check showed the first one fails without the unique-violation handling |
| Merging by linking an account that belongs to someone else | Linking is explicit and refused with `identity_taken` | `identity.Service.Link` | `TestLinkAndUnlink`, `TestLinkingFlow`, `TestLinkingAnAccountThatHasItsOwnProfile` |
| Locking oneself out by unlinking | The last provider cannot be removed, and the user row is locked so two concurrent unlinks cannot remove both | `identity.Service.Unlink` | `TestUnlinkHoldsTheUserLock`, `TestConcurrentUnlinksKeepOneLoginMethod`. A mutation check showed the lock test fails without `FOR UPDATE` |
| SQL injection | Every value is a bound parameter. Input that reaches a `uuid` column is checked first | `secure.IsUUID`, `Unlink` | `TestIsUUID`, `TestConsumeRejects`: `' OR 1=1 --` is rejected without a database error |
| Open redirect | Redirect targets are built from `FRONTEND_URL`. Callback errors map to a fixed list of codes | `httpapi` | `TestCallbackAlwaysRedirectsWithASafeCode`: `error_description` and provider messages never reach the URL |

### Information disclosure

| Threat | Mitigation | Code | Evidence |
|---|---|---|---|
| Secrets in logs | The access log records only method, path, status and duration. Nothing else about a request is logged | `httpapi` `accessLog` | `TestAccessLogLeaksNothing`: tokens, cookies, `code`, `state` and `error_description` are absent from the log |
| Provider responses echoed into errors | Errors name the failed step, never the body. Only the standard OAuth error code is copied | `provider/oidc.go`, `provider/facebook.go` | `TestGoogle` and `TestFacebook` assert that response bodies are not in the message |
| App secret or access token leaked in a URL | Facebook and Google use a POST body for the secret, Telegram uses HTTP Basic. Facebook calls carry `appsecret_proof` | providers | `TestFacebook`, `TestTelegram`: the secret is in the POST body or the Basic header, never in a URL |
| Secrets in the repository | `.env` is ignored. Configuration is validated at startup | `.gitignore`, `internal/config` | Before each push the tracked files and the whole history were scanned for token shapes and private keys |
| Stack traces to the client | One exception filter. Unexpected errors become a generic 500 | `apperr`, `writeError` | `TestErrorShapeAndRouting` |

### Denial of service

| Threat | Mitigation | Code | Evidence |
|---|---|---|---|
| Hammering the auth endpoints | Throttling: 20 per minute on `/auth/*`, 10 on refresh, 60 elsewhere, `/health` exempt | `limit` middleware (`httprate`) | `TestRateLimiting`: exactly 20 redirects and then 429, and `/health` never limited |
| Large or malformed bodies | A body size limit and validation | `bodyLimit` middleware | `TestErrorShapeAndRouting`: 413 |
| A slow provider hangs a request | A timeout on every outgoing call | providers, `provider.NewHTTPClient` | Provider tests: network failure, non-200 |
| Table growth | Not mitigated | | Rows are never deleted. See the known limits in the README |

## Residual risks

- A stolen refresh token works until the owner refreshes next, or it expires. Reuse is detected only then.
- Two tabs refreshing at the same moment look like a theft and log the user out. The SPA must send refresh calls one at a time.
- A compromised provider account is a compromised login here.
- `HS256` means one secret signs and verifies. If it leaks, rotate it. Existing access tokens die within 15 minutes, refresh tokens survive.
- Rate limiting and the client IP assume exactly one proxy in front.
- The Telegram verifier pins RS256. If BotFather's signing algorithm is changed, Telegram logins fail closed.
