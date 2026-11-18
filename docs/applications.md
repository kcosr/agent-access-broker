# Applications

A registered **application** is a client that people use and that needs Broker
access on their behalf, such as a job runner that starts agents for the person
who is signed in to it. Instead of asking each person to paste a Broker token,
the application sends them to the Broker once. The person approves, and the
application then obtains a fresh, short-lived agent token whenever it needs
one. The person never holds those tokens.

In this document an *application* is the inbound client and an *application
access* is one person's approval of it. Both are unrelated to
[credential connections](providers.md), which are the Broker's outbound
accounts at provider services.

The Broker acts as an OAuth 2.0 authorization server for these applications:
authorization code with PKCE (S256), confidential preregistered clients,
`client_secret_basic`, refresh tokens that do not rotate, RFC 8414 metadata and
RFC 7009 revocation. Public clients, dynamic registration, scopes and MCP
client discovery are not implemented.

## What a connected application can do

An application's token is an ordinary `agent_invoke` Broker token owned by the
person. It works on every existing path (HTTP API, CLI, MCP, Git gateway) and
is limited exactly as an issued agent token is:

- The person's current grants decide what it may do. Connecting grants nothing.
- `allowedExecutionContexts` is the application's
  `allowed_execution_contexts`. List every execution context in which the
  application's tokens will be presented, by the application itself and by
  the agents it starts: a request in any other context is refused.
- `allowedServices` is the application's `allowed_services` when set.
- `readOnly` is true when the application's level is `read_only` **or** an
  administrator made this person's access read-only. Either one narrows; no
  setting widens the other.
- It expires `access_token_ttl` after it is minted.

Connecting is its own permission. It does not depend on the person's
[agent-token issuance policy](roles.md) or on self-service: a person who may
not issue themselves a token can still connect an application, because they
never receive the token.

## Registering an application

Applications are operator-approved in the Broker's TOML and take effect at
startup and reload, like trusted callers:

```toml
[applications.example-runner]
display_name = "Example Runner"
client_secret_ref = "file:/etc/agent-access-broker/secrets/example-runner-client-secret"
redirect_uris = ["https://runner.example.test/auth/broker/callback"]
connect = "read_write"                    # none | read_only | read_write
allowed_execution_contexts = ["default"]
# allowed_services = ["jira"]
access_token_ttl = "8h"
refresh_idle_ttl = "90d"
```

See [configuration](configuration.md#applications) for every key, the
requirements on the rest of the configuration, and the client-secret rules.
The table name is the OAuth `client_id`.

`connect` is the level for everyone; a person does not choose it, and there is
no group setting:

| Level | Effect |
| --- | --- |
| `none` | Nobody can connect, and existing refresh tokens mint nothing. |
| `read_only` | Every token is read-only. |
| `read_write` | Tokens are limited only by the person's grants, unless an administrator made that person's access read-only. |

A changed registration applies at startup and at the reload that admits it,
to the tokens already minted as well. As soon as the new configuration is
active, and before any further token is minted, the Broker ends every live
token the registration would no longer mint:

- all of the application's tokens when it is removed or its level becomes
  `none`;
- its write-capable tokens when its level becomes `read_only`;
- every token whose execution contexts or services are not the
  registration's current `allowed_execution_contexts` and `allowed_services`.

Refresh tokens are unaffected, so the application obtains a token under the
new registration at its next request and nobody reconnects; a later widening
needs no reconnect either. A token that is merely narrower than the
registration, or that has a different remaining lifetime, is left alone. A
configuration that is rejected ends nothing. If ending the tokens fails after
the configuration became active, the reload still succeeds and reports
`applicationTokens.status: "failed"`; new tokens already follow the new
registration, and the next reload or restart ends the remaining ones. At
startup nothing is serving yet, so the Broker does not start when this step
fails: it never serves with a token the configuration no longer grants.
Removing a registration keeps each person's access row, shown to
administrators as unavailable; it mints nothing, and registering the same ID
again makes the same refresh tokens work. A redirect URI removed from the
registration is no longer used: pending approval requests and unexchanged
codes for it become invalid.

## The flow

1. The application sends the person's browser to the authorization endpoint.
2. The Broker validates the request, stores it for 10 minutes and redirects
   the browser to the portal page `/ui/authorize/<request-id>`. A person who
   is not signed in signs in first and returns to that page.
3. The page names the application and the level, and offers **Approve** and
   **Cancel**. A person who may not connect is told why and can only return to
   the application.
4. The Broker returns the browser to the application's redirect URI with a
   one-use code (valid 60 seconds) or `error=access_denied`.
5. The application exchanges the code, with its client secret and the PKCE
   verifier, for an access token and a refresh token.
6. Whenever it needs another token, the application uses the refresh token.

An approval only issues the code. The code exchange is what connects: it
installs the new refresh token and, in the same transaction, ends the previous
refresh token, every token minted through it and any other code still
outstanding for that person and application. The last successful exchange is
therefore always the live grant. An approval whose code the application never
redeems (a closed tab, a client error, a superseded attempt) changes nothing:
an existing connection keeps working, and the approval expires with its code
after 60 seconds. Reconnecting keeps the access, its ID and its administrator
settings. Ending the consent, by the person or by the application, never lifts
an administrator's restriction; see [managing access](#managing-access).

## Wire contract

All endpoints are on the Broker's public origin
(`browser_auth.public_origin`). A client reads them from the metadata document
and does not hard-code the other paths.

### Metadata

`GET /.well-known/oauth-authorization-server`, unauthenticated, returns

```json
{
  "issuer": "https://broker.example.test",
  "authorization_endpoint": "https://broker.example.test/v1/applications/authorize",
  "token_endpoint": "https://broker.example.test/v1/applications/token",
  "revocation_endpoint": "https://broker.example.test/v1/applications/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic"],
  "revocation_endpoint_auth_methods_supported": ["client_secret_basic"]
}
```

It answers 404 while no application is registered.

### Authorization request

A full-page browser `GET` of the authorization endpoint with `response_type=code`,
`client_id`, `redirect_uri`, `state`, `code_challenge` and
`code_challenge_method=S256`.

- An unknown `client_id`, a `redirect_uri` that is not exactly one of the
  registered URIs, or a repeated or oversized parameter is answered with an
  HTML error page (400) and never a redirect.
- Every other outcome returns to `redirect_uri` with the request's `state`:
  `code`, or `error`. `error` is `access_denied` (the person cancelled or may
  not connect), `invalid_scope` (a `scope` parameter was supplied; none is
  defined), `invalid_request` (a missing or malformed parameter, including a
  `response_type` other than `code` and a challenge method other than `S256`)
  or `server_error`.
- `state` is required: 1 to 512 printable ASCII characters. Without a valid
  one the error redirect carries no `state`.
- `code_challenge` is the unpadded base64url SHA-256 of the verifier (43
  characters).

### Token endpoint

`POST` with `Content-Type: application/x-www-form-urlencoded` and
`Authorization: Basic`, whose user and password are the form-urlencoded client
ID and client secret (RFC 6749 section 2.3.1).

- `grant_type=authorization_code&code=...&redirect_uri=...&code_verifier=...`
- `grant_type=refresh_token&refresh_token=...`

Success is 200 with `Cache-Control: no-store`:

```json
{
  "access_token": "aab_ai_...",
  "token_type": "Bearer",
  "expires_in": 28800,
  "refresh_token": "aar_...",
  "principal_id": "usr-11111111-2222-4333-8444-555555555555",
  "principal_name": "Alex Example",
  "read_only": false
}
```

- `refresh_token` is present only in the answer to `authorization_code`. It
  does not rotate.
- Every successful call mints a new, independent access token. Earlier ones
  stay valid until they expire or are revoked.
- `principal_id`, `principal_name` and `read_only` are in every answer,
  including a refresh. `principal_name` is the person's display name, at most
  256 characters, or their principal ID when they have none; it is never
  empty.

Failure is RFC 6749 section 5.2 JSON, `{"error": "..."}`, and never a Broker
envelope:

| Status | `error` | Meaning |
| --- | --- | --- |
| 401 | `invalid_client` | Missing or wrong client credentials; carries `WWW-Authenticate: Basic`. |
| 400 | `invalid_grant` | The code or refresh token is unknown, used, expired, or was issued to another client, redirect URI or verifier; the access was removed or disabled; the person is disabled; the application's level is `none`; the refresh token was idle longer than `refresh_idle_ttl`. |
| 400 | `invalid_request` | A missing, repeated or malformed parameter, a body that is not a form, or client credentials in the body. |
| 400 | `unsupported_grant_type` | Any other `grant_type`. |
| 503 | `temporarily_unavailable` | Rate limited, a reload in progress, the store unavailable, or the access already holds its maximum of live tokens. Retry later; a `Retry-After` header is passed through when the Broker has one. |
| 500, 503 | `server_error` | An internal failure, including an unavailable audit log. Retry later. |

A code is consumed by its first presentation, whatever the outcome. After
`invalid_grant` on refresh the same refresh token can work again, for example
when an administrator enables the access again, so a client keeps it and asks
the person to reconnect only when they want to continue.

### Revocation

`POST` to the revocation endpoint with the same client authentication and the
form field `token`. The answer is 200 whether or not the token was known.

- An access token of this application: that token ends.
- The refresh token: the person's consent for this application ends, with the
  refresh token and every token minted through it. The person approves again
  to reconnect.

## Limits and retention

- The authorization, token and revocation endpoints count against
  `limits.auth_requests_per_source_per_minute` for the caller's address, as the
  sign-in routes do. Every request counts, whatever Broker token or browser
  session it also carries.
- At most 1,000 authorization requests are pending at once.
- One access holds at most 256 unexpired, unrevoked tokens, which leaves room
  for an application that keeps one token per running agent session and
  revokes each when its session ends. A request beyond that is refused with
  `temporarily_unavailable`; revoke tokens that are no longer needed.
- An application's tokens are not listed as individual tokens in the personal
  or administrative token lists. The access shows how many are live. The rows
  are deleted once they have been expired or revoked for 7 days, by the next
  authorization or token request; audit records keep their token IDs.
- An access that is neither connected nor restricted by an administrator,
  such as a first approval whose code was never exchanged, is deleted by the
  same retention once its code has expired.

## What ends an application's tokens

Each of these ends the live tokens of the access at once:

- an administrator disables the access, changes its read-only setting or
  removes it;
- the person removes it;
- the application redeems the code of a new approval by the person;
- the application revokes its refresh token;
- the person's account is disabled. Enabling the account again does not restore
  the ended tokens; the application refreshes instead;
- a startup or reload under a registration that would no longer mint them, as
  described under [registering an application](#registering-an-application).

## Managing access

A person sees and removes their own application access in the portal or with
a `user_manage` token; neither needs self-service:

| Method and route | Result |
| --- | --- |
| `GET /v1/applications/access` | `{access: [...]}` |
| `DELETE /v1/applications/access/{accessId}` | `{removed: true}` |

Administrators manage a person's access, and auditors read it:

```bash
agent-access admin principals application-access list alice
agent-access admin principals application-access update alice ACCESS_ID --read-only true --expected-version 1
agent-access admin principals application-access update alice ACCESS_ID --enabled false --expected-version 2
agent-access admin principals application-access delete alice ACCESS_ID --expected-version 3
```

**Enabled** and **Read-only** only narrow what the application's level allows.
A disabled access cannot be refreshed or connected again until an
administrator enables it. Every actual settings change advances `version` once
and ends the access's live tokens; a change that alters nothing writes nothing.

A person, and the application by revoking its refresh token, can end the
consent but cannot remove an administrator's restriction. When they
disconnect:

- the refresh token and every live token end, and the access leaves the
  person's own list, which holds only connected applications;
- an access that is enabled and not read-only is deleted;
- an access that is disabled or read-only is kept, disconnected, with its
  settings and its ID. The administrator's list still shows it, with
  `connected: false`. A later approval reuses it: a disabled access still
  cannot be connected, and a read-only one stays read-only.

`connected` is true while the application holds a working refresh token: from
its first successful code exchange until a disconnect. It stays true through a
new approval, and a first approval is not connected until its code is
redeemed. `connectedAt` is the time of the latest successful code exchange
(for an access that was never connected, the time of its first approval).

Only an administrator's delete removes a restricted access, after which the
person may connect afresh. `version` covers the Enabled and Read-only settings
alone: connecting and disconnecting do not change it, so they never cause or
hide a conflict with an administrator's edit. An edit to an access that was
deleted answers not found, and a later approval creates a new access with a
new ID, which a stale edit cannot reach. See the
[HTTP API](http-api.md#application-access) for the routes and fields.

## The consent routes

The portal's approval page uses two JSON routes. They require a signed-in
browser session; a bearer token cannot consent, whatever its class.

`GET /v1/applications/authorizations/{requestId}` returns

```json
{
  "applicationId": "example-runner",
  "applicationName": "Example Runner",
  "connect": "read_write",
  "readOnly": false,
  "canConnect": true,
  "denialReason": null,
  "expiresAt": "2026-01-01T00:10:00Z"
}
```

`readOnly` is what this person's tokens will be. When `canConnect` is false,
`denialReason` is `connecting_disabled` (the level is `none`),
`access_disabled`, `not_human` or `account_disabled`.

`POST /v1/applications/authorizations/{requestId}/decision` with
`{"decision": "approve", "principalId": "..."}` or
`{"decision": "cancel", "principalId": "..."}` and the CSRF header returns
`{decision, redirectTo}`. `principalId` is required: it is the account the
page showed the request to, which is the `principal` of the read above. When
the session that sends the decision belongs to another account, for example
after signing in again in another tab, the decision answers 409
`version_conflict` and changes nothing; the page reads the request again. The
page navigates to `redirectTo`. Cancel always returns the application
`error=access_denied`. A refused approval
answers 403 `application_access_denied` with `details.denialReason` and leaves
the request pending, so the person can still cancel back to the application.
An unknown, used or expired request answers 404
`application_authorization_invalid` on both routes. So does a request whose
application is no longer registered with the request's exact redirect URI:
neither an approval nor a cancellation returns the browser to an address the
operator removed.

## Audit

| Action | Recorded when |
| --- | --- |
| `applications.authorizations.decide` | A person approves or cancels, or an approval is refused. |
| `applications.token.issued` | Every minted token, with the grant type, access ID, token ID and caveats. |
| `applications.authorize.refused` | A refused authorization request, with the application ID when the request named a registration. |
| `applications.token.refused` | Every refused token or revocation request: failed client authentication, a malformed request, a missing or unsupported grant type, missing grant parameters, and every `invalid_grant`. The record carries a fixed reason and never a supplied value. |
| `applications.token.revoked` | A revocation that ended a token or a consent. |
| `applications.tokens.reconciled` | A startup or reload ended tokens the registration no longer mints: one record per application with the reason and the number of tokens. |
| `applications.access.remove` | A person removes their own access. |
| `admin.principals.application_access.patch`, `.delete` | An administrator changes or removes an access, with the settings before and after. |

Records name the application ID. Client secrets, codes, PKCE verifiers,
request IDs, refresh tokens and access tokens never appear in audit records,
logs, errors or diagnostics. A token is committed before its audit record is
written; when that record cannot be written the request fails with
`server_error`, the token is not returned, and the Broker does not retry.

## Security notes

- The client secret authenticates the application, not a person. Keep it out
  of workloads and user-editable settings, as for
  [trusted caller](trusted-callers.md) credentials.
- Redirect URIs are matched exactly, so a registered application cannot be
  used to deliver a code elsewhere.
- Codes, refresh tokens and client secrets use prefixes outside the `aab_`
  token namespace and are never accepted as caller credentials.
- Refresh tokens and codes are stored only as keyed hashes; a pending
  request's parameters are encrypted with a key derived from its ID, which the
  store does not hold.
- The approval is the person's own decision in their own browser session, with
  CSRF protection, for the account the page displayed. An administrator cannot
  connect an application for someone.
- Portal documents are served with `Referrer-Policy: no-referrer`, so the
  request ID in the approval page's address is not sent in the `Referer` of
  the requests that page makes.
