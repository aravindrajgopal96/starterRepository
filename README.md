# Card Control API

Git repository - https://github.com/aravindrajgopal96/starterRepository

Lets a partner lock and unlock corporate cards. C# / .NET 10.

| Path | What |
|---|---|
| `src/CardControl.Api` | The API |
| `tests/CardControl.Api.Tests` | Automated tests |
| `mock-identity-provider`, `tokenisation-stub`, `card-platform-stub`, `tools` | Starter kit, unmodified |
| `STARTER.md` | The starter kit's README (renamed, so this one could take its place) |

`.gitignore` was extended: the starter's didn't exclude the private key that `keygen` writes to `.dev-keys/`.

## Run it

Needs the .NET 10 SDK. From the repository root, one terminal each:

```powershell
dotnet run --project mock-identity-provider --urls http://localhost:5090
dotnet run --project tokenisation-stub --urls http://localhost:5070
dotnet run --project card-platform-stub --urls http://localhost:5080
```

Create the key pair once, before starting the API (it refuses to start without a key):

```powershell
dotnet run tools/jwe-tool.cs -- keygen
dotnet run --project src/CardControl.Api --launch-profile http
```

The API listens on `http://localhost:5100`. For TLS, run `dotnet dev-certs https --trust` and use `--launch-profile https` (`https://localhost:5101`).

### Sample call (PowerShell)

```powershell
$TOKEN = (Invoke-RestMethod -Method Post -Uri http://localhost:5090/oauth2/token -Body @{
  grant_type = 'client_credentials'; client_id = 'partner-app'
  client_secret = 'dev-only-partner-app-secret'; scope = 'api://card-control/.default'
}).access_token

$PAN_JWE = dotnet run tools/jwe-tool.cs -- encrypt --key .dev-keys/bank-dev-1.public.pem 4111111111111111

Invoke-RestMethod -Method Post -Uri http://localhost:5100/v1/cards/lock -ContentType application/json `
  -Headers @{ Authorization = "Bearer $TOKEN"; 'X-Initiating-User' = 'jane.smith@acme.example' } `
  -Body (@{ encryptedPan = $PAN_JWE; corporateId = 'CORP-1001' } | ConvertTo-Json)

Invoke-RestMethod http://localhost:5080/admin/audit   # who did what
```

### Sample call (cURL)

In Bash, with `jq`. The token lasts an hour and the JWE only decrypts with your own key pair, so generate both:

```bash
TOKEN=$(curl -s -X POST http://localhost:5090/oauth2/token \
  -d grant_type=client_credentials -d client_id=partner-app \
  -d client_secret=dev-only-partner-app-secret -d scope=api://card-control/.default | jq -r .access_token)

PAN_JWE=$(dotnet run tools/jwe-tool.cs -- encrypt --key .dev-keys/bank-dev-1.public.pem 4111111111111111)

curl -X POST 'http://localhost:5100/v1/cards/lock' \
  -H "Authorization: Bearer $TOKEN" \
  -H 'X-Initiating-User: jane.smith@acme.example' \
  -H 'Content-Type: application/json' \
  -d "{\"encryptedPan\":\"$PAN_JWE\",\"corporateId\":\"CORP-1001\"}"
```

```json
{"corporateId":"CORP-1001","status":"Locked","updatedAt":"2026-11-25T16:41:18.1847081+00:00"}
```

Change `lock` to `unlock` to reverse it. In Postman, import the `curl` with both values filled in. The access token (2 dots) goes in the `Authorization` header; the JWE (4 dots) goes in the body.

### Tests

```powershell
dotnet test
```

The tests start the real starter kit services on free ports and run the API against them, so nothing needs to be running first. Fake handlers are used only for failures the stubs can't produce. Nine security controls (issuer, audience, lifetime and role checks, both entitlement checks, JWE algorithm and tag-length checks, PAN logging) were also broken one at a time to confirm a test fails.

## Contract

`POST /v1/cards/lock` and `POST /v1/cards/unlock`

```json
{ "encryptedPan": "<compact JWE>", "corporateId": "CORP-1001" }
```

`200`: `{ "corporateId": "CORP-1001", "status": "Locked", "updatedAt": "..." }`. No card token, cardholder name or masked PAN, since the partner doesn't need them.

The PAN is in the body because URLs end up in access logs. Errors are RFC 9457 Problem Details with a `code` and a `traceId`:

| Status | `code` | Meaning |
|---|---|---|
| 400 | `InvalidRequest` | Bad body, or `X-Initiating-User` missing, repeated, over 128 characters, containing control/format characters or a PAN |
| 400 | `InvalidEncryptedPan` | Not a JWE we accept. All decryption failures look the same |
| 400 | `InvalidPan` | Decrypted, but not a valid card number |
| 401 | `Unauthorized` | Missing or invalid token, or the identity provider can't be reached to check it |
| 403 | `Forbidden` | Token lacks `CardControl.Write` |
| 403 | `CorporateNotEnabled` | Partner isn't enabled for this corporate |
| 404 | `CardNotFound` | No such card **for this corporate** |
| 409 | `CardAlreadyLocked`, `CardNotLocked` | Already in the requested state |
| 413, 415 | `PayloadTooLarge`, `UnsupportedMediaType` | Over 16 KB; not JSON |
| 422 | `CardCancelled` | Card can't be changed |
| 502, 503, 504 | `UpstreamError`, `ServiceUnavailable`, `UpstreamTimeout` | Downstream failure; card not changed |
| 502, 504 | `OutcomeUnknown` | Change was sent but the result is unknown. Safe to retry; a 409 then means it's in the requested state |

`GET /healthz` is anonymous. Everything else requires the role by default.

## Design decisions

**Entitlement** has two checks. The requested corporate must be on the list for the token's `azp`; this happens before anything is decrypted. Then the card platform's `corporateId` must equal the requested one, because the partner's value is only a claim. Enabled-but-wrong corporates and cards with no corporate fail. Those return the same 404 as an unknown card, so the API can't be used to discover other companies' cards.

**Audit.** The card's status isn't checked before calling lock/unlock. The platform audits rejected attempts too, so short-circuiting would lose them (and would race). `channel` is the `azp` from the validated token. Attempts denied on entitlement never reach the platform; they are logged here as warnings with the initiating user.

**Keeping the PAN out of logs and errors**, in layers:

1. `Pan` isn't a string; it doesn't print or serialise, and its buffers are wiped. The tokenisation request is built from bytes.
2. Request bodies are parsed by hand, because framework binding errors can contain request content. Downstream bodies and messages are never logged or forwarded; only known `code` values are recognised, and all partner-facing text is fixed.
3. `HttpClient` logging and redirects are off.
4. The only log sink redacts anything that looks like a PAN, including in exceptions. It errs towards over-redacting.

**Decryption** uses .NET's RSA and AES-GCM directly. Microsoft.IdentityModel wasn't an obvious fit for this algorithm pair, and the strict profile (fixed algorithms, known `kid`, no `zip`/`crit`, exact tag length) is what most needs enforcing. Several keys can be active for rotation.

**Resilience.** Tokenise and get-card are retried (2 retries, 3 s per attempt, 8 s total). Lock/unlock is never retried, because a timed-out change may have been applied and audited. It also continues if the partner disconnects.

## Assumptions

- The partner is identified by `azp`. A second partner is a config entry under `Partners`.
- TLS ends at the ingress or Kestrel; mesh mTLS protects downstream calls, as `STARTER.md` says. Plain-HTTP identity provider metadata is allowed only in Development.
- `X-Initiating-User` is an opaque ID, vouched for by the partner; we can't verify it. A purely numeric 12-19 digit ID that happens to pass Luhn would be refused.
- `corporateId` is case-sensitive.
- Locking a locked card is a 409, as on the platform, rather than a silent success.
- The partner may unlock any lock on its cards. The platform doesn't say who set a lock, so a bank fraud lock can't be told apart. **This needs a real answer before production.**
- `kid` is required in the JWE header.

## Shortcuts, and what I'd do with more time

- **Private key on disk.** In AKS: a non-exportable Key Vault / HSM key through workload identity, with unwrap done remotely.
- **Replay.** The JWE has no timestamp, nonce or binding to the request, so a captured one can be reused by someone who also has a token. I'd agree a signed envelope or bind the request with the partner.
- **Rate limiting** per partner, to slow card enumeration. Probably at the gateway as well.
- **Denied-attempt audit** goes only to logs; it should go to a durable audit store.
- **Identity provider problems.** A cold start with the provider down gives 401 (fails closed), where 503 would be more accurate. After a signing key change, the first request can get one 401 while keys refresh.
- **Health** is liveness only; add readiness. Add a circuit breaker, metrics/tracing (with the same redaction), OpenAPI, container image and CI.
- **Memory.** Wiping is best effort; the HTTP stack may keep copies of the outgoing request.
- **Entitlements** are in config, so changes need a redeploy.
- Card ownership could in theory change between the check and the lock; closing that needs platform support for a conditional change.

## Time spent

About 4-5 hours in total, including reading the brief, setting up and running the starter kit, testing by hand and reviewing the code.

## Use of AI

Built with Claude Code (Claude Opus 5.5). It wrote the API, tests and this README from the brief and starter kit, ran the tests and the live calls above, and did the break-one-control-at-a-time check.

