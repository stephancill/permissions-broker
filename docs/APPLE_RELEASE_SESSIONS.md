# Apple Release Sessions - TestFlight Uploads From CI

Last updated: 2026-11-21

Status: broker side implemented (migration `0017_release_sessions.sql`);
`stupid-app` side released in 0.0.31. The reusable GitHub workflow is next.

A GitHub Actions run builds an iOS app on a Linux runner with `stupid-app`, and
the broker signs it and talks to App Store Connect for it. The App Store Connect
API key and the distribution private key never leave the broker.

## Goals

- Upload a new build to internal TestFlight from a GitHub Actions run, with one
  passkey approval per run.
- Keep the App Store Connect (ASC) `.p8` key and the distribution private key in
  the broker. The runner never receives either key or a token derived from them.
- Serve many apps from one team-wide credential, with each repository limited to
  the bundle ids the user registered for it.
- Authenticate workflows with GitHub OIDC, so no long-lived broker secret is
  stored in GitHub.

## Non-goals (first version)

- External TestFlight submission, beta groups, "What to Test" notes, App Store
  review submission, or any change to the app's listing.
- Creating certificates, profiles, bundle ids or devices. Those stay on the
  user's Mac (`stupid-app signing setup`).
- Development signing or device installs.

## Why this works

`stupid-app` uses a private key in exactly two places:

1. `NativeCMS.sign`: one RSA PKCS#1 v1.5 SHA-256 signature over the CMS signed
   attributes per signed bundle (an app with one extension needs two). Everything
   else in signing needs only the public certificate.
2. `ASCClient`: an ES256 JWT per App Store Connect request. The IPA itself goes
   to Apple's presigned upload URLs (no auth), so build bytes never pass through
   the broker.

So the broker offers a signing endpoint and an ASC proxy that adds the JWT.

## Credential: `apple-release`

One linked credential per Apple developer team (`src/apple/credential.ts`),
linked through the form at `/v1/accounts/connect/apple-release`
(`src/web/appleReleaseConnect.ts`) and ECIES-encrypted to the user's passkey key
like the other credentials:

```json
{
  "teamId": "...",
  "ascKeyId": "...",
  "ascIssuerId": "...",
  "ascKeyPem": "-----BEGIN PRIVATE KEY-----...",
  "distributionKeyPem": "-----BEGIN PRIVATE KEY-----...",
  "distributionCertificateId": "..."
}
```

Before saving, the form makes a JWT with the key, reads the certificate
(`GET /v1/certificates/:id`), requires a distribution certificate, and checks the
private key belongs to it (a test signature verifies with the certificate's
public key). Both keys must be PKCS#8 PEM. `metadata_json` holds
`apple_release: { teamId, ascKeyId, distributionCertificateId }`, which the
session endpoints read without decrypting.

Use a dedicated ASC team key with the Developer role (enough for internal
uploads), so it can be revoked on its own. Team keys and the distribution
certificate are team-wide: Apple cannot limit them to one app, so per-app limits
are enforced by the broker.

## Release policies

`release_policies`: which workflow may release which bundle ids. The user adds
one on the **Releases** page (`/app/releases`, linked from the apple-release
row under Accounts once it is connected): repository, workflow file, full
ref (default `refs/heads/main`) and exact bundle ids (app and extensions, at most
ten, no wildcards). Adding creates a `PENDING_APPROVAL` policy and opens
`/approve/release_policy/:id`, where a passkey assertion activates it: the
session cookie alone cannot widen what CI may release. An active policy for the
same workflow is replaced. Removing a policy needs only the session.

## Authentication: GitHub OIDC

`src/release/oidc.ts`. The workflow requests an OIDC token
(`permissions: id-token: write`) with the broker's origin (`APP_BASE_URL`) as
audience and sends it as `Authorization: Bearer <jwt>` to the session API. The
broker verifies the RS256 signature against GitHub's JWKS (cached 10 minutes,
refetched once for an unknown `kid`), the issuer, the audience, `exp` and
`nbf`/`iat` (60 s skew), and requires the claims it uses.

The audience is exactly the `APP_BASE_URL` origin (`https://vault.stupidtech.net`),
even when the run calls the legacy host, which still serves `/v1`
(`docs/DOMAIN_MIGRATION.md`); session URLs always use `APP_BASE_URL`.

The policy is matched on `repository`, the path in `workflow_ref` and `ref`.
`workflow_ref` names the caller's workflow, so a repository that calls a reusable
workflow registers its own workflow file. OIDC tokens are accepted only by the
two session API routes below; they are never an identity for the proxy.

## Session lifecycle

`src/web/release.ts`, `src/release/store.ts`.

1. `POST /v1/release/sessions` with `{ bundle_ids, version, build_number }`.
   Without a matching active policy: 403 `no_release_policy`. Bundle ids outside
   the policy: 403 `bundle_not_allowed`. Without a linked `apple-release`
   credential: 409. Otherwise the broker records the run (repository,
   workflow_ref, ref, sha, run id and attempt, actor), sends a Web Push
   (`Urgency: high`, tag `release:<id>`), lists it in the app inbox and returns
   `{ session_id, status, approval_expires_at }`. Approval expires after
   10 minutes; the workflow asks after the unsigned build, so the prompt arrives
   when the user is waiting for it.
2. The user approves on `/approve/release/:id` (run URL, commit, bundles,
   version) with their passkey, which releases the credential's DEK as a grant
   (target kind `release`) expiring with the session, or denies there.
3. `GET /v1/release/sessions/:id` with an OIDC token from the same repository,
   workflow and run polls. The first poll after approval returns `session_url`
   (`<origin>/v1/release/session/:id/rs_<secret>`); the secret's ciphertext is
   then deleted and only its hash remains.
4. The run uses the session endpoints below.
5. `DELETE <session_url>` closes the session and deletes its grant. The sweeper
   closes sessions 45 minutes after approval or after 15 minutes without
   requests, expires unapproved sessions and policies, and deletes grants of
   closed, expired and denied sessions.

## Session endpoints

`stupid-app` reads the session URL from `STUPID_APP_RELEASE_SESSION`. A wrong
secret is 404; a closed or expired session is 410.

### `GET <session_url>/info`

`{ teamId, distributionCertificateId, bundleIds }`: the team for CodeDirectories,
the certificate `signing fetch` downloads, the approved bundles.

### `<session_url>/asc/v1/...`

Forwards to `https://api.appstoreconnect.apple.com/v1/...` with a broker-made
ES256 JWT (`aud = appstoreconnect-v1`, 15 minute lifetime). The JWT is stored
APP_SECRET-encrypted on the session and reused until two minutes before it
expires, so most requests do not unlock the credential. Caller `Authorization`
headers are never forwarded. Request bodies are limited to 64 KB, responses to
8 MB.

`src/release/ascAllowlist.ts` decides each request against the session's scope.
The scope starts with the approved bundle ids and the credential's certificate,
and learns App Store Connect ids only from responses to requests it allowed:

| Method | Path | Allowed when | Learns |
|---|---|---|---|
| GET | `apps?filter[bundleId]=` | an approved bundle id | app ids whose `bundleId` is approved |
| GET | `bundleIds?filter[identifier]=` | an approved bundle id | resource ids whose `identifier` is approved |
| GET | `bundleIds/:id/profiles` | `:id` was learned | |
| GET | `certificates/:id` | the credential's certificate | |
| GET | `builds?filter[app]=` | a learned app id | build ids |
| GET | `builds/:id`, `builds/:id/buildBetaDetail` | a learned build id | |
| POST | `buildUploads` | body's `app` relationship is a learned app id | the upload id |
| GET | `buildUploads/:id` | created in this session | |
| POST | `buildUploadFiles` | body's `buildUpload` was created in this session | the file id |
| PATCH | `buildUploadFiles/:id` | created in this session | |

Filters take one value (no comma lists), only `limit`, `include`, `sort` and
`fields[...]` are allowed besides the listed filters, and POST/PATCH take no
query. Everything else is refused with 403 (`FORBIDDEN_BY_BROKER`) and audited
(`release_asc_refused`). This covers `stupid-app signing fetch`,
`release new-build`, `release archive` and `release upload --wait`.

### `POST <session_url>/sign`

Request `{ codeDirectory, signedAttributes }` (base64; the DER SET the signature
covers), response `{ signature }` (base64). `src/apple/signing.ts`:

1. Parses the CodeDirectory (SHA-256 only) and requires its identifier to be an
   approved bundle id and its team id to be the credential's team.
2. Requires the signed attributes to be exactly content type (id-data), message
   digest, the Apple cdhash plist (one `cdhashes` entry: the first 20 bytes) and
   the Apple cdhashes attribute, all naming that CodeDirectory's SHA-256, in DER
   order, with nothing else (no signing time or timestamp).
3. Allows one signature per bundle id per session (`stupid-app` settles the
   signature size with a placeholder and signs once per bundle).
4. Signs with the distribution key (RSASSA-PKCS1-v1_5, SHA-256). The bundle id and
   cdhash are audited (`release_signed`); refusals too (`release_sign_refused`).

So the endpoint only ever signs a code signature for an approved bundle.

## GitHub workflow (next)

A reusable workflow in stupid-app's repository, versioned with the CLI, which an
app repository calls with `permissions: { id-token: write, contents: write }`:

1. Install Swift, `stupid-app` and `stupid-app-macros`; download the device SDK
   from stupid simulator's runtime store (the only place SDK bundles are
   published), cached with `actions/cache`.
2. Write app-specific files from the repository's own secrets, then
   `stupid-app build`.
3. Create a release session and poll until approved.
4. `stupid-app signing fetch`, `release new-build`, commit the build number,
   `release archive`, `release upload --wait`, all through the session.
5. Close the session in an `always()` step.

Manual trigger only (`workflow_dispatch`).

## Threat model additions

| Scenario | Exposure |
|---|---|
| Runner compromised during a session | Code signatures and allowlisted ASC requests for that session's bundles until it closes; no keys |
| Repository compromised | A release session request; still needs the user's passkey approval |
| Another of the user's repositories compromised | Nothing for bundles outside its policy |
| GitHub OIDC signing key compromised | Session requests for any policy; still need passkey approval |
| Session URL leaked | The same as a compromised runner, until the session closes |

## Deploying

Apply migration `0017_release_sessions.sql` to D1 before the Worker code that
uses it reaches production: migrations are applied manually
(`wrangler d1 migrations apply permissions-broker --remote`), while pushes to
`main` deploy the code.

## Verification (2026-11-21)

- `tests/release_sessions.test.ts`: allowlist allows and refuses, scope learning,
  signing checks (other bundle, team, digest, extra attribute, arbitrary bytes),
  OIDC (signature, audience, expiry), and a session end to end with a real
  passkey-encrypted credential and grant: policy and bundle refusal, the session
  URL returned once and only to the same run, `info`, an ASC request carrying a
  JWT that verifies with the stored key, a refused request never reaching Apple,
  one signature per bundle that verifies with the certificate's key, and close.
- A signing request captured from `stupid-app` 0.0.31 (`release archive` through
  a local stand-in) passes the signing checks and is refused for another bundle.
- A JWT from `createAscJwt` with a real team key reads a distribution certificate
  from App Store Connect, and the key-certificate check accepts the real key and
  refuses another.
