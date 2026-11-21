# Apple Release Sessions - TestFlight Uploads From CI (Plan)

Last updated: 2026-11-21

Status: planned, not implemented.

This document plans approval-gated iOS releases from GitHub Actions. A workflow
builds an app on a Linux runner with `stupid-app`, and the broker signs it and
talks to App Store Connect for it. The App Store Connect API key and the
distribution private key never leave the broker.

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

## Why this is possible

`stupid-app` uses a private key in exactly two places:

1. `NativeCMS.sign`: one RSA PKCS#1 v1.5 SHA-256 signature over the CMS signed
   attributes per signed bundle (an app with one extension needs two). Everything
   else in signing needs only the public certificate.
2. `ASCClient`: an ES256 JWT per App Store Connect API request. Its `baseURL` is
   already configurable. The IPA itself goes to Apple's presigned upload URLs
   (`rawRequest`, no auth), so build bytes never pass through the broker.

The broker therefore offers a signing endpoint and an ASC proxy that adds the JWT.

## Credential: `apple-release`

One linked credential per Apple developer team, added through a connect form and
ECIES-encrypted to the user's passkey key like the other credentials
(`docs/PASSKEY_CREDENTIAL_ENCRYPTION.md`):

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

`metadata_json` holds the team id and certificate id for display. The connect
form validates the ASC key (one authenticated `GET /v1/apps?limit=1`) and that the
distribution key matches the certificate before saving.

Use a dedicated ASC team key with the Developer role (enough for internal
uploads), so it can be revoked on its own.

Team keys and the distribution certificate are team-wide: Apple cannot limit them
to one app. Per-app limits are therefore enforced by the broker (below).

## Release policies

A policy row says which workflow may release which apps:

| Column | Example |
|---|---|
| `user_id` | owner of the credential |
| `linked_account_id` | the `apple-release` credential |
| `repository` | `owner/repo` |
| `workflow_ref` | `owner/repo/.github/workflows/testflight.yml@refs/heads/main` |
| `ref` | `refs/heads/main` |
| `bundle_ids` | JSON array: the app and its extensions |

Policies are created by the user only, on a **Releases** page in the app (`/app`):
repository, workflow file, branch and bundle ids, saved with a passkey assertion
(the session cookie alone is not enough to widen what CI may release). Removing a
policy needs only the session. A repository's own `stupid-app.yml` never grants
bundle ids. Wildcard repositories or bundle ids are not supported.

## Authentication: GitHub OIDC

The workflow requests an OIDC token (`permissions: id-token: write`) with the
broker's origin as audience and sends it as `Authorization: Bearer <jwt>` when
creating a session. The broker:

1. Verifies the signature against GitHub's JWKS
   (`https://token.actions.githubusercontent.com/.well-known/jwks`, cached), the
   issuer `https://token.actions.githubusercontent.com`, the audience, `exp`,
   `nbf` and `iat`.
2. Finds the policy matching `repository`, `job_workflow_ref` (the reusable
   workflow) or `workflow_ref`, and `ref`. No match fails loudly (403).
3. Records `sha`, `run_id`, `run_attempt` and `actor` on the session for the
   prompt and audit log.

An OIDC token is accepted only for creating a release session. It is never an
identity for the generic proxy.

## Session lifecycle

Modelled on git sessions (`src/git/sessions.ts`).

1. `POST /v1/release/sessions` with `{ bundle_ids, build_number, version }`.
   `bundle_ids` must be a subset of the policy's. The broker sends a Web Push
   (`Urgency: high`, tag `release:<id>`, TTL the approval time) naming the
   repository, commit, bundle ids, version and build number, lists the request in
   the app inbox, and returns `{ id }`.
2. The user approves on `/approve/release/:id` in the app with their passkey (the
   page shows the run URL, commit and bundle ids), or denies there. The grant is
   scoped to the session.
3. `GET /v1/release/sessions/:id` (OIDC token again) polls. Once approved it
   returns the session secret and base URL, once.
4. At approval the broker resolves the ASC app ids (`GET /v1/apps?filter[bundleId]=`)
   and bundle id resource ids (`GET /v1/bundleIds?filter[identifier]=`) for the
   approved bundle ids and stores them on the session.
5. The runner uses the session endpoints below.
6. `DELETE /v1/release/session/:id/:secret` closes the session and deletes its
   grant. The sweeper closes sessions at a 45 minute hard cap or after 15 minutes
   without requests.

Approval TTL is 10 minutes: the workflow requests approval after the unsigned
build, so the prompt arrives when the user is waiting for it.

## Session endpoints

The session's base URL is `/v1/release/session/:id/:secret`. `stupid-app` reads it from
`STUPID_APP_RELEASE_SESSION` and calls the endpoints below relative to it.

### Session info: `GET /v1/release/session/:id/:secret/info`

Returns `{ teamId, distributionCertificateId, bundleIds }` for `stupid-app` (the team for
CodeDirectories, the certificate `signing fetch` downloads, the approved bundles).

### ASC proxy: `/v1/release/session/:id/:secret/asc/v1/...`

Forwards to `https://api.appstoreconnect.apple.com/v1/...` with a broker-created
ES256 JWT (WebCrypto, `aud = appstoreconnect-v1`, 10 minute lifetime, cached per
session). Caller `Authorization` headers are dropped.

Allowed requests, each checked against the session's app ids and bundle ids:

| Method | Path | Check |
|---|---|---|
| GET | `/apps` | `filter[bundleId]` is an approved bundle id |
| GET | `/apps/:id`, `/apps/:id/builds`, `/apps/:id/preReleaseVersions` | `:id` is an approved app id |
| GET | `/builds` | `filter[app]` is an approved app id |
| GET | `/builds/:id` | the response's app relationship is an approved app id |
| POST | `/buildUploads` | body's `app` relationship is an approved app id |
| GET, PATCH | `/buildUploads/:id` | the upload was created in this session |
| POST | `/buildUploadFiles` | body's `buildUpload` relationship was created in this session |
| PATCH | `/buildUploadFiles/:id` | the file was created in this session |
| GET | `/bundleIds` | `filter[identifier]` is an approved bundle id |
| GET | `/bundleIds/:id/profiles` | `:id` is an approved bundle id's resource id |
| GET | `/certificates/:id` | `:id` is the credential's distribution certificate |

Everything else is refused (403) and logged. The exact list is confirmed against
the requests `stupid-app release new-build`, `archive`, `upload --wait` and the
profile fetch make, recorded from a real run.

### Signing: `POST /v1/release/session/:id/:secret/sign`

Request: `{ codeDirectory, signedAttributes }` (base64): one bundle's CodeDirectory
(`stupid-app` emits a single SHA-256 CodeDirectory) and the DER CMS signed attributes
(the SET the signature covers). Response: `{ signature }` (base64). `stupid-app`
verifies the signature against the certificate. The broker:

1. Parses each CodeDirectory and requires its identifier to be an approved bundle
   id and its team id to be the credential's team.
2. Recomputes the CodeDirectory's SHA-256 and requires the signed attributes to be
   exactly `contentType` (id-data), `messageDigest`, the Apple cdhash plist (the
   first 20 bytes) and the Apple cdhashes attribute, all naming that digest, in DER
   canonical order and with no other attribute (no signing time or timestamp).
3. Signs the signed attributes with the distribution key (RSASSA-PKCS1-v1_5,
   SHA-256) and returns the signature.

At most one signature per approved bundle id per session (`stupid-app` settles the
signature size with a placeholder and signs once per bundle). Each signature's
bundle id and cdhashes go to `audit_events`. This keeps the endpoint from signing
arbitrary data.

## stupid-app changes (stupid-ios-dev)

Implemented (not yet released):

- `CMSSigner` in `NativeCMS`: the local key or a remote signer. Each returned
  signature is verified against the certificate's public key; a mismatch fails
  loudly.
- `STUPID_APP_RELEASE_SESSION`: every App Store Connect call goes to the session's
  `asc/v1` without a JWT, the team comes from `info`, and `release archive` signs
  through `sign` with only the certificate stored.
- `stupid-app signing fetch`: downloads the distribution certificate and the
  current App Store profiles. It never creates certificates or profiles.

## GitHub workflow

A reusable workflow in stupid-app's repository, versioned with the CLI. An app
repository calls it:

```yaml
jobs:
  testflight:
    uses: stephancill/stupid-app-cli/.github/workflows/testflight.yml@<version>
    permissions: { id-token: write, contents: write }
    secrets: inherit
```

Steps:

1. Install Swift, `stupid-app` and `stupid-app-macros` (a prebuilt runner image
   may hold these). Download the device SDK from stupid simulator's runtime store,
   the only place SDK bundles are published, cached with `actions/cache`.
2. Run the repository's pre-build hook for app-specific files from its own
   secrets, then `stupid-app build`.
3. Create a release session and wait for approval.
4. `stupid-app signing fetch`, `release new-build`, commit the build number,
   `release archive`, `release upload --wait`, all through the session.
5. Close the session in an `always()` step.

Manual trigger only (`workflow_dispatch`).

## Threat model additions

| Scenario | Exposure |
|---|---|
| Runner compromised during a session | Signatures and ASC requests for that session's apps until it closes; no keys |
| Repository compromised | A release session request; still needs the user's passkey approval |
| Another of the user's repositories compromised | Nothing for apps outside its policy |
| GitHub OIDC signing key compromised | Session requests for any policy; still need passkey approval |

## Order of work

1. stupid-app: remote signer, release sessions, `signing fetch` (implemented); release.
2. Broker: `apple-release` credential, policies and `/release-allow`, OIDC
   verification, release sessions, ASC proxy, signing endpoint, approval page,
   sweeper, tests, skill docs.
3. The reusable workflow, then the first app repository using it. The first run
   uploads to internal TestFlight only.

## Acceptance

- A workflow run uploads a build that reaches internal TestFlight, with one
  passkey approval.
- The archived IPA passes `codesign --verify --strict` on a Mac, and its
  signature matches one made locally with the same certificate.
- Requests for another app's id, a non-allowlisted path, or a CodeDirectory with
  an unapproved identifier are refused.
- Neither key appears in runner logs, the session responses or broker logs.
