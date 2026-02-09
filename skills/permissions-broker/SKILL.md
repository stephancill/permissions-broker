---
name: permissions-broker
description: Interact with the Permissions Broker service to fetch data from Google APIs behind a Telegram approval gate. Use when an agent needs to read Google Drive/Docs/Sheets data via the broker (POST proxy request, wait for user approval in Telegram, poll for upstream response) and must respect one-time retrieval, host allowlist, and GET-only constraints.
---

# Permissions Broker

## Overview

Use the broker as a user-controlled proxy for data / action requests to external services e.g. Google Drive. You create an immutable request, prompt the user to approve in Telegram, then poll until you can retrieve the upstream response exactly once.

## Agent Response Style (Important)

When using this skill, do not lead with inability/disclaimer language like "I can't access your Google Drive" or "I can't do this from here".

Instead:

- Treat the broker as the standard mechanism for access.
- Ask for the minimum missing inputs (broker base URL + user API key) and then propose the exact upstream GET URL(s) you will request.
- Explain what the user will see in Telegram and what you will return after approval.

Avoid:

- Long meta explanations about the repo setup.
- Re-stating the full allowlist/constraints unless it directly affects the requested task.

Preferred framing:

- "I can do that via your Permissions Broker. I'll create a request for <upstream_url>, you approve in Telegram, then I'll fetch the result." 

## Polling Behavior (Important)

After creating a proxy request, always attempt to poll/await approval and execution for at least 30 seconds before returning control back to the user.

Guidelines:

- Default to 30 seconds of polling (or longer if the user explicitly asks you to wait).
- If approval has not happened within that window, return the request_id and clear instructions to approve in Telegram, and continue polling on the next user message.
- If approval happens quickly, return the upstream result in the same response.

## Core Workflow

1. Collect inputs

- User API key (never paste into logs; never store in repo)

2. Create a proxy request

- Call `POST /v1/proxy/request` with:
  - `upstream_url`: the full external service API URL you want to call
  - optional `consent_hint`: plain-language reason for the user
  - optional `idempotency_key`: reuse request id on retries

3. Ask the user to approve

- Tell the user to approve the request in Telegram.
- The approval prompt includes:
  - API key label (trusted identity)
  - interpreted summary when recognized
  - raw URL details

4. Poll for status / retrieve result

- Poll `GET /v1/proxy/requests/:id` until terminal.
- If you receive the upstream response (HTTP 200/4xx/etc) you must parse and persist what you need immediately.
- Do not assume you can fetch the same result again: the broker consumes results on first retrieval.

## Sample Code (Create + Await)

Use these snippets to create a broker request and poll until you can retrieve the upstream response.

JavaScript/TypeScript (Bun/Node)

```ts
type CreateRequestResponse = {
  request_id: string;
  status: string;
  approval_expires_at: string;
};

async function createBrokerRequest(params: {
  baseUrl: string;
  apiKey: string;
  upstreamUrl: string;
  consentHint?: string;
  idempotencyKey?: string;
}): Promise<CreateRequestResponse> {
  const res = await fetch(`${params.baseUrl}/v1/proxy/request`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${params.apiKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      upstream_url: params.upstreamUrl,
      consent_hint: params.consentHint,
      idempotency_key: params.idempotencyKey,
    }),
  });

  if (!res.ok) {
    throw new Error(`broker create failed: ${res.status} ${await res.text()}`);
  }

  return (await res.json()) as CreateRequestResponse;
}

async function awaitBrokerResult(params: {
  baseUrl: string;
  apiKey: string;
  requestId: string;
  timeoutMs?: number;
}): Promise<Response> {
  // Recommended default: wait at least 30s before returning a request_id to the user.
  const deadline = Date.now() + (params.timeoutMs ?? 30_000);

  while (Date.now() < deadline) {
    const res = await fetch(`${params.baseUrl}/v1/proxy/requests/${params.requestId}`, {
      headers: { authorization: `Bearer ${params.apiKey}` },
    });

    if (res.status === 202) {
      await new Promise((r) => setTimeout(r, 1000));
      continue;
    }

    // Terminal: may be upstream bytes (200) or broker error JSON (403/408/410/etc).
    // IMPORTANT: On SUCCEEDED the broker response is one-time. Read and store what you need now.
    return res;
  }

  throw new Error("timed out waiting for approval/execution");
}

// Suggested control flow:
// - Start polling for ~30 seconds.
// - If still pending, return a user-facing message with request_id and what to approve.
// - On the next user message, poll again (or recreate if expired/consumed).

// Example usage
// const baseUrl = "https://permissions-broker.steer.fun"
// const apiKey = process.env.PB_API_KEY!
// const upstreamUrl = "https://www.googleapis.com/drive/v3/files?pageSize=5&fields=files(id,name)"
// const created = await createBrokerRequest({ baseUrl, apiKey, upstreamUrl, consentHint: "List a few Drive files." })
// Tell user: approve request in Telegram
// const terminalRes = await awaitBrokerResult({ baseUrl, apiKey, requestId: created.request_id })
// const bodyText = await terminalRes.text()
```

Python (requests)

```py
import time
import requests

def create_request(base_url, api_key, upstream_url, consent_hint=None, idempotency_key=None):
  r = requests.post(
    f"{base_url}/v1/proxy/request",
    headers={"Authorization": f"Bearer {api_key}"},
    json={
      "upstream_url": upstream_url,
      "consent_hint": consent_hint,
      "idempotency_key": idempotency_key,
    },
    timeout=30,
  )
  r.raise_for_status()
  return r.json()

def await_result(base_url, api_key, request_id, timeout_s=120):
  deadline = time.time() + timeout_s
  while time.time() < deadline:
    r = requests.get(
      f"{base_url}/v1/proxy/requests/{request_id}",
      headers={"Authorization": f"Bearer {api_key}"},
      timeout=30,
    )
    if r.status_code == 202:
      time.sleep(1)
      continue

    # Terminal response. IMPORTANT: on success this is one-time; read and store now.
    return r

  raise TimeoutError("timed out waiting for approval/execution")
```

## Constraints You Must Respect

- Upstream method: GET only.
- Upstream scheme: HTTPS only.
- Upstream host allowlist: `docs.googleapis.com` and `www.googleapis.com`.
- Upstream response size cap: 1 MiB.
- Result cache TTL: short-lived; results can expire if not retrieved quickly.
- One-time retrieval: on success, the broker consumes the cached response; subsequent polls return 410.

## Sheets Note (Without Drama)

The broker only allows upstream GET requests to `www.googleapis.com` and `docs.googleapis.com`. The Google Sheets API host (`sheets.googleapis.com`) is not reachable in MVP.

If the user asks for something that would normally use Sheets API:

- Use Drive search/list to find the spreadsheet file.
- Use Drive export to fetch its contents as CSV.
- Parse the CSV to extract the needed values.

## Handling Common Terminal States

- 202: still pending (approval/execution). Keep polling.
- 403: denied by user.
- 408: approval expired (user did not decide in time).
- 410: result consumed or expired; recreate the request if you still need it.

## How To Build Upstream URLs (Google example)

Prefer narrow reads so approvals are understandable and responses are small.

- Drive search/list files: `https://www.googleapis.com/drive/v3/files?...`
  - Use `q`, `pageSize`, and `fields` to minimize payload.
- Drive export file contents: `https://www.googleapis.com/drive/v3/files/{fileId}/export?mimeType=...`
  - Useful for Google Docs/Sheets export to `text/plain` or `text/csv`.
- Docs structured doc read: `https://docs.googleapis.com/v1/documents/{documentId}?fields=...`

See `references/api_reference.md` for endpoint details and a Google URL cheat sheet.

## Data Handling Rules

- Treat the user's API key as secret.

## Resources

- Reference: `references/api_reference.md`
