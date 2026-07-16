#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

USER_AGENT = "permissions-broker-cli/1.0"
DEFAULT_BASE_URL = "https://permissions-broker.stupidtech.net"


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def usage() -> str:
    return """pb_proxy.py - curl-like broker proxy CLI

Usage:
  pb_proxy.py [pb options] [curl options] <upstream_url>

PB options:
  --pb-api-key <key>           Permissions Broker API key (default: $PB_API_KEY)
  --pb-timeout-seconds <n>     Approval polling timeout in seconds (default: 30)
  --pb-poll-interval <n>       Poll interval in seconds (default: 1)
  --pb-consent-hint <text>     Consent hint shown in Telegram
  --pb-idempotency-key <key>   Idempotency key for create request
  --pb-base-url <url>          Broker URL (default: https://permissions-broker.stupidtech.net)
  -h, --help                   Show this help

Curl options supported:
  -X, --request <method>
  -H, --header <key:value>     Repeatable
  -d, --data <value>           Repeatable (joined with '&')
  --data-raw <value>
  --data-binary <value>
  --data-ascii <value>
  --data-urlencode <value>
  -G, --get                    Put data into query string and force GET
  --url <upstream_url>

Ignored curl flags (accepted for compatibility):
  -s, -S, -L, --location, --compressed
"""


def pop_value(argv: list[str], i: int, flag: str) -> tuple[str, int]:
    if i + 1 >= len(argv):
        raise ValueError(f"missing value for {flag}")
    return argv[i + 1], i + 2


@dataclass
class PbConfig:
    api_key: str | None
    base_url: str
    timeout_seconds: float
    poll_interval_seconds: float
    consent_hint: str | None
    idempotency_key: str | None


@dataclass
class CurlInput:
    upstream_url: str
    method: str
    headers: dict[str, str]
    body: Any | None


def parse_pb_options(argv: list[str]) -> tuple[PbConfig, list[str]]:
    cfg = PbConfig(
        api_key=os.environ.get("PB_API_KEY"),
        base_url=os.environ.get("PB_BASE_URL", DEFAULT_BASE_URL),
        timeout_seconds=30,
        poll_interval_seconds=1,
        consent_hint=None,
        idempotency_key=None,
    )

    curl_args: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            print(usage())
            raise SystemExit(0)
        if arg == "--pb-api-key":
            cfg.api_key, i = pop_value(argv, i, arg)
            continue
        if arg == "--pb-timeout-seconds":
            v, i = pop_value(argv, i, arg)
            cfg.timeout_seconds = float(v)
            continue
        if arg == "--pb-poll-interval":
            v, i = pop_value(argv, i, arg)
            cfg.poll_interval_seconds = float(v)
            continue
        if arg == "--pb-consent-hint":
            cfg.consent_hint, i = pop_value(argv, i, arg)
            continue
        if arg == "--pb-idempotency-key":
            cfg.idempotency_key, i = pop_value(argv, i, arg)
            continue
        if arg == "--pb-base-url":
            cfg.base_url, i = pop_value(argv, i, arg)
            continue

        curl_args.append(arg)
        i += 1

    return cfg, curl_args


def parse_headers(raw_headers: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in raw_headers:
        if ":" not in item:
            raise ValueError(f"invalid header format (expected key:value): {item}")
        key, value = item.split(":", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"invalid empty header key: {item}")
        headers[key] = value.strip()

    headers.pop("authorization", None)
    headers.pop("Authorization", None)
    return headers


def parse_body(data_parts: list[str], headers: dict[str, str]) -> Any | None:
    if not data_parts:
        return None

    raw = "&".join(data_parts)
    content_type = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            content_type = v.lower()
            break

    if "application/json" in content_type or "+json" in content_type:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw

    return raw


def append_query(url: str, query_part: str) -> str:
    parts = urllib.parse.urlsplit(url)
    query = parts.query
    merged = f"{query}&{query_part}" if query else query_part
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, merged, parts.fragment)
    )


def parse_curl_args(argv: list[str]) -> CurlInput:
    if not argv:
        raise ValueError("missing curl arguments")

    method: str | None = None
    raw_headers: list[str] = []
    data_parts: list[str] = []
    force_get = False
    url: str | None = None

    ignored = {
        "-s",
        "-S",
        "-L",
        "--location",
        "--compressed",
    }
    data_flags = {
        "-d",
        "--data",
        "--data-raw",
        "--data-binary",
        "--data-ascii",
        "--data-urlencode",
    }

    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ignored:
            i += 1
            continue
        if arg in ("-X", "--request"):
            v, i = pop_value(argv, i, arg)
            method = v.upper().strip()
            continue
        if arg in ("-H", "--header"):
            v, i = pop_value(argv, i, arg)
            raw_headers.append(v)
            continue
        if arg in data_flags:
            v, i = pop_value(argv, i, arg)
            data_parts.append(v)
            continue
        if arg in ("-G", "--get"):
            force_get = True
            i += 1
            continue
        if arg == "--url":
            url, i = pop_value(argv, i, arg)
            continue
        if arg.startswith("http://") or arg.startswith("https://"):
            if url is not None:
                raise ValueError("multiple URLs provided")
            url = arg
            i += 1
            continue
        if arg.startswith("-"):
            raise ValueError(f"unsupported curl option: {arg}")

        if url is None:
            url = arg
            i += 1
            continue

        raise ValueError(f"unexpected positional argument: {arg}")

    if not url:
        raise ValueError("missing upstream URL")
    if not (url.startswith("https://") or url.startswith("http://")):
        raise ValueError("upstream URL must include scheme (https://...)")

    headers = parse_headers(raw_headers)

    if force_get and data_parts:
        url = append_query(url, "&".join(data_parts))
        data_parts = []

    final_method = method or ("POST" if data_parts else "GET")
    if force_get:
        final_method = "GET"

    body = parse_body(data_parts, headers)
    return CurlInput(upstream_url=url, method=final_method, headers=headers, body=body)


def http_json(
    method: str,
    url: str,
    api_key: str,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any], str]:
    data = None
    headers = {
        "authorization": f"Bearer {api_key}",
        "user-agent": USER_AGENT,
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["content-type"] = "application/json"

    req = urllib.request.Request(url=url, method=method, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            status = resp.getcode()
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as err:
        status = err.code
        raw = err.read().decode("utf-8", errors="replace")
    except Exception as err:
        raise RuntimeError(f"request failed: {method} {url}: {err}") from err

    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        parsed = {}

    return status, parsed, raw


def execute_request(base_url: str, api_key: str, request_id: str) -> tuple[int, bytes]:
    url = f"{base_url.rstrip('/')}/v1/proxy/requests/{request_id}/execute"
    headers = {
        "authorization": f"Bearer {api_key}",
        "user-agent": USER_AGENT,
    }
    req = urllib.request.Request(url=url, method="POST", headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()
    except Exception as err:
        raise RuntimeError(f"execute failed: {err}") from err


def main() -> int:
    try:
        pb_cfg, curl_args = parse_pb_options(sys.argv[1:])
        curl_in = parse_curl_args(curl_args)
    except ValueError as err:
        eprint(str(err))
        eprint("Run with --help for usage.")
        return 12
    except SystemExit as err:
        code = err.code
        if isinstance(code, int):
            return code
        return 0

    if not pb_cfg.api_key:
        eprint("missing API key: set PB_API_KEY or pass --pb-api-key")
        return 12

    consent_hint = pb_cfg.consent_hint
    if not consent_hint:
        u = urllib.parse.urlsplit(curl_in.upstream_url)
        consent_hint = f"{curl_in.method} {u.netloc}{u.path}"

    payload: dict[str, Any] = {
        "upstream_url": curl_in.upstream_url,
        "method": curl_in.method,
        "consent_hint": consent_hint,
    }
    if curl_in.headers:
        payload["headers"] = curl_in.headers
    if curl_in.body is not None:
        payload["body"] = curl_in.body
    if pb_cfg.idempotency_key:
        payload["idempotency_key"] = pb_cfg.idempotency_key

    create_url = f"{pb_cfg.base_url.rstrip('/')}/v1/proxy/request"
    try:
        create_http, create_json, create_raw = http_json(
            method="POST",
            url=create_url,
            api_key=pb_cfg.api_key,
            body=payload,
        )
    except RuntimeError as err:
        eprint(str(err))
        return 12

    if create_http != 200:
        if create_raw:
            sys.stdout.write(create_raw)
            if not create_raw.endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()
        else:
            eprint(f"create failed: http_status={create_http}")
        return 12

    request_id = str(create_json.get("request_id", ""))
    if not request_id:
        eprint("create failed: request_id missing in response")
        return 12

    status_url = f"{pb_cfg.base_url.rstrip('/')}/v1/proxy/requests/{request_id}"
    deadline = time.monotonic() + pb_cfg.timeout_seconds

    while True:
        try:
            _, status_json, status_raw = http_json(
                method="GET",
                url=status_url,
                api_key=pb_cfg.api_key,
            )
        except RuntimeError as err:
            eprint(str(err))
            return 12

        status = str(status_json.get("status", ""))
        if status == "APPROVED":
            break

        if time.monotonic() >= deadline:
            eprint(f"timed out waiting for approval: request_id={request_id}")
            return 10

        if status and status not in {"PENDING_APPROVAL", "EXECUTING"}:
            if status_raw:
                sys.stdout.write(status_raw)
                if not status_raw.endswith("\n"):
                    sys.stdout.write("\n")
                sys.stdout.flush()
            else:
                eprint(
                    f"request reached terminal status before execute: request_id={request_id} status={status}"
                )
            return 11

        time.sleep(max(pb_cfg.poll_interval_seconds, 0.1))

    try:
        execute_http, execute_body = execute_request(
            base_url=pb_cfg.base_url,
            api_key=pb_cfg.api_key,
            request_id=request_id,
        )
    except RuntimeError as err:
        eprint(str(err))
        return 12

    sys.stdout.buffer.write(execute_body)
    if execute_body and not execute_body.endswith(b"\n"):
        sys.stdout.buffer.write(b"\n")
    sys.stdout.flush()

    if execute_http >= 400:
        eprint(f"execute returned http_status={execute_http} request_id={request_id}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
