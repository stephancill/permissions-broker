#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

DEFAULT_BASE_URL = "https://permissions-broker.stupidtech.net"
USER_AGENT = "permissions-broker-git-cli/1.0"
SUPPORTED = {"clone", "fetch", "pull", "push"}


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def usage() -> str:
    return """pb_git.py - git-like CLI via Permissions Broker

Usage:
  pb_git.py [pb options] <clone|fetch|pull|push> [git args...]

PB options:
  --pb-api-key <key>           Permissions Broker API key (default: $PB_API_KEY)
  --pb-base-url <url>          Broker base URL (default: https://permissions-broker.stupidtech.net)
  --pb-timeout-seconds <n>     Approval polling timeout in seconds (default: 90)
  --pb-poll-interval <n>       Poll interval in seconds (default: 1)
  --pb-consent-hint <text>     Consent hint shown in Telegram

Examples:
  pb_git.py clone https://github.com/OWNER/REPO.git
  pb_git.py fetch origin --prune
  pb_git.py pull origin main
  pb_git.py push origin HEAD:refs/heads/my-branch
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


def parse_pb_options(argv: list[str]) -> tuple[PbConfig, list[str]]:
    cfg = PbConfig(
        api_key=os.environ.get("PB_API_KEY"),
        base_url=os.environ.get("PB_BASE_URL", DEFAULT_BASE_URL),
        timeout_seconds=90,
        poll_interval_seconds=1,
        consent_hint=None,
    )

    rest: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-h", "--help"):
            print(usage())
            raise SystemExit(0)
        if arg == "--pb-api-key":
            cfg.api_key, i = pop_value(argv, i, arg)
            continue
        if arg == "--pb-base-url":
            cfg.base_url, i = pop_value(argv, i, arg)
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
        rest.append(arg)
        i += 1

    return cfg, rest


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


def parse_github_repo(s: str) -> str | None:
    s = s.strip()
    m = re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", s)
    if m:
        return s

    if s.startswith("https://") or s.startswith("http://"):
        u = urllib.parse.urlsplit(s)
        if u.hostname != "github.com":
            return None
        p = u.path.strip("/")
        if p.endswith(".git"):
            p = p[:-4]
        if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", p):
            return p
        return None

    m = re.match(r"^git@github\.com:([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:\.git)?$", s)
    if m:
        return m.group(1)

    return None


def git_output(args: list[str]) -> str:
    cp = subprocess.run(["git", *args], check=True, capture_output=True, text=True)
    return cp.stdout.strip()


def infer_repo_for_clone(git_args: list[str]) -> tuple[str, int]:
    for idx, a in enumerate(git_args):
        if a.startswith("-"):
            continue
        repo = parse_github_repo(a)
        if repo:
            return repo, idx
        raise ValueError(f"unsupported clone repo target: {a}")
    raise ValueError("clone requires repository argument")


def infer_repo_for_existing_repo(
    subcommand: str, git_args: list[str]
) -> tuple[str, int | None]:
    remote_name_or_url: str | None = None
    for a in git_args:
        if a.startswith("-"):
            continue
        remote_name_or_url = a
        break

    if not remote_name_or_url:
        remote_name_or_url = "origin"

    repo = parse_github_repo(remote_name_or_url)
    if repo:
        remote_index = next(
            (i for i, a in enumerate(git_args) if a == remote_name_or_url),
            None,
        )
        return repo, remote_index

    try:
        remote_url = git_output(["remote", "get-url", remote_name_or_url])
    except subprocess.CalledProcessError as err:
        raise ValueError(
            f"cannot resolve remote '{remote_name_or_url}' for {subcommand}"
        ) from err

    repo = parse_github_repo(remote_url)
    if not repo:
        raise ValueError(
            f"remote '{remote_name_or_url}' is not a supported GitHub repo URL"
        )

    remote_index = next(
        (i for i, a in enumerate(git_args) if a == remote_name_or_url),
        None,
    )
    return repo, remote_index


def create_git_session(cfg: PbConfig, operation: str, repo: str) -> str:
    url = f"{cfg.base_url.rstrip('/')}/v1/git/sessions"
    consent = cfg.consent_hint or f"{operation} {repo} via broker git proxy"
    payload = {
        "operation": operation,
        "repo": repo,
        "consent_hint": consent,
    }

    status, data, raw = http_json("POST", url, cfg.api_key or "", payload)
    if status != 200:
        if raw:
            sys.stdout.write(raw)
            if not raw.endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()
        raise RuntimeError(f"failed to create git session (http {status})")

    sid = str(data.get("session_id", ""))
    if not sid:
        raise RuntimeError("git session response missing session_id")
    return sid


def wait_for_approval(cfg: PbConfig, session_id: str) -> None:
    url = f"{cfg.base_url.rstrip('/')}/v1/git/sessions/{session_id}"
    deadline = time.monotonic() + cfg.timeout_seconds

    while True:
        _, data, raw = http_json("GET", url, cfg.api_key or "")
        status = str(data.get("status", ""))
        if status == "APPROVED":
            return
        if status in {"DENIED", "EXPIRED", "USED", "FAILED"}:
            if raw:
                sys.stdout.write(raw)
                if not raw.endswith("\n"):
                    sys.stdout.write("\n")
                sys.stdout.flush()
            raise RuntimeError(f"git session terminal status: {status}")
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"timed out waiting for approval: session_id={session_id}"
            )
        time.sleep(max(cfg.poll_interval_seconds, 0.1))


def get_remote_url(cfg: PbConfig, session_id: str) -> str:
    url = f"{cfg.base_url.rstrip('/')}/v1/git/sessions/{session_id}/remote"
    status, data, raw = http_json("GET", url, cfg.api_key or "")
    if status != 200:
        if raw:
            sys.stdout.write(raw)
            if not raw.endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()
        raise RuntimeError(f"failed to get broker remote URL (http {status})")

    remote_url = str(data.get("remote_url", ""))
    if not remote_url:
        raise RuntimeError("remote endpoint missing remote_url")
    return remote_url


def run_git_clone(remote_url: str, original_args: list[str], repo_index: int) -> int:
    args = original_args[:]
    args[repo_index] = remote_url
    return subprocess.run(["git", "clone", *args]).returncode


def run_git_existing(
    subcommand: str, remote_url: str, original_args: list[str], remote_index: int | None
) -> int:
    args = original_args[:]
    if remote_index is None:
        args = [remote_url, *args]
    else:
        args[remote_index] = remote_url
    return subprocess.run(["git", subcommand, *args]).returncode


def main() -> int:
    try:
        cfg, rest = parse_pb_options(sys.argv[1:])
    except ValueError as err:
        eprint(str(err))
        return 12
    except SystemExit as err:
        code = err.code
        if isinstance(code, int):
            return code
        return 0

    if not cfg.api_key:
        eprint("missing API key: set PB_API_KEY or pass --pb-api-key")
        return 12
    if not rest:
        eprint("missing git subcommand")
        eprint("Run with --help for usage.")
        return 12

    subcommand = rest[0]
    if subcommand not in SUPPORTED:
        eprint(f"unsupported subcommand: {subcommand}")
        eprint("supported: clone, fetch, pull, push")
        return 12

    git_args = rest[1:]

    try:
        if subcommand == "clone":
            repo, repo_index = infer_repo_for_clone(git_args)
            remote_index = repo_index
        else:
            repo, remote_index = infer_repo_for_existing_repo(subcommand, git_args)

        session_id = create_git_session(cfg, subcommand, repo)
        wait_for_approval(cfg, session_id)
        remote_url = get_remote_url(cfg, session_id)

        if subcommand == "clone":
            return run_git_clone(remote_url, git_args, remote_index)
        return run_git_existing(subcommand, remote_url, git_args, remote_index)
    except TimeoutError as err:
        eprint(str(err))
        return 10
    except ValueError as err:
        eprint(str(err))
        return 12
    except RuntimeError as err:
        eprint(str(err))
        return 12


if __name__ == "__main__":
    raise SystemExit(main())
