#!/usr/bin/env python3
"""Sign in to stupid vault and manage the stored credential.

The credential (broker URL + API key) lives in one JSON file that vault_proxy.py
and vault_git.py read. `login` obtains it with the OAuth 2.0 Device
Authorization Grant (RFC 8628): it prints a code, the user approves it in the
app, and the broker issues a new API key.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_BASE_URL = "https://vault.stupidtech.net"
CLIENT_ID = "stupid-vault-cli"
USER_AGENT = "stupid-vault-cli/1.0"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def default_credentials_path() -> Path:
    config_home = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(config_home) / "stupid-vault" / "credentials.json"


@dataclass
class Credentials:
    base_url: str
    api_key: str
    label: str | None


class CredentialsError(Exception):
    pass


def load_credentials(path: Path | None) -> Credentials:
    """Load the stored credential; raises CredentialsError with a next step."""
    p = path or default_credentials_path()
    if not p.exists():
        raise CredentialsError(
            f"not signed in: no credentials at {p}. "
            f"Run: python3 {Path(__file__).resolve()} login"
        )
    try:
        data = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as err:
        raise CredentialsError(f"unreadable credentials file {p}: {err}") from err
    base_url = data.get("base_url")
    api_key = data.get("api_key")
    if not isinstance(base_url, str) or not isinstance(api_key, str) or not api_key:
        raise CredentialsError(
            f"invalid credentials file {p}: expected base_url and api_key"
        )
    label = data.get("label")
    return Credentials(
        base_url=base_url.rstrip("/"),
        api_key=api_key,
        label=label if isinstance(label, str) else None,
    )


def save_credentials(path: Path, creds: Credentials) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    payload = json.dumps(
        {"base_url": creds.base_url, "api_key": creds.api_key, "label": creds.label},
        indent=2,
    )
    # Write 0600 from the start, then rename into place atomically.
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".credentials.")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(payload + "\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def post_form(url: str, fields: dict[str, str]) -> tuple[int, dict[str, Any]]:
    data = urllib.parse.urlencode(fields).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        method="POST",
        data=data,
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "accept": "application/json",
            "user-agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status, raw = resp.getcode(), resp.read()
    except urllib.error.HTTPError as err:
        status, raw = err.code, err.read()
    except Exception as err:
        raise RuntimeError(f"request failed: POST {url}: {err}") from err
    try:
        parsed = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        parsed = {}
    return status, parsed if isinstance(parsed, dict) else {}


def default_label() -> str:
    host = socket.gethostname().split(".")[0] or "cli"
    return f"agent on {host}"[:64]


def usage() -> str:
    return f"""vault_auth.py - sign in to stupid vault

Usage:
  vault_auth.py login [--label <text>] [--base-url <url>] [--force]
  vault_auth.py status
  vault_auth.py logout
  vault_auth.py base-url    Print the broker URL of the stored credential
  vault_auth.py header      Print the Authorization header line, for raw
                            calls: curl -H @<(vault_auth.py header) ...

Options:
  --credentials <path>      Credentials file (default: {default_credentials_path()})
  --base-url <url>          Broker URL for login (default: {DEFAULT_BASE_URL})
  --label <text>            Suggested API key label (user can edit it on approval)
  --force                   Replace an existing credential on login

login prints a URL and code; the user approves it in the app, then the new
API key is saved to the credentials file (mode 0600).

Exit codes: 0 ok, 10 code expired, 11 denied, 12 error.
"""


def cmd_login(path: Path, base_url: str, label: str | None, force: bool) -> int:
    if path.exists() and not force:
        eprint(f"already signed in ({path}); pass --force to replace it")
        return 12

    base = base_url.rstrip("/")
    status, auth = post_form(
        f"{base}/v1/device/authorize",
        {"client_id": CLIENT_ID, "label": label or default_label()},
    )
    if status != 200 or "device_code" not in auth:
        eprint(f"device authorization failed: http_status={status} body={auth}")
        return 12

    eprint("To sign in, open this URL and approve with your passkey:")
    eprint(f"  {auth['verification_uri_complete']}")
    eprint(f"Confirm the code shown there is: {auth['user_code']}")
    sys.stderr.flush()

    interval = float(auth.get("interval", 5))
    deadline = time.monotonic() + float(auth.get("expires_in", 600))
    while time.monotonic() < deadline:
        time.sleep(interval)
        status, tok = post_form(
            f"{base}/v1/device/token",
            {"grant_type": DEVICE_GRANT, "device_code": str(auth["device_code"])},
        )
        if status == 200 and tok.get("access_token"):
            creds = Credentials(
                base_url=base,
                api_key=str(tok["access_token"]),
                label=str(tok.get("api_key_label") or "") or None,
            )
            save_credentials(path, creds)
            eprint(f"signed in as API key {creds.label!r}; saved to {path}")
            return 0
        error = tok.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval += 5
            continue
        if error == "access_denied":
            eprint(f"sign-in denied: {tok.get('error_description', 'denied in the app')}")
            return 11
        if error == "expired_token":
            break
        eprint(f"sign-in failed: http_status={status} body={tok}")
        return 12

    eprint("the code expired before it was approved; run login again")
    return 10


def cmd_status(path: Path) -> int:
    creds = load_credentials(path)
    req = urllib.request.Request(
        url=f"{creds.base_url}/v1/whoami",
        headers={"authorization": f"Bearer {creds.api_key}", "user-agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            who = json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", errors="replace")
        eprint(f"stored key rejected by {creds.base_url}: http_status={err.code} {body}")
        eprint(f"Run: python3 {Path(__file__).resolve()} login --force")
        return 12
    print(
        json.dumps(
            {
                "credentials": str(path),
                "base_url": creds.base_url,
                "api_key_label": who.get("api_key_label"),
            }
        )
    )
    return 0


def cmd_header(path: Path) -> int:
    creds = load_credentials(path)
    print(f"Authorization: Bearer {creds.api_key}")
    return 0


def cmd_base_url(path: Path) -> int:
    print(load_credentials(path).base_url)
    return 0


def cmd_logout(path: Path) -> int:
    if not path.exists():
        eprint(f"not signed in ({path} does not exist)")
        return 0
    path.unlink()
    eprint(f"removed {path}. The key stays valid until you revoke it in the app (API keys).")
    return 0


COMMANDS = ("login", "status", "logout", "base-url", "header")


def main() -> int:
    argv = sys.argv[1:]
    path: Path | None = None
    base_url = DEFAULT_BASE_URL
    label: str | None = None
    force = False
    rest: list[str] = []
    i = 0
    try:
        while i < len(argv):
            arg = argv[i]
            if arg in ("-h", "--help"):
                print(usage())
                return 0
            if arg in ("--credentials", "--base-url", "--label"):
                if i + 1 >= len(argv):
                    raise ValueError(f"missing value for {arg}")
                value = argv[i + 1]
                if arg == "--credentials":
                    path = Path(value).expanduser()
                elif arg == "--base-url":
                    base_url = value
                else:
                    label = value
                i += 2
                continue
            if arg == "--force":
                force = True
                i += 1
                continue
            rest.append(arg)
            i += 1
        if len(rest) != 1 or rest[0] not in COMMANDS:
            raise ValueError(f"expected one command: {', '.join(COMMANDS)}")
    except ValueError as err:
        eprint(str(err))
        eprint("Run with --help for usage.")
        return 12

    cred_path = path or default_credentials_path()
    try:
        if rest[0] == "login":
            return cmd_login(cred_path, base_url, label, force)
        if rest[0] == "status":
            return cmd_status(cred_path)
        if rest[0] == "header":
            return cmd_header(cred_path)
        if rest[0] == "base-url":
            return cmd_base_url(cred_path)
        return cmd_logout(cred_path)
    except (CredentialsError, RuntimeError) as err:
        eprint(str(err))
        return 12


if __name__ == "__main__":
    raise SystemExit(main())
