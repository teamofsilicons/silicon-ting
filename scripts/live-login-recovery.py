#!/usr/bin/env python3
"""Verify login recovery after the IAM SLT window, then revoke the test session.

Uses the official IAM CLI's current production login unless --slt-file supplies a
fresh ting SLT (plain text or IAM's {"slt": ..., "expires_in": ...} JSON).
Credentials stay in captured subprocess output, memory, and a private recovery
file deleted only after confirmed logout; reports contain no tokens, idempotency
keys, request bodies, or actor IDs. This captures the original
response privately as a comparison/cleanup oracle; it does not inject packet loss.
"""
import argparse
import datetime
import http.client
import ipaddress
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import time
import uuid
from urllib.parse import urlsplit


class CheckFailed(Exception):
    """Only fixed, non-sensitive check labels may be used as messages."""


def require(condition, label):
    if not condition:
        raise CheckFailed(label)


def origin(value):
    parsed = urlsplit(value)
    loopback = parsed.hostname == "localhost"
    try:
        loopback |= ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        pass
    require(bool(parsed.hostname) and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment and parsed.path in ("", "/")
            and (parsed.scheme == "https" or (parsed.scheme == "http" and loopback))
            and parsed.port != 0, "invalid_service_origin")
    return parsed


def load_slt(path):
    if path:
        path = pathlib.Path(path)
        require(stat.S_ISREG(path.stat().st_mode), "slt_file_not_regular")
        require(not path.stat().st_mode & 0o077, "slt_file_must_be_private")
        with path.open("rb") as source:
            raw = source.read(16385)
        require(len(raw) <= 16384, "slt_file_too_large")
    else:
        result = subprocess.run(
            ["iam", "login", "--app-id", "ting", "--grant-org", "tos",
             "--approve-scopes", "--json"],
            capture_output=True, stdin=subprocess.DEVNULL, timeout=90, check=False,
        )
        require(result.returncode == 0, "iam_login_failed")
        raw = result.stdout
    text = raw.decode("utf-8").strip()
    # The official CLI prints ShortLivedToken directly, without a data envelope.
    if text.startswith("{"):
        payload = json.loads(text)
        token = payload.get("slt")
        if "expires_in" in payload:
            require(isinstance(payload["expires_in"], int)
                    and 0 < payload["expires_in"] <= 120, "unexpected_slt_lifetime")
    else:
        require(bool(path), "iam_login_not_json")
        token = text
    require(isinstance(token, str) and 0 < len(token) <= 8192
            and not any(character.isspace() for character in token), "invalid_slt_shape")
    return token


def request(target, method, path, body=None, headers=None):
    connection_class = (http.client.HTTPSConnection if target.scheme == "https"
                        else http.client.HTTPConnection)
    connection = connection_class(target.hostname, target.port, timeout=35)
    try:
        connection.request(method, path, body=body, headers={
            "Content-Type": "application/json", "User-Agent": "silicon-ting-login-recovery/1",
            **(headers or {}),
        })
        response = connection.getresponse()
        raw = response.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "response_too_large")
        # http.client never follows a redirect carrying the SLT or session token.
        return response.status, json.loads(raw) if raw else None
    finally:
        connection.close()


def persist_recovery(path, attempt):
    """Atomically replace a mode-600 file inside its private mode-700 directory."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".pending-", delete=False) as output:
            temporary = pathlib.Path(output.name)
            os.fchmod(output.fileno(), 0o600)
            json.dump(attempt, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run(args):
    report = {
        "test": "login_recovery_after_slt_expiry",
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "verification": "captured_response_oracle",
        "packet_loss_injected": False,
        "requested_delay_seconds": args.delay,
        "statuses": {}, "checks": {}, "cleanup_attempted": False, "passed": False,
    }
    session = None
    recovery_headers = None
    raw = None
    target = None
    recovery_file = None
    attempt = None
    login_attempted = False

    def capture_session(payload):
        nonlocal session
        if isinstance(payload, dict) and isinstance(payload.get("session_token"), str):
            session = payload["session_token"]
            attempt["session_token"] = session
            persist_recovery(recovery_file, attempt)

    def call(label, method, path, body=None, headers=None):
        status, payload = request(target, method, path, body, headers)
        report["statuses"][label] = status
        return status, payload

    def compare(label, expected, actual):
        report["checks"][label] = expected == actual
        require(report["checks"][label], label)

    try:
        require(args.delay >= 125, "delay_must_be_at_least_125_seconds")
        target = origin(args.url)
        report["url"] = target.geturl().rstrip("/")
        status, health = call("health", "GET", "/healthz")
        require(status == 200 and isinstance(health, dict), "health_failed")
        version = health.get("version", "")
        require(isinstance(version, str) and bool(re.fullmatch(
            r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]{1,50})?", version)), "health_version_invalid")
        report["server_version"] = version
        slt = load_slt(args.slt_file)
        raw = json.dumps({"slt": slt}, separators=(",", ":")).encode()
        recovery_headers = {"Idempotency-Key": str(uuid.uuid4())}
        recovery_directory = pathlib.Path(tempfile.mkdtemp(prefix="ting-login-recovery-"))
        os.chmod(recovery_directory, 0o700)
        recovery_file = recovery_directory / "attempt.json"
        attempt = {"url": report["url"], "created_at": report["started_at"],
                   "method": "POST", "path": "/v1/session", "body_utf8": raw.decode(),
                   "idempotency_key": recovery_headers["Idempotency-Key"]}
        persist_recovery(recovery_file, attempt)
        login_attempted = True
        status, original = call("login", "POST", "/v1/session", raw, recovery_headers)
        capture_session(original)
        require(status == 201, "login_not_created")
        require(isinstance(session, str) and session.startswith("ting_"), "login_missing_session")
        accepted_at = time.monotonic()
        status, immediate = call("immediate_recovery", "POST", "/v1/session", raw, recovery_headers)
        require(status == 200, "immediate_recovery_failed")
        compare("immediate_result_identical", original, immediate)
        # A deliberately invalid different value tests the conflict without minting/burning another SLT.
        changed = json.dumps({"slt": "invalid-conflict-probe-" + uuid.uuid4().hex}).encode()
        status, _ = call("changed_body", "POST", "/v1/session", changed, recovery_headers)
        require(status == 409, "changed_body_not_conflict")
        remaining = args.delay - (time.monotonic() - accepted_at)
        while remaining > 0:
            time.sleep(min(remaining, 5))
            remaining = args.delay - (time.monotonic() - accepted_at)
        report["elapsed_since_login_seconds"] = round(time.monotonic() - accepted_at, 3)
        status, delayed = call("delayed_recovery", "POST", "/v1/session", raw, recovery_headers)
        require(status == 200, "delayed_recovery_failed")
        compare("delayed_result_identical", original, delayed)
        status, _ = call("original_session_me", "GET", "/v1/me", headers={"Authorization": "Bearer " + session})
        require(status == 200, "original_session_not_active")
        report["passed"] = True
    except KeyboardInterrupt:
        report["failure"] = "interrupted"
    except CheckFailed as error:
        report["failure"] = str(error)
    except Exception:
        # Never print exceptions from IAM, JSON bodies, networking, or private file reads.
        report["failure"] = "dependency_or_input_error"
    finally:
        try:
            if session is None and login_attempted:
                # A transport failure might have hidden the first response. Recover only the same operation for cleanup.
                status, recovered = call("cleanup_recovery", "POST", "/v1/session", raw, recovery_headers)
                if status in (200, 201):
                    capture_session(recovered)
            if isinstance(session, str):
                report["cleanup_attempted"] = True
                auth = {"Authorization": "Bearer " + session}
                status, _ = call("logout", "DELETE", "/v1/session", headers=auth)
                require(status == 200, "cleanup_logout_failed")
                status, _ = call("revoked_session_me", "GET", "/v1/me", headers=auth)
                require(status == 401, "cleanup_session_still_active")
                report["checks"]["created_session_revoked"] = True
                recovery_file.unlink()
                recovery_file.parent.rmdir()
            elif login_attempted:
                report["cleanup_unconfirmed"] = True
                report["passed"] = False
        except Exception:
            report["cleanup_unconfirmed"] = True
            report["passed"] = False
        if recovery_file is not None:
            if recovery_file.exists():
                report["private_recovery_file"] = str(recovery_file)
            elif recovery_file.parent.exists():
                report["private_recovery_directory"] = str(recovery_file.parent)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://backend.ting.teamofsilicons.com")
    parser.add_argument("--output", type=pathlib.Path, help="Write the same sanitized JSON report to this path")
    parser.add_argument("--delay", type=int, default=125, help="Real seconds after original login, at least 125")
    parser.add_argument("--slt-file", help="Private file containing a fresh ting SLT; otherwise run official IAM login")
    args = parser.parse_args()
    report = run(args)
    if args.output:
        try:
            args.output.write_text(json.dumps(report, indent=2) + "\n")
        except OSError:
            report["report_write_failed"] = True
            report["passed"] = False
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
