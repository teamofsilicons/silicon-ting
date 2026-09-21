#!/usr/bin/env python3
"""Real HTTP/WS checks in one isolated IAM environment; never uses production identity.

Run: python -m pip install requests websocket-client
     python scripts/live-test.py --fixture deploy/private/live-test.json
Fixture fields: environment_id, testing_key, ting_app_secret, sender_app_id,
sender_app_secret, actor_id, org_id; optional api_url and iam_url.
The official IAM CLI must know this environment key (`iam env key <UUID>`).
The fixture's org/app/actor must already exist and scopes must be approved.
Only test context records are created; credentials and proofs are never printed.
"""
import argparse
import concurrent.futures
import json
import pathlib
import subprocess
import sys
import time
import uuid
from urllib.parse import quote

import requests
import websocket


def encode(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def key():
    return str(uuid.uuid4())


class Checks:
    def __init__(self, fixture):
        self.f = fixture
        assert uuid.UUID(fixture["environment_id"]).int, "A real testing environment UUID is required"
        assert len(fixture["testing_key"]) == 32
        self.api = fixture.get("api_url", "https://backend.ting.teamofsilicons.com").rstrip("/")
        self.test = {"IAM_TEST_APP_SECRET": fixture["ting_app_secret"],
                     "X-Testing-Environment-Key": fixture["testing_key"]}
        self.session = None
        self.passed = []
        self.org = fixture["org_id"]
        self.app = fixture["sender_app_id"]
        self.actor = fixture["actor_id"]
        self.prefix = f"/v1/orgs/{quote(self.org, safe='')}"
        self.type = self.app + ".release.check"
        self.subject = self.iam("app", "token", "exchange", self.app,
                                "--app-secret", fixture["sender_app_secret"], "--slt", self.actor)["access_token"]

    def iam(self, *args, stdin=None):
        cmd = ["iam", "--test", self.f["environment_id"], "--json"]
        if self.f.get("iam_url"):
            cmd += ["--url", self.f["iam_url"]]
        result = subprocess.run(cmd + list(args), input=stdin, capture_output=True)
        if result.returncode:
            # Do not include command arguments or raw error output, which could contain credentials.
            raise AssertionError(f"Official IAM CLI operation failed with exit {result.returncode}: {' '.join(args[:3])}")
        return json.loads(result.stdout)

    def proof(self, path, raw):
        endpoint = {"/v1/tings": "tings.send", "/v1/subscriptions": "subscriptions.register",
                    "/v1/subscriptions/query": "subscriptions.query", "/v1/subscriptions/revoke": "subscriptions.revoke",
                    "/v1/sent/query": "sent.query"}[path]
        return self.iam("app", "obo", "exchange", "tos>ting", endpoint,
                        "--as-app-id", self.app, "--app-secret", self.f["sender_app_secret"],
                        "--subject-token", self.subject, "--org-context", self.org,
                        "--method", "POST", "--body-file", "-", stdin=raw)["access_proof"]

    def http(self, method, path, body=None, *, raw=None, token=None, expected=200, extra=None, test=True):
        headers = {"Content-Type": "application/json"}
        if test:
            headers.update(self.test)
        if token or self.session:
            headers["Authorization"] = "Bearer " + (token or self.session)
        headers.update(extra or {})
        response = requests.request(method, self.api + path, headers=headers,
                                    data=raw if raw is not None else encode(body) if body is not None else None,
                                    timeout=35)
        try:
            value = response.json()
        except ValueError:
            raise AssertionError(f"{method} {path.split('?')[0]} returned non-JSON status {response.status_code}")
        allowed = [expected] if isinstance(expected, int) else expected
        assert response.status_code in allowed, (method, path.split('?')[0], response.status_code, value.get("error", {}).get("code"))
        return response.status_code, value

    def app_call(self, path, body, expected=200):
        raw = encode(body)
        return self.http("POST", path, raw=raw, token=self.proof(path, raw), expected=expected)

    def mark(self, label):
        self.passed.append(label)
        print("PASS", label, flush=True)

    def send(self, *, business_key=None, data=None):
        return {"org_id": self.org, "type": self.type, "for": self.actor,
                "data": data or {"run": self.run}, "metadata": {}, "key": business_key or key()}

    def socket(self):
        sock = websocket.create_connection(self.api.replace("https://", "wss://").replace("http://", "ws://") + "/v1/ws?protocol=v1",
                                           timeout=20, suppress_origin=True)
        ready = json.loads(sock.recv())
        assert ready["op"] == "ready"
        return Socket(sock, ready["receiver_id"])

    def run_checks(self):
        self.run = key()
        _, info = self.http("GET", "/v1/iam", test=False)
        assert info["app_id"] == "tos>ting"
        self.http("POST", "/v1/tings", body=self.send(), token="invalid-proof", expected=401)
        self.http("POST", "/v1/tings", raw=b'{"org_id":"a","org_id":"b"}', token="invalid-proof", expected=400)
        self.http("POST", "/v1/tings", body=self.send(), token="invalid-proof", extra={"IAM_TEST_APP_SECRET": ""}, expected=(400, 401, 403))
        self.mark("unauthenticated calls, duplicate keys and incomplete test context fail closed")

        # IAM's documented actor-ID shortcut is accepted only with the verified test key and app secret.
        exchange = {"slt": self.actor}
        attempt = key()
        _, signed = self.http("POST", "/v1/session", exchange, extra={"Idempotency-Key": attempt}, expected=201)
        self.session = signed["session_token"]
        _, replay = self.http("POST", "/v1/session", exchange, extra={"Idempotency-Key": attempt})
        assert signed == replay and signed["id"] == self.actor
        self.http("POST", "/v1/session", {"slt": "changed"}, extra={"Idempotency-Key": attempt}, expected=409)
        self.http("GET", "/v1/me", test=False)
        self.mark("test login, encrypted session reuse and idempotent SLT exchange")

        types = self.prefix + "/apps/" + quote(self.app, safe="") + "/types"
        definition = {"type": self.type, "description": "Isolated release integration probe"}
        self.http("POST", types, definition, expected=(200, 201))
        self.http("POST", types, definition)
        self.http("POST", types, {**definition, "description": "conflicting"}, expected=409)
        self.http("POST", types, {**definition, "defaults": {"carbon": False}}, expected=400)
        self.mark("Honeycomb management permission and immutable type identity")

        _, grant = self.app_call("/v1/subscriptions", {"org_id": self.org, "app_id": self.app, "for": self.actor}, expected=(200, 201))
        self.app_call("/v1/subscriptions", {"org_id": self.org, "app_id": self.app, "for": "someone-else"}, expected=403)
        self.mark("proof actor binds recipient grant")

        sock = self.socket()
        try:
            sock.call("subscribe", org_id=self.org, session_token=self.session, webhook_ids=[], headers=self.test)
            hooks = []
            hook_attempts = []
            for _ in range(2):
                attempt = key()
                payload = {"receiver_id": sock.receiver}
                _, hook = self.http("POST", self.prefix + "/webhooks", payload, extra={"Idempotency-Key": attempt}, expected=201)
                hooks.append(hook["id"])
                hook_attempts.append((attempt, payload, hook["id"]))
            sock.call("send", proof_token="invalid-proof", body=encode(self.send()).decode(), headers=self.test, error=True)
            body = self.send()
            raw = encode(body)
            proof = self.proof("/v1/tings", raw)
            self.http("POST", "/v1/tings", raw=encode({**body, "key": key()}), token=proof, expected=401)
            badws = self.send()
            wsproof = self.proof("/v1/tings", encode(badws))
            sock.call("send", proof_token=wsproof, body=encode({**badws, "data": {"changed": True}}).decode(), headers=self.test, error=True)
            proof = self.proof("/v1/tings", raw)
            _, accepted = self.http("POST", "/v1/tings", raw=raw, token=proof, expected=202)
            self.http("POST", "/v1/tings", raw=raw, token=proof, expected=401)
            sock.call("send", proof_token=proof, body=raw.decode(), headers=self.test, error=True)
            self.mark("HTTP and WebSocket proofs reject altered bytes and reuse")

            concurrent_body = self.send()
            concurrent_raw = encode(concurrent_body)
            proofs = [self.proof("/v1/tings", concurrent_raw) for _ in range(2)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda proof: self.http("POST", "/v1/tings", raw=concurrent_raw, token=proof, expected=(200, 202)), proofs))
            assert sorted(status for status, _ in results) == [200, 202]
            assert results[0][1] == results[1][1]
            self.app_call("/v1/tings", {**concurrent_body, "data": {"conflict": True}}, expected=409)
            wsbody = self.send()
            wsaccepted = sock.call("send", proof_token=self.proof("/v1/tings", encode(wsbody)), body=encode(wsbody).decode(), headers=self.test)
            assert wsaccepted["op"] == "accepted"
            self.mark("fresh-proof retries and concurrent producer keys create exactly one ting")

            for hook in hooks:
                sock.delivery(hook, accepted["id"])
            sock.call("ack", org_id=self.org, webhook_id=hooks[0], message_ids=[accepted["id"]], kind="delivery")
            _, detail = self.http("GET", self.prefix + "/inbox/" + accepted["id"])
            assert detail["read"] is False
            sock.call("ack", org_id=self.org, webhook_id=hooks[0], message_ids=[accepted["id"]], kind="read")
            _, detail = self.app_call("/v1/sent/query", {"org_id": self.org, "app_id": self.app, "id": accepted["id"]})
            deliveries = {item["webhook_id"]: item for item in detail["deliveries"]}
            assert detail["read"] and deliveries[hooks[0]]["read_acked"] and not deliveries[hooks[1]]["read_acked"]
            self.mark("receipt ACK does not mark read; independent hook completion is preserved")

            sock.close()
            for attempt, payload, hook in hook_attempts:
                _, recovered = self.http("POST", self.prefix + "/webhooks", payload, extra={"Idempotency-Key": attempt})
                assert recovered["id"] == hook
            sock = self.socket()
            sock.call("subscribe", org_id=self.org, session_token=self.session, webhook_ids=hooks, headers=self.test)
            sock.delivery(hooks[1], accepted["id"])
            sock.call("ack", org_id=self.org, webhook_id=hooks[1], message_ids=[accepted["id"]], kind="read")
            self.mark("dead-receiver creation recovery and unfinished-copy replay after reconnect")

            pref = {"app_id": self.app, "type": self.type, "enabled": False}
            self.http("PUT", self.prefix + "/preferences", pref)
            _, silent = self.app_call("/v1/tings", self.send(), expected=202)
            assert silent["silent"]
            self.http("DELETE", self.prefix + "/preferences?app_id=" + quote(self.app, safe="") + "&type=" + quote(self.type, safe=""))
            _, detail = self.http("GET", self.prefix + "/inbox/" + silent["id"])
            assert detail["silent"]
            _, page = self.http("GET", self.prefix + "/inbox?limit=1")
            assert page.get("next_cursor")
            cursor = quote(page["next_cursor"], safe="")
            self.http("GET", self.prefix + "/inbox?limit=1&cursor=" + cursor)
            self.http("GET", self.prefix + "/inbox?limit=1&read=true&cursor=" + cursor, expected=400)
            self.http("POST", self.prefix + "/inbox/read", {"message_ids": [silent["id"], "nonexistent"]}, expected=404)
            _, detail = self.http("GET", self.prefix + "/inbox/" + silent["id"])
            assert not detail["read"]
            self.mark("preference history, cursor binding and atomic read ownership")

            self.app_call("/v1/subscriptions/revoke", {"org_id": self.org, "id": grant["id"]})
            self.app_call("/v1/tings", self.send(), expected=403)
            _, replay = self.app_call("/v1/tings", body)
            assert replay == accepted
            self.mark("revoked grants block new sends while preserving authenticated original results")
            for hook in hooks:
                self.http("DELETE", self.prefix + "/webhooks/" + hook)
            self.http("DELETE", "/v1/session")
            self.http("GET", "/v1/me", expected=401)
            self.mark("logout revokes the local and upstream application session")
        finally:
            sock.close()
        return {"environment_id": self.f["environment_id"], "api_url": self.api,
                "checks": self.passed, "passed": len(self.passed), "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


class Socket:
    def __init__(self, sock, receiver):
        self.sock, self.receiver, self.pending = sock, receiver, []

    def call(self, op, *, error=False, **body):
        request = key()
        self.sock.send(encode({"op": op, "request_id": request, **body}).decode())
        while True:
            message = json.loads(self.sock.recv())
            if message.get("request_id") == request:
                assert (message["op"] == "error") == error, (op, message.get("error", {}).get("code"))
                return message
            self.pending.append(message)

    def delivery(self, hook, ting):
        def matches(msg):
            return msg.get("op") == "tings" and msg.get("webhook_id") == hook and any(x["id"] == ting for x in msg["tings"])
        for message in self.pending:
            if matches(message):
                return message
        while True:
            message = json.loads(self.sock.recv())
            self.pending.append(message)
            if matches(message):
                return message

    def close(self):
        self.sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=pathlib.Path)
    parser.add_argument("--report", type=pathlib.Path, default=pathlib.Path("deploy/live-test-results.json"))
    args = parser.parse_args()
    fixture = json.loads(args.fixture.read_text())
    report = Checks(fixture).run_checks()
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Completed {report['passed']} isolated integration checks. Report: {args.report}")


if __name__ == "__main__":
    main()
