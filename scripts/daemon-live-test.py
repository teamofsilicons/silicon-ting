#!/usr/bin/env python3
"""Exercise installed native Ting against an isolated real IAM/Ting environment.

Dependencies: requests, websocket-client, aiohttp. Run only after live-test.py:
  python scripts/daemon-live-test.py --fixture deploy/private/live-test.json
No mocked API responses: a loopback relay only observes and suppresses selected
WebSocket ACKs. Latency samples bypass that relay. Requires no existing daemon
or daemon state; only this script's foreground process and directories are removed.
"""
import argparse
import asyncio
import collections
import importlib.util
import hashlib
import json
import math
import os
import pathlib
import pwd
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from aiohttp import ClientSession, ClientTimeout, WSMsgType, web

spec = importlib.util.spec_from_file_location("ting_live", pathlib.Path(__file__).with_name("live-test.py"))
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


def wait_for(check, label, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(.05)
    raise AssertionError("Timed out: " + label)


class Relay:
    def __init__(self, upstream, database):
        self.upstream, self.database = upstream, database
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.read_seen = threading.Event()
        self.delivery_seen = threading.Event()
        self.hold_reads = False
        self.delivery_checks = []
        self.delivery_records = set()
        self.errors = []
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()
        assert self.ready.wait(10), "Relay did not start"

    def run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self.start())
        self.ready.set()
        self.loop.run_forever()

    async def start(self):
        self.client = ClientSession(timeout=ClientTimeout(total=40))
        app = web.Application(client_max_size=2 * 1024 * 1024)
        app.router.add_route("*", "/{tail:.*}", self.handle)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.origin = "http://127.0.0.1:" + str(site._server.sockets[0].getsockname()[1])

    async def handle(self, request):
        if request.path == "/v1/ws":
            downstream = web.WebSocketResponse(autoping=True)
            await downstream.prepare(request)
            target = self.upstream.replace("https://", "wss://").replace("http://", "ws://") + str(request.rel_url)
            async with self.client.ws_connect(target, autoping=True) as upstream:
                async def client_to_server():
                    async for message in downstream:
                        if message.type != WSMsgType.TEXT:
                            continue
                        value = json.loads(message.data)
                        if value.get("op") == "ack":
                            if value.get("kind") == "delivery":
                                with sqlite3.connect(self.database) as db:
                                    for mid in value["message_ids"]:
                                        row = db.execute("SELECT accepted FROM queue WHERE hook=? AND id=?", (value["webhook_id"], mid)).fetchone()
                                        self.delivery_checks.append(row is not None)
                                        self.delivery_records.add((value["webhook_id"], mid))
                                self.delivery_seen.set()
                            elif value.get("kind") == "read" and self.hold_reads:
                                self.read_seen.set()
                                continue
                        await upstream.send_str(message.data)

                async def server_to_client():
                    async for message in upstream:
                        if message.type == WSMsgType.TEXT:
                            await downstream.send_str(message.data)

                tasks = [asyncio.create_task(client_to_server()), asyncio.create_task(server_to_client())]
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                for task in done:
                    if not task.cancelled() and task.exception():
                        self.errors.append(type(task.exception()).__name__)
            await downstream.close()
            return downstream
        headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "connection", "content-length", "transfer-encoding")}
        async with self.client.request(request.method, self.upstream + str(request.rel_url), headers=headers,
                                       data=await request.read(), allow_redirects=False) as response:
            body = await response.read()
            return web.Response(status=response.status, body=body, headers={k: v for k, v in response.headers.items()
                                if k.lower() not in ("content-length", "transfer-encoding", "content-encoding", "connection")})

    def close(self):
        async def cleanup():
            await self.runner.cleanup()
            await self.client.close()
        asyncio.run_coroutine_threadsafe(cleanup(), self.loop).result(10)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(10)


class Destinations:
    def __init__(self):
        self.calls = collections.defaultdict(list)
        self.dead_attempts = []
        self.allow_healthy = threading.Event()
        self.allow_healthy.set()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                now = time.monotonic()
                hook = self.headers["Ting-Webhook-Id"]
                if self.path == "/dead":
                    owner.dead_attempts.append(now)
                    # Real unresponsive local destination: exceed daemon's 10s timeout.
                    time.sleep(11)
                    status = 503
                else:
                    for ting in value["tings"]:
                        owner.calls[(hook, ting["key"])].append(now)
                    owner.allow_healthy.wait(20)
                    status = 204
                try:
                    self.send_response(status)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)

    def close(self):
        self.allow_healthy.set()
        self.server.shutdown()
        self.server.server_close()


class Run:
    def __init__(self, args):
        self.args = args
        self.fixture = json.loads(args.fixture.read_text())
        self.checks = live.Checks(self.fixture)
        self.checks.run = live.key()
        self.report = {"complete": False, "checks": [], "samples_ms": [], "api_url": self.checks.api,
                       "environment_id": self.fixture["environment_id"], "client_location": args.client_location,
                       "server_location": "AWS us-east-1, Northern Virginia, United States",
                       "callback_location": "127.0.0.1 on the same macOS host as the sending WebSocket"}
        self.process = None
        self.hooks = []
        self.sessions = []
        self.socket_dir = pathlib.Path("/var/tmp/silicon-ting")
        self.state_dir = pathlib.Path(pwd.getpwuid(os.getuid()).pw_dir) / ".ting-daemon"
        self.database = self.state_dir / "queue.sqlite3"
        self.temp = tempfile.TemporaryDirectory(prefix="ting-daemon-live-")
        self.directory = pathlib.Path(self.temp.name)
        self.env = dict(os.environ)
        self.env.update(IAM_TEST_APP_SECRET=self.fixture["ting_app_secret"], IAM_TEST_KEY=self.fixture["testing_key"])
        self.env.pop("SILICON_ORG", None)
        self.created_socket_dir = False
        self.relay = None
        self.destinations = None
        self.sender = None

    def mark(self, text):
        self.report["checks"].append(text)
        print("PASS", text, flush=True)

    def cli(self, *args, stdin=None):
        result = subprocess.run([self.args.ting, "--json", *args], input=stdin, capture_output=True, text=True, env=self.env, timeout=45)
        if result.returncode:
            try:
                error = json.loads(result.stderr).get("error", {})
                code = error.get("code", "cli_error")
            except ValueError:
                code = "cli_error"
            raise AssertionError(f"ting {args[0]} failed: {code}")
        return json.loads(result.stdout)

    def start(self):
        assert self.process is None
        log = open(self.directory / "daemon.log", "ab")
        self.process = subprocess.Popen([self.args.daemon], stdout=log, stderr=log, env=self.env)
        log.close()
        wait_for(lambda: self.process.poll() is not None or (self.socket_dir / "daemon.sock").exists(), "daemon socket")
        assert self.process.poll() is None, "Foreground daemon exited"

    def stop(self):
        if self.process is not None:
            self.process.send_signal(signal.SIGINT)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
            self.process = None

    def profile(self, name, api):
        home = self.directory / name
        home.mkdir(mode=0o700)
        self.env.update(SILICON_HOME=str(home), TING_API_URL=api)
        self.cli("login", "--token-stdin", stdin=self.fixture["actor_id"] + "\n")
        session = json.loads((home / ".ting/session.json").read_text())["token"]
        self.sessions.append(session)
        self.checks.session = session
        self.cli("org", "use", self.fixture["org_id"])
        self.cli("config", "set", "telemetry.enabled", "false")

    def hook(self, path):
        result = self.cli("webhook", self.destinations.origin + path)
        hid = result["id"]
        self.hooks.append(hid)
        return hid

    def send(self, phase):
        body = self.checks.send(data={"run": self.checks.run, "phase": phase})
        raw = live.encode(body)
        proof = self.checks.proof("/v1/tings", raw)
        started = time.monotonic()
        result = self.sender.call("send", proof_token=proof, body=raw.decode(), headers=self.checks.test)
        assert result["op"] == "accepted"
        return body["key"], result["id"], started

    def rows(self, hid, mid):
        with sqlite3.connect(self.database) as db:
            return db.execute("SELECT accepted FROM queue WHERE hook=? AND id=?", (hid, mid)).fetchone()

    def read_state(self, mid):
        return self.checks.http("GET", self.checks.prefix + "/inbox/" + mid)[1]["read"]

    def detach(self, hid):
        self.cli("unhook", hid)
        self.hooks.remove(hid)

    def run(self):
        if self.state_dir.exists() or self.socket_dir.exists() or subprocess.run(["pgrep", "-x", "ting-daemon"], capture_output=True).returncode == 0:
            raise AssertionError("Existing daemon/state detected; refusing to touch another daemon")
        self.socket_dir.mkdir(mode=0o700)
        self.created_socket_dir = True
        self.report["cli_version"] = self.cli("--version")["version"]
        self.report["binary_sha256"] = {name: hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()
                                        for name, binary in (("ting", self.args.ting), ("ting-daemon", self.args.daemon))}
        self.destinations = Destinations()
        self.relay = Relay(self.checks.api, self.database)
        self.profile("faults", self.relay.origin)
        # Integration fixture cleanup is intentional and confined to this isolated actor.
        while True:
            page = self.checks.http("GET", self.checks.prefix + "/inbox?limit=100&read=false")[1]
            ids = [v["id"] for v in page["items"]]
            if not ids:
                break
            self.checks.http("POST", self.checks.prefix + "/inbox/read", {"message_ids": ids})
        self.checks.app_call("/v1/subscriptions", {"org_id": self.checks.org, "app_id": self.checks.app, "for": self.checks.actor}, expected=(200, 201))
        self.start()
        self.sender = self.checks.socket()
        healthy, dead = self.hook("/healthy"), self.hook("/dead")
        self.destinations.allow_healthy.clear()
        self.relay.hold_reads = True
        business_key, mid, started = self.send("durability-and-lost-read-ack")
        arrived = wait_for(lambda: self.destinations.calls[(healthy, business_key)], "healthy callback")[0]
        wait_for(lambda: (healthy, mid) in self.relay.delivery_records, "healthy delivery ACK observed")
        assert self.relay.delivery_checks and all(self.relay.delivery_checks), "Delivery ACK preceded durable SQLite queue"
        assert self.rows(healthy, mid) == (0,), "Callback is not yet accepted"
        assert not self.read_state(mid), "Delivery ACK incorrectly marked read"
        assert arrived - started < 10, "Unresponsive hook blocked healthy hook"
        self.mark("durable local queue precedes delivery ACK; delivery ACK keeps server unread")
        self.destinations.allow_healthy.set()
        wait_for(self.relay.read_seen.is_set, "read ACK suppression")
        assert self.rows(healthy, mid) == (1,), "204 acceptance not durably recorded before read ACK"
        assert not self.read_state(mid), "Suppressed read ACK reached server"
        def dead_has_failed():
            with sqlite3.connect(self.database) as db:
                row = db.execute("SELECT first_failure FROM hooks WHERE id=?", (dead,)).fetchone()
                return row and row[0] is not None
        wait_for(dead_has_failed, "unresponsive webhook timeout recorded", timeout=20)
        self.stop()
        self.relay.hold_reads = False
        self.start()
        wait_for(lambda: self.rows(healthy, mid) is None, "accepted receipt acknowledged after restart", timeout=90)
        assert self.read_state(mid)
        time.sleep(3)
        assert len(self.destinations.calls[(healthy, business_key)]) == 1, "Accepted callback was forwarded twice"
        self.mark("restart retries lost read ACK from durable acceptance without duplicate forwarding")
        # Keep a failed destination alive through its real retry interval.
        wait_for(lambda: len(self.destinations.dead_attempts) >= 2, "dead webhook retry", timeout=90)
        self.report["unresponsive_hook"] = {"attempts": len(self.destinations.dead_attempts),
            "first_retry_seconds": round(self.destinations.dead_attempts[1] - self.destinations.dead_attempts[0], 3),
            "healthy_delivery_ms": round((arrived - started) * 1000, 3)}
        self.mark("unresponsive webhook retries independently while healthy hook completes")
        self.detach(dead)
        self.detach(healthy)
        self.stop()
        self.relay.close()
        self.relay = None
        self.profile("latency", self.checks.api)
        self.start()
        measured = self.hook("/latency")
        # The blocking Python sender was idle during the retry test; establish a fresh measured socket.
        self.sender.close()
        self.sender = self.checks.socket()
        for sample in range(self.args.samples):
            business_key, mid, started = self.send("latency-" + str(sample + 1))
            received = wait_for(lambda: self.destinations.calls[(measured, business_key)], "latency callback")[0]
            self.report["samples_ms"].append(round((received - started) * 1000, 3))
            wait_for(lambda: self.rows(measured, mid) is None, "read acknowledgement")
            assert len(self.destinations.calls[(measured, business_key)]) == 1
            print(f"SAMPLE {sample + 1}/{self.args.samples} {self.report['samples_ms'][-1]:.3f} ms", flush=True)
        values = sorted(self.report["samples_ms"])
        self.report["latency"] = {"samples": len(values), "p50_ms": values[math.ceil(len(values) * .5) - 1],
            "p95_ms": values[math.ceil(len(values) * .95) - 1], "min_ms": values[0], "max_ms": values[-1],
            "conditions": "Monotonic proof-ready WebSocket send through public TLS AWS backend to installed native daemon and local HTTP callback arrival; existing sockets; small sequential payloads; proof minting and callback ACK excluded; no relay or mocked responses in this phase."}
        self.mark(f"{len(values)} real direct-public WebSocket sends reach native daemon webhook")
        self.detach(measured)
        self.report["complete"] = True

    def close(self):
        if self.destinations:
            self.destinations.allow_healthy.set()
        for hid in self.hooks:
            try:
                self.checks.http("DELETE", self.checks.prefix + "/webhooks/" + hid)
            except Exception:
                self.report.setdefault("cleanup_errors", []).append("hook_detach")
        self.stop()
        if self.sender:
            self.sender.close()
        if self.relay:
            self.relay.close()
        if self.destinations:
            self.destinations.close()
        for session in self.sessions:
            try:
                self.checks.http("DELETE", "/v1/session", token=session)
            except Exception:
                self.report.setdefault("cleanup_errors", []).append("session_revoke")
        # These directories were absent at startup and belong only to this run.
        if self.created_socket_dir and subprocess.run(["pgrep", "-x", "ting-daemon"], capture_output=True).returncode != 0:
            shutil.rmtree(self.state_dir, ignore_errors=True)
            shutil.rmtree(self.socket_dir, ignore_errors=True)
        self.temp.cleanup()
        self.report["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.args.report.write_text(json.dumps(self.report, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=pathlib.Path, required=True)
    parser.add_argument("--report", type=pathlib.Path, default=pathlib.Path("deploy/daemon-live-test-results.json"))
    parser.add_argument("--ting", default=shutil.which("ting"))
    parser.add_argument("--daemon", default=shutil.which("ting-daemon"))
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--client-location", default="Developer macOS host; city/country unverified")
    args = parser.parse_args()
    if not args.ting or not args.daemon or not 1 <= args.samples <= 100:
        parser.error("Installed ting/ting-daemon and 1..100 samples required")
    os.umask(0o077)
    run = Run(args)
    try:
        run.run()
    except Exception as error:
        run.report["failure"] = str(error) if isinstance(error, AssertionError) else type(error).__name__
        print("FAIL", run.report["failure"], flush=True)
        raise SystemExit(1)
    finally:
        run.close()
    print(json.dumps(run.report["latency"], indent=2))


if __name__ == "__main__":
    main()
