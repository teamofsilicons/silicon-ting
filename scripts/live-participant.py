#!/usr/bin/env python3
"""Temporary stateless test issuer participant used by live-test.py.

Route its dedicated Authorization header during isolated release checks. Never serves Ting
application data. Requires its own token, exact environment and app allowlist.
Remove the process and route after Honeycomb has disabled the test environment.
"""
import hashlib
import hmac
import json
import os
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKEN = os.environ['TING_PROBE_CONTROL_TOKEN']
ENVIRONMENT = os.environ['TING_PROBE_ENVIRONMENT']
APP = 'tos>ting-probe'
assert len(TOKEN) >= 32
DB = sqlite3.connect(os.environ.get('TING_PROBE_DATABASE', '/tmp/ting-live-participant.sqlite'))
DB.execute('PRAGMA synchronous=FULL')
DB.execute('CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, body TEXT NOT NULL)')
DB.execute('CREATE TABLE IF NOT EXISTS environment(id TEXT PRIMARY KEY, revision INTEGER NOT NULL, state TEXT NOT NULL)')


class Participant(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body):
        raw = json.dumps(body, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_PUT(self):
        if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + TOKEN):
            return self.reply(401, {'error': 'service authority required'})
        length = int(self.headers.get('Content-Length', '0'))
        if not 0 < length <= 1024 * 1024:
            return self.reply(400, {'error': 'invalid body size'})
        try:
            body = json.loads(self.rfile.read(length))
            assert body['app_id'] == APP and body['environment_id'] == ENVIRONMENT
            assert self.path == f"/internal/honeycomb/organizations/{body['org_id']}/testing-environments/{ENVIRONMENT}/operations/{body['operation_id']}"
            assert body['action'] in ['prepare', 'import', 'rotate', 'clean', 'disable', 'restore', 'purge', 'retire-applications']
            assert all(type(body[k]) is int and body[k] > 0 for k in ['environment_revision', 'generation', 'key_version'])
        except (KeyError, AssertionError, ValueError):
            return self.reply(400, {'error': 'incorrect isolated participant context'})
        fingerprint = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        old = DB.execute('SELECT fingerprint,body FROM receipts WHERE id=?', (body['operation_id'],)).fetchone()
        if old:
            return self.reply(200, json.loads(old[1])) if old[0] == fingerprint else self.reply(409, {'error': 'operation conflict'})
        current = DB.execute('SELECT revision,state FROM environment WHERE id=?', (ENVIRONMENT,)).fetchone()
        if current and (current[0] >= body['environment_revision'] or current[1] == 'purge'):
            return self.reply(409, {'error': 'stale lifecycle operation'})
        receipt = {k: body[k] for k in ['operation_id', 'environment_id', 'app_id', 'environment_revision', 'generation', 'key_version']}
        receipt.update(state='completed')
        if 'retired_apps' in body:
            receipt['retired_apps'] = body['retired_apps']
        with DB:
            DB.execute('INSERT INTO environment VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,state=excluded.state', (ENVIRONMENT, body['environment_revision'], body['action']))
            DB.execute('INSERT INTO receipts VALUES(?,?,?)', (body['operation_id'], fingerprint, json.dumps(receipt)))
        self.reply(200, receipt)


HTTPServer(('127.0.0.1', 8099), Participant).serve_forever()
