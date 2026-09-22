#!/usr/bin/env python3
"""Run after cargo build -p silicon-ting-cli. Only loopback requests are used."""
import hashlib
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading

received = []
exchanges = []
class API(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def respond(self, status, value):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(value).encode())
    def do_GET(self):
        received.append((self.path, self.headers.get('Authorization'), b''))
        if self.path == '/v1/me':
            self.respond(200, {'id':'si_test','kind':'silicon','authenticated':True})
        elif self.path == '/v1/orgs':
            self.respond(200, {'items':[{'id':'org-canonical','handle':'tos','name':'TOS'}]})
        else: self.respond(200, {'items':[]})
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        if self.path == '/v1/telemetry':
            self.respond(202, {'accepted': True})
            return
        received.append((self.path,self.headers.get('Authorization'),body))
        if self.path == '/v1/session':
            assert self.headers.get('Idempotency-Key')
            exchanges.append((self.headers.get('Idempotency-Key'), body))
            # An unreadable first result must leave the original operation recoverable.
            result = {'id':'si_test','kind':'silicon','authenticated':True}
            if len(exchanges) > 1: result['session_token']='private-session-test'
            self.respond(201, result)
        else: self.respond(202, {'id':'msg_test','status':'accepted','key':'test','created_at':'2026-09-22T00:00:00Z','silent':False})
    def do_PUT(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        received.append((self.path, self.headers.get('Authorization'), body))
        self.respond(200, {'id': 'sub-test', 'enabled': json.loads(body)['enabled']})

server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), API)
threading.Thread(target=server.serve_forever, daemon=True).start()
binary = Path(os.environ.get('TING_BINARY', 'target/debug/ting')).resolve()
with tempfile.TemporaryDirectory() as d:
    env = dict(os.environ, SILICON_HOME=d, TING_API_URL=f'http://127.0.0.1:{server.server_port}')
    for key in ['SILICON_ORG','IAM_TEST_KEY','IAM_TEST_APP_SECRET']: env.pop(key,None)
    def cli(*args, text=None, code=0):
        result = subprocess.run([str(binary), *args, '--json'], input=text, text=True, capture_output=True, env=env, cwd=d)
        assert result.returncode == code, (args, result.stderr)
        assert 'private-session-test' not in result.stdout + result.stderr
        if code: assert not result.stdout
        return json.loads(result.stdout if code==0 else result.stderr)
    cli('login','--token-stdin',text='short-lived-test\n',code=1)
    attempt_path=Path(d,'.ting','login-attempt.json')
    attempt=json.loads(attempt_path.read_text()); attempt['created']-=125
    attempt_path.write_text(json.dumps(attempt))
    assert cli('logout',code=1)['error']['code']=='login_cleanup_pending'
    cli('login','--token-stdin',text='different-token\n',code=1)
    assert len(exchanges)==1
    assert cli('login','--recover')['id']=='si_test'
    assert exchanges[0]==exchanges[1]
    assert not attempt_path.exists()
    assert cli('login','status')['authenticated']
    assert cli('org','use','tos')['org_id']=='org-canonical'
    assert cli('org','current')['org_id']=='org-canonical'
    prepared=cli('send','--type','tos>dm.msg.received','--for','si_test','--key','test','--data','{}','--write-request','send.json')
    raw=Path(d,'send.json').read_bytes()
    assert prepared['body_sha256']==hashlib.sha256(raw).hexdigest()
    if os.name != 'nt': assert Path(d,'send.json').stat().st_mode & 0o777 == 0o600
    cli('send','--request-file','send.json','--proof-token-stdin',text='proof-test\n')
    assert received[-1]==('/v1/tings','Bearer proof-test',raw)
    cli('send','--type','tos>hook.webhook.received','--for','si_test','--key','required-test','--data','{}','--delivery','required','--write-request','required.json')
    assert json.loads(Path(d,'required.json').read_text())['delivery']=='required'
    assert cli('subscriptions','required-delivery','sub-test','--enabled','true')['enabled'] is True
    assert received[-1][0]=='/v1/orgs/org%2Dcanonical/subscriptions/sub%2Dtest/required-delivery'
    assert received[-1][1]=='Bearer private-session-test'
    assert json.loads(received[-1][2])=={'enabled':True}
    count=len(received)
    cli('send','--request-file','send.json','--type','tos>dm.msg.received','--proof-token-stdin',text='proof-test\n',code=2)
    Path(d,'duplicate.json').write_text('{"org_id":"org-canonical","org_id":"other"}')
    cli('send','--request-file','duplicate.json','--proof-token-stdin',text='proof-test\n',code=2)
    cli('inbox','list','--api-url','https://different.example',code=1)
    assert len(received)==count
    assert cli('config','set','telemetry.enabled','false')['value'] is False
server.shutdown()
print('CLI smoke passed: login, canonical org, exact proof bytes, private files, input rejection, origin isolation.')
