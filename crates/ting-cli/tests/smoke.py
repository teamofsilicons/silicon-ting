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
me_response = (200, {'id':'si:test','kind':'silicon','authenticated':True})
login_response = None
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
            self.respond(*me_response)
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
            result = {'id':'si:test','kind':'silicon','authenticated':True}
            if len(exchanges) > 1: result['session_token']='private-session-test'
            status, result = login_response or (201, result)
            if status == 0:
                self.close_connection = True
                return
            self.respond(status, result)
        elif self.path == '/v1/sent/read':
            data = json.loads(body)
            self.respond(200, {key: data[key] for key in ('message_ids', 'read')})
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
    assert cli('iam')['app_id'] == 'ting'
    cli('login','--token-stdin',text='short-lived-test\n',code=1)
    attempt_path=Path(d,'.ting','login-attempt.json')
    attempt=json.loads(attempt_path.read_text()); attempt['created']-=125
    attempt_path.write_text(json.dumps(attempt))
    assert cli('logout',code=1)['error']['code']=='login_cleanup_pending'
    cli('login','--token-stdin',text='different-token\n',code=1)
    assert len(exchanges)==1
    assert cli('login','--recover')['id']=='si:test'
    assert exchanges[0]==exchanges[1]
    assert not attempt_path.exists()
    assert cli('login','status')['authenticated']
    assert cli('org','use','tos')['org_id']=='org-canonical'
    assert cli('org','current')['org_id']=='org-canonical'
    prepared=cli('send','--type','dm.msg.received','--for','si:test','--key','test','--data','{}','--write-request','send.json')
    raw=Path(d,'send.json').read_bytes()
    assert prepared['body_sha256']==hashlib.sha256(raw).hexdigest()
    if os.name != 'nt': assert Path(d,'send.json').stat().st_mode & 0o777 == 0o600
    cli('send','--request-file','send.json','--proof-token-stdin',text='proof-test\n')
    assert received[-1]==('/v1/tings','Bearer proof-test',raw)
    for command, read in [('mark-read', True), ('mark-unread', False)]:
        filename = command + '.json'
        prepared = cli('sent', command, 'msg_1', 'msg_2', '--app', 'dm', '--key', command, '--write-request', filename)
        raw = Path(d, filename).read_bytes()
        assert json.loads(raw) == {'org_id': 'org-canonical', 'app_id': 'dm', 'message_ids': ['msg_1', 'msg_2'], 'read': read, 'key': command}
        assert prepared['path'] == '/v1/sent/read'
        assert prepared['body_sha256'] == hashlib.sha256(raw).hexdigest()
        count = len(received)
        opposite = 'mark-unread' if read else 'mark-read'
        cli('sent', opposite, '--request-file', filename, '--proof-token-stdin', text='proof-test\n', code=2)
        cli('sent', command, 'msg_3', '--request-file', filename, '--proof-token-stdin', text='proof-test\n', code=2)
        assert len(received) == count
        assert cli('sent', command, '--request-file', filename, '--proof-token-stdin', text='proof-test\n')['read'] is read
        assert received[-1] == ('/v1/sent/read', 'Bearer proof-test', raw)
    cli('sent', 'mark-read', '--app', 'dm', '--key', 'missing-ids', '--write-request', 'missing.json', code=2)
    assert not Path(d, 'missing.json').exists()
    cli('send','--type','hook.webhook.received','--for','si:test','--key','required-test','--data','{}','--delivery','required','--write-request','required.json')
    assert json.loads(Path(d,'required.json').read_text())['delivery']=='required'
    assert cli('subscriptions','required-delivery','sub-test','--enabled','true')['enabled'] is True
    assert received[-1][0]=='/v1/orgs/org%2Dcanonical/subscriptions/sub%2Dtest/required-delivery'
    assert received[-1][1]=='Bearer private-session-test'
    assert json.loads(received[-1][2])=={'enabled':True}
    count=len(received)
    cli('send','--type','tos>dm.msg.received','--for','c:alice0','--key','legacy','--data','{}','--write-request','legacy.json',code=2)
    assert not Path(d, 'legacy.json').exists()
    cli('send','--request-file','send.json','--type','dm.msg.received','--proof-token-stdin',text='proof-test\n',code=2)
    Path(d,'duplicate.json').write_text('{"org_id":"org-canonical","org_id":"other"}')
    cli('send','--request-file','duplicate.json','--proof-token-stdin',text='proof-test\n',code=2)
    cli('inbox','list','--api-url','https://different.example',code=1)
    assert len(received)==count
    assert cli('config','set','telemetry.enabled','false')['value'] is False
    session_path = Path(d, '.ting', 'session.json')
    for state in ['valid', 'expired', 'revoked']:
        me_response = (200, {'id':json.loads(session_path.read_text())['id']}) if state == 'valid' else (401, {
            'error':{'code':'session_expired' if state == 'expired' else 'authentication_required','message':state,'hint':'','retryable':False}})
        assert cli('login', 'status')['authenticated'] is (state == 'valid')
        login_response = (201, {'id':f'si:{state}', 'session_token':f'private-session-test-{state}'})
        count = len(exchanges)
        if state == 'expired':
            result = cli('login', '--token-stdin', text=f'replacement-{state}\n')
        else:
            result = cli('login', f'replacement-{state}')
        assert result == {'authenticated':True, 'id':f'si:{state}'}
        assert len(exchanges) == count + 1
        assert json.loads(exchanges[-1][1]) == {'slt':f'replacement-{state}'}
        saved = json.loads(session_path.read_text())
        assert saved['id'] == f'si:{state}' and saved['token'] == f'private-session-test-{state}'
        assert not attempt_path.exists()
        if os.name != 'nt': assert session_path.stat().st_mode & 0o777 == 0o600
    for failure, code in [
        ((201, {'id':'si:replacement'}), 'connection_failed'),
        ((503, {'error':{'code':'unavailable','message':'Retry','hint':'','retryable':True}}), 'unavailable'),
        ((0, None), 'connection_failed'),
    ]:
        original = session_path.read_bytes()
        login_response = failure
        assert cli('login', 'replacement-retry', code=1)['error']['code'] == code
        assert session_path.read_bytes() == original
        pending = attempt_path.read_bytes()
        exchange = exchanges[-1]
        count = len(received)
        assert cli('logout', code=1)['error']['code'] == 'login_cleanup_pending'
        assert cli('login', 'different-token', code=1)['error']['code'] == 'login_attempt_pending'
        assert len(received) == count
        assert session_path.read_bytes() == original and attempt_path.read_bytes() == pending
        login_response = (201, {'id':'si:replacement', 'session_token':f'private-session-test-{len(exchanges)}'})
        assert cli('login', '--recover') == {'authenticated':True, 'id':'si:replacement'}
        assert exchanges[-1] == exchange
        assert json.loads(session_path.read_text())['token'] == login_response[1]['session_token']
        assert not attempt_path.exists()
server.shutdown()
print('CLI smoke passed: login replacement/recovery, canonical org, exact proof bytes, sent read/unread, private files, input rejection, origin isolation.')
