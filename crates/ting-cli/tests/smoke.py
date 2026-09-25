#!/usr/bin/env python3
"""Run after cargo build -p silicon-ting-cli -p silicon-ting-daemon. Only loopback requests are used.

The on-demand daemon rows need a system with no Ting daemon or daemon state; elsewhere they are
skipped, and under CI they are required. TING_SMOKE_SYSTEM_SERVICE=1 also installs a temporary
systemd unit with passwordless sudo to check old installs.
"""
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import unquote

received = []
exchanges = []
me_response = (200, {'id':'si:test','kind':'silicon','authenticated':True})
login_response = None
RECEIVER = 'receiver-smoke'
def websocket(handler):
    """Just enough of the v1 receiver socket for the daemon: ready, request replies, pings."""
    accept = hashlib.sha1((handler.headers['Sec-WebSocket-Key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()
    handler.protocol_version = 'HTTP/1.1'  # WebSocket clients reject an HTTP/1.0 upgrade.
    handler.send_response(101)
    for key, value in [('Upgrade', 'websocket'), ('Connection', 'Upgrade'), ('Sec-WebSocket-Accept', base64.b64encode(accept).decode())]:
        handler.send_header(key, value)
    handler.end_headers()
    handler.close_connection = True
    def send(opcode, payload):
        n = len(payload)
        size = bytes([n]) if n < 126 else bytes([126]) + n.to_bytes(2, 'big') if n < 65536 else bytes([127]) + n.to_bytes(8, 'big')
        handler.wfile.write(bytes([0x80 | opcode]) + size + payload)
    send(1, json.dumps({'op':'ready','receiver_id':RECEIVER,'protocol':'v1'}).encode())
    while True:
        head = handler.rfile.read(2)
        if len(head) < 2: return
        opcode, n = head[0] & 15, head[1] & 127
        if n > 125: n = int.from_bytes(handler.rfile.read(2 if n == 126 else 8), 'big')
        mask = handler.rfile.read(4) if head[1] & 128 else bytes(4)
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(handler.rfile.read(n)))
        if opcode == 8: return
        if opcode == 9: send(10, data)
        if opcode == 1:
            message = json.loads(data)
            send(1, json.dumps({'op':'subscribed' if message['op'] == 'subscribe' else 'ok','request_id':message.get('request_id'),'webhook_ids':message.get('webhook_ids', [])}).encode())
def hook(path):
    return {'id':unquote(path.rsplit('/', 1)[1]) if '/webhooks/' in path else 'hook_smoke','for':'si:replacement','receiver_id':RECEIVER,'state':'connected','pending':0}
class API(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def respond(self, status, value):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(value).encode())
    def do_GET(self):
        if self.path.startswith('/v1/ws'):
            return websocket(self)
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
        elif self.path.endswith('/webhooks'):
            self.respond(201, hook(self.path))
        elif self.path == '/v1/sent/read':
            data = json.loads(body)
            self.respond(200, {key: data[key] for key in ('message_ids', 'read')})
        else: self.respond(202, {'id':'msg_test','status':'accepted','key':'test','created_at':'2026-09-22T00:00:00Z','silent':False})
    def do_PATCH(self):
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.respond(200, hook(self.path))
    def do_DELETE(self):
        self.respond(200, dict(hook(self.path), state='detached'))
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

    # On-demand daemon: the CLI starts ting-daemon itself, as this account, with no sudo or prompt.
    WINDOWS = os.name == 'nt'
    if not WINDOWS: import pty, pwd
    socket_dir = None if WINDOWS else Path('/var/tmp/silicon-ting')
    state_dir = Path(os.path.expanduser('~') if WINDOWS else pwd.getpwuid(os.getuid()).pw_dir) / '.ting-daemon'
    daemon_binary = binary.with_name('ting-daemon.exe' if WINDOWS else 'ting-daemon')
    url = 'http://127.0.0.1:9/ting'
    passed = []
    def daemons():
        if WINDOWS:
            rows = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq ting-daemon.exe', '/FO', 'CSV', '/NH'], capture_output=True, text=True).stdout
            return sorted(int(row.split('","')[1]) for row in rows.splitlines() if row.startswith('"ting-daemon.exe"'))
        pids = subprocess.run(['pgrep', '-x', 'ting-daemon'], capture_output=True, text=True).stdout.split()
        # An exited daemon stays a zombie until PID 1 reaps it; it no longer runs.
        return sorted(int(pid) for pid in pids if subprocess.run(['ps', '-o', 'stat=', '-p', pid], capture_output=True, text=True).stdout.strip()[:1] not in ('', 'Z'))
    def wait_until(check, label, timeout=15):
        deadline = time.monotonic() + timeout
        while not check():
            assert time.monotonic() < deadline, 'Timed out: ' + label
            time.sleep(.05)
    def stop(pid, force=False):
        if WINDOWS: subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
        else: os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
        wait_until(lambda: pid not in daemons(), 'daemon exit')
    def silicon(*args, path=None, prefix=()):
        # Exactly how Silicon runs ting: stdin null, output captured to EOF, bounded wait.
        result = subprocess.run([*prefix, str(binary), *args, '--json'], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                env=dict(env, PATH=path) if path else env, cwd=d, timeout=30)
        assert 'AUTHENTICATING' not in result.stdout + result.stderr, result.stderr
        return result
    def connected(*args):
        result = silicon('webhook', url, *args)
        assert result.returncode == 0, result.stderr
        value = json.loads(result.stdout)
        assert value['state'] == 'connected' and value['url'] == url and 'receiver_id' not in value, value
        return value['id']
    def sudo(*args):
        subprocess.run(['sudo', '-n', *map(str, args)], check=True, capture_output=True)
    def row(text):
        passed.append(text.split(':')[0])
        print('PASS daemon', text, flush=True)
    clean = not state_dir.exists() and not (socket_dir and os.path.lexists(socket_dir)) and not daemons()
    if not clean:
        assert not os.environ.get('CI'), 'CI must start with no Ting daemon or daemon state.'
        print('SKIP daemon rows: this system already has a Ting daemon or daemon state.')
    else:
        try:
            # 9: argument probes never start a receiver.
            probe = subprocess.run([str(daemon_binary), '--version'], capture_output=True, text=True, timeout=10)
            assert probe.returncode == 0 and json.loads(probe.stdout) == {'version': cli('--version')['version']}, probe
            assert subprocess.run([str(daemon_binary), '--bogus'], capture_output=True, timeout=10).returncode == 2
            assert not daemons() and not (socket_dir and os.path.lexists(socket_dir))
            row('9: --version and unknown arguments exit without a socket')
            # 6: another account's directory is refused before anything is spawned.
            if not WINDOWS and subprocess.run(['sudo', '-n', 'true'], capture_output=True).returncode == 0:
                for mode in ['700', '755']:
                    sudo('install', '-d', '-o', 'nobody', '-m', mode, socket_dir)
                    result = silicon('webhook', url)
                    assert result.returncode == 1 and json.loads(result.stderr)['error']['code'] == 'daemon_identity_mismatch', result.stderr
                    assert not daemons()
                    sudo('rm', '-rf', socket_dir)
                row('6: a socket directory owned by another uid returns daemon_identity_mismatch; nothing spawned')
            else:
                print('SKIP daemon 6: creating another account\'s directory needs passwordless sudo.')
            # 1: first use with no directory, daemon or unit, run exactly as Silicon runs it.
            hook_id = connected()
            pids = daemons()
            assert len(pids) == 1, pids
            if not WINDOWS:
                assert os.getsid(pids[0]) == pids[0], 'daemon must lead its own session'
                info = os.lstat(socket_dir)
                assert stat.S_ISDIR(info.st_mode) and info.st_mode & 0o777 == 0o700 and info.st_uid == os.getuid()
                assert (state_dir / 'daemon.log').stat().st_mode & 0o777 == 0o600
            row('1: first webhook starts exactly one detached daemon and returns connected without hanging')
            # 5: a healthy daemon never causes a subprocess.
            log_size = (state_dir / 'daemon.log').stat().st_size
            shims, calls = Path(d, 'shims'), Path(d, 'spawned')
            path = None
            if not WINDOWS:
                shims.mkdir()
                for name in ['systemctl', 'launchctl', 'ting-daemon', 'schtasks', 'sudo']:
                    (shims / name).write_text(f'#!/bin/sh\necho {name} >> "{calls}"\nexit 1\n')
                    (shims / name).chmod(0o755)
                path = f'{shims}{os.pathsep}{env.get("PATH", os.defpath)}'
            trace = Path(d, 'trace')
            strace = ('strace', '-f', '-qq', '-e', 'trace=execve', '-o', str(trace))
            use_strace = sys.platform.startswith('linux') and shutil.which('strace') and subprocess.run([*strace, 'true'], capture_output=True).returncode == 0
            result = silicon('webhook', url, '--id', hook_id, path=path, prefix=strace if use_strace else ())
            assert result.returncode == 0 and json.loads(result.stdout)['state'] == 'connected', result.stderr
            assert not calls.exists() and daemons() == pids and (state_dir / 'daemon.log').stat().st_size == log_size
            if use_strace:
                assert sum('execve(' in line for line in trace.read_text().splitlines()) == 1, trace.read_text()
            row('5: webhook with a running daemon spawns no systemctl, launchctl or ting-daemon' + (' (strace)' if use_strace else ''))
            if not WINDOWS:
                # 4: SIGTERM, as sent by kill and systemctl stop, removes the socket.
                socket_path = socket_dir / 'daemon.sock'
                stop(pids[0])
                assert not os.path.lexists(socket_path)
                row('4: SIGTERM removes daemon.sock')
                # 10: from a terminal: no polkit text, and the daemon does not keep the terminal.
                child, terminal = pty.fork()
                if child == 0:
                    try:
                        os.chdir(d)
                        os.execve(str(binary), [str(binary), 'webhook', url, '--id', hook_id, '--json'], env)
                    finally:
                        os._exit(127)
                output, deadline = b'', time.monotonic() + 30
                while True:
                    assert select.select([terminal], [], [], max(0, deadline - time.monotonic()))[0], 'terminal session hung'
                    try:
                        chunk = os.read(terminal, 4096)
                    except OSError:
                        break
                    if not chunk: break
                    output += chunk
                os.close(terminal)
                assert os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]) == 0, output
                assert b'AUTHENTICATING' not in output and b'"state":"connected"' in output, output
                pids = daemons()
                assert len(pids) == 1 and os.getsid(pids[0]) == pids[0]
                row('10: a start from a controlling terminal prints no polkit text and detaches')
            # 3: SIGKILL leaves a stale socket; the next command replaces it.
            def refused():
                # Inode numbers are reused after unlink, so test the socket itself.
                probe = socket.socket(socket.AF_UNIX)
                try:
                    probe.connect(str(socket_dir / 'daemon.sock'))
                    return False
                except ConnectionRefusedError:
                    return True
                finally:
                    probe.close()
            killed = daemons()[0]
            stop(killed, force=True)
            if not WINDOWS: assert os.path.lexists(socket_dir / 'daemon.sock') and refused(), 'SIGKILL should leave a stale socket'
            assert connected('--id', hook_id) == hook_id
            pids = daemons()
            assert len(pids) == 1 and pids[0] != killed
            if not WINDOWS: assert not refused(), 'the stale socket was not replaced'
            row('3: after SIGKILL the next webhook recovers and replaces the stale socket')
            # 2: concurrent starts end with one daemon.
            stop(pids[0], force=WINDOWS)
            starts = [subprocess.Popen([str(binary), 'daemon', 'start', '--json'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, env=env, cwd=d) for _ in range(10)]
            outputs = [process.communicate(timeout=60) for process in starts]
            assert all(process.returncode == 0 for process in starts), outputs
            assert all(json.loads(out) == {'running': True} for out, _ in outputs), outputs
            assert len(daemons()) == 1
            row('2: 10 parallel daemon starts all exit 0 with exactly one daemon')
            if os.environ.get('TING_SMOKE_SYSTEM_SERVICE') == '1':
                # 7: an old install's system unit keeps working, and is never asked to prompt.
                assert sys.platform.startswith('linux') and Path('/run/systemd/system').is_dir()
                for pid in daemons(): stop(pid)
                user = pwd.getpwuid(os.getuid())
                unit = Path(d, 'silicon-ting.service')
                unit.write_text(f"""[Unit]
Description=Ting smoke system service
[Service]
Type=notify
NotifyAccess=main
User={user.pw_name}
ExecStart={daemon_binary}
Restart=always
RestartSec=5
UMask=0077
Environment=HOME={user.pw_dir}
[Install]
WantedBy=multi-user.target
""")
                sudo('install', '-m', '644', unit, '/etc/systemd/system/silicon-ting.service')
                try:
                    sudo('systemctl', 'daemon-reload')
                    sudo('systemctl', 'enable', '--now', 'silicon-ting.service')
                    main_pid = lambda: int(subprocess.run(['systemctl', 'show', '-p', 'MainPID', '--value', 'silicon-ting.service'], capture_output=True, text=True).stdout or 0)
                    wait_until(lambda: main_pid() and daemons() == [main_pid()] and os.path.lexists(socket_dir / 'daemon.sock'), 'system unit daemon')
                    assert connected('--id', hook_id) == hook_id
                    assert daemons() == [main_pid()]
                    row('7: a running system unit is used; no new daemon')
                    sudo('systemctl', 'stop', 'silicon-ting.service')
                    assert connected('--id', hook_id) == hook_id
                    assert len(daemons()) == 1
                    row('7: a stopped system unit is started without a prompt, or replaced by an on-demand daemon')
                finally:
                    subprocess.run(['sudo', '-n', 'systemctl', 'disable', '--now', 'silicon-ting.service'], capture_output=True)
                    subprocess.run(['sudo', '-n', 'rm', '-f', '/etc/systemd/system/silicon-ting.service'], capture_output=True)
                    subprocess.run(['sudo', '-n', 'systemctl', 'daemon-reload'], capture_output=True)
        except BaseException:
            log = state_dir / 'daemon.log'
            if log.exists(): print('daemon.log:\n' + log.read_text(errors='replace')[-4000:], file=sys.stderr)
            raise
        finally:
            # Both directories were absent at the start and belong only to this run.
            for pid in daemons(): stop(pid, force=True)
            shutil.rmtree(state_dir, ignore_errors=True)
            if socket_dir and os.path.lexists(socket_dir):
                if os.lstat(socket_dir).st_uid == os.getuid(): shutil.rmtree(socket_dir, ignore_errors=True)
                else: subprocess.run(['sudo', '-n', 'rm', '-rf', str(socket_dir)], capture_output=True)
server.shutdown()
print('CLI smoke passed: login replacement/recovery, canonical org, exact proof bytes, sent read/unread, private files, input rejection, origin isolation'
      + (f', on-demand daemon rows {", ".join(sorted(set(passed), key=int))}.' if passed else '; on-demand daemon rows skipped.'))
