#!/usr/bin/env python3
"""Verify immediate retention pause using one explicitly isolated, guarded backdated row.

Requires the live-test fixture plus permission to backdate only this new test row
through the specified AWS Systems Manager instance. Never touches production context.
"""
import argparse
import base64
import datetime
import importlib.util
import json
import pathlib
import subprocess
import time
import uuid

spec = importlib.util.spec_from_file_location('ting_live_checks', pathlib.Path(__file__).with_name('live-test.py'))
live = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)


def aws(*arguments):
    result = subprocess.run(['aws', *arguments, '--region', 'us-east-1', '--output', 'json'],
                            capture_output=True, text=True, timeout=35)
    if result.returncode:
        if arguments[:2] == ('ssm', 'get-command-invocation') and 'InvocationDoesNotExist' in result.stderr:
            return {'Status': 'Pending'}
        raise RuntimeError('AWS Systems Manager operation failed; inspect the isolated test command.')
    return json.loads(result.stdout)


def backdate(instance, fixture, message):
    assert uuid.UUID(fixture['environment_id']).int
    payload = {'context': fixture['environment_id'], 'org': fixture['org_id'],
               'app': fixture['sender_app_id'], 'recipient': fixture['actor_id'],
               'id': message['id'], 'created': message['created_at'],
               'backdated': (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=60))
               .isoformat(timespec='milliseconds').replace('+00:00', 'Z')}
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    code = """import base64,json,sqlite3,uuid
p=json.loads(base64.b64decode('%s'))
assert uuid.UUID(p['context']).int and p['context']!='production'
db=sqlite3.connect('file:/var/lib/ting/ting.sqlite?mode=rw',uri=True,timeout=10)
db.execute('BEGIN IMMEDIATE')
r=db.execute('SELECT ctx,org,app,recipient,created,silent,read,body FROM tings WHERE id=?',(p['id'],)).fetchone()
assert r and r[:5]==(p['context'],p['org'],p['app'],p['recipient'],p['created']) and r[5:7]==(0,0)
body=json.loads(r[7]);assert body['id']==p['id'] and body['created_at']==p['created']
body['created_at']=p['backdated']
changed=db.execute('UPDATE tings SET created=?,body=? WHERE id=? AND ctx=?',(p['backdated'],json.dumps(body,separators=(',',':')),p['id'],p['context'])).rowcount
assert changed==1
db.commit();db.close();print('backdated_one_isolated_ting')
""" % encoded
    command = "set -eu\npython3 - <<'TING_RETENTION_TEST'\n" + code + "TING_RETENTION_TEST\n"
    sent = aws('ssm', 'send-command', '--instance-ids', instance,
               '--document-name', 'AWS-RunShellScript', '--comment', 'Guarded single Ting test-row retention check',
               '--parameters', json.dumps({'commands': [command], 'executionTimeout': ['30']}))
    command_id = sent['Command']['CommandId']
    deadline = time.monotonic() + 55
    while time.monotonic() < deadline:
        time.sleep(.5)
        result = aws('ssm', 'get-command-invocation', '--command-id', command_id, '--instance-id', instance)
        if result['Status'] == 'Success':
            assert result['StandardOutputContent'].strip() == 'backdated_one_isolated_ting'
            return command_id
        if result['Status'] in ('Failed', 'Cancelled', 'TimedOut'):
            raise RuntimeError('Guarded isolated retention backdate was rejected: ' + result['Status'])
    raise TimeoutError('Systems Manager did not finish the guarded test backdate')


def run(fixture, instance, report):
    checks = live.Checks(fixture)
    checks.run = live.key()
    hooks, socket, cleanup_errors = [], None, []
    result = {'environment_id': fixture['environment_id'], 'api_url': checks.api, 'complete': False}
    try:
        _, signed = checks.http('POST', '/v1/session', {'slt': checks.actor},
                                extra={'Idempotency-Key': live.key()}, expected=201)
        checks.session = signed['session_token']
        # Clear only this isolated recipient's old backlog before the controlled case.
        while True:
            _, page = checks.http('GET', checks.prefix + '/inbox?read=false&limit=100')
            if not page['items']:
                break
            checks.http('POST', checks.prefix + '/inbox/read', {'message_ids': [x['id'] for x in page['items']]})
        checks.app_call('/v1/subscriptions', {'org_id': checks.org, 'app_id': checks.app, 'for': checks.actor}, expected=(200, 201))
        _, message = checks.app_call('/v1/tings', checks.send(), expected=202)
        assert message['silent'] is False
        result['backdate_command_id'] = backdate(instance, fixture, message)
        # Create receivers after SSM completes, avoiding an idle socket during dispatch.
        socket = checks.socket()
        socket.call('subscribe', org_id=checks.org, session_token=checks.session, webhook_ids=[], headers=checks.test)
        for _ in range(2):
            _, hook = checks.http('POST', checks.prefix + '/webhooks', {'receiver_id': socket.receiver},
                                  extra={'Idempotency-Key': live.key()}, expected=201)
            hooks.append(hook['id'])
        for hook in hooks:
            socket.delivery(hook, message['id'])
        socket.call('ack', org_id=checks.org, webhook_id=hooks[0], message_ids=[message['id']], kind='read')
        paused = any(x.get('op') == 'paused' and hooks[1] in x.get('webhook_ids', []) for x in socket.pending)
        deadline = time.monotonic() + 10
        while not paused:
            response = socket.receive(deadline)
            paused = response.get('op') == 'paused' and hooks[1] in response.get('webhook_ids', [])
        checks.http('GET', checks.prefix + '/inbox/' + message['id'], expected=404)
        _, current = checks.http('GET', checks.prefix + '/webhooks')
        owned = [h for h in current['items'] if h['id'] in hooks]
        assert len(owned) == 2 and all(h['pending'] == 0 for h in owned)
        result.update(complete=True, other_hook_paused=True, expired_inbox_status=404,
                      both_hook_pending_counts=[h['pending'] for h in owned], message_id=message['id'])
        return result
    finally:
        if socket:
            socket.close()
        for hook in hooks:
            try:
                checks.http('DELETE', checks.prefix + '/webhooks/' + hook)
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        if checks.session:
            try:
                checks.http('DELETE', '/v1/session')
            except Exception as error:
                cleanup_errors.append(type(error).__name__)
        result['cleanup_errors'] = cleanup_errors
        result['completed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        report.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', required=True, type=pathlib.Path)
    parser.add_argument('--instance-id', required=True)
    parser.add_argument('--report', type=pathlib.Path, default=pathlib.Path('deploy/live-retention-test-results.json'))
    ARGS = parser.parse_args()
    output = run(json.loads(ARGS.fixture.read_text()), ARGS.instance_id, ARGS.report)
    assert output['complete'] and not output['cleanup_errors']
    print('PASS immediate retention pause, inbox404 and both pending counts0; owned hooks and session cleaned')
