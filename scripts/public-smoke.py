#!/usr/bin/env python3
"""Check public HTTP boundaries without credentials or notification mutations."""
import argparse
import http.client
import json
from urllib.parse import urlsplit

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--url', default='https://backend.ting.teamofsilicons.com')
args = parser.parse_args()
origin = urlsplit(args.url)
assert origin.scheme == 'https' and not origin.username and not origin.query

checks = [
    ('discovery', 'GET', '/v1/iam', None, {}, 200, None),
    ('unauthenticated session', 'GET', '/v1/me', None, {}, 401, 'authentication_required'),
    ('foreign browser origin', 'GET', '/v1/iam', None, {'Origin': 'https://untrusted.example'}, 403, 'permission_denied'),
    ('browser mutation without origin', 'POST', '/v1/telemetry', b'{}', {'Cookie': 'ting_session=invalid'}, 403, 'permission_denied'),
    ('duplicate JSON keys', 'POST', '/v1/session', b'{"slt":"a","slt":"b"}', {}, 400, 'invalid_input'),
    ('unknown telemetry table', 'POST', '/v1/telemetry', b'{"table":"unknown","events":[]}', {}, 400, 'invalid_input'),
    ('telemetry byte limit', 'POST', '/v1/telemetry', json.dumps({'table': 'tingfrontendevents', 'events': [{'type': 'test', 'data': 'x' * 65536}]}).encode(), {}, 413, 'payload_too_large'),
    ('HTTP body byte limit', 'POST', '/v1/session', b'x' * (1024 * 1024 + 1), {}, 413, 'payload_too_large'),
    ('untrusted session', 'GET', '/v1/me', None, {'Authorization': 'Bearer invalid'}, 401, 'session_expired'),
    ('unknown route', 'GET', '/not-a-ting-route', None, {}, 404, 'not_found'),
]
for name, method, path, body, headers, status, code in checks:
    connection = http.client.HTTPSConnection(origin.hostname, origin.port or 443, timeout=30)
    try:
        connection.request(method, path, body, {'User-Agent': 'silicon-ting-smoke/1', 'Content-Type': 'application/json', **headers})
        response = connection.getresponse()
        payload = json.loads(response.read())
        assert response.status == status, (name, response.status, status)
        assert response.getheader('Ting-Request-Id'), (name, 'missing request ID')
        assert response.getheader('Content-Type', '').startswith('application/json'), name
        if code:
            assert payload.get('error', {}).get('code') == code, (name, payload)
            assert isinstance(payload['error'].get('retryable'), bool), name
        else:
            assert payload['app_id'] == 'tos>ting' and payload['api_version'] == 'v1', name
        print(json.dumps({'check': name, 'status': response.status, 'passed': True}))
    finally:
        connection.close()
print(json.dumps({'passed': len(checks), 'url': args.url}))
