#!/usr/bin/env python3
"""Check public HTTP boundaries without credentials or notification mutations."""
import argparse
import http.client
import json
from urllib.parse import urlsplit

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--url', default='https://backend.ting.teamofsilicons.com')
parser.add_argument('--browser-origin', action='append', default=[], help='Expected permitted browser origin; repeat for each integration')
parser.add_argument('--api-only', action='store_true', help='Skip routes outside /v1 when checking a frontend proxy')
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
    ('scoped receiver requires capability', 'GET', '/v1/receivers/me', None, {}, 401, 'receiver_expired'),
    ('full session cannot substitute for receiver capability', 'GET', '/v1/receivers/me', None, {'Authorization': 'Bearer ting_' + 'a' * 64}, 401, 'receiver_expired'),
    ('receiver capability cannot substitute for full session', 'GET', '/v1/me', None, {'Authorization': 'Bearer ting_recv_' + 'a' * 64}, 401, 'session_expired'),
    ('receiver bootstrap validates signed input', 'POST', '/v1/receivers/bootstrap', b'{}', {}, 400, 'invalid_input'),
    ('unknown route', 'GET', '/not-a-ting-route', None, {}, 404, 'not_found'),
]
for browser_origin in args.browser_origin:
    checks.extend([
        (f'{browser_origin} discovery CORS', 'GET', '/v1/iam', None, {'Origin': browser_origin}, 200, None),
        (f'{browser_origin} error CORS', 'GET', '/v1/me', None, {'Origin': browser_origin}, 401, 'authentication_required'),
        (f'{browser_origin} preflight CORS', 'OPTIONS', '/v1/me', None, {'Origin': browser_origin, 'Access-Control-Request-Method': 'GET'}, 204, None),
    ])
for name, method, path, body, headers, status, code in checks:
    if args.api_only and not path.startswith('/v1/'):
        continue
    connection = http.client.HTTPSConnection(origin.hostname, origin.port or 443, timeout=30)
    try:
        connection.request(method, path, body, {'User-Agent': 'silicon-ting-smoke/1', 'Content-Type': 'application/json', **headers})
        response = connection.getresponse()
        raw = response.read()
        assert response.status == status, (name, response.status, status)
        payload = json.loads(raw) if raw else None
        assert response.getheader('Ting-Request-Id'), (name, 'missing request ID')
        if status != 204:
            assert response.getheader('Content-Type', '').startswith('application/json'), name
        if headers.get('Origin') in args.browser_origin:
            assert response.getheader('Access-Control-Allow-Origin') == headers['Origin'], name
            assert response.getheader('Access-Control-Allow-Credentials') == 'true', name
            assert 'origin' in response.getheader('Vary', '').lower(), name
        elif headers.get('Origin'):
            assert response.getheader('Access-Control-Allow-Origin') is None, name
        if code:
            assert payload.get('error', {}).get('code') == code, (name, payload)
            assert isinstance(payload['error'].get('retryable'), bool), name
        elif status != 204:
            assert payload['app_id'] == 'ting' and payload['api_version'] == 'v1', name
        print(json.dumps({'check': name, 'status': response.status, 'passed': True}))
    finally:
        connection.close()
print(json.dumps({'passed': sum(not args.api_only or check[2].startswith('/v1/') for check in checks), 'url': args.url}))
