import { test } from 'node:test';
import assert from 'node:assert/strict';
import { orgPath, query, typeError, safeLink, watchDelay } from './utils.ts';
import { telemetryTransport } from './telemetry.ts';

test('browser request and validation boundaries', () => {
  assert.equal(orgPath('tos/a', 'apps'), '/v1/orgs/tos%2Fa/apps');
  assert.equal(query({ silent: false, read: undefined, cursor: 'a+b/c' }), '?silent=false&cursor=a%2Bb%2Fc');
  assert.equal(typeError('tos>dm', 'tos>dm.msg.received', 'Message arrived'), undefined);
  assert.ok(typeError('tos>dm', 'tos>other.msg.received', 'Message arrived'));
  assert.ok(typeError('tos>dm', 'tos>dm.msg.received', ''));
  assert.ok(typeError('tos>dm', 'tos>dm.msg.received', '😊'.repeat(251)));
  assert.equal(safeLink('javascript:alert(1)'), undefined);
  assert.equal(safeLink('https://example.com/a'), 'https://example.com/a');
  assert.equal(watchDelay(0, 0), 1000);
  assert.equal(watchDelay(1, 0), 2000);
  assert.equal(watchDelay(10, 1), 30000);
});

test('telemetry ignores extension errors and cools down after failed ingestion', async () => {
  let clock = 0, requests = 0;
  const batches: { events: unknown[] }[] = [];
  const send: typeof fetch = async (_, init) => {
    requests++;
    batches.push(JSON.parse(String(init?.body)));
    return new Response(null, { status: requests === 1 ? 503 : 202 });
  };
  const transport = telemetryTransport(send, 'https://ting.example', () => clock);
  const request = (events: unknown[]) => transport('/v1/telemetry', { body: JSON.stringify({ table: 'analytics', events }) });
  const ownError = { type: 'error', data: { kind: 'runtime', source: 'https://ting.example/assets/app.js' } };
  const noise = [{ type: 'error', data: { kind: 'unhandledrejection' } }, { type: 'error', data: { kind: 'runtime', source: 'chrome-extension://extension/script.js' } }];
  assert.equal((await request(noise)).status, 204);
  assert.equal(requests, 0);
  assert.equal((await request([...noise, ownError])).status, 503);
  assert.deepEqual(batches[0].events, [ownError]);
  await assert.rejects(request([{ type: 'page_view' }]));
  assert.equal(requests, 1);
  clock = 60_000;
  assert.equal((await request([{ type: 'page_view' }])).status, 202);
  assert.equal(requests, 2);
});
