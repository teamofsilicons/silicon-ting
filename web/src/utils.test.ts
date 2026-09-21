import { test } from 'node:test';
import assert from 'node:assert/strict';
import { orgPath, query, typeError, safeLink, watchDelay } from './utils.ts';

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
