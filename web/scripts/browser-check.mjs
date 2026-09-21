import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const origin = process.env.TING_WEB_TEST_ORIGIN || 'http://127.0.0.1:5173';
const browser = await chromium.launch({ channel: 'chrome', headless: true });
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1050 } });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  let readCalls = 0, authenticated = false, read = false;
  const ting = { id: 'smoke-ting', created_at: new Date().toISOString(), type: 'tos>demo.messages.received', for: 'c_smoke', key: 'smoke-key', silent: false };
  await page.route('**/v1/**', async route => {
    const url = new URL(route.request().url()), path = decodeURIComponent(url.pathname);
    let status = 200, body;
    if (path === '/v1/me') { status = authenticated ? 200 : 401; body = authenticated ? { id: 'c_smoke', kind: 'carbon', authenticated: true } : { error: { code: 'authentication_required', message: 'Sign in required.' } }; }
    else if (path === '/v1/orgs') body = { items: [{ id: 'tos', name: 'TOS' }] };
    else if (path.endsWith('/apps')) body = { items: [{ app_id: 'tos>demo', name: 'Demo', can_manage_tings: true }] };
    else if (path.endsWith('/inbox/read')) { readCalls++; read = true; body = { message_ids: ['smoke-ting'], read: true }; }
    else if (path.endsWith('/inbox/smoke-ting')) body = { ...ting, read, data: { text: 'Smoke test payload', url: 'javascript:alert(1)' }, metadata: {} };
    else if (path.endsWith('/inbox')) body = { items: url.searchParams.get('silent') === 'true' ? [] : [{ ...ting, read }] };
    else body = { items: [] };
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.routeWebSocket('**/v1/ws?protocol=v1', ws => { ws.send(JSON.stringify({ op: 'ready', receiver_id: 'smoke-receiver', protocol: 'v1' })); ws.onMessage(data => { const message = JSON.parse(data); if (message.op === 'watch_inbox') ws.send(JSON.stringify({ op: 'watching_inbox', request_id: message.request_id, org_id: message.org_id })); }); });
  await page.goto(origin);
  await page.getByRole('heading', { name: /Good things start/ }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Connect with IAM', exact: true }).count(), 1);
  await page.screenshot({ path: '/tmp/ting-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, 'Mobile layout must not overflow');
  await page.getByRole('button', { name: 'Toggle navigation' }).click();
  await page.getByRole('link', { name: 'Documentation' }).click();
  await page.getByRole('heading', { name: /Make yourself heard/ }).waitFor();
  await page.screenshot({ path: '/tmp/ting-mobile-docs.png', fullPage: true });
  authenticated = true;
  await page.setViewportSize({ width: 1440, height: 1050 });
  await page.goto(origin);
  await page.getByRole('button', { name: /tos>demo.messages.received/ }).waitFor();
  assert.equal(readCalls, 0, 'Inbox fetching must never acknowledge a ting');
  await page.getByRole('button', { name: /tos>demo.messages.received/ }).click();
  await page.getByText('Smoke test payload', { exact: true }).waitFor();
  await page.waitForFunction(() => document.querySelector('.detail-body .tag-row')?.textContent.includes('Read'));
  assert.equal(readCalls, 1, 'Opening a visible ting sends one read acknowledgement');
  assert.equal(await page.getByRole('link', { name: 'Open link' }).count(), 0, 'Unsafe payload links must not render');
  await page.getByRole('button', { name: 'Close ting details' }).click();
  await page.getByRole('tab', { name: 'Silent', exact: true }).click();
  await page.getByRole('heading', { name: 'A little peace and quiet.' }).waitFor();
  assert.equal(readCalls, 1, 'Switching inbox filters must not acknowledge unseen tings');
  await page.getByRole('link', { name: 'Applications', exact: true }).click();
  await page.getByRole('button', { name: 'Register type' }).click();
  await page.getByRole('textbox', { name: 'Type name', exact: true }).fill('tos>other.messages.received');
  await page.getByRole('textbox', { name: 'Description', exact: true }).fill('Description');
  await page.getByRole('button', { name: 'Register type', exact: true }).last().click();
  await page.getByText('Use app_id.service.event, with lowercase service and event names.').waitFor();
  assert.deepEqual(errors, [], 'No browser runtime errors');
  console.log('Chrome browser checks passed: public/mobile/docs, live authenticated inbox, no background read ACK, visible read ACK, safe URLs, silent filtering, type ownership validation.');
} finally { await browser.close(); }
