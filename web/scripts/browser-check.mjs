import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const origin = process.env.TING_WEB_TEST_ORIGIN || 'http://127.0.0.1:5173';
const browser = await chromium.launch({ channel: 'chrome', headless: true });
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1050 } });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  let readCalls = 0, authenticated = false, read = false, unreadAfterRead = false, inboxSocket;
  let requiredDelivery = false, failRequiredDelivery = false, appCatalogCalls = 0, inboxCalls = 0;
  const preferenceWrites = [];
  const requiredDeliveryWrites = [];
  const subscription = { id: 'sub-smoke-original', app_id: 'demo', for: 'c:smoke', active: true };
  const ting = { id: 'smoke-ting', created_at: new Date().toISOString(), type: 'demo.messages.received', for: 'c:smoke', key: 'smoke-key', silent: false };
  await page.route('**/v1/**', async route => {
    const url = new URL(route.request().url()), path = decodeURIComponent(url.pathname);
    let status = 200, body;
    if (path === '/v1/me') { status = authenticated ? 200 : 401; body = authenticated ? { id: 'c:smoke', kind: 'carbon', authenticated: true } : { error: { code: 'authentication_required', message: 'Sign in required.' } }; }
    else if (path === '/v1/orgs') body = { items: [{ id: 'bricks', name: 'Bricks' }] };
    else if (path.endsWith('/apps')) { appCatalogCalls++; body = { items: [{ app_id: 'local', name: 'Local app', can_manage_tings: true }] }; }
    else if (path.endsWith('/preferences') && route.request().method() === 'PUT') {
      body = route.request().postDataJSON();
      preferenceWrites.push({ path, body });
    }
    else if (route.request().method() === 'PUT') {
      const write = { path, body: route.request().postDataJSON() };
      requiredDeliveryWrites.push(write);
      assert.equal(path, `/v1/orgs/bricks/subscriptions/${subscription.id}/required-delivery`, 'Consent must target the original subscription');
      assert.equal(typeof write.body.enabled, 'boolean');
      if (failRequiredDelivery) { status = 503; body = { error: { code: 'dependency_unavailable', message: 'Required delivery could not be updated.', hint: 'Try again later.' } }; }
      else { requiredDelivery = write.body.enabled; body = { id: subscription.id, app_id: subscription.app_id, for: subscription.for, enabled: requiredDelivery }; }
    }
    else if (path.endsWith('/subscriptions')) body = { items: [{ ...subscription, required_delivery: requiredDelivery }] };
    else if (path.endsWith('/inbox/read')) { readCalls++; read = !unreadAfterRead; body = { message_ids: ['smoke-ting'], read: true }; }
    else if (path.endsWith('/inbox/smoke-ting')) body = { ...ting, read, data: { text: 'Smoke test payload', url: 'javascript:alert(1)' }, metadata: {} };
    else if (path.endsWith('/inbox')) { inboxCalls++; body = { items: url.searchParams.get('silent') === 'true' ? [] : [{ ...ting, read }] }; }
    else body = { items: [] };
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  });
  await page.routeWebSocket('**/v1/ws?protocol=v1', ws => { inboxSocket = ws; ws.send(JSON.stringify({ op: 'ready', receiver_id: 'smoke-receiver', protocol: 'v1' })); ws.onMessage(data => { const message = JSON.parse(data); if (message.op === 'watch_inbox') ws.send(JSON.stringify({ op: 'watching_inbox', request_id: message.request_id, org_id: message.org_id })); }); });
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
  await page.evaluate(() => localStorage.setItem('ting.org', 'retired-organization'));
  await page.goto(origin);
  await page.getByRole('alert').filter({ hasText: 'Your saved organization is no longer available.' }).waitFor();
  assert.equal(inboxCalls, 0, 'A stale organization must not fall back to another organization');
  await page.getByRole('combobox', { name: 'Active organization', exact: true }).selectOption('bricks');
  await page.getByRole('button', { name: /demo.messages.received/ }).waitFor();
  assert.equal(readCalls, 0, 'Inbox fetching must never acknowledge a ting');
  assert.equal(appCatalogCalls, 0, 'Recipient inbox must not depend on app-management catalog access');
  await page.locator('#inbox-apps option[value="demo"]').waitFor({ state: 'attached' });
  assert.equal(await page.locator('#inbox-apps option[value="local"]').count(), 0, 'Inbox suggestions must come from recipient connections');
  const appFilter = page.getByRole('combobox', { name: 'Filter by application', exact: true });
  let filtered = page.waitForRequest(request => new URL(request.url()).pathname.endsWith('/inbox') && new URL(request.url()).searchParams.get('app_id') === 'demo');
  await appFilter.fill('demo');
  await appFilter.press('Tab');
  assert.equal(new URL((await filtered).url()).pathname, '/v1/orgs/bricks/inbox', 'Filter foreign apps in the recipient org');
  filtered = page.waitForRequest(request => new URL(request.url()).pathname.endsWith('/inbox') && new URL(request.url()).searchParams.get('app_id') === 'unlisted');
  await appFilter.fill('unlisted');
  await appFilter.press('Tab');
  await filtered;
  await appFilter.fill('');
  await appFilter.press('Tab');
  await page.screenshot({ path: '/tmp/ting-cross-org-inbox.png', fullPage: true });
  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    await page.waitForFunction(() => document.querySelector('.sidebar').getBoundingClientRect().right <= 1);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `Inbox filters must not overflow at ${width}px`);
    assert.equal(await appFilter.evaluate(input => { const box = input.getBoundingClientRect(); return box.left >= 0 && box.right <= innerWidth; }), true, `Application filter must fit at ${width}px`);
    await page.screenshot({ path: `/tmp/ting-cross-org-inbox-${width}.png`, fullPage: true });
  }
  await page.setViewportSize({ width: 1440, height: 1050 });
  await page.getByRole('button', { name: /demo.messages.received/ }).click();
  await page.getByText('Smoke test payload', { exact: true }).waitFor();
  await page.waitForFunction(() => document.querySelector('.detail-body .tag-row')?.textContent.includes('Read'));
  assert.equal(readCalls, 1, 'Opening a visible ting sends one read acknowledgement');
  assert.equal(await page.getByRole('link', { name: 'Open link' }).count(), 0, 'Unsafe payload links must not render');
  read = false;
  inboxSocket.send(JSON.stringify({ op: 'inbox_changed', org_id: 'bricks' }));
  await page.waitForFunction(() => document.querySelector('.detail-body .tag-row')?.textContent.includes('Unread'));
  assert.equal(readCalls, 1, 'An app unread hint refreshes the open drawer without undoing it');
  read = true;
  inboxSocket.send(JSON.stringify({ op: 'watching_inbox', org_id: 'bricks' }));
  await page.waitForFunction(() => document.querySelector('.detail-body .tag-row')?.textContent.includes('Read'));
  assert.equal(readCalls, 1, 'Reconnecting refreshes the open drawer without a read ACK');
  read = false;
  const foregroundAck = page.waitForResponse(response => response.url().endsWith('/inbox/read'));
  await page.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'hidden' });
    document.dispatchEvent(new Event('visibilitychange'));
    Object.defineProperty(document, 'visibilityState', { configurable: true, value: 'visible' });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await foregroundAck;
  await page.waitForFunction(() => document.querySelector('.detail-body .tag-row')?.textContent.includes('Read'));
  assert.equal(readCalls, 2, 'Returning to a visible unread drawer acknowledges the fresh server state');
  await page.getByRole('button', { name: 'Close ting details' }).click();
  read = false; unreadAfterRead = true;
  const reopenedAck = page.waitForResponse(response => response.url().endsWith('/inbox/read'));
  await page.getByRole('button', { name: /demo.messages.received/ }).click();
  await reopenedAck;
  await page.waitForFunction(() => document.querySelector('.detail-body .tag-row')?.textContent.includes('Unread'));
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(readCalls, 3, 'Reopening permits another view ACK without overwriting a later app unread or looping');
  unreadAfterRead = false;
  await page.getByRole('button', { name: 'Close ting details' }).click();
  await page.getByRole('tab', { name: 'Silent', exact: true }).click();
  await page.getByRole('heading', { name: 'A little peace and quiet.' }).waitFor();
  assert.equal(readCalls, 3, 'Switching inbox filters must not acknowledge unseen tings');
  await page.getByRole('link', { name: 'Preferences', exact: true }).click();
  await page.locator('#preference-apps option[value="demo"]').waitFor({ state: 'attached' });
  await page.getByRole('combobox', { name: 'Application', exact: true }).fill('demo');
  await page.getByRole('button', { name: 'Save preference', exact: true }).click();
  await page.getByText('Preference saved.', { exact: true }).waitFor();
  assert.deepEqual(preferenceWrites, [{ path: '/v1/orgs/bricks/preferences', body: { app_id: 'demo', service: null, type: null, enabled: false } }]);
  assert.equal(appCatalogCalls, 0, 'Recipient preferences must not depend on app-management catalog access');
  await page.getByRole('link', { name: 'Applications', exact: true }).click();
  await page.getByRole('button', { name: 'Register type' }).click();
  await page.getByRole('textbox', { name: 'Type name', exact: true }).fill('other.messages.received');
  await page.getByRole('textbox', { name: 'Description', exact: true }).fill('Description');
  await page.getByRole('button', { name: 'Register type', exact: true }).last().click();
  await page.getByText('Use app_id.service.event, with lowercase service and event names.').waitFor();
  await page.getByRole('button', { name: 'Close type editor' }).click();
  await page.getByRole('link', { name: 'Connections', exact: true }).click();
  const consent = page.getByRole('checkbox', { name: 'Allow required automation delivery, even when notifications are muted', exact: true });
  await consent.waitFor();
  assert.equal(await consent.isChecked(), false, 'Required delivery must start disabled');
  assert.deepEqual(requiredDeliveryWrites, [], 'Listing connections must not grant required delivery');
  await consent.click();
  await page.getByText('Required automation delivery enabled.', { exact: true }).waitFor();
  await page.waitForFunction(() => document.querySelector('.required-delivery input')?.checked === true);
  assert.deepEqual(requiredDeliveryWrites, [{ path: `/v1/orgs/bricks/subscriptions/${subscription.id}/required-delivery`, body: { enabled: true } }]);
  await consent.click();
  await page.getByText('Required automation delivery disabled.', { exact: true }).waitFor();
  await page.waitForFunction(() => document.querySelector('.required-delivery input')?.checked === false);
  assert.deepEqual(requiredDeliveryWrites[1], { path: `/v1/orgs/bricks/subscriptions/${subscription.id}/required-delivery`, body: { enabled: false } });
  failRequiredDelivery = true;
  await consent.click();
  await page.getByRole('alert').filter({ hasText: 'Required delivery could not be updated.' }).waitFor();
  assert.equal(await consent.isChecked(), false, 'Failed consent updates must preserve the confirmed setting');
  assert.equal(requiredDelivery, false);
  assert.deepEqual(requiredDeliveryWrites[2], { path: `/v1/orgs/bricks/subscriptions/${subscription.id}/required-delivery`, body: { enabled: true } });
  assert.equal(requiredDeliveryWrites.length, 3, 'Only explicit consent actions may write');
  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    await page.waitForFunction(() => document.querySelector('.sidebar').getBoundingClientRect().right <= 1);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `Connections must not overflow at ${width}px`);
    assert.equal(await page.locator('.required-delivery').evaluate(label => {
      const box = label.getBoundingClientRect();
      return box.left >= 0 && box.right <= innerWidth && label.scrollWidth <= label.clientWidth;
    }), true, `Required-delivery consent must fit at ${width}px`);
  }
  await page.screenshot({ path: '/tmp/ting-mobile-connections.png', fullPage: true });
  assert.deepEqual(errors, [], 'No browser runtime errors');
  console.log('Mock Chrome browser checks passed: public/mobile/docs, authenticated inbox, no background read ACK, visible/repeated view ACK, app unread refresh and read race, reconnect/foreground drawer reconciliation, safe URLs, silent filtering, canonical Carbon IDs, stale organization rejection, cross-org app filtering/preferences without management access, type ownership validation, explicit required-delivery enable/disable and failed-update preservation, mobile Connections layout. No live IAM login or external API writes.');
} finally { await browser.close(); }
