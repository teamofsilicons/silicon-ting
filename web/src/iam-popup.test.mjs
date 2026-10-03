import { test } from "node:test";
import assert from "node:assert/strict";
import { openIamPopup, completeIamPopup } from "./iam-popup.ts";

function browser(t) {
  const oldWindow = globalThis.window, oldHistory = globalThis.history, oldStorage = globalThis.sessionStorage;
  const listeners = new Map(), storage = new Map();
  const popup = { closed: false, location: { href: "" }, close() { this.closed = true; } };
  const location = new URL("https://app.example/#apps");
  location.assign = value => { location.href = new URL(value, location.origin).href; };
  const window = { location, open: () => popup, addEventListener: (name, fn) => listeners.set(name, fn), removeEventListener: name => listeners.delete(name), opener: null, close() {} };
  globalThis.window = window;
  globalThis.history = { replaceState(_state, _title, path) { location.assign(path); } };
  globalThis.sessionStorage = { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) };
  t.after(() => { globalThis.window = oldWindow; globalThis.history = oldHistory; globalThis.sessionStorage = oldStorage; });
  return { window, popup, storage, send: data => listeners.get("message")?.(data) };
}
test("popup completion requires the exact origin, opened window and unpredictable nonce", async t => {
  const b = browser(t); let nonce, completed = false;
  const result = openIamPopup(value => { nonce = value; return "/start?nonce=" + value; }).then(value => { completed = value; });
  await Promise.resolve();
  assert.match(nonce, /^[a-f0-9]{64}$/);
  const good = { origin: "https://app.example", source: b.popup, data: { type: "silicon:iam-login-complete", nonce, result: "ok" } };
  b.send({ ...good, origin: "https://wrong.example" });
  b.send({ ...good, source: {} });
  b.send({ ...good, data: { ...good.data, nonce: "0".repeat(64) } });
  await Promise.resolve(); assert.equal(completed, false);
  b.send(good); await result;
  assert.equal(completed, true); assert.equal(b.popup.closed, true); assert.equal(b.storage.size, 0);
});
test("completion never sends callback credentials", t => {
  const b = browser(t); let message, origin;
  b.window.opener = { postMessage(value, target) { message = value; origin = target; } };
  b.window.location.href = "https://app.example/?iam_popup=complete&nonce=" + "a".repeat(64) + "&result=ok&slt=must-not-be-forwarded";
  assert.equal(completeIamPopup(), true);
  assert.equal(origin, "https://app.example");
  assert.deepEqual(message, { type: "silicon:iam-login-complete", nonce: "a".repeat(64), result: "ok" });
  assert.equal(b.window.location.search, "");
});
test("blocked popup uses full-page flow and restores its matching return destination", async t => {
  const b = browser(t); b.window.open = () => null; let nonce;
  b.window.opener = { postMessage() { assert.fail("A full-page fallback must not notify an unrelated opener"); } };
  b.storage.set("catalog-key", "same-mutation");
  assert.equal(await openIamPopup(value => { nonce = value; return "/start?nonce=" + value; }, "Honeycomb approval", "catalog-key"), false);
  assert.equal(b.window.location.pathname, "/start");
  b.window.location.href = `https://app.example/?iam_popup=complete&nonce=${nonce}&result=ok`;
  assert.equal(completeIamPopup(), false, "A full-page return must boot the app");
  assert.equal(b.window.location.href, "https://app.example/#apps");
  assert.equal(b.storage.size, 0, "Successful approval retires its mutation key");
});
test("approval denial keeps the saved mutation and gives approval-specific feedback", async t => {
  const b = browser(t); b.window.open = () => null; let nonce, error;
  b.storage.set("catalog-key", "same-mutation");
  await openIamPopup(value => { nonce = value; return "/start"; }, "Honeycomb approval", "catalog-key");
  b.window.location.href = `https://app.example/?iam_popup=complete&nonce=${nonce}&result=error`;
  assert.equal(completeIamPopup(value => { error = value; }), false);
  assert.match(error.message, /Honeycomb approval did not finish/);
  assert.equal(b.storage.get("catalog-key"), "same-mutation");
  assert.equal(b.window.location.hash, "#apps");
});
test("unmatched or malformed callbacks without an opener never block boot or restore a destination", t => {
  const b = browser(t); let error;
  b.storage.set("ting.iam.attempt:" + "a".repeat(64), JSON.stringify({ path: "/#settings" }));
  for (const nonce of ["invalid", "b".repeat(64)]) {
    b.window.location.href = `https://app.example/?iam_popup=complete&nonce=${nonce}&result=ok`;
    assert.equal(completeIamPopup(value => { error = value; }), false);
    assert.equal(b.window.location.href, "https://app.example/");
  }
  assert.equal(error, undefined);
});
test("popup closure cancels approval while keeping its mutation key", async t => {
  const b = browser(t); b.storage.set("catalog-key", "same-mutation");
  const result = openIamPopup(() => "/start", "Honeycomb approval", "catalog-key");
  b.popup.closed = true;
  await assert.rejects(result, /Honeycomb approval was cancelled/);
  assert.equal(b.storage.get("catalog-key"), "same-mutation");
});
