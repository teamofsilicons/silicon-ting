import { test } from "node:test";
import assert from "node:assert/strict";
import { openIamPopup, completeIamPopup } from "./iam-popup.ts";

function browser(t) {
  const oldWindow = globalThis.window, oldHistory = globalThis.history;
  const listeners = new Map();
  const popup = { closed: false, location: { href: "" }, close() { this.closed = true; } };
  const window = { location: { origin: "https://app.example", href: "https://app.example/" }, open: () => popup, addEventListener: (name, fn) => listeners.set(name, fn), removeEventListener: name => listeners.delete(name), opener: null, close() {} };
  globalThis.window = window; globalThis.history = { replaceState() {} };
  t.after(() => { globalThis.window = oldWindow; globalThis.history = oldHistory; });
  return { window, popup, send: data => listeners.get("message")?.(data) };
}
test("popup completion requires the exact origin, opened window and unpredictable nonce", async t => {
  const b = browser(t); let nonce, completed = false;
  const result = openIamPopup(value => { nonce = value; return "/start?nonce=" + value; }).then(() => { completed = true; });
  await Promise.resolve();
  assert.match(nonce, /^[a-f0-9]{64}$/);
  const good = { origin: "https://app.example", source: b.popup, data: { type: "silicon:iam-login-complete", nonce, result: "ok" } };
  b.send({ ...good, origin: "https://wrong.example" });
  b.send({ ...good, source: {} });
  b.send({ ...good, data: { ...good.data, nonce: "0".repeat(64) } });
  await Promise.resolve(); assert.equal(completed, false);
  b.send(good); await result;
  assert.equal(completed, true); assert.equal(b.popup.closed, true);
});
test("blocked popups fail clearly and completion never sends callback credentials", async t => {
  const b = browser(t); b.window.open = () => null;
  await assert.rejects(openIamPopup(() => "/start"), /Allow popups/);
  let message, origin;
  b.window.opener = { postMessage(value, target) { message = value; origin = target; } };
  b.window.location.href = "https://app.example/?iam_popup=complete&nonce=" + "a".repeat(64) + "&result=ok&slt=must-not-be-forwarded";
  assert.equal(completeIamPopup(), true);
  assert.equal(origin, "https://app.example");
  assert.deepEqual(message, { type: "silicon:iam-login-complete", nonce: "a".repeat(64), result: "ok" });
});
