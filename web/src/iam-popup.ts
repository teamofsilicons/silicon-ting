export type IdentityKind = "carbon" | "silicon";
type IamAction = "Sign-in" | "Honeycomb approval";
const messageType = "silicon:iam-login-complete";
const attemptKey = (nonce: string) => "ting.iam.attempt:" + nonce;
const failure = (action: IamAction) => new Error(action === "Honeycomb approval"
  ? "Honeycomb approval did not finish. Retry the saved approval, or start a new approval if you declined. Your Ting session is still active."
  : "IAM could not finish sign-in. Please try again.");

// Completion carries only a correlation nonce. The opener reloads its own
// server session; a window message never supplies identity or credentials.
export function completeIamPopup(onError?: (error: Error) => void): boolean {
  const url = new URL(window.location.href);
  if (url.searchParams.get("iam_popup") !== "complete") return false;
  const nonce = url.searchParams.get("nonce");
  const result = url.searchParams.get("result");
  history.replaceState(null, "", url.pathname + url.hash);
  if (!nonce || !/^[a-f0-9]{64}$/.test(nonce) || !["ok", "error"].includes(result || "")) return false;
  const saved = sessionStorage.getItem(attemptKey(nonce));
  sessionStorage.removeItem(attemptKey(nonce));
  let attempt;
  try { attempt = saved ? JSON.parse(saved) : undefined; } catch { /* Continue without a saved return path. */ }
  if (!attempt?.fullPage && window.opener && !window.opener.closed) {
    window.opener.postMessage({ type: messageType, nonce, result }, window.location.origin);
    window.close();
    return true;
  }
  // A blocked popup returns in this tab. Restore only this tab's matching
  // attempt and reload the server session; query parameters never sign us in.
  if (attempt) {
    try {
      const target = new URL(attempt.path, window.location.origin);
      if (target.origin === window.location.origin) history.replaceState(null, "", target.pathname + target.search + target.hash);
      if (result === "ok" && typeof attempt.pendingKey === "string") sessionStorage.removeItem(attempt.pendingKey);
      if (result === "error") onError?.(failure(attempt.action === "Honeycomb approval" ? attempt.action : "Sign-in"));
    } catch { /* A lost return path must not prevent loading the workspace. */ }
  }
  return false;
}

// False means the current tab is navigating through the full-page fallback.
export function openIamPopup(start: (nonce: string) => string | Promise<string>, action: IamAction = "Sign-in", pendingKey?: string): Promise<boolean> {
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(32)), value => value.toString(16).padStart(2, "0")).join("");
  const attempt = { path: window.location.pathname + window.location.search + window.location.hash, action, pendingKey };
  sessionStorage.setItem(attemptKey(nonce), JSON.stringify(attempt));
  const popup = window.open("about:blank", "iam-" + nonce, "popup,width=520,height=760");
  if (!popup) return Promise.resolve().then(() => {
    sessionStorage.setItem(attemptKey(nonce), JSON.stringify({ ...attempt, fullPage: true }));
    return start(nonce);
  }).then(url => {
    window.location.assign(url);
    return false;
  }).catch(error => { sessionStorage.removeItem(attemptKey(nonce)); throw error; });
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      sessionStorage.removeItem(attemptKey(nonce));
      window.removeEventListener("message", receive);
      clearInterval(closed);
      clearTimeout(timeout);
      popup.close();
      if (error) reject(error); else { if (pendingKey) sessionStorage.removeItem(pendingKey); resolve(true); }
    };
    const receive = (event: MessageEvent) => {
      if (event.origin !== window.location.origin || event.source !== popup || event.data?.type !== messageType || event.data?.nonce !== nonce) return;
      if (event.data.result === "ok") finish();
      else if (event.data.result === "error") finish(failure(action));
    };
    const closed = setInterval(() => { if (popup.closed) finish(new Error(`${action} was cancelled when its window closed. You can try again.`)); }, 500);
    const timeout = setTimeout(() => finish(new Error(`${action} expired. You can try again.`)), 600_000);
    window.addEventListener("message", receive);
    Promise.resolve().then(() => start(nonce)).then(url => { if (!settled) popup.location.href = url; }).catch(error => finish(error instanceof Error ? error : new Error(`Unable to start ${action.toLowerCase()}.`)));
  });
}
