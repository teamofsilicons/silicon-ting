export type IdentityKind = "carbon" | "silicon";
const messageType = "silicon:iam-login-complete";

// Completion carries only a correlation nonce. The opener reloads its own
// server session; a window message never supplies identity or credentials.
export function completeIamPopup(): boolean {
  const url = new URL(window.location.href);
  if (url.searchParams.get("iam_popup") !== "complete") return false;
  const nonce = url.searchParams.get("nonce");
  const result = url.searchParams.get("result");
  history.replaceState(null, "", url.pathname + url.hash);
  if (nonce && /^[a-f0-9]{64}$/.test(nonce) && ["ok", "error"].includes(result || "") && window.opener) {
    window.opener.postMessage({ type: messageType, nonce, result }, window.location.origin);
    window.close();
  }
  return true;
}

export function openIamPopup(start: (nonce: string) => string | Promise<string>): Promise<void> {
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(32)), value => value.toString(16).padStart(2, "0")).join("");
  const popup = window.open("about:blank", "iam-" + nonce, "popup,width=520,height=760");
  if (!popup) return Promise.reject(new Error("Allow popups for this site, then choose your account type again."));
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      window.removeEventListener("message", receive);
      clearInterval(closed);
      clearTimeout(timeout);
      popup.close();
      if (error) reject(error); else resolve();
    };
    const receive = (event: MessageEvent) => {
      if (event.origin !== window.location.origin || event.source !== popup || event.data?.type !== messageType || event.data?.nonce !== nonce) return;
      if (event.data.result === "ok") finish();
      else if (event.data.result === "error") finish(new Error("IAM could not finish sign-in. Please try again."));
    };
    const closed = setInterval(() => { if (popup.closed) finish(new Error("Sign-in was closed. Choose your account type to try again.")); }, 500);
    const timeout = setTimeout(() => finish(new Error("Sign-in expired. Choose your account type to try again.")), 600_000);
    window.addEventListener("message", receive);
    Promise.resolve().then(() => start(nonce)).then(url => { if (!settled) popup.location.href = url; }).catch(error => finish(error instanceof Error ? error : new Error("Unable to start sign-in.")));
  });
}
