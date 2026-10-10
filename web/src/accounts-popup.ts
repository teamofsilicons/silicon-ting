const messageType = 'silicon:accounts-login-complete';
const attemptKey = (nonce: string) => 'ting.accounts.attempt:' + nonce;
const failure = () => new Error('Silicon Accounts could not finish sign-in. Please try again.');

// Completion carries only a nonce. Identity and credentials come from the server session.
export function completeAccountsPopup(onError?: (error: Error) => void): boolean {
  const url = new URL(window.location.href);
  if (url.searchParams.get('accounts_popup') !== 'complete') return false;
  const nonce = url.searchParams.get('nonce'), result = url.searchParams.get('result');
  history.replaceState(null, '', url.pathname + url.hash);
  if (!nonce || !/^[a-f0-9]{64}$/.test(nonce) || !['ok', 'error'].includes(result || '')) return false;
  const saved = sessionStorage.getItem(attemptKey(nonce));
  sessionStorage.removeItem(attemptKey(nonce));
  let attempt: { path?: string; fullPage?: boolean } | undefined;
  try { attempt = saved ? JSON.parse(saved) : undefined; } catch { /* A lost return path must not block sign-in. */ }
  if (!attempt?.fullPage && window.opener && !window.opener.closed) {
    window.opener.postMessage({ type: messageType, nonce, result }, window.location.origin);
    window.close();
    return true;
  }
  if (attempt?.path) {
    try {
      const target = new URL(attempt.path, window.location.origin);
      if (target.origin === window.location.origin) history.replaceState(null, '', target.pathname + target.search + target.hash);
      if (result === 'error') onError?.(failure());
    } catch { /* A lost return path must not block sign-in. */ }
  }
  return false;
}

// False means this tab is navigating through the blocked-popup fallback.
export function openAccountsPopup(start: (nonce: string) => string | Promise<string>): Promise<boolean> {
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(32)), value => value.toString(16).padStart(2, '0')).join('');
  const attempt = { path: window.location.pathname + window.location.search + window.location.hash };
  sessionStorage.setItem(attemptKey(nonce), JSON.stringify(attempt));
  const popup = window.open('about:blank', 'accounts-' + nonce, 'popup,width=520,height=760');
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
      window.removeEventListener('message', receive);
      clearInterval(closed); clearTimeout(timeout); popup.close();
      if (error) reject(error); else resolve(true);
    };
    const receive = (event: MessageEvent) => {
      if (event.origin !== window.location.origin || event.source !== popup || event.data?.type !== messageType || event.data?.nonce !== nonce) return;
      if (event.data.result === 'ok') finish();
      else if (event.data.result === 'error') finish(failure());
    };
    const closed = setInterval(() => { if (popup.closed) finish(new Error('Sign-in was cancelled when its window closed. You can try again.')); }, 500);
    const timeout = setTimeout(() => finish(new Error('Sign-in expired. You can try again.')), 600_000);
    window.addEventListener('message', receive);
    Promise.resolve().then(() => start(nonce)).then(url => { if (!settled) popup.location.href = url; }).catch(error => finish(error instanceof Error ? error : failure()));
  });
}
