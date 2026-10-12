'use client';

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { useToastStack } from '@/components/silicon-ui/toast-stack/toast-stack';
import { api, ApiError, sessionChanged, type Identity } from '@/lib/api';
import { completeAccountsPopup, openAccountsPopup } from '@/lib/accounts-popup';
import { legacyHashRoute } from '@/lib/routes';
import { enc, watchDelay } from '@/lib/utils';

export type Connection = 'offline' | 'connecting' | 'live' | 'reconnecting' | 'paused';
export type ThemePreference = 'light' | 'dark' | 'system';

type Workspace = {
  identity?: Identity;
  booting: boolean;
  bootError: unknown;
  boot: () => Promise<void>;
  busy: boolean;
  actionError: unknown;
  setActionError: (error: unknown) => void;
  /** Runs a mutation, shows `message` on success and reloads every list. */
  action: (work: () => Promise<unknown>, message?: string) => Promise<boolean>;
  revision: number;
  refresh: () => void;
  /** Increments whenever the live inbox watch reports a change. */
  inboxPulse: number;
  connection: Connection;
  unread: number;
  setUnread: (count: number) => void;
  login: { open: boolean; silicon: boolean };
  openLogin: (silicon?: boolean) => void;
  closeLogin: () => void;
  loginCarbon: () => Promise<void>;
  loginSilicon: (token: string) => Promise<boolean>;
  signOut: () => Promise<boolean>;
  theme: ThemePreference;
  setTheme: (theme: ThemePreference) => void;
};

const WorkspaceContext = createContext<Workspace | null>(null);

export function useWorkspace() {
  const workspace = useContext(WorkspaceContext);
  if (!workspace) throw new Error('useWorkspace must be used inside WorkspaceProvider.');
  return workspace;
}

const sessionExpired = () => new ApiError(401, 'session_expired', 'Your session has expired.', 'Sign in again to reconnect your inbox.');
const themeKey = 'ting.theme';

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { toast } = useToastStack();
  const [identity, setIdentity] = useState<Identity>();
  const [booting, setBooting] = useState(true);
  const [bootError, setBootError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<unknown>();
  const [revision, setRevision] = useState(0);
  const [inboxPulse, setInboxPulse] = useState(0);
  const [connection, setConnection] = useState<Connection>('offline');
  const [unread, setUnread] = useState(0);
  const [login, setLogin] = useState({ open: false, silicon: false });
  const [theme, setThemeState] = useState<ThemePreference>('light');
  const identityRef = useRef(identity);
  identityRef.current = identity;
  const loginAttempt = useRef<{ token: string; key: string }>(undefined);

  const refresh = useCallback(() => setRevision(value => value + 1), []);

  const boot = useCallback(async () => {
    setBooting(true); setBootError(undefined);
    try {
      const me = await api<Identity>('/v1/me');
      if (!['carbon', 'silicon'].includes(me.kind)) throw new Error('Silicon Accounts returned an unsupported account type.');
      setIdentity(me);
    } catch (error) { if (error instanceof ApiError && error.status === 401) setIdentity(undefined); else setBootError(error); }
    finally { setBooting(false); }
  }, []);

  const action = useCallback(async (work: () => Promise<unknown>, message?: string) => {
    setBusy(true); setActionError(undefined);
    try { await work(); if (message) toast({ type: 'success', title: message }); refresh(); return true; }
    catch (error) { setActionError(error); if (error instanceof ApiError && error.status === 401) setIdentity(undefined); return false; }
    finally { setBusy(false); }
  }, [refresh, toast]);

  const loginCarbon = useCallback(async () => {
    setBusy(true); setActionError(undefined);
    try {
      if (!await openAccountsPopup(nonce => `/v1/session/login?next=${enc(location.pathname)}&identity_kind=carbon&popup_nonce=${nonce}`)) return;
      const current = await api<Identity>('/v1/me');
      if (current.kind !== 'carbon') throw new Error('The selected account could not be verified. Please sign in again.');
      await boot(); setLogin({ open: false, silicon: false });
    } catch (error) { setActionError(error); }
    finally { setBusy(false); }
  }, [boot]);

  const loginSilicon = useCallback(async (raw: string) => {
    setBusy(true); setActionError(undefined);
    try {
      const token = raw.trim();
      if (!loginAttempt.current || loginAttempt.current.token !== token) loginAttempt.current = { token, key: crypto.randomUUID() };
      await api('/v1/session', 'POST', { slt: token }, { 'Idempotency-Key': loginAttempt.current.key });
      loginAttempt.current = undefined;
      await boot(); setLogin({ open: false, silicon: false });
      return true;
    } catch (error) { setActionError(error); return false; }
    finally { setBusy(false); }
  }, [boot]);

  const signOut = useCallback(() => action(async () => { await api('/v1/session', 'DELETE'); setIdentity(undefined); }, 'Signed out.'), [action]);
  const openLogin = useCallback((silicon = false) => setLogin({ open: true, silicon }), []);
  const closeLogin = useCallback(() => { setLogin({ open: false, silicon: false }); loginAttempt.current = undefined; }, []);

  const setTheme = useCallback((next: ThemePreference) => {
    setThemeState(next);
    try { localStorage.setItem(themeKey, next); } catch { /* The choice still applies to this visit. */ }
  }, []);

  useEffect(() => {
    try { const saved = localStorage.getItem(themeKey); if (saved === 'dark' || saved === 'system') setThemeState(saved); } catch { /* Light is the default. */ }
  }, []);

  useEffect(() => {
    const media = matchMedia('(prefers-color-scheme: dark)');
    const apply = () => { document.documentElement.dataset.theme = theme === 'system' ? media.matches ? 'dark' : 'light' : theme; };
    apply();
    if (theme !== 'system') return;
    media.addEventListener('change', apply);
    return () => media.removeEventListener('change', apply);
  }, [theme]);

  // Sign-in returns to `/` from Silicon Accounts. A popup hands its result to the opener; a full-page sign-in returns to where it began.
  useEffect(() => {
    if (completeAccountsPopup(setActionError, path => router.replace(path))) return;
    const legacy = location.pathname === '/' ? legacyHashRoute(location.hash) : undefined;
    if (legacy) router.replace(legacy);
    void boot();
    const expired = () => { if (!identityRef.current) return; setIdentity(undefined); setActionError(sessionExpired()); };
    window.addEventListener('ting:session-expired', expired);
    return () => window.removeEventListener('ting:session-expired', expired);
  }, [boot, router]);

  useEffect(() => { setActionError(undefined); }, [pathname]);

  useEffect(() => {
    sessionChanged();
    if (!identity) return;
    let expiry: ReturnType<typeof setTimeout>;
    const expire = () => {
      const remaining = new Date(identity.expires_at).getTime() - Date.now();
      if (!Number.isFinite(remaining)) return;
      if (remaining <= 0) { setIdentity(undefined); setActionError(sessionExpired()); }
      else expiry = setTimeout(expire, Math.min(remaining, 2_147_483_647));
    };
    expire();
    return () => clearTimeout(expiry);
  }, [identity]);

  useEffect(() => {
    if (!identity) { setConnection('offline'); return; }
    let stopped = false, attempt = 0, socket: WebSocket | undefined;
    let retry: ReturnType<typeof setTimeout> | undefined, healthy: ReturnType<typeof setTimeout> | undefined;
    const pulse = () => setInboxPulse(value => value + 1);
    const watch = () => { if (socket?.readyState === WebSocket.OPEN) { setConnection('connecting'); socket.send(JSON.stringify({ op: 'watch_inbox', request_id: crypto.randomUUID() })); } };
    const schedule = () => { clearTimeout(retry); setConnection('reconnecting'); retry = setTimeout(connect, watchDelay(attempt++)); };
    function connect() {
      if (stopped) return;
      const url = new URL('/v1/ws?protocol=v1', location.href); url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
      setConnection('connecting'); socket = new WebSocket(url);
      socket.onmessage = event => {
        let message: { op: string; reason?: string; error?: { code: string; message: string; hint?: string } };
        try { message = JSON.parse(event.data); } catch { return; }
        if (message.op === 'ready') watch();
        if (message.op === 'watching_inbox') { setConnection('live'); pulse(); clearTimeout(healthy); healthy = setTimeout(() => { attempt = 0; }, 60_000); }
        if (message.op === 'inbox_changed' && document.visibilityState === 'visible') pulse();
        if (message.op === 'paused' || message.op === 'error') {
          const reason = message.reason || message.error?.code;
          if (reason === 'session_expired' || reason === 'authentication_required') { setIdentity(undefined); setActionError(sessionExpired()); }
          else if (reason === 'permission_changed' || reason === 'permission_denied') { setConnection('paused'); setActionError(new ApiError(403, 'permission_denied', 'Access to this account has changed.', 'Check your access in Silicon Accounts, then retry.')); }
          else { setConnection('reconnecting'); clearTimeout(retry); retry = setTimeout(watch, watchDelay(attempt++)); }
        }
      };
      socket.onclose = () => { clearTimeout(healthy); if (!stopped) schedule(); };
      socket.onerror = () => socket?.close();
    }
    connect();
    return () => { stopped = true; clearTimeout(retry); clearTimeout(healthy); socket?.close(); };
  }, [identity]);

  const value = useMemo<Workspace>(() => ({
    identity, booting, bootError, boot, busy, actionError, setActionError, action, revision, refresh, inboxPulse, connection,
    unread, setUnread, login, openLogin, closeLogin, loginCarbon, loginSilicon, signOut, theme, setTheme,
  }), [identity, booting, bootError, boot, busy, actionError, action, revision, refresh, inboxPulse, connection, unread, login, openLogin, closeLogin, loginCarbon, loginSilicon, signOut, theme, setTheme]);

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}
