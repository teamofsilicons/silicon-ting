'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { ArrowRight, BookOpen, Inbox, LayoutGrid, Link2, Menu, Settings, SlidersHorizontal, UserRound } from 'lucide-react';
import { Badge } from '@/components/silicon-ui/badge/badge';
import { Breadcrumb } from '@/components/silicon-ui/breadcrumb/breadcrumb';
import { Button } from '@/components/silicon-ui/button/button';
import { Dialog, DialogClose, DialogContent } from '@/components/silicon-ui/dialog/dialog';
import { Drawer, DrawerContent } from '@/components/silicon-ui/drawer/drawer';
import { PasswordField } from '@/components/silicon-ui/password-field/password-field';
import { UserMenu } from '@/components/silicon-ui/user-menu/user-menu';
import { pageFor, routes, type Page } from '@/lib/routes';
import { ErrorAlert } from './ui';
import { useWorkspace } from './workspace';
import styles from './shell.module.css';

const icons: Record<Page, typeof Inbox> = { inbox: Inbox, apps: LayoutGrid, preferences: SlidersHorizontal, connections: Link2, docs: BookOpen, settings: Settings };
const kindLabel = (kind: 'carbon' | 'silicon') => kind === 'silicon' ? 'Silicon account' : 'Carbon account';

export function Logo() {
  return <Link href="/" className={styles.brand} aria-label="Ting home"><span className={styles.brandMark} aria-hidden="true">t<span>•</span></span><span>ting<span className={styles.brandDot}>.</span></span></Link>;
}

export function LoginButtons() {
  const { busy, loginCarbon, openLogin } = useWorkspace();
  return <div className={styles.loginButtons}>
    <Button disabled={busy} onClick={() => void loginCarbon()}>Continue as Carbon<ArrowRight size={17} aria-hidden="true" /></Button>
    <Button variant="secondary" disabled={busy} onClick={() => openLogin(true)}>Continue as Silicon<ArrowRight size={17} aria-hidden="true" /></Button>
  </div>;
}

function NavLink({ page, active }: { page: Page; active: boolean }) {
  const { unread } = useWorkspace();
  const Icon = icons[page];
  return <Link href={routes[page].href} className={styles.navLink} aria-current={active ? 'page' : undefined}>
    <Icon size={18} strokeWidth={1.6} aria-hidden="true" />
    <span>{routes[page].name}</span>
    {page === 'inbox' && unread ? <Badge size="sm" tone="info" aria-label={`${unread} unread`}>{unread}</Badge> : null}
  </Link>;
}

function Navigation() {
  const page = pageFor(usePathname());
  const { identity, openLogin } = useWorkspace();
  return <>
    <Logo />
    <div className={styles.account}>
      <span className={styles.accountIcon}><UserRound size={16} aria-hidden="true" /></span>
      {identity
        ? <span className={styles.accountText}><strong>{identity.id}</strong><small>{kindLabel(identity.kind)}</small></span>
        : <button type="button" className={styles.accountSignIn} onClick={() => openLogin()}><span className={styles.accountText}><strong>Your account</strong><small>Carbon or Silicon</small></span><ArrowRight size={14} aria-hidden="true" /></button>}
    </div>
    <span className={styles.navLabel}>Workspace</span>
    <nav className={styles.nav} aria-label="Workspace navigation">
      {(['inbox', 'apps', 'preferences', 'connections'] as const).map(item => <NavLink key={item} page={item} active={page === item} />)}
    </nav>
    <div className={styles.sidebarBottom}>
      <p className={styles.note}><span aria-hidden="true">↳</span>For every little thing that connects us.</p>
      <nav className={styles.nav} aria-label="Resources">
        <NavLink page="docs" active={page === 'docs'} />
        <NavLink page="settings" active={page === 'settings'} />
      </nav>
    </div>
  </>;
}

function LiveStatus() {
  const { identity, connection } = useWorkspace();
  const label = !identity ? 'Your signals, in sync' : connection === 'live' ? 'Listening live' : connection === 'reconnecting' ? 'Reconnecting' : connection === 'paused' ? 'Watch paused' : 'Connecting';
  return <Badge className={styles.liveStatus} tone={identity && connection === 'live' ? 'success' : identity && connection === 'paused' ? 'warning' : 'neutral'} icon={<span className={styles.liveDot} />}>{label}</Badge>;
}

function LoginDialog() {
  const { login, closeLogin, busy, actionError, loginSilicon } = useWorkspace();
  const [token, setToken] = useState('');
  useEffect(() => { if (!login.open) setToken(''); }, [login.open]);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (await loginSilicon(token)) setToken('');
  }
  return <Dialog open={login.open} onOpenChange={open => { if (!open) closeLogin(); }}>
    <DialogContent title="Sign in to Ting" description={login.silicon ? 'Use a login token from the Silicon Accounts CLI.' : 'Continue with your Carbon account in Silicon Accounts, or use a Silicon account token.'}>
      <div className={styles.dialogStack}>
        {login.silicon
          ? <form className={styles.dialogStack} onSubmit={submit}>
            <p className={styles.dialogText}>Run <code>silicon-accounts login --app ting -q</code> for your Silicon account, then paste the login token. Your session is saved securely.</p>
            <PasswordField label="Silicon login token" autoComplete="off" spellCheck={false} required value={token} onChange={event => setToken(event.currentTarget.value)} placeholder="Paste your login token" />
            <Button type="submit" loading={busy}>Sign in as Silicon<ArrowRight size={17} aria-hidden="true" /></Button>
          </form>
          : <LoginButtons />}
        {actionError ? <ErrorAlert error={actionError} /> : null}
        <DialogClose asChild><Button variant="ghost" disabled={busy}>Cancel</Button></DialogClose>
      </div>
    </DialogContent>
  </Dialog>;
}

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const page = pageFor(pathname);
  const { identity, bootError, boot, actionError, setActionError, openLogin, signOut, theme, setTheme, login } = useWorkspace();
  const [menu, setMenu] = useState(false);
  useEffect(() => { setMenu(false); }, [pathname]);

  return <div className={styles.shell}>
    <aside className={styles.sidebar}><Navigation /></aside>
    <Drawer open={menu} onOpenChange={setMenu}>
      <DrawerContent side="left" title="Ting" className={styles.mobileNav}><div className={styles.mobileNavInner}><Navigation /></div></DrawerContent>
    </Drawer>
    <div className={styles.main}>
      <header className={styles.topbar}>
        <div className={styles.topbarLeft}>
          <span className={styles.menuButton}><Button variant="secondary" size="sm" aria-label="Open navigation" onClick={() => setMenu(true)}><Menu size={18} aria-hidden="true" /></Button></span>
          <Breadcrumb items={[{ label: 'Workspace', href: '/' }, { label: routes[page].name }]} />
        </div>
        <div className={styles.topbarRight}>
          <LiveStatus />
          {identity
            ? <UserMenu
              user={{ name: identity.id, email: kindLabel(identity.kind) }}
              theme={theme}
              onThemeChange={setTheme}
              items={[
                { label: 'Settings', icon: <Settings size={16} />, onSelect: () => router.push(routes.settings.href) },
                { label: 'Documentation', icon: <BookOpen size={16} />, onSelect: () => router.push(routes.docs.href) },
              ]}
              onSignOut={signOut}
            />
            : <Button size="sm" variant="secondary" onClick={() => openLogin()}>Sign in<ArrowRight size={14} aria-hidden="true" /></Button>}
        </div>
      </header>
      <main id="main-content" className={styles.content}>
        {actionError && !login.open ? <ErrorAlert error={actionError} onDismiss={() => setActionError(undefined)} /> : null}
        {bootError ? <ErrorAlert error={bootError} retry={() => void boot()} /> : null}
        {children}
      </main>
      <footer className={styles.footer}>
        <span className={styles.footerBrand}>ting<span className={styles.brandDot}>.</span><small>A little signal goes a long way.</small></span>
        <span className={styles.footerNote}>Part of the Silicon ecosystem <span aria-hidden="true">✳</span></span>
      </footer>
    </div>
    <LoginDialog />
  </div>;
}
