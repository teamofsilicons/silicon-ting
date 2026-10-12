export type Page = 'inbox' | 'apps' | 'preferences' | 'connections' | 'docs' | 'settings';

export const routes: Record<Page, { href: string; name: string }> = {
  inbox: { href: '/', name: 'Inbox' },
  apps: { href: '/apps', name: 'Applications' },
  preferences: { href: '/preferences', name: 'Preferences' },
  connections: { href: '/connections', name: 'Connections' },
  docs: { href: '/docs', name: 'Documentation' },
  settings: { href: '/settings', name: 'Settings' },
};

export const workspacePages: Page[] = ['inbox', 'apps', 'preferences', 'connections'];

export function pageFor(pathname: string): Page {
  const path = pathname.replace(/\/+$/, '') || '/';
  return (Object.keys(routes) as Page[]).find(page => routes[page].href === path) ?? 'inbox';
}

// Links from the single-page app used #inbox, #docs and so on.
export function legacyHashRoute(hash: string): string | undefined {
  const page = hash.replace(/^#/, '') as Page;
  return page in routes ? routes[page].href : undefined;
}
