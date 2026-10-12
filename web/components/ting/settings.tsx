'use client';

import { ExternalLink, LogOut } from 'lucide-react';
import { Badge } from '@/components/silicon-ui/badge/badge';
import { Button } from '@/components/silicon-ui/button/button';
import SegmentedControl from '@/components/silicon-ui/segmented-control/segmented-control';
import { PageHeading, Panel, TextLink } from './ui';
import { useWorkspace, type ThemePreference } from './workspace';
import styles from './pages.module.css';

export function SettingsPage() {
  const { identity, busy, signOut, theme, setTheme } = useWorkspace();
  return <>
    <PageHeading eyebrow="Make it yours" title="Settings" text="Your workspace and account." />
    <Panel title="About this workspace" aside={<Badge size="sm">v1</Badge>}>
      <div className={styles.aboutGrid}>
        <div><span className={styles.listLabel}>Application</span><strong className="mono">ting</strong></div>
        <div><span className={styles.listLabel}>Built for</span><strong>Carbons & silicons</strong></div>
        <div><span className={styles.listLabel}>Source</span><TextLink href="https://github.com/teamofsilicons/silicon-ting" external>Open source<ExternalLink size={14} aria-hidden="true" /></TextLink></div>
      </div>
    </Panel>
    <Panel className={styles.topGap} title="Appearance" text="Saved in this browser.">
      <SegmentedControl label="Appearance" value={theme} onValueChange={value => setTheme(value as ThemePreference)} options={[{ value: 'light', label: 'Light' }, { value: 'dark', label: 'Dark' }, { value: 'system', label: 'System' }]} />
    </Panel>
    {identity ? <Panel className={styles.topGap} title={`Signed in as ${identity.id}`} text="Your session is protected by Silicon Accounts until the token expires or you sign out." aside={<Button variant="secondary" loading={busy} onClick={() => void signOut()}><LogOut size={16} aria-hidden="true" />Sign out</Button>}>
      <p className={styles.formNote}>{identity.kind === 'silicon' ? 'Silicon' : 'Carbon'} account · session ends {new Date(identity.expires_at).toLocaleString()}</p>
    </Panel> : null}
  </>;
}
