'use client';

import { useState } from 'react';
import { Link2, RefreshCw, ShieldCheck, Terminal } from 'lucide-react';
import { Avatar } from '@/components/silicon-ui/avatar/avatar';
import { Badge } from '@/components/silicon-ui/badge/badge';
import { Button } from '@/components/silicon-ui/button/button';
import { CodeBlock } from '@/components/silicon-ui/code-block/code-block';
import { Dialog, DialogClose, DialogContent } from '@/components/silicon-ui/dialog/dialog';
import { EmptyState } from '@/components/silicon-ui/empty-state/empty-state';
import { Switch } from '@/components/silicon-ui/switch/switch';
import { api, type Hook, type Subscription } from '@/lib/api';
import { useList } from '@/lib/use-list';
import { apiPath, enc } from '@/lib/utils';
import { Footnote, ListStatus, More, PageHeading, Panel } from './ui';
import { RequireAccount } from './welcome';
import { useWorkspace } from './workspace';
import styles from './pages.module.css';

export function ConnectionsPage() {
  return <RequireAccount page="connections"><Connections /></RequireAccount>;
}

const hookTone = { connected: 'success', paused: 'warning', disconnected: 'neutral', detached: 'neutral' } as const;

function Connections() {
  const { identity, revision, refresh, busy, action } = useWorkspace();
  const subscriptions = useList<Subscription>(apiPath('subscriptions?limit=100'), revision, identity);
  const hooks = useList<Hook>(apiPath('webhooks?limit=100'), revision, identity);
  const [revoke, setRevoke] = useState<{ open: boolean; subscription?: Subscription }>({ open: false });

  async function confirmRevoke() {
    const subscription = revoke.subscription;
    if (subscription && await action(() => api(apiPath(`subscriptions/${enc(subscription.id)}`), 'DELETE'), 'Application access revoked.')) setRevoke(previous => ({ ...previous, open: false }));
  }

  return <>
    <PageHeading eyebrow="Your network of little signals" title="Connections" text="The apps that can reach you. The destinations that listen." action={<Button variant="secondary" loading={subscriptions.loading || hooks.loading} onClick={refresh}><RefreshCw size={16} aria-hidden="true" />Refresh</Button>} />
    <Panel title="Connected applications" text="Permission to send is granted when you connect an app through Silicon Accounts." aside={<ShieldCheck size={20} aria-hidden="true" />}>
      <ListStatus list={subscriptions} empty={<EmptyState icon={<Link2 size={24} strokeWidth={1.5} />} title="Make your first connection." description="When an app requests permission to notify you and you approve it, it will appear here." />} />
      {subscriptions.items.map(subscription => <div key={subscription.id} className={styles.connection}>
        <div className={styles.row}>
          <Avatar name={subscription.app_id} size="sm" />
          <div className={styles.rowText}><strong>{subscription.app_id}</strong><p className="mono">{subscription.id}</p></div>
          <Badge size="sm" tone={subscription.active ? 'success' : 'neutral'}>{subscription.active ? 'Connected' : 'Revoked'}</Badge>
          {subscription.active ? <Button variant="danger" size="sm" onClick={() => setRevoke({ open: true, subscription })}>Revoke access</Button> : null}
        </div>
        {subscription.active ? <div className={styles.requiredDelivery}>
          <Switch
            label="Allow required automation delivery, even when notifications are muted"
            checked={subscription.required_delivery === true}
            disabled={busy}
            onCheckedChange={enabled => void action(() => api(apiPath(`subscriptions/${enc(subscription.id)}/required-delivery`), 'PUT', { enabled }), enabled ? 'Required automation delivery enabled.' : 'Required automation delivery disabled.')}
          />
        </div> : null}
      </div>)}
      <More list={subscriptions} />
    </Panel>
    <Panel className={styles.topGap} title="Webhook destinations" text="Local destinations are managed by the Ting CLI." aside={<Badge size="sm">Read only</Badge>}>
      <ListStatus list={hooks} empty={<EmptyState icon={<Terminal size={24} strokeWidth={1.5} />} title="Give your silicon a listening ear." description="Connect a local webhook with the CLI. Your daemon takes care of delivery and recovery." action={<div className={styles.emptyCode}><CodeBlock language="bash" code="ting webhook http://localhost:3000/ting" /></div>} />} />
      {hooks.items.map(hook => <div key={hook.id} className={styles.row}>
        <span className={styles.statusIcon}><Terminal size={18} aria-hidden="true" /></span>
        <div className={styles.rowText}><strong className="mono">{hook.id}</strong><p>{hook.pending} pending {hook.pending === 1 ? 'delivery' : 'deliveries'}</p></div>
        <Badge size="sm" tone={hookTone[hook.state]}>{hook.state}</Badge>
      </div>)}
      <More list={hooks} />
    </Panel>
    <Footnote icon={<ShieldCheck size={14} aria-hidden="true" />}>Webhook URLs and secrets stay on your local machine.</Footnote>
    <Dialog open={revoke.open} onOpenChange={open => setRevoke(previous => ({ ...previous, open }))}>
      <DialogContent title="Revoke application access?" description={revoke.subscription?.app_id}>
        <div className={styles.formStack}>
          <p className={styles.dialogText}><strong>{revoke.subscription?.app_id}</strong> will no longer be able to send you tings. Pending delivery pauses; your history remains within its retention window: one month for read or silent tings, three for unread non-silent tings.</p>
          <p className={styles.dialogText}>To reconnect, approve a new Silicon Accounts consent request from the application.</p>
          <div className={styles.dialogActions}>
            <DialogClose asChild><Button variant="secondary">Keep connected</Button></DialogClose>
            <Button variant="danger" loading={busy} onClick={() => void confirmRevoke()}>Revoke access</Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  </>;
}
