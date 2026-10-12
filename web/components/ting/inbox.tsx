'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowRight, BellOff, ChevronRight, ExternalLink, Inbox as InboxIcon, RefreshCw, ShieldCheck } from 'lucide-react';
import { Avatar } from '@/components/silicon-ui/avatar/avatar';
import { Badge } from '@/components/silicon-ui/badge/badge';
import { Button } from '@/components/silicon-ui/button/button';
import { CopyButton } from '@/components/silicon-ui/copy-button/copy-button';
import { Drawer, DrawerContent } from '@/components/silicon-ui/drawer/drawer';
import { EmptyState } from '@/components/silicon-ui/empty-state/empty-state';
import { JsonViewer } from '@/components/silicon-ui/json-viewer/json-viewer';
import { SearchField } from '@/components/silicon-ui/search-field/search-field';
import SegmentedControl from '@/components/silicon-ui/segmented-control/segmented-control';
import { Select } from '@/components/silicon-ui/select/select';
import { api, type Identity, type Subscription, type Ting } from '@/lib/api';
import { routes } from '@/lib/routes';
import { useList } from '@/lib/use-list';
import { apiPath, enc, query, safeLink, timeLabel } from '@/lib/utils';
import { ButtonLink, ErrorAlert, Footnote, ListStatus, Loading, More, PageHeading, TextLink } from './ui';
import { RequireAccount } from './welcome';
import { useWorkspace } from './workspace';
import styles from './inbox.module.css';

type Scope = 'active' | 'silent' | 'all';

export function InboxPage() {
  return <RequireAccount page="inbox"><Inbox /></RequireAccount>;
}

function Inbox() {
  const { identity, revision, inboxPulse, setUnread } = useWorkspace();
  const [scope, setScope] = useState<Scope>('active');
  const [readFilter, setReadFilter] = useState('any');
  const [appFilter, setAppFilter] = useState('all');
  const [typeQuery, setTypeQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  useEffect(() => { const timer = setTimeout(() => setTypeFilter(typeQuery.trim()), 350); return () => clearTimeout(timer); }, [typeQuery]);

  const inbox = useList<Ting>(apiPath('inbox' + query({
    limit: 50,
    silent: scope === 'all' ? undefined : scope === 'silent',
    read: readFilter === 'any' ? undefined : readFilter,
    app_id: appFilter === 'all' ? undefined : appFilter,
    type: typeFilter,
  })), revision, identity);
  const subscriptions = useList<Subscription>(apiPath('subscriptions?limit=100'), revision, identity);
  const appOptions = useMemo(() => {
    const ids = new Set(subscriptions.items.map(item => item.app_id));
    if (appFilter !== 'all') ids.add(appFilter);
    return [{ value: 'all', label: 'All applications' }, ...[...ids].sort().map(id => ({ value: id, label: id }))];
  }, [subscriptions.items, appFilter]);

  useEffect(() => { setUnread(inbox.items.filter(item => !item.read).length); }, [inbox.items, setUnread]);
  useEffect(() => () => setUnread(0), [setUnread]);

  const detail = useTingDetail(identity, inbox.reload);
  const { refresh: refreshDetail, close: closeDetail } = detail;
  const reloadInbox = inbox.reload;

  // The live watch reports changes; a returning tab catches up and acknowledges the open ting.
  const lastPulse = useRef(inboxPulse);
  useEffect(() => {
    if (lastPulse.current === inboxPulse) return;
    lastPulse.current = inboxPulse;
    void reloadInbox(); void refreshDetail();
  }, [inboxPulse, reloadInbox, refreshDetail]);
  useEffect(() => {
    const visibility = () => { if (document.visibilityState === 'visible') { void reloadInbox(); void refreshDetail(true); } };
    document.addEventListener('visibilitychange', visibility);
    return () => document.removeEventListener('visibilitychange', visibility);
  }, [reloadInbox, refreshDetail]);
  useEffect(() => () => closeDetail(), [identity, closeDetail]);

  const filtered = appFilter !== 'all' || typeFilter || readFilter !== 'any';
  return <>
    <PageHeading eyebrow="Your signal desk" title="Inbox" text="Every update, right where it belongs." action={<Button variant="secondary" loading={inbox.loading} onClick={() => void inbox.reload()}><RefreshCw size={16} aria-hidden="true" />Refresh</Button>} />
    <section className={styles.card}>
      <div className={styles.toolbar}>
        <SegmentedControl label="Inbox kind" value={scope} onValueChange={value => setScope(value as Scope)} options={[{ value: 'active', label: 'Inbox' }, { value: 'silent', label: 'Silent' }, { value: 'all', label: 'All tings' }]} />
        <Badge size="sm">{`${inbox.items.length} loaded`}</Badge>
      </div>
      <div className={styles.filters}>
        <Select label="Application" value={appFilter} onValueChange={value => { setAppFilter(value); setTypeQuery(''); setTypeFilter(''); }} options={appOptions} />
        <Select label="Status" value={readFilter} onValueChange={setReadFilter} options={[{ value: 'any', label: 'Any status' }, { value: 'false', label: 'Unread' }, { value: 'true', label: 'Read' }]} />
        <SearchField label="Exact type" placeholder="app.service.event" value={typeQuery} onValueChange={setTypeQuery} />
      </div>
      <div className={styles.list}>
        <ListStatus list={inbox} empty={<EmptyState
          icon={scope === 'silent' ? <BellOff size={24} strokeWidth={1.5} /> : <InboxIcon size={24} strokeWidth={1.5} />}
          title={scope === 'silent' ? 'A little peace and quiet.' : 'You’re all caught up.'}
          description={scope === 'silent' ? 'Silent tings stay here for one calendar month from creation, without interrupting you.' : filtered ? 'No tings match these filters. Try another application or status.' : 'Your apps will send updates here once you connect them. In the meantime, enjoy the quiet.'}
          action={<TextLink href={routes.docs.href}>Connect your first app<ArrowRight size={15} aria-hidden="true" /></TextLink>}
        />} />
        {inbox.items.map(ting => <button key={ting.id} type="button" className={styles.row} data-unread={ting.read ? undefined : ''} onClick={() => detail.show(ting)}>
          <Avatar name={ting.type.split('.')[0]} size="sm" />
          <span className={styles.summary}>
            <span className={styles.type}><span>{ting.type}</span>{ting.read ? null : <i className={styles.unreadDot} aria-label="Unread" />}</span>
            <span className={styles.meta}>{ting.silent ? 'Silent ting' : 'Notification'}<span aria-hidden="true">·</span>{ting.read ? 'Read' : 'Unread'}</span>
          </span>
          <time dateTime={ting.created_at} title={new Date(ting.created_at).toLocaleString()}>{timeLabel(ting.created_at)}</time>
          <ChevronRight size={17} aria-hidden="true" />
        </button>)}
        <More list={inbox} />
      </div>
    </section>
    <Footnote icon={<ShieldCheck size={14} aria-hidden="true" />}>Read or silent: one calendar month. Unread and non-silent: three. Age starts at creation; opening a ting marks it as read.</Footnote>
    <TingDrawer detail={detail} />
  </>;
}

type TingDetail = ReturnType<typeof useTingDetail>;

// Opening a ting loads it in full and, once it has been shown, marks it read for its recipient.
// Every response is checked against the ting, account and drawer that requested it.
function useTingDetail(identity: Identity | undefined, reloadInbox: () => Promise<void>) {
  const [state, setState] = useState<{ open: boolean; ting?: Ting; loading: boolean; error?: unknown }>({ open: false, loading: false });
  const live = useRef({ id: '', open: false, ting: undefined as Ting | undefined, identity });
  live.current.identity = identity;
  const generation = useRef(0);
  const pendingView = useRef<{ actor: Identity; id: string }>(undefined);
  const acknowledging = useRef(new Set<string>());
  const reload = useRef(reloadInbox);
  reload.current = reloadInbox;

  // These read only refs, so they stay stable across renders.
  const actions = useMemo(() => {
    async function markViewed() {
      const ting = live.current.ting, actor = live.current.identity;
      if (!ting || !actor || ting.for !== actor.uuid || ting.read || document.visibilityState !== 'visible' || !live.current.open) return;
      const key = JSON.stringify([actor.uuid, ting.id]);
      if (acknowledging.current.has(key)) return;
      acknowledging.current.add(key);
      const current = () => live.current.identity === actor && live.current.id === ting.id;
      try {
        await api(apiPath('inbox/read'), 'POST', { message_ids: [ting.id] });
        if (current()) { void refresh(); void reload.current(); }
      } catch (error) { if (current()) setState(previous => ({ ...previous, error })); }
      finally { acknowledging.current.delete(key); }
    }
    async function refresh(viewed = false) {
      const { id, open } = live.current, actor = live.current.identity;
      if (!id || !actor || !open || document.visibilityState !== 'visible') return;
      if (viewed) pendingView.current = { actor, id };
      const active = ++generation.current;
      const current = () => active === generation.current && live.current.id === id && live.current.identity === actor && live.current.open;
      try {
        const full = await api<Ting>(apiPath(`inbox/${enc(id)}`));
        if (!current()) return;
        live.current.ting = full;
        setState(previous => ({ ...previous, ting: full, error: undefined, loading: false }));
        if (pendingView.current?.actor === actor && pendingView.current.id === id) {
          pendingView.current = undefined;
          requestAnimationFrame(() => requestAnimationFrame(() => { if (live.current.id === id && live.current.identity === actor) void markViewed(); }));
        }
      } catch (error) { if (current()) { live.current.ting = undefined; setState(previous => ({ ...previous, ting: undefined, error, loading: false })); } }
    }
    function show(ting: Ting) {
      live.current = { ...live.current, id: ting.id, open: true, ting: undefined };
      setState({ open: true, loading: true });
      void refresh(true);
    }
    // The last ting stays rendered while the drawer slides out.
    function close() {
      live.current = { ...live.current, id: '', open: false };
      setState(previous => ({ ...previous, open: false }));
    }
    return { show, close, refresh, markViewed };
  }, []);

  return { ...state, ...actions };
}

function TingDrawer({ detail }: { detail: TingDetail }) {
  const ting = detail.ting;
  const message = ting && (typeof ting.data?.text === 'string' ? ting.data.text : typeof ting.data?.message === 'string' ? ting.data.message : undefined);
  const link = ting && safeLink(ting.data?.url);
  return <Drawer open={detail.open} onOpenChange={open => { if (!open) detail.close(); }}>
    <DrawerContent title={ting?.type ?? 'A little ting'} description={ting ? new Date(ting.created_at).toLocaleString() : 'Opening this ting…'} className={styles.drawer}>
      <div className={styles.detail}>
        {detail.loading ? <Loading>Opening this ting…</Loading> : null}
        {detail.error ? <ErrorAlert error={detail.error} retry={() => void (ting ? detail.markViewed() : detail.refresh(true))} /> : null}
        {ting ? <>
          <div className={styles.tags}>
            <Badge tone={ting.silent ? 'neutral' : 'success'}>{ting.silent ? 'Silent' : 'Notification'}</Badge>
            <Badge tone={ting.read ? 'neutral' : 'info'}>{ting.read ? 'Read' : 'Unread'}</Badge>
          </div>
          {message ? <div className={styles.message}>{message}</div> : null}
          {link ? <ButtonLink href={link} target="_blank" rel="noreferrer" className={styles.openLink}>Open link<ExternalLink size={16} aria-hidden="true" /></ButtonLink> : null}
          <h3>Data</h3>
          <JsonViewer data={ting.data ?? {}} rootName="data" label="Ting data" searchable={false} showPath={false} maxHeight={280} />
          <h3>Metadata</h3>
          <JsonViewer data={ting.metadata ?? {}} rootName="metadata" label="Ting metadata" searchable={false} showPath={false} maxHeight={200} />
          <dl className={styles.info}>
            <dt>Ting ID</dt><dd><span className="mono">{ting.id}</span><CopyButton value={ting.id} label="Copy ting ID" iconOnly variant="plain" /></dd>
            <dt>Recipient</dt><dd><span className="mono">{ting.for}</span></dd>
            <dt>Idempotency key</dt><dd><span className="mono">{ting.key}</span></dd>
          </dl>
          <p className={styles.note}>Viewing this ting marks it read. Each webhook’s delivery progress remains independent.</p>
        </> : null}
      </div>
    </DrawerContent>
  </Drawer>;
}
