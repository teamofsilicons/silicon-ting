'use client';

import { useState, type FormEvent } from 'react';
import { Bell, BellOff, Check, SlidersHorizontal } from 'lucide-react';
import { Badge } from '@/components/silicon-ui/badge/badge';
import { Button } from '@/components/silicon-ui/button/button';
import { EmptyState } from '@/components/silicon-ui/empty-state/empty-state';
import { Input } from '@/components/silicon-ui/input/input';
import { Select } from '@/components/silicon-ui/select/select';
import { api, type Preference, type Subscription } from '@/lib/api';
import { useList } from '@/lib/use-list';
import { apiPath, query, typeError } from '@/lib/utils';
import { ErrorAlert, Footnote, ListStatus, More, PageHeading, Panel } from './ui';
import { RequireAccount } from './welcome';
import { useWorkspace } from './workspace';
import styles from './pages.module.css';

type Level = 'app' | 'service' | 'type';

export function PreferencesPage() {
  return <RequireAccount page="preferences"><Preferences /></RequireAccount>;
}

function Preferences() {
  const { identity, revision, busy, action } = useWorkspace();
  const preferences = useList<Preference>(apiPath('preferences?limit=100'), revision, identity);
  const subscriptions = useList<Subscription>(apiPath('subscriptions?limit=100'), revision, identity);
  const [app, setApp] = useState('');
  const [level, setLevel] = useState<Level>('app');
  const [target, setTarget] = useState('');
  const [enabled, setEnabled] = useState('false');
  const [formError, setFormError] = useState('');

  async function save(event: FormEvent) {
    event.preventDefault(); setFormError('');
    const appId = app.trim(), value = target.trim();
    if (!appId) { setFormError('Choose an application or enter its ID.'); return; }
    if (level === 'service' && !/^[a-z][a-z0-9_-]*$/.test(value)) { setFormError('Use a lowercase service name, starting with a letter.'); return; }
    if (level === 'type') { const error = typeError(appId, value, 'validate'); if (error) { setFormError(error); return; } }
    await action(() => api(apiPath('preferences'), 'PUT', { app_id: appId, service: level === 'service' ? value : null, type: level === 'type' ? value : null, enabled: enabled === 'true' }), 'Preference saved.');
  }

  return <>
    <PageHeading eyebrow="A little more signal. A little less noise." title="Preferences" text="Your attention belongs to you." />
    <div className={styles.preferencesLayout}>
      <Panel title="Your overrides" aside={<Badge size="sm">{`${preferences.items.length} loaded`}</Badge>}>
        <ListStatus list={preferences} empty={<EmptyState icon={<SlidersHorizontal size={24} strokeWidth={1.5} />} title="An open channel." description="All notifications are enabled by default. Add an override to make your inbox work for you." />} />
        {preferences.items.map(preference => <div key={`${preference.app_id}:${preference.service}:${preference.type}`} className={styles.row}>
          <span className={styles.statusIcon} data-on={preference.enabled ? '' : undefined}>{preference.enabled ? <Bell size={18} aria-hidden="true" /> : <BellOff size={18} aria-hidden="true" />}</span>
          <div className={styles.rowText}><strong>{preference.type || preference.service || preference.app_id}</strong><p>{preference.type ? 'Event' : preference.service ? 'Service' : 'Application'} · {preference.app_id}</p></div>
          <Badge size="sm" tone={preference.enabled ? 'success' : 'neutral'}>{preference.enabled ? 'Enabled' : 'Silent'}</Badge>
          <Button variant="secondary" size="sm" disabled={busy} onClick={() => void action(() => api(apiPath('preferences') + query({ app_id: preference.app_id, service: preference.service, type: preference.type }), 'DELETE'), 'Override reset to its inherited setting.')}>Reset</Button>
        </div>)}
        <More list={preferences} />
      </Panel>
      <Panel title="Add an override" aside={<SlidersHorizontal size={18} aria-hidden="true" />}>
        <form className={styles.formStack} onSubmit={save}>
          <Input label="Application" required list="preference-apps" placeholder="your-app" autoComplete="off" value={app} onChange={event => setApp(event.currentTarget.value)} />
          <datalist id="preference-apps">{[...new Set(subscriptions.items.map(item => item.app_id))].map(id => <option key={id} value={id} />)}</datalist>
          <Select label="Apply to" value={level} onValueChange={value => { setLevel(value as Level); setTarget(''); }} options={[{ value: 'app', label: 'Entire application' }, { value: 'service', label: 'One service' }, { value: 'type', label: 'One event type' }]} />
          {level !== 'app' ? <Input label={level === 'service' ? 'Service name' : 'Full event type'} required placeholder={level === 'service' ? 'messages' : `${app || 'app'}.messages.received`} value={target} onChange={event => setTarget(event.currentTarget.value)} /> : null}
          <Select label="Delivery" value={enabled} onValueChange={setEnabled} options={[{ value: 'false', label: 'Keep silent' }, { value: 'true', label: 'Enable notifications' }]} />
          {formError ? <ErrorAlert error={new Error(formError)} /> : null}
          <Button type="submit" loading={busy}>Save preference<Check size={16} aria-hidden="true" /></Button>
          <p className={styles.formNote}>Event settings take priority over service settings, then application settings. Reset restores the inherited setting.</p>
        </form>
      </Panel>
    </div>
    <Footnote icon={<BellOff size={14} aria-hidden="true" />}>Silent tings stay in your drawer for one calendar month from creation. Muting never revokes an app’s permission to send.</Footnote>
  </>;
}
