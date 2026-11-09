'use client';

import { useEffect, useState, type FormEvent } from 'react';
import { Bell, BellOff, Check, Clock, SlidersHorizontal } from 'lucide-react';
import { Badge } from '@/components/silicon-ui/badge/badge';
import { Button } from '@/components/silicon-ui/button/button';
import { EmptyState } from '@/components/silicon-ui/empty-state/empty-state';
import { Input } from '@/components/silicon-ui/input/input';
import { Select } from '@/components/silicon-ui/select/select';
import { Switch } from '@/components/silicon-ui/switch/switch';
import { api, type DeliveryMode, type Preference, type SilentSchedule, type Subscription } from '@/lib/api';
import { useList } from '@/lib/use-list';
import { apiPath, query, typeError } from '@/lib/utils';
import { ErrorAlert, Footnote, ListStatus, More, PageHeading, Panel } from './ui';
import { RequireAccount } from './welcome';
import { useWorkspace } from './workspace';
import styles from './pages.module.css';

type Level = 'app' | 'type' | 'sender';

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
  const [mode, setMode] = useState<DeliveryMode>('silent');
  const [formError, setFormError] = useState('');
  const [schedule, setSchedule] = useState<SilentSchedule>();
  const [scheduleError, setScheduleError] = useState<unknown>();

  useEffect(() => {
    let active = true;
    setSchedule(undefined); setScheduleError(undefined);
    api<SilentSchedule>(apiPath('silent-schedule')).then(value => { if (active) setSchedule(value); }, error => { if (active) setScheduleError(error); });
    return () => { active = false; };
  }, [identity, revision]);

  async function save(event: FormEvent) {
    event.preventDefault(); setFormError('');
    const appId = app.trim(), value = target.trim();
    if (level !== 'sender' && !appId) { setFormError('Choose an application or enter its ID.'); return; }
    if (level === 'sender' && !value) { setFormError('Enter the sender’s account UUID or complete handle.'); return; }
    if (level === 'type') { const error = typeError(appId, value, 'validate'); if (error) { setFormError(error); return; } }
    const scope = level === 'sender' ? { from: value } : { app_id: appId, ...(level === 'type' ? { type: value } : {}) };
    await action(() => api(apiPath('preferences'), 'PUT', { ...scope, mode }), 'Preference saved.');
  }

  return <>
    <PageHeading eyebrow="A little more signal. A little less noise." title="Preferences" text="Choose what reaches you and when." />
    <div className={styles.preferencesLayout}>
      <Panel title="Your preferences" aside={<Badge size="sm">{`${preferences.items.length} loaded`}</Badge>}>
        <ListStatus list={preferences} empty={<EmptyState icon={<SlidersHorizontal size={24} strokeWidth={1.5} />} title="An open channel." description="Notifications are allowed by default. Set rules for applications, notification types, or people." />} />
        {preferences.items.map(preference => <div key={`${preference.from}:${preference.app_id}:${preference.type}`} className={styles.row}>
          <span className={styles.statusIcon} data-on={preference.mode === 'allowed' ? '' : undefined}>{preference.mode === 'allowed' ? <Bell size={18} aria-hidden="true" /> : <BellOff size={18} aria-hidden="true" />}</span>
          <div className={styles.rowText}><strong>{preference.from || preference.type || preference.app_id}</strong><p>{preference.from ? 'Sender across applications' : preference.type ? 'Notification type' : 'Application'}</p></div>
          <Badge size="sm" tone={preference.mode === 'allowed' ? 'success' : 'neutral'}>{preference.mode}</Badge>
          <Button variant="secondary" size="sm" disabled={busy} onClick={() => void action(() => api(apiPath('preferences') + query({ app_id: preference.app_id, from: preference.from, type: preference.type }), 'DELETE'), 'Preference reset.')}>Reset</Button>
        </div>)}
        <More list={preferences} />
      </Panel>
      <Panel title="Add a preference" aside={<SlidersHorizontal size={18} aria-hidden="true" />}>
        <form className={styles.formStack} onSubmit={save}>
          <Select label="Apply to" value={level} onValueChange={value => { setLevel(value as Level); setTarget(''); }} options={[{ value: 'app', label: 'Entire application' }, { value: 'type', label: 'One notification type' }, { value: 'sender', label: 'One sender' }]} />
          {level !== 'sender' ? <>
            <Input label="Application" required list="preference-apps" placeholder="your-app" autoComplete="off" value={app} onChange={event => setApp(event.currentTarget.value)} />
            <datalist id="preference-apps">{[...new Set(subscriptions.items.map(item => item.app_id))].map(id => <option key={id} value={id} />)}</datalist>
          </> : null}
          {level !== 'app' ? <Input label={level === 'sender' ? 'Sender' : 'Full notification type'} required placeholder={level === 'sender' ? 'c:alice, si:assistant, or account UUID' : `${app || 'app'}.messageReceived`} value={target} onChange={event => setTarget(event.currentTarget.value)} /> : null}
          <Select label="Delivery" value={mode} onValueChange={value => setMode(value as DeliveryMode)} options={[{ value: 'allowed', label: 'Allowed — deliver immediately' }, { value: 'silent', label: 'Silent — include in the daily digest' }, { value: 'blocked', label: 'Blocked — do not accept' }]} />
          {formError ? <ErrorAlert error={new Error(formError)} /> : null}
          <Button type="submit" loading={busy}>Save preference<Check size={16} aria-hidden="true" /></Button>
          <p className={styles.formNote}>When rules overlap, blocked takes priority, then silent, then allowed. Reset removes a rule.</p>
        </form>
      </Panel>
    </div>
    <Panel className={styles.topGap} title="Daily silent digest" text="One scheduled batch of silent tings goes to your active sessions." aside={<Clock size={18} aria-hidden="true" />}>
      {scheduleError ? <ErrorAlert error={scheduleError} /> : null}
      {schedule ? <form className={styles.formStack} onSubmit={event => { event.preventDefault(); void action(() => api(apiPath('silent-schedule'), 'PUT', { enabled: schedule.enabled, time: schedule.time, timezone: schedule.timezone }), 'Silent digest schedule saved.'); }}>
        <Switch label="Send the daily silent digest" checked={schedule.enabled} onCheckedChange={enabled => setSchedule({ ...schedule, enabled })} />
        <Input label="Daily time" type="time" required value={schedule.time} onChange={event => setSchedule({ ...schedule, time: event.currentTarget.value })} />
        <Input label="Time zone" required placeholder="Asia/Kolkata" value={schedule.timezone} onChange={event => setSchedule({ ...schedule, timezone: event.currentTarget.value })} description="Initially detected from your device. Use an IANA time zone, such as Asia/Kolkata, Europe/London, or UTC." />
        <Button type="submit" loading={busy}>Save schedule<Check size={16} aria-hidden="true" /></Button>
        <p className={styles.formNote}>If no eligible session is active at the scheduled time, pending tings wait for the next daily schedule. Turning this off keeps silent tings in your inbox without a digest.</p>
      </form> : !scheduleError ? <p className={styles.formNote}>Loading schedule…</p> : null}
    </Panel>
    <Footnote icon={<BellOff size={14} aria-hidden="true" />}>Pending silent tings are kept until their scheduled digest. Blocked tings are not stored or delivered.</Footnote>
  </>;
}
