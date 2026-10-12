'use client';

import { useEffect, useState, type FormEvent } from 'react';
import { ArrowRight, Bell, Check, ChevronRight, LayoutGrid, Plus, UserRound, Zap } from 'lucide-react';
import { Avatar } from '@/components/silicon-ui/avatar/avatar';
import { Badge } from '@/components/silicon-ui/badge/badge';
import { Button } from '@/components/silicon-ui/button/button';
import { Dialog, DialogContent } from '@/components/silicon-ui/dialog/dialog';
import { EmptyState } from '@/components/silicon-ui/empty-state/empty-state';
import { Input } from '@/components/silicon-ui/input/input';
import { Textarea } from '@/components/silicon-ui/textarea/textarea';
import { api, type TingApp, type TingType } from '@/lib/api';
import { routes } from '@/lib/routes';
import { useList } from '@/lib/use-list';
import { apiPath, enc, typeError } from '@/lib/utils';
import { ErrorAlert, ListStatus, More, PageHeading, Panel, TextLink } from './ui';
import { RequireAccount } from './welcome';
import { useWorkspace } from './workspace';
import styles from './pages.module.css';

export function ApplicationsPage() {
  return <RequireAccount page="apps"><Applications /></RequireAccount>;
}

function Applications() {
  const { identity, revision, action } = useWorkspace();
  const apps = useList<TingApp>(apiPath('apps?limit=100'), revision, identity);
  const [selected, setSelected] = useState('');
  useEffect(() => { setSelected(''); }, [identity]);
  useEffect(() => { if (!selected && apps.items.length) setSelected(apps.items[0].app_id); }, [selected, apps.items]);
  const types = useList<TingType>(selected ? apiPath(`apps/${enc(selected)}/types?limit=100`) : undefined, revision, identity);
  const active = apps.items.find(item => item.app_id === selected);
  const [editor, setEditor] = useState<{ open: boolean; editing?: TingType; key: number }>({ open: false, key: 0 });
  const edit = (editing?: TingType) => setEditor(previous => ({ open: true, editing, key: previous.key + 1 }));

  async function save(type: string, description: string) {
    const editing = editor.editing;
    const saved = await action(
      () => api(apiPath(`apps/${enc(selected)}/types${editing ? `/${enc(editing.type)}` : ''}`), editing ? 'PATCH' : 'POST', editing ? { description } : { type, description }),
      editing ? 'Type updated.' : 'Type registered.',
    );
    if (saved) setEditor(previous => ({ ...previous, open: false }));
  }

  return <>
    <PageHeading eyebrow="The things that keep you in sync" title="Applications" text="Define the signals your applications send." />
    <ListStatus list={apps} empty={<Panel><EmptyState icon={<LayoutGrid size={24} strokeWidth={1.5} />} title="Room for your first app." description="Published Silicon Apps appear here. Manage your applications in the developer portal." action={<TextLink href={routes.docs.href}>Read the integration guide<ArrowRight size={15} aria-hidden="true" /></TextLink>} /></Panel>} />
    {apps.items.length ? <div className={styles.appLayout}>
      <aside className={styles.appSelector} aria-label="Your applications">
        <span className={styles.listLabel}>Your applications</span>
        {apps.items.map(app => <button key={app.app_id} type="button" className={styles.appOption} aria-pressed={selected === app.app_id} onClick={() => setSelected(app.app_id)}>
          <Avatar name={app.name || app.app_id} size="sm" />
          <span><strong>{app.name || app.app_id}</strong><small className="mono">{app.app_id}</small></span>
          <ChevronRight size={15} aria-hidden="true" />
        </button>)}
        <More list={apps} />
      </aside>
      <Panel
        title={active?.name || selected}
        text={selected}
        aside={active?.can_manage_tings ? <Button size="sm" onClick={() => edit()}><Plus size={15} aria-hidden="true" />Register type</Button> : undefined}
      >
        <p className={styles.infoLine}><Zap size={16} aria-hidden="true" />New types are enabled for carbons and silicons. Recipient preferences still apply.</p>
        <ListStatus list={types} empty={<EmptyState icon={<Bell size={24} strokeWidth={1.5} />} title="Every signal starts with a type." description="Register a service and event to give your app a notification vocabulary." />} />
        {types.items.map(type => <article key={type.type} className={styles.typeRow}>
          <div>
            <h3 className="mono">{type.type}</h3>
            <p>{type.description}</p>
            <div className={styles.tags}>
              <Badge size="sm" tone={type.defaults.carbon ? 'success' : 'neutral'}>{type.defaults.carbon ? 'Carbon' : 'Carbon off'}</Badge>
              <Badge size="sm" tone={type.defaults.silicon ? 'success' : 'neutral'}>{type.defaults.silicon ? 'Silicon' : 'Silicon off'}</Badge>
            </div>
          </div>
          {active?.can_manage_tings ? <Button variant="secondary" size="sm" onClick={() => edit(type)}>Edit</Button> : null}
        </article>)}
        <More list={types} />
      </Panel>
    </div> : null}
    <Dialog open={editor.open} onOpenChange={open => setEditor(previous => ({ ...previous, open }))}>
      <DialogContent title={editor.editing ? 'Edit ting type' : 'Register a ting type'} description={selected}>
        <TypeForm key={editor.key} app={selected} editing={editor.editing} save={save} />
      </DialogContent>
    </Dialog>
  </>;
}

function TypeForm({ app, editing, save }: { app: string; editing?: TingType; save: (type: string, description: string) => Promise<void> }) {
  const { busy, actionError } = useWorkspace();
  const [name, setName] = useState(editing?.type ?? `${app}.`);
  const [description, setDescription] = useState(editing?.description ?? '');
  const [error, setError] = useState('');
  const [submitted, setSubmitted] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault();
    const problem = typeError(app, name.trim(), description);
    setError(problem ?? '');
    if (problem) return;
    setSubmitted(true);
    await save(name.trim(), description);
  }
  return <form className={styles.formStack} onSubmit={submit}>
    <Input label="Type name" required value={name} disabled={!!editing} onChange={event => setName(event.currentTarget.value)} placeholder={`${app}.messages.received`} description="Use app_id.service.event. Name events in the past tense, like messages.received." />
    <Textarea label="Description" required rows={4} value={description} onChange={event => setDescription(event.currentTarget.value)} placeholder="What happened, and when should this ting be sent?" />
    <p className={styles.infoLine}><UserRound size={16} aria-hidden="true" />Enabled by default for both carbons and silicons.</p>
    {error ? <ErrorAlert error={new Error(error)} /> : submitted && actionError ? <ErrorAlert error={actionError} /> : null}
    <Button type="submit" loading={busy}>{editing ? 'Save changes' : 'Register type'}<Check size={16} aria-hidden="true" /></Button>
  </form>;
}
