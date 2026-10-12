'use client';

import type { ReactNode } from 'react';
import { ArrowRight, Bell, ChevronRight, Inbox, LayoutGrid, ShieldCheck, SlidersHorizontal, Terminal, Zap } from 'lucide-react';
import { Card } from '@/components/silicon-ui/card/card';
import { EmptyState } from '@/components/silicon-ui/empty-state/empty-state';
import { routes, type Page } from '@/lib/routes';
import { LoginButtons } from './shell';
import { ButtonLink, Loading, TextLink } from './ui';
import { useWorkspace } from './workspace';
import styles from './welcome.module.css';

const gateIcons: Partial<Record<Page, typeof Inbox>> = { inbox: Inbox, apps: LayoutGrid, preferences: SlidersHorizontal, connections: ShieldCheck };

const features = [
  { icon: Inbox, title: 'Everything finds its way.', text: 'A shared inbox for the apps you use. Unread, non-silent tings stay for three months. Read or silent tings stay for one.', tag: 'Room for your signals' },
  { icon: SlidersHorizontal, title: 'You set the volume.', text: 'Fine-tune by app, service, or event. Quiet the noise and find recent updates in your silent drawer.', tag: 'Your attention, your rules' },
  { icon: Terminal, title: 'Made for both of you.', text: 'A thoughtful workspace for carbons. A fast CLI and local webhooks for silicons.', tag: 'Human & agent native' },
];

export function Welcome() {
  return <>
    <section className={styles.intro}>
      <div className={styles.copy}>
        <span className={styles.eyebrow}><i /> The signal, without the noise</span>
        <h1>Good things start<br />with a little <span className={styles.serifWord}>ting.</span></h1>
        <p>One place for every app, every update, and every little thing that deserves your attention.</p>
        <div className={styles.actions}><LoginButtons /><TextLink href={routes.docs.href}>Meet your new inbox<ChevronRight size={15} aria-hidden="true" /></TextLink></div>
        <span className={styles.note}><ShieldCheck size={14} aria-hidden="true" />Your account. Your apps. Your signals.</span>
      </div>
      <div className={styles.art} aria-hidden="true">
        <div className={`${styles.orbit} ${styles.orbitOne}`} />
        <div className={`${styles.orbit} ${styles.orbitTwo}`} />
        <div className={`${styles.orbit} ${styles.orbitThree}`} />
        <div className={styles.center}><span>t<span>•</span></span></div>
        <span className={`${styles.satellite} ${styles.satelliteOne}`}><Terminal size={22} /></span>
        <span className={`${styles.satellite} ${styles.satelliteTwo}`}><Bell size={22} /></span>
        <span className={`${styles.satellite} ${styles.satelliteThree}`}><LayoutGrid size={22} /></span>
        <span className={`${styles.label} ${styles.labelOne}`}><i />Carbons</span>
        <span className={`${styles.label} ${styles.labelTwo}`}><i />Silicons</span>
      </div>
    </section>
    <div className={styles.sectionLabel}><span>A shared language for your apps</span><span>Built for carbons & silicons <Zap size={13} aria-hidden="true" /></span></div>
    <div className={styles.features}>
      {features.map(({ icon: Icon, title, text, tag }, index) => <Card
        key={title}
        title={title}
        description={text}
        media={<div className={styles.featureMedia}><span className={styles.featureIcon}><Icon size={20} aria-hidden="true" /></span><span className={styles.featureNumber}>0{index + 1}</span></div>}
        meta={<span className={styles.featureTag}>{tag}</span>}
      />)}
    </div>
    <div className={styles.banner}>
      <span className={styles.bannerIcon}><Terminal size={22} aria-hidden="true" /></span>
      <div><h3>Small signal. Endless possibilities.</h3><p>Connect your first app, or give your silicon an inbox.</p></div>
      <ButtonLink href={routes.docs.href}>Start building<ArrowRight size={16} aria-hidden="true" /></ButtonLink>
    </div>
  </>;
}

function SignInGate({ page }: { page: Page }) {
  const Icon = gateIcons[page] ?? Inbox;
  return <div className={styles.gate}>
    <span className={styles.eyebrow}>Your workspace awaits</span>
    <EmptyState
      icon={<Icon size={24} strokeWidth={1.5} />}
      title={`Your ${routes[page].name.toLowerCase()}, connected.`}
      description="Sign in with Silicon Accounts to bring your apps and signals together."
      action={<LoginButtons />}
    />
    <p className={styles.gateNote}>Your inbox and preferences belong to your Carbon or Silicon account.</p>
  </div>;
}

/** Renders the page for a signed-in account, the welcome page on the inbox, or a sign-in prompt. */
export function RequireAccount({ page, children }: { page: Page; children: ReactNode }) {
  const { booting, identity } = useWorkspace();
  if (booting) return <Loading />;
  if (!identity) return page === 'inbox' ? <Welcome /> : <SignInGate page={page} />;
  return <>{children}</>;
}
