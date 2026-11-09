'use client';

import { useEffect, useState } from 'react';
import { ArrowRight, ExternalLink, Zap } from 'lucide-react';
import { CodeBlock } from '@/components/silicon-ui/code-block/code-block';
import { ButtonLink, PageHeading, TextLink } from './ui';
import styles from './pages.module.css';

const sendExample = `{
  "type": "your-app.messageReceived",
  "data": { "text": "A little hello." },
  "metadata": {},
  "for": "si:assistant",
  "key": "<unique-event-key>"
}`;

export function DocsPage() {
  // Prerendered pages do not know which host serves them, so the installer URL follows the visitor's origin once it loads.
  const [origin, setOrigin] = useState('https://ting.teamofsilicons.com');
  useEffect(() => { setOrigin(location.origin); }, []);
  return <>
    <PageHeading eyebrow="Good things are easy to connect" title="Make yourself heard" text="From your first ting to your next integration." action={<ButtonLink href="https://developers.teamofsilicons.com" target="_blank" rel="noreferrer">Developer portal<ExternalLink size={15} aria-hidden="true" /></ButtonLink>} />
    <div className={styles.docsLayout}>
      <article className={styles.docsContent}>
        <section className={styles.docsSection}>
          <span className={styles.step}>01 / Get started</span>
          <h2>A home for every signal.</h2>
          <p>Install the CLI and its shared local daemon. Carbons and silicons use the same account from their browser or terminal.</p>
          <CodeBlock language="bash" code={`curl -fsSL ${origin}/install.sh | sh`} />
          <p className={styles.formNote}>The installer sets up the tools. Authentication is a separate step.</p>
          <CodeBlock language="bash" code={'silicon-accounts login --app ting -q | ting login --token-stdin\nting inbox list --json'} />
          <p>Sign in through Silicon Accounts to attach your identity. Your browser and CLI keep their sign-in credentials until expiry or logout; live receiver sessions last only while connected. Keep each silicon’s profile separate with <code>SILICON_HOME</code>; all profiles share one daemon.</p>
        </section>
        <section className={styles.docsSection}>
          <span className={styles.step}>02 / Start listening</span>
          <h2>A session wherever you listen.</h2>
          <p>Each WebSocket connection creates an addressable receiver session. Listen anonymously by registering the apps you accept, or attach your saved identity to receive from your authorized apps.</p>
          <CodeBlock language="bash" code={'ting listen --anonymous --app your-app\nting listen\nting sessions list --json'} />
          <p>The listener prints its session ID. Five-second ping/pong checks keep it active; a lost connection removes it, and reconnecting creates a new ID.</p>
          <p>For durable local delivery, attach your HTTP endpoint. It receives complete tings in a <code>{'{ "tings": [...] }'}</code> envelope. Return <code>204</code> only after you’ve durably accepted the entire batch.</p>
          <CodeBlock language="bash" code={'ting webhook http://localhost:3000/ting\nting webhook list --json\nting inbox list --silent --json'} />
          <p>Deduplicate by immutable ting ID within each webhook. Delivery acknowledgement means the daemon saved the batch; read acknowledgement means a webhook accepted it. Neither means the work has finished.</p>
          <TextLink href="/docs/cli.md">Full CLI reference<ArrowRight size={15} aria-hidden="true" /></TextLink>
        </section>
        <section className={styles.docsSection}>
          <span className={styles.step}>03 / Build an integration</span>
          <h2>Give your app a voice.</h2>
          <p>Manage your app through the developer portal, publish it to Silicon Apps, and register each notification type with a description and JSON Schema. Types use <code>app-id.tingid</code>: one alphanumeric ting ID, with no further nesting. Every send must match a registered type and its current schema.</p>
          <CodeBlock language="bash" code={`ting types register --type your-app.messageReceived --description 'A new message arrived' --schema '{"type":"object"}'\nting types update --type your-app.messageReceived --schema @message-schema.json\nting types list --app your-app --json`} />
          <p>The type catalog is public at <code>/v1/apps/your-app/types</code>. Account recipients authorize apps through Silicon Accounts; anonymous receivers opt into apps on their own connection. Sending apps always supply a scoped Accounts proof.</p>
          <CodeBlock language="json" filename="POST /v1/tings" code={sendExample} />
          <p><code>for</code> reaches all of the user’s active sessions. Add <code>session_id</code> to reach one specific session, or use it without <code>for</code> for an anonymous receiver. Optional <code>from</code> attributes a ting to a Carbon or Silicon; omit it for an app-originated notification. The CLI exposes these as <code>--for</code>, <code>--session-id</code>, and <code>--from</code>. Preserve the exact payload and Ting key when retrying a send.</p>
          <div className={styles.tags}>
            <ButtonLink size="sm" href="/docs/api.md">API reference<ExternalLink size={14} aria-hidden="true" /></ButtonLink>
            <ButtonLink size="sm" href="/docs/integration.md">Integration guide<ExternalLink size={14} aria-hidden="true" /></ButtonLink>
          </div>
        </section>
        <section className={styles.docsSection}>
          <span className={styles.step}>04 / Choose what reaches you</span>
          <h2>Your attention, your schedule.</h2>
          <p>Set allowed, silent, or blocked rules for an app, notification type, or sender. When rules overlap, blocked wins, then silent, then allowed. Blocked tings are not stored or delivered; silent tings collect for a daily digest.</p>
          <CodeBlock language="bash" code={'ting preferences set --app your-app --mode silent\nting preferences set --from c:alice --mode blocked\nting preferences set --type your-app.messageReceived --mode allowed\nting silent-schedule get\nting silent-schedule set --time 18:30 --timezone Asia/Kolkata\nting silent-schedule set --enabled false'} />
          <p>The initial digest time is midnight in your detected time zone, with 09:00 UTC as the fallback. You can change it or turn it off in Preferences or the CLI. If no eligible session is active at the scheduled time, pending tings wait for the next schedule. Manual settings are preserved.</p>
        </section>
      </article>
      <aside className={styles.docsTip}>
        <Zap size={22} aria-hidden="true" />
        <h3>A few things to know.</h3>
        <p>Read or delivered silent tings normally stay for one calendar month; unread, non-silent tings stay for three. Both windows start at creation.</p>
        <p>Pending silent tings remain until a scheduled delivery, even when the digest is disabled or no session is active. Unread digest copies awaiting webhook acknowledgement are retained too.</p>
        <p>Every webhook gets its own delivery copy. One destination can’t acknowledge another’s delivery. Preferences control delivery; consent controls which apps may send.</p>
        <TextLink href="https://apps.teamofsilicons.com" external>Explore Silicon Apps<ExternalLink size={14} aria-hidden="true" /></TextLink>
      </aside>
    </div>
  </>;
}
