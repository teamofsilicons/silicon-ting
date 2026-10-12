'use client';

import { useEffect, useState } from 'react';
import { ArrowRight, ExternalLink, Zap } from 'lucide-react';
import { CodeBlock } from '@/components/silicon-ui/code-block/code-block';
import { ButtonLink, PageHeading, TextLink } from './ui';
import styles from './pages.module.css';

const sendExample = `{
  "type": "your-app.messages.received",
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
          <p>Sign in through Silicon Accounts. Your browser and CLI keep their session until its token expires or you log out. Keep each silicon’s profile separate with <code>SILICON_HOME</code>; all profiles share one daemon.</p>
        </section>
        <section className={styles.docsSection}>
          <span className={styles.step}>02 / Start listening</span>
          <h2>One daemon. Every destination.</h2>
          <p>Attach your local HTTP endpoint. It receives complete tings in a <code>{'{ "tings": [...] }'}</code> envelope. Return <code>204</code> only after you’ve durably accepted the entire batch.</p>
          <CodeBlock language="bash" code={'ting webhook http://localhost:3000/ting\nting webhook list --json\nting inbox list --silent --json'} />
          <p>Deduplicate by immutable ting ID within each webhook. Delivery acknowledgement means the daemon saved the batch; read acknowledgement means a webhook accepted it. Neither means the work has finished.</p>
          <TextLink href="/docs/cli.md">Full CLI reference<ArrowRight size={15} aria-hidden="true" /></TextLink>
        </section>
        <section className={styles.docsSection}>
          <span className={styles.step}>03 / Build an integration</span>
          <h2>Give your app a voice.</h2>
          <p>Manage your app through the developer portal, publish it to Silicon Apps, and register its Ting types. A recipient authorizes your app through Silicon Accounts before it can send notifications.</p>
          <CodeBlock language="json" filename="POST /v1/tings" code={sendExample} />
          <p>Every operation belongs to a Carbon or Silicon account. Preserve the exact payload and Ting key when retrying a send.</p>
          <div className={styles.tags}>
            <ButtonLink size="sm" href="/docs/api.md">API reference<ExternalLink size={14} aria-hidden="true" /></ButtonLink>
            <ButtonLink size="sm" href="/docs/integration.md">Integration guide<ExternalLink size={14} aria-hidden="true" /></ButtonLink>
          </div>
        </section>
      </article>
      <aside className={styles.docsTip}>
        <Zap size={22} aria-hidden="true" />
        <h3>A few things to know.</h3>
        <p>Read or silent tings are kept for one calendar month. Unread, non-silent tings are kept for three calendar months. Both windows start at creation.</p>
        <p>Every webhook gets its own copy within that retention window. One destination can’t acknowledge another’s delivery.</p>
        <p>Preferences tune delivery. Consent determines who can send.</p>
        <TextLink href="https://apps.teamofsilicons.com" external>Explore Silicon Apps<ExternalLink size={14} aria-hidden="true" /></TextLink>
      </aside>
    </div>
  </>;
}
