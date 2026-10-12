'use client';

import Link from 'next/link';
import type { AnchorHTMLAttributes, ReactNode } from 'react';
import { ChevronDown, RefreshCw } from 'lucide-react';
import { Alert } from '@/components/silicon-ui/alert/alert';
import { Button, type ButtonSize, type ButtonVariant } from '@/components/silicon-ui/button/button';
import buttonStyles from '@/components/silicon-ui/button/button.module.css';
import { TextShimmer } from '@/components/silicon-ui/text-shimmer/text-shimmer';
import { ApiError } from '@/lib/api';
import type { ListState } from '@/lib/use-list';
import styles from './ui.module.css';

export function errorText(error: unknown) {
  return error instanceof Error ? error.message : 'The request could not be completed.';
}

export function ErrorAlert({ error, retry, onDismiss }: { error: unknown; retry?: () => void; onDismiss?: () => void }) {
  const hint = error instanceof ApiError ? error.hint : undefined;
  return <Alert tone="danger" title={errorText(error)} onDismiss={onDismiss} className={styles.alert}>
    {hint || retry ? <>
      {hint}
      {retry ? <span className={styles.retry}><Button variant="secondary" size="sm" onClick={retry}><RefreshCw size={15} aria-hidden="true" />Retry</Button></span> : null}
    </> : undefined}
  </Alert>;
}

export function Loading({ children = 'Getting your signals…' }: { children?: string }) {
  return <div className={styles.loading} role="status"><TextShimmer>{children}</TextShimmer></div>;
}

/** A link with Silicon UI button styling. Internal paths use client navigation. */
export function ButtonLink({ href, variant = 'secondary', size = 'md', className, children, ...props }: AnchorHTMLAttributes<HTMLAnchorElement> & { href: string; variant?: ButtonVariant; size?: ButtonSize }) {
  const classes = [buttonStyles.button, buttonStyles[variant], buttonStyles[size], className].filter(Boolean).join(' ');
  const label = <span className={buttonStyles.labelPhase}>{children}</span>;
  if (/^(https?:)?\/\//.test(href) || /\.(md|sh|ps1)$/.test(href)) return <a href={href} className={classes} {...props}>{label}</a>;
  return <Link href={href} className={classes} {...props}>{label}</Link>;
}

export function TextLink({ href, children, external }: { href: string; children: ReactNode; external?: boolean }) {
  if (external || /^https?:/.test(href) || /\.md$/.test(href)) return <a className={styles.textLink} href={href} {...(external ? { target: '_blank', rel: 'noreferrer' } : {})}>{children}</a>;
  return <Link className={styles.textLink} href={href}>{children}</Link>;
}

export function PageHeading({ eyebrow, title, text, action }: { eyebrow: string; title: string; text: string; action?: ReactNode }) {
  return <div className={styles.heading}>
    <div>
      <span className={styles.eyebrow}>{eyebrow}</span>
      <h1>{title}<span className={styles.dot}>.</span></h1>
      <p>{text}</p>
    </div>
    {action}
  </div>;
}

export function Panel({ title, text, aside, children, className }: { title?: ReactNode; text?: string; aside?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={[styles.panel, className].filter(Boolean).join(' ')}>
    {title ? <div className={styles.panelHeading}><div><h2>{title}</h2>{text ? <p>{text}</p> : null}</div>{aside}</div> : null}
    <div className={styles.panelBody}>{children}</div>
  </section>;
}

export function More({ list }: { list: Pick<ListState<unknown>, 'cursor' | 'loading' | 'more'> }) {
  if (!list.cursor) return null;
  return <div className={styles.more}><Button variant="secondary" loading={list.loading} onClick={() => void list.more()}>Load more<ChevronDown size={16} aria-hidden="true" /></Button></div>;
}

export function Footnote({ icon, children }: { icon: ReactNode; children: ReactNode }) {
  return <p className={styles.footnote}>{icon}<span>{children}</span></p>;
}

/** Shows an error, a loading state or an empty state for a list, in that order. */
export function ListStatus({ list, empty }: { list: Pick<ListState<unknown>, 'items' | 'loading' | 'error' | 'reload'>; empty: ReactNode }) {
  if (list.error) return <ErrorAlert error={list.error} retry={() => void list.reload()} />;
  if (list.loading && !list.items.length) return <Loading />;
  if (!list.loading && !list.items.length) return <>{empty}</>;
  return null;
}
