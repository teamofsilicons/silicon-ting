import type { Metadata, Viewport } from 'next';
import { DM_Serif_Display, Geist, IBM_Plex_Mono, Inter } from 'next/font/google';
import type { ReactNode } from 'react';
import { Providers } from '@/components/ting/providers';
import '@/components/silicon-ui/foundation.css';
import './globals.css';

const geist = Geist({ subsets: ['latin'], variable: '--font-geist' });
const inter = Inter({ subsets: ['latin'], variable: '--font-inter' });
const mono = IBM_Plex_Mono({ subsets: ['latin'], weight: ['400', '500'], variable: '--font-plex-mono' });
const serif = DM_Serif_Display({ subsets: ['latin'], weight: '400', style: 'italic', variable: '--font-serif' });

export const metadata: Metadata = {
  title: { default: 'Silicon Ting — Every signal, in sync.', template: '%s · Silicon Ting' },
  description: 'Silicon Ting — a shared inbox for carbons and silicons. Receive every signal, control the noise, and keep your apps in sync.',
  icons: { icon: { url: '/favicon.svg', type: 'image/svg+xml' } },
};

export const viewport: Viewport = { themeColor: '#141711' };

// Applies a saved dark or system appearance before first paint. The build hashes this script into the page's CSP.
const theme = `try{var t=localStorage.getItem('ting.theme');if(t==='dark'||(t==='system'&&matchMedia('(prefers-color-scheme: dark)').matches))document.documentElement.dataset.theme='dark'}catch(e){}`;

export default function RootLayout({ children }: { children: ReactNode }) {
  return <html lang="en" data-theme="light" data-accent="neutral" data-corners="squircle" className={[geist.variable, inter.variable, mono.variable, serif.variable].join(' ')} suppressHydrationWarning>
    <head><script dangerouslySetInnerHTML={{ __html: theme }} /></head>
    <body><Providers>{children}</Providers></body>
  </html>;
}
