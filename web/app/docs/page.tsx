import type { Metadata } from 'next';
import { DocsPage } from '@/components/ting/docs';

export const metadata: Metadata = { title: 'Documentation' };

export default function Page() {
  return <DocsPage />;
}
