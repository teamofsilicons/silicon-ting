import type { Metadata } from 'next';
import { NotFound } from '@/components/ting/not-found';

export const metadata: Metadata = { title: 'Not found' };

export default function Page() {
  return <NotFound />;
}
