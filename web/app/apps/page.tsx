import type { Metadata } from 'next';
import { ApplicationsPage } from '@/components/ting/applications';

export const metadata: Metadata = { title: 'Applications' };

export default function Page() {
  return <ApplicationsPage />;
}
