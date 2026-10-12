import type { Metadata } from 'next';
import { ConnectionsPage } from '@/components/ting/connections';

export const metadata: Metadata = { title: 'Connections' };

export default function Page() {
  return <ConnectionsPage />;
}
