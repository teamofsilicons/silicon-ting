import type { Metadata } from 'next';
import { PreferencesPage } from '@/components/ting/preferences';

export const metadata: Metadata = { title: 'Preferences' };

export default function Page() {
  return <PreferencesPage />;
}
