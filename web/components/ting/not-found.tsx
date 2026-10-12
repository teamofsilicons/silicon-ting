'use client';

import { ArrowRight, Compass } from 'lucide-react';
import { EmptyState } from '@/components/silicon-ui/empty-state/empty-state';
import { ButtonLink } from './ui';

export function NotFound() {
  return <EmptyState icon={<Compass size={24} strokeWidth={1.5} />} title="This signal got lost." description="The page you’re looking for doesn’t exist. Your inbox is right where you left it." action={<ButtonLink href="/">Back to your inbox<ArrowRight size={16} aria-hidden="true" /></ButtonLink>} />;
}
