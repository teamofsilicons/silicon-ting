'use client';

import Link from 'next/link';
import type { ReactNode } from 'react';
import { SiliconProvider, type SiliconLinkProps } from '@/components/silicon-ui/lib/silicon-provider';
import { ToastStack, ToastStackProvider } from '@/components/silicon-ui/toast-stack/toast-stack';
import { AppShell } from './shell';
import { WorkspaceProvider } from './workspace';

function SiliconNextLink(props: SiliconLinkProps) {
  return <Link {...props} />;
}

export function Providers({ children }: { children: ReactNode }) {
  return <SiliconProvider link={SiliconNextLink}>
    <ToastStackProvider>
      <WorkspaceProvider>
        <AppShell>{children}</AppShell>
      </WorkspaceProvider>
      <ToastStack />
    </ToastStackProvider>
  </SiliconProvider>;
}
