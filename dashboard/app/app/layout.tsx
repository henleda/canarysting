import type { Metadata } from 'next';
import { Suspense } from 'react';
import './globals.css';
import { SinceProvider } from '@/components/SinceProvider';
import SideNav from '@/components/SideNav';

export const metadata: Metadata = {
  title: 'CanarySting — Operations',
  description: 'CanarySting CISO operations dashboard',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        {/* The shell: a fixed left console rail + the page body. The rail lets the
            Operations wall stay decluttered (Recon / Adversary Intel moved to their
            own pages). SideNav is a client component (usePathname) but needs no
            Suspense; only SinceProvider (useSearchParams) does. */}
        <div className="shell">
          <SideNav />
          <div className="shell-body">
            <Suspense>
              <SinceProvider>{children}</SinceProvider>
            </Suspense>
          </div>
        </div>
      </body>
    </html>
  );
}
