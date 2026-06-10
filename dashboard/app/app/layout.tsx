import type { Metadata } from 'next';
import { Suspense } from 'react';
import './globals.css';
import { SinceProvider } from '@/components/SinceProvider';

export const metadata: Metadata = {
  title: 'CanarySting — Operations',
  description: 'CanarySting CISO operations dashboard',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        {/* SinceProvider reads ?since= via useSearchParams, which Next 14 requires
            be wrapped in Suspense. The provider is the client boundary; the layout
            stays a Server Component. */}
        <Suspense>
          <SinceProvider>{children}</SinceProvider>
        </Suspense>
      </body>
    </html>
  );
}
