'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

// SideNav is the left console rail (added in the layout shell). It navigates the
// drillable pages so the Operations wall can stay decluttered: Recon and Adversary
// Intelligence live on their own pages, reachable here, instead of crowding the
// one screen. Active state is derived from the pathname (query string ignored).
type Item = { href: string; label: string; hint: string; match: (p: string) => boolean };

const ITEMS: Item[] = [
  { href: '/', label: 'Operations', hint: 'the wall', match: (p) => p === '/' },
  { href: '/recon?since=1h', label: 'Recon', hint: 'watching, not acting', match: (p) => p.startsWith('/recon') },
  { href: '/intel?since=1h', label: 'Adversary Intel', hint: 'the compounding moat', match: (p) => p.startsWith('/intel') },
  { href: '/cost?since=1h', label: 'Attacker Cost', hint: 'the inversion', match: (p) => p.startsWith('/cost') },
  { href: '/precision?since=1h', label: 'Bystanders', hint: 'flow-precise, zero FP', match: (p) => p.startsWith('/precision') },
  { href: '/credibility', label: 'Credibility', hint: 'learned state · M · calibration', match: (p) => p.startsWith('/credibility') },
  { href: '/flows?since=1h', label: 'Flows', hint: 'per-tier sessions', match: (p) => p.startsWith('/flows') || p.startsWith('/flow') },
];

export default function SideNav() {
  const pathname = usePathname() || '/';
  return (
    <nav className="sidenav" aria-label="console">
      <div className="sidenav-label">Console</div>
      {ITEMS.map((it) => {
        const active = it.match(pathname);
        return (
          <Link key={it.href} href={it.href} className={`navitem${active ? ' active' : ''}`}>
            <span className="navitem-bar" />
            <span className="navitem-body">
              <span className="navitem-label">{it.label}</span>
              <span className="navitem-hint">{it.hint}</span>
            </span>
          </Link>
        );
      })}
    </nav>
  );
}
