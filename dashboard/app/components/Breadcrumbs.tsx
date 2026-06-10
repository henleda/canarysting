import Link from 'next/link';

export type Crumb = { label: string; href?: string };

// Breadcrumbs renders a single monospace "/"-separated trail (no nav bar). The
// last crumb is the current page; earlier ones with an href are links.
export default function Breadcrumbs({ crumbs }: { crumbs: Crumb[] }) {
  return (
    <nav className="crumbs" aria-label="breadcrumb">
      {crumbs.map((c, i) => (
        <span key={i}>
          {i > 0 && <span className="sep">/</span>}
          {c.href ? <Link href={c.href}>{c.label}</Link> : <span className="cur">{c.label}</span>}
        </span>
      ))}
    </nav>
  );
}
