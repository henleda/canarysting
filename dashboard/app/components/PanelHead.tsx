import type { CSSProperties, ReactNode } from 'react';

export interface PanelTag {
  label: string;
  style?: CSSProperties;
}

interface PanelHeadProps {
  title: ReactNode;
  // Tags rendered before the divider line (e.g. "flow").
  preTags?: PanelTag[];
  // Tags rendered after the divider line (e.g. "async · kernel-enforced").
  postTags?: PanelTag[];
  titleStyle?: CSSProperties;
}

// PanelHead mirrors the prototype's `.phead` (an <h2> + optional <span.tag>s and
// a flex-grow divider line). The prototype places some tags before the line and
// some after, so preTags/postTags control which side each lands on.
export default function PanelHead({ title, preTags = [], postTags = [], titleStyle }: PanelHeadProps) {
  return (
    <div className="phead">
      <h2 style={titleStyle}>{title}</h2>
      {preTags.map((t, i) => (
        <span key={`pre-${i}`} className="tag" style={t.style}>
          {t.label}
        </span>
      ))}
      <span className="line" />
      {postTags.map((t, i) => (
        <span key={`post-${i}`} className="tag" style={t.style}>
          {t.label}
        </span>
      ))}
    </div>
  );
}
