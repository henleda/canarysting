'use client';

import { useEffect, useRef, useState } from 'react';
import type { TraceEvidenceView, TraceWorkspace as TraceWorkspaceView } from '@/lib/types';

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

function formatUTC(value?: string): string {
  if (!value) return 'Source time missing';
  return new Intl.DateTimeFormat('en-US', {
    dateStyle: 'medium',
    timeStyle: 'medium',
    timeZone: 'UTC',
  }).format(new Date(value));
}

export default function TraceWorkspace({ view }: { view: TraceWorkspaceView }) {
  const [selectedEvidence, setSelectedEvidence] = useState<TraceEvidenceView | null>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);
  const openerRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    if (selectedEvidence && dialogRef.current && !dialogRef.current.open) {
      dialogRef.current.showModal();
    }
  }, [selectedEvidence]);

  function openEvidence(evidence: TraceEvidenceView, opener: HTMLButtonElement) {
    openerRef.current = opener;
    setSelectedEvidence(evidence);
  }

  function closeEvidence() {
    dialogRef.current?.close();
  }

  function restoreEvidenceFocus() {
    setSelectedEvidence(null);
    openerRef.current?.focus();
  }

  const rawEvidence = view.evidence.filter((evidence) => evidence.raw);

  return (
    <article className="trace-workspace" aria-labelledby="trace-title">
      <header className="trace-summary-card">
        <div className="trace-eyebrow">
          <span>Security trace</span>
          {view.synthetic && <span className="trace-badge trace-badge-fixture">Synthetic fixture</span>}
          <span className="trace-badge trace-badge-readonly">Read-only</span>
        </div>
        <div className="trace-title-row">
          <div>
            <h1 id="trace-title">{view.title}</h1>
            <p>{view.summary}</p>
          </div>
          <div className="trace-state-stack">
            <span className="trace-status" aria-label={`Trace status: ${view.status.label}`}>
              {view.status.label}
            </span>
            <span className="trace-confidence" aria-label={`Correlation confidence: ${view.confidence.level}`}>
              {view.confidence.level} confidence · {view.confidence.completeness} evidence
            </span>
          </div>
        </div>
        <div className="trace-scope-line">
          <span>{view.scope.display_name}</span>
          <span>{view.status.detail}</span>
          <span>Updated from immutable trace evidence</span>
        </div>
      </header>

      <div className="trace-decision-grid">
        <section className="trace-card" aria-labelledby="what-happened-heading">
          <h2 id="what-happened-heading">What happened</h2>
          <p className="trace-lead">{view.what_happened}</p>
          <ol className="trace-timeline" aria-label="Ordered security trace">
            {view.hops.map((hop, index) => (
              <li key={hop.record_id}>
                <span className="trace-hop-number" aria-hidden="true">{index + 1}</span>
                <div className="trace-hop-body">
                  <div className="trace-hop-top">
                    <strong>{hop.label}</strong>
                    <span>{hop.kind}</span>
                  </div>
                  <span className="trace-hop-time">
                    {hop.at ? <time dateTime={hop.at}>{formatUTC(hop.at)} UTC</time> : hop.time_status}
                    {' · '}{hop.time_uncertainty}{hop.time_window ? ` (±${hop.time_window})` : ''}
                  </span>
                  <div className="trace-hop-identities">
                    {hop.identities.map((identity) => (
                      <span key={`${identity.kind}:${identity.id}`}>
                        {identity.name} · {identity.kind} · {identity.verified ? 'Verified' : identity.assertion_mode}
                      </span>
                    ))}
                  </div>
                  <span className="trace-hop-evidence">{plural(hop.evidence_count, 'evidence reference')}</span>
                </div>
              </li>
            ))}
          </ol>
        </section>

        <section className="trace-card trace-explanation" aria-labelledby="trace-explanation-heading">
          <h2 id="trace-explanation-heading">Why CanaryView believes this</h2>
          <p className="trace-claim">{view.explanation.claim}</p>
          <p>{view.explanation.reason}</p>
          <dl className="trace-facts">
            <div><dt>Correlation method</dt><dd>{view.explanation.methods.join(', ') || 'No join established'}</dd></div>
            <div><dt>Confidence</dt><dd>{view.confidence.level} · {view.confidence.method}</dd></div>
            <div><dt>Identity assurance</dt><dd>{view.confidence.identity_assurance}</dd></div>
            <div><dt>Event-time confidence</dt><dd>{view.confidence.time_uncertainty}{view.confidence.time_window ? ` · ${view.confidence.time_window} trace window` : ''}</dd></div>
            <div><dt>Human review</dt><dd>{view.confidence.human_review}</dd></div>
          </dl>
          <ul className="trace-joins" aria-label="Evidence-backed candidate joins">
            {view.explanation.joins.map((join) => (
              <li key={`${join.anchor_id}:${join.candidate_id}:${join.method}`}>
                <span>{join.method} · {join.strength}</span>
                <strong>{join.ambiguous ? 'Candidate—not selected' : join.selected ? 'Selected' : 'Retained alternative'}</strong>
                <details>
                  <summary>Technical citations</summary>
                  <code>{join.citations.join(' → ')}</code>
                </details>
              </li>
            ))}
          </ul>
          {rawEvidence.map((evidence, index) => (
            <button
              key={`${evidence.id}:${evidence.hop_record_id ?? ''}:${index}`}
              type="button"
              className="trace-evidence-button"
              onClick={(event) => openEvidence(evidence, event.currentTarget)}
            >
              View raw reference for {evidence.label}
            </button>
          ))}
        </section>
      </div>

      <section className="trace-card" aria-labelledby="affected-heading">
        <h2 id="affected-heading">Affected state</h2>
        {view.affected.length > 0 ? (
          <div className="trace-affected-grid">
            {view.affected.map((identity) => (
              <div key={`${identity.kind}:${identity.id}`} className="trace-affected-item">
                <strong>{identity.name}</strong>
                <span>{identity.kind}</span>
                <span>{identity.verified ? 'Verified identity' : `${identity.assertion_mode} identity · not verified`}</span>
              </div>
            ))}
          </div>
        ) : (
          <p>No affected identity was identified by the available evidence.</p>
        )}
      </section>

      <div className="trace-limit-grid">
        <section className="trace-card trace-gap-card" aria-labelledby="partial-coverage-heading">
          <h2 id="partial-coverage-heading">Partial coverage</h2>
          {view.missing.length === 0 ? (
            <p>No declared coverage gaps remain. Complete still means complete only under the declared sources.</p>
          ) : (
            <ul>
              {view.missing.map((gap) => (
                <li key={`${gap.kind}:${gap.record_id ?? ''}`}>
                  <strong>{gap.label}</strong>
                  {gap.availability && <span>{gap.availability}</span>}
                  <p>{gap.next_step}</p>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="trace-card trace-conflict-card" aria-labelledby="conflicting-evidence-heading">
          <h2 id="conflicting-evidence-heading">Conflicting evidence</h2>
          {view.conflicts.length === 0 ? (
            <p>No conflicting evidence is recorded for this trace.</p>
          ) : (
            <ul>
              {view.conflicts.map((conflict) => (
                <li key={`${conflict.kind}:${conflict.records.join(':')}`}>
                  <strong>{conflict.label}</strong>
                  <span>{plural(conflict.records.length, 'cited record')}</span>
                  <details>
                    <summary>Technical references</summary>
                    <span>Records</span>
                    <code>{conflict.records.join(', ')}</code>
                    <span>Evidence</span>
                    <code>{conflict.evidence_ids.length ? conflict.evidence_ids.join(', ') : 'No separate evidence reference'}</code>
                  </details>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section className="trace-safety-note" role="note">
        <strong>Display only.</strong> {view.safety_note}
      </section>

      <details className="trace-lifecycle">
        <summary>Trace lifecycle and technical scope</summary>
        <dl className="trace-facts">
          <div><dt>Data class</dt><dd>{view.lifecycle.data_class}</dd></div>
          <div><dt>Lifecycle</dt><dd>{view.lifecycle.state} · expires {formatUTC(view.lifecycle.expires_at)} UTC</dd></div>
          <div><dt>Legal hold</dt><dd>{view.lifecycle.legal_hold_ids.length ? view.lifecycle.legal_hold_ids.join(', ') : 'None'}</dd></div>
          <div><dt>Residency</dt><dd>{view.scope.residency_cell_id} · {view.lifecycle.residency_policy_ref}</dd></div>
          <div><dt>Encryption boundary</dt><dd>{view.lifecycle.encryption_boundary}</dd></div>
          <div><dt>Model use</dt><dd>Per-tenant {view.lifecycle.per_tenant_model_use ? 'allowed' : 'off'} · Cross-tenant {view.lifecycle.cross_tenant_model_use ? 'allowed' : 'off'}</dd></div>
          <div><dt>Trace ID</dt><dd><code>{view.trace_id}</code></dd></div>
          <div><dt>Deployment boundary</dt><dd>{view.scope.deployment_boundary}</dd></div>
        </dl>
      </details>

      <dialog ref={dialogRef} className="trace-evidence-dialog" aria-labelledby="evidence-dialog-title" onClose={restoreEvidenceFocus}>
        {selectedEvidence && (
          <div>
            <div className="trace-dialog-head">
              <div>
                <span className="trace-eyebrow">Evidence</span>
                <h2 id="evidence-dialog-title">Evidence details</h2>
              </div>
              <button type="button" className="trace-dialog-close" onClick={closeEvidence} aria-label="Close evidence details">×</button>
            </div>
            <p className="trace-claim">{selectedEvidence.summary}</p>
            <dl className="trace-facts">
              <div><dt>Availability</dt><dd>{selectedEvidence.availability}</dd></div>
              <div><dt>Ownership</dt><dd>{selectedEvidence.source_owned ? 'Source-owned reference' : 'CanaryView evidence reference'}</dd></div>
              {selectedEvidence.role && <div><dt>Claim role</dt><dd>{selectedEvidence.role}</dd></div>}
              <div><dt>Record</dt><dd>{selectedEvidence.label}</dd></div>
              <div><dt>Reference</dt><dd><code>{selectedEvidence.reference}</code></dd></div>
              <div><dt>Integrity</dt><dd>{selectedEvidence.hash_algorithm ? `${selectedEvidence.hash_algorithm}: ${selectedEvidence.hash_value}` : 'No digest supplied'}</dd></div>
              <div><dt>Raw evidence lifecycle</dt><dd>Source-owned; not represented by this trace projection</dd></div>
            </dl>
            <h3>Trace projection lifecycle</h3>
            <dl className="trace-facts">
              <div><dt>Expiry</dt><dd>{formatUTC(view.lifecycle.expires_at)} UTC</dd></div>
              <div><dt>Legal hold</dt><dd>{view.lifecycle.legal_hold_ids.length ? view.lifecycle.legal_hold_ids.join(', ') : 'None'}</dd></div>
              <div><dt>Residency</dt><dd>{view.scope.residency_cell_id}</dd></div>
              <div><dt>Model use</dt><dd>Per-tenant {view.lifecycle.per_tenant_model_use ? 'allowed' : 'off'} · Cross-tenant {view.lifecycle.cross_tenant_model_use ? 'allowed' : 'off'}</dd></div>
            </dl>
            <p className="trace-payload-note">No source payload is stored in this workspace.</p>
          </div>
        )}
      </dialog>
    </article>
  );
}
