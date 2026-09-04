// Data access for the dashboard. Everything goes through /api/* which Next.js
// rewrites to the dashboard-backend (see next.config.ts). No host is hardcoded
// in client JS — dev and prod are identical.

import type { Overview } from './types';

export const OVERVIEW_URL = '/api/overview';
export const STREAM_URL = '/api/stream';

// fetchOverview pulls the current snapshot (GET /api/overview). Used on mount,
// before the SSE stream delivers its first frame.
export async function fetchOverview(): Promise<Overview> {
  const res = await fetch(OVERVIEW_URL, {
    cache: 'no-store',
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`overview: HTTP ${res.status}`);
  return res.json() as Promise<Overview>;
}

// ---- Interactive console drill-down endpoints ----
import type { FlowDetail, FlowsList, CostBreakdown, ReconTimeline, TopologyView, DeviantsView, TraceWorkspace } from './types';

// `since` is the Go-duration string the time pills produce ("1h","6h","24h").
// `session` (optional, Unix seconds of the session start) disambiguates a reused
// cookie's distinct sessions; omit to get the latest session.
export function flowDetailURL(cookie: string, since: string, session?: number): string {
  const s = session && session > 0 ? `&session=${session}` : '';
  return `/api/flow/${cookie}?since=${since}${s}`;
}
// flowsURL builds the /api/flows request. `minTier` (1..3, optional) selects the
// CUMULATIVE-reach cohort (rows that reached >= minTier) and, when set, takes
// precedence over the exact `tier` filter — matching the backend's two params.
export function flowsURL(tier: number, since: string, minTier?: number): string {
  if (minTier && minTier >= 1 && minTier <= 3) {
    return `/api/flows?since=${since}&min_tier=${minTier}`;
  }
  return `/api/flows?since=${since}${tier >= 0 ? `&tier=${tier}` : ''}`;
}
export function costURL(since: string): string {
  return `/api/cost?since=${since}`;
}
export function reconURL(since: string): string {
  return `/api/recon?since=${since}`;
}
// topologyURL is the learned east-west graph (F1). It is a CURRENT-state view (the
// aggregator's live in-memory topology map + canary decoy ring + recent touch
// edges), not windowed — so there is no `since`. The backend serves the tap's
// /raw/topology shape PLUS the pre-rendered honesty `caption`.
export function topologyURL(): string {
  return `/api/topology`;
}
// deviantsURL is the F2 deviant hunting log. Like topology it is a CURRENT-state
// view (the aggregator's live in-memory deviant log + resolved identities, ranked),
// not windowed — so there is no `since`. The backend serves the tap's /raw/deviants
// shape PLUS the pre-rendered honesty `caption` (and a ⚠ simulated note).
export function deviantsURL(): string {
  return `/api/deviants`;
}
export function traceWorkspaceURL(traceID: string): string {
  return `/api/traces/${encodeURIComponent(traceID)}`;
}

async function fetchJSON<T>(url: string, label: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(url, { cache: 'no-store', headers: { Accept: 'application/json' }, signal });
  if (!res.ok) throw new APIRequestError(label, res.status);
  try {
    return (await res.json()) as T;
  } catch (cause) {
    throw new MalformedResponseError(label, cause);
  }
}

export class APIRequestError extends Error {
  constructor(public readonly label: string, public readonly status: number) {
    super(`${label}: HTTP ${status}`);
    this.name = 'APIRequestError';
  }
}

export class MalformedResponseError extends Error {
  constructor(public readonly label: string, options?: unknown) {
    super(`${label}: response was malformed`, options instanceof Error ? { cause: options } : undefined);
    this.name = 'MalformedResponseError';
  }
}
export const fetchFlowDetail = (cookie: string, since: string, session?: number) =>
  fetchJSON<FlowDetail>(flowDetailURL(cookie, since, session), 'flow');
export const fetchFlows = (tier: number, since: string, minTier?: number) =>
  fetchJSON<FlowsList>(flowsURL(tier, since, minTier), 'flows');
export const fetchCost = (since: string) => fetchJSON<CostBreakdown>(costURL(since), 'cost');
export const fetchRecon = (since: string) => fetchJSON<ReconTimeline>(reconURL(since), 'recon');
export const fetchTopology = () => fetchJSON<TopologyView>(topologyURL(), 'topology');
export const fetchDeviants = () => fetchJSON<DeviantsView>(deviantsURL(), 'deviants');
export async function fetchTraceWorkspace(traceID: string, signal?: AbortSignal): Promise<TraceWorkspace> {
  const value = await fetchJSON<unknown>(traceWorkspaceURL(traceID), 'trace', signal);
  if (!isTraceWorkspace(value)) throw new MalformedResponseError('trace');
  return value;
}

type JSONRecord = Record<string, unknown>;

const record = (value: unknown): value is JSONRecord => typeof value === 'object' && value !== null && !Array.isArray(value);
const string = (value: unknown): value is string => typeof value === 'string';
const nonEmptyString = (value: unknown): value is string => string(value) && value.trim().length > 0;
const boolean = (value: unknown): value is boolean => typeof value === 'boolean';
const number = (value: unknown): value is number => typeof value === 'number' && Number.isFinite(value);
const optionalString = (value: unknown): boolean => value === undefined || string(value);
const strings = (value: unknown): value is string[] => Array.isArray(value) && value.every(string);
const oneOf = (value: unknown, allowed: readonly string[]): value is string => string(value) && allowed.includes(value);
const optionalAbsentOr = (value: unknown, validate: (candidate: unknown) => boolean): boolean => value === undefined || validate(value);

const rfc3339Pattern = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|([+-])(\d{2}):(\d{2}))$/;
const durationPattern = /^(?:\d+(?:\.\d+)?(?:ns|µs|us|ms|s|m|h))+$/;
const sha256Pattern = /^[0-9a-f]{64}$/;
const correlationKeyPattern = /^correlation-key:sha256:[0-9a-f]{64}$/;

function rfc3339(value: unknown): value is string {
  if (!string(value)) return false;
  const match = rfc3339Pattern.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const offsetHour = match[8] === undefined ? 0 : Number(match[8]);
  const offsetMinute = match[9] === undefined ? 0 : Number(match[9]);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1] &&
    hour <= 23 && minute <= 59 && second <= 59 && offsetHour <= 23 && offsetMinute <= 59 &&
    Number.isFinite(Date.parse(value));
}

function positiveDuration(value: unknown): value is string {
  if (!duration(value)) return false;
  const components = [...value.matchAll(/(\d+(?:\.\d+)?)(?:ns|µs|us|ms|s|m|h)/g)].map((match) => Number(match[1]));
  return components.some((component) => component > 0);
}

function duration(value: unknown): value is string {
  if (!string(value) || !durationPattern.test(value)) return false;
  const components = [...value.matchAll(/(\d+(?:\.\d+)?)(?:ns|µs|us|ms|s|m|h)/g)].map((match) => Number(match[1]));
  return components.length > 0 && components.every(Number.isFinite);
}

function timeFields(at: unknown, status: unknown, uncertainty: unknown, window: unknown): boolean {
  if (at === undefined) {
    return status === 'Source time missing' && uncertainty === 'Unknown' && window === undefined;
  }
  if (!rfc3339(at)) return false;
  if (uncertainty === 'Exact') return status === 'Exact source time' && window === undefined;
  if (uncertainty === 'Bounded') return status === 'Bounded source time' && positiveDuration(window);
  return false;
}

function aggregateTimeFields(uncertainty: unknown, window: unknown): boolean {
  return uncertainty === 'Bounded'
    ? positiveDuration(window)
    : oneOf(uncertainty, ['Exact', 'Unknown']) && window === undefined;
}

function joinTiming(method: unknown, gap: unknown, window: unknown): boolean {
  const timeQualified = oneOf(method, ['Verified identity', 'Declared identity and time window', 'Translated tuple and time window', 'Network tuple and time window']);
  return timeQualified ? duration(gap) && positiveDuration(window) : gap === undefined && window === undefined;
}

function translationPath(method: unknown, value: unknown): boolean {
  if (!Array.isArray(value) || !value.every((step) => record(step) && traceReference(step.record) && oneOf(step.direction, ['Forward', 'Reverse']))) return false;
  return method === 'Translated tuple and time window' ? value.length > 0 : value.length === 0;
}

function identity(value: unknown): boolean {
  return record(value) && nonEmptyString(value.id) && nonEmptyString(value.kind) && nonEmptyString(value.name) &&
    oneOf(value.assertion_mode, ['Observed', 'Declared', 'Verified', 'Inferred']) && boolean(value.verified) &&
    value.verified === (value.assertion_mode === 'Verified');
}

function traceReference(value: unknown): boolean {
  return record(value) && nonEmptyString(value.id) && number(value.schema_version) &&
    Number.isInteger(value.schema_version) && value.schema_version > 0;
}

function traceReferenceIdentity(value: unknown): string {
  return record(value) ? JSON.stringify([String(value.id), String(value.schema_version)]) : '';
}

function distinctTraceReferences(value: unknown, minimum = 0): boolean {
  if (!Array.isArray(value) || value.length < minimum || !value.every(traceReference)) return false;
  return new Set(value.map(traceReferenceIdentity)).size === value.length;
}

function joinIdentity(value: unknown): string {
  if (!record(value)) return '';
  const path = Array.isArray(value.translation_path)
    ? value.translation_path.map((step) => record(step) ? [traceReferenceIdentity(step.record), String(step.direction)] : [])
    : [];
  return JSON.stringify([
    traceReferenceIdentity(value.anchor), traceReferenceIdentity(value.candidate), value.method, value.strength,
    value.key_fingerprint, value.time_gap ?? 'not-used', value.window ?? 'not-used', path,
  ]);
}

function conflictIdentity(value: unknown): string {
  if (!record(value)) return '';
  const records = Array.isArray(value.records) ? value.records.map(traceReferenceIdentity).sort() : [];
  const evidence = Array.isArray(value.evidence) ? value.evidence.map(traceReferenceIdentity).sort() : [];
  return JSON.stringify([value.kind, records, evidence]);
}

function evidenceReference(value: unknown): boolean {
  if (!record(value) || !nonEmptyString(value.id) || !nonEmptyString(value.label) || !nonEmptyString(value.summary) ||
      !optionalAbsentOr(value.schema_version, (candidate) => number(candidate) && Number.isInteger(candidate) && candidate > 0) ||
      !optionalAbsentOr(value.hop_record, traceReference) || !boolean(value.raw) || !boolean(value.source_owned) ||
      !nonEmptyString(value.reference) || !nonEmptyString(value.availability) ||
      !optionalString(value.hash_algorithm) || !optionalString(value.hash_value)) return false;

  if (value.raw) {
    const digest = value.reference.replace('rawref:sha256:', '');
    const hashesAbsent = value.hash_algorithm === undefined && value.hash_value === undefined;
    const hashesValid = value.hash_algorithm === 'sha256' && string(value.hash_value) && sha256Pattern.test(value.hash_value);
    return value.source_owned && value.role === undefined && value.schema_version === undefined && traceReference(value.hop_record) &&
      value.id === value.reference && value.reference.startsWith('rawref:sha256:') && sha256Pattern.test(digest) &&
      oneOf(value.availability, ['Available', 'Expired', 'Deleted', 'Access denied', 'Moved', 'Integrity mismatch']) &&
      (hashesAbsent || hashesValid);
  }

  return !value.source_owned && number(value.schema_version) && Number.isInteger(value.schema_version) && value.schema_version > 0 &&
    oneOf(value.role, ['Supporting', 'Contradicting', 'Vendor extension']) &&
    value.id === value.reference && value.availability === 'Reference only' &&
    value.hash_algorithm === undefined && value.hash_value === undefined;
}

function isTraceWorkspace(value: unknown): value is TraceWorkspace {
  if (!record(value) || !record(value.status) || !record(value.confidence) || !record(value.scope) ||
      !record(value.explanation) || !record(value.lifecycle)) return false;
  const status = value.status;
  const confidence = value.confidence;
  const scope = value.scope;
  const explanation = value.explanation;
  const lifecycle = value.lifecycle;
  const statusLabels: Record<string, string> = {
    PARTIAL: 'Partial',
    COMPLETE_UNDER_DECLARED_COVERAGE: 'Complete under declared coverage',
    CONFLICTED: 'Conflicted',
  };
  return nonEmptyString(value.trace_id) && nonEmptyString(value.title) && nonEmptyString(value.summary) && nonEmptyString(value.what_happened) &&
    oneOf(status.code, Object.keys(statusLabels)) && status.label === statusLabels[status.code] && nonEmptyString(status.detail) &&
    oneOf(confidence.level, ['Low', 'Medium', 'High']) &&
    oneOf(confidence.method, ['Direct source', 'Exact identifier', 'Verified identity', 'Declared mapping', 'Tuple time window', 'Composite correlation', 'Probabilistic inference', 'Model interpretation']) &&
    oneOf(confidence.completeness, ['Partial', 'Complete']) &&
    oneOf(confidence.source_quality, ['Unverified', 'Declared', 'Verified']) &&
    oneOf(confidence.identity_assurance, ['Unverified', 'Declared', 'Verified']) &&
    number(confidence.candidate_count) && Number.isInteger(confidence.candidate_count) && confidence.candidate_count > 0 &&
    aggregateTimeFields(confidence.time_uncertainty, confidence.time_window) &&
    oneOf(confidence.human_review, ['Unreviewed', 'Confirmed', 'Rejected']) &&
    nonEmptyString(scope.tenant_id) && nonEmptyString(scope.scope_id) && nonEmptyString(scope.display_name) &&
    nonEmptyString(scope.deployment_boundary) && nonEmptyString(scope.residency_cell_id) &&
    Array.isArray(value.affected) && value.affected.every(identity) &&
    Array.isArray(value.hops) && value.hops.every((hop) => record(hop) && traceReference(hop.record) &&
      oneOf(hop.kind, ['Observation', 'Policy decision']) && nonEmptyString(hop.label) &&
      timeFields(hop.at, hop.time_status, hop.time_uncertainty, hop.time_window) &&
      Array.isArray(hop.identities) && hop.identities.every(identity) &&
      number(hop.evidence_count) && Number.isInteger(hop.evidence_count) && hop.evidence_count >= 0) &&
    nonEmptyString(explanation.claim) && nonEmptyString(explanation.reason) && strings(explanation.methods) && explanation.methods.every(nonEmptyString) &&
    Array.isArray(explanation.joins) && explanation.joins.every((join) => record(join) && traceReference(join.anchor) &&
      traceReference(join.candidate) && oneOf(join.method, ['Request ID', 'Vendor transaction ID', 'Socket cookie', 'OpenTelemetry trace and span ID', 'OpenTelemetry trace ID', 'Verified identity', 'Declared identity and time window', 'Translated tuple and time window', 'Network tuple and time window']) &&
      oneOf(join.strength, ['Exact', 'Strong', 'Weak']) && string(join.key_fingerprint) && correlationKeyPattern.test(join.key_fingerprint) && joinTiming(join.method, join.time_gap, join.window) &&
      translationPath(join.method, join.translation_path) &&
      Array.isArray(join.citations) && join.citations.length > 0 && join.citations.every(traceReference) &&
      boolean(join.selected) && boolean(join.ambiguous)) &&
    new Set(explanation.joins.map(joinIdentity)).size === explanation.joins.length &&
    Array.isArray(value.missing) && value.missing.every((gap) => record(gap) &&
      oneOf(gap.kind, ['OBSERVATION', 'POLICY_DECISION', 'SOURCE_TIME', 'RAW_EVIDENCE', 'CORRELATION']) && nonEmptyString(gap.label) &&
      optionalAbsentOr(gap.record, traceReference) && optionalAbsentOr(gap.availability, (candidate) => oneOf(candidate, ['Available', 'Expired', 'Deleted', 'Access denied', 'Moved', 'Integrity mismatch'])) && nonEmptyString(gap.next_step)) &&
    Array.isArray(value.conflicts) && value.conflicts.every((conflict) => record(conflict) &&
      oneOf(conflict.kind, ['AMBIGUOUS_CORRELATION', 'CONTRADICTORY_EVIDENCE', 'ORDERING_UNCERTAINTY']) &&
      nonEmptyString(conflict.label) && distinctTraceReferences(conflict.records, 2) && Array.isArray(conflict.evidence) && distinctTraceReferences(conflict.evidence) &&
      (conflict.kind !== 'CONTRADICTORY_EVIDENCE' || conflict.evidence.length > 0)) &&
    new Set(value.conflicts.map(conflictIdentity)).size === value.conflicts.length &&
    Array.isArray(value.evidence) && value.evidence.every(evidenceReference) &&
    lifecycle.data_class === 'Correlated trace' && lifecycle.sensitivity === 'Confidential' &&
    oneOf(lifecycle.retention_profile, ['Lean', 'Standard', 'Regulated', 'Approved override']) &&
    oneOf(lifecycle.state, ['Active', 'Expiry due', 'Held', 'Deletion pending', 'Deleted', 'Invalidated', 'Deletion failed']) &&
    rfc3339(lifecycle.expires_at) && strings(lifecycle.legal_hold_ids) && lifecycle.legal_hold_ids.every(nonEmptyString) &&
    new Set(lifecycle.legal_hold_ids).size === lifecycle.legal_hold_ids.length &&
    ((lifecycle.state === 'Held') === (lifecycle.legal_hold_ids.length > 0)) &&
    nonEmptyString(lifecycle.residency_policy_ref) && nonEmptyString(lifecycle.encryption_boundary) &&
    boolean(lifecycle.per_tenant_model_use) && boolean(lifecycle.cross_tenant_model_use) &&
    boolean(value.synthetic) && optionalAbsentOr(value.scenario_id, nonEmptyString) && nonEmptyString(value.safety_note) &&
    (value.synthetic ? nonEmptyString(value.scenario_id) : value.scenario_id === undefined) &&
    (confidence.completeness === (value.missing.length === 0 ? 'Complete' : 'Partial')) &&
    (status.code === (value.conflicts.length > 0 ? 'CONFLICTED' : value.missing.length > 0 ? 'PARTIAL' : 'COMPLETE_UNDER_DECLARED_COVERAGE'));
}
