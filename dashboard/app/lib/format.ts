// Number/string formatters matching the prototype's exact output
// (dashboard/design/prototype.html). Kept pure and dependency-free.

// fmtK: 38420 -> "38.4k", 999 -> "999". Mirrors the prototype's
// `fmtK = n => n >= 1000 ? (n/1000).toFixed(1)+'k' : ''+n`.
export function fmtK(n: number): string {
  n = Number.isFinite(n) ? n : 0;
  return n >= 1000 ? (n / 1000).toFixed(1) + 'k' : String(Math.floor(n));
}

// fmtTime: seconds -> "m:ss" (e.g. 252 -> "4:12"). Mirrors the prototype's
// `Math.floor(sec/60) + ':' + pad(sec%60)`.
export function fmtTime(sec: number): string {
  sec = Number.isFinite(sec) ? sec : 0;
  const s = Math.max(0, Math.floor(sec));
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, '0')}`;
}

// fmtTimeLong: seconds -> "4m 12s" (the intel-kpi legend form).
export function fmtTimeLong(sec: number): string {
  sec = Number.isFinite(sec) ? sec : 0;
  const s = Math.max(0, Math.floor(sec));
  return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}

// fmtBytes: bytes -> "11.6 MiB" / "4.2 KiB" / "512 B".
export function fmtBytes(bytes: number): string {
  bytes = Number.isFinite(bytes) ? bytes : 0;
  if (bytes >= 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MiB';
  if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KiB';
  return Math.floor(bytes) + ' B';
}

// fmtPct: 0.123 (a fraction in [0,1]) -> "12.3%". The backend already computes
// fractions (TierStep.fraction, attacker_cost_fraction), so this just scales.
export function fmtPct(fraction: number): string {
  fraction = Number.isFinite(fraction) ? fraction : 0;
  return (fraction * 100).toFixed(1) + '%';
}

// fmtInt: 1204 -> "1,204" (thousands separators, matches toLocaleString).
export function fmtInt(n: number): string {
  n = Number.isFinite(n) ? n : 0;
  return Math.round(n).toLocaleString('en-US');
}

// fmtOffsetLabel: the recon-feed timestamp. The backend already emits a ready
// offset_label ("−m:ss"); this is the fallback derivation from offset_sec
// (negative seconds in the past) used if a label is missing/empty.
export function fmtOffsetLabel(offsetSec: number): string {
  offsetSec = Number.isFinite(offsetSec) ? offsetSec : 0;
  const s = Math.max(0, Math.floor(-offsetSec));
  return `−${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

// fmtAgo: an RFC3339 timestamp -> a relative "Xs ago" / "Xm ago" / "Xh ago"
// ("just now" under 5s). nowMs is the "now" reference in epoch ms (pass the
// snapshot's `at` so the feed reads relative to the data, not the wall clock);
// falls back to Date.now(). Invalid/empty dates -> "" (the caller renders nothing).
export function fmtAgo(iso: string, nowMs?: number): string {
  if (!iso) return '';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return '';
  const now = Number.isFinite(nowMs as number) ? (nowMs as number) : Date.now();
  const sec = Math.max(0, Math.floor((now - t) / 1000));
  if (sec < 5) return 'just now';
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  return `${hr}h ago`;
}

// utcClock: "HH:MM:SS UTC" for the live topbar clock (matches the prototype).
export function utcClock(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}
