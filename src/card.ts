// The verdict card as a Google SecOps predefined widget: the rules and the markup, no DOM.
// build.mjs strips the types and inlines this file into template.html, so the widget ships as
// one HTML file, the way every widget in Google's content hub does
// (github.com/chronicle/content-hub, content/response_integrations/google/wiz/widgets/).
//
// It reads the result of Wiz's "Get Blue Agent Analysis" action exactly as it arrives today, and
// it says more as the result carries more. Every field it adds to that result is optional:
//
//   aiAnalysis.dataCutoffAt          the newest event the agent used              added by the agent
//   aiAnalysis.sourcesRead[]         what the agent read                          added by the agent
//   aiAnalysis.sourcesNotRead[]      what it could not read                       added by the agent
//   aiAnalysis.claims[]              what it concluded from, and where to check   added by the agent
//   aiAnalysis.missingEvidence       what it could not see, in its own words      added by the agent
//   aiAnalysis.revisedFrom           the verdict this one replaces, why, and the  added by the integration,
//                                    analyst's decision in between                which keeps the prior one
//   aiAnalysis.url                   the analysis in Wiz                          added by the agent
//   caseContext.fetchedAt            when the playbook added it to the case       added by the action
//   caseContext.checkedAt            when the integration last checked the case   added by the action
//   caseContext.coveredAlerts[]      the alerts in this case the verdict is about added by the action
//   caseContext.casePriority         this console's own rating of the case        added by the action
//   caseContext.alertsAfterCutoff[]  alerts whose events came after the cut-off   added by the action
//                                    (their event time, not when they joined)
//
// A widget can display; it cannot change the case. So there is no button here that decides
// anything: accept, override and undo are the integration's own actions, run from the host's
// Quick Actions widget, and their record is the Case Wall. Links out are the only controls.

export type Verdict = 'Malicious' | 'Suspicious' | 'Benign' | 'Unknown';
export type Level = 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';

export interface Where {
  kind: 'alert' | 'entity' | 'source';
  label: string;
  url: string | null;
}

export interface Claim {
  text: string;
  where: Where | null;
}

export interface LaterAlert {
  id: string;
  name: string;
  at: number;
}

export interface Decision {
  kind: 'accepted' | 'overridden';
  verdict: Verdict;
  at: number | null;
}

export interface Revision {
  verdict: Verdict;
  analysedAt: number | null;
  conclusion: string;
  reason: string;
  decision: Decision | null;
}

export interface CardModel {
  verdict: Verdict;
  confidence: Level | null;
  severity: Level | null;
  analysedAt: number | null;
  dataTo: number | null;
  fetchedAt: number | null;
  checkedAt: number | null;
  covered: string[] | null;
  sourcesRead: string[] | null;
  sourcesNotRead: string[] | null;
  casePriority: Level | null;
  laterAlerts: LaterAlert[] | null;
  conclusion: string;
  claims: Claim[] | null;
  missing: string | null;
  revision: Revision | null;
  analysisId: string;
  url: string | null;
}

export interface Names {
  agent: string;
  source: string;
}

// ---------------------------------------------------------------- reading the result

type Obj = Record<string, unknown>;

function isObj(x: unknown): x is Obj {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

function dig(o: unknown, ...keys: string[]): unknown {
  let cur: unknown = o;
  for (const k of keys) {
    if (!isObj(cur)) return undefined;
    cur = cur[k];
  }
  return cur;
}

function text(x: unknown): string {
  if (typeof x === 'string') return x.trim();
  if (typeof x === 'number' && Number.isFinite(x)) return String(x);
  return '';
}

function time(x: unknown): number | null {
  const s = text(x);
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}

function level(x: unknown): Level | null {
  switch (text(x).toLowerCase()) {
    case 'informational':
    case 'informative':
    case 'info':
      return 'Informational';
    case 'low':
      return 'Low';
    case 'medium':
      return 'Medium';
    case 'high':
      return 'High';
    case 'critical':
      return 'Critical';
    default:
      return null;
  }
}

function verdictOf(x: unknown): Verdict {
  switch (text(x).toLowerCase()) {
    case 'malicious':
      return 'Malicious';
    case 'suspicious':
      return 'Suspicious';
    case 'benign':
      return 'Benign';
    default:
      return 'Unknown';
  }
}

// Only https links leave the widget. Anything else in a url field is dropped, not rendered.
export function safeUrl(x: unknown): string | null {
  const s = text(x);
  return /^https:\/\/[^\s"'<>]+$/i.test(s) ? s : null;
}

// The same paths Google's widget accepts, so the card reads any shape that one reads.
export function findAnalysis(result: unknown): { analysis: Obj; context: Obj } | null {
  const first = Array.isArray(result) ? result[0] : result;
  if (!isObj(first)) return null;
  const candidates = [
    dig(first, 'data', 'issue', 'threatDetectionDetails', 'aiAnalysis'),
    dig(first, 'issue', 'threatDetectionDetails', 'aiAnalysis'),
    dig(first, 'threatDetectionDetails', 'aiAnalysis'),
    dig(first, 'aiAnalysis'),
  ];
  const nested = candidates.find(isObj);
  const analysis = nested ?? ('verdict' in first ? first : undefined);
  if (!isObj(analysis)) return null;
  const context = isObj(first.caseContext) ? first.caseContext : {};
  return { analysis, context };
}

function readWhere(x: unknown): Where | null {
  if (!isObj(x)) return null;
  const kind = text(x.kind).toLowerCase();
  const label = text(x.label);
  if (!label || (kind !== 'alert' && kind !== 'entity' && kind !== 'source')) return null;
  return { kind: kind as Where['kind'], label, url: safeUrl(x.url) };
}

function readClaim(x: unknown): Claim | null {
  if (!isObj(x)) return null;
  const t = text(x.text);
  return t ? { text: t, where: readWhere(x.where) } : null;
}

function strings(x: unknown): string[] | null {
  return Array.isArray(x) ? x.map(text).filter(Boolean) : null;
}

function readDecision(x: unknown): Decision | null {
  if (!isObj(x)) return null;
  const kind = text(x.kind).toLowerCase();
  if (kind !== 'accepted' && kind !== 'overridden') return null;
  return { kind, verdict: verdictOf(x.verdict), at: time(x.at) };
}

function readLater(x: unknown): LaterAlert | null {
  if (!isObj(x)) return null;
  const id = text(x.id);
  const at = time(x.at);
  return id && at !== null ? { id, name: text(x.name), at } : null;
}

export function readCard(result: unknown): CardModel | null {
  const found = findAnalysis(result);
  if (!found) return null;
  const a = found.analysis;
  const c = found.context;
  const claims = Array.isArray(a.claims) ? a.claims.map(readClaim).filter((x): x is Claim => x !== null) : null;
  const later = Array.isArray(c.alertsAfterCutoff)
    ? c.alertsAfterCutoff.map(readLater).filter((x): x is LaterAlert => x !== null).sort((x, y) => x.at - y.at)
    : null;
  const r = a.revisedFrom;
  return {
    verdict: verdictOf(a.verdict),
    confidence: level(a.confidenceLevel),
    severity: level(a.severity),
    analysedAt: time(a.analyzedAt),
    dataTo: time(a.dataCutoffAt),
    fetchedAt: time(c.fetchedAt),
    checkedAt: time(c.checkedAt),
    covered: Array.isArray(c.coveredAlerts)
      ? c.coveredAlerts.map((x) => (isObj(x) ? text(x.id) : text(x))).filter(Boolean)
      : null,
    sourcesRead: strings(a.sourcesRead),
    sourcesNotRead: strings(a.sourcesNotRead),
    casePriority: level(c.casePriority),
    laterAlerts: later,
    conclusion: text(a.conclusion),
    claims,
    missing: text(a.missingEvidence) || null,
    revision: isObj(r)
      ? { verdict: verdictOf(r.verdict), analysedAt: time(r.analyzedAt), conclusion: text(r.conclusion), reason: text(r.reason), decision: readDecision(r.decision) }
      : null,
    analysisId: text(a.id),
    url: safeUrl(a.url),
  };
}

// ---------------------------------------------------------------- the rules

// Low confidence withdraws the recommendation, and so does a claim the agent says it could not make.
export function isLowConfidence(m: CardModel): boolean {
  return m.confidence === 'Low' || m.missing !== null;
}

// What the verdict can be checked against: the agent's own data cut-off when it says one,
// otherwise the moment it ran, since no data it used can be newer than that.
export function cutoffOf(m: CardModel): number | null {
  return m.dataTo ?? m.analysedAt;
}

// null means nobody checked; an empty list means somebody checked and nothing came later.
export function alertsAfter(m: CardModel): LaterAlert[] | null {
  const cutoff = cutoffOf(m);
  if (m.laterAlerts === null || cutoff === null) return null;
  return m.laterAlerts.filter((x) => x.at > cutoff);
}

// ---------------------------------------------------------------- words for times

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n: number): string => String(n).padStart(2, '0');

export function clock(ms: number, now: number): string {
  const d = new Date(ms);
  const n = new Date(now);
  const hm = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
  const sameDay =
    d.getUTCFullYear() === n.getUTCFullYear() && d.getUTCMonth() === n.getUTCMonth() && d.getUTCDate() === n.getUTCDate();
  if (sameDay) return `${hm} UTC`;
  const day = `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`;
  return d.getUTCFullYear() === n.getUTCFullYear() ? `${day}, ${hm} UTC` : `${day} ${d.getUTCFullYear()}, ${hm} UTC`;
}

// A span of time in the fewest honest words, rounded down so the card never makes a verdict sound
// older than it is: "under 1 min", "43 min", "1 hr 5 min", "47 hr", "49 days".
export function span(ms: number): string {
  const min = Math.floor(Math.abs(ms) / 60_000);
  if (min < 1) return 'under 1 min';
  if (min < 60) return `${min} min`;
  const h = Math.floor(min / 60);
  if (h < 24) return min % 60 ? `${h} hr ${min % 60} min` : `${h} hr`;
  if (h < 48) return `${h} hr`;
  return `${Math.floor(h / 24)} days`;
}

// ---------------------------------------------------------------- markup

const ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => ESCAPES[ch] ?? ch);
}

// A space that never breaks, so "alert A3" is never split across two lines.
const NB = ' ';

function linkOut(url: string, label: string): string {
  return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(label)}<span aria-hidden="true"> ↗</span><span class="sr"> (opens in a new tab)</span></a>`;
}

function muted(html: string): string {
  return `<span class="m">${html}</span>`;
}

function list(items: string[]): string {
  return items.map(esc).join(', ');
}

// Whether the verdict still stands. Unchecked is not the same as current: "nothing newer" is only
// said when something looked.
type Standing =
  | { kind: 'outdated'; first: LaterAlert; more: number; cutoff: number }
  | { kind: 'current' }
  | { kind: 'unchecked'; why: 'no-check' | 'no-time' };

function standingOf(m: CardModel): Standing {
  const later = alertsAfter(m);
  const cutoff = cutoffOf(m);
  if (later === null || cutoff === null) return { kind: 'unchecked', why: m.laterAlerts === null ? 'no-check' : 'no-time' };
  return later.length ? { kind: 'outdated', first: later[0], more: later.length - 1, cutoff } : { kind: 'current' };
}

// Line 1 reads in one order in every state: the verdict, how sure the agent was, whether it still
// stands. An all-clear is green only while a check says it stands and the agent is sure of it; a
// warning keeps its colour whatever its state. A stale green invites closing a case that has moved
// on, while a stale red at worst prompts one more look.
function renderLine1(m: CardModel, s: Standing, low: boolean): string {
  const outdated = s.kind === 'outdated';
  const stale = m.verdict === 'Benign' && (s.kind !== 'current' || low);
  const weak = m.confidence === null || m.confidence === 'Low';
  const state =
    s.kind === 'outdated'
      ? `<span class="state state-outdated">Outdated by alert${NB}${esc(s.first.id)}</span>`
      : s.kind === 'current'
        ? '<span class="state state-current">No newer alerts</span>'
        : `<span class="state">${s.why === 'no-check' ? 'Newer alerts not checked' : 'Can’t check for newer alerts'}</span>`;
  return `<p class="verdict v-${m.verdict.toLowerCase()}"><span class="word${stale ? ' stale' : ''}">${m.verdict}</span><span class="sr">, </span><span class="conf${outdated ? ' quiet' : ''}${weak ? ' weak' : ''}">${m.confidence ? `${m.confidence} confidence` : 'Confidence not given'}<span class="sep" aria-hidden="true">·</span></span><span class="sr">. </span>${state}</p>`;
}

// The facts the verdict rests on, one labelled row each. Whatever the result leaves out is said
// plainly, rather than drawn as if it were known. Parts marked data-tick change with the clock.
function renderRows(m: CardModel, s: Standing, now: number, names: Names): string {
  const read = clock(now, now);
  let when = 'The agent didn’t say when it made this verdict.';
  if (m.analysedAt !== null) {
    const made = clock(m.analysedAt, now);
    // Never a negative age: an agent's clock can run ahead of the analyst's.
    const age = `<b data-tick>${span(Math.max(0, now - m.analysedAt))} old</b>`;
    when = made === read ? `${made} · ${age}` : `${made} · ${age}<span class="m" data-tick> at ${read}</span>`;
  }

  const readList = m.sourcesRead && m.sourcesRead.length ? list(m.sourcesRead) : null;
  const notRead = m.sourcesNotRead && m.sourcesNotRead.length ? list(m.sourcesNotRead) : null;
  const alerts = m.covered && m.covered.length ? `alert${m.covered.length === 1 ? '' : 's'}${NB}${list(m.covered)}` : '';
  const used =
    (m.dataTo === null && readList === null
      ? muted(`${alerts ? `About ${alerts}. ` : ''}The agent didn’t say what data it used, or up to when.`)
      : [
          m.dataTo !== null ? `data up to ${clock(m.dataTo, now)}` : muted('didn’t say up to when'),
          muted(readList ?? 'didn’t say what it read'),
          alerts ? muted(`about ${alerts}`) : '',
        ]
          .filter(Boolean)
          .join(muted(' · '))) + (notRead ? `<br>${muted('Not read:')} ${notRead}` : '');

  let since: string;
  if (s.kind === 'outdated') {
    const after = m.dataTo !== null ? 'after the newest data the agent used' : 'after the agent made this verdict';
    const more = s.more ? ` ${s.more} more alert${s.more === 1 ? '' : 's'} came after it.` : '';
    const checked = m.checkedAt !== null ? ` ${muted(`Case last checked ${clock(m.checkedAt, now)}.`)}` : '';
    const name = s.first.name ? `<p class="alert-name">Alert${NB}${esc(s.first.id)}: ${esc(s.first.name)}</p>` : '';
    since = `<div class="outdated" role="status"><p>Alert${NB}${esc(s.first.id)} happened at ${clock(s.first.at, now)}, ${span(s.first.at - s.cutoff)} ${after}. The agent hasn’t seen it.${more}${checked}</p>${name}</div>`;
  } else if (s.kind === 'current') {
    // A quiet state is only as good as its check, so the check time is never muted.
    const checked = m.checkedAt !== null;
    since = `${muted(`No newer alerts since ${m.dataTo !== null ? 'its data' : 'it was made'}${checked ? ' · case last checked' : ''}`)}${checked ? ` ${clock(m.checkedAt ?? now, now)}` : ''}`;
  } else {
    since = s.why === 'no-check'
      ? 'Can’t tell if newer alerts arrived: nothing has checked the case.'
      : 'Can’t tell if newer alerts arrived: the agent didn’t say when it made this verdict or what data it used.';
  }

  // Two ratings, each with its owner, and whether they agree. The card claims to change neither.
  const ratings: string[] = [];
  if (m.severity) ratings.push(`${muted(`${esc(names.source)}:`)} <span class="v">${m.severity}</span> ${muted('severity')}`);
  if (m.casePriority) ratings.push(`${muted(m.severity ? 'this console:' : 'This console:')} <span class="v">${m.casePriority}</span> ${muted('case priority')}`);
  if (m.severity && m.casePriority) ratings.push(muted(m.severity === m.casePriority ? 'they agree' : 'they differ'));
  const rating = ratings.join(muted(' · '));

  return `<dl class="rows"><dt>When</dt><dd>${when}</dd><dt>Used</dt><dd>${used}</dd><dt>Since</dt><dd>${since}</dd>${rating ? `<dt>Rating</dt><dd>${rating}</dd>` : ''}</dl>`;
}

function whereText(w: Where | null): string {
  if (!w) return '<span class="where">Where to check it: not given</span>';
  if (w.kind === 'alert') return `<span class="where">Check in this case: alert${NB}${esc(w.label)}</span>`;
  if (w.kind === 'entity') return `<span class="where">Check in this case: ${esc(w.label)}</span>`;
  return `<span class="where">${w.url ? linkOut(w.url, `Only in ${w.label}`) : `Only in ${esc(w.label)}`}</span>`;
}

function renderClaims(m: CardModel, names: Names): string {
  if (m.claims === null) return '<p class="m">The agent didn’t list the claims behind this verdict.</p>';
  if (m.claims.length === 0) return '<p class="m">The agent listed no claims.</p>';
  const inCase = m.claims.filter((c) => c.where && c.where.kind !== 'source').length;
  const outside = m.claims.filter((c) => c.where?.kind === 'source').length;
  const count = `${m.claims.length} · ${inCase} checkable in this case${outside ? ` · ${outside} only in ${esc(names.source)}` : ''}`;
  const items = m.claims.map((c) => `<li><span class="claim">${esc(c.text)}</span>${whereText(c.where)}</li>`).join('');
  return `<h3>The agent’s claims <span class="count">${count}</span></h3><ol class="claims">${items}</ol>`;
}

export function renderCard(m: CardModel, now: number, names: Names): string {
  const low = isLowConfidence(m);
  const s = standingOf(m);
  const rev = m.revision;
  const d = rev?.decision ?? null;
  const decided = d
    ? `; you ${d.kind === 'accepted' ? `accepted ${d.verdict}` : `overrode it to ${d.verdict}`}${d.at !== null ? ` at ${clock(d.at, now)}` : ''}`
    : '';
  const revised = rev
    ? `<p class="note revised"><b>Revised.</b> It said ${rev.verdict}${rev.analysedAt !== null ? ` at ${clock(rev.analysedAt, now)}` : ''}${decided}.${rev.reason ? ` ${muted(esc(rev.reason))}` : ''}</p>`
    : '';
  const why =
    m.confidence === 'Low'
      ? `The agent’s confidence is Low.${m.missing ? ` It reports: ${esc(m.missing)}` : ''}`
      : `The agent reports a gap: ${esc(m.missing ?? '')}`;
  const withheld = low ? `<p class="note withheld"><b>No recommendation.</b> ${why}</p>` : '';
  const earlier =
    rev && rev.conclusion
      ? `<details class="earlier"><summary>Before the revision it concluded</summary><p>${esc(rev.conclusion)}</p></details>`
      : '';
  const foot = [
    m.fetchedAt !== null ? `Added to this case ${clock(m.fetchedAt, now)}` : '',
    m.analysisId ? `Analysis <span class="mono">${esc(m.analysisId.slice(0, 8))}</span>` : '',
    m.url ? linkOut(m.url, `Open in ${names.source}`) : '',
  ]
    .filter(Boolean)
    .join(' · ');
  return `<p class="eyebrow">AI verdict from ${esc(names.agent)}</p>
${renderLine1(m, s, low)}${withheld}${revised}
${renderRows(m, s, now, names)}
<section class="body" aria-label="The agent’s account"><h3>The agent’s reasoning</h3><p class="conclusion">${m.conclusion ? esc(m.conclusion) : 'No conclusion in the result.'}</p>${earlier}
${renderClaims(m, names)}
${foot ? `<p class="foot">${foot}</p>` : ''}</section>`;
}

export function renderEmpty(names: Names): string {
  return `<p class="m">No ${esc(names.agent)} analysis in this result.</p>`;
}
