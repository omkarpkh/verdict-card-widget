// Tests for the verdict card widget: what it reads, what it decides, and what it will not draw.
// Node runs the TypeScript directly, so there is nothing to install.
//   node --test tests.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { alertsAfter, clock, cutoffOf, esc, isLowConfidence, readCard, renderCard, safeUrl, span } from './src/card.ts';

const here = dirname(fileURLToPath(import.meta.url));
const json = (p) => JSON.parse(readFileSync(join(here, p), 'utf8'));
const NAMES = { agent: 'Wiz Blue Agent', source: 'Wiz' };
const CLOCK = Date.parse(json('examples/clock.json').now);
const MIN = 60_000;
const example = (name) => readCard(json(`examples/${name}.json`));

test('reads Google’s own example result as it ships, with nothing added', () => {
  const m = readCard(json('third_party/google-content-hub/get_blue_agent_analysis_JsonResult_example.json'));
  assert.ok(m);
  assert.equal(m.verdict, 'Malicious');
  assert.equal(m.confidence, 'High');
  assert.equal(m.severity, 'Critical');
  assert.equal(m.analysedAt, Date.parse('2026-06-09T16:12:58.253716Z'));
  assert.equal(m.dataTo, null, 'today’s result has no data cut-off');
  assert.equal(m.claims, null, 'today’s result has no claims');
  assert.equal(m.laterAlerts, null, 'nothing has checked the case');
});

test('accepts every shape Google’s widget accepts', () => {
  const a = { verdict: 'BENIGN', analyzedAt: '2026-09-17T13:16:00Z', confidenceLevel: 'LOW' };
  for (const shape of [
    { data: { issue: { threatDetectionDetails: { aiAnalysis: a } } } },
    { issue: { threatDetectionDetails: { aiAnalysis: a } } },
    { threatDetectionDetails: { aiAnalysis: a } },
    { aiAnalysis: a },
    a,
    [{ aiAnalysis: a }],
  ]) {
    const m = readCard(shape);
    assert.equal(m?.verdict, 'Benign');
    assert.equal(m?.confidence, 'Low');
  }
});

test('returns nothing for a result it cannot read', () => {
  for (const junk of [null, undefined, 'text', 42, [], {}, { data: {} }]) assert.equal(readCard(junk), null);
});

test('age is plain arithmetic, rounded down: the launch screenshot’s two times are 49 days apart', () => {
  const analysed = Date.parse('2026-07-27T15:53:10.655319Z');
  const fetched = Date.parse('2026-09-14T19:00:34Z');
  assert.equal(span(fetched - analysed), '49 days');
  assert.equal(span(43 * MIN), '43 min');
  assert.equal(span(59 * MIN + 59_000), '59 min');
  assert.equal(span(65 * MIN), '1 hr 5 min');
  assert.equal(span(47 * 60 * MIN + 30 * MIN), '47 hr');
  assert.equal(span(30_000), 'under 1 min');
});

test('times are UTC, with the date only when it is not today', () => {
  const now = Date.parse('2026-09-17T14:10:00Z');
  assert.equal(clock(Date.parse('2026-09-17T13:16:00Z'), now), '13:16 UTC');
  assert.equal(clock(Date.parse('2026-06-09T16:12:58Z'), now), '9 Jun, 16:12 UTC');
  assert.equal(clock(Date.parse('2025-12-31T23:05:00Z'), now), '31 Dec 2025, 23:05 UTC');
});

test('outdated means an alert joined after the cut-off; unchecked is not the same as fresh', () => {
  const moved = example('cs-4133-moved-on');
  assert.equal(cutoffOf(moved), Date.parse('2026-09-17T13:14:00Z'));
  assert.deepEqual(alertsAfter(moved).map((a) => a.id), ['A3']);
  assert.equal(alertsAfter(example('cs-4127-fresh')).length, 0);
  assert.equal(alertsAfter(example('cs-4133-today')), null, 'no case context means nobody checked');
});

test('without a data cut-off, the check falls back to when the agent ran', () => {
  const m = readCard({
    aiAnalysis: { verdict: 'BENIGN', analyzedAt: '2026-09-17T13:16:00Z' },
    caseContext: { alertsAfterCutoff: [{ id: 'A2', at: '2026-09-17T13:15:00Z' }, { id: 'A3', at: '2026-09-17T13:57:00Z' }] },
  });
  assert.equal(cutoffOf(m), Date.parse('2026-09-17T13:16:00Z'));
  assert.deepEqual(alertsAfter(m).map((a) => a.id), ['A3'], 'A2 is older than the analysis, so it may have been seen');
});

test('low confidence, or a gap the agent names, withdraws the recommendation', () => {
  assert.equal(isLowConfidence(example('cs-4127-fresh')), false);
  const low = example('cs-4127-low-confidence');
  assert.equal(isLowConfidence(low), true);
  assert.match(renderCard(low, CLOCK, NAMES), /No recommendation\./);
  const gapOnly = readCard({ aiAnalysis: { verdict: 'BENIGN', confidenceLevel: 'HIGH', missingEvidence: 'No network telemetry.' } });
  assert.equal(isLowConfidence(gapOnly), true);
});

test('a revision says what it replaced, and the revised verdict is checked against its own cut-off', () => {
  const r = example('cs-4133-revised');
  assert.equal(r.verdict, 'Malicious');
  assert.equal(r.revision?.verdict, 'Benign');
  assert.equal(alertsAfter(r).length, 0, 'the revision saw A3, so it is no longer outdated');
  const html = renderCard(r, CLOCK, NAMES);
  assert.match(html, /Revised\.<\/b> It said Benign at 13:16 UTC; you overrode it to Malicious at 14:04 UTC\./);
  assert.match(html, /Before the revision it concluded/);
});

test('each example says the thing it exists to say', () => {
  const says = {
    'cs-4133-today': /The agent didn’t say what data it used, or up to when\./,
    'cs-4133-moved-on': /Alert\u00a0A3 happened at 13:57 UTC, 43 min after the newest data the agent used\. The agent hasn’t seen it\. <span class="m">Case last checked 13:58 UTC\.<\/span>/,
    'cs-4127-fresh': /No newer alerts since its data · case last checked<\/span> 13:12 UTC/,
    'cs-4127-low-confidence': /No recommendation\.<\/b> The agent’s confidence is Low\. It reports: No network telemetry for this account\./,
    'cs-4133-revised': /Revised\./,
  };
  for (const file of readdirSync(join(here, 'examples')).filter((f) => f.endsWith('.json') && f !== 'clock.json')) {
    const name = file.replace(/\.json$/, '');
    assert.ok(says[name], `no expectation for ${name}`);
    assert.match(renderCard(example(name), CLOCK, NAMES), says[name], name);
  }
});

test('gate G2: the card never draws a control that could change the case', () => {
  const dist = readFileSync(join(here, 'dist/verdict-card.html'), 'utf8');
  for (const name of ['cs-4133-today', 'cs-4133-moved-on', 'cs-4127-fresh', 'cs-4127-low-confidence', 'cs-4133-revised']) {
    const html = renderCard(example(name), CLOCK, NAMES);
    assert.doesNotMatch(html, /<(button|form|input|select|textarea)\b/i, `${name} draws a control`);
    for (const a of html.match(/<a\b[^>]*>/g) ?? []) assert.match(a, /target="_blank" rel="noopener noreferrer"/, 'links leave the console, nothing else');
  }
  assert.doesNotMatch(dist, /\b(fetch|XMLHttpRequest|sendBeacon|WebSocket)\b|\.submit\(|parent\.postMessage/, 'the widget file makes no request and never writes to its host');
});

test('text from the result is escaped, and only https links leave the widget', () => {
  const html = renderCard(
    readCard({ aiAnalysis: { verdict: 'MALICIOUS', conclusion: '<img src=x onerror=alert(1)>', url: 'javascript:alert(1)', claims: [{ text: '"><script>alert(1)</script>', where: { kind: 'source', label: 'Wiz', url: 'https://app.wiz.io/x' } }] } }),
    CLOCK,
    NAMES,
  );
  assert.doesNotMatch(html, /<img|<script|javascript:/i);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.equal(safeUrl('https://app.wiz.io/issues/1'), 'https://app.wiz.io/issues/1');
  for (const bad of ['http://app.wiz.io', 'javascript:alert(1)', 'data:text/html,x', 'https://a b', ' ']) assert.equal(safeUrl(bad), null, bad);
  assert.equal(esc(`<a href="x">'&'</a>`), '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;');
});

test('a result stamped ahead of the analyst’s clock reads as new, never as an age', () => {
  const m = readCard({ aiAnalysis: { verdict: 'BENIGN', analyzedAt: '2026-09-17T14:16:00Z' } });
  assert.match(renderCard(m, Date.parse('2026-09-17T14:10:00Z'), NAMES), /<b data-tick>under 1 min old<\/b>/);
});

test('with its script stripped, the widget still says why it is empty', () => {
  const dist = readFileSync(join(here, 'dist/verdict-card.html'), 'utf8');
  const withoutScripts = dist.replace(/<script>[\s\S]*?<\/script>/g, '');
  assert.match(withoutScripts, /<main id="card"[^>]*><p class="m">This card draws with a script, and scripts are switched off here\.<\/p><\/main>/);
});

test('two ratings that differ are named as differing, each with its owner, and nothing more is claimed', () => {
  const html = renderCard(example('cs-4133-moved-on'), CLOCK, NAMES);
  assert.match(html, /Wiz:<\/span> <span class="v">Low<\/span> <span class="m">severity<\/span>/);
  assert.match(html, /this console:<\/span> <span class="v">Medium<\/span> <span class="m">case priority<\/span>/);
  assert.match(html, /<span class="m">they differ<\/span><\/dd>/);
});

test('the card says what the agent read, what it could not, and which alerts the verdict is about', () => {
  const moved = renderCard(example('cs-4133-moved-on'), CLOCK, NAMES);
  assert.match(moved, /data up to 13:14 UTC<span class="m"> · <\/span><span class="m">Wiz Defend cloud telemetry, Cloud audit log<\/span>/);
  assert.match(moved, /about alert\u00a0A1/);
  const low = renderCard(example('cs-4127-low-confidence'), CLOCK, NAMES);
  assert.match(low, /<span class="m">Not read:<\/span> Network flow logs/);
});

test('unchecked is said as unchecked, never as fresh', () => {
  const m = readCard({ aiAnalysis: { verdict: 'BENIGN', analyzedAt: '2026-09-17T13:16:00Z', dataCutoffAt: '2026-09-17T13:14:00Z', sourcesRead: ['x'] } });
  const html = renderCard(m, CLOCK, NAMES);
  assert.match(html, /Can’t tell if newer alerts arrived: nothing has checked the case\./);
  assert.match(html, /<span class="state">Newer alerts not checked<\/span>/);
  const noTime = readCard({ aiAnalysis: { verdict: 'BENIGN' }, caseContext: { alertsAfterCutoff: [] } });
  assert.match(renderCard(noTime, CLOCK, NAMES), /Can’t check for newer alerts/, 'checked, but nothing to compare with, is not "not checked"');
});

test('a claim that lives only in the source links out to it, and nowhere else', () => {
  const html = renderCard(example('cs-4133-moved-on'), CLOCK, NAMES);
  assert.match(html, /<a href="https:\/\/wiz\.example\/issues\/[^"]+" target="_blank" rel="noopener noreferrer">Only in Wiz/);
});

test('line 1 reads in one order in every state: the verdict, how sure, whether it still stands', () => {
  const says = {
    'cs-4133-moved-on': /class="state state-outdated">Outdated by alert\u00a0A3</,
    'cs-4127-fresh': /class="state state-current">No newer alerts</,
    'cs-4133-today': /class="state">Newer alerts not checked</,
  };
  for (const [name, state] of Object.entries(says)) {
    const html = renderCard(example(name), CLOCK, NAMES);
    assert.match(html, state, name);
    const line1 = html.match(/<p class="verdict[^]*?<\/p>/)[0];
    assert.ok(line1.indexOf('class="word') < line1.indexOf('confidence<') && line1.indexOf('confidence<') < line1.indexOf('class="state'), `${name}: verdict, then confidence, then state`);
  }
});

test('an all-clear is green only while a check says it stands; a warning keeps its colour', () => {
  const moved = example('cs-4133-moved-on');
  const stale = (m) => /class="word stale"/.test(renderCard(m, CLOCK, NAMES));
  assert.equal(stale(moved), true, 'an outdated Benign is drawn in ink');
  assert.equal(stale({ ...moved, verdict: 'Malicious' }), false, 'an outdated Malicious keeps its red');
  assert.equal(stale({ ...moved, verdict: 'Suspicious' }), false, 'an outdated Suspicious keeps its colour');
  const low = example('cs-4127-low-confidence');
  assert.equal(stale(low), false, 'a low-confidence Malicious keeps its red');
  assert.equal(stale({ ...low, verdict: 'Benign' }), true, 'a low-confidence Benign is drawn in ink');
  assert.equal(stale(example('cs-4127-fresh')), false);
  assert.equal(stale({ ...example('cs-4127-fresh'), verdict: 'Benign' }), false, 'a Benign that stands keeps its green');
  assert.equal(stale(example('cs-4133-today')), true, 'an unchecked Benign is drawn in ink: nothing says it still stands');
});

test('the age is tied to the moment it was read, and only the age moves with the clock', () => {
  const m = example('cs-4133-moved-on');
  const html = renderCard(m, CLOCK, NAMES);
  assert.match(html, /13:16 UTC · <b data-tick>54 min old<\/b><span class="m" data-tick> at 14:10 UTC<\/span>/);
  const shape = (h) => h.replace(/(<[^>]*data-tick[^>]*>)[^<]*/g, '$1');
  assert.equal(shape(renderCard(m, CLOCK + 5 * MIN, NAMES)), shape(html), 'five minutes later, only the data-tick words differ');
});

test('with no data cut-off, an outdated verdict is measured from when it was made, and says so', () => {
  const m = readCard({
    aiAnalysis: { verdict: 'BENIGN', analyzedAt: '2026-09-17T13:16:00Z' },
    caseContext: { alertsAfterCutoff: [{ id: 'A3', name: 'x', at: '2026-09-17T13:57:00Z' }, { id: 'A4', at: '2026-09-17T13:59:00Z' }] },
  });
  const html = renderCard(m, CLOCK, NAMES);
  assert.match(html, /41 min after the agent made this verdict\. The agent hasn’t seen it\. 1 more alert came after it\./);
});
