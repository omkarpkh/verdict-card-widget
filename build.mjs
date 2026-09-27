// Build the verdict card widget and its harness. Node 22.13+ (it strips the TypeScript itself).
//   node --no-warnings build.mjs
// dist/verdict-card.html   the widget: template.html with src/card.ts inlined, types stripped
// dist/verdict-card.yaml   its definition, in the content-hub schema
// dist/harness.html        Google's widget and the card side by side, run the way SecOps runs them
import { copyFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const read = (p) => readFileSync(join(here, p), 'utf8');
const once = (text, marker, what) => {
  if (text.split(marker).length !== 2) throw new Error(`${what}: "${marker}" must appear exactly once`);
};
mkdirSync(join(here, 'dist'), { recursive: true });

// 1 · the widget
const card = stripTypeScriptTypes(read('src/card.ts'), { mode: 'strip' }).replace(/^export /gm, '');
if (/<\/script/i.test(card)) throw new Error('card.ts contains "</script", which would end the inline script early');
const template = read('template.html');
once(template, '// @inline card.ts', 'template.html');
once(template, '[{stepInstanceName}.JsonResult]', 'template.html');
const widget = template.replace('// @inline card.ts', card.trim());
writeFileSync(join(here, 'dist/verdict-card.html'), widget);
copyFileSync(join(here, 'verdict-card.yaml'), join(here, 'dist/verdict-card.yaml'));

// 2 · the harness: both widgets and every example result, in one file that runs offline
const google = read('third_party/google-content-hub/get_blue_agent_analysis.html');
const clock = JSON.parse(read('examples/clock.json')).now;
const LABELS = {
  'google-content-hub-example': ['Google’s example', 'Google’s own example result, unchanged: the seven fields the action returns today.'],
  'cs-4133-today': ['Today’s fields', 'Synthetic case CS-4133 with only today’s seven fields. The card still gives the age and keeps confidence apart from severity.'],
  'cs-4133-moved-on': ['Case moved on', 'CS-4133 with the fields the card asks for. An alert joined 43 minutes after the data the verdict used.'],
  'cs-4127-fresh': ['Nothing newer', 'CS-4127 with the full fields. Nothing has joined the case since the data it used.'],
  'cs-4127-low-confidence': ['Low confidence', 'CS-4127 when the agent could not see everything. The recommendation is withdrawn and the gap is named.'],
  'cs-4133-revised': ['Revised', 'CS-4133 after the analyst accepted at 14:04 and the agent re-ran with alert A3.'],
};
const results = [
  { id: 'google-content-hub-example', json: JSON.parse(read('third_party/google-content-hub/get_blue_agent_analysis_JsonResult_example.json')), clock: null },
  ...readdirSync(join(here, 'examples'))
    .filter((f) => f.endsWith('.json') && f !== 'clock.json')
    .map((f) => ({ id: f.replace(/\.json$/, ''), json: JSON.parse(read(`examples/${f}`)), clock })),
].sort((a, b) => Object.keys(LABELS).indexOf(a.id) - Object.keys(LABELS).indexOf(b.id))
  .map((r) => {
    if (!LABELS[r.id]) throw new Error(`no label for example ${r.id}`);
    return { ...r, label: LABELS[r.id][0], note: LABELS[r.id][1] };
  });

// Inside a <script>, "</" would end it early; "<\/" is the same string to JavaScript.
const literal = (value) => JSON.stringify(value).replace(/<\//g, '<\\/');
let harness = read('harness.template.html');
for (const m of ["/*@google*/''", "/*@card*/''", '/*@results*/[]']) once(harness, m, 'harness.template.html');
harness = harness
  .replace("/*@google*/''", () => literal(google))
  .replace("/*@card*/''", () => literal(widget))
  .replace('/*@results*/[]', () => literal(results));
writeFileSync(join(here, 'dist/harness.html'), harness);

console.log(`dist/verdict-card.html ${(widget.length / 1024).toFixed(1)} KB · dist/harness.html ${(harness.length / 1024).toFixed(1)} KB · ${results.length} results`);
