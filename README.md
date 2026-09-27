# Verdict card for Wiz's Blue Agent in Google SecOps

A drop-in replacement for the widget Google SecOps ships for Wiz's **Get Blue Agent Analysis** action. It says what the widget in use today doesn't: **how old the verdict is, what the agent looked at, and whether the case has moved on since.**

It's one HTML file in the content hub's own format: the same action, placement, size and data binding as the widget it replaces. The case study behind it is at [omkarux.com/verdict-card](https://omkarux.com/verdict-card/).

> Concept work. Not affiliated with Google or Wiz, and not tested with analysts yet. The example cases are invented.

![Google's widget today and the verdict card, side by side on the same result](docs/harness.png)

## See it

Open [`dist/harness.html`](dist/harness.html) in a browser. It runs Google's widget and the card side by side, the way the console runs a widget:
- the action's result replaces the placeholder
- each widget sits in a 400 px sandboxed frame
- each takes the host's theme message

Six results and three themes, and every state has its own link: `harness.html?r=cs-4133-moved-on&t=light`.

## What it does with the result as it arrives today

Nothing needs to change in the integration for the first step. From today's seven fields, the card:
- **gives the verdict its age**, counted live: "As of 9 Jun, 16:12 UTC. 109 days old." Today's widget shows `2026-06-09T16:12:58.253716Z`.
- **keeps confidence a word.** Today's widget draws confidence with the same dots as severity.
- **shows the whole conclusion.** Today's widget cuts it to one line.
- **says what it can't know yet:** "The agent didn't say what data it used." and "Not checked against alerts that joined this case later."

## What it asks the result to carry

Every field is optional. The card says more as the result carries more.

| Field | Added by | What the analyst gets |
|---|---|---|
| `aiAnalysis.dataCutoffAt` | the agent | "using data to 13:14 UTC" |
| `aiAnalysis.claims[]` · `{ text, where: { kind: alert \| entity \| source, label, url? } }` | the agent | each claim says where to check it: "In this case · alert A2", or "Only in Wiz" |
| `aiAnalysis.missingEvidence` | the agent | at low confidence: "No action recommended", with the gap in the agent's words |
| `aiAnalysis.revisedFrom` · `{ verdict, analyzedAt, conclusion, reason }` | the agent | "Revised. It said Benign as of 13:16 UTC." plus the earlier conclusion |
| `aiAnalysis.url` | the agent | a link to the analysis, opened in a new tab (https only) |
| `caseContext.fetchedAt` | the action | "Added to this case 13:18 UTC" |
| `caseContext.casePriority` | the action | both ratings, each with its owner, and whether they agree |
| `caseContext.alertsAfterCutoff[]` · `{ id, name, at }` | the action, re-run when an alert joins the case | "Outdated. Alert A3 joined this case at 13:57 UTC, 43 minutes after the data this verdict used." |

The examples in [`examples/`](examples/) cover each of these, and [`third_party/google-content-hub/`](third_party/google-content-hub/) holds Google's own example result.

## What it doesn't do

It never changes the case. The console's HTML widget displays; it can't write. So the card has:
- no buttons, forms or inputs
- no requests, and no messages to the host

The only controls are links out.

The decisions (Accept, Override with a reason, Undo) belong to the integration as actions. The admin puts them on a Quick Actions widget, and their record is the Case Wall. The integration's analysis action can also write the verdict and its age as an insight (basic HTML, no scripts), so the line reaches the Case Wall even where no one installs the widget.

## Use it

- **Integration maintainers:** replace `widgets/get_blue_agent_analysis.html` and `.yaml` in `content/response_integrations/google/wiz/` with [`dist/verdict-card.html`](dist/verdict-card.html) and [`dist/verdict-card.yaml`](dist/verdict-card.yaml). The widget keeps the same action identifier, scope (alert), height (400) and default width (half).
- **Admins:** add it to a playbook's view the way any predefined widget is added.
- **Another agent:** change the two names at the top of the widget's script.

## Build and test

Node 22.13 or later. Nothing to install.

```bash
node --no-warnings build.mjs
node --test tests.mjs
npx -y -p typescript tsc -p .
```

The tests cover:
- reading every result shape Google's widget reads
- the age arithmetic, including the 49 days between the two times on Wiz's launch screenshot
- the outdated rule, where "not checked" and "fresh" are kept apart
- low confidence and revisions
- escaping and https-only links
- that the card draws no control that could change the case

## Licence

Apache-2.0 ([`LICENSE`](LICENSE)). [`third_party/google-content-hub/`](third_party/google-content-hub/) is Google's, unmodified, from [github.com/chronicle/content-hub](https://github.com/chronicle/content-hub) under Apache-2.0. It's here so the harness can compare the two. See [`NOTICE`](NOTICE).

Omkar Khadamkar · [omkarux.com](https://omkarux.com/)
