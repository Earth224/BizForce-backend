"use strict";
/* Applies the startToolRun pattern (exactly as in the two pilots) to the named
   routes in server.js. Every anchor is asserted; a route that does not match
   the expected shape aborts the whole run with nothing written. */
const fs = require("fs");
const assert = require("assert");
const FILE = "C:/Users/ALGORITHM/BizForce-backend/server.js";

const TITLES = {
  "etsy/keyword-research":          ["etsy", '"Etsy · Keyword research: " + seed'],
  "etsy/pricing-strategy":          ["etsy", '"Etsy · Pricing strategy: " + listingTitle'],
  "email/sequence":                 ["email", '"Email · Sequence: " + goal'],
  "email/subject-lines":            ["email", '"Email · Subject lines: " + purpose'],
  "publicist/press-release":        ["publicist", '"Publicist · Press release: " + news.replace(/\\s+/g, " ").slice(0, 120)'],
  "publicist/pitch":                ["publicist", '"Publicist · Pitch: " + angle.replace(/\\s+/g, " ").slice(0, 120)'],
  "operations/sop":                 ["operations", '"Operations · SOP: " + processName'],
  "operations/checklist":           ["operations", '"Operations · Checklist: " + task'],
  "ads/copy":                       ["ads", '"Ads · Copy: " + product'],
  "ads/policy-check":               ["ads", '"Ads · Policy check: " + copy.replace(/\\s+/g, " ").slice(0, 120)'],
  "reputation/review-response":     ["reputation", '"Reputation · Review response: " + reviewText.replace(/\\s+/g, " ").slice(0, 120)'],
  "reputation/review-request":      ["reputation", '"Reputation · Review request: " + moment'],
  "social/post":                    ["social", '"Social · Post: " + idea.replace(/\\s+/g, " ").slice(0, 120)'],
  "social/calendar":                ["social", '"Social · Calendar: " + goal'],
  "broker/term-sheet":              ["broker", '"Broker · Term sheet: " + deal.replace(/\\s+/g, " ").slice(0, 120)'],
  "broker/due-diligence":           ["broker", '"Broker · Due diligence: " + dealType'],
  "rd/brief":                       ["rd", '"R&D · Brief: " + question'],
  "community/onboarding":           ["community", '"Community · Onboarding: " + communityType'],
  "community/engagement-calendar":  ["community", '"Community · Engagement calendar: " + (communityType || cadence)'],
  "analytics/funnel":               ["analytics", '"Analytics · Funnel: " + (funnelName || (stages.length + " stages"))'],
  "analytics/kpi-review":           ["analytics", '"Analytics · KPI review: " + (periodLabel || (metrics.length + " metrics"))'],
  "influencer/outreach":            ["influencer", '"Influencer · Outreach: " + creator.replace(/\\s+/g, " ").slice(0, 120)'],
  "influencer/partnership-offer":   ["influencer", '"Influencer · Partnership offer: " + (creator || collaboration.replace(/\\s+/g, " ").slice(0, 120))'],
  "vertical_marketing/positioning": ["vertical_marketing", '"Vertical marketing · Positioning: " + industry'],
  "vertical_marketing/objections":  ["vertical_marketing", '"Vertical marketing · Objections: " + industry'],
  "content/outline":                ["content", '"Content · Outline: " + keyword'],
  "executive/plan":                 ["executive", '"Executive · Plan: " + goal.replace(/\\s+/g, " ").slice(0, 120)']
};

function routeBounds(src, path) {
  const sig = 'app.post("/api/agents/' + path + '"';
  const start = src.indexOf(sig);
  assert(start > 0, "route not found: " + path);
  assert.strictEqual(src.indexOf(sig, start + 1), -1, "route registered twice: " + path);
  let depth = 0, i = src.indexOf("{", start), end = -1;
  for (; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) { end = i + 1; break; } }
  }
  assert.strictEqual(src.slice(end, end + 3), ");\n", "route terminator: " + path);
  return { start, end: end + 2 };
}

function transformRoute(text, path) {
  const [agent, titleExpr] = TITLES[path];
  assert(text.indexOf("startToolRun(") === -1, "already transformed: " + path);

  // 1. insert after the last validation block's closing brace
  const last400 = text.lastIndexOf("return res.status(400)");
  assert(last400 > 0, "no 400 in " + path);
  const closeIdx = text.indexOf("\n      }\n", last400);
  assert(closeIdx > 0, "400 block close not found in " + path);
  const insertAt = closeIdx + "\n      }\n".length;
  const startBlock =
    "\n      // After validation, before anything is spent: a 400 records nothing, and a\n" +
    "      // run that cannot be recorded throws here rather than running unrecorded.\n" +
    "      var run = await startToolRun(req, {\n" +
    '        agentType: "' + agent + '",\n' +
    '        taskType: "' + path + '",\n' +
    "        title: " + titleExpr + "\n" +
    "      });\n";
  text = text.slice(0, insertAt) + startBlock + text.slice(insertAt);
  // no other 400 may follow the insert
  assert.strictEqual(text.indexOf("res.status(400)", insertAt + startBlock.length), -1, "a 400 follows the insert in " + path);

  // 2. every 502 after the insert gets a fail() first
  let searchFrom = insertAt + startBlock.length, count502 = 0;
  for (;;) {
    const idx = text.indexOf("return res.status(502).json({", searchFrom);
    if (idx === -1) break;
    const lineStart = text.lastIndexOf("\n", idx) + 1;
    const indent = text.slice(lineStart, idx);
    assert(/^ +$/.test(indent), "502 indentation in " + path);
    const failLine =
      indent + "// An error path: the row must not stay \"processing\" for a run that\n" +
      indent + "// returned nothing usable.\n" +
      indent + 'await run.fail(new Error("' + path + ': the model\'s output could not be read back, so nothing was reported."));\n';
    text = text.slice(0, lineStart) + failLine + text.slice(lineStart);
    searchFrom = lineStart + failLine.length + "return res.status(502).json({".length;
    count502++;
  }
  // any other non-success response after the insert would be a shape we do not handle
  const afterInsert = text.slice(insertAt + startBlock.length);
  const statusCalls = (afterInsert.match(/res\.status\(\d+\)/g) || []).filter(s => s !== "res.status(502)");
  assert.deepStrictEqual(statusCalls, [], "unexpected status responses after insert in " + path + ": " + statusCalls);

  // 3. the single success response becomes responseBody + complete + respond
  const succ = "\n      return res.json({\n";
  const succIdx = text.indexOf(succ);
  assert(succIdx > 0, "success response not found in " + path);
  assert.strictEqual(text.indexOf(succ, succIdx + 1), -1, "more than one success response in " + path);
  const braceOpen = text.indexOf("{", succIdx + "\n      return res.json(".length);
  let depth = 0, j = braceOpen, braceClose = -1;
  for (; j < text.length; j++) {
    const c = text[j];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) { braceClose = j; break; } }
  }
  assert.strictEqual(text.slice(braceClose - 6, braceClose + 3), "      });", "success close in " + path);
  const tail =
    "      };\n\n" +
    "      // Persisted as the body exactly as sent, minus the two bookkeeping keys\n" +
    "      // added below. `persisted` is false only when the run happened and the\n" +
    "      // record of it did not — the user still gets the work either way.\n" +
    "      var persisted = await run.complete(responseBody);\n\n" +
    "      return res.json(Object.assign({}, responseBody, {\n" +
    "        task_id: run.taskId,\n" +
    "        persisted: persisted\n" +
    "      }));";
  text = text.slice(0, braceClose - 6) + tail + text.slice(braceClose + 3);
  text = text.slice(0, succIdx) + "\n      var responseBody = {\n" + text.slice(succIdx + succ.length);

  // 4. the catch marks the row failed
  const nextIdx = text.lastIndexOf("      next(error);\n");
  assert(nextIdx > 0, "next(error) not found in " + path);
  assert.strictEqual(text.indexOf("next(error)"), nextIdx + 6, "more than one next(error) in " + path);
  text = text.slice(0, nextIdx) + "      if (run) {\n        await run.fail(error);\n      }\n" + text.slice(nextIdx);

  return { text, count502 };
}

const group = process.argv.slice(2);
assert(group.length, "pass route paths");
let src = fs.readFileSync(FILE, "utf8");
// process in reverse file order so earlier indices stay valid
const ordered = group.map(p => ({ p, b: routeBounds(src, p) })).sort((a, b) => b.b.start - a.b.start);
const report = [];
for (const { p, b } of ordered) {
  const { text, count502 } = transformRoute(src.slice(b.start, b.end), p);
  src = src.slice(0, b.start) + text + src.slice(b.end);
  report.push(p + ": startToolRun inserted, " + count502 + " x 502 guarded, success wrapped, catch guarded");
}
fs.writeFileSync(FILE, src);
report.forEach(r => console.log(r));
