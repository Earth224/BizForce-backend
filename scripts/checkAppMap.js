"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkAppMap — lib/appMap.json, the map Termaximus's Guide mode may name, is
   generated from the app, matches it, and is not stale.

   Backend "Termaximus Guide mode: verified steps from a generated map of the
   app" added scripts/buildAppMap.js and lib/appMapBuild.js, which walk every
   frontend page and write lib/appMap.json: per page its path, title, h1, the
   buttons, links and tabs with a stable selector, the API route each control
   calls joined to its gate, and the page's guide tips. POST /api/guide/ask
   drops any step naming a page or control that is not in it.

     M1  the committed map equals a fresh build from today's frontend and
         server.js, byte for byte, and its inputs hash is today's;
     M2  the map is stale the moment an input changes: a renamed button, a new
         tip, a route's gate changing — each gives a different hash, and an
         edit elsewhere in server.js does not;
     M3  every label in the map is on its page: an "#id" control's element is
         in the page (or, for an agent page, built by agent-profile.js from its
         config) and shows that label; an a[href] link is in the page with that
         text; every page key is a real file at its path;
     M4  every control's route is a real server route, and its gate is the one
         the server's route line gives it; the tips are PAGE_GUIDANCE's;
     M5  nothing private: no label that looks like a key or token (a page
         fixture with one shows it is dropped), no email address, no input
         value or placeholder; test pages are not in the map;
     M6  the size, reported (the tips alone are most of it).

   No network, no model call, no database: files read as text.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const MAP = "lib/appMap.json", BUILD = "lib/appMapBuild.js", SERVER = "server.js";

const MUTATIONS = {
  // the hash ignores what the inputs say, so a changed page never makes the map stale (M2)
  "map-not-checked-for-staleness": [[BUILD, '    h.update(name + "\\u0000" + inputs[name] + "\\u0000");', '    h.update(name + "\\u0000");']],
  // a route's gate is no longer an input, so a gate change never makes the map stale (M2)
  "gate-not-hashed": [[BUILD, '  inputs["server.js#routes"] = routes.map(function (r) { return r.method + " " + r.path + " " + r.gate; }).join("\\n");\n', ""]],
  // a label edited by hand in the committed map (M1, M3)
  "label-not-on-page": [[MAP, '["#addCustomerBtn","+ Add Customer","b"]', '["#addCustomerBtn","+ Add Contact","b"]']],
  // a control added by hand that the page does not have (M1, M3)
  "invented-control": [[MAP, '["#addCustomerBtn","+ Add Customer","b"]', '["#addCustomerBtn","+ Add Customer","b"],["#importCsvBtn","Import CSV","b"]']],
  // a credential-shaped label is kept (M5)
  "secret-label-kept": [[BUILD, "  if (!t || secretLike(t)) return \"\";\n", "  if (!t) return \"\";\n"]],
  // a control kept without a unique selector (M3)
  "duplicate-id-kept": [[BUILD, "      if (c.id && idCount[c.id] === 1 && ", "      if (c.id && "]],
  // the gates are read wrong: requireActiveSubscription not seen (M4)
  "sub-gate-unread": [[BUILD, '    if (/\\brequireActiveSubscription\\b/.test(head)) gates.push("sub");\n', ""]],
  // test pages are mapped (M5)
  "test-pages-mapped": [[BUILD, "var MAP_SKIP = /^(google[0-9a-f]+\\.html|test-.*)$/i;", "var MAP_SKIP = /^(google[0-9a-f]+\\.html)$/i;"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const lf = t => t.replace(/\r\n/g, "\n");
if (!fs.existsSync(FRONTEND)) { console.log("    FAIL  frontend not found: " + FRONTEND + " (set BIZFORCE_FRONTEND_DIR)"); process.exit(1); }
const FRONT = {};
const PAGES = [];
(function walk(dir) {
  fs.readdirSync(path.join(FRONTEND, dir), { withFileTypes: true }).forEach(d => {
    const rel = dir ? dir + "/" + d.name : d.name;
    if (d.isDirectory()) { if (!/^(\.|node_modules$)/.test(d.name)) walk(rel); }
    else if (/\.html$/i.test(d.name)) PAGES.push(rel);
  });
})("");
function readFront(rel) {
  if (FRONT[rel] !== undefined) return FRONT[rel];
  const p = path.join(FRONTEND, rel);
  FRONT[rel] = fs.existsSync(p) ? lf(fs.readFileSync(p, "utf8")) : null;
  return FRONT[rel];
}
const FILES = {};
[MAP, BUILD, SERVER].forEach(f => { FILES[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });

if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}

// lib/appMapBuild.js, compiled from FILES so a mutation of it is the one that runs.
function loadBuilder(src) {
  const m = new Module(path.join(REPO, BUILD), module);
  m.filename = path.join(REPO, BUILD);
  m.paths = Module._nodeModulePaths(path.join(REPO, "lib"));
  m._compile(src, m.filename);
  return m.exports;
}
let B, MAPV;
try { B = loadBuilder(FILES[BUILD]); } catch (e) { console.log("    FAIL  lib/appMapBuild.js could not be loaded: " + e.message); process.exit(1); }
try { MAPV = JSON.parse(FILES[MAP]); } catch (e) { console.log("    FAIL  lib/appMap.json is not JSON: " + e.message); process.exit(1); }
const build = (over) => B.buildAppMap({ pages: PAGES, readFront: rel => (over && over[rel] !== undefined ? over[rel] : readFront(rel)), server: (over && over[SERVER]) || FILES[SERVER] });

console.log("\n══ M1. the committed map is a fresh build ══");
const FRESH = build();
const freshText = B.serializeAppMap(FRESH);
check("M1. lib/appMap.json equals a fresh build from today's frontend and server.js, byte for byte", freshText === FILES[MAP],
  "run node scripts/buildAppMap.js (" + Buffer.byteLength(freshText) + " vs " + Buffer.byteLength(FILES[MAP]) + " bytes)");
check("M1. ... and its inputs hash is today's", MAPV.inputs === FRESH.inputs, MAPV.inputs + " vs " + FRESH.inputs);
check("M1. ... and it is version " + B.MAP_VERSION + " with pages and routes", MAPV.v === B.MAP_VERSION && Object.keys(MAPV.pages || {}).length >= 50 && Object.keys(MAPV.routes || {}).length >= 50,
  Object.keys(MAPV.pages || {}).length + " pages");

console.log("\n══ M2. any change to an input makes the map stale ══");
{
  const crm = readFront("crm.html");
  const renamed = build({ "crm.html": s.replaceOnce(crm, 'id="addCustomerBtn">+ Add Customer<', 'id="addCustomerBtn">+ New Customer<', "fixture") });
  check("M2. renaming a button on crm.html changes the hash", renamed.inputs !== FRESH.inputs);
  const guide = readFront("scripts/termaximus-guide.js");
  const at = guide.indexOf('    "crm.html": [\n');
  const tipped = at === -1 ? guide : guide.slice(0, at) + '    "crm.html": [\n      "An extra tip.",\n' + guide.slice(at + '    "crm.html": [\n'.length);
  check("M2. a new guide tip changes the hash", at !== -1 && build({ "scripts/termaximus-guide.js": tipped }).inputs !== FRESH.inputs);
  const srv = FILES[SERVER];
  const gateAt = srv.indexOf('app.post("/api/crm/customers", requireAuth, ');
  const regated = gateAt === -1 ? srv : srv.slice(0, gateAt) + 'app.post("/api/crm/customers", requireAuth, requireActiveSubscription, ' + srv.slice(gateAt + 'app.post("/api/crm/customers", requireAuth, '.length);
  check("M2. a route's gate changing changes the hash", gateAt !== -1 && build({ [SERVER]: regated }).inputs !== FRESH.inputs);
  check("M2. an edit elsewhere in server.js (a comment) does not", build({ [SERVER]: srv + "\n// a comment\n" }).inputs === FRESH.inputs);
  const presence = readFront("scripts/termaximus-presence.js");
  check("M2. the map's own reader (termaximus-presence.js, loaded by pages) is an input too", presence !== null &&
    build({ "scripts/termaximus-presence.js": presence + "\n" }).inputs !== FRESH.inputs);
}

console.log("\n══ M3. every label in the map is on its page ══");
const decode = t => String(t).replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, " ")
  .replace(/&larr;/g, "←").replace(/&rarr;/g, "→").replace(/&uarr;/g, "↑").replace(/&darr;/g, "↓").replace(/&ndash;/g, "–").replace(/&bull;/g, "•").replace(/&times;/g, "×").replace(/&mdash;/g, "—").replace(/&hellip;/g, "…").replace(/&middot;/g, "·")
  .replace(/&#x([0-9a-f]+);/gi, (m, h) => String.fromCodePoint(parseInt(h, 16))).replace(/&#(\d+);/g, (m, d) => String.fromCodePoint(+d));
const flat = t => decode(String(t).replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim();
const AGENT_JS = readFront("scripts/agent-profile.js") || "";
const missing = [], badPages = [];
let labels = 0;
Object.keys(MAPV.pages).forEach(key => {
  const pg = MAPV.pages[key];
  const rel = String(pg.p || "").replace(/^\//, "");
  const html = readFront(rel);
  if (!html || rel.split("/").pop() !== key) { badPages.push(key + " -> " + pg.p); return; }
  const markup = html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ").replace(/<!--[\s\S]*?-->/g, " ");
  (pg.c || []).forEach(row => {
    labels++;
    const [sel, label] = row;
    const short = label.replace(/…$/, "");
    let ok = false;
    let m;
    if ((m = /^#([A-Za-z][\w-]*)$/.exec(sel))) {
      const tagRe = new RegExp("<(button|a|div|li|span)\\b[^>]*\\sid=\"" + m[1] + "\"[^>]*>([\\s\\S]*?)</\\1>");
      const t = tagRe.exec(markup);
      if (t) {
        const aria = /aria-label="([^"]*)"/.exec(t[0].slice(0, t[0].indexOf(">") + 1));
        ok = flat(aria ? aria[1] : t[2]).indexOf(short) === 0 || decode(aria ? aria[1] : "").indexOf(short) === 0;
      } else if (sel === "#apLaunchBtn") {
        ok = /window\.AGENT_PROFILE_CONFIG = /.test(html) && /id="apLaunchBtn"[^>]*>Launch Task</.test(AGENT_JS) && label === "Launch Task";
      }
    } else if ((m = /^a\[href="([^"]+)"\]$/.exec(sel))) {
      const esc = m[1].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const t = new RegExp("<a\\b[^>]*\\shref=\"" + esc + "\"[^>]*>([\\s\\S]*?)</a>").exec(markup);
      ok = !!t && (flat(t[1]).indexOf(short) === 0 || /aria-label="([^"]*)"/.test(t[0]));
    } else if ((m = /^\[data-tool-(toggle|run)="([\w-]+)"\]$/.exec(sel))) {
      const cfgM = /window\.AGENT_PROFILE_CONFIG = (\{[\s\S]*?\n\});/.exec(html);
      let cfg = null;
      try { cfg = cfgM ? require("vm").runInNewContext("(" + cfgM[1] + ")") : null; } catch (e) { cfg = null; }
      const tool = cfg && (cfg.tools || []).filter(t => t && t.id === m[2])[0];
      const shown = tool ? String(m[1] === "toggle" ? tool.label || tool.id : tool.runLabel || "Run") : "";
      ok = !!tool && shown.indexOf(short) === 0 && AGENT_JS.indexOf("data-tool-" + m[1]) !== -1;
    }
    if (!ok) missing.push(key + " " + sel + " " + JSON.stringify(label));
  });
});
check("M3. every page key names a real file at its path", badPages.length === 0, badPages.join(", "));
check("M3. every one of the " + labels + " labels in the map is on its page, on the element its selector names", labels >= 300 && missing.length === 0, missing.slice(0, 8).join(" | "));
const dupSel = [];
Object.keys(MAPV.pages).forEach(key => {
  const html = readFront(MAPV.pages[key].p.replace(/^\//, "")) || "";
  MAPV.pages[key].c.forEach(([sel]) => {
    const m = /^#([A-Za-z][\w-]*)$/.exec(sel);
    if (m && (html.split('id="' + m[1] + '"').length - 1) > 1) dupSel.push(key + " " + sel);
  });
});
check("M3. every #id selector names exactly one element on its page", dupSel.length === 0, dupSel.slice(0, 6).join(", "));
{
  // No page repeats a control's id today, so a fixture page that does shows the control is left out, not guessed at.
  const fx = B.buildAppMap({ pages: ["dup-fixture.html"], server: FILES[SERVER],
    readFront: rel => rel === "dup-fixture.html" ? '<h1>Fixture</h1><button id="go">Go</button><button id="go">Go again</button><button id="stop">Stop</button>' : readFront(rel) });
  const sels = ((fx.pages["dup-fixture.html"] || {}).c || []).map(r => r[0]);
  check("M3. a control whose id is not unique on its page is left out of the map (a fixture page with two id=\"go\")", sels.indexOf("#go") === -1 && sels.indexOf("#stop") !== -1, sels.join(","));
}

console.log("\n══ M4. routes, gates and tips ══");
{
  const routes = B.serverRoutes(FILES[SERVER]);
  const byKey = {};
  routes.forEach(r => { byKey[r.method + " " + r.path] = r; });
  const unknownRoute = [], wrongGate = [];
  Object.keys(MAPV.pages).forEach(k => MAPV.pages[k].c.forEach(row => { if (row[3] && !MAPV.routes[row[3]]) unknownRoute.push(k + " " + row[3]); }));
  Object.keys(MAPV.routes).forEach(r => {
    if (!byKey[r]) { unknownRoute.push(r); return; }
    const line = FILES[SERVER].split("\n").filter(l => l.indexOf("app." + r.split(" ")[0].toLowerCase() + "(\"" + r.split(" ")[1] + "\",") === 0)[0] || "";
    const head = line.split(/async function|function \(/)[0];
    const want = ["auth", "sub", "admin"].filter((g, i) => [/\brequireAuth\b/, /\brequireActiveSubscription\b/, /\brequireAdmin\b/][i].test(head));
    const got = MAPV.routes[r].split(",").filter(g => g !== "owner" && g !== "public");
    if (want.join(",") !== got.join(",")) wrongGate.push(r + " " + MAPV.routes[r] + " vs " + want.join(","));
  });
  check("M4. every route a control names is a real server route, listed once in the route table", unknownRoute.length === 0, unknownRoute.join(", "));
  check("M4. every route's gate is the one its server.js line gives it (requireAuth, requireActiveSubscription, requireAdmin)", wrongGate.length === 0, wrongGate.slice(0, 6).join(" | "));
  const subs = Object.keys(MAPV.routes).filter(r => /sub/.test(MAPV.routes[r]));
  check("M4. ... and subscriber-only routes are marked so (" + subs.length + ")", subs.length >= 10, subs.length);
  check("M4. the agent tools' run buttons carry their tool routes (e.g. seo.html)", (MAPV.pages["seo.html"].c || []).some(r => /^\[data-tool-run=/.test(r[0]) && /^POST \/api\/agents\/seo\//.test(r[3] || "")));
  // Block 3a (Oct 29 2026): Headquarters' sort and the calendar's read-only layer are mapped as their pages label them.
  const mapped = (p, sel) => (MAPV.pages[p] && MAPV.pages[p].c || []).find(r => r[0] === sel);
  check("M4. Headquarters' sort (executive-agent.html #hqSort) and the calendar's \"Agent runs\" toggle (#calAgentRunsBtn) are in the map",
    JSON.stringify(mapped("executive-agent.html", "#hqSort")) === JSON.stringify(["#hqSort", "Sorted by attention; press to sort A to Z", "b"]) &&
    JSON.stringify(mapped("calendar.html", "#calAgentRunsBtn")) === JSON.stringify(["#calAgentRunsBtn", "Agent runs", "b"]),
    JSON.stringify([mapped("executive-agent.html", "#hqSort"), mapped("calendar.html", "#calAgentRunsBtn")]));
  // Block 3b (Oct 29 2026): Headquarters' command controls, Send and Speak, are in the map as the page labels them.
  check("M4. Headquarters' command controls (executive-agent.html #hqSend \"Send\", #hqMic \"Speak\") are in the map",
    JSON.stringify(mapped("executive-agent.html", "#hqSend")) === JSON.stringify(["#hqSend", "Send", "b"]) &&
    JSON.stringify(mapped("executive-agent.html", "#hqMic")) === JSON.stringify(["#hqMic", "Speak", "b"]),
    JSON.stringify([mapped("executive-agent.html", "#hqSend"), mapped("executive-agent.html", "#hqMic")]));
  const vm = require("vm");
  const g = readFront("scripts/termaximus-guide.js");
  const i = g.indexOf("var PAGE_GUIDANCE = {"), j = g.indexOf("\n  };", i);
  const tips = vm.runInNewContext("(" + g.slice(g.indexOf("{", i), j + 4) + ")");
  const tipBad = Object.keys(MAPV.pages).filter(k => JSON.stringify(MAPV.pages[k].g || null) !== JSON.stringify(tips[k] || null));
  check("M4. every page's tips are its PAGE_GUIDANCE entry, unchanged", tipBad.length === 0, tipBad.join(", "));
}

console.log("\n══ M5. nothing private ══");
{
  const fixture = '<button id="k">sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv</button><button id="ok">Save</button><input id="name" value="Jane Doe" placeholder="you@example.com">';
  const got = B.controlsOf(fixture).map(c => c.label);
  check("M5. a credential-shaped label is dropped (a fixture page: a key-like button and a Save button)", got.length === 1 && got[0] === "Save", JSON.stringify(got));
  const text = FILES[MAP];
  check("M5. the map holds no email address", !/[\w.+-]+@[\w-]+\.[\w.]+/.test(text), (text.match(/[\w.+-]+@[\w-]+\.[\w.]+/) || [""])[0]);
  const keyish = [];
  Object.keys(MAPV.pages).forEach(k => MAPV.pages[k].c.forEach(r => { if (B.secretLike(r[1])) keyish.push(k + " " + r[1]); }));
  check("M5. no label looks like a key or token", keyish.length === 0, keyish.join(", "));
  check("M5. no input values or placeholders: no \"value=\" or \"placeholder\" text in the map", !/value=|placeholder=/.test(text));
  // The frontend has no test page today, so one is added to a build to show it would be left out.
  const withTest = B.buildAppMap({ pages: PAGES.concat(["test-harness.html"]), server: FILES[SERVER],
    readFront: rel => rel === "test-harness.html" ? "<title>Test</title><h1>Test</h1><button id=\"go\">Go</button>" : readFront(rel) });
  check("M5. a test page is not put in the map", !withTest.pages["test-harness.html"] && !!withTest.pages["crm.html"]);
}

console.log("\n══ M6. size ══");
{
  const bytes = Buffer.byteLength(FILES[MAP]);
  let tipBytes = 0, controls = 0, routed = 0;
  Object.keys(MAPV.pages).forEach(k => { tipBytes += Buffer.byteLength(JSON.stringify(MAPV.pages[k].g || [])); controls += MAPV.pages[k].c.length; routed += MAPV.pages[k].c.filter(r => r[3]).length; });
  console.log("    info  " + bytes + " bytes: " + Object.keys(MAPV.pages).length + " pages, " + controls + " controls (" + routed + " with a route), " +
    Object.keys(MAPV.routes).length + " routes; the tips are " + tipBytes + " bytes of it");
  check("M6. the map stays within 80 KB, so the cached system block stays small", bytes <= 80 * 1024, bytes);
}

console.log("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (passes + failures) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
process.exit(failures ? 1 : 0);
