"use strict";
/* ════════════════════════════════════════════════════════════════════════════
   checkAgentViews — FX2 (Nov 21 2026): the Agent Directory's three views on a
   phone (ai-agents.html, scripts/bf-agents-views.js) and the member's saved
   choice, user_preferences.agents_card_view (migration 200, part 200e).

     M  migration 200e: agents_card_view text, added only if it does not
        exist, NULL or large, compact, grid by a named CHECK dropped first;
        the part says it was applied by hand, with the verify result;
     S  GET and PUT /api/user/preferences (server.js, run in a vm with a fake
        database), as HQ1's hq_card_view: GET answers null when never chosen
        or not a listed value; PUT leaves an absent key alone, stores null,
        stores a listed value, and refuses anything else with a 400 naming
        the three, writing nothing;
     Y  Your data exports the column and says so; privacy.html carries it;
     P  the page in jsdom, on a phone: the row (Large, Compact, Grid, each
        an aria-label and aria-pressed), Compact by default; Compact and Grid
        are one row or tile per card, in the cards' order, each linking where
        the card's Open Agent links, its name and its role line; a choice is
        shown at once, kept on this device (bf_agents_view) and sent to the
        server; on a reload the device copy applies at once and the server's
        stored choice wins; a choice the server does not hold yet is sent to
        it; with no agents the page's own message stays shown; storage that
        throws breaks nothing; an unknown device value is ignored;
     D  on a desktop nothing is asked of the server and the cards stay;
     W  the page loads the script after its cards' script; sign-out clears
        bf_agents_view (bf-session.js); the shell caches the script.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check.
   ════════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const AGV = "scripts/bf-agents-views.js", AGP = "ai-agents.html", SESSION = "scripts/bf-session.js", SW = "sw.js", PRIVACY = "privacy.html";
const ORDER = "scripts/bf-agent-order.js", DESC = "scripts/agent-descriptions.js";
const SERVER = "@server.js", YOURDATA = "@lib/yourData.js", MIG = "@supabase/migrations/200_categories_and_intent.sql";

const MUTATIONS = {
  "migration-not-rerunnable": [[MIG, "ADD COLUMN IF NOT EXISTS agents_card_view text;", "ADD COLUMN agents_card_view text;"]],
  "migration-any-value": [[MIG, "  CHECK (agents_card_view IS NULL OR agents_card_view IN ('large', 'compact', 'grid'));", "  CHECK (true);"]],
  "route-no-400": [[SERVER, "if (req.body.agents_card_view !== null && AGENTS_CARD_VIEWS.indexOf(req.body.agents_card_view) === -1) {", "if (false) {"]],
  "route-get-unchecked": [[SERVER, "agents_card_view: AGENTS_CARD_VIEWS.indexOf(row.agents_card_view) !== -1 ? row.agents_card_view : null,", "agents_card_view: row.agents_card_view,"]],
  "route-null-dropped": [[SERVER, "      updates.agents_card_view = req.body.agents_card_view;", "      if (req.body.agents_card_view !== null) updates.agents_card_view = req.body.agents_card_view;"]],
  // NAMED (Nov 23 2026, P3-3): need_alerts (migration 202b) now follows agents_card_view, last
  "route-get-not-read": [[SERVER, "hq_card_view, hq_orbit, agents_card_view, need_alerts\")", "hq_card_view, hq_orbit, need_alerts\")"]],
  "yourdata-drops": [[YOURDATA, "hq_orbit, agents_card_view, updated_at", "hq_orbit, updated_at"]],
  "default-large": [[AGV, "DEFAULT_VIEW = \"compact\"", "DEFAULT_VIEW = \"large\""]],
  "no-device-copy": [[AGV, "    state.view = value; writeView(value); apply();", "    state.view = value; apply();"]],
  "no-server-save": [[AGV, "    return save({ agents_card_view: value });", "    return Promise.resolve(false);"]],
  "server-does-not-win": [[AGV, "        if (v) { state.view = v; writeView(v); apply(); }", "        if (false) { state.view = v; writeView(v); apply(); }"]],
  "null-not-sent": [[AGV, "        else if (b.agents_card_view === null && valid(readView())) save({ agents_card_view: state.view });\n", ""]],
  "desktop-asks": [[AGV, "    if (!phone() || state.server || typeof fetch !== \"function\")", "    if (state.server || typeof fetch !== \"function\")"]],
  "list-wrong-link": [[AGV, "      a.href = linkEl ? linkEl.getAttribute(\"href\") : \"agents-hub.html\";", "      a.href = \"agents-hub.html\";"]],
  "list-reversed": [[AGV, "    cards.forEach(function (card) {", "    cards.reverse().forEach(function (card) {"]],
  "list-not-redrawn": [[AGV, "  if (window.MutationObserver) new MutationObserver(draw).observe(grid, { childList: true });\n", ""]],
  "no-aria-pressed": [[AGV, "    VIEWS.forEach(function (v) { viewBtn[v].setAttribute(\"aria-pressed\", state.view === v ? \"true\" : \"false\"); });\n", ""]],
  "message-hidden": [[AGV, "    page.setAttribute(\"data-ag-view\", state.count ? state.view : \"large\");", "    page.setAttribute(\"data-ag-view\", state.view);"]],
  "storage-unguarded": [[AGV, "  function readView() { try { return window.localStorage.getItem(VIEW_KEY); } catch (e) { return null; } }", "  function readView() { return window.localStorage.getItem(VIEW_KEY); }"]],
  "unknown-kept": [[AGV, "  var state = { view: valid(readView()) || DEFAULT_VIEW,", "  var state = { view: readView() || DEFAULT_VIEW,"]],
  "no-role-line": [[AGV, "      if (Object.prototype.hasOwnProperty.call(ROLES, type)) text.appendChild(el(\"span\", \"ag-sub\", ROLES[type]));\n", ""]],
  "session-keeps": [[SESSION, "    \"bf_agents_view\",\n", ""]],
  "not-loaded": [[AGP, "<script src=\"/scripts/bf-agents-views.js\"></script>\n", ""]],
  "not-cached": [[SW, "  \"/scripts/bf-agents-views.js\",", "  \"/scripts/bf-agents-viewz.js\","]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

const FILES = {};
const readF = f => { try { return fs.readFileSync(path.join(FRONTEND, f), "utf8").replace(/\r\n/g, "\n"); } catch (e) { return null; } };
const readB = f => { try { return fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); } catch (e) { return null; } };
[AGV, AGP, SESSION, SW, PRIVACY, ORDER, DESC].forEach(f => { FILES[f] = readF(f); });
[SERVER, YOURDATA, MIG].forEach(f => { FILES[f] = readB(f.slice(1)); });
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let passes = 0, failures = 0;
function check(name, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + name); }
  else { failures++; console.log("    FAIL  " + name + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
process.on("unhandledRejection", e => check("no page request is left unhandled", false, (e && e.message) || e));
const J = v => JSON.stringify(v);
const has = (t, x) => typeof t === "string" && t.indexOf(x) !== -1;
const settle = ms => new Promise(r => setTimeout(r, ms || 30));
const VIEWS3 = ["large", "compact", "grid"];

/* the page's agents, as GET /api/agents answers (display_name and page_url as the server sends them) */
const AGENT_ROWS = [["executive", "Executive"], ["seo", "SEO"], ["sales", "Sales"], ["broker", "Broker"], ["rd", "R&D"], ["general", "General"]]
  .map(([t, n]) => ({ agent_type: t, display_name: n + " Agent", page_url: "/" + t + "-agent.html", active: true }));

(async () => {
  /* ══ M ══ */
  console.log("\n══ M. migration 200e ══");
  const mig = FILES[MIG] || "";
  check("M1. agents_card_view text, added only if it does not exist (safe to re-run)", has(mig, "ALTER TABLE public.user_preferences ADD COLUMN IF NOT EXISTS agents_card_view text;"));
  check("M2. NULL or large, compact, grid, by the named CHECK user_preferences_agents_card_view_check, dropped first if it exists",
    has(mig, "DROP CONSTRAINT IF EXISTS user_preferences_agents_card_view_check;") &&
    has(mig, "ADD CONSTRAINT user_preferences_agents_card_view_check\n  CHECK (agents_card_view IS NULL OR agents_card_view IN ('large', 'compact', 'grid'));") &&
    mig.indexOf("DROP CONSTRAINT IF EXISTS user_preferences_agents_card_view_check;") < mig.indexOf("ADD CONSTRAINT user_preferences_agents_card_view_check"));
  check("M3. part 200e says all five parts were applied by hand on Nov 21 2026, with the verify result",
    has(mig, "-- ===== PART 200e:") && has(mig, "-- APPLIED BY HAND: all five parts (200a, 200b, 200c, 200d, 200e) were applied by the owner\n-- on Nov 21 2026.") &&
    has(mig, "categories 32, unmapped_listings 0,\n-- non_share_posts 0, post_columns 7, agents_view_column 1."));

  /* ══ S ══ */
  console.log("\n══ S. GET and PUT /api/user/preferences ══");
  const SRC = FILES[SERVER] || "";
  function routeFn(method) {
    const sig = "app." + method + "(\"/api/user/preferences\", requireAuth, async function (req, res, next) {";
    const at = SRC.indexOf(sig);
    if (at < 0) return null;
    return SRC.slice(at + sig.indexOf("async function"), s.braceMatch(SRC, at + sig.length - 1));
  }
  const listOf = name => { const m = new RegExp("var " + name + " = (\\[[^\\]]*\\]);").exec(SRC); return m ? JSON.parse(m[1]) : null; };
  const AGVS = listOf("AGENTS_CARD_VIEWS");
  check("S0. the server's list: large, compact, grid", J(AGVS) === J(VIEWS3), J(AGVS));
  function db(row) {
    const st = { row: row ? Object.assign({}, row) : null, upserts: [], selects: [] };
    st.client = { from() {
      return {
        select(cols) { st.selects.push(cols); const q = { eq() { return q; }, maybeSingle: async () => {
          if (!st.row) return { data: null, error: null };
          const out = {}; String(cols).split(",").map(c => c.trim()).forEach(c => { out[c] = st.row[c] === undefined ? null : st.row[c]; }); return { data: out, error: null }; } }; return q; },
        upsert(u) { st.upserts.push(Object.assign({}, u)); st.row = Object.assign(st.row || {}, u); return Promise.resolve({ error: null }); }
      };
    } };
    return st;
  }
  function run(method, row, body) {
    const fn = routeFn(method), st = db(row);
    const ctx = { supabase: st.client, nowIso: () => "2026-11-21T17:00:00.000Z", LANGUAGE_NAMES: { en: "English" }, MIST_POSITIONS: ["top-right"],
      AGENT_CARD_ORDERS: ["importance", "alphabetical"], HQ_CARD_VIEWS: listOf("HQ_CARD_VIEWS"), HQ_ORBIT_CHOICES: listOf("HQ_ORBIT_CHOICES"), AGENTS_CARD_VIEWS: AGVS,
      dashboardTopCache: new Map(), require: m => require(m.indexOf("./") === 0 ? path.join(REPO, m) : m) };
    vm.createContext(ctx);
    const handler = vm.runInContext("(" + fn + ")", ctx);
    const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
    let nextErr = null;
    return Promise.resolve(handler({ user: { id: "u1" }, body: body || {} }, res, e => { nextErr = e || new Error("next"); }))
      .then(() => ({ status: res.statusCode, body: res.body, st, nextErr }));
  }
  if (!routeFn("get") || !routeFn("put")) check("S. both routes are in server.js", false);
  else {
    let r = await run("get", null);
    check("S1. GET with no settings row: agents_card_view is null (never chosen)", r.status === 200 && r.body && r.body.agents_card_view === null, J([r.body, r.nextErr && r.nextErr.message]));
    r = await run("get", { termaximus_active: true, agents_card_view: "grid" });
    check("S2. GET reads the column and answers the stored choice", !!r.body && r.body.agents_card_view === "grid" && /\bagents_card_view\b/.test(r.st.selects[0] || ""), J([r.body, r.st.selects]));
    r = await run("get", { agents_card_view: "huge" });
    check("S3. GET answers null for a stored value outside the list", !!r.body && r.body.agents_card_view === null, J(r.body));
    r = await run("put", { agents_card_view: "grid" }, { notifications_enabled: true });
    check("S4. PUT without the key leaves it alone (the upsert does not name it)", r.status === 200 && !!r.st.upserts[0] && !("agents_card_view" in r.st.upserts[0]) && r.st.row.agents_card_view === "grid", J(r.st.upserts));
    r = await run("put", { agents_card_view: "grid" }, { agents_card_view: null });
    check("S5. PUT null clears it (stored as null)", r.status === 200 && !!r.st.upserts[0] && r.st.upserts[0].agents_card_view === null, J(r.st.upserts));
    r = await run("put", null, { agents_card_view: "large" });
    check("S6. PUT a listed value stores it", r.status === 200 && !!r.st.upserts[0] && r.st.upserts[0].agents_card_view === "large", J(r.st.upserts));
    r = await run("put", null, { agents_card_view: "tiny" });
    check("S7. PUT a value outside the list: 400 naming large, compact, grid; nothing written", r.status === 400 && !!r.body && J(r.body.valid_agents_card_views) === J(VIEWS3) && r.st.upserts.length === 0, J([r.status, r.body]));
    r = await run("put", null, { agents_card_view: 5 });
    check("S8. PUT a number: 400; nothing written", r.status === 400 && r.st.upserts.length === 0, J([r.status, r.body]));
  }

  /* ══ Y ══ */
  console.log("\n══ Y. Your data ══");
  const YD = FILES[YOURDATA] || "";
  const prefLine = (YD.match(/\{ table: "user_preferences"[\s\S]*?onDelete: "delete" \}/) || [""])[0];
  check("Y1. lib/yourData.js exports agents_card_view with the member's settings row, and says so", /\bhq_orbit, agents_card_view, updated_at\b/.test(prefLine) && has(prefLine, "and your Agent Directory's view."), prefLine.slice(-240));
  check("Y2. the built privacy page carries it", has(FILES[PRIVACY], "whether its orbit is shown, and your Agent Directory&#39;s view."));

  /* ══ P, D: the page in jsdom ══ */
  const html = FILES[AGP] || "";
  const inline = (html.match(/<script>\n\(function renderLiveAgents\(\) \{[\s\S]*?<\/script>/) || [""])[0].replace(/^<script>/, "").replace(/<\/script>$/, "");
  const body = (/<body>([\s\S]*?)<script src="\/scripts\/bf-agent-order\.js"><\/script>/.exec(html) || ["", ""])[1];
  async function page(opts) {
    const o = opts || {};
    const dom = new JSDOM("<!doctype html><html><head></head><body>" + body + "</body></html>", { url: "https://bizforce.example/ai-agents.html", runScripts: "outside-only", pretendToBeVisual: true });
    const w = dom.window, calls = [];
    const store = {};
    Object.keys(o.local || {}).forEach(k => { store[k] = o.local[k]; });
    store.bf_token = "t";
    // storageThrows: every key but bf_token throws (the page's own card script, older than FX2, reads bf_token unguarded)
    const deny = k => o.storageThrows && k !== "bf_token";
    const ls = { getItem: k => (deny(k) ? (() => { throw new Error("denied"); })() : (k in store ? store[k] : null)),
      setItem: (k, v) => { if (deny(k)) throw new Error("denied"); store[k] = String(v); }, removeItem: k => { delete store[k]; } };
    Object.defineProperty(w, "localStorage", { value: ls, configurable: true });
    w.matchMedia = q => ({ matches: o.phone !== false && /max-width: 760px/.test(q), media: q, addEventListener() {}, removeEventListener() {} });
    const prefs = o.prefs === undefined ? { ok: true, preferences: {}, agents_card_view: null } : o.prefs;
    w.fetch = (u, init) => {
      const url = String(u), method = (init && init.method) || "GET";
      calls.push({ u: url, method, body: init && init.body ? JSON.parse(init.body) : null });
      const reply = (code, b) => Promise.resolve({ ok: code >= 200 && code < 300, status: code, json: () => Promise.resolve(b) });
      let p;
      if (/\/api\/agents$/.test(url)) p = o.agentsFail ? reply(500, {}) : reply(200, { agents: AGENT_ROWS });
      else if (/\/api\/user\/preferences$/.test(url)) p = method === "PUT" ? reply(200, { saved: true }) : reply(200, prefs);
      else p = reply(404, {});
      p.catch(() => {});
      return p;
    };
    let err = null;
    for (const src of [FILES[ORDER], FILES[DESC], inline, FILES[AGV]]) { try { w.eval(src || ""); } catch (e) { err = err || e.message; } }
    await settle(60);
    return { w, d: w.document, calls, store, err, close: () => w.close() };
  }
  const q = (d, sel) => Array.from(d.querySelectorAll(sel));
  const viewOf = d => { const p = d.querySelector(".page"); return p ? p.getAttribute("data-ag-view") : null; };
  const pressed = d => q(d, ".ag-view-btn").map(b => b.getAttribute("data-view") + ":" + b.getAttribute("aria-pressed")).join(",");

  console.log("\n══ P. the page on a phone ══");
  let P = await page({});
  const btns = q(P.d, "#agViewRow .ag-view-btn");
  check("P1. the row above the agents: Large, Compact and Grid, each a button with an aria-label and aria-pressed", !P.err && btns.length === 3 &&
    J(btns.map(b => b.getAttribute("data-view"))) === J(VIEWS3) && btns.every(b => b.type === "button" && b.getAttribute("aria-label") && b.hasAttribute("aria-pressed")) &&
    P.d.getElementById("agViewRow").nextElementSibling === P.d.querySelector(".agents-grid"), J([P.err, btns.length]));
  check("P2. Compact by default", viewOf(P.d) === "compact" && pressed(P.d) === "large:false,compact:true,grid:false", J([viewOf(P.d), pressed(P.d)]));
  const cards = q(P.d, "article.agent-card"), items = q(P.d, "#agList .ag-item");
  const same = cards.length === AGENT_ROWS.length && items.length === cards.length && items.every((it, i) => {
    const c = cards[i], a = it.querySelector("a.ag-link");
    return !!a && a.getAttribute("href") === c.querySelector("a.open-agent-btn").getAttribute("href") && it.querySelector(".ag-name").textContent === c.querySelector(".agent-name").textContent &&
      !!it.querySelector(".ag-icon svg") && !!it.querySelector(".ag-chev");
  });
  check("P3. one row per card, in the cards' order, each one link to where the card's Open Agent goes, with its icon, its name and a chevron", same, J(items.map(i => i.textContent)));
  const roleOf = t => { const it = P.d.querySelector('.ag-item[data-agent="' + t + '"] .ag-sub'); return it ? it.textContent : null; };
  check("P4. the one line is the Agents hub's role for the agent (none for one the hub has no role for)",
    roleOf("seo") === "Search & Rankings" && roleOf("broker") === "Deal Flow" && roleOf("rd") === "Research & Intel" && roleOf("executive") === "Cross-Agent Oversight" && roleOf("general") === null,
    J([roleOf("seo"), roleOf("broker"), roleOf("general")]));
  P.d.querySelector('.ag-view-btn[data-view="grid"]').click(); await settle(30);
  const put = P.calls.filter(c => c.method === "PUT");
  check("P5. Grid: shown at once, pressed, kept on this device and sent to the server", viewOf(P.d) === "grid" && pressed(P.d) === "large:false,compact:false,grid:true" &&
    P.store.bf_agents_view === "grid" && put.length === 1 && J(put[0].body) === J({ agents_card_view: "grid" }), J([viewOf(P.d), P.store.bf_agents_view, put.map(c => c.body)]));
  P.d.querySelector('.ag-view-btn[data-view="large"]').click(); await settle(30);
  check("P6. Large: the page's own cards", viewOf(P.d) === "large" && P.store.bf_agents_view === "large", viewOf(P.d));
  P.close();
  P = await page({ local: { bf_agents_view: "grid" }, prefs: { ok: true, agents_card_view: null } });
  const put2 = P.calls.filter(c => c.method === "PUT");
  check("P7. a reload: this device's Grid at once; the server holds none yet, so it is sent", viewOf(P.d) === "grid" && put2.length === 1 && J(put2[0].body) === J({ agents_card_view: "grid" }), J(put2.map(c => c.body)));
  P.close();
  P = await page({ local: { bf_agents_view: "grid" }, prefs: { ok: true, agents_card_view: "large" } });
  check("P8. the server's stored choice wins once it arrives (and becomes this device's copy); nothing is sent back", viewOf(P.d) === "large" && P.store.bf_agents_view === "large" &&
    P.calls.filter(c => c.method === "PUT").length === 0, J([viewOf(P.d), P.store.bf_agents_view]));
  P.close();
  P = await page({ local: { bf_agents_view: "huge" }, prefs: { ok: true } });
  check("P9. an unknown device value is ignored (Compact), and a server that says nothing about it changes nothing", viewOf(P.d) === "compact" && P.calls.filter(c => c.method === "PUT").length === 0, viewOf(P.d));
  P.close();
  P = await page({ agentsFail: true });
  check("P10. no agents (the page's message): the message stays shown, no list", viewOf(P.d) === "large" && q(P.d, "#agList .ag-item").length === 0 && !!P.d.querySelector(".agents-grid-message"), viewOf(P.d));
  P.close();
  P = await page({ storageThrows: true });
  check("P11. storage that throws (but for the sign-in token) breaks nothing: Compact, the list drawn", !P.err && viewOf(P.d) === "compact" && q(P.d, "#agList .ag-item").length === AGENT_ROWS.length, J([P.err, viewOf(P.d)]));
  P.close();

  console.log("\n══ D. the desktop ══");
  P = await page({ phone: false, local: { bf_agents_view: "grid" } });
  check("D1. above 760 px nothing is asked of the server", P.calls.filter(c => /\/api\/user\/preferences/.test(c.u)).length === 0, J(P.calls.map(c => c.u)));
  check("D2. and every rule that shows the row or the list is inside @media (max-width: 760px)",
    has(FILES[AGV], "    \".ag-view-row,.ag-list{display:none}\",\n    \"@media (max-width: 760px){\",\n") &&
    (FILES[AGV] || "").split("\"@media (max-width: 760px){\",")[0].replace(/\.ag-view-row,\.ag-list\{display:none\}/, "").indexOf("{display:") === -1);
  P.close();

  /* ══ W ══ */
  console.log("\n══ W. the page, sign-out and the shell ══");
  check("W1. ai-agents.html loads bf-agents-views.js after its cards' script", /\}\)\(\);\n<\/script>\n<!--[^\n]*-->\n<script src="\/scripts\/bf-agents-views\.js"><\/script>\n/.test(html));
  check("W2. sign-out clears bf_agents_view (bf-session.js PER_USER_LOCAL), and every storage use is in try/catch",
    has(FILES[SESSION], "    \"bf_hq_view\", \"bf_hq_orbit\",\n    \"bf_agents_view\",\n") &&
    has(FILES[AGV], "  function readView() { try { return window.localStorage.getItem(VIEW_KEY); } catch (e) { return null; } }") &&
    has(FILES[AGV], "  function writeView(v) { try { window.localStorage.setItem(VIEW_KEY, v); return true; } catch (e) { return false; } }") &&
    has(FILES[AGV], "    try { token = window.localStorage.getItem(\"bf_token\"); } catch (e) { token = null; }") && ((FILES[AGV] || "").match(/localStorage\./g) || []).length === 3);
  check("W3. the shell caches it", has(FILES[SW], "  \"/scripts/bf-agents-views.js\","));

  if (failures) { console.log("\nCHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("\nALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check crashed: " + (e && e.stack || e)); process.exit(1); });
