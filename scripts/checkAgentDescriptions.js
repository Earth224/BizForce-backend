"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkAgentDescriptions — every agent shows its one honest description.

   The one source is config/brain.js PLATFORM_KNOWLEDGE.agents (exported as
   AGENT_DESCRIPTIONS / agentDescription). The owner's live pages on Oct 28
   showed stored ai_agents.description text instead ("Etsy listing
   optimization, keyword research, pricing strategy, and competitor-shop
   analysis.", "omnichannel performance", "ROI forecasting", "Review-generation
   systems"). This holds every surface to the source, with a fixture whose
   rows still hold those stale texts.

   WHAT THIS PROVES
     C. Each canonical description is honest: no Etsy, omnichannel, ROI
        forecasting, review generation, forecasts, real-time, live,
        automatic or "marketplace intelligence"; and each specific claim
        (Stock & Margin, tag limits you enter, tracked links, reviews you
        paste in, Bluesky from your own account) is backed by the page or
        route that does it. Every agent page has a description.
     S. server.js, lifted into a vm against a fake database whose rows hold
        the stale texts: GET /api/agents and GET /api/agents/:type return the
        canonical description for every type; seeding writes description
        NULL; POST /api/agents and PUT /api/agents/:id refuse a description
        and write nothing, while the display name still changes.
     R. The roster every agent and the Oracle are told carries each canonical
        description, word for word.
     F. The frontend: every agent page's subtitle and every index.html card is
        exactly the canonical text (scripts/buildAgentDescriptions.js would
        change nothing); scripts/agent-descriptions.js is the canonical map;
        no agent page reads agent.description or rewrites its subtitle; and
        ai-agents.html, run in jsdom against the lifted GET /api/agents and
        the stale rows, draws every card with the canonical text beside the
        display name.
     E. No surface says "Etsy" for the Storefront agent.
     M. Migration 153 sets every stored description to NULL and adds a CHECK
        that keeps it NULL; 153 is the next free number.
     Z. No network.

   MUTATE=<name> edits the sources in memory; MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR, never a catch.
   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const net = require("net");
const dns = require("dns");
const Module = require("module");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkAgentDescriptions: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkAgentDescriptions: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const STALE = {
  etsy: "Etsy listing optimization, keyword research, pricing strategy, and competitor-shop analysis.",
  store: "Multi-store and e-commerce strategy: inventory, omnichannel performance, and conversion optimization.",
  influencer: "Creator outreach, partnership offers, campaign plans, and ROI forecasting for influencer marketing.",
  reputation: "Review-generation systems, response templates, and brand trust and authority plans."
};

const MUTATIONS = {
  // GET /api/agents passes the stored description through again
  "stored-description-rendered": [["SRC", "        page_url: agentPageUrl(agent && agent.type),\n        description: require(\"./config/brain\").agentDescription(agent && agent.type)\n",
    "        page_url: agentPageUrl(agent && agent.type)\n"]],
  // GET /api/agents/:type returns the row as stored
  "stored-description-by-type": [["SRC", "    return res.json({ agent: Object.assign({}, data, { description: require(\"./config/brain\").agentDescription(data.type) }) });\n",
    "    return res.json({ agent: data });\n"]],
  // an agent page shows agent.description over its subtitle again
  "page-renders-stored": [["FE:etsy-agent.html", "          /* The subtitle stays as written: it is this agent's one honest\n",
    "          if (typeof agent.description === \"string\" && agent.description.trim()) {\n" +
    "            var subtitleEl = document.querySelector(\".agent-subtitle\");\n" +
    "            if (subtitleEl) { subtitleEl.textContent = agent.description; }\n" +
    "          }\n          /* The subtitle stays as written: it is this agent's one honest\n"]],
  // ai-agents.html's card shows agent.description again
  "directory-renders-stored": [["FE:ai-agents.html", "      description.textContent = Object.prototype.hasOwnProperty.call(descriptions, type) ? descriptions[type] : \"\";\n",
    "      description.textContent = agent.description || \"\";\n"]],
  // "Etsy" is back on the Storefront card on the home page
  "etsy-on-storefront-card": [["FE:index.html", "        <h3>Storefront Agent</h3>\n        <p>Listing copy, keyword candidates measured against the tag limits you enter, and pricing arithmetic on figures you supply.</p>\n",
    "        <h3>Storefront Agent</h3>\n        <p>" + STALE.etsy + "</p>\n"]],
  // the Store agent claims omnichannel performance again, at the source
  "store-overclaim-restored": [["BRAIN", "description: \"Stock & Margin from your own inventory records, BizForce Market listings proposed for your approval, and store, conversion and launch plans.\" },\n",
    "description: \"" + STALE.store + "\" },\n"]],
  // the Influencer agent promises ROI forecasting again
  "influencer-roi-restored": [["BRAIN", "description: \"Creator outreach, partnership offers, and influencer campaign plans. It finds no creators and measures no results.\" },\n",
    "description: \"" + STALE.influencer + "\" },\n"]],
  // seeding stores a description again
  "seed-writes-description": [["SRC", "            description: null,\n            active: true,\n            settings: {},\n",
    "            description: \"\",\n            active: true,\n            settings: {},\n"]],
  // PUT /api/agents/:id stores a member's description again
  "put-stores-description": [["SRC", "    if (Object.prototype.hasOwnProperty.call(req.body, \"description\")) {\n      return res.status(400).json({ error: AGENT_DESCRIPTION_FIXED, field: \"description\" });\n    }\n\n    if (Object.prototype.hasOwnProperty.call(req.body, \"settings\")) {\n",
    "    if (Object.prototype.hasOwnProperty.call(req.body, \"description\")) {\n      updates.description = safeText(req.body.description, 500);\n    }\n\n    if (Object.prototype.hasOwnProperty.call(req.body, \"settings\")) {\n"]],
  // the migration clears only the Storefront rows
  "migration-clears-one-type": [["MIG", " WHERE description IS NOT NULL;\n", " WHERE description IS NOT NULL AND type = 'etsy';\n"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const lf = t => t.replace(/\r\n/g, "\n");
const clone = v => v === undefined ? undefined : JSON.parse(JSON.stringify(v));

/* ── the sources, mutated in memory ───────────────────────────────────────── */
const FE_FILES = ["index.html", "ai-agents.html", "agents-hub.html", "scripts/agent-descriptions.js", "scripts/termaximus-guide.js",
  "ads-agent.html", "broker-agent.html", "community-agent.html", "email-agent.html", "etsy-agent.html", "executive-agent.html", "influencer-agent.html",
  "operations-agent.html", "publicist-agent.html", "rd-agent.html", "reputation-agent.html", "store-agent.html", "vertical-marketing-agent.html",
  "agents/analytics.html", "agents/content.html", "agents/sales.html", "agents/seo.html", "agents/social.html"];
const SOURCES = {
  SRC: lf(fs.readFileSync(path.join(REPO, "server.js"), "utf8")),
  BRAIN: lf(fs.readFileSync(path.join(REPO, "config/brain.js"), "utf8")),
  MIG: lf(fs.readFileSync(path.join(REPO, "supabase/migrations/153_agent_descriptions_cleared.sql"), "utf8"))
};
FE_FILES.forEach(f => { const p = path.join(FRONTEND, f); SOURCES["FE:" + f] = fs.existsSync(p) ? lf(fs.readFileSync(p, "utf8")) : null; });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [where, from, to] of edits) SOURCES[where] = s.replaceOnce(SOURCES[where], from, to, MUTATE + " in " + where);
  console.log("\n!! MUTATION: " + MUTATE);
}
const SRC = SOURCES.SRC;
const FE = f => SOURCES["FE:" + f];

function loadLib(rel, text) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(text, file);
  return m.exports;
}
let BRAIN, BUILD;
try {
  BRAIN = loadLib("config/brain.js", SOURCES.BRAIN);
  BUILD = require("./buildAgentDescriptions");
} catch (e) {
  console.log("    FAIL  config/brain.js or scripts/buildAgentDescriptions.js could not be loaded: " + e.message);
  process.exit(1);
}
const AGENTS = BRAIN.PLATFORM_KNOWLEDGE.agents;
const CANON = BRAIN.AGENT_DESCRIPTIONS;
const PAGES = BUILD.agentPages(SRC);
const TYPES = Object.keys(PAGES);
const nameOf = t => (AGENTS.find(a => a.key === t) || {}).name;
const uncomment = code => code.replace(/<!--[\s\S]*?-->/g, " ").replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
const visibleText = html => html.replace(/<script[\s\S]*?<\/script>/g, " ").replace(/<style[\s\S]*?<\/style>/g, " ").replace(/<!--[\s\S]*?-->/g, " ")
  .replace(/<[^>]+>/g, " ").replace(/&amp;/g, "&").replace(/\s+/g, " ");

/* ── the fake database: one stale row per type ────────────────────────────── */
const USER = "aaaaaaaa-0000-4000-8000-0000000000aa";
const NEW_USER = "bbbbbbbb-0000-4000-8000-0000000000bb";
function staleRows() {
  return TYPES.map((t, i) => ({ id: "row-" + t, user_id: USER, type: t, display_name: t === "etsy" ? "Etsy Agent" : nameOf(t),
    description: STALE[t] || "An old stored description for " + t + ".", active: true, settings: {}, tasks_completed: i, estimated_roi: 0,
    created_at: "2026-07-17T00:00:" + String(i).padStart(2, "0") + ".000Z", updated_at: "2026-07-17T00:00:00.000Z" }));
}
function fakeDb(rows) {
  const db = { rows: rows.map(clone), writes: [] };
  function from(table) {
    if (table !== "ai_agents") throw new Error("unplanned table " + table);
    const q = { op: "select", filters: [], payload: null, single: null };
    const run = () => {
      const hit = db.rows.filter(r => q.filters.every(([c, v]) => r[c] === v));
      if (q.op === "insert") {
        const list = Array.isArray(q.payload) ? q.payload : [q.payload];
        db.writes.push({ op: "insert", rows: clone(list) });
        const made = list.map((p, i) => Object.assign({ id: "new-" + (db.rows.length + i) }, clone(p)));
        db.rows.push(...made);
        return { data: q.single ? made[0] : made, error: null };
      }
      if (q.op === "update") {
        db.writes.push({ op: "update", payload: clone(q.payload), filters: clone(q.filters) });
        hit.forEach(r => Object.assign(r, clone(q.payload)));
        return { data: q.single ? clone(hit[0] || null) : clone(hit), error: hit.length || !q.single ? null : { code: "PGRST116" } };
      }
      const out = hit.slice().sort((a, b) => String(a.created_at) < String(b.created_at) ? -1 : 1).map(clone);
      if (q.single === "maybe") return { data: out[0] || null, error: null };
      if (q.single === "single") return { data: out[0] || null, error: out.length ? null : { code: "PGRST116" } };
      return { data: out, error: null };
    };
    const b = {
      select() { return b; }, order() { return b; },
      eq(c, v) { q.filters.push([c, v]); return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; },
      maybeSingle() { q.single = "maybe"; return Promise.resolve(run()); },
      single() { q.single = "single"; return Promise.resolve(run()); },
      then(res, rej) { return Promise.resolve(run()).then(res, rej); }
    };
    return b;
  }
  db.client = { from };
  return db;
}

/* ── server.js's four agent routes, lifted ────────────────────────────────── */
function routeText(method, route) {
  const sig = String.fromCharCode(10) + "app." + method + "(\"" + route + "\"";
  const start = SRC.indexOf(sig) + 1;
  if (start < 1) throw new Error(method.toUpperCase() + " " + route + " not found");
  if (SRC.indexOf(sig, start + 1) !== -1) throw new Error(method.toUpperCase() + " " + route + " is defined twice");
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function (req, res, next)", start)));
  if (SRC.slice(end, end + 2) !== ");") throw new Error(method.toUpperCase() + " " + route + " did not end where expected");
  return SRC.slice(start, end + 2);
}
const fixedDef = (/^var AGENT_DESCRIPTION_FIXED = [\s\S]*?;\n/m.exec(SRC) || [""])[0];
let LIFTED;
try {
  if (!fixedDef) throw new Error("AGENT_DESCRIPTION_FIXED not found");
  LIFTED = new vm.Script(fixedDef + "\n" + [["get", "/api/agents"], ["get", "/api/agents/:type"], ["post", "/api/agents"], ["put", "/api/agents/:id"]]
    .map(r => routeText(r[0], r[1])).join("\n\n"));
} catch (e) {
  console.log("    FAIL  the agent routes could not be lifted from server.js: " + e.message);
  process.exit(1);
}
const LOGS = [];
function build(rows, opts) {
  opts = opts || {};
  const db = fakeDb(rows);
  const routes = {};
  const mount = m => function (p) { routes[m + " " + p] = arguments[arguments.length - 1]; };
  const ctx = {
    supabase: db.client, Object, Array, String, Boolean, JSON, Promise, Date, Number,
    app: { get: mount("get"), post: mount("post"), put: mount("put") },
    console: { log() {}, warn() {}, error() { LOGS.push([].slice.call(arguments).map(String).join(" ")); } },
    require: p => p === "./config/brain" ? BRAIN : (() => { throw new Error("unplanned require " + p); })(),
    requireAuth() {}, requireActiveSubscription() {},
    nowIso: () => "2026-10-28T12:00:00.000Z",
    getUserPlan: async () => ({ active: opts.active !== false, plan: "pro", config: { allowedAgents: TYPES.slice() } }),
    agentDisplayName: t => nameOf(t) || t,
    agentPageUrl: t => PAGES[t] || null,
    AGENT_SYSTEM_PROMPTS: TYPES.reduce((o, t) => { o[t] = "prompt"; return o; }, {}),
    enforceAgentLimit: async () => ({ allowed: true }),
    safeText: (v, n) => v == null ? "" : String(v).trim().slice(0, n)
  };
  vm.createContext(ctx);
  LIFTED.runInContext(ctx);
  async function hit(key, user, opts2) {
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = clone(x); return this; } };
    await routes[key]({ user: { id: user }, body: (opts2 && opts2.body) || {}, params: (opts2 && opts2.params) || {}, query: {} }, res,
      e => { res.code = 500; res.body = { error: String(e && e.message || e) }; });
    return res;
  }
  return { db, hit };
}

(async function main() {
  /* ── C. each canonical description is honest ───────────────────────────── */
  console.log("\n══ C. the canonical descriptions (config/brain.js) ══");
  const BANNED = /\betsy\b|omni-?channel|\bROI\b|forecast|review[- ]generation|real[- ]?time|\blive\b|automatic|instant|marketplace intelligence|competitor[- ]shop|guarantee/i;
  check("C1. every agent page's type has a description, and every description is one or two plain sentences under 200 characters",
    TYPES.every(t => typeof CANON[t] === "string" && CANON[t].length > 20 && CANON[t].length < 200 && /\.$/.test(CANON[t])), TYPES.filter(t => !CANON[t]).join(","));
  const bannedHits = Object.keys(CANON).filter(t => BANNED.test(CANON[t]));
  check("C2. no description says Etsy, omnichannel, ROI, forecast, review generation, real-time, live, automatic, instant, marketplace intelligence or guarantee",
    bannedHits.length === 0, bannedHits.map(t => t + ": " + CANON[t]).join(" | "));
  check("C3. Storefront: listing copy, keyword candidates against the tag limits the member enters, pricing arithmetic — and the page and route ask for those limits",
    /^Listing copy, keyword candidates measured against the tag limits you enter, and pricing arithmetic on figures you supply\.$/.test(CANON.etsy) &&
    /"label": "Tags allowed per listing"/.test(FE("etsy-agent.html")) && /"label": "Max characters per tag"/.test(FE("etsy-agent.html")) &&
    /readSellerTagLimit\(req\.body, "max_tags", 100\)/.test(SRC) && /readSellerTagLimit\(req\.body, "max_tag_length", 200\)/.test(SRC), CANON.etsy);
  check("C4. Store: Stock & Margin from the member's own inventory and proposed listings, no omnichannel — the tool and the proposals route exist",
    /^Stock & Margin from your own inventory records, BizForce Market listings proposed for your approval/.test(CANON.store) && !/omni/i.test(CANON.store) &&
    /"label": "Stock & Margin"/.test(FE("store-agent.html")) && SRC.indexOf('app.post("/api/agents/store/stock-margin"') !== -1 &&
    SRC.indexOf('app.post("/api/agents/store/generate-proposals"') !== -1, CANON.store);
  check("C5. Influencer: no ROI forecasting, and it says it finds no creators and measures no results",
    !/ROI|forecast/i.test(CANON.influencer) && /It finds no creators and measures no results\.$/.test(CANON.influencer), CANON.influencer);
  check("C6. Reputation: no review-generation systems; review requests and replies to reviews pasted in, as its two tools are",
    !/generation/i.test(CANON.reputation) && /^Review requests, replies to reviews you paste in/.test(CANON.reputation) && /It reads no review site\.$/.test(CANON.reputation) &&
    /"label": "Review Request"/.test(FE("reputation-agent.html")) && /"label": "The review"/.test(FE("reputation-agent.html")), CANON.reputation);
  check("C7. Analytics: figures the member enters and their own tracked links, reading no website analytics or revenue data; Arrivals Ledger exists",
    /on figures you enter, plus arrivals on your own tracked links\. It reads no website analytics or revenue data\.$/.test(CANON.analytics) &&
    /"label": "Arrivals Ledger"/.test(FE("agents/analytics.html")) && SRC.indexOf('app.post("/api/agents/analytics/arrivals"') !== -1, CANON.analytics);
  check("C8. Social: Bluesky posts from the member's own connected account — the Connect Bluesky card and route exist",
    /Bluesky posts from your own connected account\.$/.test(CANON.social) && /<h2 class="section-label">Connect Bluesky<\/h2>/.test(FE("agents/social.html")) &&
    SRC.indexOf('app.post("/api/social/bluesky/connect"') !== -1, CANON.social);

  /* ── S. the server returns the canonical text, never the stored one ─────── */
  console.log("\n══ S. GET, seed, POST and PUT /api/agents against stale rows ══");
  let b = build(staleRows());
  let r = await b.hit("get /api/agents", USER);
  const list = (r.body && r.body.agents) || [];
  const wrong = list.filter(a => a.description !== CANON[a.type]);
  check("S1. GET /api/agents: all " + TYPES.length + " rows, each with the canonical description, though every row stores a stale one",
    r.code === 200 && list.length === TYPES.length && wrong.length === 0, wrong.map(a => a.type + ": " + a.description).join(" | ") || r.code);
  check("S2. …the Storefront row says no Etsy, and the stale Etsy, omnichannel, ROI and review-generation texts appear nowhere in the response",
    !/etsy/i.test((list.find(a => a.type === "etsy") || {}).description || "Etsy") &&
    Object.values(STALE).every(t => JSON.stringify(r.body).indexOf(t) === -1));
  check("S3. …the display name is still the row's own (the member's to change)", (list.find(a => a.type === "etsy") || {}).display_name === "Etsy Agent");
  let bad = [];
  for (const t of TYPES) {
    const one = await b.hit("get /api/agents/:type", USER, { params: { type: t } });
    if (!(one.code === 200 && one.body.agent && one.body.agent.description === CANON[t])) bad.push(t + ": " + (one.body && one.body.agent && one.body.agent.description));
  }
  check("S4. GET /api/agents/:type: the canonical description for every type", bad.length === 0, bad.join(" | "));
  b = build([]);
  r = await b.hit("get /api/agents", NEW_USER);
  const seeded = (b.db.writes.find(w => w.op === "insert") || { rows: [] }).rows;
  check("S5. seeding a new member writes one row per agent, each with description NULL (no text that could go stale)",
    seeded.length === TYPES.length && seeded.every(x => x.description === null), JSON.stringify(seeded.map(x => x.description)).slice(0, 200));
  check("S6. …and the seeded rows are served with the canonical descriptions", r.code === 200 && (r.body.agents || []).every(a => a.description === CANON[a.type]) && (r.body.agents || []).length === TYPES.length);
  b = build(staleRows());
  r = await b.hit("post /api/agents", USER, { body: { type: "etsy", display_name: "My shop helper", description: STALE.etsy } });
  check("S7. POST /api/agents with a description: 400, nothing written", r.code === 400 && r.body.field === "description" && /can't be changed/.test(r.body.error) && b.db.writes.length === 0,
    r.code + " " + JSON.stringify(r.body));
  r = await b.hit("post /api/agents", USER, { body: { type: "etsy", display_name: "My shop helper" } });
  const ins = (b.db.writes.find(w => w.op === "insert") || { rows: [{}] }).rows[0];
  check("S8. POST /api/agents without one: the row stores description NULL and the member's display name", r.code === 201 && ins.description === null && ins.display_name === "My shop helper",
    r.code + " " + JSON.stringify(ins));
  b = build(staleRows());
  r = await b.hit("put /api/agents/:id", USER, { params: { id: "row-store" }, body: { description: STALE.store } });
  check("S9. PUT /api/agents/:id with a description: 400, nothing written", r.code === 400 && r.body.field === "description" && b.db.writes.length === 0, r.code + " " + JSON.stringify(r.body));
  r = await b.hit("put /api/agents/:id", USER, { params: { id: "row-store" }, body: { display_name: "Shop Desk" } });
  const upd = (b.db.writes.find(w => w.op === "update") || {}).payload || {};
  check("S10. PUT with only a display name: it changes, and the update carries no description",
    r.code === 200 && upd.display_name === "Shop Desk" && !Object.prototype.hasOwnProperty.call(upd, "description"), JSON.stringify(upd));

  /* ── R. the roster agents and the Oracle are told ───────────────────────── */
  console.log("\n══ R. the roster in every agent's and the Oracle's prompt ══");
  const prompt = BRAIN.buildAgentSystemPrompt("AGENT", {}, {}, []);
  const missing = TYPES.filter(t => prompt.indexOf("- " + nameOf(t) + " (" + t + "): " + CANON[t]) === -1);
  check("R1. the roster line of every agent carries its canonical description word for word", missing.length === 0, missing.join(","));
  check("R2. none of the stale texts is in the prompt", Object.values(STALE).every(t => prompt.indexOf(t) === -1));

  /* ── F. the frontend ────────────────────────────────────────────────────── */
  console.log("\n══ F. the frontend shows the canonical text ══");
  const planned = BUILD.plan({ agents: AGENTS, server: SRC, read: rel => FE(rel) });
  const stale = Object.keys(planned.files).filter(rel => planned.files[rel] !== FE(rel));
  check("F1. every agent page subtitle, every index.html card and scripts/agent-descriptions.js are exactly what buildAgentDescriptions writes from config/brain.js",
    planned.problems.length === 0 && stale.length === 0, planned.problems.concat(stale).join(" | "));
  const subtitleOf = rel => { const m = /<p class="agent-subtitle">([^<]*)<\/p>/.exec(FE(rel) || ""); return m ? m[1].replace(/&amp;/g, "&") : null; };
  const offPages = TYPES.filter(t => subtitleOf(PAGES[t]) !== CANON[t]);
  check("F2. each of the " + TYPES.length + " agent pages' subtitle reads its canonical description", offPages.length === 0, offPages.join(","));
  const readers = TYPES.filter(t => { const code = uncomment(FE(PAGES[t]).replace(/<style[\s\S]*?<\/style>/g, " ")); return /agent\.description|querySelector\(["']\.agent-subtitle["']\)/.test(code); });
  check("F3. no agent page reads agent.description or rewrites its subtitle", readers.length === 0, readers.join(","));
  const mapCtx = { window: {} }; vm.createContext(mapCtx);
  let mapOk = false;
  try { vm.runInContext(FE("scripts/agent-descriptions.js"), mapCtx); mapOk = JSON.stringify(mapCtx.window.BF_AGENT_DESCRIPTIONS) === JSON.stringify(CANON); } catch (e) { mapOk = false; }
  check("F4. scripts/agent-descriptions.js defines window.BF_AGENT_DESCRIPTIONS equal to config/brain.js's map", mapOk);
  check("F5. ai-agents.html loads scripts/agent-descriptions.js before its card script, and reads no agent.description",
    /<script src="\/scripts\/agent-descriptions\.js"><\/script>\n<script>\n\(function renderLiveAgents\(\)/.test(FE("ai-agents.html")) &&
    !/agent\.description/.test(uncomment(FE("ai-agents.html"))));

  // ai-agents.html in jsdom, fed by the lifted GET /api/agents over the stale rows.
  const { JSDOM } = require("jsdom");
  b = build(staleRows());
  const html = FE("ai-agents.html");
  const markup = html.replace(/<script[\s\S]*?<\/script>/g, "");
  const dom = new JSDOM(markup, { runScripts: "outside-only", url: "https://bizforce.example/ai-agents.html" });
  const w = dom.window;
  w.localStorage.setItem("bf_token", "t");
  w.fetch = function (url) {
    const p = String(url).replace(/^https?:\/\/[^/]+/, "");
    const pr = p === "/api/agents" ? b.hit("get /api/agents", USER).then(res => ({ ok: res.code === 200, status: res.code, json: () => Promise.resolve(res.body) }))
      : Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({}) });
    pr.catch(() => {});
    return pr;
  };
  w.eval(FE("scripts/agent-descriptions.js"));
  const inline = (/<script>\n(\(function renderLiveAgents\(\) \{[\s\S]*?)<\/script>/.exec(html) || ["", ""])[1];
  try { w.eval(inline); } catch (e) { check("F6. ai-agents.html's card script runs", false, e.message); }
  for (let i = 0; i < 40; i++) await new Promise(res => setImmediate(res));
  const cards = [...w.document.querySelectorAll(".agent-card")].map(c => ({
    type: (/agent-card--([a-z_]+)/.exec(c.className) || [])[1], name: (c.querySelector(".agent-name") || {}).textContent, text: (c.querySelector(".agent-description") || {}).textContent }));
  const offCards = cards.filter(c => c.text !== CANON[c.type]);
  check("F6. ai-agents.html draws all " + TYPES.length + " cards, each with the canonical description beside the display name, over stale stored rows",
    cards.length === TYPES.length && offCards.length === 0 && cards.every(c => c.name), (cards.length + " cards; ") + offCards.map(c => c.type + ": " + c.text).join(" | "));
  check("F7. the directory never shows a stale text", Object.values(STALE).every(t => w.document.body.textContent.indexOf(t) === -1));
  {
    // The page on its own: an answer that still carries the stored descriptions (an older server) changes nothing.
    const dom2 = new JSDOM(markup, { runScripts: "outside-only", url: "https://bizforce.example/ai-agents.html" });
    const w2 = dom2.window;
    w2.localStorage.setItem("bf_token", "t");
    const raw = staleRows().map(x => Object.assign({}, x, { page_url: PAGES[x.type] }));
    w2.fetch = () => { const pr = Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ agents: clone(raw) }) }); pr.catch(() => {}); return pr; };
    w2.eval(FE("scripts/agent-descriptions.js"));
    try { w2.eval(inline); } catch (e) { /* counted below */ }
    for (let i = 0; i < 40; i++) await new Promise(res => setImmediate(res));
    const cards2 = [...w2.document.querySelectorAll(".agent-card")].map(c => ({
      type: (/agent-card--([a-z_]+)/.exec(c.className) || [])[1], text: (c.querySelector(".agent-description") || {}).textContent }));
    check("F8. fed the stored rows as they are (stale descriptions included), ai-agents.html still draws only the canonical text",
      cards2.length === TYPES.length && cards2.every(c => c.text === CANON[c.type]) && Object.values(STALE).every(t => w2.document.body.textContent.indexOf(t) === -1),
      cards2.filter(c => c.text !== CANON[c.type]).map(c => c.type + ": " + c.text).join(" | ") || cards2.length);
  }

  /* ── E. no Etsy for the Storefront agent ────────────────────────────────── */
  console.log("\n══ E. no surface says Etsy for the Storefront agent ══");
  const sfCard = (/<h3>Storefront Agent<\/h3>\s*<p>([^<]*)<\/p>/.exec(FE("index.html")) || ["", ""])[1];
  const sfDir = (cards.find(c => c.type === "etsy") || {}).text || "";
  const sfLine = (prompt.split("\n").find(l => l.indexOf("(etsy):") !== -1) || "");
  check("E1. Storefront: the canonical text, the page's visible text, the home card, the directory card and the roster line say no Etsy",
    !/etsy/i.test(CANON.etsy) && !/etsy/i.test(visibleText(FE("etsy-agent.html"))) && !!sfCard && !/etsy/i.test(sfCard) && !!sfDir && !/etsy/i.test(sfDir) &&
    !!sfLine && !/etsy/i.test(sfLine.replace("(etsy)", "")), [sfCard, sfDir, sfLine].join(" | "));
  const guide = FE("scripts/termaximus-guide.js");
  const sfGuide = (/"etsy-agent\.html"\s*:\s*\[[\s\S]*?\n\s{4}\]/.exec(guide) || [""])[0];
  check("E2. the Termaximus Guide's Storefront tips say no Etsy", !!sfGuide && !/etsy/i.test(sfGuide.replace(/"etsy-agent\.html"/g, "")), sfGuide.slice(0, 120));

  /* ── M. migration 153 ───────────────────────────────────────────────────── */
  console.log("\n══ M. migration 153 ══");
  const sql = SOURCES.MIG.replace(/--[^\n]*/g, "");
  check("M1. every stored description is set to NULL, with no other condition",
    /UPDATE public\.ai_agents\s+SET description = NULL\s+WHERE description IS NOT NULL;/.test(sql) && (sql.match(/UPDATE /g) || []).length === 1, sql.trim().slice(0, 200));
  check("M2. a CHECK keeps it NULL from now on", /ADD CONSTRAINT ai_agents_description_not_stored CHECK \(description IS NULL\);/.test(sql));
  const migs = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d{3}_/.test(f)).sort();
  check("M3. 153 is the next free number, used once", migs.filter(f => f.indexOf("153_") === 0).length === 1 &&
    migs.indexOf("153_agent_descriptions_cleared.sql") === migs.indexOf("152_member_social_connections.sql") + 1, migs.slice(-3).join(","));

  console.log("\n══ Z. no network ══");
  check("Z. zero sockets and DNS lookups", NETWORK.length === 0, JSON.stringify(NETWORK));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check threw: " + (e && e.stack || e)); process.exit(1); });
