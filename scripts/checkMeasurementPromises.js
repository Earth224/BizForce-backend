"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkMeasurementPromises — no task promises a measurement nobody takes.

   Twelve task-type instructions asked the model for things the platform never
   reads: a store's load speed, keywords "with low competition", a "market size
   estimate", "expected lift estimates", "projected revenue", live traffic. They
   now ask only for what the model can do from the user's input and profile,
   say what is not read, and name the real tool where one exists. Beside them:
   the Analytics roster line, the social caveat's unit on Bluesky, migration
   068's policy (production has none), and one SEO meta reader.

   WHAT THIS PROVES
     1. Each of the twelve: an instruction of its own, none of the five removed
        phrases, its own "not read" statement, and the real tool named where
        one exists. Every other instruction is exactly as it was at 9d5c968,
        but for four that differ only by their opening, swapped by name in
        RENAMED_SINCE_PRE (the Etsy agent renamed to the Storefront Agent, Oct
        13 2026); pricing_strategy also carries one named change,
        CHANGED_SINCE_PRE (it no longer claims to hold the user's costs, Oct
        16 2026); any further change to one of those four fails.
     2. The Analytics roster line no longer promises traffic and conversion
        review and says what it does not read.
     3. social/post: the caveat and the provenance line say "grapheme" on a
        Bluesky result and "character" on any other.
     4. Migration 068 creates no policy, and says production has none.
     5. seo/audit's measured output is unchanged from 9d5c968 on test pages,
        with absent and empty meta tags still told apart.

   MUTATE=<name> edits the source in memory. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), vm = require("vm"), path = require("path"), net = require("net"), dns = require("dns");
const { execSync } = require("child_process");
const { decodeHTML, decodeHTMLAttribute } = require("entities");
const s = require("./_shared");

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkMeasurementPromises: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkMeasurementPromises: no network"); };

const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const SERVER = "server.js", BRAIN = "config/brain.js", M068 = "supabase/migrations/068_bsky_leads.sql";
const PRE = "9d5c968";

const MUTATIONS = {
  // the store audit promises load speed again
  "restore-load-speed": [[SERVER, "the homepage, product pages, checkout, mobile layout and trust signals, with what to look at",
    "the homepage, product pages, checkout, mobile layout, trust signals and load speed, with what to look at"]],
  // keyword research promises low competition again
  "restore-low-competition": [[SERVER, "20 keyword candidates written the way a buyer would search",
    "20 high-intent keywords with low competition"]],
  // 068 creates the read policy again
  "restore-068-policy": [[M068, "alter table public.bsky_leads enable row level security;\n",
    "alter table public.bsky_leads enable row level security;\n\ndo $$\nbegin\n  if not exists (select 1 from pg_policy where polname = 'authenticated can read leads' and polrelid = 'public.bsky_leads'::regclass) then\n    create policy \"authenticated can read leads\" on public.bsky_leads for select to authenticated using (true);\n  end if;\nend $$;\n"]],
  // the caveat says character on Bluesky
  "character-for-bluesky": [[SERVER, "\"that move with the client and the layout. The \" + (spec.unit === \"graphemes\" ? \"grapheme\" : \"character\") + \" maximum is the enforced one.\"",
    "\"that move with the client and the layout. The character maximum is the enforced one.\""]],
  // a renamed instruction changes beyond its swapped opening
  "renamed-further-change": [[SERVER, "and a 30-day improvement plan.", "and a 60-day improvement plan."]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
[SERVER, BRAIN, M068].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}
const SRC = FILES[SERVER];
const PRE_SRC = execSync("git show " + PRE + ":server.js", { cwd: REPO, maxBuffer: 1 << 26 }).toString("utf8").replace(/\r\n/g, "\n");

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}

/* ── the instructions, read as the server reads them ───────────────────── */
function instructions(src) {
  const start = src.indexOf("var taskInstructions = {");
  const end = src.indexOf("\n};", start);
  const ctx = {};
  vm.createContext(ctx);
  vm.runInContext(src.slice(start, end + 3) + "\nthis.t = taskInstructions;", ctx);
  return ctx.t;
}
const NOW_T = instructions(SRC), PRE_T = instructions(PRE_SRC);

/* The Etsy agent was renamed to the Storefront Agent (Oct 13 2026): these four
   instructions differ from PRE only by their opening, named here as [before,
   after]. Nothing else in them may change. */
const RENAMED_SINCE_PRE = {
  etsy_listing:     ["Optimize an Etsy listing: SEO-rich title (140 chars), 13 keyword tags,",
                     "Optimize a store or marketplace listing: a search-rich title and keyword tags within the limits the seller says their platform sets,"],
  shop_audit:       ["Conduct an Etsy shop audit:", "Conduct an online shop audit:"],
  pricing_strategy: ["Build an Etsy pricing strategy:", "Build a pricing strategy:"],
  etsy_store_plan:  ["Build an Etsy shop strategy:", "Build an online shop strategy:"]
};

/* NAMED BEFORE → AFTER, applied after the opening swap above. Nothing else in
   these may change.
   pricing_strategy (Stock & Margin block, Oct 16 2026): it said "This platform
   holds the user's own costs and prices", but the task never reads
   inventory_items; it now says it works from the request and the Business
   Profile, and marks a missing figure [FIGURE NEEDED]. */
const CHANGED_SINCE_PRE = {
  pricing_strategy: ["This platform holds the user's own costs and prices but sees no competitor's, so present",
                     "Work only from the costs and prices given in the request and the Business Profile: this task reads no inventory, catalogue or sales records and sees no competitor's prices, so mark a cost or price the user has not given as [FIGURE NEEDED], and present"]
};

const REMOVED = ["load speed", "low competition", "market size estimate", "expected lift estimates", "projected revenue"];
const TWELVE = {
  store_audit:      { notRead: "This platform does not fetch or open the store and measures nothing about it", tool: "seo/audit" },
  conversion_audit: { notRead: "This platform reads no analytics, traffic, checkout or conversion data", tool: "analytics/funnel" },
  analytics_report: { notRead: "This platform reads no website analytics, traffic, sales or revenue data", tool: "analytics/kpi-review" },
  kpi_review:       { notRead: "This platform reads no KPI data", tool: "analytics/kpi-review" },
  growth_analysis:  { notRead: "This platform reads no traffic, sales, revenue or customer data", tool: "analytics/funnel" },
  funnel_analysis:  { notRead: "This platform reads no traffic, checkout or conversion data", tool: "analytics/funnel" },
  revenue_forecast: { notRead: "This platform reads no sales, revenue or pipeline data", tool: "analytics/kpi-review" },
  keyword_research: { notRead: "This platform reads no search engine or marketplace data", tool: "rd/demand-signals" },
  market_research:  { notRead: "This platform reads no market data", tool: "rd/demand-signals" },
  trend_analysis:   { notRead: "This platform reads no trend, search or market data", tool: "rd/demand-signals" },
  roi_forecast:     { notRead: "This platform reads no creator, audience, engagement or sales data", tool: null },
  efficiency_audit: { notRead: "This platform reads no operations, systems or time data", tool: null }
};

(async function main() {
  /* ── 1. the twelve ────────────────────────────────────────────────────── */
  console.log("\n══ 1. the twelve instructions ══");
  for (const [type, want] of Object.entries(TWELVE)) {
    const text = NOW_T[type];
    check(type + ": has an instruction of its own", typeof text === "string" && text.length > 100, typeof text);
    const found = REMOVED.filter(p => String(text).toLowerCase().indexOf(p) !== -1);
    check(type + ": none of the removed phrases", found.length === 0, found.join(", "));
    check(type + ": says what is not read", String(text).indexOf(want.notRead) !== -1, String(text).slice(0, 160));
    if (want.tool) check(type + ": names the real tool (" + want.tool + ")", String(text).indexOf("(" + want.tool + ")") !== -1);
  }
  const everyText = Object.values(NOW_T).join(" ").toLowerCase();
  check("no instruction anywhere carries a removed phrase", REMOVED.every(p => everyText.indexOf(p) === -1), REMOVED.filter(p => everyText.indexOf(p) !== -1).join(", "));
  const others = Object.keys(PRE_T).filter(k => !Object.prototype.hasOwnProperty.call(TWELVE, k) && !Object.prototype.hasOwnProperty.call(RENAMED_SINCE_PRE, k));
  const changed = others.filter(k => NOW_T[k] !== PRE_T[k]);
  check("every other instruction is exactly as it was at " + PRE + " (" + others.length + ")", changed.length === 0, changed.join(", "));
  for (const [k, [before, after]] of Object.entries(RENAMED_SINCE_PRE)) {
    const pre = PRE_T[k];
    const once = typeof pre === "string" && pre.split(before).length === 2;
    const i = once ? pre.indexOf(before) : -1;
    let expected = once ? pre.slice(0, i) + after + pre.slice(i + before.length) : null;
    const named = CHANGED_SINCE_PRE[k];
    if (named && expected !== null) expected = expected.split(named[0]).length === 2 ? expected.replace(named[0], () => named[1]) : null;
    check(k + ": at " + PRE + " it holds the old opening exactly once, and now differs only by the Storefront swap" + (named ? " and its named change" : ""),
      once && NOW_T[k] === expected, once ? String(NOW_T[k]).slice(0, 160) : "old opening found " + (typeof pre === "string" ? pre.split(before).length - 1 : "no instruction") + " times");
  }
  const added = Object.keys(NOW_T).filter(k => !Object.prototype.hasOwnProperty.call(PRE_T, k)).sort();
  check("the only new instructions are the four analytics types", JSON.stringify(added) === JSON.stringify(["funnel_analysis", "growth_analysis", "kpi_review", "revenue_forecast"]), JSON.stringify(added));
  const allowed = JSON.parse(SRC.match(/var allowedTaskTypes = (\[[^\]]*\]);/)[1]);
  check("every instruction's type is accepted by allowedTaskTypes", Object.keys(NOW_T).every(k => allowed.indexOf(k) !== -1));

  /* ── 2. the roster line ───────────────────────────────────────────────── */
  console.log("\n══ 2. the Analytics roster line ══");
  const line = (FILES[BRAIN].match(/\{ key: "analytics",[^\n]*\}/) || [""])[0];
  check("it no longer promises traffic and conversion review", line && line.indexOf("traffic and conversion review") === -1, line);
  check("it says it reads no website analytics, traffic or revenue data", line.indexOf("Reads no website analytics, traffic or revenue data.") !== -1, line);

  /* ── 3. the social caveat ─────────────────────────────────────────────── */
  console.log("\n══ 3. social/post says graphemes on Bluesky ══");
  const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout", "fetch",
    "requireAuth", "requireActiveSubscription", "aiLimiter", "startToolRun", "toolGenerateWithOneRetry", "toolSectionShapeCorrection",
    "toolProvenance", "loadProfileForTool", "resolvePreferredLanguage", "buildAgentSystemPrompt", "buildLanguageInstruction"]);
  const ROUTE = "/api/agents/social/post";
  const rstart = SRC.indexOf("app.post(\"" + ROUTE + "\"");
  const rend = s.braceMatch(SRC, SRC.indexOf("{", rstart));
  const rootCode = SRC.slice(rstart, rend + 2);
  const have = new Map(); const queue = [...new Set(rootCode.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = s.definitionOf(SRC, name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  const lifted = [...have.values()].sort((a, b) => SRC.indexOf(a) - SRC.indexOf(b)).join("\n\n") + "\n\n" + rootCode;
  async function post(platform) {
    let handler = null;
    const ctx = { Intl, JSON, Math, Promise, Number, Object, Array, String, process: { env: {} }, console: { log() {}, error() {}, warn() {} },
      requireAuth: 0, requireActiveSubscription: 0, aiLimiter: 0,
      startToolRun: async () => ({ taskId: "t", complete: async () => true, fail: async () => {} }),
      toolGenerateWithOneRetry: async (o) => { o.parse("POST: A short post.\nHOOK_NOTE: n"); return { raw: "POST: A short post.\nHOOK_NOTE: n", completionExtra: null, failureDetails: null }; },
      toolSectionShapeCorrection: () => "", toolProvenance: (measured, inferred) => ({ measured_from: measured, inferred_by_model: inferred }),
      loadProfileForTool: async () => ({}), resolvePreferredLanguage: async () => null, buildAgentSystemPrompt: () => "S", buildLanguageInstruction: () => "",
      app: { post() { handler = arguments[arguments.length - 1]; } } };
    vm.createContext(ctx);
    vm.runInContext(lifted, ctx);
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = JSON.parse(JSON.stringify(x)); return this; } };
    await handler({ user: { id: "u" }, body: { idea: "a launch", platform } }, res, (e) => { res.code = 500; res.body = { error: String(e && e.message) }; });
    return res;
  }
  const blue = await post("bluesky"), insta = await post("instagram");
  check("Bluesky: the caveat says the grapheme maximum is the enforced one",
    blue.code === 200 && /The grapheme maximum is the enforced one\./.test(blue.body.platform_limits.practical_caveat) && !/character/.test(blue.body.platform_limits.practical_caveat),
    blue.code + " " + JSON.stringify(blue.body && blue.body.platform_limits && blue.body.platform_limits.practical_caveat));
  check("Bluesky: the provenance line counts graphemes", blue.body.provenance.measured_from[0].indexOf("The post's grapheme count against Bluesky's enforced maximum") === 0,
    blue.body.provenance.measured_from[0]);
  check("Instagram: the caveat and the provenance line still say character",
    /The character maximum is the enforced one\./.test(insta.body.platform_limits.practical_caveat) && insta.body.provenance.measured_from[0].indexOf("The post's character count against Instagram") === 0,
    JSON.stringify([insta.body.platform_limits.practical_caveat, insta.body.provenance.measured_from[0]]));

  /* ── 4. migration 068 ─────────────────────────────────────────────────── */
  console.log("\n══ 4. migration 068 ══");
  const sql = FILES[M068];
  const statements = sql.split("\n").filter(l => !/^\s*--/.test(l)).join("\n");
  check("068 creates no policy", !/create\s+policy/i.test(statements) && !/pg_policy/i.test(statements), (statements.match(/create\s+policy[^\n]*/i) || [""])[0]);
  check("068 still enables RLS", /alter table public\.bsky_leads enable row level security;/.test(statements));
  check("068's header says production has no policy", /RLS is enabled AND THERE IS NO POLICY\. Production was read on 2026-10-11/.test(sql) && sql.indexOf("ONE POLICY EXISTS") === -1);

  /* ── 5. seo/audit's measured output ───────────────────────────────────── */
  console.log("\n══ 5. seo/audit's measured output ══");
  function measurer(src) {
    const root = "this.m = seoAuditPageMeasure;";
    const have2 = new Map(); const q2 = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
    while (q2.length) {
      const name = q2.shift();
      if (have2.has(name) || s.STUBS.has(name)) continue;
      const def = s.definitionOf(src, name);
      if (!def) continue;
      try { new vm.Script(def); } catch (e) { continue; }
      have2.set(name, def);
      new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have2.has(id) && !s.STUBS.has(id)) q2.push(id); });
    }
    const ctx = { decodeHTML, decodeHTMLAttribute, URL };
    vm.createContext(ctx);
    vm.runInContext([...have2.values()].sort((a, b) => src.indexOf(a) - src.indexOf(b)).join("\n\n") + "\n\n" + root, ctx);
    return ctx.m;
  }
  const nowM = measurer(SRC), preM = measurer(PRE_SRC);
  const page = (head, body) => "<!doctype html><html lang=\"en\"><head><title>Earth Rose</title>" + head + "</head><body>" + (body || "<h1>Care</h1><p>Text.</p><img src=a.jpg alt=\"\"><a href=\"/x\">x</a>") + "</body></html>";
  const PAGES = [
    page(""), page("<meta name=\"description\" content=\"Holistic care.\"><meta name=\"viewport\" content=\"width=device-width\">"),
    page("<meta name=\"description\" content=\"\">"), page("<meta name=\"description\">"), page("<meta NAME=\" Description \" content=\"  a   b  \">"),
    page("<meta name=\"robots\" content=\"noindex, nofollow\"><link rel=\"canonical\" href=\"/other\">"), page("<meta name=\"robots\" content=\"\">"),
    page("<meta name=\"description\" content=\"Fish &amp; chips\"><script type=\"application/ld+json\">{\"@type\":\"Organization\"}</script>", "<div id=root></div><script src=/m.js></script>"),
    "", "<html><body>no head</body></html>"
  ];
  const differ = PAGES.filter(h => JSON.stringify(nowM(h, "https://site.test/")) !== JSON.stringify(preM(h, "https://site.test/")));
  check("seoAuditPageMeasure returns exactly what " + PRE + "'s did, on " + PAGES.length + " pages", differ.length === 0, differ.map(h => h.slice(0, 80)).join(" | "));
  check("a missing description is null and an empty one is \"\"", nowM(page(""), "https://site.test/").meta_description === null &&
    JSON.stringify(nowM(page("<meta name=\"description\" content=\"\">"), "https://site.test/").meta_description) === JSON.stringify({ value: "", length: 0 }));

  check("zero network", NETWORK.length === 0, JSON.stringify(NETWORK));
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
