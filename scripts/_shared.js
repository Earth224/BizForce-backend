"use strict";
const fs=require("fs");const vm=require("vm");const assert=require("assert");const {execSync}=require("child_process");
const REPO="C:/Users/ALGORITHM/BizForce-backend";
const after=fs.readFileSync(REPO+"/server.js","utf8");
const before=execSync("git show HEAD:server.js",{cwd:REPO,maxBuffer:64*1024*1024}).toString("utf8");
/* ── extraction ─────────────────────────────────────────────────────────── */
function braceMatch(src, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return i + 1; }
  }
  return -1;
}
const DEF_CACHE = new Map();
function definitionOf(src, name) {
  const key = (src === after ? "A:" : "B:") + name;
  if (DEF_CACHE.has(key)) return DEF_CACHE.get(key);
  const v = definitionOfRaw(src, name); DEF_CACHE.set(key, v); return v;
}
const SPANS = new Map();
function spansOf(src) {
  if (SPANS.has(src)) return SPANS.get(src);
  const out = []; const re = new RegExp("^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])", "gm"); let m;
  while ((m = re.exec(src))) { const open = src.indexOf("{", m.index); const end = braceMatch(src, open); if (end > 0) out.push([m.index, end]); }
  SPANS.set(src, out); return out;
}
function insideSpan(src, idx) { return spansOf(src).some(([a, b]) => idx > a && idx < b); }
function definitionOfRaw(src, name) {
  let m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(src);
  if (m) { const bodyBrace = src.indexOf(") {", m.index) + 2; return src.slice(m.index, braceMatch(src, bodyBrace)); }   // past any `= {}` default parameter
  const re = new RegExp("^(?:var|const|let) " + name + "[ \t]*=[ \t]*", "gm");
  while ((m = re.exec(src)) && insideSpan(src, m.index)) { /* a local at column 0, not a definition */ }
  if (m) {
    const eq = m.index + m[0].length;
    // statement ends at the first ";\n" followed by a column-0 char or blank line
    let from = eq;
    for (;;) {
      const semi = src.indexOf(";\n", from);
      if (semi === -1) return null;
      const nextCh = src[semi + 2];
      if (nextCh === undefined || nextCh === "\n" || /[^\s]/.test(nextCh)) return src.slice(m.index, semi + 1);
      from = semi + 1;
    }
  }
  return null;
}
function routeCode(src, path) {
  const sig = 'app.post("/api/agents/' + path + '"';
  const start = src.indexOf(sig);
  assert(start > 0, "route not found " + path);
  const end = braceMatch(src, src.indexOf("{", start));
  assert.strictEqual(src.slice(end, end + 3), ");\n");
  return src.slice(start, end + 2);
}
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "callAnthropicText",
  "loadProfileForTool", "resolvePreferredLanguage", "buildLanguageInstruction", "buildAgentSystemPrompt",
  "requireAuth", "requireActiveSubscription", "aiLimiter", "app", "agentToolCatalogue", "AGENT_SYSTEM_PROMPTS",
  "Anthropic", "stripe", "fetch", "COMPLIANCE_PROFILES", "COMPLIANCE_DISCLAIMER", "SALES_LEAD_STATUSES", "setTimeout", "setImmediate", "Buffer", "URL"]);
const CLOSURE_CACHE = new Map();
function closureFor(src, rootCode) {
  const key = (src === after ? "A:" : "B:") + rootCode.length + ":" + rootCode.slice(0, 80);
  if (CLOSURE_CACHE.has(key)) return CLOSURE_CACHE.get(key);
  const v = closureForRaw(src, rootCode); CLOSURE_CACHE.set(key, v); return v;
}
function closureForRaw(src, rootCode) {
  const have = new Map(); const queue = [...new Set(rootCode.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOf(src, name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }   // not a real top-level definition
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return [...have.values()].join("\n\n") + "\n\n" + rootCode;
}

/* ── fake supabase (ai_tasks only) ──────────────────────────────────────── */
function fakeSupabase(plan) {
  const writes = [];
  return {
    writes,
    client: {
      from(table) {
        if (table !== "ai_tasks") {
          // profile / context reads made by some routes directly: an empty row, no error
          const q = { eq() { return q; }, order() { return q; }, limit() { return q; }, single: async () => ({ data: {}, error: null }), maybeSingle: async () => ({ data: null, error: null }), then(r) { return Promise.resolve({ data: [], error: null }).then(r); } };
          return { select() { return q; } };
        }
        return {
          insert(payload) {
            writes.push({ op: "insert", payload });
            return { select() { return { single: async () => plan.insertError ? { data: null, error: plan.insertError } : { data: { id: "task-1" }, error: null } }; } };
          },
          update(payload) {
            const w = { op: "update", payload, where: [] };
            writes.push(w);
            const chain = { eq(c, v) { w.where.push([c, v]); return chain; }, then(res) { return Promise.resolve({ error: plan.updateError || null }).then(res); } };
            return chain;
          }
        };
      }
    }
  };
}

const AGENTS = ["seo","sales","content","ads","reputation","analytics","email","community","influencer","operations","executive","social","etsy","store","broker","publicist","rd","vertical_marketing"];
function build(src, path, plan) {
  const sb = fakeSupabase(plan);
  const logs = [], modelCalls = [];
  const ctx = {
    supabase: sb.client, nowIso: () => "2026-09-11T12:00:00.000Z", process: { env: {} },
    console: { log: (m) => logs.push(["log", String(m)]), error: (m) => logs.push(["error", String(m)]), warn: (m) => logs.push(["warn", String(m)]) },
    requireAuth: 0, requireActiveSubscription: 0, aiLimiter: 0,
    loadProfileForTool: async () => ({ business_name: "Biz" }),
    resolvePreferredLanguage: async () => null,
    buildLanguageInstruction: () => "",
    buildAgentSystemPrompt: () => "SYSTEM",
    AGENT_SYSTEM_PROMPTS: Object.fromEntries(AGENTS.map(a => [a, "x"])),
    agentToolCatalogue: () => ({ rd: ["brief", "competitor-scan"], content: ["audit", "outline"] }),
    callAnthropicText: async (prompt, max, u, m, ledger) => {
      modelCalls.push(ledger.route);
      if (plan.modelThrows) throw new Error("model-down");
      return { text: plan.modelText, stopReason: "end_turn" };
    }
  };
  let handler = null;
  ctx.app = { post() { handler = arguments[arguments.length - 1]; }, _router: { stack: [] } };
  vm.createContext(ctx);
  vm.runInContext(closureFor(src, routeCode(src, path)), ctx);
  assert(handler, "handler not captured for " + path);
  return { handler, writes: sb.writes, logs, modelCalls };
}
async function call(handler, body) {
  const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null;
  await handler({ user: { id: "u1" }, body }, res, (e) => { nextErr = e || new Error("next"); });
  return { status: res.statusCode, body: res.body, nextErr };
}
const strip = (b) => { const c = Object.assign({}, b); delete c.task_id; delete c.persisted; return c; };
const norm = (v) => JSON.parse(JSON.stringify(v));


/* ── fixtures ───────────────────────────────────────────────────────────── */
const F = {
  "rd/competitor-scan": { agent: "rd", prompt: "R&D · Competitor scan: Acme, Globex", body: { competitors: ["Acme", "Globex"] }, bad: { competitors: [] },
    model: "COMPETITOR: Acme\nPOSITIONING: Budget\nSTRENGTHS: Cheap\nWEAKNESSES: Slow\nCONFIDENCE: medium\nVERIFY_FIRST: Pricing\n---\nCOMPETITOR: Globex\nPOSITIONING: Enterprise\nSTRENGTHS: Scale\nWEAKNESSES: FIGURE NEEDED\nCONFIDENCE: low\nVERIFY_FIRST: Status", parseFail: "no labels here" },
  "content/audit": { agent: "content", prompt: "Content · Audit: best widgets", body: { article: "# Best Widgets\n\nBest widgets are great.\n\n## Why\n\nBecause best widgets last.", keyword: "best widgets" }, bad: {}, model: null },
  "etsy/keyword-research": { agent: "etsy", prompt: "Etsy · Keyword research: wool hat", body: { seed: "wool hat" }, bad: {}, model: "wool hat | buyer | warm\nknit beanie | gift | cosy", parseFail: "nothing with pipes" },
  "etsy/pricing-strategy": { agent: "etsy", prompt: "Etsy · Pricing strategy: Wool Hat", body: { listing_title: "Wool Hat", current_price: 20, unit_cost: 5, comparables: [{ price: 18 }, { price: 25 }] }, bad: {}, model: "Price at 22 because comparables cluster there." },
  "email/sequence": { agent: "email", prompt: "Email · Sequence: welcome new buyers", body: { goal: "welcome new buyers", audience: "first-time customers" }, bad: { goal: "g" },
    model: "DELAY_DAYS: 0\nPURPOSE: welcome\nSUBJECT: Welcome\nBODY: Thanks for joining.\n---\nDELAY_DAYS: 3\nPURPOSE: tips\nSUBJECT: Getting started\nBODY: Here is how.", parseFail: "nothing" },
  "email/subject-lines": { agent: "email", prompt: "Email · Subject lines: launch announcement", body: { purpose: "launch announcement" }, bad: {}, model: "Big news inside | curiosity\nWe launched | direct", parseFail: "" },
  "publicist/press-release": { agent: "publicist", prompt: "Publicist · Press release: Acme opens a second workshop", body: { news: "Acme opens a second workshop" }, bad: {},
    model: "HEADLINE: Acme opens second workshop\nSUBHEAD: Doubling capacity\nDATELINE: Leeds, 11 September 2026\nLEDE: Acme today opened.\nBODY: More detail.\nBOILERPLATE: About Acme.\nCONTACT: press@acme.test", parseFail: "no sections" },
  "publicist/pitch": { agent: "publicist", prompt: "Publicist · Pitch: local maker doubles output", body: { angle: "local maker doubles output", outlet_type: "trade" }, bad: { angle: "a" }, model: "SUBJECT: A maker story\nBODY: Hello, I have a story.\nWHY_THIS_OUTLET: You cover makers.", parseFail: "no body" },
  "operations/sop": { agent: "operations", prompt: "Operations · SOP: order packing", body: { process: "order packing" }, bad: {},
    model: "PURPOSE: Pack orders\nSCOPE: All orders\nOWNER: Warehouse lead\nFREQUENCY: Daily\nSUCCESS_CRITERIA: Zero errors\n---\nACTION: Print label\nOWNER: Packer\nRISK: Wrong label\nVERIFY: Scan matches", parseFail: "PURPOSE: only a header" },
  "operations/checklist": { agent: "operations", prompt: "Operations · Checklist: weekly stock count", body: { task: "weekly stock count" }, bad: {}, model: "- Count shelf A\n- Count shelf B\nNOTE: do it before opening", parseFail: "Heading:" },
  "ads/copy": { agent: "ads", prompt: "Ads · Copy: wool hats", body: { product: "wool hats", angle: "warmth", platform: "google_rsa" }, bad: { product: "p", angle: "a", platform: "nope" }, model: "HEADLINE | Warm wool hats\nDESCRIPTION | Hand knitted hats that last for years.", parseFail: "no pipes" },
  "ads/policy-check": { agent: "ads", prompt: null, body: { copy: "Guaranteed to cure your diabetes in 7 days. Doctors hate this. Lose 20 pounds fast, 100% risk-free results." }, bad: {}, model: "Rewrite: Supports a healthy routine." },
  "reputation/review-response": { agent: "reputation", prompt: null, body: { review: "The hat arrived late and the colour was wrong.", rating: 2 }, bad: { review: "x", rating: 9 }, model: "REPLY: We are sorry about the delay.\nWHY_THIS_APPROACH: Own the problem.", parseFail: "no reply" },
  "reputation/review-request": { agent: "reputation", prompt: "Reputation · Review request: after delivery", body: { moment: "after delivery" }, bad: {}, model: "DELAY_DAYS: 2\nCHANNEL: email\nPURPOSE: ask\nMESSAGE: Would you leave a review?", parseFail: "no message" },
  "social/post": { agent: "social", prompt: null, body: { idea: "new colourway launch", platform: "instagram" }, bad: { idea: "i", platform: "nope" }, model: "POST: Our new colourway is here.\nHOOK_NOTE: Leads with the product.", parseFail: "no post" },
  "social/calendar": { agent: "social", prompt: "Social · Calendar: grow followers", body: { goal: "grow followers", cadence: "daily" }, bad: { goal: "g" },
    model: "DAY: 1\nPLATFORM: instagram\nFORMAT: reel\nHOOK: Behind the scenes\nPURPOSE: reach\n---\nDAY: 2\nPLATFORM: x\nFORMAT: post\nHOOK: A tip\nPURPOSE: value", parseFail: "nothing" },
  "broker/term-sheet": { agent: "broker", prompt: null, body: { deal: "Acme buys Globex assets for cash" }, bad: {},
    model: "PARTIES: Acme and Globex\nSTRUCTURE: Asset purchase\nCONSIDERATION: Cash at close\nCONDITIONS_PRECEDENT: - Due diligence\n- Board approval\nWARRANTIES: Standard\nEXCLUSIVITY: 30 days\nGOVERNING_LAW: England\nEXPIRY: 60 days", parseFail: "no sections" },
  "broker/due-diligence": { agent: "broker", prompt: "Broker · Due diligence: acquisition", body: { deal_type: "acquisition" }, bad: {}, model: "FINANCIAL | Review three years of accounts\nLEGAL | Check material contracts\nPEOPLE | Key person dependencies", parseFail: "no pipes" },
  "rd/brief": { agent: "rd", prompt: "R&D · Brief: should we add a kids range", body: { question: "should we add a kids range" }, bad: {},
    model: "QUESTION: Kids range?\nKNOWN: - Adults sell\nASSUMED: - Parents buy\nWOULD_CHANGE: - A pilot\nRECOMMENDATION: Pilot ten units", parseFail: "no sections" },
  "community/onboarding": { agent: "community", prompt: "Community · Onboarding: discord server", body: { community_type: "discord server" }, bad: {},
    model: "WEEK_ONE_OUTCOME: - Posted once\n- Met a mod\n---\nDAY: 0\nWHAT_HAPPENS: Welcome message\nWHO_DOES_IT: Mod\nPURPOSE: Greet\n---\nDAY: 3\nWHAT_HAPPENS: Intro thread\nWHO_DOES_IT: Member\nPURPOSE: Connect", parseFail: "nothing" },
  "community/engagement-calendar": { agent: "community", prompt: "Community · Engagement calendar: weekly", body: { cadence: "weekly" }, bad: {},
    model: "RITUAL: Monday AMA\nFREQUENCY: weekly\nPURPOSE: Answer questions\nWHO_RUNS_IT: Founder\nEFFORT: low\n---\nRITUAL: Show and tell\nFREQUENCY: monthly\nPURPOSE: Celebrate\nWHO_RUNS_IT: Mod\nEFFORT: medium", parseFail: "nothing" },
  "analytics/funnel": { agent: "analytics", prompt: "Analytics · Funnel: 3 stages", body: { stages: [{ name: "visit", count: 1000 }, { name: "cart", count: 100 }, { name: "buy", count: 10 }] }, bad: { stages: [{ name: "one", count: 1 }] },
    model: "WHAT_THE_NUMBERS_SAY: Cart to buy is the drop.\nLIKELY_CAUSES: Shipping cost.\nWHAT_TO_CHECK_FIRST: Checkout page.\nWHAT_WOULD_CONFIRM_IT: Exit surveys." },
  "analytics/kpi-review": { agent: "analytics", prompt: "Analytics · KPI review: August", body: { period: "August", metrics: [{ name: "revenue", current: 1200, previous: 1000 }, { name: "orders", current: 40, previous: 50, better: "up" }] }, bad: { metrics: [] },
    model: "WHAT_MOVED: Revenue up, orders down.\nLOOK_AT_FIRST: Average order value.\nWHAT_MIGHT_EXPLAIN_IT: A price rise.\nWHAT_IS_MISSING: Refunds." },
  "influencer/outreach": { agent: "influencer", prompt: "Influencer · Outreach: knitting creator with 20k followers", body: { creator: "knitting creator with 20k followers", campaign: "winter launch" }, bad: { creator: "c" }, model: "MESSAGE: Hi Sam. I loved your cable knit video. Would you try our hats?\nWHY_THIS_OPENING: It names their work.", parseFail: "no message" },
  "influencer/partnership-offer": { agent: "influencer", prompt: "Influencer · Partnership offer: two reels and a story", body: { collaboration: "two reels and a story" }, bad: {},
    model: "DELIVERABLES: Two reels, one story\nUSAGE_RIGHTS: Six months paid social\nEXCLUSIVITY: None\nTIMELINE: Two weeks\nPAYMENT_TERMS: 50% upfront\nDISCLOSURE: #ad on every post", parseFail: "no sections" },
  "vertical_marketing/positioning": { agent: "vertical_marketing", prompt: "Vertical marketing · Positioning: dental practices", body: { industry: "dental practices" }, bad: {},
    model: "POSITIONING: The quiet scheduler.\nTRADE_LANGUAGE: - chairside\n- recall\nCHANNELS: - dental trade press\nWHAT_NOT_TO_SAY: - guaranteed\nCONFIDENCE: medium\nVERIFY_WITH_A_PRACTITIONER: - recall cadence", parseFail: "no fields" },
  "vertical_marketing/objections": { agent: "vertical_marketing", prompt: "Vertical marketing · Objections: dental practices", body: { industry: "dental practices", offer: "online booking" }, bad: { industry: "d" },
    model: "OBJECTION: Patients will not use it\nWHAT_IS_BEHIND_IT: Older patient base\nANSWER: Phone stays open\nPROOF_THAT_HELPS: Adoption stats\nLIKELIHOOD: common\n---\nCONFIDENCE: medium\nVERIFY_WITH_A_PRACTITIONER: - Ask a practice manager", parseFail: "nothing" },
  "content/outline": { agent: "content", prompt: "Content · Outline: how to wash wool", body: { keyword: "how to wash wool" }, bad: {},
    model: "H1: How to wash wool without ruining it\nSEARCH_INTENT: informational\nQUESTIONS_TO_ANSWER: - Can wool go in the machine?\n---\nH2: Why wool felts\nCOVERS: Fibre structure\nWHY_HERE: Sets up the method\n---\nH2: The cold hand-wash method\nCOVERS: Steps\nWHY_HERE: The answer", parseFail: "H1: only a header" },
  "executive/plan": { agent: "executive", prompt: "Executive · Plan: double online sales by spring", body: { goal: "double online sales by spring" }, bad: {},
    model: "ID: 1\nAGENT: rd\nTOOL: competitor-scan\nTASK: Compare the three closest rivals\nINPUT: Acme, Globex\nDEPENDS_ON: none\nSUCCESS_SIGNAL: A comparison exists\nPRIORITY: high\n---\nID: 2\nAGENT: YOU\nTOOL: NONE\nTASK: Pick the price point\nINPUT: The comparison\nDEPENDS_ON: 1\nSUCCESS_SIGNAL: A price is set\nPRIORITY: medium", parseFail: "nothing" }
};


module.exports={after,before,braceMatch,definitionOf,routeCode,STUBS,closureFor,fakeSupabase,build,call,strip,norm,F,AGENTS};
