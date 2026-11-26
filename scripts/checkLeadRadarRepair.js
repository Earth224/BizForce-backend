"use strict";
/* ═════════════════════════════════════════════════════════════════════════════
   checkLeadRadarRepair.js — LR-1 (Nov 23 2026): Lead Radar repaired.
   NAMED (Nov 23 2026, LR-2): BEFORE the outbound proof was the owner's
   POST /api/agents/sales/send-approved and the platform scorer (scoreNewLeads).
   AFTER LR-2 removed both: the only Lead Radar post is the member's own approved
   reply, POST /api/leads/:id/send (lib/leadRoutes.js, lib/leadReplies.js), and
   scoring runs on each member's own ledger (lib/memberRadar.js through server.js
   leadRadarModelCall). Sections A, B, D, E and G are re-pointed to them;
   scripts/checkLeadRadarMember.js proves the member rules in full.

   THE OWNER'S RULE. Nothing is posted, replied or sent to anyone outside BizForce
   unless a person approved that exact text first. Everyone, the owner included.

   WHAT IT PROVES (never the real database, never the network, no model call):
     A. Every outbound post or send in server.js, lib/, leadRadar.js and
        youtubeRadar.js is accounted for: Lead Radar posts in one place, the
        member's POST /api/leads/:id/send, with the text in the request, from the
        member's own account (the platform's Bluesky login only for the owner);
        the platform's login posts otherwise only in the proposal executor a
        member approves and blueskyActAs; the radar only searches; nothing creates
        a Twilio client or reads a platform Mastodon token.
     B. The automatic sales loop and the old owner-only lead routes are gone.
     C. Mastodon lead search and replies are gone (files, imports, sources,
        sender, token reads), while members' own Mastodon posting stays
        (lib/memberMastodon.js byte for byte as committed, its routes present).
     D. POST /api/leads/:id/send: members only, SALES_SEND_LIVE is the master
        switch, the text is the request's, the member's own account, and the caps
        (OUTREACH_DAILY_CAP, OUTREACH_ACCOUNT_DAILY_CEILING) are checked at the
        send with the reply reserved first, inside one serial step.
     E. Scoring is on the member's ledger: no Lead Radar file calls a model of
        its own; server.js hands callAnthropicText (limits, the member's key, the
        ledger row) to the radar before it starts.
     F. The PART D fixes, the SMS rules (no sending, consent recorded or the
        number is pending), and archived rows never shown as leads.
     G. The pages.

   MUTATE=all runs every mutation in its own process; each must turn this red.
   ═════════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const Module = require("module");
const cp = require("child_process");
const H = require("./_p21Harness");
const S = require("./_shared");

const SERVER = "@server.js", LR = "@leadRadar.js", YR = "@youtubeRadar.js", JOBS = "@lib/jobSchedules.js", ACCESS = "@lib/routeAccess.js";
const RT = "@lib/leadRoutes.js", LRP = "@lib/leadReplies.js", MR = "@lib/memberRadar.js";
const SALES = "agents/sales.html", RADAR = "agents/lead-radar.html", BFA = "scripts/bf-access.js", SITEMAP = "sitemap-pages.xml", SMS = "agents/sms.html";

const MUTATIONS = {
  // A / D: the send route
  "send-without-live-switch": [[SERVER, `sendLive: function () { return process.env.SALES_SEND_LIVE === "true"; },`, `sendLive: function () { return true; },`]],
  "send-platform-for-members": [[RT, `    if (a.kind === "platform" && userId !== deps.ownerId) return { kind: "none", platform: "bluesky" };`, ``]],
  "send-not-members-only": [[RT, `  app.post("/api/leads/:id/send", M, async`, `  app.post("/api/leads/:id/send", deps.requireAuth, async`]],
  "send-text-not-request": [[RT, `      var raw = req.body && typeof req.body.text === "string" ? req.body.text : "";`, `      var raw = (req.body && req.body.draft) || "";`]],
  "send-unreserved": [[RT, `        var slot = await LR.reserveReply(deps.sb, {`, `        var slot = { ok: true, id: "x", release: async function () {} }; void (LR.reserveReply, deps.sb, {`]],
  "send-unsafe-allowed": [[LRP, `  if (lead.outreach_safe !== true) return`, `  if (lead.outreach_safe === false) return`]],
  "caps-unwired": [[SERVER, `caps: { get perMember() { return OUTREACH_DAILY_CAP; }, get ceiling() { return OUTREACH_ACCOUNT_DAILY_CEILING; } },`, `caps: { perMember: 1000, ceiling: 100000 },`]],
  "cap-excludes-reservation": [[LRP, `    if (mine.count > caps.perMember) { await release();`, `    if (mine.count - 1 > caps.perMember) { await release();`]],
  "count-error-sends": [[LRP, `  } catch (err) {\n    await release();\n    return { ok: false, code: "check_failed", status: 503 };\n  }`, `  } catch (err) {\n    return { ok: true, id: id, release: release };\n  }`]],
  "cap-parse-nan": [[SERVER, `  var parsed = Math.floor(Number(raw));\n  if (!Number.isFinite(parsed) || parsed < 1) return 5;\n  return parsed;\n})();`, `  return Number(raw);\n})();`]],
  // NAMED (Nov 23 2026, LR-2): BEFORE the anchor read cleanDraft(out && out.text, link); the drafter now splits the verdict first.
  "draft-posts": [[RT, `      var draft = LR.cleanDraft(verdict.text, link);`, `      var draft = LR.cleanDraft(verdict.text, link);\n      await deps.actAs(userId, acct, function (agent) { return agent.post({ text: draft }); });`]],
  "radar-posts": [[LR, `      return a.app.bsky.feed.searchPosts({ q: keyword, limit: 25, sort: "latest", since: sinceIso });`, `      a.post({ text: keyword });\n      return a.app.bsky.feed.searchPosts({ q: keyword, limit: 25, sort: "latest", since: sinceIso });`]],
  // B: the loop and the old routes
  "autoloop-back": [[JOBS, `  { tick: "leadRadarTick", every_ms: 300000, jobs: [] },`, `  { tick: "salesAutoConvertTick", every_ms: 300000, jobs: [] },\n  { tick: "leadRadarTick", every_ms: 300000, jobs: [] },`]],
  "old-send-route-back": [[SERVER, `function leadRadarModelCall(userId, prompt, maxTokens, route) {`, `app.post("/api/agents/sales/send-approved", requireAuth, function (req, res) { res.json({}); });\nfunction leadRadarModelCall(userId, prompt, maxTokens, route) {`]],
  // C: Mastodon
  "mastodon-scored": [[MR, `const SCORED_SOURCES = ["bluesky", "threads"];`, `const SCORED_SOURCES = ["bluesky", "threads", "mastodon"];`]],
  "mastodon-sendable": [[LRP, `const REPLY_PLATFORMS = ["bluesky", "threads"];`, `const REPLY_PLATFORMS = ["bluesky", "threads", "mastodon"];`]],
  "mastodon-token-read": [[SERVER, `function leadRadarModelCall(userId, prompt, maxTokens, route) {`, `var platformMastodonToken = process.env.MASTODON_ACCESS_TOKEN;\nfunction leadRadarModelCall(userId, prompt, maxTokens, route) {`]],
  // E: scoring on the ledger
  "scorer-platform-pays": [[SERVER, `  return callAnthropicText(prompt, maxTokens, userId, "claude-haiku-4-5-20251001", { user_id: userId, agent_type: "lead_radar", route: route });`, `  return callAnthropicText(prompt, maxTokens, null, "claude-haiku-4-5-20251001", { agent_type: "lead_radar", route: route });`]],
  "scorer-deps-unset": [[SERVER, `    require("./leadRadar").setMemberRadarDeps(leadRadarMemberDeps);`, `    void leadRadarMemberDeps;`]],
  "scorer-own-client": [[MR, `const FP = require("./leadFingerprint");`, `const FP = require("./leadFingerprint");\nconst Anthropic = require("@anthropic-ai/sdk");`]],
  "youtube-unrecorded-call": [[YR, `module.exports = { SEARCH_MAX_RESULTS,`, `async function summarise(t) { return new (require("@anthropic-ai/sdk"))().messages.create({ model: "m", max_tokens: 5, messages: [] }); }\nmodule.exports = { SEARCH_MAX_RESULTS,`]],
  "youtube-count-rows": [[MR, `  if (r.error) throw r.error;\n  return (r.data || []).length;\n}`, `  if (r.error) throw r.error;\n  return rows.length;\n}`]],
  // F: PART D
  "demand-any-member": [[SERVER, `    q = q.eq("user_id", userId).neq("source", DEMAND_EXCLUDED_SOURCE).neq("status", "archived");`, `    q = q.neq("source", DEMAND_EXCLUDED_SOURCE).neq("status", "archived");`]],
  "demand-owner-only": [[ACCESS, `"post /api/agents/rd/demand-signals"`, `"post /api/agents/rd/demand-signals-x"`]],
  "card-leads-members": [[ACCESS, `  "get /api/digital-cards/:id/leads",   // NAMED`, `  "get /api/digital-cards/:id/leads-x",   // NAMED`]],
  "sms-sends": [[SERVER, `app.post("/api/sms/send", requireAuth, function (req, res) {\n  return res.status(503)`, `app.post("/api/sms/send", requireAuth, function (req, res) {\n  require("twilio")(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);\n  return res.status(503)`]],
  "sms-consent-optional": [[SERVER, `  if (!source || !Number.isFinite(atMs) || atMs > Date.now() + 5 * 60 * 1000) return { state: "none" };`, `  if (false) return { state: "none" };`]],
  "sms-consent-unrecorded": [[SERVER, `    if (ev.error) { console.error("[sms/consent] consent not recorded, number stored as pending:", ev.error.message); return "pending"; }`, ``]],
  "sms-none-opted-in": [[SERVER, `  if (proof.state !== "given") return "pending";`, `  if (proof.state !== "given") return "opted_in";`]],
  "drip-unguarded": [[SERVER, `if (require.main === module && process.env.ENABLE_DRIP_SCHEDULER === "true") {`, `if (process.env.ENABLE_DRIP_SCHEDULER === "true") {`]],
  "archived-in-pipeline": [[SERVER, `          .neq("status", "archived")   // NAMED (Nov 23 2026, LR-1): archived rows are not leads`, ``]],
  "archived-in-leads": [[RT, `.not("status", "in", "(dismissed,archived)")`, `.not("status", "in", "(dismissed)")`]],
  // frontend
  "radar-posts-draft": [[RADAR, `      call("POST", "/api/leads/" + encodeURIComponent(l.id) + "/send", { text: text, add_link: S.sheetLink })`, `      call("POST", "/api/leads/" + encodeURIComponent(l.id) + "/send", { text: (S.lastDraft || text), add_link: S.sheetLink })`]],
  "radar-draft-sends": [[RADAR, `        $("lrSheetBody").innerHTML = draftHtml(l, res.data);\n`, `        $("lrSheetBody").innerHTML = draftHtml(l, res.data); send();\n`]],
  "radar-console": [[RADAR, `Sign in to see Lead Radar.`, `Failed to load leads. Check console.`]],
  "sales-sends": [[SALES, `archiveRead = fetch(API_URL + "/api/leads/archive", { headers: { "Authorization": "Bearer " + token } })`, `archiveRead = fetch(API_URL + "/api/agents/sales/send-approved", { method: "POST", headers: { "Authorization": "Bearer " + token } })`]],
  // NAMED (Nov 24 2026, LR-3): BEFORE "sfmessage-back" (the dead selector returning). AFTER the selector is wired to seller.html's
  // real Message button, so the mutation takes the button's id away and leaves the selector dead again.
  "sfmessage-dead": [["seller.html", `btn.id = "sfMessage";`, `btn.id = "sfMsg";`]],
  "suppressed-back": [[SITEMAP, `</urlset>`, `  <url><loc>https://bizforceai.net/suppressed.html</loc></url>\n</urlset>`]]
};

const T = H.setup(__filename, MUTATIONS, [SERVER, LR, YR, JOBS, ACCESS, RT, LRP, MR, "@lib/leadFingerprint.js", "@lib/memberMastodon.js", "@lib/yourData.js", "@README.md",
  "@supabase/migrations/203_lr1_archived_and_sms_pending.sql", "@scripts/oneoff/lr1Archive.js", "@lib/triggerRunner.js", "@lib/agentSignatures.js",
  SALES, RADAR, BFA, SITEMAP, SMS, "sw.js", "privacy.html", "seller.html"]);   // NAMED (Nov 24 2026, LR-3): + seller.html
const { FILES, check, finish, J, has, count } = T;
const SRC = FILES[SERVER];
const code = t => S.stripComments ? S.stripComments(t) : String(t || "").replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
const OWNER = require(path.join(H.REPO, "lib", "ownerAccount.js")).OWNER_ACCOUNT_ID;
const OTHER = "22222222-2222-4222-8222-222222222222";
function section(t) { console.log("\n== " + t); }
function fnBody(src, sig) { const at = src.indexOf(sig); if (at < 0) return null; const open = src.indexOf("{", at + sig.length - 1); const end = S.braceMatch(src, open); return end > open ? src.slice(at, end + 1) : null; }
function routeBody(method, p) { return H.routeStatement(SRC, method, p) || (function () { const at = SRC.indexOf("app." + method + "(\"" + p + "\","); if (at < 0) return null; const open = SRC.indexOf("{", at); const end = S.braceMatch(SRC, open); return SRC.slice(at, end + 1); })(); }
/* A route run with only the small server definitions it is given. */
function bareCtx(roots, stubs) {
  const ctx = Object.assign({ console: { log() {}, warn() {}, error() {} }, process: { env: {} }, Promise, Date, Math, JSON, Number, String, Object, Array, Set, Map, RegExp, Error,
    requireAuth: 0, requireActiveSubscription: 0, aiLimiter: 0, nowIso: () => new Date().toISOString(), setImmediate, setTimeout,
    URL, require: n => require(/^\./.test(n) ? path.join(H.REPO, n) : require.resolve(n, { paths: [H.REPO] })) }, stubs);
  vm.createContext(ctx);
  // comment-blind closure: each definition's code (comments stripped) names what it needs; source order keeps consts valid
  const skip = new Set(Object.keys(stubs).concat(Object.keys(ctx)).concat([...S.STUBS]));
  const have = new Map(), queue = roots.slice();
  while (queue.length) {
    const n = queue.shift();
    if (have.has(n) || skip.has(n)) continue;
    const d = S.definitionOf(SRC, n);
    if (!d) { have.set(n, null); continue; }
    have.set(n, d);
    (code(d).replace(/"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'/g, '""').match(/[A-Za-z_$][A-Za-z0-9_$]*/g) || []).forEach(w => { if (!have.has(w) && !skip.has(w)) queue.push(w); });
  }
  const defs = [...have.values()].filter(Boolean).sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y));
  vm.runInContext(defs.join("\n").replace(/^(?:const|let) /gm, "var "), ctx);
  Object.keys(stubs).forEach(k => { ctx[k] = stubs[k]; });
  return ctx;
}
function bareRoute(method, p, roots, stubs) {
  const stmt = H.routeStatement(SRC, method, p) || (function () { const at = SRC.indexOf("app." + method + "(\"" + p + "\","); if (at < 0) return null; const end = SRC.indexOf("\n});", at); return SRC.slice(at, end + 4); })();
  if (!stmt) return null;
  let handler = null;
  const ctx = bareCtx(roots, stubs);
  const reg = function () { if (arguments[0] === p) handler = arguments[arguments.length - 1]; };
  ctx.app = { post: reg, get: reg, put: reg, delete: reg };
  vm.runInContext(stmt, ctx);
  return async function (req) {
    const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
    let err = null; await handler(Object.assign({ user: { id: OWNER }, body: {}, params: {}, query: {}, headers: {} }, req), res, e => { err = e; });
    return { status: res.statusCode, body: res.body, err: err && String(err.message || err) };
  };
}
const SMS_ROOTS = ["safeText", "canonicalPhone", "smsConsentProof", "smsConsentStatusFor"];
const libFiles = fs.readdirSync(path.join(H.REPO, "lib")).filter(f => /\.js$/.test(f));
const LIB = {}; libFiles.forEach(f => { LIB[f] = FILES["@lib/" + f] || fs.readFileSync(path.join(H.REPO, "lib", f), "utf8").replace(/\r\n/g, "\n"); });
const ALL = Object.assign({ "server.js": SRC, "leadRadar.js": FILES[LR], "youtubeRadar.js": FILES[YR] }, Object.fromEntries(Object.keys(LIB).map(k => ["lib/" + k, LIB[k]])));
const OLD_ROUTES = ["app.get(\"/api/leads\",", "app.get(\"/api/leads/youtube-signals\"", "app.post(\"/api/leads/draft-reply\"", "app.get(\"/api/agents/sales/leads\"", "app.post(\"/api/agents/sales/convert\"",
  "app.post(\"/api/agents/sales/send-approved\"", "app.post(\"/api/agents/sales/lead-status\"", "app.get(\"/api/agents/sales/pipeline\""];

/* The send route, mounted from lib/leadRoutes.js against fakes. */
const NOW = Date.now();
function mkLead(o) { return Object.assign({ id: "aaaaaaaa-0000-4000-8000-0000000000aa", user_id: OTHER, source: "bluesky", external_id: "at://did:plc:a/app.bsky.feed.post/1", text: "Anyone know a plumber?",
  posted_at: new Date(NOW - 86400000).toISOString(), score: 82, outreach_safe: true, reply_invited: true, status: "new" }, o || {}); }
function sendWorld(lead, opts) {
  opts = opts || {};
  const st = { posted: [], acts: [], replies: [], released: 0, failCount: !!opts.failCount, count: opts.count || 0, live: opts.live !== false };
  const db = H.fakeDb(function (t, q) {
    if (t === "member_leads" && q.op === "select") return { data: lead && H.filterVal(q, "eq", "user_id") === lead.user_id ? lead : null, error: null };
    if (t === "member_lead_replies") {
      if (q.op === "insert") { st.replies.push(q.payload); return { data: { id: "r" + st.replies.length }, error: null }; }
      if (q.op === "delete") { st.released++; st.replies.pop(); return { data: null, error: null }; }
      if (q.op === "update") return { data: null, error: null };
      if (q.head) return st.failCount ? { count: null, error: { message: "read failed" } } : { count: st.count + st.replies.length, error: null };
      const uid = H.filterVal(q, "eq", "user_id");
      return { data: uid ? [] : st.replies.map(r => ({ user_id: r.user_id })), error: null };
    }
    return { data: [], error: null };
  });
  const routes = [];
  const reg = m => function (p) { routes.push({ m, p, hs: [].concat.apply([], [].slice.call(arguments, 1)) }); };
  T.libRequire("./leadRoutes").mountLeadRoutes({ get: reg("GET"), post: reg("POST"), put: reg("PUT") }, {
    sb: db.client, ownerId: OWNER, siteOrigin: "https://bizforceai.net",
    requireAuth: function (req, res, next) { if (!req.user) return res.status(401).json({}); next(); },
    requireActiveSubscription: function (req, res, next) { if (req.member !== true) return res.status(402).json({ code: "members_only" }); next(); },
    callModel: async function () { throw new Error("no model in this check"); },
    postingAccount: async function (userId, role) { return opts.account || (role === "admin" ? { kind: "platform" } : { kind: "member", handle: "m.bsky.social", row: {} }); },
    actAs: async function (userId, acct, fn) { st.acts.push({ userId, kind: acct.kind }); return { ok: true, value: await fn({ getPosts: async a => ({ data: { posts: a.uris.map(u => ({ uri: u, cid: "c" })) } }), post: async r => { st.posted.push({ kind: acct.kind, text: r.text }); return { uri: "at://posted/1" }; } }) }; },
    actFailure: function (res) { return res.status(502).json({}); }, linkFacets: function () { return []; },
    replyRefsFor: function (p) { return { root: { uri: p.uri, cid: p.cid }, parent: { uri: p.uri, cid: p.cid } }; },
    caps: { get perMember() { return opts.perMember || 5; }, get ceiling() { return 25; } }, sendLive: function () { return st.live; },
    threads: { state: async function () { return { state: "not_connected" }; }, reply: async function () { throw new Error("no threads here"); } },
    now: function () { return NOW; }
  });
  const r = routes.find(x => x.m === "POST" && x.p === "/api/leads/:id/send");
  async function run(req) {
    const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
    req = Object.assign({ params: { id: mkLead().id }, body: {} }, req);
    for (const h of r ? r.hs : []) { let go = false; await h(req, res, function () { go = true; }); if (!go) break; }
    return { status: res.statusCode, body: res.body };
  }
  return { st, run: r ? run : null };
}

(async function main() {
  /* ── A ───────────────────────────────────────────────────────────────── */
  section("A. every outbound post or send is accounted for");
  {
    const sbr = Object.keys(ALL).filter(f => /sendBlueskyReply\(|sendMastodonReply\(/.test(code(ALL[f])));
    check("A1. the platform's old reply sender is gone from every file (no sendBlueskyReply)", sbr.length === 0, J(sbr));
    const rt = code(FILES[RT]);
    const sendAt = rt.indexOf("app.post(\"/api/leads/:id/send\"");
    const pbAt = rt.indexOf("async function postBluesky(");
    check("A2. Lead Radar posts in one route only, POST /api/leads/:id/send, with the text from the request: one agent.post (in postBluesky, called once from the send) and one Threads reply",
      (rt.match(/agent\.post\(/g) || []).length === 1 && rt.indexOf("agent.post(") > pbAt && (rt.match(/postBluesky\(/g) || []).length === 2 && rt.indexOf("postBluesky(", sendAt) < pbAt &&
      (rt.match(/deps\.threads\.reply\(/g) || []).length === 1 && rt.indexOf("deps.threads.reply(") > sendAt && rt.indexOf("deps.threads.reply(") < pbAt &&
      /var raw = req\.body && typeof req\.body\.text === "string" \? req\.body\.text : "";/.test(rt));
    const gateSites = (code(SRC).match(/bskyGate\.call\(/g) || []).length;
    const gateFns = [];
    { const re = /bskyGate\.call\(/g; let m; const c = code(SRC); while ((m = re.exec(c)) !== null) { const before = c.slice(0, m.index); const f = /(?:^|\n)(?:async )?function ([A-Za-z0-9_]+)\([^)]*\) \{(?![\s\S]*\n(?:async )?function [A-Za-z0-9_]+\()/.exec(before); gateFns.push(f ? f[1] : "?"); } }
    check("A3. the platform's Bluesky login posts in two functions only: executePublishSocialPost and blueskyActAs (" + J(gateFns) + ")",
      gateSites === 2 && J(gateFns.slice().sort()) === J(["blueskyActAs", "executePublishSocialPost"]));
    const lrc = code(FILES[LR]);
    check("A3b. the radar's own gate calls only search (searchPosts), never post", (lrc.match(/bskyGate\.call\(/g) || []).length === 1 && /bskyGate\.call\(function \(a\) \{\n\s*return a\.app\.bsky\.feed\.searchPosts\(/.test(lrc) && !/\.post\(/.test(lrc));
    const execUsers = (code(SRC).match(/executePublishSocialPost/g) || []).length;
    check("A4. executePublishSocialPost runs only as the approved-proposal executor or the member's own filing (3 mentions: definition, executor map, the filing route)",
      execUsers === 3 && /publish_social_post: executePublishSocialPost,/.test(SRC) && /autoExecuteFiledProposal\(proposal, executePublishSocialPost\)/.test(SRC));
    const actAs = (code(SRC).match(/blueskyActAs\(/g) || []).length;
    check("A5. blueskyActAs: the member's mention replies and profile edits (definition plus 3 calls), and handed to Lead Radar's send as its account step",
      actAs === 4 && /actAs: blueskyActAs, actFailure: blueskyActFailure,/.test(SRC));
    check("A5b. ... where the platform account is the owner's alone (OWNER_ACCOUNT_ID, not the admin role)",
      /if \(a\.kind === "platform" && userId !== deps\.ownerId\) return \{ kind: "none", platform: "bluesky" \};/.test(FILES[RT]) && /ownerId: OWNER_ACCOUNT_ID, siteOrigin: FRONTEND_URL,/.test(SRC));
    const twilioMade = Object.keys(ALL).filter(f => /twilio\s*\(\s*(process|accountSid|sid)|\.messages\.create\(\s*\{\s*(to|from|body)\s*:/.test(code(ALL[f])));
    check("A6. nothing creates a Twilio client or sends an SMS (twilio is used only to verify inbound webhooks)", twilioMade.length === 0 &&
      (code(SRC).match(/twilio\./g) || []).every(x => x === "twilio.") && /twilio\.validateRequest\(/.test(SRC) && (code(SRC).match(/twilio\.[a-zA-Z]+/g) || []).every(x => x === "twilio.validateRequest"), J(twilioMade));
    const mastoReads = Object.keys(ALL).filter(f => /process\.env\.MASTODON_(ACCESS_TOKEN|INSTANCE)/.test(code(ALL[f])));
    check("A7. no file reads a platform Mastodon token or instance", mastoReads.length === 0, J(mastoReads));
    const mm = LIB["memberMastodon.js"] || "";
    check("A8. the one Mastodon post (lib/memberMastodon.js /api/v1/statuses) runs on the member's own connection", (code(mm).match(/\/api\/v1\/statuses"/g) || []).length === 1 && !/process\.env\.MASTODON_ACCESS_TOKEN/.test(mm));
    const radarFiles = ["lib/memberRadar.js", "lib/leadFingerprint.js", "lib/leadReplies.js", "leadRadar.js", "youtubeRadar.js"];
    check("A9. the radar, the Fingerprint and the reply rules post nothing", radarFiles.every(f => !/\.post\(|actAs|replyTo\(|\.reply\(/.test(code(ALL[f]))));
  }

  /* ── B ───────────────────────────────────────────────────────────────── */
  section("B. the automatic sales loop and the old owner-only lead routes are gone");
  {
    const names = ["runSalesAutoConvert", "salesAutoConvertTick", "ENABLE_SALES_AUTOLOOP", "SALES_AUTOLOOP_DRY_RUN", "SALES_AUTOLOOP_DAILY_DRAFT_CAP", "salesAutoConvertRunning"];
    const left = names.filter(n => Object.keys(ALL).some(f => new RegExp("\\b" + n + "\\b").test(code(ALL[f]))));
    check("B1. none of the loop's names is in any code (comments may say it is retired)", left.length === 0, J(left));
    check("B2. lib/jobSchedules.js lists no salesAutoConvertTick and does list leadRadarTick", !/salesAutoConvertTick/.test(code(FILES[JOBS])) && /tick: "leadRadarTick", every_ms: 300000/.test(FILES[JOBS]));
    check("B3. a NAMED note says it is retired by the owner's rule", /runSalesAutoConvert \(the automatic sales loop\) is RETIRED by the owner's rule/.test(SRC));
    check("B4. module.exports carries no loop", !/runSalesAutoConvert/.test(code(SRC.slice(SRC.lastIndexOf("module.exports")))));
    const back = OLD_ROUTES.filter(r => code(SRC).indexOf(r) !== -1);
    check("B5. the eight old owner-only lead routes (convert, send-approved, draft-reply, sales leads, pipeline, lead-status, youtube-signals, the old GET /api/leads) are gone", back.length === 0, J(back));
    const gone = ["convertSingleLead", "reserveOutreachSend", "canSendOutreach", "outreachDraftRejection", "OUTREACH_SENDABLE_SOURCES"].filter(n => new RegExp("\\b" + n + "\\b").test(code(SRC)));
    check("B6. ... and their helpers (convertSingleLead, reserveOutreachSend, canSendOutreach, outreachDraftRejection, OUTREACH_SENDABLE_SOURCES)", gone.length === 0, J(gone));
  }

  /* ── C ───────────────────────────────────────────────────────────────── */
  section("C. Mastodon lead search and replies are gone; members' own Mastodon posting stays");
  {
    check("C1. mastodonRadar.js and redditRadar.js are deleted", !fs.existsSync(path.join(H.REPO, "mastodonRadar.js")) && !fs.existsSync(path.join(H.REPO, "redditRadar.js")));
    const gone = ["runMastodonRadarOnce", "ENABLE_MASTODON_RADAR", "sendMastodonReply", "truncateToMastodonLimit", "mastodonRetryAfterSeconds", "startRedditRadar", "mastodonDisabledLogged"];
    const left = gone.filter(n => Object.keys(ALL).some(f => new RegExp("\\b" + n + "\\b").test(code(ALL[f]))));
    check("C2. no code names the radar, its gate, the platform sender or Reddit's start", left.length === 0, J(left));
    check("C3. the scored sources and the reply platforms are Bluesky and Threads only (no Mastodon, no Reddit)",
      /const SCORED_SOURCES = \["bluesky", "threads"\];/.test(FILES[MR]) && /const REPLY_PLATFORMS = \["bluesky", "threads"\];/.test(FILES[LRP]) && !/mastodon|reddit/i.test(code(FILES[MR]) + code(FILES[LRP]) + code(FILES[RT])));
    // NAMED (Nov 23 2026, LR-2): BEFORE the list was ["bluesky", "youtube"] (the owner's bsky_leads); AFTER the member's own
    // member_leads by source, BizForce Needs and Threads added. Still no Mastodon.
    check("C4. the command centre counts no Mastodon finds", /var sources = \["bizforce", "bluesky", "youtube", "threads"\];/.test(SRC) && !/mastodon/.test(code(FILES["@lib/agentSignatures.js"]).slice(code(FILES["@lib/agentSignatures.js"]).indexOf("function sales("), code(FILES["@lib/agentSignatures.js"]).indexOf("function sales(") + 1500)));
    let committed = null;
    try { committed = cp.execFileSync("git", ["show", "HEAD:lib/memberMastodon.js"], { cwd: H.REPO, encoding: "utf8" }).replace(/\r\n/g, "\n"); } catch (e) { committed = null; }
    check("C5. lib/memberMastodon.js is byte for byte as committed", committed !== null && committed === FILES["@lib/memberMastodon.js"]);
    const routes = ["post /api/social/mastodon/connect", "post /api/social/mastodon/disconnect", "put /api/social/mastodon/automation", "post /api/agents/social/propose-post"];
    check("C6. the member Mastodon routes are all still served", routes.every(r => { const [m, p] = r.split(" "); return SRC.indexOf("app." + m + "(\"" + p + "\"") !== -1; }), J(routes));
    check("C7. the README lists no Mastodon radar variable", !/ENABLE_MASTODON_RADAR|MASTODON_ACCESS_TOKEN|MASTODON_INSTANCE|mastodonRadar\.js/.test(FILES["@README.md"]));
  }

  /* ── D ───────────────────────────────────────────────────────────────── */
  section("D. POST /api/leads/:id/send");
  const GOOD = "Try closing the valve under the sink first; a licensed plumber can usually fix a leaking trap the same day.";
  {
    const w = sendWorld(mkLead());
    check("D0. the route exists", typeof w.run === "function");
    const r = await w.run({ user: { id: OTHER, role: "member" }, member: true, body: { text: GOOD, draft: "something else" } });
    check("D1. a member's approved text is posted exactly as written, once, from the member's own account", r.status === 200 && r.body.sent === true && J(w.st.posted) === J([{ kind: "member", text: GOOD }]), J([r, w.st.posted]));
    check("D2. ... reserved in member_lead_replies before it posted, with that text", w.st.replies.length === 1 && w.st.replies[0].text === GOOD && w.st.replies[0].user_id === OTHER);
    const free = await sendWorld(mkLead()).run({ user: { id: OTHER }, member: false, body: { text: GOOD } });
    check("D3. a free account is refused (402), members only", free.status === 402);
    const off = sendWorld(mkLead(), { live: false });
    const offR = await off.run({ user: { id: OTHER }, member: true, body: { text: GOOD } });
    check("D4. SALES_SEND_LIVE not exactly \"true\": refused, nothing reserved or posted", offR.status === 409 && offR.body.code === "send_off" && off.st.posted.length === 0 && off.st.replies.length === 0, J(offR));
    check("D5. server.js: SALES_SEND_LIVE is the master switch and the caps are OUTREACH_DAILY_CAP and OUTREACH_ACCOUNT_DAILY_CEILING, read at the send",
      /sendLive: function \(\) \{ return process\.env\.SALES_SEND_LIVE === "true"; \},/.test(SRC) &&
      /caps: \{ get perMember\(\) \{ return OUTREACH_DAILY_CAP; \}, get ceiling\(\) \{ return OUTREACH_ACCOUNT_DAILY_CEILING; \} \},/.test(SRC));
    const plat = sendWorld(mkLead());
    const pr = await plat.run({ user: { id: OTHER, role: "admin" }, member: true, body: { text: GOOD } });
    check("D6. a member who is an admin is never given the platform account (Connect your Bluesky account to reply)", pr.status === 409 && pr.body.code === "not_connected" && plat.st.posted.length === 0, J(pr));
    const ow = sendWorld(mkLead({ user_id: OWNER }));
    const orr = await ow.run({ user: { id: OWNER, role: "admin" }, member: true, body: { text: GOOD } });
    check("D7. the owner, with no connection, posts from the platform account (the owner's own)", orr.status === 200 && ow.st.posted.length === 1 && ow.st.posted[0].kind === "platform", J(orr));
    const un = sendWorld(mkLead({ outreach_safe: null }));
    const ur = await un.run({ user: { id: OTHER }, member: true, body: { text: GOOD } });
    check("D8. a lead not scored SAFE is refused, nothing reserved or posted", ur.status === 422 && ur.body.code === "not_safe" && un.st.posted.length === 0 && un.st.replies.length === 0, J(ur));
    const cap = sendWorld(mkLead(), { count: 5 });
    const cr = await cap.run({ user: { id: OTHER }, member: true, body: { text: GOOD } });
    check("D9. the member's 5 a day reached (counted WITH the reservation): refused at the send, the reservation removed, nothing posted",
      cr.status === 429 && cr.body.code === "member_daily_cap" && cap.st.posted.length === 0 && cap.st.released === 1, J(cr));
    const four = sendWorld(mkLead(), { count: 4 });
    const fr = await four.run({ user: { id: OTHER }, member: true, body: { text: GOOD } });
    check("D10. ... the 5th of the day posts", fr.status === 200 && four.st.posted.length === 1, J(fr));
    const fc = sendWorld(mkLead(), { failCount: true });
    const fcr = await fc.run({ user: { id: OTHER }, member: true, body: { text: GOOD } });
    check("D11. a cap that cannot be counted fails closed: refused, reservation removed, nothing posted", fcr.status === 503 && fcr.body.code === "check_failed" && fc.st.posted.length === 0 && fc.st.released === 1, J(fcr));
    const rt = code(FILES[RT]);
    check("D12. the reservation and the post run inside one serial step (LR.serial), the reservation first",
      /var outcome = await LR\.serial\(async function \(\) \{\n\s*var slot = await LR\.reserveReply\(deps\.sb,/.test(rt) && rt.indexOf("LR.reserveReply(") < rt.indexOf("postBluesky(userId, acct"));
    const iife = /const OUTREACH_DAILY_CAP = (\(function \(\) \{[\s\S]*?\}\)\(\));/.exec(SRC);
    const parse = v => iife ? vm.runInNewContext(iife[1], { process: { env: v === undefined ? {} : { OUTREACH_DAILY_CAP: v } }, Number, Math, String }) : NaN;
    const table = [[undefined, 5], ["", 5], ["  ", 5], ["abc", 5], ["0", 5], ["-2", 5], ["7", 7], ["2.9", 2]].map(([v, want]) => [v, parse(v), want]);
    check("D13. OUTREACH_DAILY_CAP fails closed to 5, never NaN (" + J(table.map(x => x[1])) + ")", table.every(x => x[1] === x[2]), J(table));
    const RA = (() => { const m = new Module("ra", module); m._compile(FILES[ACCESS], path.join(H.REPO, "lib", "routeAccess.js")); return m.exports; })();
    check("D14. the route is in group M", RA.groupOf("post /api/leads/:id/send") === "M" && RA.groupOf("post /api/leads/:id/draft") === "M");
    check("D15. drafting never posts: the draft route makes no account call but the account check", (function () { const d = rt.slice(rt.indexOf("app.post(\"/api/leads/:id/draft\""), rt.indexOf("app.post(\"/api/leads/:id/send\"")); const body = d.slice(d.indexOf("{")); return body.length > 300 && !/actAs|postBluesky|\.post\(|threads\.reply/.test(body); })());
  }

  /* ── E ───────────────────────────────────────────────────────────────── */
  section("E. scoring is on the member's ledger");
  {
    const files = [FILES[LR], FILES[YR], FILES[MR], FILES[RT], FILES[LRP], FILES["@lib/leadFingerprint.js"]];
    check("E1. no Lead Radar file calls a model of its own (no Anthropic client, no messages.create)", files.every(f => !/anthropic|messages\.create\(/i.test(code(f))));
    check("E2. every score is ONE deps.callModel call with the member's id and the route memberRadarScore (agent_type lead_radar)",
      (code(FILES[MR]).match(/deps\.callModel\(/g) || []).length === 1 && /out = await deps\.callModel\(userId, scoringPrompt\(member\.fp, names, lead\), 300, SCORE_ROUTE\);/.test(FILES[MR]) &&
      /const SCORE_ROUTE = "memberRadarScore";/.test(FILES[MR]) && /const AGENT_TYPE = "lead_radar";/.test(FILES[MR]));
    check("E3. server.js: callModel is callAnthropicText (limits first, the member's key first, the ledger row), with the member as payer and on the ledger as lead_radar",
      /function leadRadarModelCall\(userId, prompt, maxTokens, route\) \{\n\s*return callAnthropicText\(prompt, maxTokens, userId, "claude-haiku-4-5-20251001", \{ user_id: userId, agent_type: "lead_radar", route: route \}\);/.test(SRC) &&
      /callModel: leadRadarModelCall,/.test(SRC));
    check("E4. server.js hands the member radar its deps before the radar starts", /require\("\.\/leadRadar"\)\.setMemberRadarDeps\(leadRadarMemberDeps\);[\s\S]{0,400}startLeadRadar\(/.test(SRC));
    check("E5. with no deps handed in the radar captures and scores nothing", /if \(!memberDeps\) \{/.test(FILES[LR]) && /memberDeps = deps && typeof deps\.tierOf === "function" && typeof deps\.callModel === "function" \? deps : null;/.test(FILES[LR]));
    check("E6. youtubeRadar.js makes no Anthropic call at all", !/anthropic|messages\.create\(/i.test(code(FILES[YR])));
  }

  /* ── F ───────────────────────────────────────────────────────────────── */
  section("F. the PART D fixes, SMS, and archived rows");
  {
    const accessFile = FILES[ACCESS];
    const g = k => { const m = new Module("ra", module); m._compile(accessFile, path.join(H.REPO, "lib", "routeAccess.js")); return m.exports.groupOf(k); };
    const demand = fnBody(SRC, "async function loadDemandRows(") || "";
    check("F1. demand-signals is every member's (group M) and reads only that member's own leads (member_leads, user_id)",
      g("post /api/agents/rd/demand-signals") === "M" && /q = q\.eq\("user_id", userId\)/.test(demand) && /\.from\("member_leads"\)/.test(demand) && !/bsky_leads/.test(code(demand)));
    check("F2. the owner's old draft-reply route is gone", SRC.indexOf("app.post(\"/api/leads/draft-reply\"") === -1 && g("post /api/leads/draft-reply") === null);
    check("F3. the card leads read is in group F (a member always reads their own leads), and its comment says so",
      g("get /api/digital-cards/:id/leads") === "F" && /in group F now \(lib\/routeAccess\.js\), which is what makes that sentence true/.test(SRC));
    check("F4. no import of startRedditRadar or runMastodonRadarOnce; the reddit_leads table is kept (no migration drops it)",
      !/require\("\.\/redditRadar"\)|require\("\.\/mastodonRadar"\)/.test(code(SRC) + code(FILES[LR])) &&
      !fs.readdirSync(path.join(H.REPO, "supabase", "migrations")).filter(f => /.sql$/.test(f)).some(f => /drop table[^;]*reddit_leads/i.test(fs.readFileSync(path.join(H.REPO, "supabase", "migrations", f), "utf8"))));
    check("F5. the radar counts what the upsert inserted (ignoreDuplicates, then .select), never the rows it tried",
      /\.upsert\(rows, \{ onConflict: "user_id,source,external_id", ignoreDuplicates: true \}\)\.select\("id"\);\n\s*if \(r\.error\) throw r\.error;\n\s*return \(r\.data \|\| \[\]\)\.length;/.test(FILES[MR]));
    check("F6. radar_status is written after every tick (migration 135's outcomes)", /if \(memberDeps\) await writeRadarHeartbeat\(tickHeartbeat\(startedAt, result\), "tick"\);/.test(FILES[LR]));
    check("F7. the stale comment is fixed: no \"four lead-reading routes\"; migration 068 is not edited",
      !/The refusal the four lead-reading routes send/.test(SRC) && cp.execFileSync("git", ["diff", "--name-only", "HEAD", "--", "supabase/migrations/068_*"], { cwd: H.REPO, encoding: "utf8", shell: false }).trim() === "");
    const smsSend = routeBody("post", "/api/sms/send") || "";
    const sms = bareRoute("post", "/api/sms/send", [], {});
    const smsR = sms ? await sms({ body: { to: "15551234567", message: "hi" } }) : null;
    check("F8. /api/sms/send answers 503 \"SMS sending is not offered\" and has no sending code", smsR && smsR.status === 503 && /SMS sending is not offered/.test(smsR.body.error) &&
      !/twilio|fetch\(|messages\.create/.test(code(smsSend)) && !/SMS_DIRECT_SEND_ENABLED/.test(code(SRC)), J(smsR));
    const drip = fnBody(SRC, "async function runDripEngine(") || "";
    check("F9. runDripEngine stays a dry run (no Twilio, no fetch), and dripTick starts only when server.js is the program",
      drip.length > 200 && !/twilio\s*\(|fetch\(|messages\.create/.test(code(drip)) && /if \(require\.main === module && process\.env\.ENABLE_DRIP_SCHEDULER === "true"\) \{\n\s*shutdownControl\.trackInterval\("dripTick"/.test(SRC));

    function smsWorld(opts) {
      const st = { subs: [], events: [] };
      const db = H.fakeDb(function (t, q) {
        if (t === "sms_subscribers" && q.op === "insert") { [].concat(q.payload).forEach(p => st.subs.push(p)); return { data: [].concat(q.payload)[0], error: null }; }
        if (t === "consent_events" && q.op === "insert") { if (opts && opts.eventFails) return { data: null, error: { message: "no" } }; st.events.push(q.payload); return { data: null, error: null }; }
        if (t === "sms_subscribers") return { data: [], error: null, count: 0 };
        return { data: null, error: null };
      });
      const stubs = { supabase: db.client, findOrCreateContactByPhone: async () => "contact-1" };
      return { st, add: bareRoute("post", "/api/sms/subscribers", SMS_ROOTS, stubs), bulk: bareRoute("post", "/api/sms/subscribers/bulk", SMS_ROOTS, stubs) };
    }
    const past = new Date(Date.now() - 3 * 86400000).toISOString();
    const a1 = smsWorld(); await a1.add({ body: { phone: "+1 555 123 4567", name: "Ann", consent: true } });
    check("F10. consent ticked but no source or time: stored as pending, no consent row", a1.st.subs.length === 1 && a1.st.subs[0].consent_status === "pending" && a1.st.events.length === 0, J(a1.st));
    const a2 = smsWorld(); await a2.add({ body: { phone: "+1 555 123 4567", name: "Ann", consent: true, consent_source: "paper form at the shop", consent_at: past } });
    check("F11. consent with source and time: a consent_events row (sms, granted, that source and time), then opted in",
      a2.st.subs[0] && a2.st.subs[0].consent_status === "opted_in" && a2.st.events.length === 1 && a2.st.events[0].channel === "sms" && a2.st.events[0].action === "granted" &&
      a2.st.events[0].source === "paper form at the shop" && a2.st.events[0].occurred_at === past && a2.st.events[0].contact_id === "contact-1", J(a2.st));
    const a3 = smsWorld({ eventFails: true }); await a3.add({ body: { phone: "+1 555 123 4567", consent: true, consent_source: "form", consent_at: past } });
    check("F12. consent that could not be recorded: pending", a3.st.subs[0] && a3.st.subs[0].consent_status === "pending", J(a3.st));
    const a4 = smsWorld(); await a4.add({ body: { phone: "+1 555 123 4567", consent: true, consent_source: "form", consent_at: new Date(Date.now() + 86400000).toISOString() } });
    check("F13. a consent time in the future: pending", a4.st.subs[0] && a4.st.subs[0].consent_status === "pending", J(a4.st));
    const a5 = smsWorld(); await a5.add({ body: { phone: "+1 555 123 4567", consent: false } });
    check("F14. consent refused: opted out, no consent row", a5.st.subs[0] && a5.st.subs[0].consent_status === "opted_out" && a5.st.events.length === 0);
    const b1 = smsWorld(); await b1.bulk({ body: { subscribers: [{ phone: "+15551230001", consent: true, consent_source: "signup sheet", consent_at: past }, { phone: "+15551230002", consent: true }, { phone: "+15551230003" }] } });
    check("F15. import: each number needs its own recorded consent (1 opted in with a row; 2 pending)", J(b1.st.subs.map(x => x.consent_status)) === J(["opted_in", "pending", "pending"]) && b1.st.events.length === 1, J(b1.st));
    const mig = FILES["@supabase/migrations/203_lr1_archived_and_sms_pending.sql"] || "";
    check("F16. migration 203b sets the sms_subscribers.consent_status default to 'pending', existing rows unchanged", /ALTER TABLE public\.sms_subscribers ALTER COLUMN consent_status SET DEFAULT 'pending';/.test(mig) && !/UPDATE /i.test(mig));
    check("F17. migration 203 is paste-safe: no <= or >=, no DO block, no BEGIN or COMMIT, CHECK dropped if exists first",
      !/<=|>=|\bDO\b|\bBEGIN\b|\bCOMMIT\b/i.test(mig.replace(/--[^\n]*/g, "")) && mig.indexOf("DROP CONSTRAINT IF EXISTS sales_lead_pipeline_status_check") !== -1 &&
      mig.indexOf("DROP CONSTRAINT IF EXISTS sales_lead_pipeline_status_check") < mig.indexOf("ADD CONSTRAINT sales_lead_pipeline_status_check") && /'archived'\)\);/.test(mig));
    check("F18. archived rows never appear as leads: the command centre's pipeline, demand, the high-intent trigger and the member's list skip them; members cannot set it",
      /\.neq\("status", "archived"\)   \/\/ NAMED \(Nov 23 2026, LR-1\): archived rows are not leads/.test(SRC) && /\.neq\("status", "archived"\);/.test(demand) &&
      /\.neq\("status", "archived"\)\.order\("id"/.test(FILES["@lib/triggerRunner.js"]) && /\.not\("status", "in", "\(dismissed,archived\)"\)/.test(FILES[RT]) &&
      /const MEMBER_STATUSES = \["new", "saved", "dismissed", "won", "lost"\];/.test(FILES[RT]) && /var SALES_LEAD_STATUSES = \["new", "drafted", "contacted", "replied", "converted"\];/.test(SRC));
    const arch = FILES["@scripts/oneoff/lr1Archive.js"] || "";
    check("F19. the archive script is a dry run by default, never deletes, never re-scores, never touches YouTube or a Bluesky row from 2026-08-20 on",
      /const APPLY = process\.argv\.indexOf\("--apply"\) !== -1;/.test(arch) && !/\.delete\(|anthropic|scoreNewLeads/i.test(code(arch)) && !/eq\("source", "youtube"\)/.test(arch) &&
      /const BLUESKY_CUTOFF = "2026-08-20T00:00:00\.000Z";/.test(arch) && (arch.match(/\.lt\("created_at", BLUESKY_CUTOFF\)/g) || []).length === 2);
  }

  /* ── G ───────────────────────────────────────────────────────────────── */
  section("G. the pages");
  {
    const sp = FILES[SALES] || "";
    check("G1. sales.html: no confirm dialog, no bulk post, no segment, no draft or send route of the old radar", !/window\.confirm\(/.test(sp) && !/salesConvertAllBtn|convertAllHighIntent|segment:/.test(sp) &&
      !/\/api\/agents\/sales\/(convert|send-approved|leads|pipeline|lead-status)/.test(code(sp)) && !/postApprovedReply/.test(sp));
    check("G2. ... the owner's read-only archive comes from GET /api/leads/archive", /fetch\(API_URL \+ "\/api\/leads\/archive", \{ headers: \{ "Authorization": "Bearer " \+ token \} \}\)/.test(sp));
    const rp = FILES[RADAR] || "";
    const send = fnBody(rp, "function send(") || "";
    check("G3. lead-radar.html: \"Post my reply\" sends exactly the text in the box to /api/leads/:id/send, bound only to its own button",
      /var text = box\.value\.trim\(\);/.test(send) && /call\("POST", "\/api\/leads\/" \+ encodeURIComponent\(l\.id\) \+ "\/send", \{ text: text, add_link: S\.sheetLink \}\)/.test(send) &&
      count(rp, "/send\"") === 1 && count(rp, "send();") === 1 && /if \(e\.target\.closest\("#lrPost"\)\) \{ send\(\); return; \}/.test(rp));
    const draft = fnBody(rp, "function draft(") || "";
    check("G4. Write it again and the first draft only ask for a draft; nothing posts until Post my reply", /\/draft"/.test(draft) && !/\/send"|send\(\)/.test(draft) && />Post my reply<\/button>/.test(rp) && /<textarea class="lr-draft" id="lrDraft"/.test(rp));
    check("G5. lead-radar.html: never \"Check console\"; signed out it asks for sign-in", !/Check console/.test(rp) && /Sign in to see Lead Radar\./.test(rp));
    // NAMED (Nov 24 2026, LR-3): BEFORE "bf-access.js no longer names #sfMessage" (LR-1: no button carried it). AFTER the storefront's
    // Message button carries it again (checkInbound S holds the button), so the selector is named once and is never dead.
    check("G6. bf-access.js names \"#sfMessage\" once, and seller.html draws a button with that id", count(code(FILES[BFA]), "#sfMessage") === 1 && /btn.id = "sfMessage";/.test(FILES["seller.html"] || ""));
    check("G7. sitemap-pages.xml no longer lists /suppressed.html", !/suppressed\.html/.test(FILES[SITEMAP]));
    // NAMED (Nov 26 2026, FX4A): BEFORE "h1b"; AFTER "fx4a" (the boombox, AI Agent Tasks, the Oracle pages and the calendar on phones). H1B: BEFORE "h1"; AFTER "h1b" (no mist on Home or the composer; room under the mist at the end of card-view and proposals). H1: BEFORE "g1"; AFTER "h1" (the home tabs, Search and the storefront badge). HOTFIX-G1: BEFORE "lr4b"; AFTER "g1" (phone layouts restored; only the controls under the Guide tab moved). LR-4B: BEFORE "lr4"; AFTER "lr4b" (the storefront menu draws whichever loads first). LR-4: BEFORE "lr3b"; AFTER "lr4" (Get found). LR-3B: BEFORE "lr3"; AFTER "lr3b" (nothing to tap under the Guide tab on the phone). LR-3: BEFORE "lr2b"; AFTER "lr3" (Inbound, the storefront Message button). LR-2B: BEFORE "lr2"; LR-2: BEFORE "lr1b".
    check("G8. sw.js SHELL_REV is \"fx4a\"", /var SHELL_REV = "fx4a";/.test(FILES["sw.js"]));
    check("G9. the Privacy Policy no longer says Mastodon receives outreach replies", !/Bluesky and Mastodon: replies sent through outreach/.test(FILES["privacy.html"]));
    const smsPage = FILES[SMS] || "";
    check("G10. sms.html sends where and when consent was given, or no consent", /consent_source: source, consent_at: day \+ "T00:00:00\.000Z"/.test(smsPage) && /id="sms-add-source"/.test(smsPage) && /id="sms-bulk-source"/.test(smsPage));
  }
  finish();
})().catch(e => { console.log("    FAIL  the check ran to the end  [" + (e && e.stack || e) + "]"); process.exit(1); });
