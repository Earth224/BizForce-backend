"use strict";
/* ═════════════════════════════════════════════════════════════════════════════
   checkLeadRadarRepair.js — LR-1 (Nov 23 2026): Lead Radar repaired.

   THE OWNER'S RULE. Nothing is posted, replied or sent to anyone outside BizForce
   unless a person approved that exact text first. Everyone, the owner included.

   WHAT IT PROVES (never the real database, never the network, no model call):
     A. Every outbound post or send in server.js, lib/, leadRadar.js and
        youtubeRadar.js is accounted for: sendBlueskyReply is called from one
        place, POST /api/agents/sales/send-approved, with the text in the request;
        the platform's Bluesky login posts only there and in the proposal
        executors a member approves; nothing creates a Twilio client or reads a
        platform Mastodon token.
     B. The automatic sales loop is gone: no runSalesAutoConvert, no
        salesAutoConvertTick, no ENABLE_SALES_AUTOLOOP / SALES_AUTOLOOP_* read,
        no schedule entry, no export. POST /api/agents/sales/convert drafts one
        lead and never posts; segment mode answers 400.
     C. Mastodon lead search and replies are gone (files, imports, sources,
        sender, token reads), while members' own Mastodon posting stays
        (lib/memberMastodon.js byte for byte as committed, its routes present).
     D. send-approved: owner only, SALES_SEND_LIVE is the master switch, the text
        is required (300 at most, emoji stripped, links checked), the lead must be
        Bluesky, scored, recent, outreach_safe and reply_invited, one reply per
        post, and BOTH caps are checked at the send with the send reserved first,
        so two racing requests never overshoot.
     E. The scorer is on the ledger: every Anthropic call in leadRadar.js is
        capped first and recorded after; youtubeRadar.js makes none; with no
        ledger nothing is scored.
     F. Every PART D fix, the SMS rules (no sending, consent recorded or the
        number is pending), and archived rows never shown as leads.

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
const SALES = "agents/sales.html", RADAR = "agents/lead-radar.html", BFA = "scripts/bf-access.js", SITEMAP = "sitemap-pages.xml", SMS = "agents/sms.html";

const MUTATIONS = {
  // A / D: the send route
  "send-without-live-switch": [[SERVER, `    if (process.env.SALES_SEND_LIVE !== "true") {\n      return res.status(409).json({ error: "Posting replies is switched off (SALES_SEND_LIVE). Nothing was posted.", code: "send_off" });`, `    if (false) {\n      return res.status(409).json({ error: "Posting replies is switched off (SALES_SEND_LIVE). Nothing was posted.", code: "send_off" });`]],
  "send-not-owner-only": [[SERVER, `    if (userId !== OUTREACH_CREDENTIAL_OWNER_ID) return res.status(403).json(OUTREACH_UNAVAILABLE);\n\n    if (process.env.SALES_SEND_LIVE`, `    if (false) return res.status(403).json(OUTREACH_UNAVAILABLE);\n\n    if (process.env.SALES_SEND_LIVE`]],
  "send-no-length-limit": [[SERVER, `    if (Array.from(text).length > SEND_APPROVED_MAX_CHARS) {`, `    if (false) {`]],
  "send-no-emoji-strip": [[SERVER, `    var text = stripOutreachEmoji(rawText);`, `    var text = rawText.trim() || null;`]],
  "send-no-link-check": [[SERVER, `    if (linkRejection) return res.status(400)`, `    if (false) return res.status(400)`]],
  "send-any-ref-token": [[SERVER, `        checkText = text.split(destUrl.origin + destUrl.pathname + "?ref=" + outreachRefToken(lead)).join(offerDestination);`, `        checkText = text.split("?ref=").map(function (part, i) { return i ? part.replace(/^[A-Za-z0-9_-]+/, "") : part; }).join("");`]],
  "send-unsafe-allowed": [[SERVER, `    if (lead.outreach_safe !== true) refusals.push("not_outreach_safe");`, `    if (lead.outreach_safe === false) refusals.push("not_outreach_safe");`]],
  "send-uninvited-allowed": [[SERVER, `    if (lead.reply_invited !== true) refusals.push("reply_not_invited");`, ``]],
  "send-any-source": [[SERVER, `    if (OUTREACH_SENDABLE_SOURCES.indexOf(lead.source) === -1) refusals.push("unsupported_source");`, ``]],
  "send-old-posts": [[SERVER, `    if (!Number.isFinite(postMs) || postMs < Date.now() - OUTREACH_MAX_POST_AGE_DAYS * 24 * 60 * 60 * 1000) refusals.push("post_too_old");`, ``]],
  "send-archived": [[SERVER, `    if (lead.status !== "scored" || !leadHasRealScore(lead)) refusals.push("not_scored");`, ``]],
  "cap-excludes-reservation": [[SERVER, `    if (mine > OUTREACH_DAILY_CAP) { await release();`, `    if (mine - 1 > OUTREACH_DAILY_CAP) { await release();`]],
  "no-account-ceiling": [[SERVER, `    if (all > OUTREACH_ACCOUNT_DAILY_CEILING) { await release();`, `    if (false) { await release();`]],
  "no-one-reply-per-post": [[SERVER, `  if ((anyReply.data || []).length) return { ok: false, reason: "already_contacted" };`, ``]],
  "no-release-on-failure": [[SERVER, `      if (!result || !result.sent) { await slot.release();`, `      if (!result || !result.sent) {`]],
  "count-error-sends": [[SERVER, `    await release();\n    console.error("[outreach] Cap check failed at the send — refusing:", (countErr && countErr.message) || countErr);\n    return { ok: false, reason: "check_failed" };`, `    console.error("[outreach] Cap check failed at the send — refusing:", (countErr && countErr.message) || countErr);`]],
  "cap-parse-nan": [[SERVER, `  var parsed = Math.floor(Number(raw));\n  if (!Number.isFinite(parsed) || parsed < 1) return 5;\n  return parsed;\n})();`, `  return Number(raw);\n})();`]],
  // B: the loop and the convert route
  "convert-sends": [[SERVER, `  // \${N}: the send block that stood here is gone; nothing in this function posts.`.replace("${N}", "NAMED (Nov 23 2026, LR-1)"), `  if (cleanMessage) await sendBlueskyReply(lead, cleanMessage);`]],
  "segment-back": [[SERVER, `      return res.status(400).json({ error: "Provide lead_post_uri: one lead is drafted at a time." });`, `      targetLeads = [];`]],
  "autoloop-back": [[JOBS, `  { tick: "leadRadarTick", every_ms: 300000, jobs: [] },`, `  { tick: "salesAutoConvertTick", every_ms: 300000, jobs: [] },\n  { tick: "leadRadarTick", every_ms: 300000, jobs: [] },`]],
  "convert-any-source": [[SERVER, `      if (OUTREACH_SENDABLE_SOURCES.indexOf(requestedLead.source) === -1) {`, `      if (false) {`]],
  // C: Mastodon
  "mastodon-scorable": [[LR, `const SCORABLE_SOURCES = ["bluesky"];`, `const SCORABLE_SOURCES = ["bluesky", "mastodon"];`]],
  "mastodon-sendable": [[SERVER, `const OUTREACH_SENDABLE_SOURCES = ["bluesky"];`, `const OUTREACH_SENDABLE_SOURCES = ["bluesky", "mastodon"];`]],
  "mastodon-token-read": [[SERVER, `const SEND_APPROVED_MAX_CHARS = 300;`, `const SEND_APPROVED_MAX_CHARS = 300;\nvar platformMastodonToken = process.env.MASTODON_ACCESS_TOKEN;`]],
  // E: the scorer
  "scorer-unrecorded": [[LR, `        await modelLedger.record({\n          userId:    SCORING_ACCOUNT_ID,`, `        if (false) await modelLedger.record({\n          userId:    SCORING_ACCOUNT_ID,`]],
  "scorer-uncapped": [[LR, `          await modelLedger.enforce(SCORING_ACCOUNT_ID, SCORER_LEDGER_ROUTE);`, `          void 0;`]],
  "scorer-no-ledger-scores": [[LR, `var modelLedger = null;`, `var modelLedger = { record: async function () {}, enforce: async function () { return true; } };`]],
  "scorer-wrong-agent": [[LR, `const SCORER_AGENT_TYPE = "lead_radar";`, `const SCORER_AGENT_TYPE = "sales";`]],
  "youtube-unrecorded-call": [[YR, `module.exports = { runYoutubeRadarOnce, KEYWORDS };`, `async function summarise(t) { return new (require("@anthropic-ai/sdk"))().messages.create({ model: "m", max_tokens: 5, messages: [] }); }\nmodule.exports = { runYoutubeRadarOnce, KEYWORDS };`]],
  // F: PART D
  "demand-by-role": [[SERVER, `      if (userId !== OWNER_ACCOUNT_ID) {\n        return res.status(403).json({ error: DEMAND_OWNER_ONLY });`, `      if (req.user.role !== "admin") {\n        return res.status(403).json({ error: DEMAND_OWNER_ONLY });`]],
  "draft-reply-open": [[SERVER, `    if (req.user.id !== OUTREACH_CREDENTIAL_OWNER_ID) return res.status(403).json(LEAD_RADAR_UNAVAILABLE);\n`, ``]],
  "card-leads-members": [[ACCESS, `  "get /api/digital-cards/:id/leads"   // NAMED`, `  "get /api/digital-cards/:id/leads-x"   // NAMED`]],
  "youtube-count-rows": [[YR, `        var newCount = (insertedRows || []).length;`, `        var newCount = rows.length;`]],
  "youtube-no-heartbeat": [[LR, `          }, "youtube pass", "youtube");`, `          }, "youtube pass");`]],
  "sms-sends": [[SERVER, `app.post("/api/sms/send", requireAuth, function (req, res) {\n  return res.status(503)`, `app.post("/api/sms/send", requireAuth, function (req, res) {\n  require("twilio")(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);\n  return res.status(503)`]],
  "sms-consent-optional": [[SERVER, `  if (!source || !Number.isFinite(atMs) || atMs > Date.now() + 5 * 60 * 1000) return { state: "none" };`, `  if (false) return { state: "none" };`]],
  "sms-consent-unrecorded": [[SERVER, `    if (ev.error) { console.error("[sms/consent] consent not recorded, number stored as pending:", ev.error.message); return "pending"; }`, ``]],
  "sms-none-opted-in": [[SERVER, `  if (proof.state !== "given") return "pending";`, `  if (proof.state !== "given") return "opted_in";`]],
  "drip-unguarded": [[SERVER, `if (require.main === module && process.env.ENABLE_DRIP_SCHEDULER === "true") {`, `if (process.env.ENABLE_DRIP_SCHEDULER === "true") {`]],
  "archived-in-pipeline": [[SERVER, `      .neq("status", "archived")   // NAMED (Nov 23 2026, LR-1): archived rows never appear as leads`, ``]],
  // frontend
  "sales-confirm-back": [[SALES, `      function convertLead(idx, btn) {\n        var lead = currentLeads[idx];\n        if (!lead) return;`, `      function convertLead(idx, btn) {\n        var lead = currentLeads[idx];\n        if (!lead) return;\n        if (!window.confirm("Post?")) return;`]],
  "sales-draft-posts": [[SALES, `          if (result) renderConversion(idx, result.conversion || "", result.draft || "", result.draft_rejection || "");`, `          if (result) { renderConversion(idx, result.conversion || "", result.draft || "", result.draft_rejection || ""); postApprovedReply(idx, btn); }`]],
  "radar-console": [[RADAR, `The leads could not be loaded. Try Refresh in a moment.`, `Failed to load leads. Check console.`]],
  "radar-no-signin": [[RADAR, `      if (!tok()) { showSignIn(countEl, list); return; }\n`, ``]],
  "sfmessage-back": [[BFA, `"#pfsMessage", ".btn-message", "[data-members-only]"]`, `"#pfsMessage", ".btn-message", "#sfMessage", "[data-members-only]"]`]],
  "suppressed-back": [[SITEMAP, `</urlset>`, `  <url><loc>https://bizforceai.net/suppressed.html</loc></url>\n</urlset>`]]
};

const T = H.setup(__filename, MUTATIONS, [SERVER, LR, YR, JOBS, ACCESS, "@lib/memberMastodon.js", "@lib/yourData.js", "@README.md",
  "@supabase/migrations/203_lr1_archived_and_sms_pending.sql", "@scripts/oneoff/lr1Archive.js", "@lib/triggerRunner.js", "@lib/agentSignatures.js",
  SALES, RADAR, BFA, SITEMAP, SMS, "sw.js", "privacy.html"]);
const { FILES, check, finish, J, has, count } = T;
const SRC = FILES[SERVER];
const code = t => S.stripComments ? S.stripComments(t) : String(t || "").replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
const OWNER = require(path.join(H.REPO, "lib", "ownerAccount.js")).OWNER_ACCOUNT_ID;
const OTHER = "22222222-2222-4222-8222-222222222222";
function section(t) { console.log("\n== " + t); }
function fnBody(src, sig) { const at = src.indexOf(sig); if (at < 0) return null; const open = src.indexOf("{", at + sig.length - 1); const end = S.braceMatch(src, open); return end > open ? src.slice(at, end + 1) : null; }
function routeBody(method, p) { return H.routeStatement(SRC, method, p) || (function () { const at = SRC.indexOf("app." + method + "(\"" + p + "\","); if (at < 0) return null; const open = SRC.indexOf("{", at); const end = S.braceMatch(SRC, open); return SRC.slice(at, end + 1); })(); }
/* A route run with only the small server definitions it is given (H.route builds the whole closure, which for the
   convert and draft-reply routes is most of server.js and takes minutes). */
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
const SEND_ROOTS = ["safeText", "stripOutreachEmoji", "leadHasRealScore", "OUTREACH_SENDABLE_SOURCES", "OUTREACH_MAX_POST_AGE_DAYS", "OUTREACH_BOOK_PRODUCT", "OUTREACH_BOOK_DESTINATION",
  "OUTREACH_PRODUCT_DESTINATIONS", "outreachDraftRejection", "outreachSerial", "reserveOutreachSend", "OUTREACH_UNAVAILABLE", "formatLeadHandle", "SEND_APPROVED_MAX_CHARS", "outreachRefToken"];
const SMS_ROOTS = ["safeText", "canonicalPhone", "smsConsentProof", "smsConsentStatusFor"];
const CONVERT_NAMES = ["safeText", "leadHasRealScore", "LEAD_SCORE_FAILED_REASON", "OUTREACH_SENDABLE_SOURCES", "OUTREACH_MAX_POST_AGE_DAYS", "OUTREACH_UNAVAILABLE"];
const libFiles = fs.readdirSync(path.join(H.REPO, "lib")).filter(f => /\.js$/.test(f));
const LIB = {}; libFiles.forEach(f => { LIB[f] = FILES["@lib/" + f] || fs.readFileSync(path.join(H.REPO, "lib", f), "utf8").replace(/\r\n/g, "\n"); });
const ALL = Object.assign({ "server.js": SRC, "leadRadar.js": FILES[LR], "youtubeRadar.js": FILES[YR] }, Object.fromEntries(Object.keys(LIB).map(k => ["lib/" + k, LIB[k]])));

(async function main() {
  /* ── A ───────────────────────────────────────────────────────────────── */
  section("A. every outbound post or send is accounted for");
  {
    const sbr = Object.keys(ALL).map(f => [f, (code(ALL[f]).match(/sendBlueskyReply\(/g) || []).length]).filter(x => x[1]);
    check("A1. sendBlueskyReply is defined once and called once, both in server.js (" + J(sbr) + ")", J(sbr) === J([["server.js", 2]]));
    const sendRoute = routeBody("post", "/api/agents/sales/send-approved") || "";
    check("A2. ... and that one call is inside POST /api/agents/sales/send-approved, with the text from the request",
      /result = await sendBlueskyReply\(lead, text\);/.test(sendRoute) && /var rawText = typeof \(req\.body && req\.body\.text\) === "string" \? req\.body\.text : "";/.test(sendRoute));
    const gateSites = (code(SRC).match(/bskyGate\.call\(/g) || []).length;
    const gateFns = [];
    { const re = /bskyGate\.call\(/g; let m; const c = code(SRC); while ((m = re.exec(c)) !== null) { const before = c.slice(0, m.index); const f = /(?:^|\n)(?:async )?function ([A-Za-z0-9_]+)\([^)]*\) \{(?![\s\S]*\n(?:async )?function [A-Za-z0-9_]+\()/.exec(before); gateFns.push(f ? f[1] : "?"); } }
    check("A3. the platform's Bluesky login posts in three functions only: sendBlueskyReply, executePublishSocialPost and blueskyActAs (" + J(gateFns) + ")",
      gateSites === 3 && J(gateFns.slice().sort()) === J(["blueskyActAs", "executePublishSocialPost", "sendBlueskyReply"]));
    const execUsers = (code(SRC).match(/executePublishSocialPost/g) || []).length;
    check("A4. executePublishSocialPost runs only as the approved-proposal executor or the member's own filing (3 mentions: definition, executor map, the filing route)",
      execUsers === 3 && /publish_social_post: executePublishSocialPost,/.test(SRC) && /autoExecuteFiledProposal\(proposal, executePublishSocialPost\)/.test(SRC));
    const actAs = (code(SRC).match(/blueskyActAs\(/g) || []).length;
    check("A5. blueskyActAs is used by the member's mention replies and profile edits (definition plus 3 calls), never by Lead Radar", actAs === 4 &&
      !/blueskyActAs/.test(fnBody(SRC, "async function convertSingleLead(") || "x"));
    const twilioMade = Object.keys(ALL).filter(f => /twilio\s*\(\s*(process|accountSid|sid)|\.messages\.create\(\s*\{\s*(to|from|body)\s*:/.test(code(ALL[f])));
    check("A6. nothing creates a Twilio client or sends an SMS (twilio is used only to verify inbound webhooks)", twilioMade.length === 0 &&
      (code(SRC).match(/twilio\./g) || []).every(x => x === "twilio.") && /twilio\.validateRequest\(/.test(SRC) && (code(SRC).match(/twilio\.[a-zA-Z]+/g) || []).every(x => x === "twilio.validateRequest"), J(twilioMade));
    const mastoReads = Object.keys(ALL).filter(f => /process\.env\.MASTODON_(ACCESS_TOKEN|INSTANCE)/.test(code(ALL[f])));
    check("A7. no file reads a platform Mastodon token or instance", mastoReads.length === 0, J(mastoReads));
    const mm = LIB["memberMastodon.js"] || "";
    check("A8. the one Mastodon post (lib/memberMastodon.js /api/v1/statuses) runs on the member's own connection", (code(mm).match(/\/api\/v1\/statuses"/g) || []).length === 1 && !/process\.env\.MASTODON_ACCESS_TOKEN/.test(mm));
    check("A9. convertSingleLead posts nothing: no sender, no Bluesky login, no outreach_sends write, no 'contacted'",
      (function () { const b = code(fnBody(SRC, "async function convertSingleLead(") || ""); return b.length > 1000 && !/sendBlueskyReply|bskyGate|blueskyActAs|from\("outreach_sends"\)|status:\s*"contacted"/.test(b); })());
  }

  /* ── B ───────────────────────────────────────────────────────────────── */
  section("B. the automatic sales loop is gone");
  {
    const names = ["runSalesAutoConvert", "salesAutoConvertTick", "ENABLE_SALES_AUTOLOOP", "SALES_AUTOLOOP_DRY_RUN", "SALES_AUTOLOOP_DAILY_DRAFT_CAP", "salesAutoConvertRunning"];
    const left = names.filter(n => Object.keys(ALL).some(f => new RegExp("\\b" + n + "\\b").test(code(ALL[f]))));
    check("B1. none of the loop's names is in any code (comments may say it is retired)", left.length === 0, J(left));
    check("B2. lib/jobSchedules.js lists no salesAutoConvertTick and does list leadRadarTick", !/salesAutoConvertTick/.test(code(FILES[JOBS])) && /tick: "leadRadarTick", every_ms: 300000/.test(FILES[JOBS]));
    check("B3. a NAMED note says it is retired by the owner's rule", /runSalesAutoConvert \(the automatic sales loop\) is RETIRED by the owner's rule/.test(SRC));
    check("B4. module.exports carries no loop", !/runSalesAutoConvert/.test(code(SRC.slice(SRC.lastIndexOf("module.exports")))));
    const convert = bareRoute("post", "/api/agents/sales/convert", CONVERT_NAMES, { supabase: H.fakeDb(() => ({ data: null, error: null })).client, OUTREACH_CREDENTIAL_OWNER_ID: OWNER });
    const seg = await convert({ user: { id: OWNER }, body: { segment: { high_intent: true } } });
    check("B5. convert with a segment and no lead answers 400 (segment mode is removed)", seg.status === 400 && /one lead is drafted at a time/.test((seg.body || {}).error || ""), J(seg));
    const fake = H.fakeDb((t, q) => t === "bsky_leads" ? { data: { post_uri: "at://x", source: "mastodon", status: "scored", intent_score: 80, outreach_safe: true, reply_invited: true, post_created_at: new Date().toISOString() }, error: null } : { data: null, error: null });
    const c2 = bareRoute("post", "/api/agents/sales/convert", CONVERT_NAMES, { supabase: fake.client, OUTREACH_CREDENTIAL_OWNER_ID: OWNER });
    const mast = await c2({ user: { id: OWNER }, body: { lead_post_uri: "at://x" } });
    check("B6. convert refuses a lead from a source no reply can go to (mastodon), before drafting", mast.status !== 200 && J(mast.body).indexOf("unsupported_source") !== -1, J(mast));
    const other = await c2({ user: { id: OTHER }, body: { lead_post_uri: "at://x" } });
    check("B7. convert is owner only", other.status === 403);
  }

  /* ── C ───────────────────────────────────────────────────────────────── */
  section("C. Mastodon lead search and replies are gone; members' own Mastodon posting stays");
  {
    check("C1. mastodonRadar.js and redditRadar.js are deleted", !fs.existsSync(path.join(H.REPO, "mastodonRadar.js")) && !fs.existsSync(path.join(H.REPO, "redditRadar.js")));
    const gone = ["runMastodonRadarOnce", "ENABLE_MASTODON_RADAR", "sendMastodonReply", "truncateToMastodonLimit", "mastodonRetryAfterSeconds", "startRedditRadar", "mastodonDisabledLogged"];
    const left = gone.filter(n => Object.keys(ALL).some(f => new RegExp("\\b" + n + "\\b").test(code(ALL[f]))));
    check("C2. no code names the radar, its gate, the platform sender or Reddit's start", left.length === 0, J(left));
    check("C3. SCORABLE_SOURCES and OUTREACH_SENDABLE_SOURCES are Bluesky only", /const SCORABLE_SOURCES = \["bluesky"\];/.test(FILES[LR]) && /const OUTREACH_SENDABLE_SOURCES = \["bluesky"\];/.test(SRC));
    check("C4. the scorer's prompt has no Mastodon branch, and the command centre counts no Mastodon finds",
      !/source === "mastodon"/.test(code(FILES[LR])) && /var sources = \["bluesky", "youtube"\];/.test(SRC) && !/mastodon/.test(code(FILES["@lib/agentSignatures.js"]).slice(code(FILES["@lib/agentSignatures.js"]).indexOf("function sales("), code(FILES["@lib/agentSignatures.js"]).indexOf("function sales(") + 1500)));
    let committed = null;
    try { committed = cp.execFileSync("git", ["show", "HEAD:lib/memberMastodon.js"], { cwd: H.REPO, encoding: "utf8" }).replace(/\r\n/g, "\n"); } catch (e) { committed = null; }
    check("C5. lib/memberMastodon.js is byte for byte as committed", committed !== null && committed === FILES["@lib/memberMastodon.js"]);
    const routes = ["post /api/social/mastodon/connect", "post /api/social/mastodon/disconnect", "put /api/social/mastodon/automation", "post /api/agents/social/propose-post"];
    check("C6. the member Mastodon routes are all still served", routes.every(r => { const [m, p] = r.split(" "); return SRC.indexOf("app." + m + "(\"" + p + "\"") !== -1; }), J(routes));
    check("C7. the README lists no Mastodon radar variable", !/ENABLE_MASTODON_RADAR|MASTODON_ACCESS_TOKEN|MASTODON_INSTANCE|mastodonRadar\.js/.test(FILES["@README.md"]));
  }

  /* ── D ───────────────────────────────────────────────────────────────── */
  section("D. POST /api/agents/sales/send-approved");
  const NOW = Date.now();
  function mkLead(o) { return Object.assign({ post_uri: "at://did:plc:a/app.bsky.feed.post/1", source: "bluesky", status: "scored", intent_score: 82, intent_reason: "asks for help", outreach_safe: true, reply_invited: true,
    suggested_product: "Quantum Jumping book", author_handle: "asker.bsky.social", post_created_at: new Date(NOW - 86400000).toISOString() }, o || {}); }
  function world(leads, sends, opts) {
    const st = { leads: leads, sends: sends || [], pipeline: [], tasks: [], posted: [], nextId: 1, failCount: false };
    const db = H.fakeDb(function (t, q) {
      if (t === "bsky_leads") return { data: st.leads.find(l => l.post_uri === H.filterVal(q, "eq", "post_uri")) || null, error: null };
      if (t === "outreach_sends") {
        if (q.op === "insert") {
          const p = q.payload; if (st.sends.some(r => r.user_id === p.user_id && r.lead_post_uri === p.lead_post_uri)) return { data: null, error: { code: "23505", message: "duplicate" } };
          const row = Object.assign({ id: "s" + (st.nextId++), sent_at: new Date().toISOString() }, p); st.sends.push(row); return { data: { id: row.id }, error: null };
        }
        if (q.op === "delete") { const id = H.filterVal(q, "eq", "id"); st.sends = st.sends.filter(r => r.id !== id); return { data: null, error: null }; }
        if (q.op === "update") { const id = H.filterVal(q, "eq", "id"); st.sends.filter(r => r.id === id).forEach(r => Object.assign(r, q.payload)); return { data: null, error: null }; }
        if (q.head) { if (st.failCount) return { count: null, error: { message: "read failed" } }; const u = H.filterVal(q, "eq", "user_id"); return { count: st.sends.filter(r => !u || r.user_id === u).length, error: null }; }
        const uri = H.filterVal(q, "eq", "lead_post_uri"); return { data: st.sends.filter(r => r.lead_post_uri === uri).slice(0, 1), error: null };
      }
      if (t === "sales_lead_pipeline") { st.pipeline.push(q.payload); return { data: null, error: null }; }
      if (t === "ai_tasks") { st.tasks.push(q.payload); return { data: null, error: null }; }
      return { data: null, error: null };
    });
    const env = { SALES_SEND_LIVE: "true" };
    const stubs = Object.assign({ supabase: db.client, OUTREACH_CREDENTIAL_OWNER_ID: OWNER, process: { env: env }, recordGateDecision: function () {},
      RichText: require(require.resolve("@atproto/api", { paths: [H.REPO] })).RichText, URL: URL,
      sendBlueskyReply: async function (lead, text) { st.posted.push({ uri: lead.post_uri, text: text }); await new Promise(r => setImmediate(r)); return (opts && opts.fail) ? { sent: false, reason: "post_error" } : { sent: true, uri: "at://posted/" + st.posted.length }; } },
      (opts && opts.stubs) || {});
    if (!("OUTREACH_DAILY_CAP" in stubs)) stubs.OUTREACH_DAILY_CAP = 5;
    if (!("OUTREACH_ACCOUNT_DAILY_CEILING" in stubs)) stubs.OUTREACH_ACCOUNT_DAILY_CEILING = 25;
    const run = bareRoute("post", "/api/agents/sales/send-approved", SEND_ROOTS, stubs);
    return { st, env, run };
  }
  const GOOD = "That sounds hard. The book I wrote covers this, and the first chapter is free: https://blacksuncircle.com/";
  {
    const w = world([mkLead()]);
    check("D0. the route exists", typeof w.run === "function");
    const r = await w.run({ user: { id: OWNER }, body: { lead_post_uri: mkLead().post_uri, text: GOOD } });
    check("D1. the owner's approved text is posted exactly as written, once", r.status === 200 && r.body && r.body.sent === true && J(w.st.posted) === J([{ uri: mkLead().post_uri, text: GOOD }]), J(r) + J(w.st.posted));
    check("D2. ... the send is on the ledger with its uri, and the pipeline says contacted", w.st.sends.length === 1 && w.st.sends[0].platform_uri === "at://posted/1" && w.st.pipeline.some(p => p.status === "contacted" && p.last_draft === GOOD), J(w.st.sends));
    const again = await w.run({ user: { id: OWNER }, body: { lead_post_uri: mkLead().post_uri, text: GOOD } });
    check("D3. a second reply to the same post is refused (already contacted) and nothing posts", again.status === 409 && again.body.reason === "already_contacted" && w.st.posted.length === 1, J(again));
    const wo = world([mkLead()], [{ id: "x1", user_id: OTHER, lead_post_uri: mkLead().post_uri, sent_at: new Date(NOW - 5 * 86400000).toISOString() }]);
    const byOther = await wo.run({ user: { id: OWNER }, body: { lead_post_uri: mkLead().post_uri, text: GOOD } });
    check("D3b. a post already replied to from any account (another day, another user) is refused: one reply per post", byOther.status === 409 && byOther.body.reason === "already_contacted" && wo.st.posted.length === 0, J(byOther));
  }
  {
    const w = world([mkLead()]);
    const r = await w.run({ user: { id: OTHER }, body: { lead_post_uri: mkLead().post_uri, text: GOOD } });
    check("D4. any other account is refused 403 and nothing posts", r.status === 403 && w.st.posted.length === 0, J(r));
    w.env.SALES_SEND_LIVE = "false";
    const off = await w.run({ user: { id: OWNER }, body: { lead_post_uri: mkLead().post_uri, text: GOOD } });
    check("D5. SALES_SEND_LIVE not exactly \"true\": refused, nothing reserved or posted", off.status === 409 && off.body.code === "send_off" && w.st.posted.length === 0 && w.st.sends.length === 0, J(off));
  }
  {
    const cases = [
      ["no text", { text: "" }, 400], ["301 characters", { text: "a".repeat(301) }, 400], ["a link to one of our own pages that is not the lead's destination", { text: "See https://mrearthrose.com/shop" }, 400],
      ["a Stripe link", { text: "Buy here https://buy.stripe.com/abc" }, 400]
    ];
    for (const [name, body, want] of cases) {
      const w = world([mkLead()]);
      const r = await w.run({ user: { id: OWNER }, body: Object.assign({ lead_post_uri: mkLead().post_uri }, body) });
      check("D6. refused: " + name + " (" + want + "), nothing posted", r.status === want && w.st.posted.length === 0 && w.st.sends.length === 0, J(r));
    }
    const w = world([mkLead()]);
    const e = await w.run({ user: { id: OWNER }, body: { lead_post_uri: mkLead().post_uri, text: "Glad to help " + String.fromCodePoint(0x1F600) + " with this" } });
    check("D7. emoji are stripped from the approved text before it posts", e.status === 200 && w.st.posted.length === 1 && w.st.posted[0].text === "Glad to help with this", J(w.st.posted));
    const w3 = world([mkLead()]);
    const exact = await w3.run({ user: { id: OWNER }, body: { lead_post_uri: mkLead().post_uri, text: "b".repeat(300) } });
    check("D8. exactly 300 characters is allowed", exact.status === 200 && w3.st.posted.length === 1);
    // the BizForce draft carries this lead's own arrival link (?ref=<token>); approved unchanged it posts, another token does not
    const bizLead = mkLead({ suggested_product: "BizForceAI" });
    const tokCtx = bareCtx(["outreachRefToken", "OUTREACH_PRODUCT_DESTINATIONS"], {});
    const bizDest = new URL(tokCtx.OUTREACH_PRODUCT_DESTINATIONS.BizForceAI);
    const tracked = "Happy to help: " + bizDest.origin + bizDest.pathname + "?ref=" + tokCtx.outreachRefToken(bizLead);
    const w5 = world([bizLead]);
    const t1 = await w5.run({ user: { id: OWNER }, body: { lead_post_uri: bizLead.post_uri, text: tracked } });
    check("D8b. a BizForce draft approved unchanged, with this lead's own arrival link, posts exactly as written", t1.status === 200 && w5.st.posted.length === 1 && w5.st.posted[0].text === tracked, J(t1));
    const w6 = world([bizLead]);
    const t2 = await w6.run({ user: { id: OWNER }, body: { lead_post_uri: bizLead.post_uri, text: "Happy to help: " + bizDest.origin + bizDest.pathname + "?ref=lr-someoneelse" } });
    check("D8c. ... with any other ref token it is refused, nothing posted", t2.status === 400 && w6.st.posted.length === 0, J(t2));
  }
  {
    const bad = [["outreach_safe null", { outreach_safe: null }, "not_outreach_safe"], ["outreach_safe false", { outreach_safe: false }, "not_outreach_safe"],
      ["reply_invited false", { reply_invited: false }, "reply_not_invited"], ["reply_invited null", { reply_invited: null }, "reply_not_invited"],
      ["a Mastodon lead", { source: "mastodon" }, "unsupported_source"], ["an archived lead", { status: "archived" }, "not_scored"],
      ["a post older than the window", { post_created_at: new Date(NOW - 30 * 86400000).toISOString() }, "post_too_old"]];
    for (const [name, o, reason] of bad) {
      const w = world([mkLead(o)]);
      const r = await w.run({ user: { id: OWNER }, body: { lead_post_uri: mkLead().post_uri, text: GOOD } });
      check("D9. refused: " + name + " (" + reason + "), nothing posted or reserved", r.status === 422 && (r.body.reasons || []).indexOf(reason) !== -1 && w.st.posted.length === 0 && w.st.sends.length === 0, J(r));
    }
  }
  {
    const today = new Date().toISOString();
    const w = world([mkLead()], [{ id: "old1", user_id: OWNER, lead_post_uri: "at://other/1", sent_at: today }], { stubs: { OUTREACH_DAILY_CAP: 1, OUTREACH_ACCOUNT_DAILY_CEILING: 25 } });
    const r = await w.run({ user: { id: OWNER }, body: { lead_post_uri: mkLead().post_uri, text: GOOD } });
    check("D10. the owner's daily cap reached: refused at the send, the reservation removed, nothing posted", r.status === 409 && r.body.reason === "daily_cap_reached" && w.st.posted.length === 0 && w.st.sends.length === 1, J(r));
    const w2 = world([mkLead()], [{ id: "o2", user_id: OTHER, lead_post_uri: "at://other/2", sent_at: today }], { stubs: { OUTREACH_DAILY_CAP: 5, OUTREACH_ACCOUNT_DAILY_CEILING: 1 } });
    const r2 = await w2.run({ user: { id: OWNER }, body: { lead_post_uri: mkLead().post_uri, text: GOOD } });
    check("D11. the account ceiling reached (by any account's sends): refused, reservation removed", r2.status === 409 && r2.body.reason === "account_ceiling_reached" && w2.st.posted.length === 0 && w2.st.sends.length === 1, J(r2));
    const w3 = world([mkLead()], [], { stubs: { OUTREACH_DAILY_CAP: 5, OUTREACH_ACCOUNT_DAILY_CEILING: 25 } });
    w3.st.failCount = true;
    const r3 = await w3.run({ user: { id: OWNER }, body: { lead_post_uri: mkLead().post_uri, text: GOOD } });
    check("D12. a cap that cannot be counted fails closed: refused, reservation removed", r3.status === 409 && r3.body.reason === "check_failed" && w3.st.posted.length === 0 && w3.st.sends.length === 0, J(r3));
    const w4 = world([mkLead()], [], { fail: true });
    const r4 = await w4.run({ user: { id: OWNER }, body: { lead_post_uri: mkLead().post_uri, text: GOOD } });
    check("D13. a post that fails is not counted: the reservation is removed", r4.status === 502 && w4.st.sends.length === 0, J(r4) + J(w4.st.sends));
  }
  {
    const A = mkLead({ post_uri: "at://did:plc:a/app.bsky.feed.post/A" }), B = mkLead({ post_uri: "at://did:plc:a/app.bsky.feed.post/B" });
    const w = world([A, B], [], { stubs: { OUTREACH_DAILY_CAP: 1, OUTREACH_ACCOUNT_DAILY_CEILING: 25 } });
    const both = await Promise.all([w.run({ user: { id: OWNER }, body: { lead_post_uri: A.post_uri, text: GOOD } }), w.run({ user: { id: OWNER }, body: { lead_post_uri: B.post_uri, text: GOOD } })]);
    check("D14. two racing requests with one slot left: exactly one posts, the other is refused, one send recorded", w.st.posted.length === 1 && w.st.sends.length === 1 && both.filter(x => x.status === 200).length === 1, J(both.map(x => [x.status, x.body && x.body.reason])));
    const sameW = world([A], [], { stubs: { OUTREACH_DAILY_CAP: 5, OUTREACH_ACCOUNT_DAILY_CEILING: 25 } });
    const same = await Promise.all([sameW.run({ user: { id: OWNER }, body: { lead_post_uri: A.post_uri, text: GOOD } }), sameW.run({ user: { id: OWNER }, body: { lead_post_uri: A.post_uri, text: GOOD } })]);
    check("D15. two racing requests for the same post: one reply only", sameW.st.posted.length === 1 && sameW.st.sends.length === 1, J(same.map(x => x.status)));
    // the reservation alone, without the in-process queue: run reserveOutreachSend twice at once
    const st = { sends: [], nextId: 1 };
    const db = H.fakeDb(function (t, q) {
      if (q.op === "insert") { if (st.sends.some(r => r.user_id === q.payload.user_id && r.lead_post_uri === q.payload.lead_post_uri)) return { error: { code: "23505" } }; const row = Object.assign({ id: "r" + st.nextId++ }, q.payload); st.sends.push(row); return { data: { id: row.id }, error: null }; }
      if (q.op === "delete") { const id = H.filterVal(q, "eq", "id"); st.sends = st.sends.filter(r => r.id !== id); return { data: null, error: null }; }
      if (q.head) return { count: st.sends.length, error: null };
      return { data: st.sends.filter(r => r.lead_post_uri === H.filterVal(q, "eq", "lead_post_uri")), error: null };
    });
    const out = { reserve: bareCtx(["reserveOutreachSend"], { supabase: db.client, OUTREACH_DAILY_CAP: 1, OUTREACH_ACCOUNT_DAILY_CEILING: 25 }).reserveOutreachSend };
    const got = await Promise.all([out.reserve(OWNER, A), out.reserve(OWNER, B)]);
    check("D16. the reservation alone (no queue) never lets two racing sends past a cap of one", got.filter(g => g.ok).length <= 1 && st.sends.length <= 1, J(got));
    check("D17. the route is in group M and its owner check is in the handler", require(path.join(H.REPO, "lib", "routeAccess.js")).groupOf("post /api/agents/sales/send-approved") === "M" &&
      /if \(userId !== OUTREACH_CREDENTIAL_OWNER_ID\) return res\.status\(403\)\.json\(OUTREACH_UNAVAILABLE\);/.test(routeBody("post", "/api/agents/sales/send-approved")));
    const iife = /const OUTREACH_DAILY_CAP = (\(function \(\) \{[\s\S]*?\}\)\(\));/.exec(SRC);
    const parse = v => iife ? vm.runInNewContext(iife[1], { process: { env: v === undefined ? {} : { OUTREACH_DAILY_CAP: v } }, Number, Math, String }) : NaN;
    const table = [[undefined, 5], ["", 5], ["  ", 5], ["abc", 5], ["0", 5], ["-2", 5], ["7", 7], ["2.9", 2]].map(([v, want]) => [v, parse(v), want]);
    check("D18. OUTREACH_DAILY_CAP fails closed to 5, never NaN (" + J(table.map(x => x[1])) + ")", table.every(x => x[1] === x[2]), J(table));
  }

  /* ── E ───────────────────────────────────────────────────────────────── */
  section("E. the scorer is on the spend ledger");
  {
    const lr = code(FILES[LR]), yr = code(FILES[YR]);
    const creates = (lr.match(/\.messages\.create\(/g) || []).length;
    const helper = fnBody(lr, "async function createScoringMessage(") || "";
    check("E1. leadRadar.js calls Anthropic only inside createScoringMessage (2 sites: the call and its one auth retry)", creates === 2 && (helper.match(/\.messages\.create\(/g) || []).length === 2);
    const uses = (lr.match(/createScoringMessage\(/g) || []).length;
    const at = lr.indexOf("var response = await createScoringMessage(");
    const enforceAt = lr.lastIndexOf("await modelLedger.enforce(SCORING_ACCOUNT_ID, SCORER_LEDGER_ROUTE);", at);
    const recordAt = lr.indexOf("await modelLedger.record({", at);
    check("E2. createScoringMessage is called once; the caps are checked before it and the call recorded right after", uses === 2 && enforceAt !== -1 && at - enforceAt < 400 && recordAt !== -1 && recordAt - at < 400);
    check("E3. the record names agent_type lead_radar, route scoreNewLeads, the model Anthropic returned and its usage",
      /const SCORER_AGENT_TYPE = "lead_radar";/.test(FILES[LR]) && /const SCORER_LEDGER_ROUTE = "scoreNewLeads";/.test(FILES[LR]) &&
      /agentType: SCORER_AGENT_TYPE,\n\s*route:\s*SCORER_LEDGER_ROUTE,\n\s*model:\s*\(response && response\.model\) \|\| "claude-sonnet-4-6",\n\s*usage:\s*response && response\.usage,/.test(FILES[LR]));
    check("E4. youtubeRadar.js makes no Anthropic call at all", !/anthropic|messages\.create\(/i.test(yr));
    check("E5. server.js hands recordModelCall and enforceDailyModelCallLimit to the radar before it starts",
      /require\("\.\/leadRadar"\)\.setModelLedger\(\{ record: recordModelCall, enforce: enforceDailyModelCallLimit \}\);\n\s*startLeadRadar\(/.test(SRC));

    // run the real scorer against fakes
    async function score(opts) {
      const calls = { creates: [], records: [], enforces: [], updates: [] };
      const fakeSb = { createClient: () => ({ from: (t) => {
        const q = { t, op: "select", filters: [] }; const b = {};
        ["select", "eq", "in", "order", "limit", "neq", "is", "lt", "gt", "gte", "maybeSingle", "single"].forEach(m => { b[m] = function () { if (m === "maybeSingle" || m === "single") return Promise.resolve({ data: null, error: null }); return b; }; });
        b.update = p => { q.op = "update"; calls.updates.push(p); return b; };
        b.upsert = () => b;
        b.then = (res, rej) => Promise.resolve(t === "bsky_leads" && q.op === "select" ? { data: [{ id: 1, source: "bluesky", status: "new", post_text: "my legs are weak, any help?", matched_keyword: "weak legs", lang: "en", score_attempts: 0 }], error: null } : { data: null, error: null }).then(res, rej);
        return b; } }) };
      function FakeAnthropic() { this.messages = { create: async (p) => { calls.creates.push(p.model); return { model: "claude-sonnet-4-6", usage: { input_tokens: 120, output_tokens: 30 }, content: [{ type: "text", text: "{\"score\": 70, \"reason\": \"asks\", \"product\": \"none\", \"outreach_safe\": true, \"reply_invited\": true}" }] }; } }; }
      const stubs = { "@supabase/supabase-js": fakeSb, "@anthropic-ai/sdk": FakeAnthropic, "@atproto/api": { BskyAgent: function () { return {}; } }, "dotenv": { config() {} } };
      const m = new Module(path.join(H.REPO, "leadRadar.js"), module);
      m.filename = path.join(H.REPO, "leadRadar.js"); m.paths = Module._nodeModulePaths(H.REPO);
      const realReq = m.require.bind(m);
      m.require = function (n) {
        if (stubs[n]) return stubs[n];
        if (n === "./lib/resolveAnthropicKey") return () => { const f = async () => null; f.withSource = async () => ({ key: null }); return f; };
        if (n === "./youtubeRadar") return { runYoutubeRadarOnce: async () => null };
        return realReq(n);
      };
      const saved = process.env.ANTHROPIC_API_KEY; process.env.ANTHROPIC_API_KEY = "sk-check-fake-never-sent";
      const quiet = console.log, qe = console.error, qw = console.warn; console.log = console.error = console.warn = function () {};
      try {
        m._compile(FILES[LR], m.filename);
        if (opts.ledger) m.exports.setModelLedger({ record: async d => { calls.records.push(d); }, enforce: async (u, r) => { calls.enforces.push([u, r, calls.creates.length]); if (opts.refuse) { const e = new Error("cap"); e.status = 429; throw e; } return true; } });
        await m.exports.scoreNewLeads();
      } finally { console.log = quiet; console.error = qe; console.warn = qw; if (saved === undefined) delete process.env.ANTHROPIC_API_KEY; else process.env.ANTHROPIC_API_KEY = saved; }
      return calls;
    }
    const ok = await score({ ledger: true });
    check("E6. a scored lead: the caps were checked before the call and the call was recorded once with its tokens",
      ok.creates.length === 1 && ok.enforces.length === 1 && ok.enforces[0][2] === 0 && ok.records.length === 1 && ok.records[0].agentType === "lead_radar" &&
      ok.records[0].route === "scoreNewLeads" && ok.records[0].model === "claude-sonnet-4-6" && ok.records[0].usage.input_tokens === 120, J(ok));
    const none = await score({ ledger: false });
    check("E7. no ledger handed in: nothing is scored (no call made)", none.creates.length === 0 && none.updates.length === 0, J(none));
    const refused = await score({ ledger: true, refuse: true });
    check("E8. a cap refusal: no call is made and no attempt is counted against the lead", refused.creates.length === 0 && refused.updates.length === 0, J(refused));
  }

  /* ── F ───────────────────────────────────────────────────────────────── */
  section("F. the PART D fixes, SMS, and archived rows");
  {
    const RA = require(path.join(H.REPO, "lib", "routeAccess.js"));
    const accessFile = FILES[ACCESS];
    const g = k => { const m = new Module("ra", module); m._compile(accessFile, path.join(H.REPO, "lib", "routeAccess.js")); return m.exports.groupOf(k); };
    const inH = (() => { const m = new Module("ra", module); m._compile(accessFile, path.join(H.REPO, "lib", "routeAccess.js")); return m.exports.ADMIN_IN_HANDLER; })();
    const demand = routeBody("post", "/api/agents/rd/demand-signals") || "";
    check("F1. demand-signals checks the owner by OWNER_ACCOUNT_ID, not role, and is in group A with the check in the handler",
      /if \(userId !== OWNER_ACCOUNT_ID\) \{\n\s*return res\.status\(403\)\.json\(\{ error: DEMAND_OWNER_ONLY \}\);/.test(demand) && !/req\.user\.role !== "admin"/.test(code(demand)) &&
      g("post /api/agents/rd/demand-signals") === "A" && inH.indexOf("post /api/agents/rd/demand-signals") !== -1);
    const dr = bareRoute("post", "/api/leads/draft-reply", ["LEAD_RADAR_UNAVAILABLE"], { supabase: H.fakeDb(() => ({ data: null, error: null })).client, OUTREACH_CREDENTIAL_OWNER_ID: OWNER });
    const drr = dr ? await dr({ user: { id: OTHER }, body: { post_text: "help", handle: "x" } }) : null;
    check("F2. draft-reply refuses every account but the owner (403 lead_radar_unavailable) and is in group A", drr && drr.status === 403 && drr.body.code === "lead_radar_unavailable" &&
      g("post /api/leads/draft-reply") === "A" && inH.indexOf("post /api/leads/draft-reply") !== -1, J(drr));
    check("F3. the card leads read is in group F (a member always reads their own leads), and its comment says so",
      g("get /api/digital-cards/:id/leads") === "F" && /in group F now \(lib\/routeAccess\.js\), which is what makes that sentence true/.test(SRC));
    check("F4. no import of startRedditRadar or runMastodonRadarOnce; the reddit_leads table is kept (no migration drops it)",
      !/require\("\.\/redditRadar"\)|require\("\.\/mastodonRadar"\)/.test(code(SRC) + code(FILES[LR])) &&
      !fs.readdirSync(path.join(H.REPO, "supabase", "migrations")).filter(f => /.sql$/.test(f)).some(f => /drop table[^;]*reddit_leads/i.test(fs.readFileSync(path.join(H.REPO, "supabase", "migrations", f), "utf8"))));
    check("F5. youtubeRadar counts what the upsert inserted (a .select after it) and logs matched and new apart",
      /\.upsert\(rows, \{ onConflict: "post_uri", ignoreDuplicates: true \}\)\n\s*\.select\("post_uri"\);/.test(FILES[YR]) && /var newCount = \(insertedRows \|\| \[\]\)\.length;/.test(FILES[YR]) && / matched, " \+ newCount \+ " new"/.test(FILES[YR]));
    check("F6. radar_status is written for youtube too (its own source row, after each pass)",
      count(FILES[LR], '"youtube pass", "youtube");') === 2 && /upsert\(Object\.assign\(\{ source: source \|\| RADAR_HEARTBEAT_SOURCE \}, fields\)/.test(FILES[LR]) && /return pass;\n\}/.test(FILES[YR]));
    check("F7. the stale comments are fixed: five lead-reading routes, and leadRadar.js names every bsky_leads status (068 is not edited)",
      !/The refusal the four lead-reading routes send/.test(SRC) && /the bsky_leads\.status values in use\. Migration 068/.test(FILES[LR]) &&
      cp.execFileSync("git", ["diff", "--name-only", "HEAD", "--", "supabase/migrations/068_*"], { cwd: H.REPO, encoding: "utf8", shell: false }).trim() === "");
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
    check("F18. archived rows never appear as leads: the pipeline, the command centre, demand and the high-intent trigger skip them; members cannot set it",
      count(SRC, '.neq("status", "archived")') === 4 && /\.neq\("status", "archived"\)\.order\("id"/.test(FILES["@lib/triggerRunner.js"]) &&
      /var SALES_LEAD_STATUSES = \["new", "drafted", "contacted", "replied", "converted"\];/.test(SRC));
    const arch = FILES["@scripts/oneoff/lr1Archive.js"] || "";
    check("F19. the archive script is a dry run by default, never deletes, never re-scores, never touches YouTube or a Bluesky row from 2026-08-20 on",
      /const APPLY = process\.argv\.indexOf\("--apply"\) !== -1;/.test(arch) && !/\.delete\(|anthropic|scoreNewLeads/i.test(code(arch)) && !/eq\("source", "youtube"\)/.test(arch) &&
      /const BLUESKY_CUTOFF = "2026-08-20T00:00:00\.000Z";/.test(arch) && (arch.match(/\.lt\("created_at", BLUESKY_CUTOFF\)/g) || []).length === 2);
  }

  /* ── G ───────────────────────────────────────────────────────────────── */
  section("G. the pages");
  {
    const sp = FILES[SALES] || "";
    check("G1. sales.html: no confirm dialog, no bulk post, no segment", !/window\.confirm\(/.test(sp) && !/salesConvertAllBtn|convertAllHighIntent|segment:/.test(sp));
    const draft = fnBody(sp, "function convertLead(") || "";
    check("G2. Draft asks for the draft only; it never calls send-approved", /\/api\/agents\/sales\/convert/.test(draft) && !/send-approved|postApprovedReply/.test(draft));
    const post = fnBody(sp, "function postApprovedReply(") || "";
    check("G3. \"Post my reply\" sends exactly the text in the box to send-approved, and is bound only to its own button",
      /\/api\/agents\/sales\/send-approved/.test(post) && /var text = box\.value\.trim\(\);/.test(post) && /body: JSON\.stringify\(\{ lead_post_uri: lead\.post_uri, text: text \}\)/.test(post) &&
      count(sp, "postApprovedReply(") === 2 && /var approveBtn = e\.target\.closest\("\.sales-approve-btn"\);\n\s*if \(approveBtn\) \{ postApprovedReply\(/.test(sp) && count(sp, "send-approved") === 1);
    check("G4. the box shows the draft for editing, with the button labelled Post my reply", /<textarea class="sales-approve-text"/.test(sp) && />Post my reply<\/button>/.test(sp));
    const rp = FILES[RADAR] || "";
    check("G5. lead-radar.html: never \"Check console\"; signed out it asks for sign-in", !/Check console/.test(rp) && /if \(!tok\(\)\) \{ showSignIn\(countEl, list\); return; \}/.test(rp) && /if \(res\.status === 401\) \{ showSignIn\(countEl, list\); return; \}/.test(rp) && /Sign in to see Lead Radar/.test(rp));
    check("G6. bf-access.js no longer names \"#sfMessage\"", !/#sfMessage/.test(code(FILES[BFA])));
    check("G7. sitemap-pages.xml no longer lists /suppressed.html", !/suppressed\.html/.test(FILES[SITEMAP]));
    // NAMED (Nov 23 2026, LR-1B): BEFORE "lr1"; AFTER "lr1b" (suppressed.html noindex).
    check("G8. sw.js SHELL_REV is \"lr1b\"", /var SHELL_REV = "lr1b";/.test(FILES["sw.js"]));
    check("G9. the Privacy Policy no longer says Mastodon receives outreach replies", !/Bluesky and Mastodon: replies sent through outreach/.test(FILES["privacy.html"]) && /Bluesky: replies sent through outreach, each one approved by a person before it posts\./.test(FILES["privacy.html"]));
    const smsPage = FILES[SMS] || "";
    check("G10. sms.html sends where and when consent was given, or no consent", /consent_source: source, consent_at: day \+ "T00:00:00\.000Z"/.test(smsPage) && /id="sms-add-source"/.test(smsPage) && /id="sms-bulk-source"/.test(smsPage));
  }
  finish();
})().catch(e => { console.log("    FAIL  the check ran to the end  [" + (e && e.stack || e) + "]"); process.exit(1); });
