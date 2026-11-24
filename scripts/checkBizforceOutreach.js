/* ════════════════════════════════════════════════════════════════════════════
   checkBizforceOutreach.js — no fixed phrase list, no platform pipeline: Lead
   Radar searches each member's own words, and nothing posts unless the send
   switch is exactly "true".

   NAMED (Nov 23 2026, LR-2): BEFORE this proved the owner's radar searched 25
   supplement phrases then seven BizForce phrases (KEYWORDS, BIZFORCE_KEYWORDS),
   that a Bluesky row found by a BizForce phrase became a BizForce lead on a
   pipeline of its own, that convertSingleLead drafted it against a BizForce
   instruction and destination while every supplement prompt and reply stayed
   byte-identical to BASELINE, and that every server.js line naming a send
   flag was unchanged. AFTER LR-2 removed the fixed lists, the BizForce
   pipeline and the platform's own drafter and senders (the original check and
   code are in git, 65c0825): Lead Radar is every member's, searching that
   member's own Fingerprint words, and the one send is POST /api/leads/:id/send
   (lib/leadRoutes.js). What is still true is proved here.

   WHAT THIS PROVES, with no model call, no database and no network:
     1. Removed: KEYWORDS, BIZFORCE_KEYWORDS, OUTREACH_BIZFORCE_PRODUCT,
        OUTREACH_OWN_DOMAINS, outreachDraftRejection, convertSingleLead,
        canSendOutreach, sendBlueskyReply and sendMastodonReply appear in no
        code of server.js, leadRadar.js or the Lead Radar libraries.
     2. Capture keeps a post only for a word of the member's own: the real
        cheapFilter keeps "blocked drain" for a plumber and drops a supplement
        phrase the old list searched, and a member's words never reach another
        member.
     3. The send switch: SALES_SEND_LIVE is read in exactly one code line of
        server.js, as === "true" (unset, "TRUE", "1", "yes" and "false" are all
        off); and with it off, the real send route answers 409 send_off with
        ZERO database calls and nothing posted.

   MUTATIONS (MUTATE=<name> edits a source IN MEMORY; MUTATE=all runs each):
     flag-loose        the switch reads !== "false" (on unless told off)   → 3
     flag-check-late   the send route reads the lead before the switch     → 3
     words-shared      capture matches the old supplement phrase too      → 2
   ════════════════════════════════════════════════════════════════════════════ */
"use strict";
const fs = require("fs"), path = require("path"), Module = require("module");
const REPO = path.join(__dirname, "..");
const MUT = require("./_shared");
const MUTATE = process.env.MUTATE || "";

const MR = "lib/memberRadar.js", RT = "lib/leadRoutes.js", LRP = "lib/leadReplies.js", SERVER = "server.js";
const SEND_OFF = '      if (!deps.sendLive()) return res.status(409).json({ code: "send_off", error: "Posting replies is switched off (SALES_SEND_LIVE). Nothing was posted." });\n';
const MUTATIONS = {
  "flag-loose": [[SERVER, 'sendLive: function () { return process.env.SALES_SEND_LIVE === "true"; },', 'sendLive: function () { return process.env.SALES_SEND_LIVE !== "false"; },']],
  "flag-check-late": [[RT, SEND_OFF, ""], [RT, "      var userId = req.user.id, nowMs = now();\n      if (!deps.sendLive())", "      var userId = req.user.id, nowMs = now();\n      if (!deps.sendLive())"]],
  "words-shared": [[MR, "function cheapFilter(post, fp, own, nowMs) {\n  if (!post || !fp) return { ok: false, reason: \"no_post\" };\n  var keyword = matchKeyword(post.text, fp.keywords);",
    "function cheapFilter(post, fp, own, nowMs) {\n  if (!post || !fp) return { ok: false, reason: \"no_post\" };\n  var keyword = matchKeyword(post.text, fp.keywords.concat([\"how to increase libido naturally\"]));"]]
};
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
[SERVER, "leadRadar.js", MR, RT, LRP].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  if (MUTATE === "flag-check-late") {
    // the switch moves to after the lead is read
    FILES[RT] = MUT.replaceOnce(FILES[RT], SEND_OFF, "", MUTATE);
    const at = FILES[RT].indexOf("\n", FILES[RT].indexOf(".from(\"member_leads\")", FILES[RT].indexOf("app.post(\"/api/leads/:id/send\"")));
    if (at < 0) { console.error("flag-check-late: no lead read in the send route"); process.exit(2); }
    const stmtEnd = FILES[RT].indexOf(";\n", at) + 2;
    FILES[RT] = FILES[RT].slice(0, stmtEnd) + SEND_OFF + FILES[RT].slice(stmtEnd);
  } else for (const [file, from, to] of edits) FILES[file] = MUT.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}
function load(rel, requireMap) {
  const m = new Module(path.join(REPO, rel), module);
  m.filename = path.join(REPO, rel);
  m.paths = Module._nodeModulePaths(path.dirname(m.filename));
  if (requireMap) { const real = m.require.bind(m); m.require = id => Object.prototype.hasOwnProperty.call(requireMap, id) ? requireMap[id] : real(id); }
  m._compile(FILES[rel], m.filename);
  return m.exports;
}

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const J = JSON.stringify;
const code = src => src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

(async function main() {
  console.log("\n══ 1. the fixed lists and the platform pipeline are removed ══");
  const all = Object.keys(FILES).map(f => code(FILES[f])).join("\n");
  const GONE = ["KEYWORDS", "BIZFORCE_KEYWORDS", "OUTREACH_BIZFORCE_PRODUCT", "OUTREACH_OWN_DOMAINS", "outreachDraftRejection", "convertSingleLead", "canSendOutreach", "sendBlueskyReply", "sendMastodonReply"];
  // KEYWORDS is also a word in prompt text (Demand Signals' "KEYWORDS IN SCOPE"); for it, only a declaration or a property read counts.
  const left = GONE.filter(n => n === "KEYWORDS" ? /\b(?:const|var|let)\s+KEYWORDS\b|\.KEYWORDS\b|[{,]\s*KEYWORDS\s*[,}]/.test(all) : new RegExp("\\b" + n + "\\b").test(all));
  check("1. " + GONE.join(", ") + " appear in no code", left.length === 0, left.join(", "));

  console.log("\n══ 2. capture keeps a post only for the member's own words ══");
  const M = load(MR);
  const FPM = require(path.join(REPO, "lib", "leadFingerprint.js"));
  const now = Date.now(), fresh = new Date(now - 3600000).toISOString();
  const plumber = FPM.shape({ keywords: ["blocked drain"], sources: { bluesky: true } });
  const post = text => ({ text, posted_at: fresh, author_ids: ["someone.bsky.social"], author_text: "" });
  const keep = M.cheapFilter(post("Anyone know who can fix a blocked drain today?"), plumber, null, now);
  const drop = M.cheapFilter(post("Does anyone know how to increase libido naturally?"), plumber, null, now);
  check("2. a post with the member's word is kept, matched on that word", keep.ok === true && keep.keyword === "blocked drain", J(keep));
  check("2. a phrase the old fixed list searched (\"how to increase libido naturally\") is not the member's, and is dropped", drop.ok === false && drop.reason === "no_keyword", J(drop));
  const baker = FPM.shape({ keywords: ["wedding cake"], sources: { bluesky: true } });
  check("2. one member's word never keeps a post for another", M.cheapFilter(post("Anyone know who can fix a blocked drain today?"), baker, null, now).ok === false);

  console.log("\n══ 3. the send switch ══");
  const lines = code(FILES[SERVER]).split("\n").filter(l => /SALES_SEND_LIVE/.test(l));
  check("3. SALES_SEND_LIVE is read in exactly one code line of server.js, the send route's sendLive", lines.length === 1 && /sendLive: function \(\) \{ return process\.env\.SALES_SEND_LIVE/.test(lines[0]), J(lines));
  const expr = (/return (process\.env\.SALES_SEND_LIVE [^;]+);/.exec(lines[0] || "") || [])[1];
  const on = v => { try { return new Function("process", "return " + expr + ";")({ env: v === undefined ? {} : { SALES_SEND_LIVE: v } }); } catch (e) { return "threw"; } };
  const offs = [undefined, "", "TRUE", "1", "yes", "false", " true"].map(on);
  check("3. it is on only for exactly \"true\": unset, blank, \"TRUE\", \"1\", \"yes\", \"false\" and \" true\" are all off", on("true") === true && offs.every(x => x === false), J(offs));
  const R = load(RT);
  const handlers = {};
  const app = { get() {}, put() {}, post(p) { handlers["post " + p] = arguments[arguments.length - 1]; } };
  let dbCalls = 0, posted = 0;
  const sb = { from() { dbCalls++; const b = new Proxy({}, { get(_, k) { if (k === "then") return (res, rej) => Promise.resolve({ data: { id: "l1", user_id: "u1", source: "bluesky" }, error: null }).then(res, rej); return () => b; } }); return b; }, rpc() { dbCalls++; return Promise.resolve({ data: null, error: null }); } };
  const sendLive = new Function("process", "return function () { return " + expr + "; };")({ env: {} });
  R.mountLeadRoutes(app, { sb, requireAuth() {}, requireActiveSubscription() {}, aiLimiter() {}, ownerId: "owner", siteOrigin: "https://bizforceai.net", now: () => Date.now(),
    sendLive, caps: { perMember: 10, ceiling: 100 }, recordGate: async () => true, callModel: async () => { throw new Error("no model"); },
    postingAccount: async () => { posted++; return null; }, actAs: async () => { posted++; return null; }, linkFacets: () => [], replyRefsFor: () => null, threads: {} });
  const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
  await handlers["post /api/leads/:id/send"]({ user: { id: "u1" }, params: { id: "l1" }, body: { text: "Happy to help with that drain." } }, res, e => { res.statusCode = 500; res.body = String(e); });
  check("3. with SALES_SEND_LIVE unset the send route answers 409 send_off, with zero database calls and nothing posted",
    res.statusCode === 409 && res.body && res.body.code === "send_off" && dbCalls === 0 && posted === 0, J({ s: res.statusCode, b: res.body, dbCalls, posted }));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
