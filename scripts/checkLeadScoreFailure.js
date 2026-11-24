/* ═══════════════════════════════════════════════════════════════════════════
   checkLeadScoreFailure — a failed score is not a score.

   THE DEFECT (2026). When scoring a lead failed three times, leadRadar.js wrote
   intent_score 0 with status "scored": a judgement nobody made, stored as a
   real low score, sorted and counted with the real ones.

   NAMED (Nov 23 2026, LR-2): BEFORE this ran leadRadar.js scoreNewLeads and the
   five bsky_leads consumers (GET /api/leads, GET /api/agents/sales/leads, the
   pipeline, POST /api/agents/sales/convert and its segment mode). AFTER LR-2
   removed all of them (the original is in git, 65c0825): each member's leads
   are scored by lib/memberRadar.js scoreMember on their own ledger, read by
   lib/leadRoutes.js, and counted for demand by server.js demandRowOf.

   WHAT THIS PROVES, with the real functions and a fake database (no model, no
   network, no write anywhere):
     1. Removed: scoreNewLeads, runSalesAutoConvert, convertSingleLead and the
        sales/leads, sales/pipeline and sales/convert routes are in no code.
     2. A call that fails (thrown) writes nothing: the lead stays unscored and
        waits for the next tick, and the tick stops there.
     3. An answer that cannot be read is stored with NO score (null) and the
        reason SCORE_UNREAD_REASON ("The score could not be read."), unsafe
        and not invited, so it can never be replied to, and with scored_at
        set, so it is never scored again (no second charge for it) and it
        counts toward the member's daily scoring cap (a call was spent).
        NAMED (Nov 23 2026, LR-2): BEFORE the first LR-2 stored it as 0 with
        no reason (the defect above, again); the owner fixed it the same day.
     4. It is not shown as a lead by default (isWeak), and the summary count
        asks only for scores of 40 or more.
     5. Demand (demandRowOf) reads it as a failed score, with the failure
        reason, never as a real 0; a real 0 with its reason stays a 0.
     6. A readable answer is stored as given, with its reason.

   MUTATIONS (MUTATE=<name> edits a source IN MEMORY; MUTATE=all runs each):
     unread-zero     an unreadable answer is stored as a 0 again            → 3, 5
     unread-reason   an unreadable answer gets a match reason, like a real one → 3, 5
     unread-safe     an unreadable answer is stored safe and invited        → 3
     unread-rescored an unreadable answer leaves scored_at null             → 3
     thrown-writes   a thrown call is written as a 0                        → 2
     demand-real     demand reads an unreadable answer as a real score      → 5
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";
const fs = require("fs"), path = require("path"), vm = require("vm"), Module = require("module");
const REPO = path.join(__dirname, "..");
const MUT = require("./_shared");
const MUTATE = process.env.MUTATE || "";

const MR = "lib/memberRadar.js", SERVER = "server.js";
const MUTATIONS = {
  "unread-zero": [[MR, "      : { score: null, match_reason: SCORE_UNREAD_REASON,", "      : { score: 0, match_reason: SCORE_UNREAD_REASON,"]],
  "unread-reason": [[MR, "      : { score: null, match_reason: SCORE_UNREAD_REASON,", "      : { score: null, match_reason: \"Good match: unread\","]],
  "unread-safe": [[MR, "      : { score: null, match_reason: SCORE_UNREAD_REASON, outreach_safe: false, reply_invited: false,", "      : { score: null, match_reason: SCORE_UNREAD_REASON, outreach_safe: true, reply_invited: true,"]],
  "unread-rescored": [[MR, "      : { score: null, match_reason: SCORE_UNREAD_REASON, outreach_safe: false, reply_invited: false, scored_at: at,", "      : { score: null, match_reason: SCORE_UNREAD_REASON, outreach_safe: false, reply_invited: false, scored_at: null,"]],
  "thrown-writes": [[MR, "      return { scored: scored, alerts: alerts, reason: \"call_failed\" };", "      out = { text: \"{\\\"score\\\": 0, \\\"reason\\\": \\\"failed\\\"}\" };"]],
  "demand-real": [[SERVER, "  var scored = !!l.scored_at;\n", "  var scored = !!l.scored_at && typeof l.score === \"number\";\n"]]
};
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
[MR, SERVER, "leadRadar.js"].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = MUT.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}
function load(rel) {
  const m = new Module(path.join(REPO, rel), module);
  m.filename = path.join(REPO, rel);
  m.paths = Module._nodeModulePaths(path.dirname(m.filename));
  m._compile(FILES[rel], m.filename);
  return m.exports;
}
let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const code = src => src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
const J = JSON.stringify;

/* A fake member_leads: the scored-today count, the unscored queue, and every update recorded. */
function fakeDb(leads) {
  const updates = [];
  return { updates, from(table) {
    const st = { head: false, upd: null, filters: [] };
    const b = {
      select(cols, o) { st.head = !!(o && o.head); return b; }, eq(k, v) { st.filters.push([k, v]); return b; }, in() { return b; }, gte() { return b; }, is() { return b; },
      order() { return b; }, limit() { return b; }, update(f) { st.upd = f; return b; },
      then(res, rej) {
        let out;
        if (st.upd) { updates.push({ table, fields: st.upd, id: (st.filters.find(f => f[0] === "id") || [])[1] }); out = { error: null }; }
        else if (st.head) out = { count: 0, error: null };
        else out = { data: leads, error: null };
        return Promise.resolve(out).then(res, rej);
      }
    };
    return b;
  } };
}

(async function main() {
  console.log("\n══ 1. the owner's scorer and its consumers are removed ══");
  const all = code(FILES[SERVER]) + "\n" + code(FILES["leadRadar.js"]);
  const gone = ["scoreNewLeads", "runSalesAutoConvert", "convertSingleLead", "\"/api/agents/sales/leads\"", "\"/api/agents/sales/pipeline\"", "\"/api/agents/sales/convert\""].filter(n => all.indexOf(n) !== -1);
  check("scoreNewLeads, runSalesAutoConvert, convertSingleLead and the sales lead routes are in no code", gone.length === 0, gone.join(", "));

  const M = load(MR);
  const NOW = Date.parse("2026-11-23T12:00:00Z");
  const member = { user_id: "u1", fp: require(path.join(REPO, "lib", "leadFingerprint.js")).shape({ offer_summary: "Drain repair", keywords: ["blocked drain"], sources: { bluesky: true } }) };
  const lead = (id) => ({ id, user_id: "u1", source: "bluesky", text: "Who fixes blocked drains?", posted_at: new Date(NOW - 3600000).toISOString() });
  const run = async (answer) => {
    const db = fakeDb([lead("l1"), lead("l2")]);
    const deps = { sb: db, env: {}, callModel: async () => { if (answer instanceof Error) throw answer; return { text: answer }; } };
    const out = await M.scoreMember(deps, member, NOW);
    return { out, updates: db.updates };
  };

  console.log("\n══ 2. a call that fails writes nothing ══");
  {
    const prev = console.warn; console.warn = () => {};
    const t = await run(new Error("socket hang up"));
    console.warn = prev;
    check("nothing is written, the tick stops there (call_failed), and the lead waits unscored", t.updates.length === 0 && t.out.reason === "call_failed" && t.out.scored === 0, J(t));
  }

  console.log("\n══ 3. an answer that cannot be read ══");
  let unread;
  {
    const prev = console.warn; console.warn = () => {};
    const t = await run("I think this person might want a plumber.");
    console.warn = prev;
    unread = t.updates[0] && t.updates[0].fields;
    check("it is stored with no score (null) and the reason \"" + M.SCORE_UNREAD_REASON + "\", unsafe and not invited",
      !!unread && unread.score === null && unread.match_reason === M.SCORE_UNREAD_REASON && M.SCORE_UNREAD_REASON === "The score could not be read." &&
      unread.outreach_safe === false && unread.reply_invited === false, J(t.updates));
    check("…and counted toward the daily cap: the tick says scored, and the cap counts scored_at, not score",
      t.out.scored === 2 && /\.select\("id", \{ count: "exact", head: true \}\)\.eq\("user_id", userId\)\.in\("source", SCORED_SOURCES\)\.gte\("scored_at", utcDayStart\(nowMs\)\)/.test(FILES[MR]), J(t.out));
    check("…with scored_at set, so it is never scored again", !!unread && typeof unread.scored_at === "string" && Date.parse(unread.scored_at) === NOW, J(unread));
    const LR = require(path.join(REPO, "lib", "leadReplies.js"));
    const stored = Object.assign(lead("l1"), unread, { status: "new" });
    check("…so it can never be replied to (not_safe)", (LR.replyRefusal(stored, NOW) || {}).code === "not_safe", J(LR.replyRefusal(stored, NOW)));
  }

  console.log("\n══ 4. it is not shown as a lead by default ══");
  {
    const RT = require(path.join(REPO, "lib", "leadRoutes.js"));
    const stored = Object.assign(lead("l1"), unread, { status: "new" });
    check("isWeak: hidden from the default list", RT.isWeak(stored) === true);
    const src = fs.readFileSync(path.join(REPO, "lib", "leadRoutes.js"), "utf8");
    check("the summary's new-lead count asks only for scores of " + M.WEAK_BELOW + " or more (or a Need or comment, never scored)",
      src.indexOf('.or("source.eq.bizforce,source.eq.youtube,score.gt." + (MR.WEAK_BELOW - 1))') !== -1 && M.WEAK_BELOW === 40);
  }

  console.log("\n══ 5. demand reads it as a failed score ══");
  {
    const ctx = { LEAD_SCORE_FAILED_REASON: undefined };
    vm.createContext(ctx);
    const def = name => { const at = FILES[SERVER].search(new RegExp("^(?:var|const) " + name + " = |^function " + name + "\\(", "m")); if (at < 0) throw new Error(name + " not found");
      const end = FILES[SERVER].indexOf("\n}\n", at); return /^function/.test(FILES[SERVER].slice(at, at + 9)) ? FILES[SERVER].slice(at, end + 2) : FILES[SERVER].slice(at, FILES[SERVER].indexOf(";\n", at) + 1); };
    vm.runInContext(def("LEAD_SCORE_FAILED_REASON").replace(/^const /, "var ") + "\n" + def("demandRowOf") + "\nthis.f = demandRowOf;", ctx);
    const failed = ctx.f(Object.assign(lead("l1"), unread));
    check("an unreadable answer: done (status scored, never waiting), no score, the failure reason", failed.status === "scored" && failed.intent_score === null && failed.intent_reason === ctx.LEAD_SCORE_FAILED_REASON && !!ctx.LEAD_SCORE_FAILED_REASON, J(failed));
    const legacy = ctx.f(Object.assign(lead("l4"), { score: 0, match_reason: null, scored_at: new Date(NOW).toISOString() }));
    check("…and a first-LR-2 row (0 with no reason) reads as failed too, never a real 0", legacy.intent_score === null && legacy.intent_reason === ctx.LEAD_SCORE_FAILED_REASON, J(legacy));
    const real0 = ctx.f(Object.assign(lead("l2"), { score: 0, match_reason: "Good match: not asking", scored_at: new Date(NOW).toISOString() }));
    check("a real 0, with its reason, stays a real 0", real0.intent_score === 0 && real0.intent_reason === "Good match: not asking", J(real0));
    const unscored = ctx.f(lead("l3"));
    check("an unscored lead is new, with no reason", unscored.status === "new" && unscored.intent_reason == null, J(unscored));
  }

  console.log("\n══ 6. a readable answer ══");
  {
    const t = await run('{"score": 82, "reason": "asks for a drain repair today", "safety": "SAFE", "invitation": "INVITED"}');
    const f = t.updates[0] && t.updates[0].fields;
    check("stored as given: 82, its reason, safe and invited", !!f && f.score === 82 && f.match_reason === "Strong match: asks for a drain repair today" && f.outreach_safe === true && f.reply_invited === true, J(f));
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
