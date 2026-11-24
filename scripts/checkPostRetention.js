"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkPostRetention.js — what happens to removed posts, removed comments and
   the share tally over time (P2-3, Nov 20 2026; lib/postRetention.js, the
   04:45 UTC chain in server.js, lib/jobSchedules.js, the privacy page).

   An in-memory database (scripts/_p23Db.js) keeps migration 194's share
   counter, so the share tally's trigger runs as it does in Postgres.

   WHAT THIS PROVES
     A. A REMOVED POST'S TEXT is emptied 90 days after it was removed (by its
        author or by moderation), not a day sooner, and never while an open
        report or a live copyright notice (received, removed or countered)
        holds it; a closed report or a rejected notice does not hold it; a
        published post is never touched.
     B. A COMMENT MODERATION REMOVED becomes "[removed]" 90 days after the
        decision, unless a report or a notice holds it.
     C. A REMOVED POST'S PHOTOS are let go 30 days after: its post_media rows
        are deleted and the library files stay (the member's own to delete);
        not while held.
     D. THE SHARE TALLY: rows older than 30 days are deleted and the post's
        share_count is the same after (the trigger's decrement is added back).
     E. THE RUN: a day already claimed does nothing; a claimed day runs the
        four steps, and one step's error does not stop the others; it is the
        last step of the 04:45 UTC chain, listed in lib/jobSchedules.js, and
        the privacy page states its three figures from the code.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");
const { memDb } = require("./_p23Db");

const SERVER = "@server.js", PR = "@lib/postRetention.js", JS = "@lib/jobSchedules.js";
const MUTATIONS = {
  "purge-early": [[PR, "const BODY_PURGE_DAYS = 90;", "const BODY_PURGE_DAYS = 9;"]],
  "report-ignored": [[PR, "  (r[0].data || []).concat(r[1].data || []).forEach(", "  (r[1].data || []).forEach("]],
  "notice-ignored": [[PR, "  (r[0].data || []).concat(r[1].data || []).forEach(", "  (r[0].data || []).forEach("]],
  "rejected-holds": [[PR, 'const HOLDING_NOTICES = ["received", "removed", "countered"];', 'const HOLDING_NOTICES = ["received", "removed", "countered", "rejected"];']],
  "comment-purge-unheld": [[PR, '  var held = await heldAmong(sb, "comment", found);', "  var held = new Set();"]],
  "photos-held-ignored": [[PR, '  if (!due.length) return { released: 0, held: held.size };\n  var d = await sb.from("post_media")', '  due = ids;\n  var d = await sb.from("post_media")']],
  "photos-early": [[PR, "const PHOTO_RELEASE_DAYS = 30;", "const PHOTO_RELEASE_DAYS = 3;"]],
  "shares-not-restored": [[PR, "{ share_count: (Number(p.data.share_count) || 0) + per[id] }", "{ share_count: Number(p.data.share_count) || 0 }"]],
  "shares-kept-forever": [[PR, "const SHARE_DAYS_KEEP = 30;", "const SHARE_DAYS_KEEP = 3000;"]],
  "step-error-stops": [[PR, "      try { out[steps[i][0]] = await steps[i][1](sb, nowIso); } catch (e) { err = err || e; out[steps[i][0]] = null; }", "      out[steps[i][0]] = await steps[i][1](sb, nowIso);"]],
  "unclaimed-runs": [[PR, "    if (!claimed) return { claimed: false };\n", ""]],
  "chain-dropped": [[SERVER, ".then(copyrightRestoreTick).then(postRetentionTick)\n", ".then(copyrightRestoreTick)\n"]], /* NAMED (Nov 23 2026, LR-2): the chain now ends with memberLeadsPurgeTick (Lead Radar's retention) */
  "schedule-unlisted": [[JS, '      "post_retention",\n', "\n"]] /* NAMED (Nov 23 2026, LR-2): the chain now ends with memberLeadsPurgeTick (Lead Radar's retention) */
};
const T = H.setup(__filename, MUTATIONS, [SERVER, PR, JS]);
const { FILES, check, J, has } = T;
const R = T.libRequire("./lib/postRetention");

const ME = "11111111-1111-4111-8111-111111111111";
const NOW = "2026-11-20T04:45:00.000Z";
const daysAgo = d => new Date(Date.parse(NOW) - d * 86400000).toISOString();
const pid = n => "aaaaaaaa-0000-4000-8000-" + String(n).padStart(12, "0");
const post = (n, extra) => Object.assign({ id: pid(n), author_id: ME, body: "Text " + n, status: "removed", removed_at: daysAgo(91), like_count: 0, comment_count: 0, save_count: 0, share_count: 0 }, extra || {});
const quiet = async fn => { const l = console.log, e = console.error; console.log = () => {}; console.error = () => {}; try { return await fn(); } finally { console.log = l; console.error = e; } };
function base(extra) { return memDb(Object.assign({ posts: [], post_comments: [], post_media: [], post_share_days: [], member_media: [], moderation_queue: [], content_reports: [], copyright_notices: [], job_runs: [] }, extra || {})); }

(async function main() {
  /* ── A ── */
  console.log("\n══ A. a removed post's text ══");
  let db = base({
    posts: [post(1), post(2, { removed_at: daysAgo(89) }), post(3), post(4), post(5), post(6), post(7, { status: "published", removed_at: null }), post(8, { removed_reason: "moderation" })],
    content_reports: [{ object_type: "post", object_id: pid(3), status: "open" }, { object_type: "post", object_id: pid(6), status: "closed" }],
    copyright_notices: [{ object_type: "post", object_id: pid(4), status: "countered" }, { object_type: "post", object_id: pid(5), status: "rejected" }]
  });
  let r = await R.purgePostBodies(db.client, NOW);
  const body = n => db.t.posts.find(p => p.id === pid(n)).body;
  check("A1. 90 days after it was removed the text is emptied (by its author or by moderation), not a day sooner", body(1) === "" && body(8) === "" && body(2) === "Text 2", J(r));
  check("A2. an open report or a live copyright notice holds it", body(3) === "Text 3" && body(4) === "Text 4" && r.held === 2);
  check("A3. a closed report or a rejected notice does not", body(5) === "" && body(6) === "");
  check("A4. a published post is never touched", body(7) === "Text 7");
  r = await R.purgePostBodies(db.client, NOW);
  check("A5. a second run finds nothing more to do", r.purged === 0);

  /* ── B ── */
  console.log("\n══ B. a comment moderation removed ══");
  const cm = (n, extra) => Object.assign({ id: pid(100 + n), post_id: pid(7), author_id: ME, body: "Comment " + n, status: "removed" }, extra || {});
  db = base({
    post_comments: [cm(1), cm(2), cm(3), cm(4, { status: "published" })],
    moderation_queue: [{ object_type: "comment", object_id: pid(101), state: "removed", decided_at: daysAgo(91) }, { object_type: "comment", object_id: pid(102), state: "removed", decided_at: daysAgo(80) },
      { object_type: "comment", object_id: pid(103), state: "removed", decided_at: daysAgo(100) }, { object_type: "comment", object_id: pid(104), state: "removed", decided_at: daysAgo(100) }],
    content_reports: [{ object_type: "comment", object_id: pid(103), status: "open" }]
  });
  r = await R.purgeCommentBodies(db.client, NOW);
  const cb = n => db.t.post_comments.find(c => c.id === pid(100 + n)).body;
  check("B1. 90 days after the decision its text becomes \"[removed]\"; sooner, or held by a report, it stays; a comment put back is never touched",
    cb(1) === "[removed]" && cb(2) === "Comment 2" && cb(3) === "Comment 3" && cb(4) === "Comment 4", J(db.t.post_comments.map(c => c.body)));

  /* ── C ── */
  console.log("\n══ C. a removed post's photos ══");
  db = base({
    posts: [post(1, { removed_at: daysAgo(31) }), post(2, { removed_at: daysAgo(29) }), post(3, { removed_at: daysAgo(40) }), post(4, { status: "published", removed_at: null })],
    post_media: [1, 2, 3, 4].map(n => ({ post_id: pid(n), media_id: pid(200 + n), thumb_media_id: null, idx: 0 })),
    member_media: [1, 2, 3, 4].map(n => ({ id: pid(200 + n), user_id: ME })),
    copyright_notices: [{ object_type: "post", object_id: pid(3), status: "received" }]
  });
  r = await R.releasePhotos(db.client, NOW);
  check("C1. 30 days after removal its photos are let go; sooner, held, or still published, they stay", J(db.t.post_media.map(m => m.post_id).sort()) === J([pid(2), pid(3), pid(4)]) && r.released === 1 && r.held === 1, J(r));
  check("C2. the library files themselves stay: the member's own to delete", db.t.member_media.length === 4);

  /* ── D ── */
  console.log("\n══ D. the share tally ══");
  db = base({ posts: [post(1, { status: "published", removed_at: null, share_count: 3 })],
    post_share_days: [{ post_id: pid(1), user_id: ME, day: "2026-10-01" }, { post_id: pid(1), user_id: pid(9), day: "2026-10-10" }, { post_id: pid(1), user_id: ME, day: "2026-11-19" }] });
  r = await R.dropOldShareDays(db.client, NOW);
  check("D1. rows older than 30 days are deleted; the post's share_count is the same after", J(db.t.post_share_days.map(x => x.day)) === J(["2026-11-19"]) && db.t.posts[0].share_count === 3 &&
    r.deleted === 2 && r.restored === 2, J([r, db.t.posts[0].share_count]));

  /* ── E ── */
  console.log("\n══ E. the run ══");
  db = base({ posts: [post(1)] });
  r = await quiet(() => R.tick({ supabase: db.client, claimDailyJob: async () => false, now: () => new Date(NOW) }));
  check("E1. a day already claimed does nothing", J(r) === J({ claimed: false }) && db.t.posts[0].body === "Text 1" && db.writes().length === 0);
  db = base({ posts: [post(1)], post_share_days: [{ post_id: pid(1), user_id: ME, day: "2026-10-01" }] });
  db.failOn("moderation_queue", "select");
  const claims = [];
  r = await quiet(() => R.tick({ supabase: db.client, claimDailyJob: async (sb, job, day) => { claims.push(job + ":" + day); return true; }, now: () => new Date(NOW) }));
  check("E2. a claimed day runs the four steps; one step's error does not stop the others", r && r.claimed === true && r.posts && r.posts.purged === 1 && r.comments === null && r.photos && r.shares && r.shares.deleted === 1 &&
    J(claims) === J(["post_retention:2026-11-20"]), J(r));
  const S = FILES[SERVER];
  // NAMED (Nov 23 2026, LR-2): BEFORE "the last step"; Lead Radar's retention now follows it.
  check("E3. a step of the 04:45 UTC chain after the copyright restore (Lead Radar's retention follows), through the shared daily claim", has(S, ".then(safetyRetentionTick).then(copyrightRestoreTick).then(postRetentionTick)\n        .then(memberLeadsPurgeTick);") &&
    has(S, 'return await require("./lib/postRetention").tick({ supabase: supabase, claimDailyJob: require("./lib/accountFiles").claimDailyJob });') && R.JOB_NAME === "post_retention");
  // NAMED (Nov 23 2026, LR-2): BEFORE post_retention closed the list; member_leads_purge now follows it.
  check("E4. lib/jobSchedules.js lists post_retention in the 04:45 entry", /\{ tick: "cardLeadsPurgeTick\(", cron: "45 4 \* \* \*",[\s\S]*?"post_retention",\n[^\n]*\n\s*"member_leads_purge"\] \},/.test(FILES[JS]));
  const LPX = require("../lib/legalPages");   // the real one: it reads its sources from disk
  const priv = LPX.buildLegalPages(LPX.codeFacts())["privacy.html"] || "";
  check("E5. the privacy page states the three figures from the code", priv.indexOf("its text is erased " + R.BODY_PURGE_DAYS + " days later") !== -1 &&
    priv.indexOf("let go from it after " + R.PHOTO_RELEASE_DAYS + " days") !== -1 && priv.indexOf("The share tally is deleted after " + R.SHARE_DAYS_KEEP + " days.") !== -1);

  T.finish();
})().catch(e => { check("the check ran to the end", false, e && (e.stack || e.message || JSON.stringify(e))); T.finish(); });
