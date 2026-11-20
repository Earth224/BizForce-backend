"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkReports.js — reporting (P2-2, Nov 20 2026).

   A signed-in member reports a profile, a listing, a campaign or a message
   they received, with one of 13 reasons and an optional detail. The item goes
   to the owner's moderation queue. Three different reporters, or one report
   about a child's safety, hide it until it is decided, and its author is told
   it is under review (never who reported it).

   WHAT THIS PROVES
     A. THE RULES: validateReport (types today, a uuid, the 13 reasons, the
        detail at most 1000 characters, trimmed, empty is null); priority 1
        for minor_safety and copyright, else 2; shouldAutoHide (3 distinct
        reporters, or any minor_safety).
     B. fileReport, run against a stateful fake database: a report is saved
        (owner, open) and queues the item (source report); your own item 400;
        something that does not exist 404; a message only by its receiver;
        the same report twice 409; the third reporter hides the item and the
        author is told, without the reporter's name; a minor_safety report
        hides at once with priority 1; an item the owner kept goes back to
        waiting; a removed item stays removed.
     C. THE ROUTE: POST /api/reports is signed in, limited to 20 an hour per
        member, and answers fileReport's status and body.
     D. RETENTION: retentionTick deletes only resolved reports and decided
        queue items over a year old and copyright notices over three, logs
        the counts, and does nothing when the day's run is claimed; it is a
        step of the 04:45 UTC chain, after the Shopify reminder.
     E. THE PAGES: the report sheet posts /api/reports with the reason and
        the detail (counted to 1000); the menu is mounted on the campaign
        cards, the storefront, the listing page, a member's profile, the
        Inbox thread and Messages.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");

const SERVER = "@server.js", SAFETY = "@lib/safety.js";
const MUTATIONS = {
  "long-detail": [[SAFETY, "if (detail.length > DETAIL_MAX) return { error: MESSAGES.detailLong, field: \"detail\" };", ""]],
  "copyright-p2": [[SAFETY, 'const PRIORITY_ONE = ["minor_safety", "copyright"];', 'const PRIORITY_ONE = ["minor_safety"];']],
  "hide-at-two": [[SAFETY, "const AUTO_HIDE_REPORTERS = 3;", "const AUTO_HIDE_REPORTERS = 2;"]],
  "report-own": [[SAFETY, "  if (item.owner_id === reporterId) return { status: 400, body: { error: MESSAGES.ownItem } };\n", ""]],
  "report-any-message": [[SAFETY, '  if (v.object_type === "message" && item.receiver_id !== reporterId) return { status: 404, body: { error: MESSAGES.notFound } };\n', ""]],
  "kept-stays-kept": [[SAFETY, '  if (row.state === "kept") { patch.state = "waiting"; patch.decided_at = null; patch.decided_by = null; }\n', ""]],
  "author-not-told": [[SAFETY, "    if (hidden && item.owner_id) {", "    if (false) {"]],
  "retention-open-too": [[SAFETY, '.delete().neq("status", "open").lt("resolved_at", yearAgo)', '.delete().lt("created_at", yearAgo)']],
  "report-unlimited": [[SERVER, 'app.post("/api/reports", requireAuth, reportLimiter, async function', 'app.post("/api/reports", requireAuth, async function']],
  // NAMED (Nov 20 2026, P2-3): the chain now ends with the post retention
  "chain-dropped": [[SERVER, ".then(shopifyDataRequestReminderTick).then(safetyRetentionTick).then(copyrightRestoreTick).then(postRetentionTick);", ".then(shopifyDataRequestReminderTick).then(copyrightRestoreTick).then(postRetentionTick);"]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, SAFETY, "scripts/bf-safety.js", "campaigns.html", "seller.html", "listing.html", "profile.html", "inbox.html", "messages.html"]);
const { FILES, check, J, has } = T;
const SF = T.libRequire("./lib/safety");

const ME = "11111111-1111-4111-8111-111111111111", AUTHOR = "22222222-2222-4222-8222-222222222222", ITEM = "44444444-4444-4444-8444-444444444444";
const R2 = "55555555-5555-4555-8555-555555555555", R3 = "66666666-6666-4666-8666-666666666666";
const NOW = "2026-11-20T12:00:00.000Z";

/* A small stateful database: listings, messages, content_reports, moderation_queue, notifications. */
function world(opts) {
  opts = opts || {};
  const st = { reports: (opts.reports || []).slice(), queue: opts.queue ? [Object.assign({}, opts.queue)] : [], notes: [] };
  const db = H.fakeDb((t, q) => {
    const eq = c => H.filterVal(q, "eq", c);
    if (t === "marketplace_listings") return { data: eq("id") === ITEM ? { id: ITEM, seller_id: AUTHOR, title: "Oak table", description: "", slug: "oak-table", media: [] } : null, error: null };
    if (t === "messages") return { data: eq("id") === ITEM ? { id: ITEM, sender_id: AUTHOR, receiver_id: ME, content: "hi" } : null, error: null };
    if (t === "notifications") { if (q.op === "insert") st.notes.push(q.payload); return { data: null, error: null }; }
    if (t === "content_reports") {
      if (q.op === "insert") {
        if (st.reports.some(r => r.reporter_id === q.payload.reporter_id && r.object_id === q.payload.object_id && r.status === "open")) return { data: null, error: { code: "23505" } };
        st.reports.push(q.payload); return { data: { id: "r" + st.reports.length }, error: null };
      }
      return { data: st.reports.filter(r => r.object_id === eq("object_id") && r.status === "open"), error: null };
    }
    if (t === "moderation_queue") {
      if (q.op === "select") return { data: st.queue[0] || null, error: null };
      if (q.op === "insert") { st.queue.push(Object.assign({ id: "q1" }, q.payload)); return { data: st.queue[0], error: null }; }
      if (q.op === "update") {
        const row = st.queue[0];
        if (!row || (H.filterVal(q, "eq", "state") && row.state !== H.filterVal(q, "eq", "state"))) return { data: [], error: null };
        Object.assign(row, q.payload);
        return { data: q.terminal === "single" ? row : [{ id: row.id }], error: null };
      }
    }
    return { data: null, error: null };
  });
  return { st, db };
}
const report = (w, who, body) => SF.fileReport(w.db.client, who, Object.assign({ object_type: "listing", object_id: ITEM, reason: "spam" }, body || {}), NOW);

(async function main() {
  /* ── A ── */
  console.log("\n══ A. the rules ══");
  const v = SF.validateReport({ object_type: "listing", object_id: ITEM.toUpperCase(), reason: "scam", detail: "  sent me a fake link  " });
  check("A1. a good report: the id lower-cased, the detail trimmed", J(v) === J({ object_type: "listing", object_id: ITEM, reason: "scam", detail: "sent me a fake link" }), J(v));
  // NAMED (Nov 20 2026, P2-3): BEFORE profile, listing, campaign and message, a post refused. AFTER posts and comments come first
  // (P2-3 made them); a review is still refused.
  check("A2. the types today: post, comment, profile, listing, campaign, message (reviews later)", J(SF.REPORTABLE_NOW) === J(["post", "comment", "profile", "listing", "campaign", "message"]) &&
    SF.validateReport({ object_type: "review", object_id: ITEM, reason: "spam" }).field === "object_type");
  check("A3. the 13 reasons", J(SF.REASONS) === J(["spam", "harassment", "hate", "sexual", "minor_safety", "violence", "health_claim", "prohibited_item", "scam", "copyright", "impersonation", "privacy", "other"]) &&
    SF.validateReport({ object_type: "listing", object_id: ITEM, reason: "rude" }).field === "reason");
  check("A4. the detail: at most 1000 characters; empty is null; not an id is refused",
    SF.validateReport({ object_type: "listing", object_id: ITEM, reason: "spam", detail: "x".repeat(1001) }).error === SF.MESSAGES.detailLong &&
    SF.validateReport({ object_type: "listing", object_id: ITEM, reason: "spam", detail: "x".repeat(1000) }).detail.length === 1000 &&
    SF.validateReport({ object_type: "listing", object_id: ITEM, reason: "spam", detail: "   " }).detail === null &&
    SF.validateReport({ object_type: "listing", object_id: "12", reason: "spam" }).field === "object_id");
  check("A5. priority 1 for a child's safety and copyright, 2 for the rest", SF.priorityFor("minor_safety") === 1 && SF.priorityFor("copyright") === 1 && SF.priorityFor("spam") === 2);
  check("A6. auto-hide: 3 different reporters, or any report about a child's safety",
    !SF.shouldAutoHide([{ reporter_id: "a" }, { reporter_id: "a" }, { reporter_id: "b" }]) && SF.shouldAutoHide([{ reporter_id: "a" }, { reporter_id: "b" }, { reporter_id: "c" }]) &&
    SF.shouldAutoHide([{ reporter_id: "a", reason: "minor_safety" }]));

  /* ── B ── */
  console.log("\n══ B. filing a report ══");
  let w = world();
  const b1 = await report(w, ME, { detail: "copied photos" });
  check("B1. saved open, with the owner, and the item queued (source report, priority 2, 1 report, waiting)", b1.status === 201 && b1.body.reported === true && b1.body.hidden === false &&
    b1.body.message === SF.MESSAGES.reported && w.st.reports[0].owner_id === AUTHOR && w.st.reports[0].status === "open" && w.st.reports[0].detail === "copied photos" &&
    w.st.queue[0].source === "report" && w.st.queue[0].priority === 2 && w.st.queue[0].report_count === 1 && w.st.queue[0].state === "waiting" && w.st.notes.length === 0, J({ b1, st: w.st }));
  w = world();
  const own = await report(w, AUTHOR), gone = await report(w, ME, { object_id: R2 });
  check("B2. your own item 400; one that does not exist 404; nothing saved", own.status === 400 && own.body.error === SF.MESSAGES.ownItem && gone.status === 404 && w.st.reports.length === 0, J({ own, gone }));
  w = world();
  const notMine = await report(w, R2, { object_type: "message" }), mine = await report(w, ME, { object_type: "message", reason: "harassment" });
  check("B3. a message is reported only by the member who received it", notMine.status === 404 && mine.status === 201, J({ notMine, mine }));
  w = world();
  await report(w, ME);
  const again = await report(w, ME);
  check("B4. the same member reporting the same item again: 409, already waiting", again.status === 409 && again.body.reason === "already_reported" && w.st.queue[0].report_count === 1, J(again));
  w = world();
  await report(w, ME); const second = await report(w, R2); const third = await report(w, R3, { reason: "scam" });
  check("B5. the third different reporter hides the item", second.body.hidden === false && third.body.hidden === true && w.st.queue[0].state === "hidden" && w.st.queue[0].report_count === 3, J({ third, q: w.st.queue[0] }));
  const told = w.st.notes[0] || {};
  check("B6. the author is told it is under review, and not who reported it", w.st.notes.length === 1 && told.user_id === AUTHOR && told.type === "moderation" &&
    told.title === "Your listing is under review" && told.object_type === "listing" && JSON.stringify(told).indexOf(ME) === -1 && JSON.stringify(told).indexOf(R3) === -1, J(w.st.notes));
  w = world();
  const minor = await report(w, ME, { reason: "minor_safety" });
  check("B7. one report about a child's safety hides at once, priority 1", minor.body.hidden === true && w.st.queue[0].state === "hidden" && w.st.queue[0].priority === 1, J(w.st.queue));
  w = world({ queue: { id: "q1", object_type: "listing", object_id: ITEM, owner_id: AUTHOR, source: "report", priority: 2, report_count: 2, state: "kept", decided_at: NOW, decided_by: AUTHOR } });
  await report(w, ME);
  check("B8. an item the owner kept goes back to waiting when it is reported again", w.st.queue[0].state === "waiting" && w.st.queue[0].decided_at === null && w.st.queue[0].report_count === 3, J(w.st.queue));
  w = world({ queue: { id: "q1", object_type: "listing", object_id: ITEM, owner_id: AUTHOR, source: "report", priority: 2, report_count: 1, state: "removed", decided_at: NOW } });
  await report(w, ME, { reason: "minor_safety" });
  check("B9. a removed item stays removed (the priority still rises)", w.st.queue[0].state === "removed" && w.st.queue[0].priority === 1 && w.st.notes.length === 0, J(w.st.queue));

  /* ── C ── */
  console.log("\n══ C. the route ══");
  const S = FILES[SERVER];
  check("C1. POST /api/reports: signed in, limited, fileReport's answer", has(S, 'app.post("/api/reports", requireAuth, reportLimiter, async function (req, res, next) {\n  try {\n    const r = await require("./lib/safety").fileReport(supabase, req.user.id, req.body, nowIso());\n    return res.status(r.status).json(r.body);'));
  const lim = (/const reportLimiter = rateLimit\(\{[\s\S]*?\n\}\);/.exec(S) || [""])[0];
  check("C2. reportLimiter: 20 an hour per member, with the sentence", has(lim, "max: 20,") && has(lim, "windowMs: 60 * 60 * 1000,") && has(lim, 'return "report:" + (req.user && req.user.id);') &&
    has(lim, "You can send 20 reports an hour.") && SF.REPORTS_PER_HOUR === 20);
  const rdb = world();
  const rt = H.route(S, "post", "/api/reports", { supabase: rdb.db.client, reportLimiter: 0 }, T.libRequire);
  const rr = rt ? await rt({ user: { id: ME }, body: { object_type: "listing", object_id: ITEM, reason: "spam" } }) : null;
  check("C3. the route, run: 201 and the report saved", rr && rr.status === 201 && rdb.st.reports.length === 1, J(rr));

  /* ── D ── */
  console.log("\n══ D. retention ══");
  const tdb = H.fakeDb((t, q) => ({ data: q.op === "delete" ? [{ id: "x" }, { id: "y" }].slice(0, t === "copyright_notices" ? 1 : 2) : null, error: null }));
  const logs = [];
  const orig = console.log; console.log = m => logs.push(String(m));
  const out = await SF.retentionTick({ supabase: tdb.client, claimDailyJob: async () => true, now: () => new Date(NOW) });
  console.log = orig;
  const dels = tdb.log.filter(q => q.op === "delete");
  const byT = t => dels.find(q => q.table === t) || { filters: [] };
  check("D1. resolved reports over a year old (never an open one)", J(byT("content_reports").filters) === J([["neq", "status", "open"], ["lt", "resolved_at", "2025-11-20T12:00:00.000Z"]]), J(byT("content_reports").filters));
  check("D2. decided queue items over a year old", J(byT("moderation_queue").filters) === J([["in", "state", ["kept", "hidden", "removed"]], ["not", "decided_at", "is", null], ["lt", "decided_at", "2025-11-20T12:00:00.000Z"]]), J(byT("moderation_queue").filters));
  check("D3. copyright notices over three years old", J(byT("copyright_notices").filters) === J([["lt", "created_at", "2023-11-21T12:00:00.000Z"]]), J(byT("copyright_notices").filters));
  check("D4. the counts, logged and returned; job_runs finished", J(out) === J({ claimed: true, reports: 2, queue: 2, notices: 1 }) &&
    logs.some(l => l === "[SafetyRetention] deleted 2 resolved reports, 2 decided queue items, 1 copyright notices.") && tdb.log.some(q => q.table === "job_runs" && q.op === "update"), J({ out, logs }));
  const idle = H.fakeDb(() => ({ data: null, error: null }));
  const none = await SF.retentionTick({ supabase: idle.client, claimDailyJob: async () => false, now: () => new Date(NOW) });
  check("D5. a day already claimed: nothing deleted", J(none) === J({ claimed: false }) && idle.log.length === 0);
  check("D6. a step of the 04:45 chain, after the Shopify reminder, through the shared daily claim (job safety_retention)",
    has(S, ".then(shopifyDataRequestReminderTick).then(safetyRetentionTick).then(copyrightRestoreTick).then(postRetentionTick);") &&   // NAMED (Nov 20 2026, P2-3): BEFORE the line ended at copyrightRestoreTick
    has(S, 'return await require("./lib/safety").retentionTick({ supabase: supabase, claimDailyJob: require("./lib/accountFiles").claimDailyJob });') && SF.RETENTION_JOB_NAME === "safety_retention");

  /* ── E ── */
  console.log("\n══ E. the pages ══");
  const js = FILES["scripts/bf-safety.js"] || "";
  check("E1. the report sheet posts the item, the reason and the detail, counted to 1000",
    // NAMED (Nov 20 2026, P2-3): BEFORE the body was written inside the call. AFTER it is built first (sent), so a campaign known
    // only by its share link sends share_id in place of object_id.
    /var sent = \{ object_type: item\.type, object_id: item\.id, reason: picked\.value, detail: detail\.value \};/.test(js) && /call\("POST", "\/api\/reports", sent\)/.test(js) && /DETAIL_MAX = 1000/.test(js) && has(js, 'detail.value.length + " / " + DETAIL_MAX'));
  const mounted = { "campaigns.html": "BFSafety.mount(", "seller.html": "BFSafety.mount(", "listing.html": "BFSafety.mount(", "profile.html": "BFSafety.mount(", "inbox.html": "BFSafety.", "messages.html": "BFSafety." };
  const missing = Object.keys(mounted).filter(f => !has(FILES[f], mounted[f]) || !has(FILES[f], '<script src="/scripts/bf-safety.js"></script>'));
  check("E2. the menu is on the campaign cards, the storefront, the listing page, a member's profile, the Inbox thread and Messages", missing.length === 0, J(missing));
  check("E3. signed out, the menu offers \"Sign in to report\" and comes back here", has(js, "Sign in to report") && has(js, 'localStorage.setItem("bf_return_to", window.location.href)'));

  T.finish();
})().catch(e => { console.error(e); process.exit(1); });
