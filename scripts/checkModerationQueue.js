"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkModerationQueue.js — the owner's moderation queue (P2-2, Nov 20 2026).

   WHAT THIS PROVES
     A. THE TABS (lib/moderation.js queueList, a fake database): waiting is
        waiting items and those hidden by reports and not yet decided,
        priority first, then oldest; decided is newest decision first; reports
        are the open reports, newest first, with the reporter's and author's
        names and the item's queue id; copyright is the notices, with the
        queue id; any other tab 400.
     B. A DECISION (decide, a stateful fake): the action and the note are
        checked; the row records who, when and the note; the open reports are
        dismissed on keep and actioned otherwise; moderation_logs gets
        "moderation_<action>"; every reporter is told the outcome without the
        note; the author is told the decision and the note, never who
        reported, and is not told when a waiting item is simply kept.
     C. COPYRIGHT IN A DECISION: removing an item with a notice marks the
        notice removed (upheld) and gives the author the counter-notice link;
        the third upheld notice bans the member (logged as a ban), the second
        does not; keeping marks the notice rejected. courtFiled only on a
        countered notice, and logged.
     D. STORAGE (lib/storageUsage.js): every bucket's files are added up,
        folders followed, against 1 GB; the walk stops at its budget and says
        partial; the answer is kept 10 minutes unless asked fresh.
     E. THE ROUTES: all five admin routes are requireAuth + requireAdmin
        (403 for anyone else); the Inbox counts carry the waiting count for
        the admin only.
     F. THE PAGES: moderation.html is owner only (one line for anyone else),
        with the four tabs, Keep, Hide, Remove, Remove and ban (remove, then
        the existing ban route), the court filing and the storage panel; the
        dashboard and the Inbox show the waiting count to the owner, only
        when above 0.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");

const SERVER = "@server.js", MOD = "@lib/moderation.js", STORE = "@lib/storageUsage.js";
const MUTATIONS = {
  "keep-actions-reports": [[MOD, 'status: state === "kept" ? "dismissed" : "actioned"', 'status: "actioned"']],
  "reporter-gets-note": [[MOD, "message: REPORTER_TEXT[state], read: false", "message: REPORTER_TEXT[state] + (note ? \" \" + note : \"\"), read: false"]],
  "author-told-quiet-keep": [[MOD, 'if (row.owner_id && !(state === "kept" && !wasHidden)) {', "if (row.owner_id) {"]],
  "unlogged-action": [[MOD, 'action: "moderation_" + opts.action,', 'action: "decision",']],
  "ban-at-two": [[MOD, "if (upheld < SF.REPEAT_INFRINGER_LIMIT) return { banned: false, upheld: upheld };", "if (upheld < 2) return { banned: false, upheld: upheld };"]],
  "court-any-state": [[MOD, 'if (!n.data || n.data.status !== "countered") return { status: 404, body: { error: MESSAGES.noticeNotFound } };', "if (!n.data) return { status: 404, body: { error: MESSAGES.noticeNotFound } };"]],
  "storage-unbounded": [[STORE, "      if (budget.objects <= 0) { partial = true; break; }\n", ""]],
  "decide-not-admin": [[SERVER, 'app.post("/api/admin/moderation/item/:id/decide", requireAuth, requireAdmin, async', 'app.post("/api/admin/moderation/item/:id/decide", requireAuth, async']],
  "count-for-all": [[SERVER, 'if (req.user.role === "admin") {\n      const waiting', "if (true) {\n      const waiting"]],
  "page-ban-unremoved": [["moderation.html", 'action: act === "ban" ? "remove" : act', "action: act"]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, MOD, STORE, "moderation.html", "dashboard.html", "inbox.html", "scripts/bf-safety.js"]);
const { FILES, check, J, has } = T;
const M = T.libRequire("./lib/moderation");
const SU = T.libRequire("./lib/storageUsage");

const ADMIN = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", AUTHOR = "22222222-2222-4222-8222-222222222222", R1 = "55555555-5555-4555-8555-555555555555", R2 = "66666666-6666-4666-8666-666666666666";
const ITEM = "44444444-4444-4444-8444-444444444444", QID = "77777777-7777-4777-8777-777777777777", NID = "88888888-8888-4888-8888-888888888888";
const NOW = "2026-11-20T12:00:00.000Z";

function world(o) {
  o = o || {};
  const st = { queue: Object.assign({ id: QID, object_type: "listing", object_id: ITEM, owner_id: AUTHOR, source: "report", priority: 2, report_count: 2, state: "waiting" }, o.queue || {}),
    reports: (o.reports || [{ id: "r1", reporter_id: R1 }, { id: "r2", reporter_id: R2 }]).map(r => Object.assign({ status: "open" }, r)),
    notices: (o.notices || []).slice(), upheldElsewhere: o.upheldElsewhere || 0, logs: [], notes: [], userUpdates: [], reportUpdates: [], noticeUpdates: [] };
  const db = H.fakeDb((t, q) => {
    if (t === "moderation_queue") {
      if (q.op === "update") { Object.assign(st.queue, q.payload); return { data: st.queue, error: null }; }
      if (H.filterVal(q, "eq", "owner_id")) return { data: [{ object_type: "listing", object_id: ITEM }, { object_type: "campaign", object_id: "c-elsewhere" }], error: null };
      return { data: H.filterVal(q, "eq", "id") === QID ? Object.assign({}, st.queue) : null, error: null };
    }
    if (t === "content_reports") {
      if (q.op === "update") { st.reportUpdates.push(q.payload); st.reports.forEach(r => Object.assign(r, q.payload)); return { data: null, error: null }; }
      return { data: st.reports.filter(r => r.status === "open"), error: null };
    }
    if (t === "copyright_notices") {
      if (q.op === "update") {
        st.noticeUpdates.push(q.payload);
        const ids = H.filterVal(q, "in", "id") || [H.filterVal(q, "eq", "id")];
        st.notices.forEach(n => { if (ids.indexOf(n.id) !== -1) Object.assign(n, q.payload); });
        return { data: null, error: null };
      }
      if (q.head) {
        const here = H.filterVal(q, "eq", "object_id") === ITEM ? st.notices.filter(n => n.status === "removed").length : st.upheldElsewhere;
        return { data: null, count: here, error: null };
      }
      if (H.filterVal(q, "eq", "id")) return { data: st.notices.find(n => n.id === H.filterVal(q, "eq", "id")) || null, error: null };
      const want = H.filterVal(q, "in", "status") || [];
      return { data: st.notices.filter(n => want.indexOf(n.status) !== -1), error: null };
    }
    if (t === "moderation_logs") { st.logs.push(q.payload); return { data: null, error: null }; }
    if (t === "notifications") { st.notes.push(q.payload); return { data: null, error: null }; }
    if (t === "users" && q.op === "update") { st.userUpdates.push(q.payload); return { data: [{ id: AUTHOR }], error: null }; }
    return { data: [], error: null };
  });
  return { st, db };
}
const decide = (w, action, note) => M.decide(w.db.client, { adminId: ADMIN, id: QID, action: action, note: note, nowIso: NOW });

(async function main() {
  /* ── A ── */
  console.log("\n══ A. the tabs ══");
  const list = async (tab, rows) => { const d = H.fakeDb((t) => ({ data: t === "bf_profiles" ? [{ user_id: AUTHOR, username: "author" }, { user_id: R1, username: "rita" }] : t === "moderation_queue" && tab !== "waiting" && tab !== "decided" ? [{ id: QID, object_type: "listing", object_id: ITEM }] : rows, error: null })); return { r: await M.queueList(d.client, tab), log: d.log }; };
  const wq = await list("waiting", [{ id: QID, owner_id: AUTHOR, state: "hidden", decided_at: null }]);
  const wsel = wq.log.find(q => q.table === "moderation_queue");
  check("A1. waiting: waiting, or hidden by reports and not yet decided; priority first, then oldest", J(wsel.filters.slice(0, 3)) === J([["or", "state.eq.waiting,and(state.eq.hidden,decided_at.is.null)"],
    ["order", "priority", { ascending: true }], ["order", "created_at", { ascending: true }]]) && wq.r.body.items[0].auto_hidden === true && wq.r.body.items[0].author === "@author", J(wsel.filters));
  const dq = await list("decided", []);
  check("A2. decided: newest decision first", J(dq.log[0].filters.slice(0, 2)) === J([["not", "decided_at", "is", null], ["order", "decided_at", { ascending: false }]]), J(dq.log[0].filters));
  const rq = await list("reports", [{ id: "r1", reporter_id: R1, owner_id: AUTHOR, object_type: "listing", object_id: ITEM, reason: "spam", status: "open" }]);
  const rsel = rq.log.find(q => q.table === "content_reports");
  check("A3. reports: the open ones, newest first, with who reported, the author and the item's queue id", J(rsel.filters.slice(0, 2)) === J([["eq", "status", "open"], ["order", "created_at", { ascending: false }]]) &&
    rq.r.body.items[0].reporter === "@rita" && rq.r.body.items[0].author === "@author" && rq.r.body.items[0].queue_id === QID, J({ f: rsel.filters, items: rq.r.body.items }));
  const cq = await list("copyright", [{ id: NID, object_type: "listing", object_id: ITEM, status: "received" }]);
  check("A4. copyright: the notices, with the item's queue id", cq.r.status === 200 && cq.r.body.items[0].queue_id === QID && cq.log.some(q => q.table === "copyright_notices"), J(cq.r));
  const bad = await M.queueList(H.fakeDb(() => ({ data: [], error: null })).client, "everything");
  check("A5. any other tab 400", bad.status === 400 && bad.body.error === M.MESSAGES.badTab && J(M.TABS) === J(["waiting", "reports", "copyright", "decided"]));

  /* ── B ── */
  console.log("\n══ B. a decision ══");
  let w = world();
  const b0 = [await M.decide(w.db.client, { adminId: ADMIN, id: QID, action: "delete", nowIso: NOW }), await decide(w, "keep", "x".repeat(1001)),
    await M.decide(w.db.client, { adminId: ADMIN, id: "nope", action: "keep", nowIso: NOW })];
  check("B1. the action is keep, hide or remove; the note at most 1000; an unknown item 404", b0[0].status === 400 && b0[1].status === 400 && b0[1].body.error === M.MESSAGES.noteLong && b0[2].status === 404 && w.db.log.length === 0, J(b0));
  w = world();
  const keep = await decide(w, "keep", "  fine as is  ");
  check("B2. keep: the row records who, when and the note; the reports are dismissed", keep.status === 200 && w.st.queue.state === "kept" && w.st.queue.decided_by === ADMIN &&
    w.st.queue.decided_at === NOW && w.st.queue.decision_note === "fine as is" && J(w.st.reportUpdates) === J([{ status: "dismissed", resolved_at: NOW }]), J({ q: w.st.queue, ru: w.st.reportUpdates }));
  check("B3. the decision is logged as moderation_keep, with the item and the note", w.st.logs.length === 1 && w.st.logs[0].action === "moderation_keep" && w.st.logs[0].admin_id === ADMIN &&
    w.st.logs[0].target_user_id === AUTHOR && w.st.logs[0].reason === "listing " + ITEM + ": fine as is", J(w.st.logs));
  const toReporters = w.st.notes.filter(n => n.user_id !== AUTHOR);
  check("B4. every reporter is told the outcome, without the note", keep.body.reporters_told === 2 && toReporters.length === 2 && toReporters.every(n => n.message === M.REPORTER_TEXT.kept && n.message.indexOf("fine as is") === -1), J(toReporters));
  check("B5. a waiting item that is simply kept: the author is not told (nothing changed for them)", !w.st.notes.some(n => n.user_id === AUTHOR), J(w.st.notes));
  w = world({ queue: { state: "hidden" } });
  await decide(w, "keep", "");
  check("B6. a hidden item that is kept: the author is told it is visible again", w.st.notes.some(n => n.user_id === AUTHOR && n.title === "Your listing is visible again"), J(w.st.notes));
  w = world();
  const rem = await decide(w, "remove", "copied photos");
  const toAuthor = w.st.notes.find(n => n.user_id === AUTHOR) || {};
  check("B7. remove: the reports are actioned; logged moderation_remove", rem.status === 200 && w.st.queue.state === "removed" && J(w.st.reportUpdates) === J([{ status: "actioned", resolved_at: NOW }]) && w.st.logs[0].action === "moderation_remove");
  check("B8. the author is told the decision and the note, never who reported", toAuthor.title === "Your listing was removed" && toAuthor.message === M.AUTHOR_TEXT.removed[1] + " copied photos" &&
    JSON.stringify(toAuthor).indexOf(R1) === -1 && JSON.stringify(toAuthor).indexOf(R2) === -1 && toAuthor.object_type === "listing", J(toAuthor));
  w = world({ reports: [] });
  await decide(w, "hide", "");
  check("B9. hide, with no reports: no report is touched, the author is told it is hidden", w.st.reportUpdates.length === 0 && w.st.notes.length === 1 && w.st.notes[0].title === "Your listing is hidden" && w.st.queue.state === "hidden");

  /* ── C ── */
  console.log("\n══ C. copyright in a decision ══");
  w = world({ notices: [{ id: NID, status: "received" }] });
  const cr = await decide(w, "remove", "");
  const ca = w.st.notes.find(n => n.user_id === AUTHOR) || {};
  check("C1. removing for a notice upholds it and gives the author the counter-notice link", w.st.notices[0].status === "removed" && cr.body.counter_notice_link === "/copyright.html?counter=" + NID &&
    ca.link === "/copyright.html?counter=" + NID && /you can send a counter-notice\.$/.test(ca.message), J({ cr: cr.body, ca }));
  check("C2. one upheld notice: no ban", J(cr.body.repeat_infringer) === J({ banned: false, upheld: 1 }) && w.st.userUpdates.length === 0, J(cr.body.repeat_infringer));
  w = world({ notices: [{ id: NID, status: "received" }], upheldElsewhere: 2 });
  const third = await decide(w, "remove", "");
  check("C3. the third upheld notice bans the member, and the ban is logged", J(third.body.repeat_infringer) === J({ banned: true, upheld: 3 }) && w.st.userUpdates.length === 1 &&
    w.st.userUpdates[0].ban_reason === "Repeat infringement: 3 upheld copyright notices." && w.st.logs.some(l => l.action === "ban" && l.target_user_id === AUTHOR), J({ r: third.body.repeat_infringer, logs: w.st.logs }));
  w = world({ notices: [{ id: NID, status: "received" }], upheldElsewhere: 1 });
  const second = await decide(w, "remove", "");
  check("C4. the second does not", second.body.repeat_infringer.banned === false && second.body.repeat_infringer.upheld === 2 && w.st.userUpdates.length === 0);
  w = world({ notices: [{ id: NID, status: "received" }] });
  await decide(w, "keep", "");
  check("C5. keeping marks the notice rejected", w.st.notices[0].status === "rejected" && w.st.userUpdates.length === 0);
  w = world({ notices: [{ id: NID, status: "countered", counter_notice: { name: "A", received_at: "2026-11-18T00:00:00Z" } }] });
  const cf = await M.courtFiled(w.db.client, NID, ADMIN, NOW);
  check("C6. the court filing is recorded on a countered notice, and logged", cf.status === 200 && w.st.notices[0].counter_notice.court_filed === true && w.st.notices[0].counter_notice.court_filed_at === NOW &&
    w.st.notices[0].counter_notice.name === "A" && w.st.logs.some(l => l.action === "copyright_court_filed"), J(w.st.notices[0]));
  w = world({ notices: [{ id: NID, status: "removed" }] });
  const cf2 = await M.courtFiled(w.db.client, NID, ADMIN, NOW);
  check("C7. on any other notice: 404, nothing written", cf2.status === 404 && w.st.noticeUpdates.length === 0 && w.st.logs.length === 0);

  /* ── D ── */
  console.log("\n══ D. storage ══");
  const tree = { "": [{ name: "a", id: null }, { name: "f1", id: "1", metadata: { size: 100 } }], "a": [{ name: "f2", id: "2", metadata: { size: 50 } }, { name: "f3", id: "3", metadata: {} }] };
  const listCalls = [];
  const storage = { from: () => ({ list: async (p, o) => { listCalls.push([p, o.offset]); return { data: o.offset ? [] : tree[p] || [], error: null }; } }) };
  const t1 = await SU.bucketTotal(storage, "bf-public", { objects: 100, folders: 100 });
  check("D1. a bucket's files are added up, folders followed", J(t1) === J({ bucket: "bf-public", bytes: 150, files: 3, partial: false }), J(t1));
  const t2 = await SU.bucketTotal(storage, "bf-public", { objects: 1, folders: 100 });
  check("D2. the walk stops at its budget and says partial", t2.partial === true && t2.files <= 2, J(t2));
  SU.resetCache();
  let walks = 0;
  const sb = { storage: { listBuckets: async () => { walks++; return { data: [{ name: "bf-public" }], error: null }; }, from: storage.from } };
  const m1 = await SU.measure(sb, { now: 1000 }), m2 = await SU.measure(sb, { now: 1000 + 60000 }), m3 = await SU.measure(sb, { now: 1000 + 60000, fresh: true });
  check("D3. against 1 GB, kept 10 minutes unless asked fresh", SU.FREE_PLAN_BYTES === 1073741824 && m1.limit_bytes === 1073741824 && m1.total_bytes === 150 && m1.cached === false &&
    m2.cached === true && m3.cached === false && walks === 2 && SU.CACHE_MS === 600000, J({ m1, m2, walks }));

  /* ── E ── */
  console.log("\n══ E. the routes ══");
  const S = FILES[SERVER];
  const ADMIN_ROUTES = ['app.get("/api/admin/moderation", ', 'app.get("/api/admin/moderation/storage", ', 'app.get("/api/admin/moderation/item/:id", ',
    'app.post("/api/admin/moderation/item/:id/decide", ', 'app.post("/api/admin/moderation/notice/:id/court-filed", '];
  const open = ADMIN_ROUTES.filter(r => !has(S, r + "requireAuth, requireAdmin, async function (req, res, next) {"));
  check("E1. all five admin routes: requireAuth and requireAdmin", open.length === 0, J(open));
  check("E2. requireAdmin answers 403 to anyone but the admin", /async function requireAdmin\(req, res, next\) \{\n  if \(!req\.user \|\| req\.user\.role !== "admin"\) \{\n    return res\.status\(403\)/.test(S));
  const dec = H.routeStatement(S, "post", "/api/admin/moderation/item/:id/decide") || "";
  // NAMED (Nov 23 2026, P3-3B): BEFORE the decision took no post deps. AFTER it is handed postDeps() too, so an approved Need sends its alerts (checkPostIntent J)
  check("E3. a decision is made as the signed-in admin", has(dec, "decide(supabase, { adminId: req.user.id, id: req.params.id, action: body.action, note: body.note, nowIso: nowIso(), postDeps: postDeps() })"));
  const counts = H.routeStatement(S, "get", "/api/inbox/counts") || "";
  check("E4. the Inbox counts carry the waiting count for the admin only (waiting, or hidden and undecided)",
    has(counts, 'if (req.user.role === "admin") {\n      const waiting = await supabase.from("moderation_queue").select("id", { count: "exact", head: true }).or("state.eq.waiting,and(state.eq.hidden,decided_at.is.null)");\n      if (!waiting.error) counts.moderation = waiting.count || 0;'));

  /* ── F ── */
  console.log("\n══ F. the pages ══");
  const P = FILES["moderation.html"] || "";
  check("F1. owner only: one line for anyone else, and nothing drawn", has(P, '<p class="empty-state" id="ownerOnly" hidden>This page is for the site owner.</p>') &&
    has(P, "if (r.status === 401 || r.status === 403) { showOwnerOnly(); return; }") && has(P, "if (!token) showOwnerOnly();") && has(P, '<meta name="robots" content="noindex"/>'));
  check("F2. the four tabs", ["waiting", "reports", "copyright", "decided"].every(t => has(P, 'data-tab="' + t + '"')) && has(P, '"/api/admin/moderation?tab=" + encodeURIComponent(current)'));
  check("F3. Keep, Hide, Remove, and Remove and ban (remove, then the existing ban route)", ["keep", "hide", "remove", "ban"].every(a => has(P, 'data-act="' + a + '"')) &&
    has(P, 'action: act === "ban" ? "remove" : act, note: note') && has(P, 'call("POST", "/api/admin/ban/" + encodeURIComponent(author.id)'));
  check("F4. the court filing and the storage panel", has(P, '"/api/admin/moderation/notice/" + encodeURIComponent(id) + "/court-filed"') && has(P, '"/api/admin/moderation/storage"') && has(P, 'id="storageAgain"'));
  const js = FILES["scripts/bf-safety.js"] || "";
  const oc = (/function ownerCount\(el\) \{[\s\S]*?\n  \}\n/.exec(js) || [""])[0];
  check("F5. the waiting count shows only when above 0, linking to the page", has(oc, '"/api/inbox/counts"') && /> 0/.test(oc) && has(oc, "/moderation.html"), oc.slice(0, 300));
  check("F6. the dashboard and the Inbox show it", ["dashboard.html", "inbox.html"].every(f => has(FILES[f], 'id="ownerModeration"') && has(FILES[f], 'window.BFSafety.ownerCount(document.getElementById("ownerModeration"))')));
  check("F7. no emoji on the page or in this check", !/\p{Extended_Pictographic}/u.test(P + require("fs").readFileSync(__filename, "utf8")));

  T.finish();
})().catch(e => { console.error(e); process.exit(1); });
