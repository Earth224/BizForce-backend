"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkCopyrightNotices.js — copyright notices and counter-notices (P2-2,
   Nov 20 2026).

   Anyone may send a notice from copyright.html (no sign-in, 5 an hour from
   one address). It names the work, where it is on BizForce, and carries the
   good-faith and accuracy statements and a typed signature. The item goes to
   the owner's queue at priority 1. If the owner removes it, the member may
   send a counter-notice; unless the claimant reports a court filing, the item
   is restored after 10 business days. Three upheld notices ban a member
   (checkModerationQueue C).

   WHAT THIS PROVES
     A. THE NOTICE (validateNotice, locateObject): the required fields, the
        limits, the email, both statements; where is a listing, a campaign, a
        @handle or a storefront link on this site and nothing else.
     B. submitNotice (a fake database): the notice is saved received, with
        the address, the phone and where folded into the work text; the item
        is queued at priority 1 (source copyright_notice); a link to nothing
        404 and nothing saved.
     C. THE COUNTER-NOTICE (counterView, submitCounter): only the member the
        material belongs to sees it or sends it; only after the removal; its
        statements are required; it is saved countered and logged.
     D. RESTORING (businessDaysBetween, restoreTick): 10 business days,
        weekends not counted; not after a court filing; the item is kept
        again, the notice restored, the member told; a step of the 04:45
        chain (job copyright_restore).
     E. THE ROUTES: POST /api/copyright/notices needs no sign-in and is
        limited 5 an hour; the counter-notice routes are signed in.
     F. THE PAGES: copyright.html posts exactly the fields the server reads,
        fills in ?where=, and the counter form is ?counter=<id>, signed in; it is
        public to visit but noindex (no marketing page);
        the footer, the Terms and the report menu link to it.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");

const SERVER = "@server.js", SAFETY = "@lib/safety.js", MOD = "@lib/moderation.js";
const MUTATIONS = {
  "no-good-faith": [[SAFETY, "  if (body.good_faith !== true) return { error: COPYRIGHT_MESSAGES.goodFaith, field: \"good_faith\" };\n", ""]],
  "any-site-link": [[SAFETY, "var m = /(?:^|bizforceai\\.net)\\/listing\\/", "var m = /\\/listing\\/"]],
  "notice-priority-2": [[MOD, 'source: "copyright_notice", priority: 1', 'source: "copyright_notice", priority: 2']],
  "counter-anyones": [[MOD, "  if (owner !== userId) return null;\n", ""]],
  "counter-before-removal": [[MOD, "  if (o.notice.status !== \"removed\") return { status: 409, body: { error: SF.COPYRIGHT_MESSAGES.counterState } };\n", ""]],
  "restore-early": [[SAFETY, "const RESTORE_BUSINESS_DAYS = 10;", "const RESTORE_BUSINESS_DAYS = 5;"]],
  "restore-despite-court": [[SAFETY, "  if (c.court_filed === true) return false;\n", ""]],
  "weekends-count": [[SAFETY, "    if (w !== 0 && w !== 6) n++;", "    n++;"]],
  "notices-need-signin": [[SERVER, 'app.post("/api/copyright/notices", copyrightLimiter,', 'app.post("/api/copyright/notices", requireAuth, copyrightLimiter,']],
  "counter-unauthed": [[SERVER, 'app.post("/api/copyright/counter/:id", requireAuth, copyrightLimiter,', 'app.post("/api/copyright/counter/:id", copyrightLimiter,']],
  "footer-no-link": [["scripts/bf-legal-footer.js", 'var LINE2 = [["Copyright notices", "/copyright.html"]];', "var LINE2 = [];"]],
  "page-wrong-field": [["copyright.html", 'good_faith: ticked("nGood")', 'goodFaith: ticked("nGood")']]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, SAFETY, MOD, "copyright.html", "terms.html", "scripts/bf-legal-footer.js", "scripts/bf-safety.js"]);
const { FILES, check, J, has } = T;
const SF = T.libRequire("./lib/safety");
const M = T.libRequire("./lib/moderation");

const AUTHOR = "22222222-2222-4222-8222-222222222222", OTHER = "33333333-3333-4333-8333-333333333333", ITEM = "44444444-4444-4444-8444-444444444444", NID = "88888888-8888-4888-8888-888888888888";
const NOW = "2026-11-20T12:00:00.000Z";
const GOOD = { name: "Pat Owner", email: "pat@example.com", work: "My photo of the harbour", location: "https://bizforceai.net/listing/oak-table",
  address: "1 Main St", phone: "555 0100", signature: "Pat Owner", good_faith: true, accuracy: true };

function world(o) {
  o = o || {};
  const st = { notice: o.notice ? Object.assign({ id: NID, object_type: "listing", object_id: ITEM }, o.notice) : null, inserted: [], queue: [], logs: [], updates: [] };
  const db = H.fakeDb((t, q) => {
    if (t === "marketplace_listings") return { data: (H.filterVal(q, "eq", "slug") === "oak-table" || H.filterVal(q, "eq", "id") === ITEM) ? { id: ITEM, seller_id: AUTHOR, title: "Oak table", slug: "oak-table" } : null, error: null };
    if (t === "copyright_notices") {
      if (q.op === "insert") { st.inserted.push(q.payload); return { data: { id: NID }, error: null }; }
      if (q.op === "update") {
        st.updates.push({ payload: q.payload, filters: q.filters });
        if (st.notice && (!H.filterVal(q, "eq", "status") || st.notice.status === H.filterVal(q, "eq", "status"))) { Object.assign(st.notice, q.payload); return { data: [{ id: NID }], error: null }; }
        return { data: [], error: null };
      }
      return { data: st.notice && H.filterVal(q, "eq", "id") === NID ? Object.assign({}, st.notice) : null, error: null };
    }
    if (t === "moderation_queue") {
      if (q.op === "insert") { st.queue.push(q.payload); return { data: Object.assign({ id: "q1" }, q.payload), error: null }; }
      return { data: null, error: null };
    }
    if (t === "moderation_logs") { st.logs.push(q.payload); return { data: null, error: null }; }
    return { data: null, error: null };
  });
  return { st, db };
}

(async function main() {
  /* ── A ── */
  console.log("\n══ A. the notice ══");
  const v = SF.validateNotice(GOOD);
  check("A1. a good notice: every field, and where it is", v.name === "Pat Owner" && v.email === "pat@example.com" && J(v.where) === J({ object_type: "listing", key: "oak-table" }), J(v));
  const without = k => SF.validateNotice(Object.assign({}, GOOD, { [k]: k === "good_faith" || k === "accuracy" ? false : "" })).field;
  check("A2. name, email, the work, where and the signature are required; address and phone are not",
    ["name", "email", "work", "location", "signature"].every(k => without(k) === k) && !SF.validateNotice(Object.assign({}, GOOD, { address: "", phone: "" })).error);
  check("A3. both statements must be confirmed (true, not \"yes\")", without("good_faith") === "good_faith" && without("accuracy") === "accuracy" &&
    SF.validateNotice(Object.assign({}, GOOD, { good_faith: "yes" })).field === "good_faith");
  check("A4. a real email; the limits", SF.validateNotice(Object.assign({}, GOOD, { email: "pat@" })).field === "email" &&
    SF.validateNotice(Object.assign({}, GOOD, { work: "x".repeat(2001) })).field === "work" && J(SF.NOTICE_LIMITS) === J({ name: 200, email: 254, work: 2000, location: 500, signature: 200, address: 500, phone: 40 }));
  const L = s => J(SF.locateObject(s));
  check("A5. where: a listing, a campaign, a @handle or a storefront on this site", L("https://bizforceai.net/listing/oak-table") === J({ object_type: "listing", key: "oak-table" }) &&
    L("bizforceai.net/campaign/abcdefgh23456789") === J({ object_type: "campaign", share_id: "abcdefgh23456789" }) && L("https://bizforceai.net/@Rita") === J({ object_type: "profile", handle: "rita" }) &&
    L("https://bizforceai.net/seller.html?u=rita") === J({ object_type: "profile", handle: "rita" }));
  check("A6. a link to another site is not where", SF.locateObject("https://evil.example/listing/oak-table") === null && SF.validateNotice(Object.assign({}, GOOD, { location: "https://evil.example/listing/x" })).field === "location");

  /* ── B ── */
  console.log("\n══ B. sending a notice ══");
  let w = world();
  const sent = await M.submitNotice(w.db.client, GOOD, NOW);
  const row = w.st.inserted[0] || {};
  check("B1. saved received, with the claimant, the statement and the signature", sent.status === 201 && sent.body.message === SF.COPYRIGHT_MESSAGES.received && row.status === "received" &&
    row.claimant_name === "Pat Owner" && row.claimant_email === "pat@example.com" && row.good_faith === true && row.signature === "Pat Owner" && row.object_id === ITEM && row.object_type === "listing", J({ sent, row }));
  check("B2. the address, the phone and where are kept in the work text, labelled", row.work === "My photo of the harbour\n\nClaimant address: 1 Main St\nClaimant phone: 555 0100\n\nWhere: https://bizforceai.net/listing/oak-table\nAccuracy statement confirmed under penalty of perjury.", J(row.work));
  const qr = w.st.queue[0] || {};
  check("B3. the item is queued at priority 1, source copyright_notice, with its owner", qr.priority === 1 && qr.source === "copyright_notice" && qr.owner_id === AUTHOR && qr.object_id === ITEM, J(qr));
  w = world();
  const nowhere = await M.submitNotice(w.db.client, Object.assign({}, GOOD, { location: "https://bizforceai.net/listing/nothing-here" }), NOW);
  check("B4. a link to nothing: 404, naming the field, and nothing saved", nowhere.status === 404 && nowhere.body.field === "location" && w.st.inserted.length === 0 && w.st.queue.length === 0, J(nowhere));

  /* ── C ── */
  console.log("\n══ C. the counter-notice ══");
  const COUNTER = { name: "Al Author", address: "2 Side St", phone: "", statement: "I took that photo.", signature: "Al Author", perjury: true, consent: true };
  w = world({ notice: { status: "removed", work: "My photo\n\nClaimant address: x", created_at: "2026-11-18T09:00:00Z" } });
  const view = await M.counterView(w.db.client, AUTHOR, NID), notMine = await M.counterView(w.db.client, OTHER, NID);
  check("C1. the member the material belongs to sees the notice (the work, not the claimant's contact details); anyone else 404",
    view.status === 200 && J(view.body.notice) === J({ id: NID, status: "removed", received: "2026-11-18", object_type: "listing", title: "Oak table", work: "My photo", countered: false }) &&
    notMine.status === 404 && notMine.body.error === SF.COPYRIGHT_MESSAGES.counterNotYours, J({ view, notMine }));
  const otherSends = await M.submitCounter(w.db.client, OTHER, NID, COUNTER, NOW);
  check("C2. nor can anyone else send one", otherSends.status === 404 && w.st.updates.length === 0);
  const missing = await M.submitCounter(w.db.client, AUTHOR, NID, Object.assign({}, COUNTER, { consent: false }), NOW);
  check("C3. the perjury statement and the consent are required", missing.status === 400 && missing.body.field === "consent" &&
    SF.validateCounter(Object.assign({}, COUNTER, { perjury: "yes" })).field === "perjury" && SF.validateCounter(Object.assign({}, COUNTER, { statement: "" })).field === "statement");
  const ok = await M.submitCounter(w.db.client, AUTHOR, NID, COUNTER, NOW);
  const saved = w.st.notice.counter_notice || {};
  check("C4. saved countered, with the statements, the time and no court filing; logged", ok.status === 200 && ok.body.message === SF.COPYRIGHT_MESSAGES.counterReceived &&
    w.st.notice.status === "countered" && saved.received_at === NOW && saved.court_filed === false && saved.perjury === true && saved.consent === true && saved.phone === null &&
    w.st.logs.some(l => l.action === "copyright_counter_notice" && l.target_user_id === AUTHOR), J({ ok, saved }));
  w = world({ notice: { status: "received" } });
  const early = await M.submitCounter(w.db.client, AUTHOR, NID, COUNTER, NOW);
  check("C5. only after the material was removed (409 before)", early.status === 409 && early.body.error === SF.COPYRIGHT_MESSAGES.counterState && w.st.updates.length === 0, J(early));

  /* ── D ── */
  console.log("\n══ D. restoring ══");
  check("D1. business days, weekends not counted: Mon 2 Nov to Mon 16 Nov is 10, to Fri 13 Nov is 9", SF.businessDaysBetween("2026-11-02T15:00:00Z", "2026-11-16T09:00:00Z") === 10 &&
    SF.businessDaysBetween("2026-11-02T15:00:00Z", "2026-11-13T09:00:00Z") === 9 && SF.businessDaysBetween("2026-11-07T00:00:00Z", "2026-11-09T00:00:00Z") === 1);
  const countered = (extra) => ({ id: NID, object_type: "listing", object_id: ITEM, status: "countered", counter_notice: Object.assign({ received_at: "2026-11-02T15:00:00Z", court_filed: false }, extra || {}) });
  function tickDb(notices) {
    const st = { qUpd: [], nUpd: [], notes: [] };
    const db = H.fakeDb((t, q) => {
      if (t === "copyright_notices" && q.op === "select") return { data: notices, error: null };
      if (t === "copyright_notices") { st.nUpd.push({ p: q.payload, f: q.filters }); return { data: null, error: null }; }
      if (t === "moderation_queue") { st.qUpd.push({ p: q.payload, f: q.filters }); return { data: [{ owner_id: AUTHOR }], error: null }; }
      if (t === "notifications") { st.notes.push(q.payload); return { data: null, error: null }; }
      return { data: null, error: null };
    });
    return { st, db };
  }
  const quietLog = async fn => { const o = console.log; console.log = () => {}; try { return await fn(); } finally { console.log = o; } };
  let k = tickDb([countered()]);
  const r1 = await quietLog(() => SF.restoreTick({ supabase: k.db.client, claimDailyJob: async () => true, now: () => new Date("2026-11-16T04:45:00Z") }));
  check("D2. after 10 business days: the item is kept again, the notice restored, the member told", J(r1) === J({ claimed: true, restored: 1 }) &&
    k.st.qUpd.length === 1 && k.st.qUpd[0].p.state === "kept" && J(k.st.qUpd[0].f) === J([["eq", "object_type", "listing"], ["eq", "object_id", ITEM], ["eq", "state", "removed"]]) &&
    J(k.st.nUpd[0]) === J({ p: { status: "restored" }, f: [["eq", "id", NID], ["eq", "status", "countered"]] }) && k.st.notes.length === 1 && k.st.notes[0].user_id === AUTHOR && k.st.notes[0].title === "Your listing is back", J({ r1, st: k.st }));
  k = tickDb([countered()]);
  const r2 = await quietLog(() => SF.restoreTick({ supabase: k.db.client, claimDailyJob: async () => true, now: () => new Date("2026-11-13T04:45:00Z") }));
  check("D3. after 9: nothing yet", r2.restored === 0 && k.st.qUpd.length === 0);
  k = tickDb([countered({ court_filed: true })]);
  const r3 = await quietLog(() => SF.restoreTick({ supabase: k.db.client, claimDailyJob: async () => true, now: () => new Date("2026-12-30T04:45:00Z") }));
  check("D4. a court filing recorded: never restored", r3.restored === 0 && k.st.qUpd.length === 0);
  const S = FILES[SERVER];
  // NAMED (Nov 20 2026, P2-3): BEFORE the restore was the chain's last step. AFTER the post retention (P2-3) follows it.
  check("D5. a step of the 04:45 chain, after the safety retention and before the post retention, through the shared daily claim (job copyright_restore)", has(S, ".then(safetyRetentionTick).then(copyrightRestoreTick).then(postRetentionTick)\n        .then(memberLeadsPurgeTick);") /* NAMED (Nov 23 2026, LR-2): the chain now ends with memberLeadsPurgeTick (Lead Radar's retention) */ &&
    has(S, 'return await require("./lib/safety").restoreTick({ supabase: supabase, claimDailyJob: require("./lib/accountFiles").claimDailyJob });') && SF.RESTORE_JOB_NAME === "copyright_restore" && SF.RESTORE_BUSINESS_DAYS === 10);

  /* ── E ── */
  console.log("\n══ E. the routes ══");
  check("E1. a notice needs no sign-in, and is limited", has(S, 'app.post("/api/copyright/notices", copyrightLimiter, async function (req, res, next) {'));
  const lim = (/const copyrightLimiter = rateLimit\(\{[\s\S]*?\n\}\);/.exec(S) || [""])[0];
  check("E2. 5 an hour from one address (no keyGenerator: the address)", has(lim, "max: 5,") && has(lim, "windowMs: 60 * 60 * 1000,") && !has(lim, "keyGenerator") && has(lim, SF.COPYRIGHT_MESSAGES.rateLimited));
  check("E3. the counter-notice routes are signed in", has(S, 'app.get("/api/copyright/counter/:id", requireAuth, async function') && has(S, 'app.post("/api/copyright/counter/:id", requireAuth, copyrightLimiter, async function'));
  w = world();
  const route = H.route(S, "post", "/api/copyright/notices", { supabase: w.db.client, copyrightLimiter: 0 }, T.libRequire);
  const rr = route ? await route({ user: undefined, body: GOOD }) : null;
  check("E4. the route, run without a member: 201 and the notice saved", rr && rr.status === 201 && w.st.inserted.length === 1, J(rr));

  /* ── F ── */
  console.log("\n══ F. the pages ══");
  const P = FILES["copyright.html"] || "";
  const keysOf = (path) => { const m = new RegExp('send\\("' + path.replace(/[/.]/g, "\\$&") + '[^"]*"(?: \\+ [^,]+)?, \\{([\\s\\S]*?)\\}(?:, token\\(\\))?\\)').exec(P); return m ? m[1].match(/([a-z_]+):/g).map(x => x.slice(0, -1)) : null; };
  const nk = keysOf("/api/copyright/notices"), ck = keysOf("/api/copyright/counter/");
  check("F1. the notice form posts exactly the fields the server reads", J((nk || []).slice().sort()) === J(["accuracy", "address", "email", "good_faith", "location", "name", "phone", "signature", "work"]), J(nk));
  check("F2. the counter form posts exactly the fields the server reads, signed in", J((ck || []).slice().sort()) === J(["address", "consent", "name", "perjury", "phone", "signature", "statement"]) &&
    has(P, "}, token()).then("), J(ck));
  check("F3. ?where= fills in where; ?counter= is the counter form, which asks a signed-out visitor to sign in and comes back",
    has(P, 'var where = params.get("where");') && has(P, 'var counterId = params.get("counter");') && has(P, 'localStorage.setItem("bf_return_to", window.location.pathname + window.location.search)'));
  // Public to visit (no sign-in, no owner gate), but not indexed: it is no marketing page (checkLaunchBlockB 12).
  check("F4. public to visit, noindex, the legal footer", has(P, '<meta name="robots" content="noindex"/>') && !has(P, "showOwnerOnly") && has(P,'<footer class="bf-legal-footer" data-bf-legal-footer></footer>\n<script src="/scripts/bf-legal-footer.js"></script>'));
  check("F5. the footer's second line links it", has(FILES["scripts/bf-legal-footer.js"], 'var LINE2 = [["Copyright notices", "/copyright.html"]];'));
  check("F6. the Terms explain it (section 7, #copyright) and link the page", has(FILES["terms.html"], 'id="copyright"') && has(FILES["terms.html"], "https://bizforceai.net/copyright.html"));
  check("F7. the report menu offers \"Send a copyright notice\" with where filled in", has(FILES["scripts/bf-safety.js"], 'var copyrightHref = "/copyright.html?where=" + encodeURIComponent(whereOf(item));') &&
    has(FILES["scripts/bf-safety.js"], ">Send a copyright notice</a>"));
  check("F8. no emoji on the page or in this check", !/\p{Extended_Pictographic}/u.test(P + require("fs").readFileSync(__filename, "utf8")));

  T.finish();
})().catch(e => { console.error(e); process.exit(1); });
