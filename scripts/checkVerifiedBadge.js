/* ══════════════════════════════════════════════════════════════════════════
   checkVerifiedBadge.js — the Verified badge (P3-2, Nov 21 2026; lib/verified.js,
   migration 199).

   WHAT IT PROVES
     A. WHO GETS IT: 'member' for a paid member while entitled (getUserPlan
        active with access_reason "subscription"; the owner pass and the admin
        exemption are not); 'seller' and 'official' only from the owner; a
        member who is also a seller or official keeps that kind when the
        membership ends. Read over an in-memory database.
     B. KEPT IN STEP WITH MEMBERSHIP: syncOne sets 'member' when the plan is
        active and clears it the moment it is not; the Stripe webhook runs it
        for the event's account (checkout metadata, the subscription, the
        customer); the hourly reconcile (cron "20 * * * *" UTC, on unless
        ENABLE_VERIFIED_SYNC is exactly "false") brings every badge and every
        subscription in step, test accounts and the owner left out of the
        subscription list, one failure never stopping the pass.
     C. THE REMOVAL CASES: a ban (the admin ban route and the repeat-infringer
        ban), an admin un-verify (a paid member drops back to 'member'), and a
        moderation removal of the profile each take it away; a banned account
        or a removed profile is never given one, and the owner cannot give one.
     D. ONE MARK, DRAWN THE SAME EVERYWHERE: scripts/bf-verified.js (run in a
        vm) builds exactly lib/verified.js badgeHtml, with the same rules; null
        draws nothing.
     E. THE SHEET: a tap opens "Verified: [kind]. This is not an endorsement."
        with a 44 px Close; the tap never follows the link the mark sits in.
     F. EVERY SURFACE: feed cards and the full-screen feed, Talk, suggestions,
        follow lists (peopleById, run), the profile, the storefront, public
        listings, services, card pages and /p/ (renderPostPage, run), each
        reading the server's `verified` field; every page loads bf-verified.js.
     G. SUGGESTIONS SORT VERIFIED FIRST (lib/posts.js suggestions, run), then
        recent posts; RANK_WEIGHT 1.5 is recorded for P2-6 and no ranking uses
        it yet.
     H. THE OWNER'S PAGE, THE LEGAL PAGES AND YOUR DATA: moderation.html's
        "Verified sellers" (the three admin routes, logged in moderation_logs);
        the Terms and Privacy say what it means, the three kinds, how it is
        removed, the factor (read from code) and that it is not an endorsement;
        Your data names it in the bf_profiles export.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   Reads files only: no database, no network.
   ══════════════════════════════════════════════════════════════════════════ */
"use strict";
const vm = require("vm");
const H = require("./_p21Harness");

const SERVER = "@server.js", VER = "@lib/verified.js", POSTS = "@lib/posts.js", PP = "@lib/postPage.js", MOD = "@lib/moderation.js",
  LP = "@lib/legalPages.js", YD = "@lib/yourData.js", RA = "@lib/routeAccess.js";
const FE_VB = "scripts/bf-verified.js", FEED = "scripts/bf-feed.js", SHELL = "scripts/bf-profile-shell.js";
const PAGES = ["home.html", "profile.html", "seller.html", "services.html", "listing.html", "card-view.html"];
const OWNER_PAGE = "moderation.html", TERMS = "terms.html", PRIVACY = "privacy.html";

const MUTATIONS = {
  // the owner pass counts as a paid membership
  "owner-pass-is-member": [[VER, 'plan.active === true && plan.access_reason === "subscription"', "plan.active === true"]],
  // a seller loses the badge when the membership ends
  "seller-cleared-on-lapse": [[VER, "  if (OWNER_SET.indexOf(current) !== -1) return current;\n", ""]],
  // a banned account keeps its badge
  "ban-keeps-badge": [[VER, "  if (st.banned || st.removed) return null;\n", "  if (st.removed) return null;\n"]],
  // the owner may give a badge to a banned account
  "verify-banned": [[VER, "  if (st.banned || !st.exists || st.removed) return { status: 409,", "  if (false) return { status: 409,"]],
  // un-verifying a paid member leaves no badge at all
  "unverify-drops-member": [[VER, "  await writeReason(deps, userId, null);\n  const after = await syncOne(deps, userId);\n  return { status: 200, body: { user_id: userId, verified_reason: after.to, from: from } };",
    "  await writeReason(deps, userId, null);\n  return { status: 200, body: { user_id: userId, verified_reason: null, from: from } };"]],
  // the reconcile no longer visits badges whose account has no subscription
  "reconcile-subs-only": [[VER, "  const ids = [...new Set([].concat(a.data || [], subs)", "  const ids = [...new Set([].concat(subs)"]],
  // test accounts are reconciled from the subscription list
  "reconcile-counts-tests": [[VER, "  const subs = (b.data || []).filter(function (r) { return r && !isUncountedAccount({ id: r.user_id }); });", "  const subs = (b.data || []).filter(Boolean);"]],
  // the webhook no longer moves the badge
  "stripe-no-sync": [[SERVER, "      try { await require(\"./lib/verified\").afterStripeEvent(verifiedDeps(), event); }", "      try { }"]],
  // the ban route leaves the badge
  "ban-route-no-clear": [[SERVER, "    try { badgeCleared = (await require(\"./lib/verified\").clearFor(verifiedDeps(), userId)).cleared; }", "    try { }"]],
  // a moderation removal of the profile leaves the badge
  "removal-no-clear": [[MOD, "  if (row.object_type === \"profile\" && state === \"removed\" && row.object_id) {", "  if (false) {"]],
  // the frontend mark is drawn differently from the server's
  "mark-differs": [[FE_VB, "stroke=\"#070b18\" stroke-width=\"1.9\"", "stroke=\"#070b18\" stroke-width=\"2.4\""]],
  // the sheet drops "not an endorsement"
  "sheet-no-endorsement": [[FE_VB, "  var NOT_ENDORSEMENT = \"This is not an endorsement.\";", "  var NOT_ENDORSEMENT = \"\";"]],
  // a tap on the mark follows the link it sits in
  "tap-follows-link": [[FE_VB, "    e.preventDefault();\n    e.stopPropagation();\n    open(", "    open("]],
  // the feed card drops the badge
  "feed-no-badge": [[FEED, "esc(a.name || \"A member\") + vb(a.verified) + '</span>'", "esc(a.name || \"A member\") + '</span>'"]],
  // follow lists and Talk lose the badge
  "people-no-verified": [[POSTS, "link: p.username ? \"/@\" + p.username : \"/profile.html?id=\" + id, verified: require(\"./verified\").reasonOf(bf[id]) };", "link: p.username ? \"/@\" + p.username : \"/profile.html?id=\" + id, verified: null };"]],
  // suggestions forget Verified first
  "suggestions-unranked": [[POSTS, "return VERIFIED_RANK(b.p) - VERIFIED_RANK(a.p) || b.n - a.n || a.i - b.i;", "return b.n - a.n || a.i - b.i;"]],
  // /p/ drops the badge
  "postpage-no-badge": [[PP, "function badgeFor(post) { var r = verifiedReason(post); return r ? VB.badgeHtml(r) : \"\"; }", "function badgeFor(post) { return \"\"; }"]],
  // the storefront stops sending the badge
  "storefront-no-verified": [[SERVER, "      verified: await verifiedReasonOf(userId)\n", "      verified: null\n"]],
  // the Terms stop saying it is not an endorsement
  "terms-no-endorsement": [[LP, "    \"Tapping the badge says which kind it is. \" + f.verifiedNotEndorsement + \" BizForce", "    \"Tapping the badge says which kind it is. BizForce"]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, VER, POSTS, PP, MOD, LP, YD, RA, FE_VB, FEED, SHELL, OWNER_PAGE, TERMS, PRIVACY].concat(PAGES));
const { FILES, check, finish, J, has } = T;
const S = FILES[SERVER] || "";
const V = T.libRequire("./lib/verified");

const PAID = "aaaaaaaa-0000-4000-8000-000000000001", SELLER = "aaaaaaaa-0000-4000-8000-000000000002", LAPSED = "aaaaaaaa-0000-4000-8000-000000000003",
  BANNED = "aaaaaaaa-0000-4000-8000-000000000004", REMOVED = "aaaaaaaa-0000-4000-8000-000000000005", NOPROF = "aaaaaaaa-0000-4000-8000-000000000006",
  OWNERP = "aaaaaaaa-0000-4000-8000-000000000007", PAIDSELLER = "aaaaaaaa-0000-4000-8000-000000000008", FREE = "aaaaaaaa-0000-4000-8000-000000000009";
const OWNER_ID = require("../lib/ownerAccount").OWNER_ACCOUNT_ID;
const TEST_ID = (require("../lib/testAccounts").TEST_ACCOUNTS.ids || [])[0];

/* An in-memory database over the harness's recording fake: eq, in, not(col, "is", null), limit; update writes the rows. */
function memDb(t) {
  const match = (q) => (r) => q.filters.every(f => {
    if (f[0] === "eq") return r[f[1]] === f[2];
    if (f[0] === "in") return f[2].indexOf(r[f[1]]) !== -1;
    if (f[0] === "not" && f[2] === "is" && f[3] === null) return r[f[1]] !== null && r[f[1]] !== undefined;
    return true;
  });
  const db = H.fakeDb((table, q) => {
    if (db.fail && db.fail(table, q)) return { data: null, error: { message: table + " is down" } };
    const rows = (t[table] || []).filter(match(q));
    if (q.op === "update") { rows.forEach(r => Object.assign(r, q.payload)); return { data: rows.map(r => Object.assign({}, r)), error: null }; }
    let out = rows.map(r => Object.assign({}, r));
    const lim = H.filterVal(q, "limit"); if (typeof lim === "number") out = out.slice(0, lim);
    if (q.terminal === "maybeSingle" || q.terminal === "single") return { data: out[0] || null, error: null };
    return { data: out, error: null };
  });
  db.t = t;
  return db;
}
function world() {
  const t = {
    bf_profiles: [PAID, SELLER, LAPSED, BANNED, REMOVED, OWNERP, PAIDSELLER, FREE, OWNER_ID].concat(TEST_ID ? [TEST_ID] : [])
      .map(id => ({ user_id: id, username: "u" + id.slice(-2), display_name: "Name " + id.slice(-2), verified_reason: null, verified_at: null })),
    users: [PAID, SELLER, LAPSED, BANNED, REMOVED, NOPROF, OWNERP, PAIDSELLER, FREE, OWNER_ID].concat(TEST_ID ? [TEST_ID] : [])
      .map(id => ({ id, role: id === OWNERP ? "admin" : "user", banned_at: id === BANNED ? "2026-11-20T00:00:00.000Z" : null })),
    moderation_queue: [{ object_type: "profile", object_id: REMOVED, state: "removed" }],
    subscriptions: [{ user_id: PAID, stripe_subscription_id: "sub_paid", stripe_customer_id: "cus_paid" }, { user_id: LAPSED, stripe_subscription_id: "sub_lapsed", stripe_customer_id: "cus_lapsed" },
      { user_id: PAIDSELLER, stripe_subscription_id: "sub_ps", stripe_customer_id: "cus_ps" }, { user_id: BANNED, stripe_subscription_id: "sub_b", stripe_customer_id: "cus_b" },
      { user_id: OWNER_ID, stripe_subscription_id: "sub_o", stripe_customer_id: "cus_o" }].concat(TEST_ID ? [{ user_id: TEST_ID, stripe_subscription_id: "sub_t", stripe_customer_id: "cus_t" }] : [])
  };
  const db = memDb(t);
  const plans = {};
  [PAID, PAIDSELLER, BANNED, REMOVED, TEST_ID].forEach(id => { if (id) plans[id] = { active: true, access_reason: "subscription" }; });
  plans[OWNER_ID] = { active: true, access_reason: "owner" };   // the owner pass, as getUserPlan answers it
  plans[OWNERP] = { active: true, access_reason: "admin", exempt: true };
  const deps = { sb: db.client, planOf: async (id) => plans[id] || { active: false, access_reason: null }, now: () => "2026-11-21T12:00:00.000Z" };
  const reason = (id) => { const r = t.bf_profiles.find(x => x.user_id === id); return r ? r.verified_reason : undefined; };
  const setReason = (id, v) => { const r = t.bf_profiles.find(x => x.user_id === id); r.verified_reason = v; r.verified_at = v ? "2026-11-01T00:00:00.000Z" : null; };
  return { t, db, deps, plans, reason, setReason };
}

/* scripts/bf-verified.js run in a vm over a small fake page. */
function frontend() {
  const nodes = [];
  function el(tag) {
    const n = { tag, children: [], attrs: {}, listeners: {}, textContent: "", className: "", parentNode: null, style: {},
      setAttribute(k, v) { this.attrs[k] = String(v); }, getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
      appendChild(c) { c.parentNode = this; this.children.push(c); return c; },
      removeChild(c) { this.children = this.children.filter(x => x !== c); c.parentNode = null; return c; },
      addEventListener(k, f) { this.listeners[k] = f; }, focus() { doc.focused = this; } };
    nodes.push(n);
    return n;
  }
  const docListeners = {};
  const doc = { focused: null, head: el("head"), body: el("body"), createElement: el,
    getElementById(id) { return nodes.find(n => n.id === id && attached(n)) || null; },
    addEventListener(k, f) { (docListeners[k] = docListeners[k] || []).push(f); },
    removeEventListener(k, f) { docListeners[k] = (docListeners[k] || []).filter(x => x !== f); } };
  function attached(n) { let p = n; while (p) { if (p === doc.head || p === doc.body) return true; p = p.parentNode; } return false; }
  const win = {};
  const ctx = { window: win, document: doc, console: { log() {}, warn() {}, error() {} } };
  vm.createContext(ctx);
  vm.runInContext(FILES[FE_VB] || "", ctx);
  const veil = () => doc.body.children.find(c => c.className === "bf-vb-veil") || null;
  function tap(reason) {
    const mark = { getAttribute: (k) => k === "data-bf-verified" ? reason : null };
    const ev = { target: { closest: (sel) => sel === ".bf-vb" ? mark : null }, prevented: false, stopped: false,
      preventDefault() { this.prevented = true; }, stopPropagation() { this.stopped = true; } };
    (docListeners.click || []).forEach(f => f(ev));
    return ev;
  }
  function key(k) { const ev = { key: k, preventDefault() {} }; (docListeners.keydown || []).slice().forEach(f => f(ev)); }
  return { win, doc, veil, tap, key, styleText: () => { const s = doc.head.children.find(c => c.id === "bf-verified-style"); return s ? s.textContent : null; } };
}

function fnText(src, sig) {
  const at = src.indexOf(sig);
  return at < 0 ? "" : src.slice(at, require("./_shared").braceMatch(src, src.indexOf("{", at)) + 1);
}
const textOf = (h) => String(h || "").replace(/<[^>]+>/g, " ").replace(/&amp;/g, "&").replace(/&quot;/g, "\"").replace(/&#39;/g, "'").replace(/\s+/g, " ");

(async function main() {
  /* ── A ── */
  console.log("\n══ A. who gets it ══");
  check("A1. three kinds, with their words", J(V.REASONS) === J(["member", "seller", "official"]) &&
    J(V.LABELS) === J({ member: "BizForce member", seller: "Verified seller", official: "Official BizForce account" }), J(V.LABELS));
  check("A2. a paid membership is active with access_reason subscription; the owner pass, an admin, a lapsed plan and no answer are not",
    V.paidMember({ active: true, access_reason: "subscription" }) === true && V.paidMember({ active: true, access_reason: "owner" }) === false &&
    V.paidMember({ active: true, access_reason: "admin" }) === false && V.paidMember({ active: false, access_reason: "subscription" }) === false &&
    V.paidMember(null) === false && V.paidMember({ active: "true", access_reason: "subscription" }) === false);
  check("A3. the next reason: paid gives member, unpaid none; seller and official stay whatever the plan; a ban or a removal gives none",
    V.nextReason(null, { paid: true }) === "member" && V.nextReason("member", { paid: false }) === null && V.nextReason("seller", { paid: false }) === "seller" &&
    V.nextReason("official", { paid: true }) === "official" && V.nextReason("seller", { paid: true, banned: true }) === null &&
    V.nextReason("official", { removed: true }) === null && V.nextReason("member", { paid: true, banned: true }) === null);
  check("A4. a stored value that is not one of the three is shown as nothing", V.reasonOf({ verified_reason: "VIP" }) === null && V.reasonOf(null) === null &&
    V.reasonOf({ verified_reason: "seller" }) === "seller" && V.badgeHtml("VIP") === "" && V.badgeHtml(null) === "");
  let w = world();
  for (const id of [PAID, OWNERP, FREE, OWNER_ID]) await V.syncOne(w.deps, id);
  check("A5. over the database: a paid member gets member; the admin exemption, a free account and the owner get none",
    w.reason(PAID) === "member" && w.reason(OWNERP) === null && w.reason(FREE) === null && w.reason(OWNER_ID) === null, J([w.reason(PAID), w.reason(OWNERP), w.reason(FREE), w.reason(OWNER_ID)]));
  const paidRow = w.t.bf_profiles.find(r => r.user_id === PAID);
  check("A6. ...and verified_at is when it was given", paidRow.verified_at === "2026-11-21T12:00:00.000Z", paidRow.verified_at);
  const ownerSet = await V.setByOwner(w.deps, SELLER, "seller"), official = await V.setByOwner(w.deps, FREE, "official");
  check("A7. the owner gives seller and official", ownerSet.status === 200 && w.reason(SELLER) === "seller" && official.status === 200 && w.reason(FREE) === "official", J([ownerSet, official]));
  const badKind = await V.setByOwner(w.deps, SELLER, "member"), noProf = await V.setByOwner(w.deps, NOPROF, "seller");
  check("A8. the owner cannot hand out member (400) nor badge an account with no profile (404)", badKind.status === 400 && noProf.status === 404 && w.reason(SELLER) === "seller", J([badKind.status, noProf.status]));
  w.setReason(PAIDSELLER, "seller"); w.plans[PAIDSELLER] = { active: false, access_reason: null };
  await V.syncOne(w.deps, PAIDSELLER);
  check("A9. a member who is also a seller keeps seller when the membership ends", w.reason(PAIDSELLER) === "seller", w.reason(PAIDSELLER));
  w.setReason(FREE, "official"); await V.syncOne(w.deps, FREE);
  check("A10. ...and an official account keeps official without any membership", w.reason(FREE) === "official", w.reason(FREE));
  const np = await V.syncOne(w.deps, NOPROF);
  check("A11. an account with no profile is left alone (nothing to show)", np.changed === false && np.reason === "no_profile" && !w.t.bf_profiles.some(r => r.user_id === NOPROF), J(np));

  /* ── B ── */
  console.log("\n══ B. kept in step with membership ══");
  w = world();
  w.setReason(LAPSED, "member");
  await V.syncOne(w.deps, LAPSED);
  check("B1. a membership that ended clears member at once", w.reason(LAPSED) === null, w.reason(LAPSED));
  w.plans[LAPSED] = { active: true, access_reason: "subscription" };
  const ev1 = await V.afterStripeEvent(w.deps, { id: "evt_1", type: "checkout.session.completed", data: { object: { metadata: { user_id: LAPSED } } } });
  check("B2. a checkout that completes sets member for the account in its metadata", w.reason(LAPSED) === "member" && ev1 && ev1.changed === true, J(ev1));
  w.plans[LAPSED] = { active: false, access_reason: null };
  await V.afterStripeEvent(w.deps, { id: "evt_2", type: "customer.subscription.deleted", data: { object: { id: "sub_lapsed", customer: "cus_lapsed" } } });
  check("B3. a subscription deleted clears it, the account found by the subscription", w.reason(LAPSED) === null, w.reason(LAPSED));
  w.plans[LAPSED] = { active: true, access_reason: "subscription" };
  await V.afterStripeEvent(w.deps, { id: "evt_3", type: "invoice.payment_succeeded", data: { object: { customer: "cus_lapsed" } } });
  check("B4. an invoice paid sets it again, the account found by the customer", w.reason(LAPSED) === "member", w.reason(LAPSED));
  const other = await V.afterStripeEvent(w.deps, { id: "evt_4", type: "charge.refunded", data: { object: { customer: "cus_lapsed" } } });
  w.db.fail = () => true;
  const down = await V.afterStripeEvent(w.deps, { id: "evt_5", type: "checkout.session.completed", data: { object: { metadata: { user_id: PAID } } } });
  w.db.fail = null;
  check("B5. any other event is ignored, and a failure never throws into the webhook", other === null && down === null);
  const hookAt = S.indexOf("      await handleStripeEvent(event);\n");
  const hook = hookAt < 0 ? "" : S.slice(hookAt, hookAt + 600);
  check("B6. the Stripe webhook runs it after the event is handled, inside its own try",
    hook.length > 100 && hook.indexOf("      try { await require(\"./lib/verified\").afterStripeEvent(verifiedDeps(), event); }") !== -1, hook.slice(0, 120));
  check("B7. the server's deps: getUserPlan, the server's client and clock", has(S, "function verifiedDeps() {") && /return \{ sb: supabase, planOf: (?:function \(id\) \{ return getUserPlan\(id\); \}|\(?id\)? => getUserPlan\(id\)), now: nowIso \};/.test(fnText(S, "function verifiedDeps() {")), fnText(S, "function verifiedDeps() {"));
  check("B8. the reconcile is scheduled at :20 every hour UTC, on unless ENABLE_VERIFIED_SYNC is exactly \"false\"",
    has(S, "    cron.schedule(\"20 * * * *\", function () {\n      require(\"./lib/verified\").reconcile(verifiedDeps())") &&
    /if \(process\.env\.ENABLE_VERIFIED_SYNC !== "false"\) \{/.test(S));
  w = world();
  w.setReason(SELLER, "seller"); w.setReason(BANNED, "seller"); w.setReason(LAPSED, "member"); w.setReason(REMOVED, "official");
  const rc = await V.reconcile(w.deps);
  check("B9. the reconcile: the paid member set, the lapsed member, the banned seller and the removed official cleared, the seller kept",
    w.reason(PAID) === "member" && w.reason(PAIDSELLER) === "member" && w.reason(LAPSED) === null && w.reason(BANNED) === null && w.reason(REMOVED) === null && w.reason(SELLER) === "seller" &&
    rc.set === 2 && rc.cleared === 3 && rc.failed === 0, J([rc, w.reason(PAID), w.reason(LAPSED), w.reason(BANNED), w.reason(REMOVED), w.reason(SELLER)]));
  check("B10. ...test accounts and the owner are left out of the subscription list (isUncountedAccount)",
    w.reason(OWNER_ID) === null && (!TEST_ID || w.reason(TEST_ID) === null), J([w.reason(OWNER_ID), TEST_ID && w.reason(TEST_ID)]));
  w = world();
  w.db.fail = (table, q) => table === "users" && H.filterVal(q, "eq", "id") === LAPSED;
  const rc2 = await V.reconcile(w.deps);
  check("B11. one account failing is counted, and the pass goes on", rc2.failed === 1 && w.reason(PAID) === "member", J(rc2));

  /* ── C ── */
  console.log("\n══ C. the removal cases ══");
  w = world();
  w.setReason(BANNED, "member"); await V.syncOne(w.deps, BANNED);
  check("C1. a banned account is never a member (its plan may still be active)", w.reason(BANNED) === null, w.reason(BANNED));
  await V.syncOne(w.deps, REMOVED);
  check("C2. nor an account whose profile moderation removed", w.reason(REMOVED) === null, w.reason(REMOVED));
  const vb = await V.setByOwner(w.deps, BANNED, "seller"), vr = await V.setByOwner(w.deps, REMOVED, "official");
  check("C3. the owner cannot badge a banned account or a removed profile (409)", vb.status === 409 && vr.status === 409 && w.reason(BANNED) === null && w.reason(REMOVED) === null, J([vb.status, vr.status]));
  w.setReason(SELLER, "official");
  const cf = await V.clearFor(w.deps, SELLER);
  check("C4. clearFor takes any kind away and says so", cf.cleared === true && cf.from === "official" && w.reason(SELLER) === null, J(cf));
  w.setReason(PAID, "seller"); w.setReason(FREE, "seller");
  const u1 = await V.unsetByOwner(w.deps, PAID), u2 = await V.unsetByOwner(w.deps, FREE);
  check("C5. an un-verify: a paid member drops back to member, anyone else to nothing", u1.status === 200 && u1.body.verified_reason === "member" && w.reason(PAID) === "member" &&
    u2.status === 200 && u2.body.verified_reason === null && w.reason(FREE) === null, J([u1, u2]));
  const ban = S.slice(S.indexOf("app.post(\"/api/admin/ban/:userId\""), S.indexOf("app.post(\"/api/admin/unban/:userId\""));
  check("C6. the admin ban route clears the badge after the ban lands, and says whether it did",
    ban.indexOf("    try { badgeCleared = (await require(\"./lib/verified\").clearFor(verifiedDeps(), userId)).cleared; }") !== -1 &&
    ban.indexOf("return res.json({ user: data, badge_cleared: badgeCleared });") !== -1);
  const unban = S.slice(S.indexOf("app.post(\"/api/admin/unban/:userId\""), S.indexOf("app.post(\"/api/admin/verify/:userId\""));
  check("C7. ...and an unban brings a paid member's badge back (syncOne)", /require\("\.\/lib\/verified"\)\.syncOne\(verifiedDeps\(\), userId\)/.test(unban));
  const M = FILES[MOD] || "";
  check("C8. the repeat-infringer ban clears it (lib/moderation.js banForRepeats)", /await require\("\.\/verified"\)\.clearFor\(\{ sb: sb, now: function \(\) \{ return nowIso; \} \}, ownerId\);/.test(fnText(M, "async function banForRepeats(")));
  check("C9. a moderation removal of the profile clears it (lib/moderation.js decide)",
    fnText(M, "async function decide(").indexOf("  if (row.object_type === \"profile\" && state === \"removed\" && row.object_id) { try { await require(\"./verified\").clearFor(") !== -1);
  const vrt = S.slice(S.indexOf("app.post(\"/api/admin/verify/:userId\""), S.indexOf("app.post(\"/api/admin/flag/:userId\""));
  check("C10. the admin routes: verify gives seller (official when asked) and logs verify_<kind>; unverify logs unverify; both admin only",
    has(vrt, "const badgeReason = req.body && req.body.reason === \"official\" ? \"official\" : \"seller\";") && has(vrt, "action: \"verify_\" + badgeReason") &&
    has(vrt, "app.post(\"/api/admin/unverify/:userId\", requireAuth, requireAdmin,") && has(vrt, "action: \"unverify\"") &&
    has(vrt, "app.get(\"/api/admin/verified\", requireAuth, requireAdmin,") && T.libRequire("./lib/routeAccess").groupOf("post /api/admin/unverify/:userId") === "A" &&
    T.libRequire("./lib/routeAccess").groupOf("get /api/admin/verified") === "A");

  /* ── D ── */
  console.log("\n══ D. one mark, drawn the same everywhere ══");
  const fe = frontend();
  const B = fe.win.bfVerified;
  check("D1. scripts/bf-verified.js loads and says the same three kinds", !!B && J(B.REASONS) === J(V.REASONS) && J(B.LABELS) === J(V.LABELS), B && J(B.LABELS));
  const same = B ? V.REASONS.filter(r => B.html(r) !== V.badgeHtml(r)) : ["(no script)"];
  check("D2. its markup is lib/verified.js badgeHtml's, for each kind", same.length === 0, same.join(", "));
  check("D3. null and an unknown kind draw nothing", !!B && B.html(null) === "" && B.html("VIP") === "" && B.html(undefined) === "");
  const st = fe.styleText() || "";
  check("D4. its rules begin with lib/verified.js CSS, word for word", st.indexOf(V.CSS) === 0, st.slice(0, 80));
  check("D5. the mark is 16 px with a 44 px tap area that moves nothing, inline after the name, not focusable",
    /\.bf-vb\{position:relative;display:inline-flex;[^}]*width:16px;height:16px;margin:0 0 0 4px;/.test(V.CSS) &&
    /\.bf-vb::after\{content:"";position:absolute;left:50%;top:50%;width:44px;height:44px;transform:translate\(-50%,-50%\)\}/.test(V.CSS) &&
    /role="img"/.test(V.badgeHtml("member")) && !/tabindex|<button|<a /.test(V.badgeHtml("member")) && /aria-label="BizForce member"/.test(V.badgeHtml("member")));

  /* ── E ── */
  console.log("\n══ E. the sheet ══");
  check("E1. the sheet's words, for each kind", V.sheetText("member") === "Verified: BizForce member. This is not an endorsement." &&
    V.sheetText("seller") === "Verified: Verified seller. This is not an endorsement." && V.sheetText("official") === "Verified: Official BizForce account. This is not an endorsement." &&
    V.sheetText(null) === null);
  const ev = fe.tap("seller");
  const veil = fe.veil();
  const sheet = veil && veil.children[0], para = sheet && sheet.children.find(c => c.tag === "p"), close = sheet && sheet.children.find(c => c.tag === "button");
  check("E2. a tap opens it: \"Verified: Verified seller. This is not an endorsement.\"", !!para && para.textContent === V.sheetText("seller") && B.sheetText("seller") === V.sheetText("seller"),
    para && para.textContent);
  check("E3. ...and the tap does not follow the link the mark sits in", ev.prevented === true && ev.stopped === true);
  check("E4. a dialog with Close, focused; Close is at least 44 px", !!sheet && sheet.attrs.role === "dialog" && !!close && close.textContent === "Close" && fe.doc.focused === close &&
    /\.bf-vb-sheet button\{min-height:44px;/.test(st));
  close && close.listeners.click && close.listeners.click();
  check("E5. Close closes it", !fe.veil());
  fe.tap("official"); fe.key("Escape");
  check("E6. Escape closes it too", !fe.veil());

  /* ── F ── */
  console.log("\n══ F. every surface ══");
  const missingTag = PAGES.filter(p => !/<script src="\/scripts\/bf-verified\.js"><\/script>/.test(FILES[p] || ""));
  check("F1. every page that draws it loads scripts/bf-verified.js (" + PAGES.join(", ") + ")", missingTag.length === 0, missingTag.join(", "));
  const home = FILES["home.html"] || "", feedAt = home.indexOf("/scripts/bf-feed.js"), vbAt = home.indexOf("/scripts/bf-verified.js");
  check("F2. ...on Home before the feed that draws it", vbAt !== -1 && feedAt !== -1 && vbAt < feedAt);
  const feed = FILES[FEED] || "";
  check("F3. feed cards and the full-screen feed: inside the name, after its text", has(feed, "function vb(reason) { return window.bfVerified ? window.bfVerified.html(reason) : \"\"; }") &&
    has(feed, "<span class=\"bfp-name\">' + esc(a.name || \"A member\") + vb(a.verified) + '</span>'"));
  check("F4. Talk: each comment's name", has(feed, "'\">' + esc(a.name || \"A member\") + vb(a.verified) + '</a>'"));
  check("F5. suggestions on Home", /<span class="person-name">' \+ escapeHtml\(p\.name\) \+ \(window\.bfVerified \? window\.bfVerified\.html\(p\.verified\)/.test(home));
  const shell = FILES[SHELL] || "";
  check("F6. the profile shell's title and the follow lists", has(shell, "'<h2 class=\"pfs-title\">' + esc(name) + vb(state.verified) + '</h2>'") &&
    has(shell, "'<span><strong>' + esc(p.name || \"A member\") + vb(p.verified) + '</strong>'"));
  check("F7. the profile page, from the server's verified", has(FILES["profile.html"], "profileData.verified = typeof pBody.verified === \"string\" ? pBody.verified : null;") &&
    has(FILES["profile.html"], "document.getElementById(\"displayName\").insertAdjacentHTML(\"beforeend\", window.bfVerified.html(p.verified));"));
  // NAMED (Nov 25 2026, H1, part G): BEFORE the storefront drew the badge at once, so a slow bf-verified.js lost it. AFTER whenVerified
  // waits for either order and draws it once (PHONE_H1 delays each script both ways).
  check("F8. the storefront, once bf-verified.js and the answer are both in, in either order",
    has(FILES["seller.html"], "  if (data.verified) whenVerified(function () {\n    var nameEl = document.getElementById(\"sfName\");\n    if (!nameEl.querySelector(\"[data-bf-verified]\")) nameEl.insertAdjacentHTML(\"beforeend\", window.bfVerified.html(data.verified));\n  });") &&
    has(FILES["seller.html"], "function whenVerified(fn) {\n  if (window.bfVerified) { fn(); return; }\n"));
  check("F9. public listings: the seller's name with the badge", /window\.bfVerified \? window\.bfVerified\.html\(d\.verified\) : ""\) \+ '<\/a><\/p>'/.test(FILES["listing.html"] || ""));
  check("F10. services: the seller's name", has(FILES["services.html"], "<div class=\"svc-seller-name\">' + sellerName + (window.bfVerified && seller ? window.bfVerified.html(seller.verified) : \"\") + '</div>'"));
  check("F11. card pages", has(FILES["card-view.html"], "document.getElementById(\"pName\").insertAdjacentHTML(\"beforeend\", window.bfVerified.html(d.verified));"));
  check("F12. the server sends verified on the profile, the storefront, a listing and both card answers",
    has(S, "member: data ? await ownerIsMember(userId) : false, verified: data ? await verifiedReasonOf(userId) : null });") &&
    has(S, "      member: await ownerIsMember(userId),\n") && has(S, "      verified: await verifiedReasonOf(userId)\n") &&
    has(S, "      verified: seller ? await verifiedReasonOf(listing.seller_id) : null") &&
    S.split("support_links: await publicSupportLinks(data.user_id),\n      verified: await verifiedReasonOf(data.user_id) });").length - 1 === 2);
  check("F13. verifiedReasonOf reads only verified_reason and answers through reasonOf; a failed read shows nothing",
    /select\("user_id, verified_reason"\)\.eq\("user_id", userId\)\.maybeSingle\(\)/.test(fnText(S, "async function verifiedReasonOf(userId) {")) &&
    /return require\("\.\/lib\/verified"\)\.reasonOf\(r\.data\);/.test(fnText(S, "async function verifiedReasonOf(userId) {")) &&
    /catch \(badgeReadError\) \{[\s\S]*return null;/.test(fnText(S, "async function verifiedReasonOf(userId) {")));
  const P = T.libRequire("./lib/posts");
  const pdb = memDb({ bf_profiles: [{ user_id: PAID, username: "rose", display_name: "Rose", avatar_url: null, verified_reason: "member" },
    { user_id: FREE, username: "ivy", display_name: "Ivy", avatar_url: null, verified_reason: null }], profiles: [] });
  const people = await P.peopleById(pdb.client, [PAID, FREE]);
  check("F14. Talk, follow lists and the feed's authors (peopleById, run): verified for the badge, null for none",
    people[PAID] && people[PAID].verified === "member" && people[FREE] && people[FREE].verified === null, J(people));
  const PG = T.libRequire("./lib/postPage");
  const post = { id: "bbbbbbbb-0000-4000-8000-000000000001", kind: "text", body: "Fresh bread today", published_at: "2026-11-21T10:00:00.000Z", photos: [],
    author: { id: PAID, name: "Rose", username: "rose", link: "/@rose", avatar_url: null, verified: "seller" } };
  const withB = PG.renderPostPage(post), without = PG.renderPostPage(Object.assign({}, post, { author: Object.assign({}, post.author, { verified: null }) }));
  check("F15. /p/ (renderPostPage, run): the mark inside the author's name, its rules and bf-verified.js, only for a verified author",
    withB.indexOf(V.badgeHtml("seller")) !== -1 && /class="pp-name"[^>]*>Rose<span class="bf-vb"/.test(withB) && withB.indexOf(V.CSS) !== -1 &&
    withB.indexOf("<script src=\"/scripts/bf-verified.js\"></script>") !== -1 &&
    without.indexOf("bf-vb") === -1 && without.indexOf("bf-verified.js") === -1, (/pp-name[^\n]{0,200}/.exec(withB) || [""])[0]);

  /* ── G ── */
  console.log("\n══ G. suggestions sort Verified first ══");
  const ids = [1, 2, 3, 4].map(n => "cccccccc-0000-4000-8000-00000000000" + n);
  const sdb = memDb({
    bf_profiles: ids.map((id, i) => ({ user_id: id, username: "m" + i, display_name: "M" + i, avatar_url: null, updated_at: "2026-11-2" + i, verified_reason: i === 3 ? "seller" : i === 2 ? "member" : null })),
    moderation_queue: [],
    posts: [ids[0], ids[0], ids[0], ids[1]].map(a => ({ author_id: a, status: "published", audience: "public" }))
  });
  const sugg = await P.suggestions({ sb: sdb.client, ownerPublic: async () => true, now: () => "2026-11-21T12:00:00.000Z" },
    { viewer: "dddddddd-0000-4000-8000-000000000001", following: new Set(), blocked: new Set(), muted: new Set(), publicCache: {} });
  const order = (sugg || []).map(x => x.username);
  check("G1. verified accounts first (in the order read), then the most recent posts", J(order) === J(["m2", "m3", "m0", "m1"]), J(order));
  check("G2. ...each suggestion carries verified", sugg && sugg[0].verified === "member" && sugg[1].verified === "seller" && sugg[2].verified === null, J(sugg && sugg.map(x => x.verified)));
  const rankUsers = ["@lib/posts.js", "@server.js"].filter(f => /RANK_WEIGHT/.test(FILES[f] || ""));
  check("G3. RANK_WEIGHT is 1.5, recorded for For You, Market and Local (P2-6), and no ranking uses it yet", V.RANK_WEIGHT === 1.5 && rankUsers.length === 0 &&
    /For You, Market and Local: a verified account's placement is multiplied by this \(P2-6\)\. Not used by any ranking yet\./.test(FILES[VER] || ""), rankUsers.join(", "));

  /* ── H ── */
  console.log("\n══ H. the owner's page, the legal pages and Your data ══");
  const mod = FILES[OWNER_PAGE] || "";
  check("H1. moderation.html: a \"Verified sellers\" section with a handle, the kind (seller or official) and Give the badge",
    has(mod, "<h2 id=\"verifiedTitle\">Verified sellers</h2>") && /<option value="seller"[^>]*>/.test(mod) && /<option value="official"[^>]*>/.test(mod) && has(mod, "Give the badge"));
  check("H2. ...it finds the handle, then gives the badge, and lists and removes through the admin routes",
    has(mod, "call(\"GET\", \"/api/admin/verified?handle=\" + encodeURIComponent(handle))") &&
    has(mod, "call(\"POST\", \"/api/admin/verify/\" + encodeURIComponent(r.body.found.user_id), { reason: kind })") &&
    has(mod, "call(\"POST\", \"/api/admin/unverify/\" + encodeURIComponent(b.getAttribute(\"data-unverify\")))") && has(mod, "call(\"GET\", \"/api/admin/verified\")"));
  // lib/legalPages.js reads files beside it (__dirname), so it is compiled here from the text this check holds (a mutation reaches it).
  const LPm = (function () {
    const Module = require("module"), path = require("path"), file = path.join(H.REPO, "lib", "legalPages.js");
    const m = new Module(file, module); m.filename = file; m.paths = Module._nodeModulePaths(path.dirname(file));
    m._compile(FILES[LP] || "", file); return m.exports;
  })();
  const facts = LPm.codeFacts();
  check("H3. the legal pages read the kinds, the sentence and the factor from lib/verified.js", J(facts.verifiedLabels) === J(V.LABELS) &&
    facts.verifiedNotEndorsement === V.NOT_ENDORSEMENT && facts.verifiedWeight === V.RANK_WEIGHT, J([facts.verifiedLabels, facts.verifiedWeight]));
  const built = LPm.buildLegalPages(facts);
  const termsHtml = (built && built["terms.html"]) || FILES[TERMS] || "", privHtml = (built && built["privacy.html"]) || FILES[PRIVACY] || "";
  const tv = textOf(termsHtml.slice(termsHtml.indexOf("<h3 id=\"verified\">"), termsHtml.indexOf("<h", termsHtml.indexOf("<h3 id=\"verified\">") + 5)));
  check("H4. the Terms: what it means and the three kinds", /The Verified badge/.test(tv) && /BizForce member, for a member while their paid membership is active/.test(tv) &&
    /Verified seller, for a seller BizForce has checked and verified/.test(tv) && /Official BizForce account, for BizForce's own accounts/.test(tv), tv.slice(0, 200));
  check("H5. ...how it is removed", /taken away the day it ends/.test(tv) && /removed when the account is banned, when BizForce removes the profile under these Terms, or when BizForce takes the verification away/.test(tv));
  check("H6. ...suggestions first now, and the placement factor from code stated as what will apply (no ranking uses it yet)",
    tv.indexOf("Once For You, Market and Local are ranked, a verified account's placement there will be raised by a factor of " + V.RANK_WEIGHT + ".") !== -1 && /shown first in suggestions/.test(tv) &&
    !/placement in For You, Market and Local is raised/.test(tv));
  check("H7. ...and that it is not an endorsement", tv.indexOf("This is not an endorsement. BizForce does not vouch for the account") !== -1);
  const pv = textOf(privHtml);
  check("H8. Privacy: what is kept for it and who sees it, and not an endorsement",
    pv.indexOf("To show the Verified badge: whether your account has one, which kind (BizForce member, Verified seller or Official BizForce account) and when it was given.") !== -1 &&
    pv.indexOf("Your Verified badge, if you have one, and its kind can be seen by anyone wherever your name shows. This is not an endorsement.") !== -1);
  check("H9. the built pages equal the frontend's (buildLegalPages was run)", ["terms.html", "privacy.html"].every(f => built[f].replace(/\r\n/g, "\n") === (FILES[f] || "")));
  const YDm = T.libRequire("./lib/yourData");
  const ydEntry = (YDm.TABLES || YDm.EXPORT_TABLES || []).find ? (YDm.TABLES || YDm.EXPORT_TABLES || []).find(x => x.table === "bf_profiles") : null;
  check("H10. Your data: the bf_profiles export names the Verified badge (verified_reason and verified_at come with every column)",
    /your Verified badge, if you have one/.test((ydEntry && ydEntry.what) || (FILES[YD] || "")) && /verified_reason/.test(FILES["@supabase/migrations/199_verified_badge.sql"] || require("fs").readFileSync(require("path").join(H.REPO, "supabase/migrations/199_verified_badge.sql"), "utf8")));
  const mig = require("fs").readFileSync(require("path").join(H.REPO, "supabase/migrations/199_verified_badge.sql"), "utf8");
  check("H11. migration 199 is what is live: the two columns, IF NOT EXISTS, the named CHECK, applied by hand Nov 21 2026",
    /ALTER TABLE public\.bf_profiles\s+ADD COLUMN IF NOT EXISTS verified_reason text\s+CONSTRAINT bf_profiles_verified_reason_allowed\s+CHECK \(verified_reason IS NULL OR verified_reason IN \('member', 'seller', 'official'\)\);/.test(mig) &&
    /ALTER TABLE public\.bf_profiles\s+ADD COLUMN IF NOT EXISTS verified_at timestamptz;/.test(mig) && /^-- APPLIED \(P3-2, recorded Nov 21 2026\): applied BY HAND by the owner on Nov 21 2026, and verified/.test(mig) && mig.indexOf("<=") === -1 && mig.indexOf(">=") === -1);
  finish();
})().catch(e => { console.log("    FAIL  the check threw: " + (e && e.stack || e)); process.exit(1); });
