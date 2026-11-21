/* ═══════════════════════════════════════════════════════════════════════════
   checkInstantUse.js — a new account is used at once (P3-1, Nov 20 2026).

   NAMED (Nov 20 2026, P3-1): BEFORE H5 held every post from an account younger
   than the BizCash hold (7 days), or of unknown age, as pending with a
   moderation queue item (source new_member). AFTER there is no posting hold;
   the 7-day hold on SENDING BizCash stays.

   WHAT IT PROVES
     A. POSTING, on the real lib/posts.js over an in-memory database: an
        account opened a minute ago posts and is published at once (201, held
        false, no queue item); an account whose age cannot be read posts too;
        the account's age is never read to make a post.
     B. NOTHING ELSE HOLDS A NEW ACCOUNT: lib/posts.js has no hold left (no
        holdDays, no new_member queue item); a new listing, a message and a
        follow never read the account's age.
     C. THE BIZCASH HOLD STAYS: 7 days by default (lib/bfcTransferLimits.js);
        the transfer and support path and a donation each read users.created_at
        and refuse (403 new_account_hold) before anything moves, with an age
        that cannot be read held too; the database is handed the hold
        (p_hold_days) as well.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");
const { memDb } = require("./_p23Db");

const SERVER = "@server.js", POSTS = "@lib/posts.js", LIMITS = "@lib/bfcTransferLimits.js";
const MUTATIONS = {
  // H5 back: a post from an account younger than 7 days is held for review
  "posting-hold-back": [[POSTS, "  var place = await placeFor(deps.sb, userId);\n",
    "  var age0 = await deps.sb.from(\"users\").select(\"id, created_at\").eq(\"id\", userId).maybeSingle();\n" +
    "  if (!age0.data || !age0.data.created_at || Date.parse(now(deps)) - Date.parse(age0.data.created_at) < 7 * DAY) findings = findings || [];\n" +
    "  var place = await placeFor(deps.sb, userId);\n"]],
  // the BizCash send hold dropped
  "send-hold-gone": [[LIMITS, "var BFC_TRANSFER_HOLD_DAYS_DEFAULT = 7;", "var BFC_TRANSFER_HOLD_DAYS_DEFAULT = 0;"]],
  // the transfer path stops asking the hold
  "transfer-hold-skipped": [[SERVER, "    const sender = await supabase.from(\"users\").select(\"id, created_at\").eq(\"id\", req.user.id).maybeSingle();\n    if (sender.error) throw sender.error;\n    const openedMs = sender.data ? Date.parse(sender.data.created_at) : NaN;\n    const sendableFromMs = openedMs + limits.holdDays * 24 * 60 * 60 * 1000;\n    // NaN",
    "    const sender = await supabase.from(\"users\").select(\"id, created_at\").eq(\"id\", req.user.id).maybeSingle();\n    if (sender.error) throw sender.error;\n    const openedMs = 0;\n    const sendableFromMs = openedMs + limits.holdDays * 24 * 60 * 60 * 1000;\n    // NaN"]],
  // a listing hold for new accounts
  "listing-hold": [[SERVER, 'app.post("/api/marketplace/listings", requireAuth, requireVerifiedEmail, async function (req, res, next) {\n  try {\n',
    'app.post("/api/marketplace/listings", requireAuth, requireVerifiedEmail, async function (req, res, next) {\n  try {\n    if (Date.now() - Date.parse(req.user.created_at) < 7 * 864e5) return res.status(403).json({ reason: "new_account_hold" });\n']]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, POSTS, LIMITS, "@lib/postMedia.js"]);
const { FILES, check, finish, J, has } = T;
const P = T.libRequire("./lib/posts");
const S = FILES[SERVER] || "";

const NEW = "44444444-4444-4444-8444-444444444444", AGELESS = "55555555-5555-4555-8555-555555555555";
const NOW0 = "2026-11-20T12:00:00.000Z";

function world() {
  const users = [{ id: NEW, created_at: "2026-11-20T11:59:00.000Z", email_verified_at: "2026-11-20T11:59:30.000Z" }, { id: AGELESS, created_at: null, email_verified_at: "2026-11-01T00:00:00.000Z" }];
  const db = memDb({ users, posts: [], post_media: [], post_comments: [], post_likes: [], post_saves: [], post_share_days: [], notifications: [], moderation_queue: [],
    follows: [], member_blocks: [], member_mutes: [], member_media: [], profiles: [],
    bf_profiles: [NEW, AGELESS].map((id, i) => ({ user_id: id, username: "u" + i, display_name: "U" + i, avatar_url: null, updated_at: NOW0, place_city: null, place_region: null, place_country: null, local_opt_in: false })) });
  const reads = [];
  const realFrom = db.client.from.bind(db.client);
  const client = Object.assign({}, db.client, {
    from(table) { const b = realFrom(table); const sel = b.select; b.select = function (cols) { reads.push([table, cols]); return sel.apply(b, arguments); }; return b; }
  });
  const deps = { sb: client, now: () => NOW0, claims: () => null, ownerPublic: async () => true, push: async () => {}, env: {} };
  return { db, deps, reads };
}
function fnText(src, sig) {
  const at = src.indexOf(sig);
  return at < 0 ? "" : src.slice(at, require("./_shared").braceMatch(src, src.indexOf("{", at)) + 1);
}

(async function main() {
  console.log("\n══ A. posting is instant ══");
  let w = world();
  let r = await P.createPost(w.deps, NEW, { body: "Opened my shop a minute ago." });
  const p1 = w.db.t.posts.find(p => p.author_id === NEW);
  check("A1. an account opened a minute ago: 201, published at once, held false", r.status === 201 && r.body.held === false && p1 && p1.status === "published" && p1.published_at === NOW0, J([r.status, r.body && r.body.held, p1 && p1.status]));
  check("A2. ...no moderation queue item, and none with source new_member", w.db.t.moderation_queue.length === 0, J(w.db.t.moderation_queue));
  check("A3. ...the account's age is never read to make a post", !w.reads.some(([t, c]) => t === "users" && /created_at/.test(String(c))), J(w.reads.filter(x => x[0] === "users")));
  r = await P.createPost(w.deps, AGELESS, { body: "Age unknown, still posting." });
  const p2 = w.db.t.posts.find(p => p.author_id === AGELESS);
  check("A4. an account whose age cannot be read posts and is published too", r.status === 201 && p2 && p2.status === "published", J([r.status, r.body]));

  console.log("\n══ B. nothing else holds a new account ══");
  const PS = FILES[POSTS] || "";
  check("B1. lib/posts.js has no posting hold left: no holdDays, no new_member queue item", !/function holdDays|holdDays\(deps\)/.test(PS) && !has(PS, "source: \"new_member\"") && has(PS, "status: findings ? \"pending\" : \"published\""));
  const AGE = /created_at\)|holdDays|new_account_hold|\.created_at/;
  [["post", "/api/marketplace/listings", "a new listing"], ["post", "/api/messages", "a message"], ["post", "/api/posts", "a post"]].forEach(([m, p, label], i) => {
    const st = H.routeStatement(S, m, p) || "";
    check("B" + (i + 2) + ". " + label + " (" + m.toUpperCase() + " " + p + ") never reads the account's age", st.length > 0 && !AGE.test(st), st.length);
  });
  const followFn = fnText(PS, "async function follow(");
  check("B5. following (POST /api/follows, lib/posts.js follow) never reads the account's age", has(S, 'app.post("/api/follows", requireAuth, postRoute(') && followFn.length > 0 && !AGE.test(followFn), followFn.length);

  console.log("\n══ C. the BizCash send hold stays ══");
  const L = T.libRequire("./lib/bfcTransferLimits");
  const lim = L.bfcTransferLimits({});
  check("C1. 7 days by default", lim.holdDays === 7 && L.BFC_TRANSFER_HOLD_DAYS_DEFAULT === 7, J(lim));
  const steps = fnText(S, "async function bfcSendWithinLimitsSteps(req, res, send) {");
  const donate = H.routeStatement(S, "post", "/api/crowdfunding/campaigns/:id/donate") || "";
  const HOLD = ["select(\"id, created_at\").eq(\"id\", req.user.id)", "const openedMs = ", ".data ? Date.parse(", ".data.created_at) : NaN;",   // sender in the transfer path, donor in a donation
    "if (!(Date.now() >= sendableFromMs)) {", "reason: \"new_account_hold\""];
  const holds = (t, before) => HOLD.every(x => has(t, x)) && t.indexOf("new_account_hold") < t.indexOf(before);
  check("C2. transfer and support: the sender's age is read and a young or unreadable one is 403 new_account_hold before anything moves", holds(steps, "supabase.rpc(\"bfc_send\""), steps.length);
  check("C3. a donation: the same hold, before anything moves", holds(donate, "supabase.rpc(\"bfc_donate\""), donate.length);
  check("C4. the database is handed the hold as well (p_hold_days)", has(steps, "p_hold_days: limits.holdDays") && has(donate, "p_hold_days: limits.holdDays"));
  finish();
})().catch(e => { console.log("    FAIL  the check threw: " + (e && e.stack || e)); process.exit(1); });
