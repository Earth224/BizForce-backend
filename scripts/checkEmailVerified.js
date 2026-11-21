/* ═══════════════════════════════════════════════════════════════════════════
   checkEmailVerified.js — a confirmed email before the four public acts
   (P3-1, Nov 20 2026; lib/emailVerification.js).

   WHAT IT PROVES
     A. THE LIBRARY: the four acts (post publicly, list in the Market, message
        a non-follower, receive BizCash); the refusal is 403-shaped with reason
        email_unverified, what was blocked, and POST /api/auth/resend-verification;
        the recipient refusal says nothing was sent; verifiedById reads the
        users row fresh, a missing row is not verified, a read error throws.
     B. requireVerifiedEmail (server.js, lifted): a confirmed account goes on;
        an unconfirmed one is 403 with the resend link and the route it hit.
     C. LISTING: POST /api/marketplace/listings is requireAuth then
        requireVerifiedEmail and nothing more (selling is free). PUT, lifted:
        an unconfirmed seller's edit is 403 and nothing is written; a pause
        still goes through.
     D. MESSAGING, lifted: an unconfirmed sender may answer someone who follows
        them; a message to a non-follower is 403 email_unverified and nothing
        is written; a confirmed sender messages anyone.
     E. RECEIVING BIZCASH: the transfer and support path (bfcSendWithinLimits),
        a Market purchase (for the seller) and a donation (for the campaign's
        owner) each refuse an unconfirmed recipient (409
        recipient_email_unverified) BEFORE anything moves: before the daily cap
        is read, before bfc_buy_listing runs.
     F. POSTING: lib/posts.js refuses a public post from an unconfirmed author
        and lets a followers post through (checkPosts B7 runs it); the resend
        route stays sign-in only; /api/auth/me says email_verified.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");

const SERVER = "@server.js", EV = "@lib/emailVerification.js", POSTS = "@lib/posts.js";
const MUTATIONS = {
  "middleware-waves": [[SERVER, "  if (EV.isVerified(req.user)) return next();\n", "  return next();\n"]],
  "verified-any-truthy-row": [[EV, "  return !!(r.data && r.data.id === userId && r.data.email_verified_at);", "  return !!r.data;"]],
  "listing-unguarded": [[SERVER, 'app.post("/api/marketplace/listings", requireAuth, requireVerifiedEmail, async', 'app.post("/api/marketplace/listings", requireAuth, async']],
  "edit-unguarded": [[SERVER, "    if (!pauseOnly && !require(\"./lib/emailVerification\").isVerified(req.user)) {", "    if (false) {"]],
  "message-anyone": [[SERVER, "      if (!followsSender.data) {\n        return res.status(403).json(require(\"./lib/emailVerification\").unverifiedBody(\"message_non_follower\"));", "      if (false) {\n        return res.status(403).json(require(\"./lib/emailVerification\").unverifiedBody(\"message_non_follower\"));"]],
  "transfer-to-unverified": [[SERVER, "    if (!(await require(\"./lib/emailVerification\").verifiedById(supabase, recipient.id))) {", "    if (false) {"]],
  "sale-to-unverified": [[SERVER, "      if (!(await require(\"./lib/emailVerification\").verifiedById(supabase, priced.seller_id))) {", "      if (false) {"]],
  "donation-to-unverified": [[SERVER, "    if (!(await require(\"./lib/emailVerification\").verifiedById(supabase, campaign.owner_id))) {", "    if (false) {"]],
  "no-resend-link": [[EV, "resend_url: RESEND_URL, resend_method: \"POST\" };", "resend_method: \"POST\" };"]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, EV, POSTS]);
const { FILES, check, finish, J, has } = T;
const S = FILES[SERVER] || "";
const E = T.libRequire("./lib/emailVerification");
const ME = "11111111-1111-4111-8111-111111111111", OTHER = "22222222-2222-4222-8222-222222222222";
const VERIFIED = { id: ME, email_verified_at: "2026-10-01T10:00:00.000Z" }, UNVERIFIED = { id: ME, email_verified_at: null };

function fnText(src, sig) {
  const at = src.indexOf(sig);
  if (at < 0) return "";
  return src.slice(at, require("./_shared").braceMatch(src, src.indexOf("{", at)) + 1);
}

(async () => {
  console.log("\n══ A. the library ══");
  check("A1. the four acts", J(E.REQUIRED_FOR) === J(["post_public", "list_market", "message_non_follower", "receive_bizcash"]), J(E.REQUIRED_FOR));
  const b = E.unverifiedBody("list_market");
  check("A2. the refusal: reason email_unverified, what was blocked, the resend route by POST, and that nothing was saved",
    b.reason === "email_unverified" && b.blocked === "list_market" && b.resend_url === "/api/auth/resend-verification" && b.resend_method === "POST" &&
    /nothing was saved/.test(b.error) && /Resend email/.test(b.error), J(b));
  const rb = E.recipientUnverifiedBody("receive_bizcash");
  check("A3. the recipient refusal: recipient_email_unverified, nothing sent, the balance unchanged", rb.reason === "recipient_email_unverified" && /Nothing was sent/.test(rb.error) && /balance is unchanged/.test(rb.error), J(rb));
  check("A4. isVerified reads email_verified_at only", E.isVerified(VERIFIED) === true && E.isVerified(UNVERIFIED) === false && E.isVerified(null) === false);
  const row = r => H.fakeDb(() => r).client;
  check("A5. verifiedById: a confirmed row is true; an unconfirmed, a missing or another account's row is false",
    (await E.verifiedById(row({ data: { id: OTHER, email_verified_at: "x" }, error: null }), OTHER)) === true &&
    (await E.verifiedById(row({ data: { id: OTHER, email_verified_at: null }, error: null }), OTHER)) === false &&
    (await E.verifiedById(row({ data: null, error: null }), OTHER)) === false &&
    (await E.verifiedById(row({ data: { id: "someone-else", email_verified_at: "x" }, error: null }), OTHER)) === false);
  let threw = false;
  try { await E.verifiedById(row({ data: null, error: { message: "down" } }), OTHER); } catch (e) { threw = true; }
  check("A6. verifiedById: a read error throws (the caller refuses, never a guess)", threw);

  console.log("\n══ B. requireVerifiedEmail ══");
  const mwText = fnText(S, "function requireVerifiedEmail(req, res, next) {");
  const mw = new Function("require", mwText + "\nreturn requireVerifiedEmail;")(T.libRequire);
  const res = () => ({ code: 200, body: null, status(c) { this.code = c; return this; }, json(x) { this.body = x; return this; } });
  let nexted = false, r1 = res();
  mw({ user: VERIFIED, method: "POST", route: { path: "/api/marketplace/listings" } }, r1, () => { nexted = true; });
  check("B1. a confirmed account goes on", nexted && r1.body === null);
  nexted = false; const r2 = res();
  mw({ user: UNVERIFIED, method: "POST", route: { path: "/api/marketplace/listings" } }, r2, () => { nexted = true; });
  check("B2. an unconfirmed one is 403 email_unverified with the resend link and the route it hit",
    !nexted && r2.code === 403 && r2.body && r2.body.reason === "email_unverified" && r2.body.resend_url === E.RESEND_URL && r2.body.blocked === "post /api/marketplace/listings", J([r2.code, r2.body]));

  console.log("\n══ C. listing ══");
  check("C1. a new listing: requireAuth, requireVerifiedEmail, nothing more (selling is free)", has(S, 'app.post("/api/marketplace/listings", requireAuth, requireVerifiedEmail, async function (req, res, next) {'));
  const listDb = () => H.fakeDb((table, q) => {
    if (table === "marketplace_listings" && q.op === "update") return { data: Object.assign({ id: "L1", seller_id: ME }, q.payload), error: null };
    if (table === "marketplace_listings") return { data: { id: "L1", seller_id: ME, status: "active" }, error: null };
    return { data: null, error: null };
  });
  const put = (db, user, body) => {
    // refuseUnlessSubscribed is named only in the NAMED comment (the BEFORE); a stub keeps the plan machinery out of the vm
    const fn = H.route(S, "put", "/api/marketplace/listings/:id", { supabase: db.client, refuseUnlessSubscribed: () => false, safeText: (v, n) => (v == null ? "" : String(v).slice(0, n)) }, T.libRequire);
    return fn ? fn({ user, params: { id: "L1" }, body }) : Promise.resolve({ status: "no route" });
  };
  let d = listDb(), r = await put(d, UNVERIFIED, { title: "New title" });
  check("C2. an unconfirmed seller's edit is 403 email_unverified (list_market), and nothing is read or written", r.status === 403 && r.body && r.body.reason === "email_unverified" && r.body.blocked === "list_market" && d.log.length === 0, J([r.status, r.body, d.log.length]));
  d = listDb(); r = await put(d, UNVERIFIED, { status: "paused" });
  check("C3. ...a pause still goes through", r.status !== 403 && d.log.some(q => q.op === "update"), J([r.status, r.body]));

  console.log("\n══ D. messaging ══");
  const msgDb = followed => H.fakeDb((table, q) => {
    if (table === "users") return { data: H.filterVal(q, "eq", "id") === OTHER ? { id: OTHER } : null, error: null };
    if (table === "follows") return { data: followed ? { follower_id: OTHER } : null, error: null };
    if (table === "messages" && q.op === "insert") return { data: Object.assign({ id: "m-9" }, q.payload), error: null };
    return { data: null, error: null };
  });
  const send = (db, user) => {
    const fn = H.route(S, "post", "/api/messages", { supabase: db.client, safeText: (v, n) => (v == null ? "" : String(v).slice(0, n)) }, T.libRequire);
    return fn ? fn({ user, body: { receiver_id: OTHER, content: "hello" } }) : Promise.resolve({ status: "no route" });
  };
  const wrote = db => db.log.some(q => q.table === "messages" && q.op === "insert");
  d = msgDb(true); r = await send(d, UNVERIFIED);
  check("D1. an unconfirmed sender answers someone who follows them (201)", r.status === 201 && wrote(d), J([r.status, r.body]));
  d = msgDb(false); r = await send(d, UNVERIFIED);
  const fq = d.log.find(q => q.table === "follows") || { filters: [] };
  check("D2. a message to a non-follower is 403 email_unverified, and nothing is written", r.status === 403 && r.body && r.body.blocked === "message_non_follower" && !wrote(d), J([r.status, r.body]));
  check("D3. ...the follow asked is theirs of the sender", H.filterVal(fq, "eq", "follower_id") === OTHER && H.filterVal(fq, "eq", "following_id") === ME, J(fq.filters));
  d = msgDb(false); r = await send(d, VERIFIED);
  check("D4. a confirmed sender messages anyone, and the follow is not even asked", r.status === 201 && wrote(d) && !d.log.some(q => q.table === "follows"), J([r.status, r.body]));

  console.log("\n══ E. receiving BizCash ══");
  const order = (text, gate, after, label) => {
    const g = text.indexOf(gate), a = text.indexOf(after, g + 1);
    check(label, g !== -1 && a !== -1 && has(text.slice(g, g + 400), "recipientUnverifiedBody(\"receive_bizcash\")"), g + " " + a);
  };
  const sendCore = fnText(S, "async function bfcSendWithinLimitsSteps(req, res, send) {");   // bfcSendWithinLimits wraps it (gate decisions)
  order(sendCore, "verifiedById(supabase, recipient.id)", "bfcSentLast24h(req.user.id)", "E1. transfer and support (bfcSendWithinLimitsSteps): an unconfirmed recipient is refused before the daily cap is read and anything moves");
  check("E2. ...both the transfer and the support route send through it", has(H.routeStatement(S, "post", "/api/wallet/transfer"), "bfcSendWithinLimits(") && has(H.routeStatement(S, "post", "/api/wallet/support"), "bfcSendWithinLimits("));
  order(H.routeStatement(S, "post", "/api/marketplace/listings/:id/buy") || "", "verifiedById(supabase, priced.seller_id)", "supabase.rpc(\"bfc_buy_listing\"", "E3. a Market purchase: an unconfirmed seller is refused before bfc_buy_listing runs");
  order(H.routeStatement(S, "post", "/api/crowdfunding/campaigns/:id/donate") || "", "verifiedById(supabase, campaign.owner_id)", "bfcSentLast24h(req.user.id)", "E4. a donation: an unconfirmed campaign owner is refused before anything moves");
  check("E5. sending stays members only: transfer, support, donate and buy carry requireActiveSubscription",
    ["/api/wallet/transfer", "/api/wallet/support", "/api/crowdfunding/campaigns/:id/donate"].every(p => has(S, 'app.post("' + p + '", requireAuth, requireActiveSubscription,')) &&
    require("../lib/routeAccess").groupOf("post /api/marketplace/listings/:id/buy") === "M");

  console.log("\n══ F. posting, resending, and what the app is told ══");
  const P = FILES[POSTS] || "";
  check("F1. lib/posts.js refuses a public post from an unconfirmed author with the same body", has(P, "authorVerified(deps, userId)") && has(P, "unverifiedBody(\"post_public\")"));
  check("F2. the resend route is sign-in only, rate limited", has(S, 'app.post("/api/auth/resend-verification", requireAuth, verificationResendLimiter, async function'));
  check("F3. /api/auth/me says email_verified", has(S, "email_verified: !!req.user.email_verified_at"));
  finish();
})().catch(e => { console.log("    FAIL  the check threw: " + (e && e.stack || e)); process.exit(1); });
