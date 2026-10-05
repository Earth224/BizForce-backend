/* ══════════════════════════════════════════════════════════════════════════
   checkUnsubscribedSurface.js — what an account can reach without paying, and
   what anyone can reach without an account, recorded so a new route of that
   kind cannot arrive unreviewed.

   THE HOLE THIS RECORDS. No script walked the router asking which routes
   write, publish or spend without a subscription gate. checkEntitlementGate
   and checkRemainingSpendPaths prove the gate on NAMED model routes;
   checkOpenSurfaceClosed proves one route (POST /api/sms/send) stays shut.
   Nothing covered the class. A read of 2026-10-04 found POST /api/proposals
   and POST /api/proposals/:id/approve open to any signed-in account: together
   they publish a public blog post or an active marketplace listing, with no
   subscription and no model call.

   THIS RECORDS THE SURFACE. IT DOES NOT CHANGE IT. The owner's decision of
   2026-10-05 is what it records: PUBLISHING NEEDS A SUBSCRIPTION; PREPARING
   DOES NOT. Five routes moved behind requireActiveSubscription (a new
   listing, a card share link, a campaign and its edits, a BFC transfer);
   three gate part of what they do inside the handler (approve, by action
   type; a listing edit that is not a pause; the BFC credit on a
   certification); and the public pages — profile, seller page, cards — are
   served only while their OWNER is entitled, with the writes left open.
   Deletes, pauses, buying and messages stay open.

   HOW. server.js is booted in this process, as checkDormantRoutesDeleted does,
   and the REAL Express router is walked: every route and method, and the
   names of the middleware in front of its handler. A route is
     admin         requireAdmin is in its stack
     gated         requireActiveSubscription is in its stack
     login-only    requireAuth, and neither of the above
     unauthenticated   none of the three
   A handler's EFFECTS are read from the handler function the router holds
   (its own text), plus the server.js helpers it calls: a helper counts as
   writing if it, or anything it calls, runs insert / upsert / update /
   delete() / rpc, and as spending if it reaches callAnthropicText or a model
   client. A multer upload middleware or a storage .upload counts as storage.

   ⚠️ LIMITS, stated. Classification is by middleware NAME: a route that checks
   a subscription inside its handler reads as login-only, and an inline
   anonymous auth check reads as unauthenticated. Effects are found by text, so
   a write through a dynamic call (a function held in a variable or object)
   can be missed — PROPOSAL_EXECUTORS is matched by name for that reason. The
   EXPECTED lists are the review: a route is in them because a person read it.

   WHERE THE LINE IS DRAWN, for login-only routes that write:
     PUBLIC      writes something an UNAUTHENTICATED reader is served. The
                 public GET routes serve exactly these tables: profiles,
                 digital_cards (by share token), bf_profiles, profile_products,
                 profile_portfolio, bf_music_tracks, bf_videos, content_library
                 (status published), marketplace_listings. A route that writes
                 one of them is public, including an edit or a delete, because
                 it changes what a stranger sees.
     OTHERS      reaches another ACCOUNT, or value that moves between
                 accounts: a direct message, a crowdfunding campaign other
                 accounts can see and fund, BFC credited, transferred or spent,
                 a USD checkout paying a seller.
     THIRD_PARTY holds or acts on people who are not accounts: SMS
                 subscribers' phone numbers, campaigns and enrollments, and the
                 direct send (shut by SMS_DIRECT_SEND_ENABLED = false).
     STORAGE     puts a file in a Supabase storage bucket — real cost against
                 the plan's storage and egress caps, and bf-public is publicly
                 readable by URL.
     OWN         the account's own records, visible to it alone: settings,
                 sessions and passkeys, its CRM, inventory, calendar, memory,
                 drafts, documents, proposals it has not approved, billing.
   No login-only route may spend a model call; that list is empty and must stay
   empty.

   WHAT THIS PROVES
     1. Every route classifies, and the counts are printed.
     2. The subscription-gated set is exactly EXPECTED_GATED, and the admin set
        exactly EXPECTED_ADMIN — a route that loses its gate fails here.
     3. No login-only route reaches a model call.
     4. Every login-only route that writes, publishes, stores or reaches
        another person is in exactly one EXPECTED list; a new one fails until
        it is reviewed and added. A listed route that no longer exists, is no
        longer login-only, or no longer has any effect also fails, so the
        lists stay exact.
     5. Every unauthenticated route that writes is in EXPECTED_UNAUTH_WRITES,
        on the same terms.
     6. Each public page route is unauthenticated and its handler carries the
        owner check, and the check itself answers correctly for real accounts:
        the unentitled check account's page is not served, the entitled seed
        account's is, and the owner's is (admin exemption).
     7. Each in-handler gate is present, and a 402 keeps error and
        upgrade_required and adds message and billing_url.

   MUTATE=add-public   mounts POST /api/check-mutation/publish after boot,
                       behind requireAuth only, with a handler that inserts a
                       published content_library row. Section 4 must go red.
                       The handler is never called.
   MUTATE=ungate       removes requireActiveSubscription from the live stack of
                       POST /api/agents/seo/generate-post. Sections 2, 3 and 4
                       must go red — it loses its gate, it spends a model call,
                       and it becomes an unreviewed login-only writer.
   MUTATE=serve-open   removes the owner check from GET /api/bfp/seller/:handle
                       at compile time. Section 6 must go red.
   Section 6 reads two accounts' plans, so BIZFORCE_CHECK_USER_ID must be set.
   Starting server.js starts its intervals and crons as it always does; the run
   is over in seconds, nothing is requested over HTTP, and nothing here writes
   to the database.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const fs = require("fs");
const path = require("path");
const { braceMatch } = require("./_shared");
const { resolveSubjectAccount, resolveEntitledAccount, OWNER_ACCOUNT_ID } = require("./checkRunResidue");
const REPO = path.join(__dirname, "..");
const SERVER_PATH = path.join(REPO, "server.js");

const MUTATIONS = ["add-public", "ungate", "serve-open"];
const MUTATE = process.env.MUTATE || "";
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", "));
  process.exit(2);
}

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

/* ── the review: every entry was read by a person ──────────────────────── */
const EXPECTED_GATED = [
  "post /api/business-chat", "post /api/agents", "post /api/agents/store/generate-proposals",
  "post /api/agents/seo/generate-post", "post /api/ai/tasks", "post /api/assignments/:id/start",
  "post /api/oracle", "get /api/oracle/invocation", "post /api/oracle/chat", "post /api/insights/page",
  "post /api/seo/audit", "post /api/agents/seo/optimize", "post /api/agents/etsy/keyword-research",
  "post /api/agents/etsy/pricing-strategy", "post /api/agents/email/sequence", "post /api/agents/email/subject-lines",
  "post /api/agents/publicist/press-release", "post /api/agents/publicist/pitch", "post /api/agents/operations/sop",
  "post /api/agents/operations/checklist", "post /api/agents/ads/copy", "post /api/agents/ads/policy-check",
  "post /api/agents/reputation/review-response", "post /api/agents/reputation/review-request",
  "post /api/agents/social/post", "post /api/agents/social/calendar", "post /api/agents/broker/term-sheet",
  "post /api/agents/broker/due-diligence", "post /api/agents/rd/brief", "post /api/agents/rd/competitor-scan",
  "post /api/agents/community/onboarding", "post /api/agents/community/engagement-calendar",
  "post /api/agents/analytics/funnel", "post /api/agents/analytics/kpi-review", "post /api/agents/influencer/outreach",
  "post /api/agents/influencer/partnership-offer", "post /api/agents/vertical_marketing/positioning",
  "post /api/agents/vertical_marketing/objections", "post /api/agents/content/outline", "post /api/agents/content/audit",
  "post /api/assignments/dispatch", "post /api/agents/executive/plan", "get /api/dashboard", "post /api/self-reviews/run",
  "post /api/saved-prompts/:id/run", "post /api/routines/:id/run", "post /api/leads/draft-reply", "post /api/agents/sales/convert",
  // gated 2026-10-05, "Publishing needs a subscription; preparing does not"
  "post /api/marketplace/listings", "post /api/cards/share-token", "post /api/crowdfunding/campaigns",
  "put /api/crowdfunding/campaigns/:id", "post /api/wallet/transfer"
];

const EXPECTED_ADMIN = [
  "get /api/admin/flagged-accounts", "post /api/admin/ban/:userId", "post /api/admin/unban/:userId",
  "post /api/admin/verify/:userId", "post /api/admin/flag/:userId", "post /api/admin/store-proposals/run"
];

/* Login-only routes that write something a stranger is served. */
const EXPECTED_PUBLIC = {
  "post /api/proposals/:id/approve":        "publish_blog_post → public blog post; publish_listing / update_listing → public listing — those three need a subscription, checked in the handler; a calendar event does not",
  "put /api/marketplace/listings/:id":      "edits a public listing — needs a subscription, checked in the handler, except a pause",
  "delete /api/marketplace/listings/:id":   "removes a public listing",
  "put /api/profile/me":                    "profiles, served by GET /api/profile/:username only while the owner is entitled",
  "post /api/digital-cards":                "a card, served by GET /api/cards/share/:token",
  "put /api/digital-cards/:id":             "edits a shareable card",
  "delete /api/digital-cards/:id":          "removes a shareable card",
  "put /api/bfp/profile/me":                "bf_profiles: the public handle and seller page",
  "post /api/bfp/pproducts":                "profile_products, served publicly",
  "put /api/bfp/pproducts/:id":             "profile_products, served publicly",
  "delete /api/bfp/pproducts/:id":          "profile_products, served publicly",
  "post /api/bfp/pportfolio":               "profile_portfolio, served publicly",
  "put /api/bfp/pportfolio/:id":            "profile_portfolio, served publicly",
  "delete /api/bfp/pportfolio/:id":         "profile_portfolio, served publicly",
  "post /api/bfp/music":                    "bf_music_tracks, served publicly",
  "put /api/bfp/music/:id":                 "bf_music_tracks, served publicly",
  "delete /api/bfp/music/:id":              "bf_music_tracks, served publicly",
  "post /api/bfp/videos":                   "bf_videos, served publicly",
  "put /api/bfp/videos/:id":                "bf_videos, served publicly",
  "delete /api/bfp/videos/:id":             "bf_videos, served publicly"
};

/* Login-only routes that reach another account, or value between accounts. */
const EXPECTED_OTHERS = {
  "post /api/messages":                          "a direct message to another account",
  "post /api/crowdfunding/campaigns/:id/donate": "moves BFC to another account's campaign",
  "get /api/wallet":                             "reads the balance; creates a missing wallet at 0 BFC (the welcome bonus is granted on first subscription, not here)",
  "post /api/certifications/award":              "records a certification; its 100 BFC credit is paid only to an entitled account, checked in the handler",
  "post /api/marketplace/listings/:id/buy":      "spends BFC on another account's listing",
  "post /api/marketplace/listings/:id/checkout-usd": "a Stripe checkout paying another account's listing"
};

/* Login-only routes that hold or act on people who are not accounts. */
const EXPECTED_THIRD_PARTY = {
  "post /api/sms/send":                     "texts any number — shut: SMS_DIRECT_SEND_ENABLED = false, checkOpenSurfaceClosed",
  "post /api/sms/subscribers":              "stores a person's phone number",
  "post /api/sms/subscribers/bulk":         "stores many phone numbers",
  "post /api/sms/campaigns":                "a campaign addressed to subscribers",
  "post /api/sms/campaigns/:id/messages":   "a campaign's message steps",
  "post /api/sms/campaigns/:id/enroll":     "enrolls subscribers in a campaign",
  "post /api/sms/run-engine":               "advances the caller's enrollments; runDripEngine has DRY_RUN true and no Twilio call"
};

/* Login-only routes that put a file in storage. */
const EXPECTED_STORAGE = {
  "post /api/marketplace/upload-digital":           "a digital good, bf-digital-goods",
  "post /api/bfp/upload-url":                       "a signed URL the browser uploads to storage with",
  "post /api/bizbook/generate":                     "a book file and cover",
  "post /api/bizbook/books/:id/cover":              "a cover image",
  "post /api/bizbook/books/:id/generate-from-content": "a generated book file",
  "post /api/bizbook/books/create-from-content":    "a generated book file",
  "post /api/cover-wraps/:id/bg-image":             "a background image",
  "post /api/editor/image":                         "an editor image"
};

/* Login-only routes that write only the account's own records. */
const EXPECTED_OWN = [
  "post /api/auth/logout", "post /api/auth/resend-verification",
  "post /api/webauthn/register/start", "post /api/webauthn/register/finish", "delete /api/webauthn/credentials/:id",
  "put /api/user/api-key", "delete /api/user/api-key", "put /api/user/preferences",
  "post /api/crm/customers", "put /api/crm/customers/:id", "delete /api/crm/customers/:id", "post /api/crm/customers/:id/activities",
  "post /api/prospects", "put /api/prospects/:id", "delete /api/prospects/:id", "post /api/prospects/:id/convert",
  "post /api/icp-profiles", "put /api/icp-profiles/:id", "delete /api/icp-profiles/:id",
  "post /api/inventory/items", "put /api/inventory/items/:id", "delete /api/inventory/items/:id", "post /api/inventory/items/:id/movements",
  "get /api/agents", "put /api/agents/:id", "delete /api/agents/:id",
  "post /api/proposals",                  // a pending proposal is private; publishing it is approve's, which is gated by action type
  "post /api/proposals/calendar-event", "post /api/proposals/:id/reject",
  "post /api/business-profile", "put /api/business-profile",
  "post /api/ai-reports", "post /api/assignments/batch",
  "post /api/memory", "delete /api/memory/:id", "delete /api/ai/tasks", "delete /api/ai/tasks/:id",
  "post /api/oracle/sync",
  "post /api/calendar/events", "patch /api/calendar/events/:id", "delete /api/calendar/events/:id",
  "post /api/inner-iq/results", "delete /api/inner-iq/results/:id",
  "post /api/push/subscribe", "delete /api/push/subscribe", "post /api/push/test",
  "post /api/saved-prompts", "put /api/saved-prompts/:id", "delete /api/saved-prompts/:id",
  "post /api/routines", "put /api/routines/:id", "delete /api/routines/:id",
  "put /api/agent-autonomy", "put /api/agent-schedules", "delete /api/agent-schedules/:agent_type",
  "post /api/birth-records", "delete /api/birth-records/:id",
  "put /api/notifications/:id/read",
  "post /api/stripe/checkout", "post /api/billing/portal",
  "post /api/bizdoc/documents", "put /api/bizdoc/documents/:id", "post /api/bizdoc/documents/:id/sign", "delete /api/bizdoc/documents/:id",
  "post /api/bizbook/books/:id/cover-from-wrap", "put /api/bizbook/books/:id", "put /api/bizbook/books/:id/cover-design", "delete /api/bizbook/books/:id",
  "post /api/cover-wraps", "put /api/cover-wraps/:id", "delete /api/cover-wraps/:id",
  "post /api/social-drafts", "put /api/social-drafts/:id",
  "post /api/content-library", "post /api/content-library/empty", "delete /api/content-library/:id",
  "post /api/content-library/:id/external-published",
  "post /api/agents/sales/lead-status"   // refuses every account but the credential owner (checkLeadRadarOwnerGate)
];

/* Unauthenticated routes that write. */
const EXPECTED_UNAUTH_WRITES = {
  "post /api/webhook":                      "Stripe webhook, signature-verified (handleStripeEvent)",
  "post /api/webhooks/resend":              "Resend webhook, Svix-verified",
  "post /api/auth/register":                "creates an account",
  "post /api/auth/login":                   "a session",
  "post /api/auth/refresh":                 "rotates a session",
  "post /api/auth/password-reset":          "a reset token, emailed",
  "post /api/auth/password-reset/confirm":  "sets a password from a token",
  "post /api/auth/verify-email":            "marks an email verified from a token",
  "post /api/webauthn/login/start":         "a passkey challenge",
  "post /api/webauthn/login/finish":        "a session from a passkey",
  "post /api/contacts/capture":             "a contact and consent row from a public form",
  "post /api/capture":                      "a lead capture from a public form",
  "get /api/unsubscribe":                   "an unsubscribe, from a signed token",
  "post /api/unsubscribe":                  "an unsubscribe, from a signed token (RFC 8058)",
  "post /api/engine-visits":                "an arrival from a Lead Radar reply (migration 128)",
  "post /api/sms/inbound":                  "an inbound SMS reply (STOP / HELP)"
};

/* Login-only routes that gate PART of what they do inside the handler. The
   middleware cannot see these, so each handler must carry its gate's text. */
const EXPECTED_HANDLER_GATES = {
  "post /api/proposals/:id/approve":   'refuseUnlessSubscribed(req, res, "approve " + pending.action_type)',
  "put /api/marketplace/listings/:id": 'refuseUnlessSubscribed(req, res, "put /api/marketplace/listings/:id")',
  "post /api/certifications/award":    'creditWithheld = "subscription_required"'
};

/* Unauthenticated GET routes that serve an account's public page, and must
   serve it only while the OWNER is entitled. Writes to these pages stay open;
   this is where publishing is gated. */
const SERVE_GUARD = "if (!(await ownerPagePublic(";
const EXPECTED_SERVE_GATED = {
  "get /api/profile/:username":             SERVE_GUARD,
  "get /api/cards/share/:token":            SERVE_GUARD,
  "get /api/bfp/profile/:userId":           SERVE_GUARD,
  "get /api/bfp/pproducts/public/:userId":  SERVE_GUARD,
  "get /api/bfp/pportfolio/public/:userId": SERVE_GUARD,
  "get /api/bfp/music/public/:userId":      SERVE_GUARD,
  "get /api/bfp/videos/public/:userId":     SERVE_GUARD,
  "get /api/bfp/seller/:handle":            SERVE_GUARD,
  "get /api/bfp/services/browse":           "publicOwnersAmong(",
  "get /api/bfp/artists/browse":            "publicOwnersAmong("
};

/* ── MUTATE=serve-open: the seller page's guard removed at compile ──────── */
if (MUTATE === "serve-open") {
  const Module = require("module");
  const realCompile = Module.prototype._compile;
  const GUARD_LINE = '    if (!(await ownerPagePublic(seller.user_id))) return res.status(404).json({ error: "seller not found" });\n';
  Module.prototype._compile = function (content, filename) {
    if (path.resolve(filename) === path.resolve(SERVER_PATH)) {
      content = content.replace(/\r\n/g, "\n");
      const hits = content.split(GUARD_LINE).length - 1;
      if (hits !== 1) { console.error("MUTATION REFUSED: expected the seller page's guard exactly once, found " + hits); process.exit(1); }
      content = content.replace(GUARD_LINE, "");
      console.error("\n!! MUTATION: GET /api/bfp/seller/:handle serves every seller page, entitled or not — section 6 must fail.");
    }
    return realCompile.call(this, content, filename);
  };
}

/* ── what each helper in server.js does ─────────────────────────────────── */
const SRC = fs.readFileSync(SERVER_PATH, "utf8").replace(/\r\n/g, "\n");
const FNS = {};
{
  const re = /^(?:async\s+)?function\s+([A-Za-z0-9_]+)\s*\(/gm;
  let f;
  while ((f = re.exec(SRC))) { const o = SRC.indexOf("{", f.index); FNS[f[1]] = SRC.slice(o, braceMatch(SRC, o)); }
}
const callRe = function (name) { return new RegExp("\\b" + name + "\\s*\\("); };
function reaching(seed) {
  const set = new Set(Object.keys(FNS).filter(function (n) { return seed.test(FNS[n]); }));
  let grew = true;
  while (grew) {
    grew = false;
    Object.keys(FNS).forEach(function (n) {
      if (set.has(n)) return;
      for (const s of set) { if (callRe(s).test(FNS[n])) { set.add(n); grew = true; break; } }
    });
  }
  return set;
}
const WRITES = /\.(insert|upsert|update|rpc)\(|\.delete\(\)/;
const WRITE_FNS = reaching(WRITES);
const MODEL_FNS = reaching(/callAnthropicText\s*\(|\.messages\.create\(\s*\{\s*model/);

function effectsOf(names, handlerText) {
  const fx = [];
  if (WRITES.test(handlerText) || [...WRITE_FNS].some(function (s) { return callRe(s).test(handlerText); })) fx.push("writes");
  if (/PROPOSAL_EXECUTORS\[/.test(handlerText)) fx.push("executors");
  if (/status:\s*"(published|active)"/.test(handlerText)) fx.push("publishes");
  if (/\.upload\(|createSignedUploadUrl\(/.test(handlerText) || names.some(function (n) { return /multer/i.test(n); })) fx.push("storage");
  if (/stripe\w*\.(checkout|customers|subscriptions|billingPortal|paymentIntents)/.test(handlerText)) fx.push("stripe");
  if (/messages\.create\(|sendEmail\(|sendBlueskyReply|sendMastodonReply|sendPushToUser\(/.test(handlerText)) fx.push("sends");
  if (/callAnthropicText\s*\(/.test(handlerText) || [...MODEL_FNS].some(function (s) { return callRe(s).test(handlerText); })) fx.push("MODEL");
  return fx;
}

/* ── boot the real server, capturing the app ────────────────────────────── */
const EXPRESS_PATH = require.resolve("express", { paths: [REPO] });
const realExpress = require(EXPRESS_PATH);
let app = null;
const expressWrapper = function () { const made = realExpress.apply(this, arguments); if (!app) app = made; return made; };
Object.keys(realExpress).forEach(function (k) { expressWrapper[k] = realExpress[k]; });
require.cache[EXPRESS_PATH].exports = expressWrapper;
process.env.PORT = process.env.CHECK_PORT || "0";
const quiet = { log: console.log, warn: console.warn };
console.log = function () {}; console.warn = function () {};   // the server's own boot logging
require(SERVER_PATH);
console.log = quiet.log; console.warn = quiet.warn;

function layerFor(method, routePath) {
  return app._router.stack.filter(function (l) { return l.route && l.route.path === routePath && l.route.methods[method]; })[0];
}

if (MUTATE === "add-public") {
  const requireAuthFn = layerFor("post", "/api/proposals").route.stack[0].handle;
  app.post("/api/check-mutation/publish", requireAuthFn, async function (req, res) {
    await require("@supabase/supabase-js").createClient("x", "x").from("content_library")
      .insert({ user_id: req.user.id, status: "published", title: "never called" });
    res.json({ ok: true });
  });
  const added = app._router.stack.pop();
  let lastRouteIdx = -1;
  app._router.stack.forEach(function (l, i) { if (l.route) lastRouteIdx = i; });
  app._router.stack.splice(lastRouteIdx + 1, 0, added);
  console.log("\n!! MUTATION: POST /api/check-mutation/publish is mounted behind requireAuth only and inserts a published post — section 4 must fail.");
}
if (MUTATE === "ungate") {
  const layer = layerFor("post", "/api/agents/seo/generate-post");
  const before = layer.route.stack.length;
  layer.route.stack = layer.route.stack.filter(function (s) { return s.handle.name !== "requireActiveSubscription"; });
  console.log("\n!! MUTATION: requireActiveSubscription removed from POST /api/agents/seo/generate-post (" + before + " → " +
    layer.route.stack.length + " handlers) — sections 2, 3 and 4 must fail.");
}

/* ── walk it ────────────────────────────────────────────────────────────── */
const ROUTES = [];
app._router.stack.forEach(function (l) {
  if (!l.route) return;
  Object.keys(l.route.methods).forEach(function (method) {
    const names = l.route.stack.map(function (s) { return s.handle.name || "<anonymous>"; });
    const handler = l.route.stack[l.route.stack.length - 1].handle.toString();
    const cls = names.indexOf("requireAdmin") !== -1 ? "admin"
      : names.indexOf("requireActiveSubscription") !== -1 ? "gated"
      : names.indexOf("requireAuth") !== -1 ? "login-only" : "unauthenticated";
    ROUTES.push({ key: method + " " + l.route.path, cls: cls, fx: effectsOf(names, handler), text: handler });
  });
});
const of = function (cls) { return ROUTES.filter(function (r) { return r.cls === cls; }); };
const keys = function (rs) { return rs.map(function (r) { return r.key; }); };
function sameSet(label, actual, expected) {
  const a = new Set(actual), e = new Set(expected);
  const extra = actual.filter(function (k) { return !e.has(k); });
  const missing = expected.filter(function (k) { return !a.has(k); });
  check(label, extra.length === 0 && missing.length === 0,
    (extra.length ? "new: " + extra.join(", ") : "") + (extra.length && missing.length ? " | " : "") + (missing.length ? "gone: " + missing.join(", ") : ""));
}

console.log("\n══ 1. every route, classified from the live router ══");
["unauthenticated", "login-only", "gated", "admin"].forEach(function (c) { console.log("    " + c.padEnd(16) + of(c).length); });
console.log("    " + "total".padEnd(16) + ROUTES.length);
check("1. every route has exactly one class", ROUTES.every(function (r) { return !!r.cls; }), ROUTES.length);

console.log("\n══ 2. the gated and admin sets ══");
sameSet("2. the subscription-gated routes are exactly the " + EXPECTED_GATED.length + " reviewed", keys(of("gated")), EXPECTED_GATED);
sameSet("2. the admin routes are exactly the " + EXPECTED_ADMIN.length + " reviewed", keys(of("admin")), EXPECTED_ADMIN);

console.log("\n══ 3. no login-only route spends a model call ══");
const spenders = of("login-only").filter(function (r) { return r.fx.indexOf("MODEL") !== -1; });
check("3. no login-only route reaches callAnthropicText or a model client", spenders.length === 0, keys(spenders).join(", "));

console.log("\n══ 4. every login-only route with an effect, reviewed ══");
const LISTS = {
  PUBLIC: Object.keys(EXPECTED_PUBLIC), OTHERS: Object.keys(EXPECTED_OTHERS), THIRD_PARTY: Object.keys(EXPECTED_THIRD_PARTY),
  STORAGE: Object.keys(EXPECTED_STORAGE), OWN: EXPECTED_OWN
};
const listed = {};
let doubled = [];
Object.keys(LISTS).forEach(function (name) {
  LISTS[name].forEach(function (k) { if (listed[k]) doubled.push(k + " (" + listed[k] + " and " + name + ")"); listed[k] = name; });
});
check("4. no route is in two lists", doubled.length === 0, doubled.join(", "));
const effectful = of("login-only").filter(function (r) { return r.fx.length; });
const unreviewed = effectful.filter(function (r) { return !listed[r.key]; });
check("4. every login-only route that writes, publishes, stores or sends is reviewed (" + effectful.length + ")",
  unreviewed.length === 0, unreviewed.map(function (r) { return r.key + " {" + r.fx.join(",") + "}"; }).join(", "));
const byKey = {};
ROUTES.forEach(function (r) { byKey[r.key] = r; });
const stale = Object.keys(listed).filter(function (k) { const r = byKey[k]; return !r || r.cls !== "login-only" || !r.fx.length; });
check("4. every reviewed route still exists, is still login-only, and still has an effect", stale.length === 0,
  stale.map(function (k) { const r = byKey[k]; return k + (r ? " (" + r.cls + (r.fx.length ? "" : ", no effect") + ")" : " (not mounted)"); }).join(", "));
Object.keys(LISTS).forEach(function (name) { console.log("    " + name.padEnd(12) + LISTS[name].length); });
console.log("    reaches the public: " + Object.keys(EXPECTED_PUBLIC).length + " routes; reaches another account: " +
  Object.keys(EXPECTED_OTHERS).length + "; third parties: " + Object.keys(EXPECTED_THIRD_PARTY).length);

console.log("\n══ 5. every unauthenticated route that writes, reviewed ══");
const unauthWriters = of("unauthenticated").filter(function (r) { return r.fx.length; });
sameSet("5. the unauthenticated routes that write are exactly the " + Object.keys(EXPECTED_UNAUTH_WRITES).length + " reviewed",
  keys(unauthWriters), Object.keys(EXPECTED_UNAUTH_WRITES));
const unauthSpend = unauthWriters.concat(of("unauthenticated")).filter(function (r) { return r.fx.indexOf("MODEL") !== -1; });
check("5. no unauthenticated route reaches a model call", unauthSpend.length === 0, keys(unauthSpend).join(", "));

(async function finish() {
  console.log("\n══ 6. public pages are served only while their owner is entitled ══");
  Object.keys(EXPECTED_SERVE_GATED).forEach(function (k) {
    const r = byKey[k];
    check("6. " + k + " is unauthenticated and its handler carries the owner check",
      !!r && r.cls === "unauthenticated" && r.text.indexOf(EXPECTED_SERVE_GATED[k]) !== -1,
      r ? r.cls + (r.text.indexOf(EXPECTED_SERVE_GATED[k]) === -1 ? ", no owner check" : "") : "not mounted");
  });
  /* The helper itself, against real accounts: whose page a stranger may see. */
  const subject = resolveSubjectAccount();
  const { createClient } = require("@supabase/supabase-js");
  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);
  const seed = await resolveEntitledAccount(supabase);
  const server = require(SERVER_PATH);
  const quietLog = console.log; console.log = function () {};
  const subjectPublic = await server.__ownerPagePublic(subject);
  const seedPublic = await server.__ownerPagePublic(seed.id);
  const ownerPublic = await server.__ownerPagePublic(OWNER_ACCOUNT_ID);
  console.log = quietLog;
  check("6. an unentitled account's page is not served (" + subject + ")", subjectPublic === false, String(subjectPublic));
  check("6. an entitled account's page is served (" + seed.email + ")", seedPublic === true, String(seedPublic));
  check("6. the owner's page is served (admin exemption)", ownerPublic === true, String(ownerPublic));

  console.log("\n══ 7. the gates inside handlers, and what a refusal says ══");
  Object.keys(EXPECTED_HANDLER_GATES).forEach(function (k) {
    const r = byKey[k];
    check("7. " + k + " is login-only and gates in its handler",
      !!r && r.cls === "login-only" && r.text.indexOf(EXPECTED_HANDLER_GATES[k]) !== -1,
      r ? r.cls + (r.text.indexOf(EXPECTED_HANDLER_GATES[k]) === -1 ? ", gate text missing" : "") : "not mounted");
  });
  const refusal = server.__subscriptionRequiredBody({ inactive_reason: "no_subscription" }, "post /api/marketplace/listings");
  check("7. a 402 keeps error and upgrade_required, and adds message and billing_url",
    refusal.error === "Active subscription required" && refusal.upgrade_required === true &&
    /Nothing was published/.test(refusal.message || "") && refusal.billing_url === "/billing.html", JSON.stringify(refusal));
  const fallback = server.__subscriptionRequiredBody({ inactive_reason: "no_subscription" }, "post /api/ai/tasks");
  check("7. a route with no message of its own says nothing ran and nothing was charged",
    /Nothing was run and nothing was charged/.test(fallback.message || ""), fallback.message);

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : "")); process.exit(1); }
  console.log("ALL CHECKS PASSED" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
