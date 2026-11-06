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

   WARNING: LIMITS, stated. Classification is by middleware NAME: a route that checks
   a subscription inside its handler reads as login-only, and an inline
   anonymous auth check reads as unauthenticated. Effects are found by text, so
   a write through a dynamic call (a function held in a variable or object)
   can be missed — PROPOSAL_EXECUTORS is matched by name for that reason. The
   EXPECTED lists are the review: a route is in them because a person read it.

   WHERE THE LINE IS DRAWN, for login-only routes that write:
     PUBLIC      writes something an UNAUTHENTICATED reader is served. The
                 public GET routes serve exactly these tables (BEFORE Oct 27
                 2026 also profiles; AFTER, GET /api/profile/:username is gone):
                 digital_cards (by share token), bf_profiles, profile_products,
                 profile_portfolio, bf_music_tracks, bf_videos, content_library
                 (status published), marketplace_listings. A route that writes
                 one of them is public, including an edit or a delete, because
                 it changes what a stranger sees.
     OTHERS      reaches another ACCOUNT, or value that moves between
                 accounts: a direct message, a crowdfunding campaign other
                 accounts can see and fund, BFC credited, transferred or spent,
                 (BEFORE, to ae8e5db: also a USD checkout paying a seller.
                 AFTER: none; BizForce Market trades in BizCash only.)
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
const MUT = require("./_shared");
// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") MUT.runAllMutations(__filename, MUTATIONS);
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
  "post /api/agents/seo/optimize", "post /api/agents/etsy/keyword-research",
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
  "put /api/crowdfunding/campaigns/:id", "post /api/wallet/transfer",
  // A real SEO audit, measured before it is explained
  "post /api/agents/seo/audit",
  // File an email sequence for approval
  "post /api/agents/email/propose-sequence",
  // Publish approved posts to Bluesky
  "post /api/agents/social/propose-post",
  // Read the radar as demand evidence
  "post /api/agents/rd/demand-signals",
  // The Store agent's Stock & Margin, measured from the caller's own inventory
  "post /api/agents/store/stock-margin",
  // Claims Scan runs both claim rulebooks over everything you publish
  "post /api/agents/vertical_marketing/claims-scan",
  // The Community agent's Audience Ledger, counted from the caller's own sign-ups
  "post /api/agents/community/audience",
  // The Analytics agent's Arrivals Ledger, counted through the caller's own tracked links
  "post /api/agents/analytics/arrivals",
  // The SEO agent's Social Search, measured from the caller's own draft
  "post /api/agents/seo/social-search",
  // NAMED (Oct 27 2026, launch hardening #2; gated 61 -> 62, OTHERS 5 -> 4, effectful login-only 122 -> 121):
  // BEFORE, a campaign donation was login-only and listed in EXPECTED_OTHERS. AFTER, it needs a
  // subscription like the transfer it now shares limits with (requireActiveSubscription, bfcDonateLimiter).
  "post /api/crowdfunding/campaigns/:id/donate",
  // NAMED (Oct 28 2026, member support; gated 62 -> 63): BEFORE no support route. AFTER Support with BizCash
  // needs a subscription like the transfer whose limits it shares (requireActiveSubscription, bfcSupportLimiter).
  "post /api/wallet/support",
  // NAMED (Oct 28 2026, members connect their own Bluesky; gated 63 -> 65): BEFORE no member connection. AFTER
  // connecting a Bluesky account and filing a profile update need a subscription (requireActiveSubscription);
  // disconnecting and reading the status never do.
  "post /api/social/bluesky/connect", "post /api/social/bluesky/propose-profile",
  // NAMED (Nov 1 2026, member gates, migration 159; gated 65 -> 70): BEFORE no member gate. AFTER a member reads,
  // makes, changes, deletes and tests their own gates with a subscription (requireActiveSubscription,
  // memberGatesLimiter), because a gate governs agents that only run with one. The rule language and the
  // Decisions reads stay login-only: a member can always see why something ran (checkGates N).
  "get /api/member-gates", "post /api/member-gates", "put /api/member-gates/:id", "delete /api/member-gates/:id",
  "post /api/member-gates/preview",
  // NAMED (Nov 1 2026, member triggers, migration 160; gated 70 -> 74): BEFORE no trigger. AFTER a member makes,
  // changes, deletes and previews their own triggers with a subscription (requireActiveSubscription, triggersLimiter),
  // because a trigger acts only through agents that run with one. Reading the language, the list and the firings
  // history stays login-only: a member can always see what fired and why (checkTriggers G0).
  "post /api/triggers", "put /api/triggers/:id", "delete /api/triggers/:id", "post /api/triggers/preview",
  // NAMED (Nov 1 2026, the agent network B6/B7, migration 161; gated 74 -> 75): BEFORE no network route. AFTER a member
  // switches a declared link between two agents off or on with a subscription (requireActiveSubscription,
  // networkLimiter), because the links carry work only agents with one can do. Reading the map and a link's runs
  // stays login-only: a member can always see what flowed (checkAgentNetwork E0).
  "put /api/agents/network/links",
  // NAMED (Nov 1 2026, learning cycles B8/B9, migration 162; gated 75 -> 81): BEFORE no cycle route. AFTER a member
  // opens a cycle, reviews a plan (one model call), edits, approves, discards or sets aside a cycle with a subscription
  // (requireActiveSubscription; the review aiLimiter, the rest cycleLimiter), because a review is a model call and an
  // approved cycle starts a plan. Reading the cycle history stays login-only: a member can always see their results
  // (checkPlanCycles D16).
  "post /api/executive/cycles", "post /api/executive/cycles/:id/review", "put /api/executive/cycles/:id",
  "post /api/executive/cycles/:id/approve", "post /api/executive/cycles/:id/discard", "post /api/executive/cycles/:id/supersede",
  // NAMED (Nov 3 2026, store connections, migration 163; gated 81 -> 83): BEFORE no store connection. AFTER connecting a
  // Shopify or WooCommerce store (5 an hour) and "Sync now" (6 a day) need a subscription (requireActiveSubscription),
  // because the read feeds agents that run only with one. The list and disconnect stay login-only: a member can always
  // see what is connected and take their key back (checkStoreConnections C1, Y0, S2).
  "post /api/store/connections", "post /api/store/connections/:id/sync",
  // NAMED (Nov 3 2026, the Bluesky Mentions inbox, migration 164; gated 83 -> 86): BEFORE no inbox. AFTER reading the
  // inbox (12 an hour, 60 a day), drafting a reply (one model call; aiLimiter and 10 an hour, 30 a day) and filing it for
  // approval need a subscription (requireActiveSubscription), because each reads Bluesky or calls the model for an
  // account that posts only with one. Approving the reply is G3-gated on the approve route like every Bluesky action
  // (SUBSCRIPTION_GATED_PROPOSAL_ACTIONS; checkBlueskyMentions R1-R3).
  "get /api/social/bluesky/mentions", "post /api/social/bluesky/mentions/draft-reply", "post /api/social/bluesky/mentions/propose-reply",
  // NAMED (Nov 3 2026, Connect Mastodon, migration 165; gated 86 -> 88): BEFORE no member Mastodon connection. AFTER
  // connecting a Mastodon account (5 an hour) and filing a drafted post for approval need a subscription
  // (requireActiveSubscription); approving it is G3-gated on the approve route (SUBSCRIPTION_GATED_PROPOSAL_ACTIONS).
  // The status, disconnect and automation routes stay login-only, as Bluesky's do (checkMastodonConnect C, S, A).
  "post /api/social/mastodon/connect", "post /api/social/mastodon/propose-post",
  // NAMED (Nov 4 2026, campaign sharing, migration 166; gated 88 -> 90): BEFORE no campaign could be shared. AFTER turning a
  // campaign's sharing or discovery on or off, and making it a new link, need a subscription (requireActiveSubscription),
  // as editing the campaign does; the page itself is served only while the owner's plan is active (section 6).
  "put /api/crowdfunding/campaigns/:id/share", "post /api/crowdfunding/campaigns/:id/share/new-link",
  // NAMED (Nov 4 2026, the Media Library, migration 167; gated 90 -> 91): BEFORE no Media Library. AFTER adding a file to
  // it (POST /api/media: checked by its bytes, location data removed, 10 MB a file and 250 MB in all, into bf-public
  // media/<member id>/) needs a subscription (requireActiveSubscription), as the brief decides; listing, labelling and
  // deleting stay login-only (section 4's OWN list), so a member whose plan lapses can still clear their library.
  "post /api/media",
  // NAMED (Nov 5 2026, mailbox connection, migration 169; gated 91 -> 94): BEFORE no mailbox. AFTER connecting a mailbox
  // (the IMAP login and SMTP auth check, then the sealed app password) and reading it (the inbox list and one message,
  // read-only, never stored) need a subscription; the status and disconnect stay login-only, so a member whose plan
  // lapses can always see and remove the connection (checkMailboxConnect).
  "post /api/mailbox/connect", "get /api/mailbox/inbox", "get /api/mailbox/inbox/:uid",
  // NAMED (Nov 5 2026, mailbox replies, migration 170; gated 94 -> 96): BEFORE no reply could be drafted. AFTER drafting a
  // reply to one message (one model call; aiLimiter and 10 an hour, 30 a day) and filing it for approval need a
  // subscription (requireActiveSubscription); approving it is G3-gated on the approve route
  // (SUBSCRIPTION_GATED_PROPOSAL_ACTIONS send_mailbox_reply; checkMailboxReply).
  "post /api/mailbox/inbox/:uid/draft-reply", "post /api/mailbox/propose-reply"
];

const EXPECTED_ADMIN = [
  "get /api/admin/flagged-accounts", "post /api/admin/ban/:userId", "post /api/admin/unban/:userId",
  "post /api/admin/verify/:userId", "post /api/admin/flag/:userId", "post /api/admin/store-proposals/run",
  // NAMED (Nov 3 2026, the schema check; admin 6 -> 7): BEFORE no admin health route. AFTER /health's admin detail,
  // requireAuth and requireAdmin, which reads only the last schema check's result and writes nothing (checkSchemaCheck H2).
  "get /api/admin/health"
];

/* Login-only routes that write something a stranger is served. */
const EXPECTED_PUBLIC = {
  "post /api/proposals/:id/approve":        "publish_blog_post → public blog post; publish_listing / update_listing → public listing — those three need a subscription, checked in the handler; a calendar event does not",
  "put /api/marketplace/listings/:id":      "edits a public listing — needs a subscription, checked in the handler, except a pause",
  "delete /api/marketplace/listings/:id":   "removes a public listing",
  // BEFORE (e364883): "put /api/profile/me", profiles, served to anyone by GET /api/profile/:username.
  // AFTER: that route is deleted (launch hardening #1), so the edit is in EXPECTED_OWN.
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
  "delete /api/bfp/videos/:id":             "bf_videos, served publicly",
  // NAMED (Oct 28 2026, member support; effectful login-only 122 -> 123): BEFORE no support settings. AFTER
  // a member saves their support links and page switches, served on their public pages and support page.
  "put /api/support/me":                    "member_support: the support links and support page, served publicly"
};

/* Login-only routes that reach another account, or value between accounts. */
const EXPECTED_OTHERS = {
  "post /api/messages":                          "a direct message to another account",
  // BEFORE (e364883): "post /api/crowdfunding/campaigns/:id/donate", login-only. AFTER: gated (EXPECTED_GATED).
  "get /api/wallet":                            "reads the balance; creates a missing wallet at 0 BFC (the welcome bonus is granted on first subscription, not here)",
  "post /api/certifications/award":              "records a certification; its 100 BFC credit is paid only to an entitled account, checked in the handler",
  "post /api/marketplace/listings/:id/buy":      "spends BFC on another account's listing"
  // BEFORE (ae8e5db): "post /api/marketplace/listings/:id/checkout-usd", a Stripe checkout paying another
  // account's listing. AFTER: removed; BizForce Market trades in BizCash only (checkMarketplaceBfcOnly).
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
  "post /api/editor/image":                         "an editor image",
  // NAMED (Oct 29 2026, the theme engine): the member's backdrop photo, checked by its bytes, at most 5 MB
  "post /api/themes/photo":                         "a backdrop photo, bf-public theme-photos/<member id>/",
  // NAMED (Oct 30 2026, members' music library): a member's own audio file, checked by its bytes, at most 25 MB and
  // 250 MB in all, in the PRIVATE bucket bf-music under <member id>/ (checkMusicPlayer A2-A6)
  "post /api/music/tracks":                         "a member's own audio file, private bf-music <member id>/"
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
  // NAMED (Oct 22 2026, schedule control; effectful login-only 120 -> 122): pause and resume
  // change only the caller's own schedule's paused state. Deliberately ungated,
  // like stopping a sequence: pausing never needs a subscription, and resuming a
  // lapsed member's schedule runs nothing, because the runner checks entitlement.
  "put /api/agent-schedules/:agent_type/pause", "put /api/agent-schedules/:agent_type/resume",
  "post /api/birth-records", "delete /api/birth-records/:id",
  "put /api/notifications/:id/read",
  "post /api/stripe/checkout", "post /api/billing/portal",
  "post /api/bizdoc/documents", "put /api/bizdoc/documents/:id", "post /api/bizdoc/documents/:id/sign", "delete /api/bizdoc/documents/:id",
  "post /api/bizbook/books/:id/cover-from-wrap", "put /api/bizbook/books/:id", "put /api/bizbook/books/:id/cover-design", "delete /api/bizbook/books/:id",
  "post /api/cover-wraps", "put /api/cover-wraps/:id", "delete /api/cover-wraps/:id",
  "post /api/social-drafts", "put /api/social-drafts/:id",
  "post /api/content-library", "post /api/content-library/empty", "delete /api/content-library/:id",
  "post /api/content-library/:id/external-published",
  "post /api/agents/sales/lead-status",  // refuses every account but the credential owner (checkLeadRadarOwnerGate)
  // Let the owner see and stop every sequence: pauses, resumes or cancels the
  // caller's own sequence. Deliberately ungated, so stopping mail never needs a subscription.
  "post /api/email/sequences/:id/status",
  // NAMED (Oct 25 2026, legal pages; effectful login-only 122 -> 123): BEFORE, no Terms route.
  // AFTER, accepting the current Terms writes only the caller's own users.terms_accepted_at and
  // terms_version. Deliberately ungated: agreeing to the Terms never needs a subscription.
  "post /api/me/terms/accept",
  // NAMED (Oct 27 2026, launch hardening #1): BEFORE, in EXPECTED_PUBLIC, because GET
  // /api/profile/:username served the profiles row to anyone. AFTER, no unauthenticated route
  // serves profiles; GET /api/profile/by-id/:userId needs a login and returns five display columns.
  "put /api/profile/me",
  // NAMED (Oct 28 2026, the learning loop; effectful login-only 123 -> 129): BEFORE no ratings, examples or
  // preferences. AFTER a member rates and pins their own runs and keeps their own preferences per agent; every
  // row is theirs (agent_feedback, agent_preferences), served to no one else. The learning view is listed for the
  // lifted loadArrivals it reads through. Deliberately ungated: rating a past run never needs a subscription,
  // and nothing here calls the model (the runs that use the guidance are gated where they were).
  "put /api/agents/feedback/:taskId", "post /api/agents/feedback/:taskId/pin", "get /api/agents/:agentType/learning",
  "post /api/agents/:agentType/preferences", "put /api/agents/:agentType/preferences/:id", "delete /api/agents/:agentType/preferences/:id",
  // NAMED (Oct 28 2026, members connect their own Bluesky; effectful login-only 129 -> 131): BEFORE no member
  // connection. AFTER a member deletes their own connection row (member_social_connections) and sets their own
  // automation switch (logged in member_social_setting_changes); both rows are theirs and served to no one else.
  "post /api/social/bluesky/disconnect", "put /api/social/bluesky/automation",
  // NAMED (Oct 29 2026, signature live modules; effectful login-only 131 -> 133): BEFORE the two live routes were pure
  // reads and unlisted. AFTER they reach blogRefToken (the Analytics and SEO arrivals), whose crypto hash .update( this
  // file's WRITES pattern reads as a write, the same way the learning view is listed for loadArrivals. They write
  // nothing; checkAgentLive holds every query they make to the caller's own rows and to reads.
  "get /api/agents/live", "get /api/agents/:type/live",
  // NAMED (Oct 29 2026, the theme engine, Block 4a; effectful login-only 133 -> 138, with the photo upload in
  // EXPECTED_STORAGE): BEFORE no member themes. AFTER a member saves, changes, deletes, applies and resets their own
  // looks; every row is theirs (member_themes, their own user_preferences), served to no one else, and nothing calls the
  // model. Deliberately ungated, like every display preference: how the app looks never needs a subscription.
  "post /api/themes", "put /api/themes/apply", "put /api/themes/:id", "delete /api/themes/:id", "post /api/themes/reset",
  // NAMED (Oct 30 2026, members' music library; effectful login-only 138 -> 143, with the upload in EXPECTED_STORAGE):
  // BEFORE no music library. AFTER a member renames and deletes their own tracks (deleting removes the file too) and
  // keeps their own playlists; every row is theirs (member_tracks, member_playlists), served to no one else, and nothing
  // calls the model. Deliberately ungated, like the themes: listening to one's own music never needs a subscription.
  "put /api/music/tracks/:id", "delete /api/music/tracks/:id",
  "post /api/music/playlists", "put /api/music/playlists/:id", "delete /api/music/playlists/:id",
  // NAMED (Oct 31 2026, profile designs, migration 156; effectful login-only 144 -> 146): BEFORE no profile design.
  // AFTER a member saves and resets their own profile's design (bf_profiles.profile_design, their own row), checked
  // against a closed schema; visitors read it only as validated. Nothing calls the model. Deliberately ungated, like
  // the themes: how a member's own profile looks never needs a subscription (checkProfileDesign C0–C8).
  "put /api/bfp/profile/design", "delete /api/bfp/profile/design",
  // NAMED (Oct 31 2026, the boombox-mixer, migration 157; effectful login-only 146 -> 147): BEFORE no player settings.
  // AFTER a member saves their own player's finish and EQ (user_preferences.music_player, their own row), checked
  // against a closed shape (±12 dB); served to no one else, and nothing calls the model. Deliberately ungated, like
  // the themes and the music library (checkMusicPlayer H5).
  "put /api/music/player",
  // NAMED (Nov 1 2026, every gate recorded; effectful login-only 147 -> 148): BEFORE the guide wrote nothing. AFTER
  // each answer or refusal the guide gives records its G25 decision (gate_decisions, the caller's own row, kept 90
  // days, served only to them through "Why?"); the answer itself is unchanged and calls no model (checkGates J).
  "post /api/guide/ask",
  // NAMED (Nov 1 2026, Termaximus answers from records B10; effectful login-only 149 -> 150): BEFORE no records
  // question. AFTER a typed question about the member's own records records its G25 decision like the guide's and
  // makes one Haiku call inside Guide mode's own daily allowance (30 subscribed, 5 not, counted from model_calls),
  // through enforceDailyModelCallLimit and the ledger, so an unsubscribed member is capped exactly as in Guide mode.
  // It reads only the caller's own rows and writes nothing else (checkTermaximusRecords C, D, F).
  "post /api/guide/records",
  // NAMED (Nov 3 2026, Connect Mastodon, migration 165; effectful login-only 151 -> 153): BEFORE no member Mastodon
  // connection. AFTER a member deletes their own connection row (member_mastodon_connections) and sets their own
  // automation switch (logged in member_social_setting_changes, platform mastodon); both rows are theirs and served
  // to no one else.
  "post /api/social/mastodon/disconnect", "put /api/social/mastodon/automation",
  // NAMED (Nov 4 2026, the Media Library, migration 167; effectful login-only 153 -> 155): BEFORE no Media Library.
  // AFTER a member edits the label and alt text of their own file (PATCH) and deletes their own file (DELETE: refused
  // with 409 while it is used anywhere, else the file and then its row; checkMediaLibrary). Both rows are theirs, and the
  // file is in their own media/<id>/ folder; nothing another member is served is written.
  "patch /api/media/:id", "delete /api/media/:id",
  // NAMED (Nov 5 2026, mailbox connection, migration 169; effectful login-only 155 -> 156): BEFORE no mailbox. AFTER a
  // member deletes their own member_email_connections row (the sealed app password with it); the row is theirs and
  // served to no one else, and disconnecting must always work, subscribed or not.
  "post /api/mailbox/disconnect",
  // NAMED (Nov 6 2026, card upgrades C2, migration 172; effectful login-only 156 -> 158): BEFORE no card leads. AFTER a
  // member marks one of their own leads read or archived (PATCH) and deletes one of their own leads (DELETE); both are
  // .eq("user_id", req.user.id), the rows are the member's own data, served to no one else, and stay theirs to manage
  // subscribed or not (checkCardLeads). GET /api/digital-cards/:id/leads is a login-only read and needs no entry here.
  "patch /api/card-leads/:id", "delete /api/card-leads/:id"
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
  // Writes one consent_events "confirmed" row, only for a genuine, unexpired
  // token signed for the contact's current address, and nothing after "revoked".
  "post /api/confirm":                      "a confirmed consent, from a signed token (double opt-in)",
  "post /api/engine-visits":                "an arrival from a Lead Radar reply (migration 128)",
  "post /api/sms/inbound":                  "an inbound SMS reply (STOP / HELP)",
  // NAMED (Nov 3 2026, store connections, migration 163; 17 -> 18): BEFORE no store callback. AFTER a member's own
  // WooCommerce store posts the Read key it made here; it is stored only for the member an HMAC-signed state, at most
  // 30 minutes old, names, only with permission "read", after one GET the store accepts (checkStoreConnections W3-W8).
  "post /api/store/woocommerce/callback":   "a member's read-only WooCommerce key, from a signed state (migration 163)",
  // NAMED (Nov 6 2026, card upgrades C1, migration 171; 18 -> 21): BEFORE no card page or tap was counted. AFTER a GET of a
  // card page adds one to that card's daily views (and qr_views for ?via=qr), and a tap on its Call, Email, Save Contact or
  // Support adds one to that counter, through bump_card_count only. Nothing about the visitor is written; HEAD, no
  // User-Agent, bots and a lapsed owner's card are not counted (checkCardUpgrades). GET /api/digital-cards/:id/stats
  // is a login-only read of the owner's own card and needs no entry here.
  "get /c/:slug":                           "one added to a card's daily view count, nothing about the visitor (migration 171)",
  "get /card/:token":                       "one added to a card's daily view count, nothing about the visitor (migration 171)",
  "post /api/cards/tap":                    "one added to a card's daily tap count, nothing about the visitor (migration 171)",
  // NAMED (Nov 6 2026, card upgrades C2, migration 172; 21 -> 22): BEFORE no card took a lead. AFTER a visitor leaves one
  // lead (name, email or phone, message, the server's consent sentence) on a card whose owner turned the form on and is
  // public, behind a form token, a honeypot, per-card caps, a dedupe and an IP limiter; at most one notice an hour to
  // the owner, with no lead details. Nothing about the visitor's device is written (checkCardLeads).
  "post /api/cards/lead":                   "one lead on a card whose owner turned the form on, consent recorded (migration 172)"
};

/* Login-only routes that gate PART of what they do inside the handler. The
   middleware cannot see these, so each handler must carry its gate's text. */
const EXPECTED_HANDLER_GATES = {
  "post /api/proposals/:id/approve":   'refuseUnlessSubscribed(req, res, "approve " + pending.action_type)',
  "put /api/marketplace/listings/:id": 'refuseUnlessSubscribed(req, res, "put /api/marketplace/listings/:id")',
  "post /api/certifications/award":    'creditWithheld = "subscription_required"',
  // NAMED (Oct 28 2026, members connect their own Bluesky): BEFORE three. AFTER turning automatic posting ON needs a
  // subscription, checked in the handler; turning it off never does.
  "put /api/social/bluesky/automation": 'refuseUnlessSubscribed(req, res, "turn on automatic Bluesky posting")',
  // NAMED (Nov 3 2026, Connect Mastodon): BEFORE four. AFTER turning automatic Mastodon posting ON needs a
  // subscription, checked in the handler; turning it off never does.
  "put /api/social/mastodon/automation": 'refuseUnlessSubscribed(req, res, "turn on automatic Mastodon posting")'
};

/* Unauthenticated GET routes that serve an account's public page, and must
   serve it only while the OWNER is entitled. Writes to these pages stay open;
   this is where publishing is gated. */
const SERVE_GUARD = "if (!(await ownerPagePublic(";
const EXPECTED_SERVE_GATED = {
  // BEFORE (e364883): "get /api/profile/:username". AFTER: deleted (launch hardening #1, checkDormantRoutesDeleted).
  "get /api/cards/share/:token":            SERVE_GUARD,
  // NAMED (Oct 27 2026, launch item #10): BEFORE a card was served only by its share token. AFTER the short link
  // bizforceai.net/c/<slug> is served by GET /api/cards/slug/:slug, with the same owner check.
  "get /api/cards/slug/:slug":              SERVE_GUARD,
  "get /api/bfp/profile/:userId":           SERVE_GUARD,
  "get /api/bfp/pproducts/public/:userId":  SERVE_GUARD,
  "get /api/bfp/pportfolio/public/:userId": SERVE_GUARD,
  "get /api/bfp/music/public/:userId":      SERVE_GUARD,
  "get /api/bfp/videos/public/:userId":     SERVE_GUARD,
  "get /api/bfp/seller/:handle":            SERVE_GUARD,
  "get /api/bfp/services/browse":           "publicOwnersAmong(",
  "get /api/bfp/artists/browse":            "publicOwnersAmong(",
  // NAMED (Oct 28 2026, member support): BEFORE no support page. AFTER bizforceai.net/support/<username> and the
  // support sitemap, each serving a member only while the owner is entitled.
  "get /support/:username":                 "!(await ownerPagePublic(member.user_id))",
  "get /api/sitemap/support.xml":           "publicOwnersAmong(",
  // NAMED (Nov 4 2026, campaign sharing; serve-gated 12 -> 14): BEFORE no campaign page. AFTER bizforceai.net/campaign/<id>
  // and the campaign sitemap, each serving a campaign only while its owner is entitled.
  "get /campaign/:shareId":                 "!(await ownerPagePublic(shared.owner_id))",
  "get /api/sitemap/campaigns.xml":         "publicOwnersAmong(",
  // NAMED (Nov 6 2026, card upgrades C1; serve-gated 14 -> 17): BEFORE Netlify served card-view.html at /c/<slug> itself.
  // AFTER bizforceai.net/c/<slug> and /card/<token> are served here by serveCardPage, whose owner check is
  // "(await ownerPagePublic(row.user_id)) === true" (checkCardUpgrades proves a lapsed owner's card is a 404 and uncounted),
  // and the cards sitemap lists a card only while its owner is entitled.
  "get /c/:slug":                           "serveCardPage(req, res,",
  "get /card/:token":                       "serveCardPage(req, res,",
  "get /api/sitemap/cards.xml":             "publicOwnersAmong("
};

/* ── MUTATE=serve-open: the seller page's guard removed at compile ──────── */
if (MUTATE === "serve-open") {
  const Module = require("module");
  const realCompile = Module.prototype._compile;
  const GUARD_LINE = '    if (!(await ownerPagePublic(seller.user_id))) return res.status(404).json({ error: "seller not found" });\n';
  Module.prototype._compile = function (content, filename) {
    if (path.resolve(filename) === path.resolve(SERVER_PATH)) {
      content = content.replace(/\r\n/g, "\n");
      content = MUT.replaceOnce(content, GUARD_LINE, "", "serve-open");
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
// The confirm page's GET only renders; the POST is the one that writes.
check("5. get /api/confirm is mounted, unauthenticated, and NOT a writer",
  of("unauthenticated").some(function (r) { return r.key === "get /api/confirm"; }) &&
  keys(unauthWriters).indexOf("get /api/confirm") === -1, keys(unauthWriters).join(", "));
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
