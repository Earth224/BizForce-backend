/* ══════════════════════════════════════════════════════════════════════════
   NAMED (Nov 23 2026, LR-1): static pins updated; this check is excluded from the suite (it resolves account 6df1851e) and was not run.

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
                 direct send (NAMED (Nov 23 2026, LR-1): BEFORE shut by SMS_DIRECT_SEND_ENABLED = false;
                 AFTER a 503 "SMS sending is not offered." with no send code).
     STORAGE     puts a file in a Supabase storage bucket — real cost against
                 the plan's storage and egress caps, and bf-public is publicly
                 readable by URL.
     OWN         the account's own records, visible to it alone: settings,
                 sessions and passkeys, its CRM, inventory, calendar, memory,
                 drafts, documents, proposals it has not approved, billing.
   No login-only route may spend a model call; that list is empty and must stay
   empty.

   P3-1 (Nov 20 2026): THE FOUR GROUPS. Free accounts and one membership. lib/routeAccess.js assigns every
   route a group: P public (no sign-in), F free (sign-in only), M members only (requireActiveSubscription,
   inserted by applyRouteAccess where the route line lacked it) and A the owner or an admin (requireAdmin, or
   the owner check in the handler, ADMIN_IN_HANDLER). This check holds the table to the live router.

   WHAT THIS PROVES
     1. Every route classifies, the counts are printed, and every live route is in exactly one group
        (a new route fails until it is assigned; a grouped route that is gone fails too).
     2. Each group is what the router does: P has no sign-in, F is sign-in only, M has
        requireActiveSubscription, A is requireAdmin or an owner check in the handler. The admin set is
        exactly EXPECTED_ADMIN; every route EXPECTED_GATED reviewed before P3-1 is still M except the
        three P3-1 freed (posting, post photos, a new listing) and the two LR-1 moved to A (draft-reply,
        demand-signals; NAMED (Nov 23 2026, LR-1)); every disconnect is F.
        (NAMED, P3-1: BEFORE section 2 held the gated set to EXPECTED_GATED.)
     3. No free (login-only) route reaches a model call.
     4. Every free route that writes, publishes, stores or reaches another person is in exactly one
        EXPECTED list; a new one fails until it is reviewed and added. A listed route that no longer
        exists, is no longer free, or no longer has any effect also fails, so the lists stay exact.
     5. Every unauthenticated route that writes is in EXPECTED_UNAUTH_WRITES, on the same terms.
     6. Each public page route is unauthenticated and its handler carries the owner check, and the
        check answers for real accounts: a page is served while its owner is in good standing (NAMED,
        P3-1: BEFORE while entitled). The free check account's page is served, the seed's and the
        owner's too; an id with no account is not.
     7. Each in-handler gate is present, and a 402 keeps error and upgrade_required, adds message and
        billing_url, and carries the members panel (lib/membership.js) at the price in code.

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
   MUTATE=free-selling NAMED (Nov 21 2026, P3-1B): removes requireActiveSubscription
                       from the live stack of POST /api/marketplace/listings (the
                       P3-1 free listing). The P3-1B section must go red.
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

const MUTATIONS = ["add-public", "ungate", "serve-open", "free-selling"];   // NAMED (Nov 21 2026, P3-1B): + free-selling
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
  "post /api/mailbox/inbox/:uid/draft-reply", "post /api/mailbox/propose-reply",
  // NAMED (Nov 6 2026, Outlook sign-in, migration 173; gated 96 -> 98): BEFORE a mailbox connected by app password only.
  // AFTER Sign in with Microsoft starts (a single-use state stored) and finishes (the code exchanged, the IMAP and SMTP
  // checks run, the sealed tokens stored) behind a subscription, as connect does; status and disconnect stay
  // login-only (checkMailboxOutlook).
  "post /api/mailbox/microsoft/start", "post /api/mailbox/microsoft/finish",
  // NAMED (Nov 6 2026, store changes, migration 175; gated 98 -> 100): BEFORE BizForce only read a store. AFTER proposing a
  // WooCommerce price or stock change (one live read of the item) and proposing its undo need a subscription
  // (requireActiveSubscription; 30 an hour), and approving one is G3-gated on the approve route
  // (SUBSCRIPTION_GATED_PROPOSAL_ACTIONS update_store_item). Reading the record of changes stays login-only: a member can
  // always see what BizForce changed (checkStoreChanges).
  "post /api/store/changes/propose", "post /api/store/changes/:id/undo",
  // NAMED (Nov 7 2026, Shopify on OAuth, migration 176; gated 100 -> 102): BEFORE a Shopify shop connected by a pasted token
  // through POST /api/store/connections. AFTER Connect Shopify starts (a single-use state stored) and finishes (the HMAC and
  // timestamp checked, the state consumed, the code exchanged, both tokens sealed, the row stored) behind a subscription, as
  // WooCommerce's connect does; the list, the location routes and disconnect stay login-only (checkShopifyConnect).
  "post /api/store/shopify/start", "post /api/store/shopify/finish",
  // NAMED (Nov 7 2026, YouTube uploads, migration 177; gated 102 -> 109): BEFORE no YouTube connection or member video. AFTER
  // Connect YouTube starts (a single-use state and a sealed PKCE verifier stored) and finishes (the code exchanged, both
  // scopes required, the tokens sealed, the channel stored); a signed upload URL into the private bf-video bucket and the
  // streamed check of what arrived (finalize); filing an upload or a removal for approval; and an AI draft of the title,
  // description and tags (aiLimiter). All need a subscription; approving either is G3-gated on the approve route
  // (SUBSCRIPTION_GATED_PROPOSAL_ACTIONS publish_youtube_video and delete_youtube_video). Status, disconnect, the list of
  // videos, deleting a ready video and a video's status stay login-only (checkYoutubeUploads).
  "post /api/youtube/start", "post /api/youtube/finish", "post /api/videos/upload-url", "post /api/videos/finalize",
  "post /api/youtube/propose-upload", "post /api/youtube/draft-metadata", "post /api/youtube/videos/:id/propose-delete",
  // NAMED (Nov 7 2026, TikTok posting, migration 178; gated 109 -> 113): BEFORE no TikTok connection. AFTER Connect TikTok
  // starts (a single-use state stored) and finishes (the code exchanged, both scopes required, the tokens sealed, the user
  // read); filing a post for approval (TikTok's posting rules against a fresh creator_info); and an AI draft of the caption
  // (aiLimiter). All need a subscription; approving a post is G3-gated on the approve route
  // (SUBSCRIPTION_GATED_PROPOSAL_ACTIONS publish_tiktok_post). Status, disconnect, creator-info and a post's status stay
  // login-only (checkTiktokPosting).
  "post /api/tiktok/start", "post /api/tiktok/finish", "post /api/tiktok/propose-post", "post /api/tiktok/draft-caption",
  // NAMED (Nov 7 2026, Instagram posting, migration 179; gated 113 -> 117): BEFORE no Instagram connection. AFTER Connect
  // Instagram starts (a single-use state stored) and finishes (the code exchanged, the short token swapped at once for the
  // long-lived one, sealed before /me, Business and Creator accounts only); filing a post for approval (each photo's bytes
  // checked JPEG, or the Reel's type); and an AI draft of the caption (aiLimiter). All need a subscription; approving a post is
  // G3-gated on the approve route (SUBSCRIPTION_GATED_PROPOSAL_ACTIONS publish_instagram_post). Status, disconnect, the list
  // of posts and a post's status stay login-only (checkInstagramPosting).
  "post /api/instagram/start", "post /api/instagram/finish", "post /api/instagram/propose-post", "post /api/instagram/draft-caption",
  // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages); migration 180; gated 117 -> 122: BEFORE no Facebook connection. AFTER Connect
  // Facebook starts (a single-use state stored) and finishes (the code exchanged, every scope required, the long-lived user
  // token sealed, the Pages listed); a Page is chosen (its token sealed); a post is filed for approval (text, photos or a
  // video, fingerprinted); and an AI draft of the post text (aiLimiter). All need a subscription; approving a post is G3-gated
  // on the approve route (SUBSCRIPTION_GATED_PROPOSAL_ACTIONS publish_facebook_post). The Pages list, status, disconnect, the
  // list of posts, a post's status and filing a removal stay login-only: a removal stays free (checkFacebookPages).
  "post /api/facebook/start", "post /api/facebook/finish", "post /api/facebook/choose-page", "post /api/facebook/propose-post",
  "post /api/facebook/draft-caption",
  // NAMED (Nov 8 2026, Etsy store connection, migration 181; gated 122 -> 124): BEFORE a store was Shopify or WooCommerce only.
  // AFTER Connect Etsy starts (a single-use state and a sealed PKCE verifier stored) and finishes (the state consumed once, the
  // code exchanged, both tokens sealed, the shop read and stored); both need a subscription, under Connect Shopify's limiter.
  // The list, sync now and disconnect are the existing store routes, unchanged (checkEtsyConnect).
  "post /api/store/etsy/start", "post /api/store/etsy/finish",
  // NAMED (Nov 8 2026, Amazon store connection, migration 182; gated 124 -> 126): BEFORE a store was Shopify, WooCommerce or
  // Etsy. AFTER Connect Amazon starts (the marketplace checked, a single-use state stored) and finishes (the seller id checked,
  // the state consumed once, the code exchanged, both tokens sealed, the participation read and stored); both need a
  // subscription, under Connect Shopify's limiter. The list, sync now and disconnect are the existing store routes,
  // unchanged (checkAmazonConnect).
  "post /api/store/amazon/start", "post /api/store/amazon/finish",
  // NAMED (Nov 18 2026, BV1, migration 187; gated 126 -> 128): BEFORE a video was one upload-url and one finalize. AFTER a
  // video over 50 MB asks part-url for each part's signed URL and reports it with part-done; both need a subscription, like
  // upload-url and finalize, under their own limiter (120 an hour; checkYoutubeUploads BV20).
  "post /api/videos/part-url", "post /api/videos/part-done",
  // NAMED (Nov 20 2026, P2-3, migrations 193 and 194; gated 128 -> 130): BEFORE no posts. AFTER making a post and uploading its
  // photos need a subscription, like every other thing a member publishes; reading, Talk, likes, saves, shares and follows are
  // login-only (checkPosts, checkPostMedia).
  "post /api/posts/photos", "post /api/posts"
];

const EXPECTED_ADMIN = [
  "get /api/admin/flagged-accounts", "post /api/admin/ban/:userId", "post /api/admin/unban/:userId",
  "post /api/admin/verify/:userId", "post /api/admin/flag/:userId", "post /api/admin/store-proposals/run",
  // NAMED (Nov 21 2026, P3-2; admin 15 -> 17): BEFORE no way to remove a badge or list who has one. AFTER the owner's
  // "Verified sellers" on moderation.html: removing a seller or official badge (writes bf_profiles.verified_reason and a
  // moderation_logs row) and the list of verified accounts with a handle lookup (read-only), both requireAuth and
  // requireAdmin (checkVerifiedBadge).
  "post /api/admin/unverify/:userId", "get /api/admin/verified",
  // NAMED (Nov 3 2026, the schema check; admin 6 -> 7): BEFORE no admin health route. AFTER /health's admin detail,
  // requireAuth and requireAdmin, which reads only the last schema check's result and writes nothing (checkSchemaCheck H2).
  "get /api/admin/health",
  // NAMED (Nov 14 2026, L1; admin 7 -> 8): BEFORE no price-change route. AFTER the owner's price-change notice, requireAuth and
  // requireAdmin; it emails billed subscribers once each, 7 to 30 days ahead, and never changes a Stripe price (checkLegalL1 D12-D15).
  "post /api/admin/price-change-notice",
  // NAMED (Nov 15 2026, W2; admin 8 -> 10): BEFORE no Shopify data-request routes. AFTER the owner's list of Shopify data
  // requests (read-only) and marking one answered (sets answered_at only), both requireAuth and requireAdmin (checkShopifyWebhooks K).
  "get /api/admin/shopify-data-requests", "post /api/admin/shopify-data-requests/:id/answered",
  // NAMED (Nov 20 2026, P2-2, migration 191; admin 10 -> 15): BEFORE no moderation routes. AFTER the owner's moderation.html: the
  // queue's tabs, the storage panel and one item (read-only), a decision (keep, hide or remove; logged, the author and reporters
  // told) and a court filing on a countered notice, every one requireAuth and requireAdmin (checkModerationQueue, checkCopyrightNotices).
  "get /api/admin/moderation", "get /api/admin/moderation/storage", "get /api/admin/moderation/item/:id",
  "post /api/admin/moderation/item/:id/decide", "post /api/admin/moderation/notice/:id/court-filed"
];

/* Login-only routes that write something a stranger is served. */
const EXPECTED_PUBLIC = {
  "post /api/proposals/:id/approve":        "publish_blog_post → public blog post; publish_listing / update_listing → public listing — those three need a subscription, checked in the handler; a calendar event does not",
  "put /api/marketplace/listings/:id":      "edits a public listing — needs a subscription, checked in the handler, except a pause",
  "delete /api/marketplace/listings/:id":   "removes a public listing",
  // NAMED (Nov 20 2026, P3-1; PUBLIC 20 -> 21): BEFORE a new listing needed a subscription (EXPECTED_GATED). AFTER selling is free:
  // a new listing is public once made, and needs a confirmed email (requireVerifiedEmail; checkEmailVerified).
  "post /api/marketplace/listings":        "makes a public listing — free, with a confirmed email (requireVerifiedEmail, P3-1)",
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
  // NAMED (Nov 23 2026, LR-1): BEFORE "texts any number — shut: SMS_DIRECT_SEND_ENABLED = false". AFTER a 503 stub, no send code (M, gated).
  "post /api/sms/send":                     "SMS sending is not offered: a 503 stub, no Twilio code, checkOpenSurfaceClosed",
  // NAMED (Nov 23 2026, LR-1): AFTER opted in only with recorded consent (smsConsentProof, a consent_events row); else pending or opted_out.
  "post /api/sms/subscribers":              "stores a person's phone number, opted in only with recorded consent",
  "post /api/sms/subscribers/bulk":         "stores many phone numbers, each opted in only with recorded consent",
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
  // NAMED (Nov 23 2026, LR-2): BEFORE "post /api/agents/sales/lead-status" (the owner's pipeline), removed with the platform radar.
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
  // subscribed or not (checkCardLeads). GET /api/digital-cards/:id/leads is a login-only read and needs no entry here
  // (NAMED (Nov 23 2026, LR-1): BEFORE it sat in M by mistake; AFTER it is F in lib/routeAccess.js, so a member always reads their own leads).
  "patch /api/card-leads/:id", "delete /api/card-leads/:id",
  // NAMED (Nov 7 2026, Shopify on OAuth, migration 176; effectful login-only 158 -> 159): BEFORE no location choice. AFTER a
  // member sets where Shopify stock changes apply on their own connection (location_id and location_name, one of the shop's
  // active locations read live), .eq("user_id", req.user.id) and platform shopify; the row is theirs, served to no one else,
  // and changes nothing in the store. GET /api/store/connections/:id/locations is a login-only live read (it may mark the
  // member's own connection needs_reconnect, as Sync now does) and needs no entry here (checkShopifyConnect).
  "put /api/store/connections/:id/location",
  // NAMED (Nov 7 2026, YouTube uploads, migration 177; one more effectful login-only route): BEFORE no YouTube connection.
  // AFTER a member disconnects their own channel: Google is asked to revoke the token as a best effort (never blocking), and
  // their own member_youtube_connections row and their own youtube_google oauth_states are deleted; nothing another member
  // is served is written, and disconnecting must always work, subscribed or not. DELETE /api/videos/:id (a ready video the
  // member owns, through lib/memberVideos.js) and the status reads write nothing a member is served and need no entry here.
  "post /api/youtube/disconnect",
  // NAMED (Nov 7 2026, TikTok posting, migration 178; one more effectful login-only route): BEFORE no TikTok connection.
  // AFTER a member disconnects their own TikTok account: TikTok is asked to revoke the token as a best effort (never
  // blocking), and their own member_tiktok_connections row and their own tiktok_login oauth_states are deleted; nothing
  // another member is served is written, and disconnecting must always work, subscribed or not. The creator-info and status
  // reads (through lib/tiktokApi.js) write only the member's own rows and need no entry here.
  "post /api/tiktok/disconnect",
  // NAMED (Nov 7 2026, Instagram posting, migration 179; one more effectful login-only route): BEFORE no Instagram connection.
  // AFTER a member disconnects their own Instagram account: their own member_instagram_connections row and their own
  // instagram_login oauth_states are deleted; nothing another member is served is written, and disconnecting must always
  // work, subscribed or not. The posts list and a post's status (through lib/instagramApi.js) write only the member's own
  // rows, finishing a post the member already approved, and need no entry here.
  "post /api/instagram/disconnect",
  // NAMED (Nov 23 2026, LR-2, migration 204e; one more effectful login-only route): a member disconnects their own Threads
  // account: their own threads_connections row is deleted; disconnecting must always work, subscribed or not.
  "post /api/social/threads/disconnect",
  // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages; migration 180; one more effectful login-only route): BEFORE no Facebook
  // connection. AFTER a member disconnects their own Facebook Page: their own member_facebook_pages row and their own
  // facebook_login oauth_states are deleted; nothing another member is served is written, and disconnecting must always work,
  // subscribed or not. The Pages list, the posts list, a post's status and filing a removal (through lib/facebookApi.js) write
  // only the member's own rows and need no entry here.
  "post /api/facebook/disconnect",
  // NAMED (Nov 10 2026, orbit top half; one more effectful login-only route): BEFORE no dashboard aggregate. AFTER GET
  // /api/dashboard/top reads the caller's own figures for the dashboard's orbit. It is listed for the same reason as the
  // live routes above: it reaches blogRefToken through loadArrivals, whose crypto hash .update( this file's WRITES pattern
  // reads as a write. It writes nothing and starts no task; checkDashboardTop holds every query it makes to the caller's
  // own rows and to reads, and holds it login-only on purpose, so a lapsed member still sees their own numbers.
  "get /api/dashboard/top",
  // NAMED (Nov 19 2026, P2-1, migrations 189 and 190; effectful login-only 165 -> 168): BEFORE no Inbox and no place. AFTER
  // opening a conversation marks the caller's own message notices from that person read, "Mark all read" marks the
  // caller's own notices read, and Settings, Local saves the caller's own place (bf_profiles, their own row). Each writes
  // only the caller's rows (checkInbox I3 and N7, checkHandles L7). Deliberately ungated: reading your own notices and
  // saying where you are never need a subscription.
  "post /api/inbox/read/:userId", "post /api/notifications/read-all", "put /api/me/place",
  // NAMED (Nov 20 2026, P2-2, migration 191; effectful login-only 168 -> 172): BEFORE no blocks or mutes. AFTER a member blocks,
  // unblocks, mutes and unmutes; each writes only the caller's own member_blocks or member_mutes rows (checkBlocks). Deliberately
  // ungated: keeping someone away must never need a subscription.
  "post /api/blocks", "delete /api/blocks/:userId", "post /api/mutes", "delete /api/mutes/:userId"
  // NAMED (Nov 11 2026, orbit stage 2; classified, not listed): GET /api/dashboard/pulse is login-only and READ-ONLY. It reads the
  // caller's own running agents and recent events (ai_tasks, agent_proposals, store_change_log, card_leads, social_post_drafts,
  // instagram_posts, facebook_posts, member_videos, content_library), writes nothing, starts no task and calls no model, and does
  // not reach loadArrivals, so this file's WRITES pattern finds no write and it belongs on no list here. checkOrbitStage2 holds it
  // read-only (pulse-writes) and login-only, so a lapsed member still sees their own agents.
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
  // NAMED (Nov 7 2026, migration 176): BEFORE "a member's read-only WooCommerce key". AFTER since migration 175 the key is read,
  // or read_write when the member allowed changes and the signed state asked for exactly that; the entry says so.
  "post /api/store/woocommerce/callback":   "a member's WooCommerce key, read or read_write exactly as the signed state asked (migrations 163, 175)",
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
  "post /api/cards/lead":                   "one lead on a card whose owner turned the form on, consent recorded (migration 172)",
  // NAMED (Nov 7 2026, Shopify on OAuth, migration 176; 22 -> 23): BEFORE no Shopify webhook. AFTER Shopify posts app/uninstalled
  // and the three privacy topics here, raw body, HMAC-SHA256 verified under the app's secret (401 otherwise, 503 unconfigured);
  // each delivery's id is recorded once in shopify_webhook_events (kept 30 days), and uninstall or shop/redact deletes that
  // shop's connection and everything read from it, as Disconnect does. Nothing else is written (checkShopifyConnect).
  "post /api/webhooks/shopify":             "Shopify webhook, HMAC-verified: a receipt, and on uninstall or shop/redact the shop's connection deleted (migration 176)",
  // NAMED (Nov 20 2026, P2-2; 23 -> 26): BEFORE these three public reads wrote nothing. AFTER each asks who the viewer is
  // (viewerIdFrom), which runs requireAuth on the request's own token, so a signed-in viewer's session gets its last_used_at, as
  // every signed-in request does; nothing else is written, and a visitor with no token writes nothing (checkBlocks).
  "get /api/bfp/profile/:userId":           "a signed-in viewer's own session last_used_at only (viewerIdFrom, P2-2)",
  "get /api/bfp/seller/:handle":            "a signed-in viewer's own session last_used_at only (viewerIdFrom, P2-2)",
  "get /api/marketplace/listings/:id":      "a signed-in viewer's own session last_used_at only (viewerIdFrom, P2-2)",
  // NAMED (Nov 20 2026, P2-3; 26 -> 27): BEFORE no public post page. AFTER /p/<id> asks who the viewer is (viewerIdFrom) to leave
  // a blocked viewer out, as P2-2's three reads do; nothing else is written (checkPublicPostPage).
  "get /p/:id":                             "a signed-in viewer's own session last_used_at only (viewerIdFrom, P2-3)",
  // NAMED (Nov 23 2026, LR-2, migration 204e; 27 -> 28): BEFORE no Threads connection. AFTER Meta redirects a member back here;
  // the code is exchanged and the member's own threads_connections row written only for the member an HMAC-signed, single-use
  // state names (lib/threadsRoutes.js, checkThreadsConnect).
  "get /api/social/threads/callback":       "a member's own Threads connection, for the member a signed single-use state names (migration 204e)",
  // NAMED (Nov 24 2026, LR-2B; 28 -> 30): BEFORE no Meta callbacks. AFTER Meta's Uninstall and Delete callbacks, each refused
  // (400, nothing written) without a signed_request verified by HMAC-SHA256 under THREADS_APP_SECRET; they only DELETE: the
  // connection Meta names, and for a deletion that member's Threads leads and replies (checkThreadsConnect M).
  "post /api/social/threads/deauthorize":   "Meta's Uninstall Callback, signed_request verified: deletes the Threads connection it names (migration 204e)",
  "post /api/social/threads/data-deletion": "Meta's Delete Callback, signed_request verified: deletes that member's Threads leads, replies and connection (migration 204)"
};

/* Login-only routes that gate PART of what they do inside the handler. The
   middleware cannot see these, so each handler must carry its gate's text. */
const EXPECTED_HANDLER_GATES = {
  "post /api/proposals/:id/approve":   'refuseUnlessSubscribed(req, res, "approve " + pending.action_type)',
  // NAMED (Nov 20 2026, P3-1): BEFORE refuseUnlessSubscribed (G3) for any edit but a pause. AFTER selling is free; an edit but a pause
  // needs a confirmed email instead (lib/emailVerification.js, checkEmailVerified).
  "put /api/marketplace/listings/:id": 'unverifiedBody("list_market")',
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
  "get /api/sitemap/cards.xml":             "publicOwnersAmong(",
  // NAMED (Nov 6 2026, Google Wallet; serve-gated 17 -> 18): BEFORE no pass. AFTER GET /api/cards/google-wallet answers a
  // signed save link for a card only while its owner is entitled (a lapsed owner or a throwing lookup is 404); it writes
  // nothing, so it is not an unauthenticated write (checkGoogleWallet).
  "get /api/cards/google-wallet":           SERVE_GUARD
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
  // NAMED (Nov 23 2026, LR-1): BEFORE the list also named sendMastodonReply, which is removed (Mastodon lead replies are gone).
  if (/messages\.create\(|sendEmail\(|sendBlueskyReply|sendPushToUser\(/.test(handlerText)) fx.push("sends");
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

if (MUTATE === "free-selling") {   // NAMED (Nov 21 2026, P3-1B)
  const layer = layerFor("post", "/api/marketplace/listings");
  layer.route.stack = layer.route.stack.filter(function (x) { return x.handle.name !== "requireActiveSubscription"; });
  console.log("\n!! MUTATION: requireActiveSubscription removed from POST /api/marketplace/listings — the P3-1B section must fail.");
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

/* ── P3-1 (Nov 20 2026): THE FOUR GROUPS, lib/routeAccess.js ───────────────
   Every route is P (public), F (free accounts and members, sign-in only), M (members only:
   requireActiveSubscription in front) or A (the owner or an admin). The table is the review;
   the live router must agree with it route by route. */
const RA = require(path.join(REPO, "lib", "routeAccess.js"));
const BY_KEY = {};
ROUTES.forEach(function (r) { BY_KEY[r.key] = r; });
const byKeyOf = function (k) { return BY_KEY[k]; };
const GROUP_NAME = { P: "public", F: "free", M: "members only", A: "owner or admin" };
/* The three routes P3-1 took out of EXPECTED_GATED on purpose (posting, post photos, a new listing): free now. */
// NAMED (Nov 21 2026, P3-1B): BEFORE P3-1 freed three (posting, post photos, a new listing). AFTER the owner's final rules put the
// new listing back with the members (MOVED_BY_P31B), so P3-1 freed two that stay free.
const FREED_BY_P31 = ["post /api/posts", "post /api/posts/photos"];
/* NAMED (Nov 21 2026, P3-1B, the owner's final rules): selling, campaigns and BizCash in every form are members only. These
   moved from F to M in lib/routeAccess.js; each is M and gated (requireActiveSubscription in its live stack). */
const MOVED_BY_P31B = ["post /api/marketplace/listings", "put /api/marketplace/listings/:id", "post /api/marketplace/upload-digital",
  "post /api/bfp/pproducts", "put /api/bfp/pproducts/:id", "get /api/crowdfunding/campaigns", "get /api/crowdfunding/campaigns/by-share/:shareId",
  "get /api/crowdfunding/my-campaigns", "get /api/crowdfunding/donations", "get /api/crowdfunding/donations/:id", "get /api/support/me",
  "put /api/support/me", "get /api/wallet"];

console.log("\n══ 1. every route, classified from the live router, and assigned a group ══");
["unauthenticated", "login-only", "gated", "admin"].forEach(function (c) { console.log("    " + c.padEnd(16) + of(c).length); });
console.log("    " + "total".padEnd(16) + ROUTES.length);
["P", "F", "M", "A"].forEach(function (g) { console.log("    group " + g + " " + ("(" + GROUP_NAME[g] + ")").padEnd(17) + RA.GROUPS[g].length); });
check("1. every route has exactly one class", ROUTES.every(function (r) { return !!r.cls; }), ROUTES.length);
const listedKeys = [].concat(RA.PUBLIC, RA.FREE, RA.MEMBER, RA.ADMIN);
const twice = listedKeys.filter(function (k, i) { return listedKeys.indexOf(k) !== i; });
check("1. no route is in two groups", twice.length === 0, twice.join(", "));
sameSet("1. every live route is in exactly one group, and every grouped route is live (" + ROUTES.length + ")", keys(ROUTES), listedKeys);

console.log("\n══ 2. each group is what the router does ══");
const groupOf = function (k) { return RA.groupOf(k); };
const wrongP = ROUTES.filter(function (r) { return (groupOf(r.key) === "P") !== (r.cls === "unauthenticated"); });
check("2. P is exactly the routes with no sign-in (" + RA.PUBLIC.length + ")", wrongP.length === 0, wrongP.map(function (r) { return r.key + " (" + r.cls + ")"; }).join(", "));
/* NAMED (Nov 23 2026, LR-1): POST /api/leads/draft-reply and POST /api/agents/rd/demand-signals moved M -> A (owner by id, in the handler).
   Both call the model, so they keep requireActiveSubscription in their stacks (a login-only route must never spend, section 3).
   BEFORE M was exactly the gated routes. AFTER M is the gated routes but those owner-in-handler A routes. */
const inHandlerGated = function (r) { return RA.ADMIN_IN_HANDLER.indexOf(r.key) !== -1 && r.cls === "gated"; };
const wrongM = ROUTES.filter(function (r) { return (groupOf(r.key) === "M") !== (r.cls === "gated" && !inHandlerGated(r)); });
check("2. M is exactly the routes with requireActiveSubscription in front (" + RA.MEMBER.length + ")", wrongM.length === 0, wrongM.map(function (r) { return r.key + " (" + r.cls + ")"; }).join(", "));
const wrongA = ROUTES.filter(function (r) {
  const a = groupOf(r.key) === "A";
  const inHandler = RA.ADMIN_IN_HANDLER.indexOf(r.key) !== -1;
  return a !== (r.cls === "admin" || inHandler) || (inHandler && r.cls !== "login-only" && r.cls !== "gated");   // NAMED (Nov 23 2026, LR-1): BEFORE in-handler had to be login-only
});
check("2. A is exactly requireAdmin's routes and the owner-in-handler routes (" + RA.ADMIN.length + ")", wrongA.length === 0, wrongA.map(function (r) { return r.key + " (" + r.cls + ")"; }).join(", "));
// NAMED (Nov 23 2026, LR-2): + the archive's check by id in lib/leadRoutes.js (req.user.id !== deps.ownerId).
const OWNER_TEXT = /req\.user\.id !== deps\.ownerId|isOwnerAccount\(req\.user\.id\)|!== OUTREACH_CREDENTIAL_OWNER_ID|userId !== OWNER_ACCOUNT_ID/;   // NAMED (Nov 23 2026, LR-1): + demand-signals' owner check by id
const inHandlerNoCheck = RA.ADMIN_IN_HANDLER.filter(function (k) { const r = byKeyOf(k); return !r || !OWNER_TEXT.test(r.text); });
check("2. each owner-in-handler route's handler carries the owner check (" + RA.ADMIN_IN_HANDLER.length + ")", inHandlerNoCheck.length === 0, inHandlerNoCheck.join(", "));
const wrongF = ROUTES.filter(function (r) { return groupOf(r.key) === "F" && r.cls !== "login-only"; });
check("2. F is sign-in only (" + RA.FREE.length + ")", wrongF.length === 0, wrongF.map(function (r) { return r.key + " (" + r.cls + ")"; }).join(", "));
sameSet("2. the requireAdmin routes are exactly the " + EXPECTED_ADMIN.length + " reviewed", keys(of("admin")), EXPECTED_ADMIN);
/* NAMED (Nov 20 2026, P3-1): BEFORE section 2 held the gated set to EXPECTED_GATED. AFTER M (lib/routeAccess.js) is the set; every
   route EXPECTED_GATED reviewed must still be M, except the three P3-1 freed (posting, post photos, a new listing). */
/* NAMED (Nov 23 2026, LR-2): BEFORE LR-1 held POST /api/leads/draft-reply and POST /api/agents/rd/demand-signals in A (owner in
   the handler, still gated) and POST /api/agents/sales/send-approved in M with the owner check. AFTER LR-2 removed draft-reply,
   send-approved, convert and the pipeline routes, and made Lead Radar and the demand signals every member's: each is M and gated,
   and none of the removed routes is live or grouped. */
const REMOVED_BY_LR2 = ["post /api/leads/draft-reply", "post /api/agents/sales/send-approved", "post /api/agents/sales/convert",
  "post /api/agents/sales/lead-status", "get /api/agents/sales/leads", "get /api/agents/sales/pipeline", "get /api/leads/youtube-signals"];
const MEMBER_BY_LR2 = ["get /api/leads", "get /api/leads/fingerprint", "put /api/leads/fingerprint", "post /api/leads/fingerprint/rebuild",
  "post /api/leads/fingerprint/suggest", "get /api/leads/summary", "post /api/leads/:id/status", "post /api/leads/:id/draft", "post /api/leads/:id/send",
  "post /api/agents/rd/demand-signals"];
const removedLive = REMOVED_BY_LR2.filter(function (k) { return !!byKeyOf(k) || groupOf(k) !== null; });
check("2. LR-2: the old owner-only Lead Radar routes are gone (not live, in no group)", removedLive.length === 0, removedLive.join(", "));
const lr2NotGated = MEMBER_BY_LR2.filter(function (k) { return groupOf(k) !== "M" || !byKeyOf(k) || byKeyOf(k).cls !== "gated"; });
check("2. LR-2: Lead Radar's routes and the demand signals are members only (M, gated)", lr2NotGated.length === 0, lr2NotGated.join(", "));
check("2. LR-2: the owner's archive is A with the owner check by id in its handler, sign-in only",
  groupOf("get /api/leads/archive") === "A" && RA.ADMIN_IN_HANDLER.indexOf("get /api/leads/archive") !== -1 && !!byKeyOf("get /api/leads/archive") &&
  byKeyOf("get /api/leads/archive").cls === "login-only" && OWNER_TEXT.test(byKeyOf("get /api/leads/archive").text));
check("2. LR-1: GET /api/digital-cards/:id/leads is free (F, sign-in only)",
  groupOf("get /api/digital-cards/:id/leads") === "F" && !!byKeyOf("get /api/digital-cards/:id/leads") && byKeyOf("get /api/digital-cards/:id/leads").cls === "login-only");
const lostGate = EXPECTED_GATED.filter(function (k) { return FREED_BY_P31.indexOf(k) === -1 && REMOVED_BY_LR2.indexOf(k) === -1 && groupOf(k) !== "M"; });   // NAMED (Nov 23 2026, LR-2): BEFORE but the two LR-1 moved to A; AFTER but the routes LR-2 removed
check("2. every route reviewed as gated before P3-1 is still members only, but the three P3-1 freed and those LR-2 removed", lostGate.length === 0, lostGate.join(", "));
const freedOk = FREED_BY_P31.every(function (k) { return groupOf(k) === "F" && byKeyOf(k) && byKeyOf(k).cls === "login-only"; });
check("2. posting and post photos are free (F, sign-in only)", freedOk, FREED_BY_P31.map(function (k) { return k + " " + groupOf(k); }).join(", "));   // NAMED (Nov 21 2026, P3-1B): BEFORE "posting, post photos and a new listing"
const movedBad = MOVED_BY_P31B.filter(function (k) { return groupOf(k) !== "M" || !byKeyOf(k) || byKeyOf(k).cls !== "gated"; });
check("2. P3-1B: the " + MOVED_BY_P31B.length + " selling, campaign and BizCash routes the owner's rules moved are members only (M, gated)", movedBad.length === 0,
  movedBad.map(function (k) { return k + " " + groupOf(k) + " " + (byKeyOf(k) ? byKeyOf(k).cls : "missing"); }).join(", "));
check("2. P3-1B: the posts sitemap is public (P, no sign-in)", groupOf("get /api/sitemap/posts.xml") === "P" && !!byKeyOf("get /api/sitemap/posts.xml") && byKeyOf("get /api/sitemap/posts.xml").cls === "unauthenticated");
const disconnects = ROUTES.filter(function (r) { return /\/disconnect$/.test(r.key); });
check("2. every disconnect stays free (" + disconnects.length + ")", disconnects.length > 5 && disconnects.every(function (r) { return groupOf(r.key) === "F" && r.cls === "login-only"; }),
  disconnects.filter(function (r) { return groupOf(r.key) !== "F"; }).map(function (r) { return r.key; }).join(", "));

console.log("\n══ 3. no free route spends a model call ══");
const spenders = of("login-only").filter(function (r) { return r.fx.indexOf("MODEL") !== -1; });
check("3. no login-only route reaches callAnthropicText or a model client", spenders.length === 0, keys(spenders).join(", "));

console.log("\n══ 4. every free route with an effect, reviewed ══");
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
/* NAMED (Nov 20 2026, P3-1): BEFORE every reviewed route had to be login-only. AFTER P3-1 moved many of them behind
   requireActiveSubscription (M, lib/routeAccess.js); each such one is accounted for here, never stale, while it is M and gated. */
const nowMember = Object.keys(listed).filter(function (k) { const r = byKeyOf(k); return r && r.cls === "gated" && groupOf(k) === "M"; });
console.log("    reviewed before P3-1 and now members only: " + nowMember.length);
const stale = Object.keys(listed).filter(function (k) { const r = byKeyOf(k); return nowMember.indexOf(k) === -1 && (!r || r.cls !== "login-only" || !r.fx.length); });
check("4. every reviewed route still exists, is still login-only, and still has an effect", stale.length === 0,
  stale.map(function (k) { const r = byKeyOf(k); return k + (r ? " (" + r.cls + (r.fx.length ? "" : ", no effect") + ")" : " (not mounted)"); }).join(", "));
Object.keys(LISTS).forEach(function (name) { console.log("    " + name.padEnd(12) + LISTS[name].length); });

console.log("\n══ 5. every unauthenticated route that writes, reviewed ══");
const unauthWriters = of("unauthenticated").filter(function (r) { return r.fx.length; });
sameSet("5. the unauthenticated routes that write are exactly the " + Object.keys(EXPECTED_UNAUTH_WRITES).length + " reviewed",
  keys(unauthWriters), Object.keys(EXPECTED_UNAUTH_WRITES));
check("5. get /api/confirm is mounted, unauthenticated, and NOT a writer",
  of("unauthenticated").some(function (r) { return r.key === "get /api/confirm"; }) &&
  keys(unauthWriters).indexOf("get /api/confirm") === -1, keys(unauthWriters).join(", "));
const unauthSpend = unauthWriters.concat(of("unauthenticated")).filter(function (r) { return r.fx.indexOf("MODEL") !== -1; });
check("5. no unauthenticated route reaches a model call", unauthSpend.length === 0, keys(unauthSpend).join(", "));

(async function finish() {
  /* NAMED (Nov 20 2026, P3-1): BEFORE "public pages are served only while their owner is entitled". AFTER while their owner is in
     good standing (ownerPagePublic: the account exists, is not banned or deleted, and moderation has not hidden its profile).
     A free account's pages are public; the check account, which has no plan, is served now. */
  console.log("\n══ 6. public pages are served only while their owner is in good standing ══");
  Object.keys(EXPECTED_SERVE_GATED).forEach(function (k) {
    const r = byKeyOf(k);
    check("6. " + k + " is unauthenticated and its handler carries the owner check",
      !!r && r.cls === "unauthenticated" && r.text.indexOf(EXPECTED_SERVE_GATED[k]) !== -1,
      r ? r.cls + (r.text.indexOf(EXPECTED_SERVE_GATED[k]) === -1 ? ", no owner check" : "") : "not mounted");
  });
  const subject = resolveSubjectAccount();
  const { createClient } = require("@supabase/supabase-js");
  const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);
  const seed = await resolveEntitledAccount(supabase);
  const server = require(SERVER_PATH);
  const quietLog = console.log; console.log = function () {};
  const subjectPublic = await server.__ownerPagePublic(subject);
  const seedPublic = await server.__ownerPagePublic(seed.id);
  const ownerPublic = await server.__ownerPagePublic(OWNER_ACCOUNT_ID);
  const nobodyPublic = await server.__ownerPagePublic("00000000-0000-4000-8000-00000000dead");
  console.log = quietLog;
  check("6. a free account in good standing: its page is served (" + subject + ")", subjectPublic === true, String(subjectPublic));
  check("6. an entitled account's page is served (" + seed.email + ")", seedPublic === true, String(seedPublic));
  check("6. the owner's page is served", ownerPublic === true, String(ownerPublic));
  check("6. an id with no account: not served", nobodyPublic === false, String(nobodyPublic));
  const opp = (function () { const m = /async function ownerPagePublic\(userId\) \{/.exec(SRC); return m ? SRC.slice(m.index, braceMatch(SRC, SRC.indexOf("{", m.index))) : ""; })();
  check("6. ownerPagePublic reads standing (banned, deleted, moderation), never the plan, and fails closed",
    /banned_at/.test(opp) && /role === "deleted"/.test(opp) && /hiddenAmong\(supabase, "profile"/.test(opp) && opp.indexOf("getUserPlan") === -1 && opp.indexOf(" page hidden.\");" + "\n    return false;") !== -1, opp.slice(0, 200));

  console.log("\n══ 7. the gates inside handlers, and what a refusal says ══");
  Object.keys(EXPECTED_HANDLER_GATES).forEach(function (k) {
    const r = byKeyOf(k);
    check("7. " + k + " carries its gate in its handler (" + GROUP_NAME[groupOf(k)] + ")",
      !!r && (r.cls === "login-only" || r.cls === "gated") && r.text.indexOf(EXPECTED_HANDLER_GATES[k]) !== -1,
      r ? r.cls + (r.text.indexOf(EXPECTED_HANDLER_GATES[k]) === -1 ? ", gate text missing" : "") : "not mounted");
  });
  const refusal = server.__subscriptionRequiredBody({ inactive_reason: "no_subscription" }, "post /api/crowdfunding/campaigns");
  const panel = require(path.join(REPO, "lib", "membership.js")).membersPanelFromCode();
  check("7. a 402 keeps error and upgrade_required, adds message and billing_url, and carries the members panel",
    refusal.error === "Active subscription required" && refusal.upgrade_required === true && refusal.billing_url === "/billing.html" &&
    typeof refusal.message === "string" && refusal.members_only === true && refusal.tier_required === "member" &&
    JSON.stringify(refusal.members_panel) === JSON.stringify(panel) && panel.price_text === "$199 a month" && panel.join_url === "/billing.html", JSON.stringify(refusal).slice(0, 400));
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
