"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   lib/routeAccess.js — who may use each route (P3-1, Nov 20 2026).

   EVERY ROUTE HAS ONE GROUP, written down here, so the whole map can be read
   in one place and scripts/checkUnsubscribedSurface.js can hold the live
   router to it, route by route:
     P  public: no sign-in.
     F  free and member: sign-in only. A free account gets exactly the owner's
        list (lib/membership.js FREE_INCLUDES). NAMED (Nov 21 2026, P3-1B):
        BEFORE it included selling and listing in the Market and receiving
        tips and donations. AFTER: profile and @handle, photo posts and Needs,
        likes, saves, shares and follows, browsing the Market, comments on
        free accounts' posts, replies, Settings, Your data, Billing, the
        safety tools and the Inbox. The rules inside F routes (a share post's
        photo, no listing link, no comment on a member's post, no first
        message, no BizCash received) are held in the handlers.
     M  members only: requireActiveSubscription stands in front of the
        handler, and a free account is refused 402 with the members panel
        (server.js subscriptionRequiredBody, lib/membership.js membersPanel).
     A  the owner or an admin (requireAdmin, or the owner check in the handler
        of GET /api/admin/agent-learning and the five Lead Radar reads; see
        ADMIN_IN_HANDLER).

   INSIDE A MEMBER-ONLY TOOL, A FEW ROUTES STAY F ON PURPOSE. Removing your own
   data or a connection, or stopping something, never needs membership, so a
   member whose plan ends can always clear their records (Your data) and take
   their keys back: every DELETE of the account's own rows, every
   "disconnect", a connection's status (needed to disconnect), the automation
   switches (turning one ON is refused inside the handler without membership),
   rejecting a proposal, pausing a schedule, stopping an email sequence, and
   filing a Facebook post's removal.

   HOW M IS ENFORCED. Routes written with requireActiveSubscription in
   server.js keep it. For every other M route, applyRouteAccess(app, ...) puts
   the same requireActiveSubscription function into the live route's stack,
   directly after requireAuth, once every route is mounted (server.js, just
   above the 404 handler). The router then holds the gate exactly as if it had
   been written on the route line, which is what checkUnsubscribedSurface and
   checkFreeAccount read. A route the table does not name is left as written
   and logged; the check fails on it.
   ══════════════════════════════════════════════════════════════════════════ */

/* P: public, no sign-in (55; NAMED Nov 21 2026, P3-1B: + get /api/sitemap/posts.xml, the indexable members' posts). NAMED (Nov 21 2026, P3-2): the owner confirmed get /api/cards/google-wallet as P, served
   while the card's owner is in good standing (ownerPagePublic); cards are made by members only. */
const PUBLIC = Object.freeze([
  "get /", "get /api/bfp/artists/browse", "get /api/bfp/music/public/:userId", "get /api/bfp/pportfolio/public/:userId", "get /api/bfp/pproducts/public/:userId",
  "get /api/bfp/profile/:userId", "get /api/bfp/profile/:userId/stats", "get /api/bfp/seller/:handle", "get /api/bfp/services/browse",
  "get /api/bfp/videos/public/:userId", "get /api/billing/consent", "get /api/blog/:handle", "get /api/blog/:handle/:slug", "get /api/cards/google-wallet",
  "get /api/cards/share/:token", "get /api/cards/slug/:slug", "get /api/confirm", "get /api/follows/:userId/counts", "get /api/marketplace/listings/:id",
  "get /api/moon", "get /api/posts/by/:userId", "get /api/sitemap/blog.xml", "get /api/sitemap/campaigns.xml", "get /api/sitemap/cards.xml", "get /api/sitemap/posts.xml",
  "get /api/sitemap/support.xml", "get /api/unsubscribe", "get /api/your-data", "get /c/:slug", "get /campaign/:shareId", "get /card/:token",
  "get /health", "get /p/:id", "get /support/:username", "post /api/auth/login", "post /api/auth/password-reset", "post /api/auth/password-reset/confirm",
  "post /api/auth/refresh", "post /api/auth/register", "post /api/auth/verify-email", "post /api/capture", "post /api/cards/lead",
  "post /api/cards/tap", "post /api/confirm", "post /api/contacts/capture", "post /api/copyright/notices", "post /api/engine-visits",
  "post /api/sms/inbound", "post /api/store/woocommerce/callback", "post /api/unsubscribe", "post /api/webauthn/login/finish",
  "post /api/webauthn/login/start", "post /api/webhook", "post /api/webhooks/resend", "post /api/webhooks/shopify"
]);

/* F: free accounts and members, sign-in only (159; NAMED P3-1B: BEFORE 172). NAMED (Nov 21 2026, P3-2, the owner's decisions on P3-1's unsure list):
   themes/photo, pproducts and pportfolio stay F; post and put /api/bfp/videos moved to M (video uses the most storage); its
   delete and the member's own list stay F, so a free account can always remove its videos. POST /api/bfp/upload-url stays F,
   and refuses the videos and music folders inside the handler without a membership (server.js UPLOAD_URL_MEMBER_FOLDERS).
   media.html and business-id.html now show the members panel to a free account (scripts/bf-access.js MEMBER_PAGES): the media
   library's upload (post /api/media) was M already and its edit (patch /api/media/:id) moved to M; its delete stays F. The
   business ID page writes put /api/profile/me, which STAYS F: Settings (free) writes the same route for the business name,
   contact email, industry, website and location. */
const FREE = Object.freeze([
  "delete /api/agent-schedules/:agent_type", "delete /api/agents/:agentType/preferences/:id", "delete /api/agents/:id", "delete /api/ai/tasks",
  "delete /api/ai/tasks/:id", "delete /api/bfp/music/:id", "delete /api/bfp/pportfolio/:id", "delete /api/bfp/pproducts/:id",
  "delete /api/bfp/profile/design", "delete /api/bfp/videos/:id", "delete /api/birth-records/:id", "delete /api/bizbook/books/:id",
  "delete /api/bizdoc/documents/:id", "delete /api/blocks/:userId", "delete /api/calendar/events/:id", "delete /api/card-leads/:id",
  "delete /api/comments/:id", "delete /api/content-library/:id", "delete /api/cover-wraps/:id", "delete /api/crm/customers/:id",
  "delete /api/digital-cards/:id", "delete /api/follows/:userId", "delete /api/icp-profiles/:id", "delete /api/inner-iq/results/:id",
  "delete /api/inventory/items/:id", "delete /api/marketplace/listings/:id", "delete /api/media/:id", "delete /api/memory/:id",
  "delete /api/music/playlists/:id", "delete /api/music/tracks/:id", "delete /api/mutes/:userId", "delete /api/posts/:id", "delete /api/posts/:id/like",
  "delete /api/posts/:id/save", "delete /api/prospects/:id", "delete /api/push/subscribe", "delete /api/routines/:id", "delete /api/saved-prompts/:id",
  "delete /api/store/connections/:id", "delete /api/themes/:id", "delete /api/user/api-key", "delete /api/videos/:id", "delete /api/webauthn/credentials/:id",
  "get /api/auth/me", "get /api/bfp/music", "get /api/bfp/pportfolio", "get /api/bfp/pproducts", "get /api/bfp/profile/me", "get /api/bfp/profile/me/stats",
  "get /api/bfp/videos", "get /api/conversations", "get /api/copyright/counter/:id",  
     "get /api/facebook/status",
  "get /api/feed/following", "get /api/follows/:userId/:which", "get /api/gate-decisions", "get /api/gate-decisions/:id", "get /api/gate-decisions/for",
  "get /api/home/starter", "get /api/inbox/conversations", "get /api/inbox/counts", "get /api/inbox/person/:userId", "get /api/instagram/status",
  "get /api/mailbox/status", "get /api/marketplace/listings", "get /api/marketplace/my-listings", "get /api/marketplace/orders",
  "get /api/marketplace/orders/:id", "get /api/me/export", "get /api/me/place", "get /api/me/relation", "get /api/me/safety",
  "get /api/me/terms", "get /api/me/trade-statement", "get /api/me/trades", "get /api/me/trades.csv", "get /api/media", "get /api/media/:id/uses",
  "get /api/media/usage", "get /api/messages/:userId", "get /api/music", "get /api/music/player", "get /api/music/tracks/:id/url",
  "get /api/notifications", "get /api/posts/:id", "get /api/posts/:id/comments", "get /api/posts/saved", "get /api/profile/by-id/:userId",
  "get /api/profile/me", "get /api/purchases", "get /api/purchases/:orderId/download", "get /api/push/public-key", "get /api/social/bluesky/automation",
  "get /api/social/bluesky/status", "get /api/social/mastodon/automation", "get /api/social/mastodon/status", 
  "get /api/themes", "get /api/tiktok/status", "get /api/user/preferences",  "get /api/webauthn/credentials",
  "get /api/youtube/status", "patch /api/posts/:id", "post /api/auth/logout", "post /api/auth/resend-verification",
  "post /api/bfp/pportfolio",  "post /api/bfp/upload-check", "post /api/bfp/upload-url",
  "post /api/billing/portal", "post /api/blocks", "post /api/comments/:id/hide", "post /api/copyright/counter/:id", "post /api/email/sequences/:id/status",
  "post /api/facebook/disconnect", "post /api/facebook/posts/:id/propose-delete", "post /api/follows", "post /api/inbox/read/:userId",
  "post /api/instagram/disconnect", "post /api/mailbox/disconnect",  
  "post /api/me/delete", "post /api/me/terms/accept", "post /api/messages", "post /api/music/playlists", "post /api/mutes", "post /api/notifications/read-all",
  "post /api/posts", "post /api/posts/:id/comments", "post /api/posts/:id/like", "post /api/posts/:id/save", "post /api/posts/:id/share",
  "post /api/posts/photos", "post /api/proposals/:id/reject", "post /api/push/subscribe", "post /api/push/test", "post /api/reports",
  "post /api/social/bluesky/disconnect", "post /api/social/mastodon/disconnect", "post /api/stripe/checkout", "post /api/themes",
  "post /api/themes/photo", "post /api/themes/reset", "post /api/tiktok/disconnect", "post /api/webauthn/register/finish", "post /api/webauthn/register/start",
  "post /api/youtube/disconnect", "put /api/agent-schedules/:agent_type/pause", "put /api/bfp/pportfolio/:id", 
  "put /api/bfp/profile/design", "put /api/bfp/profile/me",  "put /api/me/place",
  "put /api/music/player", "put /api/music/playlists/:id", "put /api/music/tracks/:id", "put /api/notifications/:id/read", "put /api/profile/me",
  "put /api/social/bluesky/automation", "put /api/social/mastodon/automation",  "put /api/themes/:id",
  "put /api/themes/apply", "put /api/user/preferences"
]);

/* M: members only; requireActiveSubscription is in front of each (311; NAMED P3-1B: BEFORE 298). NAMED (Nov 21 2026, P3-2): the owner confirmed
   business-profile (M), campaign creation and donating (M; donating is sending BizCash), and added post and put
   /api/bfp/videos and patch /api/media/:id (media.html's edit). */
const MEMBER = Object.freeze([
  "delete /api/member-gates/:id", "delete /api/triggers/:id", "get /api/activity/overview", "get /api/agent-autonomy", "get /api/agent-schedules",
  "get /api/agents", "get /api/agents/:agentType/learning", "get /api/agents/:type", "get /api/agents/:type/live", "get /api/agents/feedback/:taskId",
  "get /api/agents/live", "get /api/agents/live/calendar", "get /api/agents/network", "get /api/agents/network/edge", "get /api/agents/seo/optimize-count",
  "get /api/agents/tool-specs", "get /api/ai/tasks", "get /api/ai/tasks/:id", "get /api/analytics/summary", "get /api/assignments",
  "get /api/assignments/:id", "get /api/birth-records", "get /api/bizbook/books", "get /api/bizbook/books/:id/cover", "get /api/bizbook/books/:id/download",
  "get /api/bizdoc/documents", "get /api/bizdoc/documents/:id", "get /api/business-chat", "get /api/business-profile", "get /api/calendar/events",
  "get /api/certifications/catalog", "get /api/certifications/earned", "get /api/command-center", "get /api/content-library",
  "get /api/cover-wraps", "get /api/cover-wraps/:id", "get /api/cover-wraps/:id/bg-image", "get /api/cover-wraps/:id/layer-image",
  "get /api/cover-wraps/:id/region-bg-image", "get /api/crm/customers", "get /api/crm/customers/:id/activities", "get /api/dashboard",
  "get /api/dashboard/pulse", "get /api/dashboard/top", "get /api/digital-cards", "get /api/digital-cards/:id/leads", "get /api/digital-cards/:id/stats",
  "get /api/editor/image", "get /api/email/sequences", "get /api/email/sequences/:id", "get /api/executive/cycles", "get /api/facebook/pages",
  "get /api/facebook/posts", "get /api/facebook/posts/:id/status", "get /api/guide/records/answer", "get /api/guide/suggestions",
  "get /api/icp-profiles", "get /api/inner-iq/results", "get /api/instagram/posts", "get /api/instagram/posts/:id/status", "get /api/inventory/items",
  "get /api/inventory/items/:id/movements", "get /api/mailbox/inbox", "get /api/mailbox/inbox/:uid", "get /api/member-gates",
  "get /api/member-gates/language", "get /api/memory", "get /api/memory/:id", "get /api/oracle", "get /api/oracle/invocation",
  "get /api/oracle/natal", "get /api/oracle/numerology", "get /api/oracle/sync", "get /api/proposals", "get /api/prospects",
  "get /api/routines", "get /api/saved-prompts", "get /api/self-reviews", "get /api/sms/campaigns", "get /api/sms/campaigns/:id/enrollments",
  "get /api/sms/campaigns/:id/messages", "get /api/sms/send-log", "get /api/sms/subscribers", "get /api/social-drafts", "get /api/social/accounts",
  "get /api/social/bluesky/mentions", "get /api/store/changes", "get /api/store/connections", "get /api/store/connections/:id/locations",
  "get /api/synastry/:recordId", "get /api/tiktok/creator-info", "get /api/tiktok/videos/:id/status", "get /api/triggers", "get /api/triggers/firings",
  "get /api/triggers/language", "get /api/user/api-key", "get /api/videos", "get /api/videos/:id/preview", "get /api/wallet/recipient",
  "get /api/youtube/videos/:id/status", "patch /api/calendar/events/:id", "patch /api/card-leads/:id", "patch /api/media/:id", "post /api/agents", "post /api/agents/:agentType/preferences",
  "post /api/agents/ads/copy", "post /api/agents/ads/policy-check", "post /api/agents/analytics/arrivals", "post /api/agents/analytics/funnel",
  "post /api/agents/analytics/kpi-review", "post /api/agents/broker/due-diligence", "post /api/agents/broker/term-sheet", "post /api/agents/community/audience",
  "post /api/agents/community/engagement-calendar", "post /api/agents/community/onboarding", "post /api/agents/content/audit",
  "post /api/agents/content/outline", "post /api/agents/email/propose-sequence", "post /api/agents/email/sequence", "post /api/agents/email/subject-lines",
  "post /api/agents/etsy/keyword-research", "post /api/agents/etsy/pricing-strategy", "post /api/agents/executive/plan", "post /api/agents/feedback/:taskId/pin",
  "post /api/agents/influencer/outreach", "post /api/agents/influencer/partnership-offer", "post /api/agents/operations/checklist",
  "post /api/agents/operations/sop", "post /api/agents/publicist/pitch", "post /api/agents/publicist/press-release", "post /api/agents/rd/brief",
  "post /api/agents/rd/competitor-scan", "post /api/agents/rd/demand-signals", "post /api/agents/reputation/review-request",
  "post /api/agents/reputation/review-response", "post /api/agents/sales/convert", "post /api/agents/seo/audit", "post /api/agents/seo/generate-post",
  "post /api/agents/seo/optimize", "post /api/agents/seo/social-search", "post /api/agents/social/calendar", "post /api/agents/social/post",
  "post /api/agents/social/propose-post", "post /api/agents/store/generate-proposals", "post /api/agents/store/stock-margin",
  "post /api/agents/vertical_marketing/claims-scan", "post /api/agents/vertical_marketing/objections", "post /api/agents/vertical_marketing/positioning",
  "post /api/ai-reports", "post /api/ai/tasks", "post /api/assignments/:id/start", "post /api/assignments/batch", "post /api/assignments/dispatch",
  "post /api/bfp/music", "post /api/bfp/videos", "post /api/birth-records", "post /api/bizbook/books/:id/cover", "post /api/bizbook/books/:id/cover-from-wrap",
  "post /api/bizbook/books/:id/generate-from-content", "post /api/bizbook/books/create-from-content", "post /api/bizbook/generate",
  "post /api/bizdoc/documents", "post /api/bizdoc/documents/:id/sign", "post /api/business-chat", "post /api/business-profile",
  "post /api/calendar/events", "post /api/cards/share-token", "post /api/certifications/award", "post /api/content-library",
  "post /api/content-library/:id/external-published", "post /api/content-library/empty", "post /api/cover-wraps", "post /api/cover-wraps/:id/bg-image",
  "post /api/cover-wraps/:id/export-pdf", "post /api/crm/customers", "post /api/crm/customers/:id/activities", "post /api/crowdfunding/campaigns",
  "post /api/crowdfunding/campaigns/:id/donate", "post /api/crowdfunding/campaigns/:id/share/new-link", "post /api/digital-cards",
  "post /api/editor/image", "post /api/executive/cycles", "post /api/executive/cycles/:id/approve", "post /api/executive/cycles/:id/discard",
  "post /api/executive/cycles/:id/review", "post /api/executive/cycles/:id/supersede", "post /api/facebook/choose-page", "post /api/facebook/draft-caption",
  "post /api/facebook/finish", "post /api/facebook/propose-post", "post /api/facebook/start", "post /api/guide/ask", "post /api/guide/records",
  "post /api/icp-profiles", "post /api/inner-iq/results", "post /api/insights/page", "post /api/instagram/draft-caption", "post /api/instagram/finish",
  "post /api/instagram/propose-post", "post /api/instagram/start", "post /api/inventory/items", "post /api/inventory/items/:id/movements",
  "post /api/leads/draft-reply", "post /api/mailbox/connect", "post /api/mailbox/inbox/:uid/draft-reply", "post /api/mailbox/microsoft/finish",
  "post /api/mailbox/microsoft/start", "post /api/mailbox/propose-reply", "post /api/marketplace/listings/:id/buy", "post /api/media",
  "post /api/member-gates", "post /api/member-gates/preview", "post /api/memory", "post /api/music/tracks", "post /api/oracle",
  "post /api/oracle/chat", "post /api/oracle/sync", "post /api/proposals", "post /api/proposals/:id/approve", "post /api/proposals/calendar-event",
  "post /api/prospects", "post /api/prospects/:id/convert", "post /api/routines", "post /api/routines/:id/run", "post /api/saved-prompts",
  "post /api/saved-prompts/:id/run", "post /api/self-reviews/run", "post /api/sms/campaigns", "post /api/sms/campaigns/:id/enroll",
  "post /api/sms/campaigns/:id/messages", "post /api/sms/run-engine", "post /api/sms/send", "post /api/sms/subscribers", "post /api/sms/subscribers/bulk",
  "post /api/social-drafts", "post /api/social/bluesky/connect", "post /api/social/bluesky/mentions/draft-reply", "post /api/social/bluesky/mentions/propose-reply",
  "post /api/social/bluesky/propose-profile", "post /api/social/connect/:platform", "post /api/social/mastodon/connect", "post /api/social/mastodon/propose-post",
  "post /api/store/amazon/finish", "post /api/store/amazon/start", "post /api/store/changes/:id/undo", "post /api/store/changes/propose",
  "post /api/store/connections", "post /api/store/connections/:id/sync", "post /api/store/etsy/finish", "post /api/store/etsy/start",
  "post /api/store/shopify/finish", "post /api/store/shopify/start", "post /api/tiktok/draft-caption", "post /api/tiktok/finish",
  "post /api/tiktok/propose-post", "post /api/tiktok/start", "post /api/triggers", "post /api/triggers/preview", "post /api/videos/finalize",
  "post /api/videos/part-done", "post /api/videos/part-url", "post /api/videos/upload-url", "post /api/wallet/support", "post /api/wallet/transfer",
  "post /api/youtube/draft-metadata", "post /api/youtube/finish", "post /api/youtube/propose-upload", "post /api/youtube/start",
  "post /api/youtube/videos/:id/propose-delete", "put /api/agent-autonomy", "put /api/agent-schedules", "put /api/agent-schedules/:agent_type/resume",
  "put /api/agents/:agentType/preferences/:id", "put /api/agents/:id", "put /api/agents/feedback/:taskId", "put /api/agents/network/links",
  "put /api/bfp/music/:id", "put /api/bfp/videos/:id", "put /api/bizbook/books/:id", "put /api/bizbook/books/:id/cover-design", "put /api/bizdoc/documents/:id",
  "put /api/business-profile", "put /api/cover-wraps/:id", "put /api/crm/customers/:id", "put /api/crowdfunding/campaigns/:id",
  "put /api/crowdfunding/campaigns/:id/share", "put /api/digital-cards/:id", "put /api/executive/cycles/:id", "put /api/icp-profiles/:id",
  "put /api/inventory/items/:id", "put /api/member-gates/:id", "put /api/prospects/:id", "put /api/routines/:id", "put /api/saved-prompts/:id",
  "put /api/social-drafts/:id", "put /api/store/connections/:id/location", "put /api/triggers/:id", "put /api/user/api-key",
  /* NAMED (Nov 21 2026, P3-1B, the owner's final rules): moved from F. Selling (creating and changing a Market listing, garage
     sales and services among them, its digital file, the profile's products), campaigns (reading them as their owner and the
     donations), and BizCash in every form (the wallet, the support page's settings). A free account keeps deleting its own
     listings and products and reading its own listings and orders (F). */
  "post /api/marketplace/listings", "put /api/marketplace/listings/:id", "post /api/marketplace/upload-digital", "post /api/bfp/pproducts", "put /api/bfp/pproducts/:id", "get /api/crowdfunding/campaigns", "get /api/crowdfunding/campaigns/by-share/:shareId", "get /api/crowdfunding/my-campaigns", "get /api/crowdfunding/donations", "get /api/crowdfunding/donations/:id", "get /api/support/me", "put /api/support/me", "get /api/wallet"
]);

/* A: the owner or an admin (23). NAMED (Nov 21 2026, P3-2): the owner confirmed Lead Radar (A, the owner) until the
   Radar-for-every-member block, and added get /api/admin/verified and post /api/admin/unverify/:userId (the Verified badge). */
const ADMIN = Object.freeze([
  "get /api/admin/agent-learning", "get /api/admin/flagged-accounts", "get /api/admin/health", "get /api/admin/moderation", "get /api/admin/moderation/item/:id",
  "get /api/admin/moderation/storage", "get /api/admin/shopify-data-requests", "get /api/admin/verified", "get /api/agents/sales/leads", "get /api/agents/sales/pipeline",
  "get /api/leads", "get /api/leads/youtube-signals", "post /api/admin/ban/:userId", "post /api/admin/flag/:userId", "post /api/admin/moderation/item/:id/decide",
  "post /api/admin/moderation/notice/:id/court-filed", "post /api/admin/price-change-notice", "post /api/admin/shopify-data-requests/:id/answered",
  "post /api/admin/store-proposals/run", "post /api/admin/unban/:userId", "post /api/admin/unverify/:userId", "post /api/admin/verify/:userId", "post /api/agents/sales/lead-status"
]);

/* Routes in A whose admin check is in the handler rather than requireAdmin. */
/* A by the owner check inside the handler, not requireAdmin: the owner's learning report, and the five Lead Radar routes
   that read the owner's own leads (LEAD_RADAR_UNAVAILABLE, 403 for every other account; checkLeadRadarOwnerGate). */
const ADMIN_IN_HANDLER = Object.freeze(["get /api/admin/agent-learning", "get /api/leads", "get /api/leads/youtube-signals",
  "get /api/agents/sales/leads", "post /api/agents/sales/lead-status", "get /api/agents/sales/pipeline"]);

const GROUPS = Object.freeze({ P: PUBLIC, F: FREE, M: MEMBER, A: ADMIN });
const GROUP_OF = (function () {
  const out = Object.create(null);
  Object.keys(GROUPS).forEach(function (g) { GROUPS[g].forEach(function (k) { out[k] = g; }); });
  return out;
})();

function routeKey(method, routePath) { return String(method).toLowerCase() + " " + routePath; }
function groupOf(key) { return GROUP_OF[key] || null; }

/* Puts `gates.requireActiveSubscription` in front of every M route that lacks
   it, right after requireAuth. Returns what it did and what does not match,
   and logs the same. Never throws: a mismatch must be seen (the check fails
   on it), not stop the server. */
function applyRouteAccess(app, gates, log) {
  const say = log || console;
  const Layer = require("express/lib/router/layer");
  const summary = { routes: 0, inserted: [], unlisted: [], mismatched: [] };
  const stack = (app && app._router && app._router.stack) || [];
  stack.forEach(function (l) {
    if (!l.route) return;
    Object.keys(l.route.methods).forEach(function (method) {
      summary.routes++;
      const key = routeKey(method, l.route.path);
      const g = groupOf(key);
      const fns = l.route.stack.map(function (s) { return s.handle; });
      const hasAuth = fns.indexOf(gates.requireAuth) !== -1;
      const hasSub = fns.indexOf(gates.requireActiveSubscription) !== -1;
      const hasAdmin = fns.indexOf(gates.requireAdmin) !== -1;
      if (!g) { summary.unlisted.push(key); return; }
      if (g === "M" && !hasSub) {
        const at = fns.indexOf(gates.requireAuth);
        if (at === -1) { summary.mismatched.push(key + " (M without requireAuth)"); return; }
        const layer = Layer("/", {}, gates.requireActiveSubscription);
        layer.method = method;
        l.route.stack.splice(at + 1, 0, layer);
        summary.inserted.push(key);
        return;
      }
      if (g === "F" && (!hasAuth || hasSub || hasAdmin)) summary.mismatched.push(key + " (F)");
      if (g === "P" && (hasAuth || hasSub || hasAdmin)) summary.mismatched.push(key + " (P)");
      if (g === "A" && !hasAdmin && ADMIN_IN_HANDLER.indexOf(key) === -1) summary.mismatched.push(key + " (A)");
    });
  });
  say.log("[route-access] " + summary.routes + " route(s): P " + PUBLIC.length + ", F " + FREE.length + ", M " + MEMBER.length +
    ", A " + ADMIN.length + "; members-only gate added in front of " + summary.inserted.length + ".");
  if (summary.unlisted.length) say.error("[route-access] NOT IN lib/routeAccess.js (left as written): " + summary.unlisted.join(", "));
  if (summary.mismatched.length) say.error("[route-access] DOES NOT MATCH its group: " + summary.mismatched.join(", "));
  return summary;
}

module.exports = { PUBLIC, FREE, MEMBER, ADMIN, ADMIN_IN_HANDLER, GROUPS, routeKey, groupOf, applyRouteAccess };
