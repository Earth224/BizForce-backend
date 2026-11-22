/* ═══════════════════════════════════════════════════════════════════════════
   checkFreeAccount.js — free accounts and the one membership (P3-1, Nov 20 2026;
   lib/membership.js, lib/routeAccess.js).

   WHAT IT PROVES
     A. THE OWNER'S LISTS: what a free account gets (eight lines) and what
        membership adds (eight lines) are lib/membership.js's, word for word.
     B. EVERY LINE IS THE ROUTES: each free line's routes are F (sign-in only)
        and each member line's routes are M (members only), read from
        lib/routeAccess.js and held to the live router by
        checkUnsubscribedSurface. Removing (disconnecting, deleting) is free.
     C. THE PRICE IS CODE'S: the members panel is $199 a month from
        PLAN_CONFIG.all_access (lib/legalPages.js codeFacts), with Join to
        /billing.html; the membership is paid in real money only: the Stripe
        checkout never reads or moves BizCash.
     D. ONE WORD FOR THE TIER: accessTier (server.js) is "member" only while
        the plan answer is active (a paying member, the owner, an admin);
        everything else is "free". /api/auth/me carries it in access.tier.
     E. "BIZFORCE MEMBER" ONLY FOR MEMBERS: the public profile and the
        storefront answer member from ownerIsMember, which reads the plan and
        answers false when the lookup throws (never shown on a guess).
     F. A PUBLIC PAGE IS GOOD STANDING, NOT A PLAN: ownerPagePublic never asks
        the plan (a free account's pages are public).
     G. THE APP (scripts/bf-access.js in a vm over a small fake page): a free
        account on a member-only page sees the members panel (the server's
        price, the eight lines, Join to billing.html, Go to Home); a member, an
        unreadable answer and a free page see none; the bottom bar's HQ tab
        opens the panel for a free account only; every member-only page loads
        it through bf-session.js; app.html lands a free account on Home and a
        member on the dashboard; the wallet says who may send; an unconfirmed
        email gets the banner, whose "Resend email" posts to
        /api/auth/resend-verification.
     NAMED (Nov 21 2026, P3-1B, the owner's final rules): BEFORE seven free
     lines (selling, receiving BizCash and messaging included) and nine member
     lines. AFTER eight and eight (A, B): selling, BizCash in every form,
     text-only posts, comments on members' posts, starting conversations and
     Google optimisation are members only; the selling, campaign and wallet
     routes moved to M.
     I. THE SERVER REFUSES: a BizCash credit to a free account (transfer,
        support, purchase, donation) is 409 recipient_free with one sentence to
        the payer, before anything moves; starting a conversation is 403 with
        the members panel; lib/posts.js gets the tier from postDeps.
     J. THE APP FOR A FREE ACCOUNT: Buy opens the card-checkout-coming sheet;
        a create button, Message and the Create sheet's members entries open
        the members panel; a ?create= link on the Market opens it too; a
        member sees none of it. The Create sheet tags its members entries
        "Members"; the composer, Talk and the Inbox carry their sentences.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");

const SERVER = "@server.js", MEM = "@lib/membership.js", RA = "@lib/routeAccess.js";
// NAMED (Nov 20 2026, P3-1): the app's files (the frontend), read by section G
const ACCESS = "scripts/bf-access.js", APP = "app.html", SESSION = "scripts/bf-session.js", WALLET = "wallet.html";
const MUTATIONS = {
  "messaging-members-only": [[RA, "\"post /api/me/delete\", \"post /api/me/terms/accept\", \"post /api/messages\", ", "\"post /api/me/delete\", \"post /api/me/terms/accept\", "],
                             [RA, "\"post /api/wallet/support\", \"post /api/wallet/transfer\",", "\"post /api/wallet/support\", \"post /api/wallet/transfer\", \"post /api/messages\","]],
  "transfer-free": [[RA, "\"post /api/wallet/support\", \"post /api/wallet/transfer\",", "\"post /api/wallet/support\","],
                    [RA, "\"post /api/me/delete\", \"post /api/me/terms/accept\", \"post /api/messages\", ", "\"post /api/me/delete\", \"post /api/me/terms/accept\", \"post /api/messages\", \"post /api/wallet/transfer\", "]],
  // NAMED (Nov 21 2026, P3-1B): BEFORE the Oracle was its own line ("  \"the Oracle\",\n", removed). AFTER it ends the agents' line.
  "oracle-line-dropped": [[MEM, "HQ and the orbit, and the Oracle\",\n", "HQ and the orbit\",\n"]],
  "tier-any-plan": [[SERVER, "  return planState && planState.active === true ? \"member\" : \"free\";", "  return planState ? \"member\" : \"free\";"]],
  "member-on-a-guess": [[SERVER, " — shown as not a member.\");\n    return false;", " — shown as not a member.\");\n    return true;"]],
  "price-typed": [[MEM, "    price_text: \"$\" + Number(price) + \" a \" + per,", "    price_text: \"$99 a month\","]],
  // NAMED (Nov 21 2026, P3-2): BEFORE the anchor ended "(userId)\n"; AFTER "(userId),\n", the Verified badge's key follows it.
  "storefront-always-member": [[SERVER, "      member: await ownerIsMember(userId),\n", "      member: true,\n"]],
  // the app: the HQ tab goes to the dashboard for everyone
  "hq-tab-open": [[ACCESS, "    if (!a || state.tier !== \"free\") return;\n", "    return;\n"]],
  // the app: a free account lands on the dashboard
  "landing-dashboard": [[APP, "go(d && d.access && d.access.tier === \"free\" ? \"/home.html\" : \"/dashboard.html\");", "go(\"/dashboard.html\");"]],
  // the app: the dashboard is no longer a member-only page
  "dashboard-unpaneled": [[ACCESS, "    \"dashboard.html\", \"agents-hub.html\",", "    \"agents-hub.html\","]],
  // the app: the panel's price typed in the page
  "panel-price-typed": [[ACCESS, "    box.appendChild(el(\"p\", \"bfa-price\", p.price_text || \"\"));", "    box.appendChild(el(\"p\", \"bfa-price\", \"$199 a month\"));"]],
  // the app: bf-session.js stops loading the access script
  "session-no-access": [[SESSION, "    loadTabBar();\n    loadAccess();\n", "    loadTabBar();\n"]],
  // the members panel no longer comes with /api/auth/me
  "me-no-panel": [[SERVER, "          members_panel: require(\"./lib/membership\").membersPanelFromCode()\n", "          members_panel: null\n"]],
  // NAMED (Nov 21 2026, P3-2): the owner's route decisions (section H)
  // adding a video goes back to sign-in only
  "videos-free": [[RA, "\"post /api/bfp/music\", \"post /api/bfp/videos\", ", "\"post /api/bfp/music\", "]],
  // the upload URL no longer refuses a free account for the videos and music folders
  "upload-url-ungated": [[SERVER, "  if (UPLOAD_URL_MEMBER_FOLDERS.indexOf(folder) !== -1 && (await refuseUnlessSubscribed(req, res, \"post /api/bfp/upload-url \" + folder))) return;\n", ""]],
  // the media library shows a free account no members panel
  // NAMED (Nov 21 2026, P3-1B): BEFORE the anchor ended "business-id.html\"\n"; AFTER P3-1B's pages follow it.
  "media-page-free": [[ACCESS, "    \"media.html\", \"business-id.html\",\n", "    \"business-id.html\",\n"]],
  // NAMED (Nov 21 2026, P3-1B): the owner's final rules
  // creating a listing goes back to free
  "listing-free-again": [[RA, "\"post /api/marketplace/listings\", \"put /api/marketplace/listings/:id\", ", ""],
                         [RA, "\"post /api/me/delete\", \"post /api/me/terms/accept\", ", "\"post /api/me/delete\", \"post /api/me/terms/accept\", \"post /api/marketplace/listings\", \"put /api/marketplace/listings/:id\", "]],
  // a free seller is paid for a sale
  "buy-pays-free": [[SERVER, "      if (!(await ownerIsMember(priced.seller_id))) {", "      if (false && !(await ownerIsMember(priced.seller_id))) {"]],
  // a free campaign owner takes a donation
  "donate-to-free": [[SERVER, "    if (!(await ownerIsMember(campaign.owner_id))) {", "    if (false && !(await ownerIsMember(campaign.owner_id))) {"]],
  // a free account starts a conversation
  "free-starts-chat": [[SERVER, "accessTier(await getUserPlan(req.user.id, req.user)) !== \"member\"", "false"]],
  // the app: Buy goes through for a free account
  "buy-sheet-off": [[ACCESS, "    if (e.target.closest(BUY_ACTIONS.join(\",\"))) { e.preventDefault(); e.stopPropagation(); showBuySheet(); return; }\n", ""]],
  // the app: a create button opens the form for a free account
  "create-unpaneled": [[ACCESS, "  var MEMBER_ACTIONS = [\".create-btn\", ", "  var MEMBER_ACTIONS = ["]],
  // the app: the wallet is no longer a member-only page
  "wallet-free": [[ACCESS, "    \"wallet.html\", \"receipts.html\", ", "    \"receipts.html\", "]]
};
const TABBAR = "scripts/bf-tabbar.js", COMPOSER = "scripts/bf-composer.js", FEED = "scripts/bf-feed.js", INBOX = "inbox.html";   // NAMED (Nov 21 2026, P3-1B)
const T = H.setup(__filename, MUTATIONS, [SERVER, MEM, RA, ACCESS, APP, SESSION, WALLET, TABBAR, COMPOSER, FEED, INBOX]);
const { FILES, check, finish, J, has } = T;
const S = FILES[SERVER] || "";
const M = T.libRequire("./lib/membership");
const R = T.libRequire("./lib/routeAccess");

function fnText(src, sig) {
  const at = src.indexOf(sig);
  return at < 0 ? "" : src.slice(at, require("./_shared").braceMatch(src, src.indexOf("{", at)) + 1);
}

/* Each line of the two lists, and the routes it is. */
/* NAMED (Nov 21 2026, P3-1B, the owner's final rules): BEFORE seven free lines (with selling, receiving BizCash and messaging)
   and nine member lines. AFTER eight and eight. A line whose rule lives inside a route (the photo rule, the comment rule,
   reply-only messaging, Show in Google) lists the route here, and section I and checkPosts, checkSocialGraph, checkInbox and
   checkPublicPostPage prove the rule. Buying by card has no route yet (Stripe, later): its line lists the browsing reads. */
const FREE_ROUTES = {
  "an account, a profile and @handle (name, photo, bio and banner, inside 50 MB)": ["get /api/bfp/profile/me", "put /api/bfp/profile/me", "put /api/bfp/profile/design", "get /api/profile/me", "put /api/profile/me"],
  "posting photos (a share post needs at least one photo) and short video": ["post /api/posts", "post /api/posts/photos", "patch /api/posts/:id", "delete /api/posts/:id"],
  "posting a Need: asking for help, with text and an optional photo": ["post /api/posts", "post /api/posts/photos"],
  "liking, saving, sharing and following, and watching the feed": ["post /api/posts/:id/share", "get /api/posts/saved", "post /api/follows", "delete /api/follows/:userId", "get /api/feed/following"],
  "browsing the Market and viewing listings; buying by card arrives later": ["get /api/marketplace/listings", "get /api/marketplace/my-listings", "delete /api/marketplace/listings/:id"],
  "commenting on posts by other free accounts": ["post /api/posts/:id/comments", "get /api/posts/:id/comments", "delete /api/comments/:id"],
  "replying in a conversation a member started with you": ["post /api/messages", "get /api/messages/:userId"],
  "the safety tools (report, block and mute), Settings, Your data, Billing and the Inbox": ["post /api/reports", "post /api/blocks", "delete /api/blocks/:userId", "post /api/mutes",
    "get /api/user/preferences", "put /api/user/preferences", "get /api/me/export", "post /api/me/delete", "post /api/stripe/checkout", "post /api/billing/portal", "get /api/inbox/conversations", "get /api/notifications"]
};
const MEMBER_ROUTES = {
  "selling: offer posts, Market listings, garage sales and services, and linking a product or service to a post": ["post /api/marketplace/listings", "put /api/marketplace/listings/:id",
    "post /api/marketplace/upload-digital", "post /api/bfp/pproducts", "put /api/bfp/pproducts/:id"],
  "BizCash in every form, starting with 1,000 BizCash: receiving tips, donations, support and sales, sending it, and the wallet" /* NAMED (Nov 21 2026, P3-1C): BEFORE "BizCash in every form: receiving tips, ..." */: ["get /api/wallet", "post /api/wallet/transfer", "post /api/wallet/support",
    "post /api/crowdfunding/campaigns/:id/donate", "post /api/marketplace/listings/:id/buy", "get /api/wallet/recipient", "get /api/support/me", "put /api/support/me", "get /api/crowdfunding/donations"],
  "text-only posts, commenting on members' posts and starting conversations": [],
  "showing your posts in Google, with your own search title and description": [],
  "the 18 AI agents and every agent page, HQ and the orbit, and the Oracle": ["get /api/agents", "get /api/agents/:type", "put /api/agents/:id", "get /api/agents/live",
    "get /api/command-center", "get /api/agents/network", "get /api/agents/live/calendar", "get /api/oracle", "post /api/oracle/sync", "get /api/oracle/natal", "get /api/oracle/numerology"],
  "social publishing and auto-posting, store connections and analytics": ["post /api/social/connect/:platform", "post /api/social/mastodon/propose-post", "post /api/social-drafts", "get /api/social/accounts",
    "get /api/store/connections", "post /api/store/connections", "get /api/analytics/summary", "get /api/dashboard/pulse"],
  "the business tools: CRM, prospects, ICP, inventory, calendar, BizDoc, BizBook, cover wraps, certifications, Inner IQ and the Guide": [
    "post /api/crm/customers", "post /api/prospects", "post /api/icp-profiles", "post /api/inventory/items", "post /api/calendar/events", "post /api/bizdoc/documents",
    "post /api/bizbook/generate", "post /api/cover-wraps", "post /api/certifications/award", "post /api/inner-iq/results", "post /api/guide/ask"],
  "music uploads, digital cards and Google Wallet passes, campaigns and media library uploads outside posts": ["post /api/bfp/music", "post /api/music/tracks", "post /api/digital-cards", "put /api/digital-cards/:id",
    "post /api/crowdfunding/campaigns", "get /api/crowdfunding/campaigns", "get /api/crowdfunding/my-campaigns", "post /api/media"]
};

(async function main() {
  console.log("\n══ A. the owner's lists ══");
  // NAMED (Nov 21 2026, P3-1B): BEFORE "the seven lines" and "the nine lines". AFTER the owner's final eight and eight.
  check("A1. a free account gets the eight lines, in order", J(M.FREE_INCLUDES) === J(Object.keys(FREE_ROUTES)), J(M.FREE_INCLUDES));
  check("A2. membership adds the eight lines, in order", J(M.MEMBER_ADDS) === J(Object.keys(MEMBER_ROUTES)), J(M.MEMBER_ADDS));

  console.log("\n══ B. every line is the routes ══");
  Object.keys(FREE_ROUTES).forEach((line, i) => {
    const bad = FREE_ROUTES[line].filter(k => R.groupOf(k) !== "F");
    check("B" + (i + 1) + ". free: " + line + " (" + FREE_ROUTES[line].length + " routes F)", bad.length === 0, bad.map(k => k + " " + R.groupOf(k)).join(", "));
  });
  Object.keys(MEMBER_ROUTES).forEach((line, i) => {
    const bad = MEMBER_ROUTES[line].filter(k => R.groupOf(k) !== "M");
    check("B" + (i + 9) + ". members: " + line + " (" + MEMBER_ROUTES[line].length + " routes M)", bad.length === 0, bad.map(k => k + " " + R.groupOf(k)).join(", "));
  });
  /* Removing is free. Two deletes were members only in their own route lines before P3-1 (the agents' member gates and
     triggers, member-only tools whose rules only a member can make); P3-1 gated no delete and no disconnect. */
  const disconnects = R.MEMBER.filter(k => /\/disconnect$/.test(k));
  const gatedByP31 = R.MEMBER.filter(k => /^delete /.test(k)).filter(k => {
    const p = k.slice(7);
    return !has(S, "app.delete(\"" + p + "\", requireAuth, requireActiveSubscription,");
  });
  check("B17. removing is free: no disconnect is members only, and P3-1 made no delete members only", disconnects.length === 0 && gatedByP31.length === 0, disconnects.concat(gatedByP31).join(", "));
  check("B18. ...the two deletes gated before P3-1 are the member gates' and the triggers'", J(R.MEMBER.filter(k => /^delete /.test(k)).sort()) === J(["delete /api/member-gates/:id", "delete /api/triggers/:id"]));

  console.log("\n══ C. the price is code's, and paid in money ══");
  const facts = require("../lib/legalPages").codeFacts();
  const panel = M.membersPanel(facts.price, facts.interval);
  check("C1. PLAN_CONFIG.all_access is $199 a month", facts.price === 199 && facts.interval === "month", J([facts.price, facts.interval]));
  check("C2. the members panel: \"Members get this\", $199 a month, the eight lines, Join to /billing.html",
    panel.title === "Members get this" && panel.price_text === "$199 a month" && panel.price_usd === 199 && J(panel.adds) === J(M.MEMBER_ADDS) &&
    panel.join_url === "/billing.html" && panel.join_label === "Join", J(panel));
  check("C3. lib/membership.js never types the price", !/199/.test(FILES[MEM] || ""));
  const checkout = H.routeStatement(S, "post", "/api/stripe/checkout") || fnText(S, 'app.post("/api/stripe/checkout"');
  check("C4. the Stripe checkout never reads or moves BizCash", checkout.length > 200 && !/bfc_|BizCash|bfc_wallets|wallet/i.test(checkout), checkout.length);

  console.log("\n══ D. one word for the tier ══");
  const tierText = fnText(S, "function accessTier(planState) {");
  const accessTier = new Function(tierText + "\nreturn accessTier;")();
  check("D1. member only while the plan answer is active; anything else free",
    accessTier({ active: true }) === "member" && accessTier({ active: false, exempt: true }) === "free" && accessTier({ active: "true" }) === "free" && accessTier(null) === "free" && accessTier(undefined) === "free");
  check("D2. /api/auth/me carries access.tier from the same answer", has(S, "          tier: accessTier(planState),\n"));

  console.log("\n══ E. \"BizForce member\" only for members ══");
  const oim = fnText(S, "async function ownerIsMember(userId) {");
  const ownerIsMember = (plan) => new Function("accessTier", "getUserPlan", "console", oim + "\nreturn ownerIsMember;")(accessTier, plan, { error() {} });
  check("E1. ownerIsMember: true for an active plan, false for a lapsed one, false when the lookup throws, false for no id",
    (await ownerIsMember(async () => ({ active: true }))("u")) === true && (await ownerIsMember(async () => ({ active: false }))("u")) === false &&
    (await ownerIsMember(async () => { throw new Error("down"); })("u")) === false && (await ownerIsMember(async () => ({ active: true }))(null)) === false);
  // NAMED (Nov 21 2026, P3-2): BEFORE the profile line ended "member: data ? await ownerIsMember(userId) : false });". AFTER the
  // Verified badge's key follows it on the same line.
  check("E2. the public profile and the storefront answer member from ownerIsMember", has(S, "member: data ? await ownerIsMember(userId) : false, verified: data ? await verifiedReasonOf(userId) : null });") && has(S, "      member: await ownerIsMember(userId),\n"));   // NAMED (Nov 21 2026, P3-2): BEFORE the storefront line ended the object (no comma); AFTER verified follows it

  console.log("\n══ F. a public page is good standing ══");
  const opp = fnText(S, "async function ownerPagePublic(userId) {");
  check("F1. ownerPagePublic never asks the plan", opp.length > 100 && !/getUserPlan|requireActiveSubscription|accessTier/.test(opp), opp.length);

  /* ── G. THE APP (the frontend): scripts/bf-access.js run in a vm over a small fake page; app.html, bf-session.js and
     wallet.html read. browserCheckPhone runs the real pages at 360, 390 and 430. */
  console.log("\n══ G. the app ══");
  // a price the page could not have typed: the panel must show what the server sends
  const ME_PANEL = M.membersPanel(123, "month");
  async function page(name, access) {
    const byId = {}, clicks = [];
    function node(tag) {
      const n = { tag, children: [], attrs: {}, className: "", textContent: "", hidden: false, parentNode: null, listeners: {},
        set id(v) { this._id = v; byId[v] = this; }, get id() { return this._id; },
        setAttribute(k, v) { this.attrs[k] = v; }, appendChild(c) { c.parentNode = this; this.children.push(c); if (c._id) byId[c._id] = c; return c; },
        insertBefore(c) { c.parentNode = this; this.children.unshift(c); return c; }, removeChild(c) { this.children = this.children.filter(x => x !== c); delete byId[c._id]; },
        addEventListener(t, f) { this.listeners[t] = f; }, focus() {},
        querySelector(sel) { const cls = sel.replace(/^\./, ""); let hit = null; (function walk(x) { x.children.forEach(c => { if (!hit && (" " + c.className + " ").indexOf(" " + cls + " ") !== -1) hit = c; walk(c); }); })(this); return hit; },
        get firstChild() { return this.children[0] || null; } };
      return n;
    }
    const body = node("body"), head = node("head");
    const document = { readyState: "complete", body, head, documentElement: node("html"), createElement: node,
      getElementById: id => { const n = byId[id]; if (!n) return null; let x = n; while (x && x !== body && x !== head) x = x.parentNode; return x ? n : null; },
      addEventListener: (t, f) => { if (t === "click") clicks.push(f); } };
    const fetched = [];
    const ctx = { window: {}, document, localStorage: { getItem: k => (k === "bf_token" ? "tok" : null) }, Promise, JSON, String, Array, Object,
      setTimeout, console: { log() {}, error() {} } };
    // NAMED (Nov 21 2026, P3-1B): a name may carry a query (marketplace.html?create=product)
    ctx.window.location = { pathname: "/" + name.split("?")[0], search: name.indexOf("?") !== -1 ? "?" + name.split("?")[1] : "" };
    ctx.window.fetch = (url, o) => { fetched.push([url, o && o.method]); return Promise.resolve({ ok: true, json: () => Promise.resolve(url.indexOf("/api/auth/me") !== -1 ? { access } : { message: "We sent a new link." }) }); };
    ctx.fetch = ctx.window.fetch; ctx.location = ctx.window.location;
    require("vm").createContext(ctx);
    require("vm").runInContext(FILES[ACCESS] || "", ctx);
    const got = ctx.window.bfAccess ? await ctx.window.bfAccess.ready : null;
    const panel = document.getElementById("bf-members-panel"), banner = document.getElementById("bf-verify-banner");
    const texts = n => !n ? "" : [n.textContent].concat(n.children.map(texts)).join(" ");
    const hq = (fn) => { let prevented = false; const a = { closest: s => (s.indexOf('data-tab="hq"') !== -1 ? {} : null) }; fn({ target: a, preventDefault: () => { prevented = true; } }); return prevented; };
    return { got, panel, banner, text: texts(panel), bannerText: texts(banner), fetched, clicks, hq, ctx, document };
  }
  const free = { tier: "free", active: false, email_verified: true, members_panel: ME_PANEL };
  const member = { tier: "member", active: true, email_verified: true, members_panel: ME_PANEL };
  let pg = await page("dashboard.html", free);
  const join = pg.panel && pg.panel.querySelector(".bfa-join");
  check("G1. a free account on the dashboard: the members panel, \"Members get this\", the price from the server, the eight lines, Join to billing.html",
    !!pg.panel && /Members get this/.test(pg.text) && pg.text.indexOf(ME_PANEL.price_text) !== -1 && M.MEMBER_ADDS.every(l => pg.text.indexOf(l) !== -1) && join && join.href === "/billing.html", pg.text.slice(0, 200));
  check("G2. ...and Go to Home", /Go to Home/.test(pg.text));
  pg = await page("agents/sales.html", free);
  check("G3. an agent page is member-only too (agents/sales.html)", !!pg.panel);
  pg = await page("dashboard.html", member);
  check("G4. a member on the dashboard: no panel", !pg.panel && pg.got && pg.got.tier === "member");
  pg = await page("dashboard.html", null);
  check("G5. an answer that cannot be read: no panel, no banner (nothing guessed)", !pg.panel && !pg.banner && pg.got && pg.got.tier === null);
  pg = await page("home.html", free);
  check("G6. Home is free: no panel", !pg.panel);
  // NAMED (Nov 21 2026, P3-1B): BEFORE one click listener. AFTER two: P3-1B's Buy and members intercept, then the HQ tab's.
  check("G7. the bottom bar's HQ tab opens the panel for a free account, instead of the dashboard", pg.clicks.length === 2 && pg.hq(pg.clicks[1]) === true && !!pg.document.getElementById("bf-members-panel"));
  const mpg = await page("home.html", member);
  check("G8. ...and opens the dashboard for a member", mpg.hq(mpg.clicks[1]) === false && !mpg.panel);
  const freePages = ["home.html", "profile.html", "marketplace.html", "garage-sale.html", "services.html", "inbox.html", "messages.html", "settings.html", "your-data.html", "billing.html", "compose.html"];   // NAMED (Nov 21 2026, P3-1B): BEFORE wallet.html and campaigns.html were here too (G9c)
  // NAMED (Nov 21 2026, P3-2, the owner's decision): BEFORE media.html was in this list. AFTER it is a member-only page (G9b).
  const listed = (pg.ctx.window.bfAccess && pg.ctx.window.bfAccess.MEMBER_PAGES) || [];
  check("G9. the free pages are never member-only", freePages.every(p => listed.indexOf(p) === -1) && listed.length >= 40, freePages.filter(p => listed.indexOf(p) !== -1).join(", "));
  check("G9b. the media library and the business ID are member-only pages (the owner, P3-2)", listed.indexOf("media.html") !== -1 && listed.indexOf("business-id.html") !== -1, J(listed.slice(-3)));
  // NAMED (Nov 21 2026, P3-1B): BizCash in every form, and campaigns, are members only: the wallet, receipts and campaigns
  check("G9c. the wallet, receipts and campaigns are member-only pages (P3-1B); the public support page is not", ["wallet.html", "receipts.html", "campaigns.html"].every(p => listed.indexOf(p) !== -1) && listed.indexOf("support.html") === -1, J(listed.slice(-5)));
  const missing = listed.filter(p => { try { return !/bf-session\.js/.test(require("fs").readFileSync(require("path").join(H.FRONTEND, p), "utf8")); } catch (e) { return true; } });
  check("G10. every member-only page exists and loads scripts/bf-session.js (which loads the panel)", missing.length === 0, missing.join(", "));
  check("G11. bf-session.js loads scripts/bf-access.js with the bottom bar", has(FILES[SESSION], "    loadTabBar();\n    loadAccess();\n") && has(FILES[SESSION], "tag.src = \"/scripts/bf-access.js\";"));
  check("G12. app.html lands a free account on Home and a member on the dashboard; a page that sent them still wins",
    has(FILES[APP], "go(d && d.access && d.access.tier === \"free\" ? \"/home.html\" : \"/dashboard.html\");") && has(FILES[APP], "    var back = signInReturnTo();\n    if (back) { window.location.href = back; return; }\n    landByTier(data.token);"));
  // NAMED (Nov 21 2026, P3-1B): BEFORE "receiving is free and sending is for members". AFTER BizCash in every form is for members.
  check("G13. the wallet says BizCash in every form, receiving and sending, is for members", has(FILES[WALLET], "BizCash in every form is for members: receiving it (tips, support, donations and sales) and sending it (a transfer, support or a tip, a donation, or buying in the Market). BizCash never pays for membership."));
  check("G14. /api/auth/me hands the app the members panel from code", has(S, "          members_panel: require(\"./lib/membership\").membersPanelFromCode()\n"));
  pg = await page("home.html", Object.assign({}, free, { email_verified: false }));
  const resend = pg.banner && pg.banner.children.find(c => c.tag === "button");
  check("G15. an unconfirmed email: the banner says what it is needed for, with \"Resend email\"",
    !!pg.banner && /post publicly and to message people who do not follow you/.test(pg.bannerText) && !/BizCash|list in the Market/.test(pg.bannerText)   // NAMED (Nov 21 2026, P3-1B): BEFORE "post publicly, list in the Market, message ..., and receive BizCash"
    && resend && resend.textContent === "Resend email", pg.bannerText.slice(0, 200));
  if (resend) { resend.listeners.click(); await new Promise(r => setTimeout(r, 20)); }
  check("G16. ...Resend email posts to /api/auth/resend-verification and says what happened",
    pg.fetched.some(f => /\/api\/auth\/resend-verification$/.test(f[0]) && f[1] === "POST") && /We sent a new link/.test(pg.bannerText + " " + (pg.banner ? pg.banner.children.map(c => c.textContent).join(" ") : "")), J(pg.fetched));
  pg = await page("home.html", free);
  check("G17. a confirmed email: no banner", !pg.banner);

  /* ── H. THE OWNER'S ROUTE DECISIONS (P3-2, Nov 21 2026), read from lib/routeAccess.js (held to the live router by
     checkUnsubscribedSurface). ── */
  console.log("\n══ H. the owner's route decisions (P3-2) ══");
  const inG = (g, keys) => keys.filter(k => R.groupOf(k) !== g).map(k => k + " " + R.groupOf(k));
  let bad = inG("M", ["get /api/business-profile", "post /api/business-profile", "put /api/business-profile"]);
  check("H1. the business-profile routes are members only (M)", bad.length === 0, bad.join(", "));
  // NAMED (Nov 21 2026, P3-1B): BEFORE adding and editing a profile product were F too. AFTER they are selling, members only (M);
  // reading and removing one stay free, so a free account can see and remove what it made before.
  bad = inG("F", ["post /api/themes/photo", "get /api/bfp/pproducts", "delete /api/bfp/pproducts/:id",
    "get /api/bfp/pportfolio", "post /api/bfp/pportfolio", "put /api/bfp/pportfolio/:id", "delete /api/bfp/pportfolio/:id"])
    .concat(inG("M", ["post /api/bfp/pproducts", "put /api/bfp/pproducts/:id"]));
  check("H2. themes/photo, pportfolio and reading or removing a profile product are sign-in only (F); adding or editing one is members only (M)", bad.length === 0, bad.join(", "));
  bad = inG("M", ["post /api/bfp/videos", "put /api/bfp/videos/:id"]).concat(inG("F", ["get /api/bfp/videos", "delete /api/bfp/videos/:id"]));
  check("H3. bfp/videos: adding and editing a video are members only (M, for now); reading and removing stay free", bad.length === 0, bad.join(", "));
  const uploadUrl = H.routeStatement(S, "post", "/api/bfp/upload-url") || "";
  check("H4. ...and the upload URL refuses a free account for the videos and music folders (refuseUnlessSubscribed in the handler)",
    has(S, "const UPLOAD_URL_MEMBER_FOLDERS = [\"videos\", \"music\", \"music-art\"];") &&
    uploadUrl.indexOf("if (UPLOAD_URL_MEMBER_FOLDERS.indexOf(folder) !== -1 && (await refuseUnlessSubscribed(req, res, \"post /api/bfp/upload-url \" + folder))) return;") !== -1, uploadUrl.length);
  // NAMED (Nov 21 2026, P3-1B): BEFORE the campaign reads were free (F). AFTER campaigns are members only, reads included (M).
  bad = inG("M", ["get /api/crowdfunding/campaigns", "get /api/crowdfunding/campaigns/by-share/:shareId", "get /api/crowdfunding/my-campaigns", "get /api/crowdfunding/donations",
    "post /api/crowdfunding/campaigns", "post /api/crowdfunding/campaigns/:id/donate"]);
  check("H5. campaigns are members only (M): their reads, creating one and donating", bad.length === 0, bad.join(", "));
  const radar = ["get /api/leads", "get /api/leads/youtube-signals", "get /api/agents/sales/leads", "post /api/agents/sales/lead-status", "get /api/agents/sales/pipeline"];
  bad = inG("A", radar).concat(radar.filter(k => R.ADMIN_IN_HANDLER.indexOf(k) === -1));
  check("H6. the Lead Radar routes stay the owner's (A) until the Radar-for-every-member block", bad.length === 0, bad.join(", "));
  const wallet = H.routeStatement(S, "get", "/api/cards/google-wallet") || "";
  check("H7. get /api/cards/google-wallet is public (P), served while the card's owner is in good standing (ownerPagePublic)",
    R.groupOf("get /api/cards/google-wallet") === "P" && /ownerPagePublic\(/.test(wallet), R.groupOf("get /api/cards/google-wallet") + " " + wallet.length);
  bad = inG("M", ["post /api/media", "patch /api/media/:id"]);
  check("H8. the media library's writes are members only (M); removing a file stays free", bad.length === 0 && R.groupOf("delete /api/media/:id") === "F", bad.join(", "));
  check("H9. put /api/profile/me stays sign-in only: Settings (free) writes it", R.groupOf("put /api/profile/me") === "F");

  /* ── I. THE SERVER REFUSES (NAMED, Nov 21 2026, P3-1B, the owner's final rules). A BizCash credit to a free account is
     refused before anything moves (checkBfcIntegrity runs the transfer's refusal; checkMarketplaceBfcOnly and
     checkLaunchHardening keep a member seller and owner). ── */
  console.log("\n══ I. the server refuses what is for members (P3-1B) ══");
  const FREE_GUARD = "free accounts never receive BizCash (lib/membership.js RECIPIENT_FREE); refused before anything moves. */\n";
  check("I1. a transfer or support to a free account: 409 recipient_free (\"transfer\" or \"support\"), before the 24-hour total",
    has(S, FREE_GUARD + "    if (!(await ownerIsMember(recipient.id))) {\n      return res.status(409).json(require(\"./lib/membership\").recipientFreeBody(send.support ? \"support\" : \"transfer\"));\n    }\n\n    const sent = await bfcSentLast24h(req.user.id);"));
  check("I2. buying a free seller's listing: 409 recipient_free (\"purchase\"), before the purchase",
    has(S, FREE_GUARD + "      if (!(await ownerIsMember(priced.seller_id))) {\n        return res.status(409).json(require(\"./lib/membership\").recipientFreeBody(\"purchase\"));\n      }\n"));
  check("I3. donating to a free owner's campaign: 409 recipient_free (\"donation\")",
    has(S, FREE_GUARD + "    if (!(await ownerIsMember(campaign.owner_id))) {\n      return res.status(409).json(require(\"./lib/membership\").recipientFreeBody(\"donation\"));\n    }\n"));
  const RF = M.RECIPIENT_FREE || {};
  check("I4. each refusal is one clear sentence to the payer: the account is free, and nothing was sent or charged",
    ["transfer", "support", "donation"].every(k => /free account/.test(RF[k] || "") && /Nothing was sent\.$/.test(RF[k])) && /Nothing was charged\.$/.test(RF.purchase || "") &&
    J(M.recipientFreeBody("purchase")) === J({ error: RF.purchase, reason: "recipient_free" }), J(RF));
  check("I5. starting a conversation: a free sender with no message from them first gets 403 members_only with the members panel",
    has(S, "    if (accessTier(await getUserPlan(req.user.id, req.user)) !== \"member\") {\n      const startedByThem = await supabase.from(\"messages\").select(\"id\")\n        .eq(\"sender_id\", receiverId).eq(\"receiver_id\", req.user.id).limit(1);\n") &&
    has(S, "        return res.status(403).json({ error: require(\"./lib/membership\").FREE_RULES.start_conversation, reason: \"members_only\",\n          members_panel: require(\"./lib/membership\").membersPanelFromCode() });"));
  const FR = M.FREE_RULES || {};
  check("I6. the four post and message rules are one sentence each, saying nothing was posted or sent",
    /photo/.test(FR.share_photo || "") && /Nothing was posted\.$/.test(FR.share_photo) && /Nothing was posted\.$/.test(FR.listing_link || "") &&
    /members' posts are for members/.test(FR.comment_member_post || "") && /Nothing was posted\.$/.test(FR.comment_member_post) &&
    /reply when a member messages you first/.test(FR.start_conversation || "") && /Nothing was sent\.$/.test(FR.start_conversation), J(FR));
  check("I7. lib/posts.js is handed the tier (postDeps().tierOf, the same accessTier) and the members panel",
    has(S, "    tierOf: async function (userId) { return accessTier(await getUserPlan(userId)); },\n    membersPanel: function () { return require(\"./lib/membership\").membersPanelFromCode(); } };"));

  /* ── J. THE APP FOR A FREE ACCOUNT (NAMED, Nov 21 2026, P3-1B): scripts/bf-access.js in the same vm page; the Create sheet,
     the composer, Talk and the Inbox read. browserCheckPhone PHONE_P31 taps the real pages. ── */
  console.log("\n══ J. the app for a free account (P3-1B) ══");
  function tap(p, sel) {
    let prevented = false;
    const target = { closest: s => (String(s).split(",").map(x => x.trim()).indexOf(sel) !== -1 ? {} : null) };
    p.clicks[0]({ target, preventDefault: () => { prevented = true; }, stopPropagation: () => {} });
    return prevented;
  }
  pg = await page("marketplace.html", free);
  const buyPrevented = tap(pg, ".btn-buy");
  const sheet = pg.document.getElementById("bf-buy-sheet"), sheetText = sheet ? [sheet].concat(sheet.children).map(function t(n) { return [n.textContent].concat(n.children.map(t)).join(" "); }).join(" ") : "";
  const BT = (pg.ctx.window.bfAccess && pg.ctx.window.bfAccess.BUY_TEXT) || [];
  check("J1. a free account's Buy opens the card-checkout-coming sheet, and nothing is bought",
    buyPrevented && !!sheet && BT[0] === "Card checkout is coming" && sheetText.indexOf(BT[0]) !== -1 && /never pays in BizCash/.test(sheetText) && !pg.document.getElementById("bf-members-panel"), sheetText.slice(0, 160));
  pg = await page("marketplace.html", free);
  check("J2. ...a create button opens the members panel instead of the form", tap(pg, ".create-btn") && !!pg.document.getElementById("bf-members-panel"));
  pg = await page("profile.html", free);
  check("J3. ...Message on a profile (starting a conversation) opens the members panel", tap(pg, "#pfsMessage") && !!pg.document.getElementById("bf-members-panel"));
  pg = await page("home.html", free);
  check("J4. ...the Create sheet's members entries open the members panel", tap(pg, "a.bf-create-opt.is-members") && !!pg.document.getElementById("bf-members-panel"));
  pg = await page("marketplace.html?create=product", free);
  check("J5. ...and a ?create= link on the Market opens the members panel on arrival", !!pg.panel);
  pg = await page("marketplace.html", member);
  check("J6. a member's Buy and create button go through: nothing is stopped, no sheet, no panel",
    tap(pg, ".btn-buy") === false && tap(pg, ".create-btn") === false && !pg.document.getElementById("bf-buy-sheet") && !pg.document.getElementById("bf-members-panel"));
  pg = await page("marketplace.html?create=product", member);
  check("J7. ...and a member's ?create= link opens no panel", !pg.panel);
  const TB = FILES[TABBAR] || "";
  const memberKeys = ["product", "service", "agent", "campaign", "garage", "card"];
  check("J8. the Create sheet marks Product listing, Service, Ask an agent, Campaign, Garage sale item and Business card as members only; Post and Video are not",
    memberKeys.every(k => has(TB, "{ key: \"" + k + "\", members: true, title:")) && !has(TB, "{ key: \"post\", members: true") && !has(TB, "{ key: \"video\", members: true"));
  check("J9. ...for a free account each carries a \"Members\" tag and the is-members class bf-access.js listens for",
    has(TB, "tag.className = \"bf-create-members\"; tag.textContent = \"Members\";") && has(TB, "o.classList.add(\"is-members\");") && has(TB, "if (!a || a.tier !== \"free\") return;") &&
    ((pg.ctx.window.bfAccess && pg.ctx.window.bfAccess.MEMBER_ACTIONS) || []).indexOf("a.bf-create-opt.is-members") !== -1);
  const CP = FILES[COMPOSER] || "", PL = T.libRequire("./lib/posts");
  check("J10. the composer: a free account's share post needs a photo, says why and is not sent; a Need may be text",
    has(CP, "var FREE_PHOTO_NOTE = \"A free account's share post needs at least one photo. Text-only posts are for members; a Need can be text.\";") &&
    has(CP, "      if (tier === \"free\" && intent() === \"share\" && !photos.length) { err.textContent = FREE_PHOTO_NOTE; freeNote.hidden = false; return; }\n"));
  check("J11. ...a member gets Show in Google (on by default) with a search title of " + PL.SEO_TITLE_MAX + " and a description of " + PL.SEO_DESCRIPTION_MAX + " characters, the server's own limits",
    has(CP, "  var SEO_TITLE_MAX = " + PL.SEO_TITLE_MAX + ", SEO_DESCRIPTION_MAX = " + PL.SEO_DESCRIPTION_MAX + ";") && has(CP, "<input type=\"checkbox\" id=\"bfcSearch\" checked> Show in Google") &&
    has(CP, "      seoBox.hidden = !(tier === \"member\" && audienceNow() === \"public\");\n") && PL.SEO_TITLE_MAX === 70 && PL.SEO_DESCRIPTION_MAX === 160);
  const FD = FILES[FEED] || "";
  // NAMED (Nov 22 2026, FX3): BEFORE a hand-typed heading TALK_MEMBERS ("Comments on members' posts are for members") over the
  // server's refusal. AFTER one sentence, the server's: lib/membership.js TALK_MEMBERS_ONLY before an attempt (checkSocialGraph G4-G8).
  check("J12. Talk on a member's post: the server's sentence with Join, when the server says can_comment is false (no copy typed in the app)",
    !has(FD, "var TALK_MEMBERS") && has(FD, "<a class=\"bfp-send bfp-tm-join\" href=\"/billing.html\">Join</a>") &&
    has(FD, "      if (r.body.can_comment === false) talkRule(r.body.comment_rule);"));
  const IB = FILES[INBOX] || "";
  check("J13. the Inbox: a free account replies where a member wrote first; otherwise the server's sentence, Join and the members panel",
    has(IB, "<p class=\"empty\" id=\"replyOnly\" hidden>Starting a conversation is for members. You can reply when a member messages you first. <a href=\"/billing.html\">Join</a></p>") &&
    (FR.start_conversation || "").indexOf("Starting a conversation is for members. You can reply when a member messages you first.") === 0 &&
    has(IB, "  var theirs = state.thread.some(function (m) { return m && m.sender_id === otherId; });\n  var blocked = accessTier() === \"free\" && !theirs;\n"));
  finish();
})().catch(e => { console.log("    FAIL  the check threw: " + (e && e.stack || e)); process.exit(1); });
