/* ═══════════════════════════════════════════════════════════════════════════
   checkFreeAccount.js — free accounts and the one membership (P3-1, Nov 20 2026;
   lib/membership.js, lib/routeAccess.js).

   WHAT IT PROVES
     A. THE OWNER'S LISTS: what a free account gets (seven lines) and what
        membership adds (nine lines) are lib/membership.js's, word for word.
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
        price, the nine lines, Join to billing.html, Go to Home); a member, an
        unreadable answer and a free page see none; the bottom bar's HQ tab
        opens the panel for a free account only; every member-only page loads
        it through bf-session.js; app.html lands a free account on Home and a
        member on the dashboard; the wallet says who may send; an unconfirmed
        email gets the banner, whose "Resend email" posts to
        /api/auth/resend-verification.

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
  "oracle-line-dropped": [[MEM, "  \"the Oracle\",\n", ""]],
  "tier-any-plan": [[SERVER, "  return planState && planState.active === true ? \"member\" : \"free\";", "  return planState ? \"member\" : \"free\";"]],
  "member-on-a-guess": [[SERVER, " — shown as not a member.\");\n    return false;", " — shown as not a member.\");\n    return true;"]],
  "price-typed": [[MEM, "    price_text: \"$\" + Number(price) + \" a \" + per,", "    price_text: \"$99 a month\","]],
  "storefront-always-member": [[SERVER, "      member: await ownerIsMember(userId)\n", "      member: true\n"]],
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
  "me-no-panel": [[SERVER, "          members_panel: require(\"./lib/membership\").membersPanelFromCode()\n", "          members_panel: null\n"]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, MEM, RA, ACCESS, APP, SESSION, WALLET]);
const { FILES, check, finish, J, has } = T;
const S = FILES[SERVER] || "";
const M = T.libRequire("./lib/membership");
const R = T.libRequire("./lib/routeAccess");

function fnText(src, sig) {
  const at = src.indexOf(sig);
  return at < 0 ? "" : src.slice(at, require("./_shared").braceMatch(src, src.indexOf("{", at)) + 1);
}

/* Each line of the two lists, and the routes it is. */
const FREE_ROUTES = {
  "a profile and @handle": ["get /api/bfp/profile/me", "put /api/bfp/profile/me", "put /api/bfp/profile/design", "get /api/profile/me", "put /api/profile/me"],
  "posting to the feed (text and photos)": ["post /api/posts", "post /api/posts/photos", "patch /api/posts/:id", "delete /api/posts/:id", "post /api/posts/:id/comments"],
  "selling and listing in the Market, including garage sales and services": ["post /api/marketplace/listings", "put /api/marketplace/listings/:id", "delete /api/marketplace/listings/:id", "get /api/marketplace/my-listings"],
  "receiving tips and donations": ["get /api/wallet", "get /api/crowdfunding/donations", "get /api/crowdfunding/my-campaigns"],
  "messaging and following": ["post /api/messages", "get /api/messages/:userId", "post /api/follows", "delete /api/follows/:userId", "get /api/feed/following"],
  "Settings, Your data and Billing": ["get /api/user/preferences", "put /api/user/preferences", "get /api/me/export", "post /api/me/delete", "post /api/stripe/checkout", "post /api/billing/portal"],
  "the safety tools (report, block and mute) and the Inbox": ["post /api/reports", "post /api/blocks", "delete /api/blocks/:userId", "post /api/mutes", "get /api/inbox/conversations", "get /api/notifications"]
};
const MEMBER_ROUTES = {
  "the 18 AI agents and every agent page": ["get /api/agents", "get /api/agents/:type", "put /api/agents/:id", "get /api/agents/live"],
  "HQ and the orbit": ["get /api/command-center", "get /api/agents/network", "get /api/agents/live/calendar"],
  "the Oracle": ["get /api/oracle", "post /api/oracle/sync", "get /api/oracle/natal", "get /api/oracle/numerology"],
  "social publishing and auto-posting": ["post /api/social/connect/:platform", "post /api/social/mastodon/propose-post", "post /api/social-drafts", "get /api/social/accounts"],
  "store connections and analytics": ["get /api/store/connections", "post /api/store/connections", "get /api/analytics/summary", "get /api/dashboard/pulse"],
  "sending BizCash: transfers, support and tips, donations and buying in the Market": ["post /api/wallet/transfer", "post /api/wallet/support", "post /api/crowdfunding/campaigns/:id/donate", "post /api/marketplace/listings/:id/buy", "get /api/wallet/recipient"],
  "the business tools: CRM, prospects, ICP, inventory, calendar, BizDoc, BizBook, cover wraps, certifications, Inner IQ and the Guide": [
    "post /api/crm/customers", "post /api/prospects", "post /api/icp-profiles", "post /api/inventory/items", "post /api/calendar/events", "post /api/bizdoc/documents",
    "post /api/bizbook/generate", "post /api/cover-wraps", "post /api/certifications/award", "post /api/inner-iq/results", "post /api/guide/ask"],
  "music uploads, digital cards and Google Wallet passes": ["post /api/bfp/music", "post /api/music/tracks", "post /api/digital-cards", "put /api/digital-cards/:id"],
  "creating campaigns and media library uploads outside posts and listings": ["post /api/crowdfunding/campaigns", "post /api/media"]
};

(async function main() {
  console.log("\n══ A. the owner's lists ══");
  check("A1. a free account gets the seven lines, in order", J(M.FREE_INCLUDES) === J(Object.keys(FREE_ROUTES)), J(M.FREE_INCLUDES));
  check("A2. membership adds the nine lines, in order", J(M.MEMBER_ADDS) === J(Object.keys(MEMBER_ROUTES)), J(M.MEMBER_ADDS));

  console.log("\n══ B. every line is the routes ══");
  Object.keys(FREE_ROUTES).forEach((line, i) => {
    const bad = FREE_ROUTES[line].filter(k => R.groupOf(k) !== "F");
    check("B" + (i + 1) + ". free: " + line + " (" + FREE_ROUTES[line].length + " routes F)", bad.length === 0, bad.map(k => k + " " + R.groupOf(k)).join(", "));
  });
  Object.keys(MEMBER_ROUTES).forEach((line, i) => {
    const bad = MEMBER_ROUTES[line].filter(k => R.groupOf(k) !== "M");
    check("B" + (i + 8) + ". members: " + line + " (" + MEMBER_ROUTES[line].length + " routes M)", bad.length === 0, bad.map(k => k + " " + R.groupOf(k)).join(", "));
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
  check("C2. the members panel: \"Members get this\", $199 a month, the nine lines, Join to /billing.html",
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
  check("E2. the public profile and the storefront answer member from ownerIsMember", has(S, "member: data ? await ownerIsMember(userId) : false });") && has(S, "      member: await ownerIsMember(userId)\n"));

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
    ctx.window.location = { pathname: "/" + name };
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
  check("G1. a free account on the dashboard: the members panel, \"Members get this\", the price from the server, the nine lines, Join to billing.html",
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
  check("G7. the bottom bar's HQ tab opens the panel for a free account, instead of the dashboard", pg.clicks.length === 1 && pg.hq(pg.clicks[0]) === true && !!pg.document.getElementById("bf-members-panel"));
  const mpg = await page("home.html", member);
  check("G8. ...and opens the dashboard for a member", mpg.hq(mpg.clicks[0]) === false && !mpg.panel);
  const freePages = ["home.html", "profile.html", "marketplace.html", "garage-sale.html", "services.html", "inbox.html", "messages.html", "settings.html", "your-data.html", "billing.html", "wallet.html", "compose.html", "media.html", "campaigns.html"];
  const listed = (pg.ctx.window.bfAccess && pg.ctx.window.bfAccess.MEMBER_PAGES) || [];
  check("G9. the free pages are never member-only", freePages.every(p => listed.indexOf(p) === -1) && listed.length >= 40, freePages.filter(p => listed.indexOf(p) !== -1).join(", "));
  const missing = listed.filter(p => { try { return !/bf-session\.js/.test(require("fs").readFileSync(require("path").join(H.FRONTEND, p), "utf8")); } catch (e) { return true; } });
  check("G10. every member-only page exists and loads scripts/bf-session.js (which loads the panel)", missing.length === 0, missing.join(", "));
  check("G11. bf-session.js loads scripts/bf-access.js with the bottom bar", has(FILES[SESSION], "    loadTabBar();\n    loadAccess();\n") && has(FILES[SESSION], "tag.src = \"/scripts/bf-access.js\";"));
  check("G12. app.html lands a free account on Home and a member on the dashboard; a page that sent them still wins",
    has(FILES[APP], "go(d && d.access && d.access.tier === \"free\" ? \"/home.html\" : \"/dashboard.html\");") && has(FILES[APP], "    var back = signInReturnTo();\n    if (back) { window.location.href = back; return; }\n    landByTier(data.token);"));
  check("G13. the wallet says receiving is free and sending is for members", has(FILES[WALLET], "Receiving BizCash is free once your email is confirmed. Sending it (a transfer, support or a tip, a donation, or buying in the Market) is for members. BizCash never pays for membership."));
  check("G14. /api/auth/me hands the app the members panel from code", has(S, "          members_panel: require(\"./lib/membership\").membersPanelFromCode()\n"));
  pg = await page("home.html", Object.assign({}, free, { email_verified: false }));
  const resend = pg.banner && pg.banner.children.find(c => c.tag === "button");
  check("G15. an unconfirmed email: the banner says what it is needed for, with \"Resend email\"",
    !!pg.banner && /post publicly, list in the Market, message people who do not follow you, and receive BizCash/.test(pg.bannerText) && resend && resend.textContent === "Resend email", pg.bannerText.slice(0, 200));
  if (resend) { resend.listeners.click(); await new Promise(r => setTimeout(r, 20)); }
  check("G16. ...Resend email posts to /api/auth/resend-verification and says what happened",
    pg.fetched.some(f => /\/api\/auth\/resend-verification$/.test(f[0]) && f[1] === "POST") && /We sent a new link/.test(pg.bannerText + " " + (pg.banner ? pg.banner.children.map(c => c.textContent).join(" ") : "")), J(pg.fetched));
  pg = await page("home.html", free);
  check("G17. a confirmed email: no banner", !pg.banner);
  finish();
})().catch(e => { console.log("    FAIL  the check threw: " + (e && e.stack || e)); process.exit(1); });
