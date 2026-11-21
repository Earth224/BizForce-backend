"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkProfileShell.js — P2-1 (Nov 19 2026): the profile header.

     S  the counts: GET /api/bfp/profile/me/stats (Sales and the member's own
        BizCash) and GET /api/bfp/profile/:userId/stats (Sales only, only
        while the page is public), run with a fake database
     R  scripts/bf-profile-shell.js run in jsdom, as the owner and as a
        visitor: @handle, Sales, BizCash for the owner only, Edit profile,
        Share profile (/@handle by the share sheet, else copied), Wallet, the
        bio, the storefront link, the Posts, Shop and Services tabs (active
        listings by listing_kind); no Following, Followers or Reviews and no
        zeros for them
     P  profile.html: the block between the page's header and its sections,
        the script after the editor's; the desktop keeps its layout

   Run: node scripts/checkProfileShell.js      MUTATE=<name> | all
   Nothing here touches the live database or the network.
   ══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");

const SERVER = "@server.js", SHELL = "scripts/bf-profile-shell.js", PAGE = "profile.html";

const MUTATIONS = {
  "visitor-gets-bizcash": [[SERVER, "    return res.json({ stats: { sales: await profileSalesCount(userId) } });", "    return res.json({ stats: { sales: await profileSalesCount(userId), bizcash: 5 } });"]],
  "visitor-stats-ungated": [[SERVER, "    if (!require(\"./lib/inbox\").isUuid(userId) || !(await ownerPagePublic(userId))) return res.json({ stats: null });", "    if (!require(\"./lib/inbox\").isUuid(userId)) return res.json({ stats: null });"]],
  "sales-any-status": [[SERVER, "    .eq(\"seller_id\", userId).eq(\"status\", \"completed\");", "    .eq(\"seller_id\", userId);"]],
  "bizcash-someone-else": [[SERVER, "    const wallet = await supabase.from(\"user_wallets\").select(\"balance\").eq(\"user_id\", req.user.id).maybeSingle();", "    const wallet = await supabase.from(\"user_wallets\").select(\"balance\").maybeSingle();"]],
  // NAMED (Nov 20 2026, FX1): BEFORE the anchor "if (owner && typeof s.bizcash"; AFTER BizCash is a paid member's only (state.member)
  "shell-bizcash-for-all": [[SHELL, "    if (owner && state.member === true && typeof s.bizcash === \"number\")", "    if (typeof s.bizcash === \"number\")"]],
  "shell-bizcash-unpaid": [[SHELL, "    if (owner && state.member === true && typeof s.bizcash === \"number\")", "    if (owner && typeof s.bizcash === \"number\")"]],
  "shell-wallet-unpaid": [[SHELL, "          (owner && paid ? '<a class=\"pfs-btn is-wallet\" href=\"wallet.html\"", "          (owner ? '<a class=\"pfs-btn is-wallet\" href=\"wallet.html\""]],
  "shell-fake-follow-counts": [[SHELL, "    return out.length ? '<ul class=\"pfs-stats\"", "    out.push('<li class=\"pfs-stat\"><span class=\"pfs-num\">0</span><span class=\"pfs-lab\">Followers</span></li>');\n    return out.length ? '<ul class=\"pfs-stats\""]],
  "shell-edit-for-visitor": [[SHELL, "          (owner ? '<button type=\"button\" class=\"pfs-btn\" id=\"pfsEdit\">Edit profile</button>' : \"\") +", "          '<button type=\"button\" class=\"pfs-btn\" id=\"pfsEdit\">Edit profile</button>' +"]],
  "shell-share-wrong-url": [[SHELL, "    var url = ORIGIN + \"/@\" + handle;", "    var url = ORIGIN + \"/profile.html\";"]],
  "shell-no-copy-fallback": [[SHELL, "    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(url).then(done, function () { note(url); });\n    else note(url);", "    note(\"Sharing is not available.\");"]],
  "shell-drafts-in-shop": [[SHELL, "    var active = (rows || []).filter(function (l) { return l.status === \"active\"; });", "    var active = rows || [];"]],
  "shell-services-in-shop": [[SHELL, "    state.shop = active.filter(function (l) { return l.listing_kind !== \"service\"; }).map(map);", "    state.shop = active.map(map);"]],
  "shell-no-storefront": [[SHELL, "      (handle ? '<a class=\"pfs-store\" href=\"/@' + encodeURIComponent(handle) + '\">'", "      (false ? '<a class=\"pfs-store\" href=\"/@' + encodeURIComponent(handle) + '\">'"]],
  // NAMED (Nov 20 2026, FX1): BEFORE the anchor was the "Posts are coming soon" line P2-3 removed (a MUTATION ANCHOR ERROR since);
  // AFTER a failed load claims posts instead of saying it failed (R6)
  "shell-posts-fake": [[SHELL, "    if (failed) return '<p class=\"pfs-empty\">These could not be loaded just now. This is not a statement that there are none.</p>';", "    if (failed) return '<p class=\"pfs-empty\">3 posts</p>';"]],
  "shell-edit-not-wired": [[SHELL, "      if (typeof window.toggleEditMode === \"function\") window.toggleEditMode();\n", ""]],
  "shell-no-wallet": [[SHELL, "          (owner && paid ? '<a class=\"pfs-btn is-wallet\" href=\"wallet.html\"", "          (false ? '<a class=\"pfs-btn is-wallet\" href=\"wallet.html\""]],
  "shell-small-targets": [[SHELL, ".pfs-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:44px;", ".pfs-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:32px;"]],
  "page-no-container": [[PAGE, "<div id=\"pfShell\"></div>\n", ""]],
  "page-no-script": [[PAGE, "<script src=\"/scripts/bf-profile-shell.js\"></script>\n", ""]]
};

const T = H.setup(__filename, MUTATIONS, [SERVER, SHELL, PAGE]);
const { FILES, check, has, J } = T;
const ME = "11111111-1111-4111-8111-111111111111", OTHER = "22222222-2222-4222-8222-222222222222";
let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }
const settle = ms => new Promise(r => setTimeout(r, ms || 40));

(async () => {
  /* ══ S ══ */
  console.log("\n══ S. the counts ══");
  const sDb = () => H.fakeDb((table, q) => {
    if (table === "marketplace_orders") return { count: H.filterVal(q, "eq", "status") === "completed" ? 3 : 9, error: null };
    if (table === "user_wallets") return { data: H.filterVal(q, "eq", "user_id") === ME ? { balance: "1500" } : { balance: 777 }, error: null };
    return { data: null, error: null };
  });
  const run = async (method, routePath, req, pub) => {
    const db = sDb();
    const fn = H.route(FILES[SERVER], method, routePath, { supabase: db.client, safeText: (v, n) => String(v == null ? "" : v).slice(0, n), ownerPagePublic: async (u) => u === pub }, T.libRequire);
    const r = fn ? await fn(req) : { status: "no route" };
    r.log = db.log;
    return r;
  };
  const mine = await run("get", "/api/bfp/profile/me/stats", {});
  const oq = mine.log.find(q => q.table === "marketplace_orders") || { filters: [] };
  check("S1. the owner's counts: completed sales and their own BizCash balance", mine.status === 200 && J(mine.body) === J({ sales: 3, bizcash: 1500 }), J([mine.status, mine.body]));
  check("S2. sales counted (never listed): the member as seller, status completed", H.filterVal(oq, "eq", "seller_id") === ME && H.filterVal(oq, "eq", "status") === "completed" && oq.head === true, J(oq));
  const vis = await run("get", "/api/bfp/profile/:userId/stats", { params: { userId: OTHER } }, OTHER);
  check("S3. a visitor's answer for a public page: sales only, no bizcash key at all", vis.status === 200 && J(vis.body) === J({ stats: { sales: 3 } }), J(vis.body));
  const priv = await run("get", "/api/bfp/profile/:userId/stats", { params: { userId: OTHER } }, null);
  const junk = await run("get", "/api/bfp/profile/:userId/stats", { params: { userId: "me'; drop" } }, "me'; drop");
  check("S4. a page that is not public, or an id that is not one, answers no counts and reads nothing", J(priv.body) === J({ stats: null }) && J(junk.body) === J({ stats: null }) && priv.log.length === 0 && junk.log.length === 0, J([priv.body, junk.body]));
  const stmt = H.routeStatement(FILES[SERVER], "get", "/api/bfp/profile/me/stats") || "";
  check("S5. the owner's counts need sign-in", /^app\.get\("\/api\/bfp\/profile\/me\/stats", requireAuth, /.test(stmt));
  const SRC = FILES[SERVER] || "";
  check("S6. /me/stats is registered before /:userId/stats (so \"me\" is never read as an id)", SRC.indexOf("app.get(\"/api/bfp/profile/me/stats\"") > 0 && SRC.indexOf("app.get(\"/api/bfp/profile/me/stats\"") < SRC.indexOf("app.get(\"/api/bfp/profile/:userId/stats\""));

  /* ══ R ══ */
  console.log("\n══ R. the header, rendered ══");
  const b64 = o => Buffer.from(JSON.stringify(o)).toString("base64").replace(/=+$/, "");
  const TOKEN = "x." + b64({ id: ME }) + ".y";
  async function render(url, answers, opts) {
    const dom = new JSDOM("<!doctype html><html><head></head><body><div class=\"pf-header-wrap\"></div><div id=\"pfShell\"></div></body></html>", { url, runScripts: "outside-only", pretendToBeVisual: true });
    const w = dom.window;
    w.localStorage.setItem("bf_token", TOKEN);
    const calls = [];
    w.fetch = (u, o) => {
      const p = String(u).replace(/^https:\/\/[^/]+/, "");
      calls.push(p);
      const a = answers[p];
      if (a === undefined) return Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({}) });
      return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(JSON.parse(JSON.stringify(a))) });
    };
    w.toggleEditMode = () => { w.__edited = (w.__edited || 0) + 1; };
    w.Element.prototype.scrollIntoView = function () {};
    const copied = [];
    if (opts && opts.share) w.navigator.share = (d) => { w.__shared = d; return Promise.resolve(); };
    Object.defineProperty(w.navigator, "clipboard", { value: { writeText: (t) => { copied.push(t); return Promise.resolve(); } }, configurable: true });
    w.eval(FILES[SHELL]);
    await settle(60);
    return { w, doc: w.document, calls, copied, text: () => w.document.getElementById("pfShell").textContent.replace(/\s+/g, " ") };
  }
  const OWNER_ANSWERS = {
    // NAMED (Nov 20 2026, FX1): the owner is a paid member (BizCash, the wallet and "BizForce member" are a paid member's only)
    "/api/auth/me": { access: { active: true, tier: "member" } },   // NAMED (Nov 20 2026, P3-1): the shell reads access.tier
    "/api/bfp/profile/me": { profile: { username: "rose", display_name: "Rose", bio: "I make hats." } },
    "/api/bfp/profile/me/stats": { sales: 3, bizcash: 1500 },
    "/api/marketplace/my-listings": { listings: [
      { id: "p1", title: "Wool hat", status: "active", listing_kind: "product", price_bfc: 40, media: [{ url: "https://cdn.test/h.jpg" }] },
      { id: "s1", title: "Hat repair", status: "active", listing_kind: "service", price_bfc: 15, media: [] },
      { id: "d1", title: "Draft scarf", status: "draft", listing_kind: "product", price_bfc: 10, media: [] }
    ] }
  };
  const o = await render("https://bizforceai.net/profile.html", OWNER_ANSWERS);
  const ot = o.text();
  check("R1. the owner sees @handle, Sales 3 and BizCash 1,500", /@rose/.test(ot) && /3\s*Sales/.test(ot) && /1,500\s*BizCash/.test(ot), ot.slice(0, 300));
  check("R2. Edit profile, Share profile and Wallet (wallet.html)", !!o.doc.getElementById("pfsEdit") && !!o.doc.getElementById("pfsShare") && !!o.doc.querySelector("a.pfs-btn.is-wallet[href=\"wallet.html\"]"));
  // NAMED (Nov 20 2026, FX1): the owner's decision: sending BizCash is for paid members, so BizCash, the gold wallet and
  // "BizForce member" show only for one (GET /api/auth/me access.active); a free owner, or one not yet known, sees none
  const free = await render("https://bizforceai.net/profile.html", Object.assign({}, OWNER_ANSWERS, { "/api/auth/me": { access: { active: false, tier: "free" } } }));
  const ft = free.text();
  check("R2b. a free owner: Sales, but no BizCash, no wallet and no \"BizForce member\"", /3\s*Sales/.test(ft) && !/BizCash|1,500|BizForce member/.test(ft) && !free.doc.querySelector(".pfs-btn.is-wallet") && /@rose/.test(ft), ft.slice(0, 300));
  check("R2c. a paid owner's handle line says BizForce member", /@rose · BizForce member/.test(ot), ot.slice(0, 120));
  o.doc.getElementById("pfsEdit").click();
  check("R3. Edit profile opens the page's own edit mode", o.w.__edited === 1);
  check("R4. the bio and the storefront link (/@handle)", /I make hats\./.test(ot) && !!o.doc.querySelector("a.pfs-store[href=\"/@rose\"]"));
  // NAMED (Nov 20 2026, P2-3): BEFORE never Following or Followers. AFTER they are shown only from the server's counts
  // (GET /api/follows/:id/counts); this page answers none, so none is shown. Reviews are still not shown.
  // NAMED (Nov 20 2026, FX1): BEFORE "no Reviews"; AFTER the approved design's Reviews tab (Coming soon), still no review shown
  check("R5. with no counts from the server, no Following or Followers figure; Reviews only as the tab", !/Follow/i.test(ot) && (ot.match(/Review/g) || []).length === 1);
  const tabs = Array.from(o.doc.querySelectorAll("[role=tab]")).map(t => t.textContent + ":" + t.getAttribute("aria-selected"));
  // NAMED (Nov 20 2026, P2-3): BEFORE tabs Posts, Shop, Services, and Posts said "Posts are coming soon". AFTER the owner also has a
  // private Saved tab, and Posts is the member's grid from GET /api/posts/by/:id; unanswered here, it says so and claims nothing.
  // NAMED (Nov 20 2026, FX1): + Reviews (a phone shows Posts, Shop, Services and Reviews; a desktop Posts, Shop, Services and Saved)
  check("R6. tabs Posts (selected), Shop, Services, Saved (the owner's), Reviews; Posts unanswered says so, never a made-up post", J(tabs) === J(["Posts:true", "Shop:false", "Services:false", "Saved:false", "Reviews:false"]) &&
    /These could not be loaded just now\. This is not a statement that there are none\./.test(o.doc.getElementById("pfsPanel").textContent) && !o.doc.querySelector("#pfsPanel .pfs-grid"), J(tabs));
  o.doc.querySelector("[data-pfs-tab=shop]").click(); await settle();
  const shop = Array.from(o.doc.querySelectorAll("#pfsPanel .pfs-cell")).map(a => a.getAttribute("href") + "|" + a.textContent);
  check("R7. Shop: the active products only (not a draft, not a service), each opening its listing", J(shop) === J(["/listing/p1|Wool hat40 BFC"]), J(shop));
  o.doc.querySelector("[data-pfs-tab=services]").click(); await settle();
  const svc = Array.from(o.doc.querySelectorAll("#pfsPanel .pfs-cell")).map(a => a.getAttribute("href"));
  check("R8. Services: the active services", J(svc) === J(["/listing/s1"]) && o.doc.getElementById("pfs-tab-services").getAttribute("aria-selected") === "true", J(svc));
  o.doc.getElementById("pfsShare").click(); await settle();
  check("R9. Share profile with no share sheet copies https://bizforceai.net/@rose and says so", J(o.copied) === J(["https://bizforceai.net/@rose"]) && /Link copied/.test(o.doc.getElementById("pfsNote").textContent), J(o.copied));
  const o2 = await render("https://bizforceai.net/profile.html", OWNER_ANSWERS, { share: true });
  o2.doc.getElementById("pfsShare").click(); await settle();
  check("R10. ...and with one, the device's share sheet gets /@rose", o2.w.__shared && o2.w.__shared.url === "https://bizforceai.net/@rose" && o2.copied.length === 0, J(o2.w.__shared));

  const VISITOR_ANSWERS = {
    ["/api/bfp/profile/" + OTHER]: { profile: { username: "two", display_name: "Two Co", bio: "" } },
    ["/api/bfp/profile/" + OTHER + "/stats"]: { stats: { sales: 2, bizcash: 99 } },
    "/api/bfp/seller/two": { seller: {}, products: [{ id: "x1", slug: "big-hat", name: "Big hat", image_url: "https://cdn.test/b.jpg", price: 12 }], services: [] }
  };
  const v = await render("https://bizforceai.net/profile.html?id=" + OTHER, VISITOR_ANSWERS);
  const vt = v.text();
  check("R11. a visitor sees @handle and Sales, and never BizCash (even if an answer carried one)", /@two/.test(vt) && /2\s*Sales/.test(vt) && !/BizCash|99/.test(vt), vt.slice(0, 300));
  check("R12. a visitor gets Share profile, and no Edit profile or Wallet", !v.doc.getElementById("pfsEdit") && !!v.doc.getElementById("pfsShare") && !v.doc.querySelector(".pfs-btn.is-wallet"));
  check("R13. a visitor's view reads only public routes: the public profile, its stats, the storefront",
    v.calls.indexOf("/api/bfp/profile/me") === -1 && v.calls.indexOf("/api/marketplace/my-listings") === -1 && v.calls.indexOf("/api/bfp/seller/two") !== -1, J(v.calls));
  v.doc.querySelector("[data-pfs-tab=shop]").click(); await settle();
  check("R14. a visitor's Shop shows the storefront's products", J(Array.from(v.doc.querySelectorAll("#pfsPanel .pfs-cell")).map(a => a.getAttribute("href"))) === J(["/listing/big-hat"]));
  v.doc.querySelector("[data-pfs-tab=services]").click(); await settle();
  check("R15. an empty list says so plainly", /No services listed\./.test(v.doc.getElementById("pfsPanel").textContent));
  const f = await render("https://bizforceai.net/profile.html", { "/api/bfp/profile/me": { profile: { username: "rose" } } });
  f.doc.querySelector("[data-pfs-tab=shop]").click(); await settle();
  check("R16. no counts answer: no counts shown (nothing claimed); a failed list says it failed, not that there are none",
    !f.doc.querySelector(".pfs-stats") && /could not be loaded/.test(f.doc.getElementById("pfsPanel").textContent));
  const css = FILES[SHELL] || "";
  check("R17. every button and tab is at least 44 px tall", has(css, ".pfs-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:44px;min-width:44px;") &&
    has(css, ".pfs-tab{flex:1 1 0;min-height:44px;") && has(css, ".pfs-store{display:inline-flex;align-items:center;gap:6px;min-height:44px;"));
  check("R18. the bio line shows on a phone only (on a desktop the About section has it); the grid is three to a row",
  // NAMED (Nov 20 2026, FX1): BEFORE ".pfs-bio{display:block}"; AFTER the phone rule also carries the design's size and spacing
    has(css, ".pfs-bio{display:none;") && /@media \(max-width: 760px\)\{[\s\S]*\.pfs-bio\{display:block[;}]/.test(css) && has(css, ".pfs-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));"));

  /* ══ P ══ */
  console.log("\n══ P. profile.html ══");
  const pg = FILES[PAGE] || "";
  const box = pg.indexOf("<div id=\"pfShell\"></div>");
  check("P1. the block sits after the page's header and before its sections", box > pg.indexOf("id=\"profileLoadError\"") && box < pg.indexOf("<div class=\"pf-sections\">") && box > 0);
  check("P2. its script loads after the profile editor's, once", pg.indexOf("<script src=\"/scripts/bf-profile-shell.js\"></script>") > pg.indexOf("<script src=\"/scripts/bf-profile-editor.js\"></script>") && T.count(pg, "<script src=\"/scripts/bf-profile-shell.js\"") === 1);
  check("P3. the page's own edit mode is a global the block can call", /\bfunction toggleEditMode\s*\(/.test(pg));

  T.finish();
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
