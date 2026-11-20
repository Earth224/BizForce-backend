"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkHomeStarter.js — P2-1 (Nov 19 2026): Home (home.html) before posts.

     S  GET /api/home/starter, run with a fake database: real records only;
        listings active and with a photo, campaigns active with a share link,
        people with a public page (never the member themself); every owner's
        page public (publicOwnersAmong); the caps 8, 6, 8; sign-in required
     P  home.html: Make your first post opens the Create sheet, the three
        lists and their empty and error states, the plain line about posts and
        the four tabs, a 600 px column with a right column on a desktop and
        one column on a phone, no sample content
     O  signed out: bf-session.js sends the page to app.html and keeps
        /home.html (and an Inbox address) in bf_return_to, nothing else

   Run: node scripts/checkHomeStarter.js      MUTATE=<name> | all
   Nothing here touches the live database or the network.
   ══════════════════════════════════════════════════════════════════════════ */
const vm = require("vm");
const H = require("./_p21Harness");

const SERVER = "@server.js", PAGE = "home.html", SESSION = "scripts/bf-session.js";

const MUTATIONS = {
  "listings-without-photo": [[SERVER, ".filter(function (l) { return l.photo; });", ";"]],
  "listings-any-status": [[SERVER, "      supabase.from(\"marketplace_listings\").select(\"id, slug, seller_id, title, price_bfc, category, listing_kind, media, created_at\")\n        .eq(\"status\", \"active\")", "      supabase.from(\"marketplace_listings\").select(\"id, slug, seller_id, title, price_bfc, category, listing_kind, media, created_at\")\n        .neq(\"status\", \"deleted\")"]],
  "campaigns-unshared": [[SERVER, ".eq(\"status\", \"active\").not(\"share_id\", \"is\", null)", ".eq(\"status\", \"active\")"]],
  "private-sellers-shown": [[SERVER, "      listings: withPhoto.filter(function (l) { return visible.has(l.seller_id); })", "      listings: withPhoto.filter(function (l) { return true; })"]],
  "self-in-people": [[SERVER, "return visible.has(p.user_id) && p.user_id !== req.user.id;", "return visible.has(p.user_id);"]],
  "no-cap": [[SERVER, "const HOME_LISTINGS = 8, HOME_CAMPAIGNS = 6, HOME_PEOPLE = 8;", "const HOME_LISTINGS = 80, HOME_CAMPAIGNS = 6, HOME_PEOPLE = 8;"]],
  "video-as-photo": [[SERVER, "(!x.type || /^image/.test(String(x.type)) || x.kind === \"image\")", "true"]],
  "route-public": [[SERVER, "app.get(\"/api/home/starter\", requireAuth, async function", "app.get(\"/api/home/starter\", async function"]],
  "people-leak-id": [[SERVER, "return { username: p.username, name: p.display_name || \"@\" + p.username,", "return { user_id: p.user_id, username: p.username, name: p.display_name || \"@\" + p.username,"]],
  "page-no-create": [[PAGE, "  if (window.BFTabbar) { window.BFTabbar.openCreate(btn); return; }", "  return;"]],
  "page-no-soon-line": [[PAGE, "Posts are coming. The Following, Local, Market and For You tabs arrive with them.", "Welcome home."]],
  "page-sample-content": [[PAGE, "  if (!list.length) { el.innerHTML = '<p class=\"empty\">No public member pages yet.</p>'; return; }", "  if (!list.length) list = [{ name: \"Jane Doe\", username: \"jane\", link: \"/@jane\" }];"]],
  "page-desktop-one-column": [[PAGE, ".home-grid{display:grid;grid-template-columns:minmax(0,600px) minmax(0,300px);", ".home-grid{display:grid;grid-template-columns:minmax(0,600px);"]],
  "page-error-as-empty": [[PAGE, "  } catch (e) {\n    showError();\n  }", "  } catch (e) {\n    renderMarket([]); renderCampaigns([]); renderPeople([]);\n  }"]],
  "signed-out-no-return": [[SESSION, "    if ((window.location.pathname === \"/home.html\" && !window.location.search) ||", "    if (false ||"]],
  "return-any-inbox": [[SESSION, "/^(\\?(tab=(messages|approvals|notifications)|with=[0-9a-f-]{36}))?$/.test(window.location.search)", "true"]]
};

const T = H.setup(__filename, MUTATIONS, [SERVER, PAGE, SESSION]);
const { FILES, check, has, J } = T;
const ME = "11111111-1111-4111-8111-111111111111";
const id = n => "aaaaaaaa-0000-4000-8000-" + String(n).padStart(12, "0");

(async () => {
  /* ══ S ══ */
  console.log("\n══ S. GET /api/home/starter ══");
  const PRIVATE = id(99);
  const listings = [];   // the three that must be left out are the NEWEST, so the cap of 8 cannot hide a mistake
  for (let i = 1; i <= 12; i++) listings.push({ id: "l" + i, seller_id: id(i), title: "Item " + i, price_bfc: i * 10, category: "x", listing_kind: i % 2 ? "product" : "service", media: [{ url: "https://cdn.test/" + i + ".jpg", type: "image/jpeg" }] });
  listings.unshift({ id: "nophoto", seller_id: id(1), title: "No photo", media: [] });
  listings.unshift({ id: "video", seller_id: id(1), title: "Video only", media: [{ url: "https://cdn.test/v.mp4", type: "video/mp4" }] });
  listings.unshift({ id: "private", seller_id: PRIVATE, title: "Private seller", media: [{ url: "https://cdn.test/p.jpg" }] });
  const campaigns = [{ id: "c1", owner_id: id(1), title: "Roof", goal_bfc: 1000, raised_bfc: 200, media: [], share_id: "abcdefghijklmnop" }, { id: "c2", owner_id: PRIVATE, title: "Hidden", share_id: "qrstuvwxyzabcdef" }];
  const people = [{ user_id: ME, username: "me" }, { user_id: id(2), username: "two", display_name: "Two Co", tagline: "We make", avatar_url: null }, { user_id: PRIVATE, username: "private" }, { user_id: id(3), username: "three" }];
  const db = H.fakeDb((table) => {
    if (table === "marketplace_listings") return { data: listings, error: null };
    if (table === "crowdfunding_campaigns") return { data: campaigns, error: null };
    if (table === "bf_profiles") return { data: people, error: null };
    return { data: null, error: null };
  });
  let asked = [];
  const stubs = { supabase: db.client, publicOwnersAmong: async (ids) => { asked = ids; return new Set(ids.filter(x => x !== PRIVATE)); } };
  const fn = H.route(FILES[SERVER], "get", "/api/home/starter", stubs, T.libRequire);
  const r = fn ? await fn({}) : { status: "no route" };
  const b = r.body || {};
  const q = t => db.log.find(x => x.table === t) || { filters: [] };
  check("S1. it answers listings, campaigns and people", r.status === 200 && Array.isArray(b.listings) && Array.isArray(b.campaigns) && Array.isArray(b.people), J([r.status, r.err && r.err.message]));
  check("S2. listings: active only, newest first", H.filterVal(q("marketplace_listings"), "eq", "status") === "active" && (q("marketplace_listings").filters.find(f => f[0] === "order") || [])[2].ascending === false);
  check("S3. ...only those with a photo (a video or no media is left out), at most 8",
    b.listings && b.listings.length === 8 && !b.listings.some(l => ["nophoto", "video"].indexOf(l.id) !== -1) && b.listings.every(l => /\.jpg$/.test(l.photo)), J(b.listings && b.listings.map(l => l.id)));
  check("S4. ...each with its kind (product or service), title, price and photo, nothing else",
    b.listings && J(Object.keys(b.listings[0]).sort()) === J(["category", "id", "kind", "photo", "price_bfc", "title"]) && b.listings[1].kind === "service", J(b.listings && b.listings[0]));
  check("S5. campaigns: active ones with a share link, linked by it", H.filterVal(q("crowdfunding_campaigns"), "eq", "status") === "active" &&
    J(q("crowdfunding_campaigns").filters.find(f => f[0] === "not")) === J(["not", "share_id", "is", null]) && b.campaigns && b.campaigns[0] && b.campaigns[0].link === "/campaign/abcdefghijklmnop", J(b.campaigns));
  check("S6. people: members with a handle, never the member themself, each with a Visit link to /@handle and no member id",
    b.people && J(b.people.map(p => p.link)) === J(["/@two", "/@three"]) && b.people[0].name === "Two Co" && b.people[1].name === "@three" && !b.people.some(p => "user_id" in p), J(b.people));
  check("S7. nothing from a member whose page is not public: their listing, campaign and page are left out (publicOwnersAmong asked about every owner)",
    asked.indexOf(PRIVATE) !== -1 && !J(b).includes("Private seller") && !J(b).includes("Hidden") && !J(b).includes("/@private"));
  const stmt = H.routeStatement(FILES[SERVER], "get", "/api/home/starter") || "";
  check("S8. sign-in required, and no sample or placeholder records", /^app\.get\("\/api\/home\/starter", requireAuth, async function/.test(stmt) && !/sample|placeholder|lorem|demo/i.test(stmt));

  /* ══ P ══ */
  console.log("\n══ P. home.html ══");
  const pg = FILES[PAGE] || "";
  check("P1. Make your first post opens the Create sheet (scripts/bf-tabbar.js)", has(pg, "id=\"openCreate\"") && has(pg, "  if (window.BFTabbar) { window.BFTabbar.openCreate(btn); return; }"));
  check("P2. New in the Market, Campaigns and People, from GET /api/home/starter only", has(pg, "fetch(API_URL + \"/api/home/starter\"") &&
    has(pg, "id=\"marketList\"") && has(pg, "id=\"campaignList\"") && has(pg, "id=\"peopleList\"") && has(pg, "New in the Market"));
  check("P3. each list says plainly when it is empty", has(pg, "No listings with a photo yet.") && has(pg, "No shared campaigns right now.") && has(pg, "  if (!list.length) { el.innerHTML = '<p class=\"empty\">No public member pages yet.</p>'; return; }"));
  check("P4. a failed load says so, and does not claim there is nothing", has(pg, "It is not a statement that there is nothing here.") && has(pg, "  } catch (e) {\n    showError();\n  }"));
  check("P5. the plain line: posts and the four tabs arrive later", has(pg, "Posts are coming. The Following, Local, Market and For You tabs arrive with them."));
  check("P6. people have a Visit button to their page", has(pg, "aria-label=\"Visit ' + escapeHtml(p.name) + '\">Visit</a>"));
  check("P7. a desktop has the 600 px column and a right column; a phone one column",
    has(pg, ".home-grid{display:grid;grid-template-columns:minmax(0,600px) minmax(0,300px);") && /@media \(max-width: 760px\)\{[\s\S]{0,200}\.home-grid\{grid-template-columns:minmax\(0,1fr\)/.test(pg));
  check("P8. no sample people, listings or numbers in the page", !/Jane|John|Lorem|sample|example\.com/i.test(pg.replace(/\/\*[\s\S]*?\*\//g, "")));
  check("P9. the page carries the theme, the session guard, the phone stylesheet last in the head, the bfc notice and the legal footer, and no Guide",
    has(pg, "<script src=\"/scripts/bf-session.js\"></script>") && pg.indexOf("/css/bf-phone.css") > pg.indexOf("</style>") && pg.indexOf("/css/bf-phone.css") < pg.indexOf("</head>") &&
    has(pg, "data-bfc-notice") && has(pg, "data-bf-legal-footer") && !has(pg, "termaximus-guide.js"));

  /* ══ O ══ */
  console.log("\n══ O. signed out ══");
  const sess = FILES[SESSION] || "";
  const at = sess.indexOf("    if ((window.location.pathname === \"/home.html\"");
  const block = at < 0 ? "" : sess.slice(at, sess.indexOf("    window.location.replace(LOGIN_PAGE);", at));
  function returnTo(pathname, search) {
    const saved = {};
    try { vm.runInNewContext(block, { window: { location: { pathname, search } }, write: (k, v) => { saved[k] = v; } }); } catch (e) { return "threw " + e.message; }
    return saved.bf_return_to || null;
  }
  check("O1. /home.html signed out is kept to come back to", returnTo("/home.html", "") === "/home.html", returnTo("/home.html", ""));
  check("O2. an Inbox address with a tab or a conversation is kept",
    returnTo("/inbox.html", "?tab=approvals") === "/inbox.html?tab=approvals" && returnTo("/inbox.html", "?with=" + ME) === "/inbox.html?with=" + ME && returnTo("/inbox.html", "") === "/inbox.html");
  check("O3. anything else is not: other queries, other pages",
    returnTo("/home.html", "?x=1") === null && returnTo("/inbox.html", "?tab=evil") === null && returnTo("/inbox.html", "?with=https://evil") === null && returnTo("/dashboard.html", "") === null);
  check("O4. ...and the page is then sent to sign in", at > 0 && sess.indexOf("    window.location.replace(LOGIN_PAGE);", at) > at);

  T.finish();
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
