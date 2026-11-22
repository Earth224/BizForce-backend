"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkPublicPostPage.js — a post's public page, bizforceai.net/p/<id>, and
   the report menu on a shared campaign (P2-3, Nov 20 2026; lib/postPage.js,
   lib/posts.js publicPost, GET /p/:id, scripts/bf-post-page.js, _redirects,
   app.html, scripts/bf-campaign.js, lib/safety.js).

   WHAT THIS PROVES (an in-memory database, scripts/_p23Db.js; the route run in
   a vm with its own text from server.js)
     A. THE PAGE: the author and the first words as its title, the Open Graph
        and Twitter tags (the first photo's thumbnail as the image), noindex,
        canonical; the text escaped; only https pictures; the counts; Like,
        Talk, Save, Follow and Share; never the author's id.
     B. NO POST: one page, "No post found", for every reason, with no buttons.
     C. WHICH POSTS: only public, published, not hidden by moderation, by a
        member whose pages are public; a followers-only, pending, hidden or
        removed post, or one whose author's pages are not public, is no post.
     D. THE ROUTE: a bad id, a post that is not shown, and a viewer either side
        of a block all get 404 and the same page; a shown post 200, HTML, kept
        only by the viewer's own browser (Cache-Control private), limited.
     E. THE BROWSER: Netlify proxies /p/:id to the backend; signed out, the
        buttons keep this page in bf_return_to and sign-in brings the member
        back (app.html allows /p/<id>); signed in, they open the post in the
        app; Share is the device's share sheet, else the link copied; the
        three-dot menu reports a post.
     F. A SHARED CAMPAIGN: /campaign/<id> has the same menu, and a report
        naming the campaign by its share link is accepted.
     G. NAMED (Nov 21 2026, P3-1B): MEMBERS' GOOGLE OPTIMISATION. A paid
        member's published public post with Show in Google on is the one
        indexable post page: robots "index, follow", the canonical URL, the
        search title and description (else the first words) in <title>, the
        meta description and Open Graph, and schema.org SocialMediaPosting
        (author, date, image) with nothing able to close its script. A free
        account's post (even with search_visible set), Show in Google off,
        and no tier answer all stay noindex. /sitemap-posts.xml lists exactly
        the indexable posts (not hidden, author's pages public); robots.txt
        allows /p/ and names it; the sitemap index and _redirects carry it.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const vm = require("vm");
const H = require("./_p21Harness");
const sh = require("./_shared");
const { memDb } = require("./_p23Db");

const SERVER = "@server.js", PAGE = "@lib/postPage.js", POSTS = "@lib/posts.js", SAFETY = "@lib/safety.js", CS = "@lib/campaignShare.js";
const PP_JS = "scripts/bf-post-page.js", REDIRECTS = "_redirects", APP = "app.html", CAMPAIGN_JS = "scripts/bf-campaign.js";
const ROBOTS = "robots.txt", SITEMAP_INDEX = "sitemap.xml";   // NAMED (Nov 21 2026, P3-1B)
const MUTATIONS = {
  // NAMED (Nov 21 2026, P3-1B): BEFORE the robots line was always noindex (the mutation removed it). AFTER noindex unless the post
  // is indexable; the mutation makes every page indexable.
  "page-indexed": [[PAGE, "(seo ? \"index, follow\" : \"noindex\")", "\"index, follow\""]],
  // NAMED (Nov 21 2026, P3-1B): section G
  "free-indexable": [[POSTS, "  return (await deps.tierOf(post.author_id)) === \"member\";\n}", "  return true;\n}"]],
  "search-off-indexed": [[POSTS, "post.audience !== \"public\" || post.search_visible !== true) return false;", "post.audience !== \"public\") return false;"]],
  "ld-unescaped": [[PAGE, "  return JSON.stringify(data).replace(/</g, \"\\\\u003c\")", "  return JSON.stringify(data).replace(/\\u0000/g, \"\")"]],
  "sitemap-lists-all": [[SERVER, " && await P.indexablePost(deps, r)) kept.push(r); }", ") kept.push(r); }"]],
  "sitemap-keeps-hidden": [[SERVER, "      for (const r of list) { if (!hidden.has(r.id) && ", "      for (const r of list) { if ("]],
  "robots-no-posts": [[ROBOTS, "Sitemap: https://bizforceai.net/sitemap-posts.xml\n", ""]],
  "body-unescaped": [[PAGE, "'\" id=\"ppBody\">' + esc(post.body) + '</p>'", "'\" id=\"ppBody\">' + post.body + '</p>'"]],
  "http-pictures": [[PAGE, "function httpsUrl(url) { return typeof url === \"string\" && /^https:\\/\\/[", "function httpsUrl(url) { return typeof url === \"string\" && /^https?:\\/\\/["]],
  "followers-public": [[POSTS, '  if (!post || post.status !== "published" || post.audience !== "public") return null;', '  if (!post || post.status !== "published") return null;']],
  "hidden-public": [[POSTS, '  if ((await SF.hiddenAmong(deps.sb, "post", [post.id])).has(post.id)) return null;\n', ""]],
  "private-author-public": [[POSTS, "  if (!(deps.ownerPublic && (await deps.ownerPublic(post.author_id)) === true)) return null;\n", ""]],
  "blocked-viewer-sees": [[SERVER, '    if (viewer && await require("./lib/safety").blockedEitherWay(supabase, viewer, post.author.id)) return', "    if (false) return"]],
  "shared-cache": [[SERVER, '    res.set("Cache-Control", "private, max-age=60");', '    res.set("Cache-Control", "public, max-age=60");']],
  "no-return-to": [[PP_JS, '      try { localStorage.setItem("bf_return_to", window.location.pathname); } catch (e) { /* signs in to the dashboard */ }\n', ""]],
  "redirect-missing": [[REDIRECTS, "/p/:id https://dynamic-prosperity-production-5382.up.railway.app/p/:id 200\n", ""]],
  "app-no-return": [[APP, "|p\\/[0-9a-f-]{36}", ""]],
  "campaign-no-menu": [[CAMPAIGN_JS, "if (menu && root.BFSafety) root.BFSafety.mount(menu,", "if (false) root.BFSafety.mount(menu,"]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, PAGE, POSTS, SAFETY, CS, PP_JS, REDIRECTS, APP, CAMPAIGN_JS, ROBOTS, SITEMAP_INDEX]);
const { FILES, check, J, has } = T;
const PG = T.libRequire("./lib/postPage");
const P = T.libRequire("./lib/posts");

const ME = "11111111-1111-4111-8111-111111111111", THEM = "22222222-2222-4222-8222-222222222222", PRIV = "55555555-5555-4555-8555-555555555555";
const pid = n => "aaaaaaaa-0000-4000-8000-" + String(n).padStart(12, "0");
const PHOTO = "https://x.supabase.co/storage/v1/object/public/bf-public/media/" + ME + "/";
function world() {
  const db = memDb({
    posts: [], post_media: [], member_media: [], moderation_queue: [], member_blocks: [{ blocker_id: THEM, blocked_id: ME }], member_mutes: [], follows: [],
    bf_profiles: [{ user_id: ME, username: "rose", display_name: "Rose Hill", avatar_url: "https://x.supabase.co/a.png" }], profiles: [], post_likes: [], post_saves: []
  });
  const deps = { sb: db.client, now: () => "2026-11-20T12:00:00.000Z", ownerPublic: async id => id !== PRIV, env: { SUPABASE_URL: "https://x.supabase.co" } };
  return { db, deps };
}
const row = (id, extra) => Object.assign({ id, author_id: ME, kind: "text", body: "Fresh bread today", audience: "public", status: "published", like_count: 3, comment_count: 1, save_count: 0, share_count: 0,
  created_at: "2026-11-19T10:00:00.000Z", published_at: "2026-11-19T10:00:00.000Z" }, extra || {});
const meta = (html, name) => { const m = new RegExp('<meta (?:property|name)="' + name.replace(/[.:]/g, "\\$&") + '" content="([^"]*)"').exec(html); return m ? m[1] : null; };

/* GET /p/:id run in a vm with its own text */
function routeOf(stubs) {
  const S = FILES[SERVER];
  const at = S.indexOf('app.get("/p/:id", postPageLimiter, async function (req, res) {');
  if (at === -1) return null;
  const end = sh.braceMatch(S, S.indexOf("{", S.indexOf("async function (req, res)", at)));
  const code = S.slice(at, end + 3);
  let handler = null;
  const ctx = Object.assign({ console: { log() {}, warn() {}, error() {} }, require: T.libRequire, String, Promise, postPageLimiter: function () {},
    app: { get: function (p) { if (p === "/p/:id") handler = arguments[arguments.length - 1]; } } }, stubs);
  vm.createContext(ctx);
  vm.runInContext(code, ctx);
  return async req => {
    const res = { code: 200, headers: {}, text: null, status(c) { this.code = c; return this; }, set(k, v) { this.headers[k.toLowerCase()] = v; return this; }, send(t) { this.text = String(t); return this; } };
    await handler(Object.assign({ params: {}, headers: {} }, req), res);
    return res;
  };
}

(async function main() {
  /* ── A ── */
  console.log("\n══ A. the page ══");
  let w = world();
  w.db.t.posts.push(row(pid(1), { kind: "photo", body: "Fresh bread today <script>alert(1)</script> & \"more\"" }));
  w.db.t.member_media.push({ id: pid(80), path: "media/" + ME + "/full.webp" }, { id: pid(81), path: "media/" + ME + "/thumb.webp" }, { id: pid(82), path: "media/" + ME + "/two.webp" });
  w.db.t.post_media.push({ post_id: pid(1), media_id: pid(80), thumb_media_id: pid(81), idx: 0 }, { post_id: pid(1), media_id: pid(82), thumb_media_id: null, idx: 1 });
  const shown = await P.publicPost(w.deps, pid(1));
  const html = PG.renderPostPage(shown);
  check("A1. the title is the author and the first words; og and twitter titles match", shown && /^Rose Hill on BizForce: Fresh bread today/.test(PG.titleFor(shown)) &&
    meta(html, "og:title") === meta(html, "twitter:title") && meta(html, "og:title").indexOf("Rose Hill on BizForce: Fresh bread today") === 0, meta(html, "og:title"));
  check("A2. og:image is the first photo's thumbnail, the card large; og:url and canonical are the post's own link", meta(html, "og:image") === PHOTO + "thumb.webp" &&
    meta(html, "twitter:card") === "summary_large_image" && meta(html, "og:url") === "https://bizforceai.net/p/" + pid(1) && has(html, '<link rel="canonical" href="https://bizforceai.net/p/' + pid(1) + '"/>'), meta(html, "og:image"));
  // NAMED (Nov 21 2026, P3-1B): these deps carry no tier, so the page is the noindex one (section G holds the one exception)
  check("A3. noindex: a member posting has not asked to be in search engines", has(html, '<meta name="robots" content="noindex"/>'));
  check("A4. the text is escaped, never markup", html.indexOf("<script>alert(1)") === -1 && has(html, "&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;more&quot;"));
  check("A5. the photos, each thumbnail opening its full photo; the counts", has(html, '<div class="pp-photos n2">') && has(html, '<a href="' + PHOTO + 'full.webp" target="_blank" rel="noopener"><img src="' + PHOTO + 'thumb.webp"') &&
    has(html, '<p class="pp-counts" id="ppCounts">3 likes · 1 comment · 0 shares</p>'));
  check("A6. Like, Talk, Save and Follow, then Share; the author links to /@rose", ["like", "talk", "save", "follow"].every(a => has(html, 'data-pp-act="' + a + '" href="/app.html"')) && has(html, 'id="ppShare">Share</button>') &&
    has(html, '<a class="pp-name" href="/@rose">Rose Hill</a>'));
  check("A7. never the author's id", html.indexOf(ME) === html.indexOf("media/" + ME) || html.split(ME).length - 1 === (html.match(new RegExp("media/" + ME, "g")) || []).length);
  const hostile = PG.renderPostPage(Object.assign({}, shown, { photos: [{ url: "http://plain.example/a.png", thumb_url: "javascript:alert(1)" }], author: { name: "X", avatar_url: "http://plain.example/b.png" } }));
  check("A8. only https pictures: an http photo or avatar and a javascript: thumbnail are dropped", hostile.indexOf("plain.example") === -1 && hostile.indexOf("javascript:") === -1);

  /* ── B ── */
  console.log("\n══ B. no post ══");
  const none = PG.renderPostPage(null);
  check("B1. \"No post found\": one page, no buttons, the site's own image", has(none, "<h1>No post found</h1>") && has(none, 'data-state="none"') && none.indexOf("data-pp-act") === -1 &&
    meta(none, "og:image") === PG.DEFAULT_IMAGE && has(none, '<meta name="robots" content="noindex"/>'));

  /* ── C ── */
  console.log("\n══ C. which posts ══");
  w = world();
  w.db.t.posts.push(row(pid(1)), row(pid(2), { audience: "followers" }), row(pid(3), { status: "pending" }), row(pid(4), { status: "removed" }), row(pid(5)), row(pid(6), { author_id: PRIV }));
  w.db.t.moderation_queue.push({ object_type: "post", object_id: pid(5), state: "hidden" });
  const got = [];
  for (let i = 1; i <= 6; i++) got.push(!!(await P.publicPost(w.deps, pid(i))));
  check("C1. public and published only: followers-only, pending, removed, hidden, and a member whose pages are not public are no post", J(got) === J([true, false, false, false, false, false]), J(got));

  /* ── D ── */
  console.log("\n══ D. the route ══");
  w = world();
  w.db.t.posts.push(row(pid(1)), row(pid(2), { audience: "followers" }));
  let viewer = null;
  const run = routeOf({ supabase: w.db.client, postDeps: () => Object.assign({ claims: () => null, push: async () => {} }, w.deps), viewerIdFrom: async () => viewer });
  check("D0. the route is there", !!run);
  let r = await run({ params: { id: pid(1) } });
  check("D1. a shown post: 200, HTML, nosniff, kept only by the viewer's own browser", r.code === 200 && /text\/html/.test(r.headers["content-type"]) && r.headers["x-content-type-options"] === "nosniff" &&
    r.headers["cache-control"] === "private, max-age=60" && has(r.text, 'data-post-id="' + pid(1) + '"'), J(r.headers));
  const bads = [await run({ params: { id: "nope" } }), await run({ params: { id: pid(2) } }), await run({ params: { id: pid(99) } })];
  check("D2. a bad id, a post not shown and no post: 404 and the same page", bads.every(x => x.code === 404 && x.text === none), J(bads.map(x => x.code)));
  viewer = THEM;
  r = await run({ params: { id: pid(1) } });
  check("D3. a signed-in viewer either side of a block: 404, the same page", r.code === 404 && r.text === none);
  const S = FILES[SERVER];
  check("D4. it has its own limiter, and sits with the campaign page", /const postPageLimiter = rateLimit\(\{/.test(S) && S.indexOf('app.get("/p/:id", postPageLimiter,') !== -1);

  /* ── E ── */
  console.log("\n══ E. the browser ══");
  check("E1. Netlify proxies /p/:id to the backend, next to the campaign page", /\n\/p\/:id https:\/\/dynamic-prosperity-production-5382\.up\.railway\.app\/p\/:id 200\n/.test("\n" + FILES[REDIRECTS]));
  const js = FILES[PP_JS] || "";
  check("E2. signed out, the buttons keep this page and go to sign-in", has(js, 'try { localStorage.setItem("bf_return_to", window.location.pathname); } catch (e) {'));
  check("E3. sign-in brings the member back to a post's page", has(FILES[APP], "|p\\/[0-9a-f-]{36}|"));
  check("E4. signed in, they open the post in the app (Talk with &talk=1; Follow the author's storefront)",
    has(js, 'a.href = act === "follow" && handle ? "/@" + encodeURIComponent(handle) : "/home.html?post=" + encodeURIComponent(id) + (act === "talk" ? "&talk=1" : "");'));
  check("E5. Share is the device's share sheet, else the link copied; the menu reports a post",
    has(js, "navigator.share({ title: title, url: url })") && has(js, "navigator.clipboard.writeText(url)") && has(js, 'window.BFSafety.mount(menu, { type: "post", id: id, handle: handle || null, where: url });'));

  /* ── F ── */
  console.log("\n══ F. a shared campaign ══");
  const cj = FILES[CAMPAIGN_JS] || "";
  check("F1. /campaign/<id> has the menu, naming the campaign by its share link", has(FILES[CS], '<span class="cmp-menu" id="cmpMenu"></span>') && has(FILES[CS], '<script src="/scripts/bf-safety.js"></script>') &&
    has(cj, 'if (menu && root.BFSafety) root.BFSafety.mount(menu, { type: "campaign", shareId: shareId, name: main.getAttribute("data-title") || "", where: url });'));
  const SFX = T.libRequire("./lib/safety");
  const okShare = SFX.validateReport({ object_type: "campaign", share_id: "abcdefghijklmnop", reason: "scam" });
  const badShare = SFX.validateReport({ object_type: "campaign", share_id: "ABC", reason: "scam" });
  check("F2. a report of a campaign by its share link is accepted; a share id that is not one is refused", !okShare.error && !!badShare.error, J([okShare, badShare]));
  check("F3. posts and comments can be reported", SFX.REPORTABLE_NOW.indexOf("post") !== -1 && SFX.REPORTABLE_NOW.indexOf("comment") !== -1);


  /* ── G (NAMED, Nov 21 2026, P3-1B): members' Google optimisation ── */
  console.log("\n══ G. members' posts in Google, and the posts sitemap ══");
  {
    const FREE_AUTHOR = "66666666-6666-4666-8666-666666666666";
    const gw = world();
    gw.deps.tierOf = async id => (id === FREE_AUTHOR ? "free" : "member");
    gw.db.t.bf_profiles.push({ user_id: FREE_AUTHOR, username: "fay", display_name: "Fay", avatar_url: null });
    gw.db.t.posts.push(
      row(pid(11), { kind: "photo", body: "Fresh sourdough every morning </script><b>hi</b>", search_visible: true, seo_title: "Sourdough in Leeds", seo_description: "Baked daily at dawn." }),
      row(pid(12), { search_visible: true }),
      row(pid(13), { search_visible: false }),
      row(pid(14), { author_id: FREE_AUTHOR, search_visible: true, seo_title: "Free account" }),
      row(pid(15), { audience: "followers", search_visible: true }),
      row(pid(16), { search_visible: true }),
      row(pid(17), { author_id: PRIV, search_visible: true }),
      row(pid(18), { status: "pending", search_visible: true }));
    gw.db.t.member_media.push({ id: pid(90), path: "media/" + ME + "/full.webp" }, { id: pid(91), path: "media/" + ME + "/thumb.webp" });
    gw.db.t.post_media.push({ post_id: pid(11), media_id: pid(90), thumb_media_id: pid(91), idx: 0 });
    gw.db.t.moderation_queue.push({ object_type: "post", object_id: pid(16), state: "hidden" });
    const g11 = await P.publicPost(gw.deps, pid(11));
    const h = PG.renderPostPage(g11);
    const url = "https://bizforceai.net/p/" + pid(11);
    check("G1. a paid member's public post with Show in Google on: robots \"index, follow\" and the canonical URL",
      !!g11 && !!g11.seo && has(h, '<meta name="robots" content="index, follow"/>') && has(h, '<link rel="canonical" href="' + url + '"/>'), J(g11 && g11.seo));
    check("G2. ...its search title and description in <title>, the meta description and Open Graph",
      has(h, "<title>Sourdough in Leeds</title>") && meta(h, "description") === "Baked daily at dawn." && meta(h, "og:title") === "Sourdough in Leeds" &&
      meta(h, "og:description") === "Baked daily at dawn." && meta(h, "og:url") === url, J([meta(h, "og:title"), meta(h, "description")]));
    const ldm = /<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(h);
    let ld = null; try { ld = ldm && JSON.parse(ldm[1]); } catch (e) { ld = null; }
    check("G3. ...and schema.org SocialMediaPosting: headline, author (Person, name and page), date and image",
      !!ld && ld["@context"] === "https://schema.org" && ld["@type"] === "SocialMediaPosting" && ld.headline === "Sourdough in Leeds" && ld.url === url &&
      ld.author && ld.author["@type"] === "Person" && ld.author.name === "Rose Hill" && ld.author.url === "https://bizforceai.net/@rose" &&
      ld.datePublished === "2026-11-19T10:00:00.000Z" && ld.image === PHOTO + "thumb.webp", ldm && ldm[1].slice(0, 200));
    check("G4. ...where nothing in the post can close the script: no \"<\" inside it, and the text comes back whole",
      !!ldm && ldm[1].indexOf("<") === -1 && ld && ld.articleBody === "Fresh sourdough every morning </script><b>hi</b>", ldm && ldm[1].slice(-120));
    const h12 = PG.renderPostPage(await P.publicPost(gw.deps, pid(12)));
    check("G5. no search title or description: still indexable, with the first words", has(h12, '<meta name="robots" content="index, follow"/>') && /^Rose Hill on BizForce: Fresh bread today/.test(meta(h12, "og:title")));
    const noindex = async id => { const x = await P.publicPost(gw.deps, id); return !!x && x.seo === null && has(PG.renderPostPage(x), '<meta name="robots" content="noindex"/>') && PG.renderPostPage(x).indexOf("application/ld+json") === -1; };
    check("G6. Show in Google off: noindex, no structured data", await noindex(pid(13)));
    check("G7. a free account's post, even with search_visible set: noindex (free accounts' posts are never indexable)", await noindex(pid(14)));
    const noTier = Object.assign({}, gw.deps); delete noTier.tierOf;
    const nt = await P.publicPost(noTier, pid(11));
    check("G8. no tier answer: noindex (never indexed on a guess)", !!nt && nt.seo === null);
    check("G9. indexablePost is published, public, Show in Google on and a member author, and nothing else",
      (await P.indexablePost(gw.deps, row(pid(1), { search_visible: true }))) === true && (await P.indexablePost(gw.deps, row(pid(1), { search_visible: true, audience: "followers" }))) === false &&
      (await P.indexablePost(gw.deps, row(pid(1), { search_visible: true, status: "pending" }))) === false && (await P.indexablePost(gw.deps, row(pid(1)))) === false &&
      (await P.indexablePost(gw.deps, row(pid(1), { search_visible: true, author_id: FREE_AUTHOR }))) === false);

    // the sitemap route, run in a vm with its own text
    const S = FILES[SERVER];
    const at = S.indexOf("let postSitemapCache = { xml: null, at: 0 };");
    const rs = S.indexOf('app.get("/api/sitemap/posts.xml", postPageLimiter, async function (req, res) {', at);
    let smHandler = null;
    if (at !== -1 && rs !== -1) {
      const end = sh.braceMatch(S, S.indexOf("{", S.indexOf("async function (req, res)", rs)));
      const ctx = { console: { log() {}, warn() {}, error() {} }, require: T.libRequire, String, Promise, Date, postPageLimiter: function () {},
        supabase: gw.db.client, BLOG_SITEMAP_CACHE_MS: 0, supportLinks: T.libRequire("./lib/supportLinks"), postDeps: () => gw.deps,
        publicOwnersAmong: async ids => new Set(ids.filter(id => id !== PRIV)),
        app: { get: function (p) { if (p === "/api/sitemap/posts.xml") smHandler = arguments[arguments.length - 1]; } } };
      vm.createContext(ctx);
      vm.runInContext(S.slice(at, end + 3), ctx);
    }
    const smRes = { code: 200, headers: {}, text: null, status(c) { this.code = c; return this; }, set(k, v) { this.headers[k.toLowerCase()] = v; return this; }, type() { return this; }, send(t) { this.text = String(t); return this; } };
    if (smHandler) await smHandler({ params: {}, headers: {}, query: {} }, smRes);
    const locs = ((smRes.text || "").match(/<loc>[^<]*<\/loc>/g) || []).map(x => x.slice(5, -6)).sort();
    check("G10. /sitemap-posts.xml lists exactly the indexable posts: not Show in Google off, a free account's, followers-only, hidden, a private author's or pending",
      !!smHandler && smRes.code === 200 && /application\/xml/.test(smRes.headers["content-type"] || "") && J(locs) === J([pid(11), pid(12)].map(id => "https://bizforceai.net/p/" + id).sort()) &&
      /<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/.test(smRes.text) && /<lastmod>2026-11-19<\/lastmod>/.test(smRes.text), J([smRes.code, locs]));
    check("G11. ...it is public and cached ten minutes like the other sitemaps", smRes.headers["cache-control"] === "public, max-age=600" &&
      T.libRequire("./lib/routeAccess").groupOf("get /api/sitemap/posts.xml") === "P");
    const robots = FILES[ROBOTS] || "";
    check("G12. robots.txt allows /p/ and names the posts sitemap", /\nAllow: \/p\/\n/.test("\n" + robots) && /\nSitemap: https:\/\/bizforceai\.net\/sitemap-posts\.xml\n/.test("\n" + robots) && !/Disallow: \/p\//.test(robots), robots);
    check("G13. the sitemap index lists it, and Netlify proxies it to the backend, above every catch-all",
      has(FILES[SITEMAP_INDEX] || "", "<sitemap><loc>https://bizforceai.net/sitemap-posts.xml</loc></sitemap>") &&
      /\n\/sitemap-posts\.xml https:\/\/dynamic-prosperity-production-5382\.up\.railway\.app\/api\/sitemap\/posts\.xml 200\n/.test("\n" + FILES[REDIRECTS]) &&
      FILES[REDIRECTS].indexOf("/sitemap-posts.xml") < FILES[REDIRECTS].indexOf("\n/*"));   // the first line that starts with a catch-all
  }
  T.finish();
})().catch(e => { check("the check ran to the end", false, e && (e.stack || e.message || JSON.stringify(e))); T.finish(); });
