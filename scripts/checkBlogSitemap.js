"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkBlogSitemap — published blog posts are listed in a sitemap, and
   mrearthrose.net gets the supplement rules.

   GET /api/sitemap/blog.xml and its helpers are lifted from server.js and run
   against an in-memory content_library and bf_profiles that honour every
   filter the route sends. blogpost.html's own canonical expression is lifted
   and evaluated beside the sitemap's. The frontend's sitemap.xml,
   sitemap-pages.xml, _redirects and robots.txt are read as files. The host map
   is exercised through the generate route's own domainProfileName statement.
   No network, no model, no database.

   WHAT THIS PROVES
     A. The sitemap lists every SERVED post (type blog, status published, a
        slug, no site, an author with a username) and nothing else: not a
        draft, not an external-site row (draft or published), not "used",
        not an sms row, not a row without a slug, not an author without a
        username. The existing Facebook-ad post is in it, with its lastmod.
        Rows past the first 1,000 are read.
     B. Every <loc> equals the canonical blogpost.html sets, for the stored
        handle's casing and for handles and slugs needing encoding.
     C. The XML is well-formed and & < > never appear raw; the escaper
        escapes them.
     D. The route: application/xml, cached in memory for 10 minutes (one
        read pair per window), a read failure is a 503 and is not cached.
     E. The frontend: sitemap.xml is an index of exactly sitemap-pages.xml
        and sitemap-blog.xml; sitemap-pages.xml keeps /, /app, /vitality,
        /xxl-xtreme and adds /suppressed.html; _redirects rewrites
        /sitemap-blog.xml (200) to this route on blogpost.html's API host,
        above every catch-all; no static sitemap-blog.xml shadows it;
        robots.txt names the index.
     F. A money_url on mrearthrose.net (any case, with or without www.) gets
        supplement_vitality automatically; mrearthrose.com still does;
        bizforceai.net and blacksuncircle.com get none.

   MUTATE=<name> edits server.js IN MEMORY (nothing on disk is touched).
   MUTATE=all runs each in its own process and passes only if every one fails
   at least one check. A mutation whose search text does not match exactly
   once is an ERROR, never counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const SERVER = "server.js";
const FILES = { [SERVER]: fs.readFileSync(path.join(REPO, SERVER), "utf8").replace(/\r\n/g, "\n") };
const fe = (f) => { const p = path.join(FRONTEND, f); return fs.existsSync(p) ? fs.readFileSync(p, "utf8").replace(/\r\n/g, "\n") : null; };

const MUTATIONS = {
  // drafts are listed
  "drafts-included": [[SERVER, "      .eq(\"type\", \"blog\")\n      .eq(\"status\", \"published\")\n      .is(\"site\", null)\n", "      .eq(\"type\", \"blog\")\n      .is(\"site\", null)\n"]],
  // rows written for another property are listed
  "external-included": [[SERVER, "      .eq(\"status\", \"published\")\n      .is(\"site\", null)\n      .not(\"slug\", \"is\", null)\n", "      .eq(\"status\", \"published\")\n      .not(\"slug\", \"is\", null)\n"]],
  // the escaper leaves & raw
  "unescaped-ampersand": [[SERVER, "  return String(value).replace(/&/g, \"&amp;\").replace(/</g, \"&lt;\")", "  return String(value).replace(/</g, \"&lt;\")"]],
  // the loc is written raw: no encoding, no escaping
  "raw-loc": [[SERVER, "blogSitemapXmlEscape(blogSitemapLoc(handle, row.slug))", "BLOG_SITEMAP_ORIGIN + \"/blog/\" + handle + \"/\" + row.slug"]],
  // mrearthrose.net leaves the host map
  "mrearthrose-net-removed": [[SERVER, "  \"mrearthrose.com\":   \"supplement_vitality\",\n", "  \"mrearthrose.com\":   \"supplement_vitality\"\n"],
    [SERVER, "  \"mrearthrose.net\":   \"supplement_vitality\"\n};\n", "};\n"]],
  // the cache never expires
  "cache-forever": [[SERVER, "    if (!blogSitemapCache.xml || Date.now() - blogSitemapCache.at > BLOG_SITEMAP_CACHE_MS) {", "    if (!blogSitemapCache.xml) {"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}
const SRC = FILES[SERVER];

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}

/* ── an in-memory Supabase that honours every filter the route sends ──────── */
function fakeDb(tables, opts) {
  opts = opts || {};
  const log = [];
  function keep(f, r) {
    if (f[0] === "eq") return r[f[1]] === f[2];
    if (f[0] === "is") return f[2] === null ? r[f[1]] === null || r[f[1]] === undefined : r[f[1]] === f[2];
    if (f[0] === "not") { if (f[2] !== "is" || f[3] !== null) throw new Error("fake: unsupported not"); return r[f[1]] !== null && r[f[1]] !== undefined; }
    if (f[0] === "in") return f[2].indexOf(r[f[1]]) !== -1;
    throw new Error("fake: unsupported filter " + f[0]);
  }
  function from(table) {
    const q = { table, cols: "*", filters: [], order: null, range: null };
    const b = {
      select(c) { q.cols = c; return b; },
      eq(c, v) { q.filters.push(["eq", c, v]); return b; },
      is(c, v) { q.filters.push(["is", c, v]); return b; },
      not(c, op, v) { q.filters.push(["not", c, op, v]); return b; },
      in(c, v) { q.filters.push(["in", c, v]); return b; },
      order(c, o) { q.order = [c, o]; return b; },
      range(a, z) { q.range = [a, z]; return b; },
      then(res, rej) {
        log.push(q);
        if (opts.fail && opts.fail(q)) return Promise.resolve({ data: null, error: { message: "read refused" } }).then(res, rej);
        let hits = (tables[table] || []).filter(r => q.filters.every(f => keep(f, r)));
        if (q.order) hits = hits.slice().sort((x, y) => (String(x[q.order[0]]) < String(y[q.order[0]]) ? -1 : String(x[q.order[0]]) > String(y[q.order[0]]) ? 1 : 0) * (q.order[1] && q.order[1].ascending === false ? -1 : 1));
        if (q.range) hits = hits.slice(q.range[0], q.range[1] + 1);
        const cols = q.cols.split(",").map(c => c.trim());
        return Promise.resolve({ data: hits.map(r => { const o = {}; cols.forEach(c => { o[c] = r[c] === undefined ? null : r[c]; }); return o; }), error: null }).then(res, rej);
      }
    };
    return b;
  }
  return { log, client: { from } };
}

/* ── the route, lifted ─────────────────────────────────────────────────────── */
const NAMES = ["BLOG_SITEMAP_ORIGIN", "BLOG_SITEMAP_CACHE_MS", "BLOG_SITEMAP_PAGE", "BLOG_SITEMAP_MAX_URLS", "blogSitemapCache",
  "blogSitemapXmlEscape", "blogSitemapLoc", "buildBlogSitemapXml", "readServedBlogPosts"];
const DEFS = NAMES.map(n => s.definitionOf(SRC, n) || "");
const SIG = "app.get(\"/api/sitemap/blog.xml\", async function (req, res) {";
const at = SRC.indexOf(SIG);
const ROUTE = at < 0 ? "" : SRC.slice(at, s.braceMatch(SRC, SRC.indexOf("{", at)) + 2);
function load(db, clock) {
  let handler = null;
  const ctx = { supabase: db.client, console: { log() {}, error() {}, warn() {} }, String, encodeURIComponent,
    Date: { now: () => clock.now },
    app: { get(p, h) { if (p === "/api/sitemap/blog.xml") handler = h; } } };
  vm.createContext(ctx);
  vm.runInContext(DEFS.join("\n") + "\n" + ROUTE + "\n;this.__api = { blogSitemapXmlEscape, blogSitemapLoc, buildBlogSitemapXml };", ctx);
  return { ctx, call: async function () {
    const res = { code: 200, headers: {}, body: null, status(c) { this.code = c; return this; }, set(k, v) { this.headers[k.toLowerCase()] = v; return this; },
      type(t) { this.headers["content-type"] = t; return this; }, send(b) { this.body = String(b); return this; } };
    await handler({}, res);
    return res;
  } };
}

const OWNER = "ea887c6e-e278-4a15-b7e9-cd78a9949b78", OTHER = "11111111-0000-4000-8000-000000000002", ODD = "11111111-0000-4000-8000-000000000003", NOHANDLE = "11111111-0000-4000-8000-000000000004";
const FB_SLUG = "how-do-you-get-customers-after-facebook-ad-account-disabled";
const post = (o) => Object.assign({ type: "blog", status: "published", site: null, published_at: "2026-09-01T10:00:00Z", created_at: "2026-09-01T09:00:00Z" }, o);
function fixture() {
  return {
    bf_profiles: [{ user_id: OWNER, username: "earth-rose" }, { user_id: OTHER, username: "Some-Seller" }, { user_id: ODD, username: "a&b<c>é" }, { user_id: NOHANDLE, username: null }],
    content_library: [
      post({ user_id: OWNER, slug: FB_SLUG, published_at: "2026-10-08T17:02:11Z", created_at: "2026-10-08T17:02:00Z" }),
      post({ user_id: OWNER, slug: "how-does-virtual-wellness-coaching-work", published_at: "2026-07-28T12:00:00Z" }),
      post({ user_id: OTHER, slug: "another-sellers-post", published_at: null, created_at: "2026-08-15T08:00:00Z" }),
      post({ user_id: ODD, slug: "x&y<z>" }),
      post({ user_id: OWNER, slug: "a-draft-post", status: "draft", published_at: null }),
      post({ user_id: OWNER, slug: "what-is-tongkat-ali", status: "draft", site: "swordvitality.com", published_at: null }),
      post({ user_id: OWNER, slug: "published-for-mrearthrose-net", site: "mrearthrose.net" }),
      post({ user_id: OWNER, slug: "an-old-used-post", status: "used" }),
      post({ user_id: OWNER, slug: "an-sms-row", type: "sms" }),
      post({ user_id: OWNER, slug: null }),
      post({ user_id: NOHANDLE, slug: "author-without-a-handle" }),
      post({ user_id: "11111111-0000-4000-8000-000000000009", slug: "author-without-a-profile" })
    ]
  };
}
const locs = (xml) => (String(xml).match(/<loc>([^<]*)<\/loc>/g) || []).map(l => l.slice(5, -6).replace(/&amp;/g, "&"));

// Well-formed: one declaration, balanced tags, and no & that is not an entity, no < outside a tag.
function wellFormed(xml) {
  if (!/^<\?xml version="1\.0" encoding="UTF-8"\?>\n/.test(xml)) return "declaration";
  const body = xml.replace(/^<\?xml[^>]*\?>\n/, "");
  if (/&(?!(?:amp|lt|gt|quot|apos);)/.test(body)) return "raw &";
  const stack = []; const re = /<(\/?)([A-Za-z][\w:-]*)([^<>]*?)(\/?)>|[<>]/g; let m;
  while ((m = re.exec(body))) {
    if (!m[2]) return "stray " + m[0];
    if (m[4] === "/") continue;
    if (m[1]) { if (stack.pop() !== m[2]) return "unbalanced " + m[2]; } else stack.push(m[2]);
  }
  return stack.length ? "unclosed " + stack.join(",") : null;
}

(async function main() {
  const clock = { now: Date.UTC(2026, 9, 19, 12) };

  /* ── A. served posts only ──────────────────────────────────────────────── */
  console.log("\n══ A. the sitemap lists every served post and nothing else ══");
  const T = fixture();
  const dbA = fakeDb(T);
  const A = load(dbA, clock);
  const r = await A.call();
  const got = locs(r.body);
  const want = [
    "https://bizforceai.net/blog/earth-rose/" + FB_SLUG,
    "https://bizforceai.net/blog/earth-rose/how-does-virtual-wellness-coaching-work",
    "https://bizforceai.net/blog/Some-Seller/another-sellers-post",
    "https://bizforceai.net/blog/a%26b%3Cc%3E%C3%A9/x%26y%3Cz%3E"
  ];
  check("A. the route is registered and answers 200", ROUTE.length > 0 && r.code === 200, r.code);
  check("A. exactly the four served posts are listed", JSON.stringify(got.slice().sort()) === JSON.stringify(want.slice().sort()), JSON.stringify(got));
  check("A. the existing Facebook-ad post is in it, at https://bizforceai.net/blog/earth-rose/" + FB_SLUG + ", lastmod 2026-10-08",
    r.body.indexOf("<url><loc>https://bizforceai.net/blog/earth-rose/" + FB_SLUG + "</loc><lastmod>2026-10-08</lastmod></url>") !== -1, r.body.slice(0, 400));
  check("A. a draft is not listed", got.every(u => u.indexOf("a-draft-post") === -1));
  check("A. an external-site row is not listed, as a draft (swordvitality.com) or even as published (mrearthrose.net)",
    got.every(u => u.indexOf("what-is-tongkat-ali") === -1 && u.indexOf("published-for-mrearthrose-net") === -1));
  check("A. a row whose status is not published (\"used\") is not listed", got.every(u => u.indexOf("an-old-used-post") === -1));
  check("A. an sms row, a row with no slug, and an author with no username or no profile are not listed",
    got.every(u => !/an-sms-row|author-without|\/null$|\/undefined$/.test(u)));
  check("A. lastmod is published_at as a date, else created_at", /another-sellers-post<\/loc><lastmod>2026-08-15<\/lastmod>/.test(r.body) && /coaching-work<\/loc><lastmod>2026-07-28<\/lastmod>/.test(r.body));
  check("A. the query itself filters type blog, status published, no site and a slug",
    (function () {
      const q = dbA.log.filter(x => x.table === "content_library")[0];
      const have = q ? q.filters.map(f => f[0] + ":" + f[1] + ":" + f[2]) : [];
      return ["eq:type:blog", "eq:status:published", "is:site:null", "not:slug:is"].every(k => have.indexOf(k) !== -1);
    })(), JSON.stringify(dbA.log[0] && dbA.log[0].filters));
  const many = { bf_profiles: [{ user_id: OWNER, username: "earth-rose" }],
    content_library: Array.from({ length: 1050 }, (_, i) => post({ user_id: OWNER, slug: "post-" + i })) };
  const M = await load(fakeDb(many), clock).call();
  check("A. rows past the first 1,000 are read: 1,050 published posts give 1,050 entries", locs(M.body).length === 1050, locs(M.body).length);

  /* ── B. the canonical ──────────────────────────────────────────────────── */
  console.log("\n══ B. every <loc> is blogpost.html's canonical ══");
  const PAGE = fe("blogpost.html") || "";
  const origin = (/var CANONICAL_ORIGIN = "([^"]+)";/.exec(PAGE) || [])[1];
  const exprAt = PAGE.indexOf("setCanonical(\n        \"/blog/\" + encodeURIComponent(d.handle) + \"/\" + encodeURIComponent(post.slug)\n      );");
  check("B. blogpost.html sets its canonical as CANONICAL_ORIGIN + \"/blog/\" + encodeURIComponent(d.handle) + \"/\" + encodeURIComponent(post.slug), d.handle being the stored username",
    origin === "https://bizforceai.net" && exprAt !== -1 && /tag\.setAttribute\("href", CANONICAL_ORIGIN \+ path\);/.test(PAGE));
  const pageCanonical = (h, sl) => origin + vm.runInNewContext("\"/blog/\" + encodeURIComponent(d.handle) + \"/\" + encodeURIComponent(post.slug)", { d: { handle: h }, post: { slug: sl }, encodeURIComponent });
  const cases = [["earth-rose", FB_SLUG], ["Some-Seller", "another-sellers-post"], ["a&b<c>é", "x&y<z>"], ["Ünïcode Name", "slug-1"]];
  check("B. the sitemap's loc equals the page's canonical, character for character, for stored casing and for handles and slugs that need encoding",
    cases.every(([h, sl]) => A.ctx.__api.blogSitemapLoc(h, sl) === pageCanonical(h, sl)), JSON.stringify(cases.map(([h, sl]) => [A.ctx.__api.blogSitemapLoc(h, sl), pageCanonical(h, sl)])));
  check("B. every listed loc, unescaped, is the canonical of its row", want.every(u => got.indexOf(u) !== -1) &&
    got.indexOf(pageCanonical("a&b<c>é", "x&y<z>")) !== -1 && got.indexOf(pageCanonical("Some-Seller", "another-sellers-post")) !== -1);

  /* ── C. well-formed XML ────────────────────────────────────────────────── */
  console.log("\n══ C. well-formed, escaped XML ══");
  const wf = wellFormed(r.body);
  check("C. the sitemap is well-formed: declaration, a urlset in the sitemap namespace, balanced tags, no raw & or <", wf === null &&
    /<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/.test(r.body), wf);
  check("C. a handle and slug with & < > never put them raw in the XML", r.body.indexOf("a&b") === -1 && r.body.indexOf("<c>") === -1 && r.body.indexOf("x&y") === -1 && /a%26b%3Cc%3E/.test(r.body));
  check("C. the escaper escapes & < > \" '", A.ctx.__api.blogSitemapXmlEscape("a&b<c>\"d'") === "a&amp;b&lt;c&gt;&quot;d&apos;", A.ctx.__api.blogSitemapXmlEscape("a&b<c>\"d'"));
  check("C. an empty table gives a well-formed, empty urlset", (function () { const x = A.ctx.__api.buildBlogSitemapXml([], {}); return wellFormed(x) === null && locs(x).length === 0; })());

  /* ── D. the route's caching and failure ────────────────────────────────── */
  console.log("\n══ D. cached 10 minutes; a failed read is a 503 and is not cached ══");
  check("D. served as application/xml", /^application\/xml/.test(r.headers["content-type"] || ""), r.headers["content-type"]);
  const dbD = fakeDb(fixture()), c2 = { now: clock.now };
  const D = load(dbD, c2);
  await D.call(); const reads1 = dbD.log.length;
  c2.now += 9 * 60 * 1000; await D.call(); const reads2 = dbD.log.length;
  c2.now += 2 * 60 * 1000; await D.call(); const reads3 = dbD.log.length;
  check("D. the cache is 10 minutes: no new read 9 minutes later, a fresh read at 11", (/BLOG_SITEMAP_CACHE_MS = 10 \* 60 \* 1000;/.test(SRC)) && reads1 === 2 && reads2 === 2 && reads3 === 4,
    JSON.stringify([reads1, reads2, reads3]));
  let failing = true;
  const dbF = fakeDb(fixture(), { fail: () => failing });
  const Fz = load(dbF, { now: clock.now });
  const f1 = await Fz.call();
  failing = false;
  const f2 = await Fz.call();
  check("D. a failed read is a 503 with no sitemap, and the next request reads again and succeeds", f1.code === 503 && !/urlset/.test(f1.body) && f2.code === 200 && locs(f2.body).length === 4,
    JSON.stringify([f1.code, f2.code]));
  check("D. no auth and no extra limiter on the route; the global apiLimiter covers it", ROUTE.indexOf("requireAuth") === -1 && /\napp\.use\(apiLimiter\);\n/.test(SRC) &&
    SRC.indexOf("app.use(apiLimiter);") < SRC.indexOf(SIG));

  /* ── E. the frontend files ─────────────────────────────────────────────── */
  console.log("\n══ E. sitemap index, pages sitemap, rewrite, robots ══");
  const INDEX = fe("sitemap.xml"), PAGES = fe("sitemap-pages.xml"), REDIR = fe("_redirects"), ROBOTS = fe("robots.txt");
  check("E. sitemap.xml is a sitemap index listing exactly sitemap-pages.xml and sitemap-blog.xml", !!INDEX && wellFormed(INDEX) === null &&
    /<sitemapindex xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/.test(INDEX) &&
    JSON.stringify(locs(INDEX)) === JSON.stringify(["https://bizforceai.net/sitemap-pages.xml", "https://bizforceai.net/sitemap-blog.xml"]), INDEX);
  check("E. sitemap-pages.xml keeps /, /app, /vitality, /xxl-xtreme and adds /suppressed.html", !!PAGES && wellFormed(PAGES) === null &&
    JSON.stringify(locs(PAGES)) === JSON.stringify(["https://bizforceai.net/", "https://bizforceai.net/app", "https://bizforceai.net/vitality", "https://bizforceai.net/xxl-xtreme", "https://bizforceai.net/suppressed.html"]), PAGES);
  const api = (/var API_URL = "([^"]+)";/.exec(PAGE) || [])[1];
  const redirLines = (REDIR || "").split("\n").map(l => l.trim());
  const rw = redirLines.indexOf("/sitemap-blog.xml " + api + "/api/sitemap/blog.xml 200");
  const firstCatchAll = redirLines.findIndex(l => /^\/\*/.test(l));
  check("E. _redirects rewrites /sitemap-blog.xml (200) to the backend route on blogpost.html's API host, above every catch-all",
    !!api && rw !== -1 && (firstCatchAll === -1 || rw < firstCatchAll), JSON.stringify([api, rw, firstCatchAll]));
  check("E. the route the rewrite names is the one server.js registers", ROUTE.length > 0);
  check("E. no static sitemap-blog.xml shadows the rewrite", fe("sitemap-blog.xml") === null);
  check("E. robots.txt points at the index", /^Sitemap: https:\/\/bizforceai\.net\/sitemap\.xml$/m.test(ROBOTS || ""), ROBOTS);

  /* ── F. the compliance host map ────────────────────────────────────────── */
  console.log("\n══ F. mrearthrose.net gets the supplement rules ══");
  const mapDef = s.definitionOf(SRC, "COMPLIANCE_PROFILE_BY_HOST") || "", hostDef = s.definitionOf(SRC, "canonicalSiteHost") || "";
  const stmtAt = SRC.indexOf("    const domainProfileName =\n");
  const STMT = stmtAt < 0 ? "" : SRC.slice(stmtAt, SRC.indexOf(";\n", stmtAt) + 1);
  function profileFor(moneyUrl) {
    const ctx = { URL, String, Object, moneyUrl };
    vm.createContext(ctx);
    return vm.runInContext(mapDef + "\n" + hostDef + "\nconst externalMode = Boolean(moneyUrl);\nconst externalSite = externalMode ? canonicalSiteHost(moneyUrl) : null;\n" + STMT + "\ndomainProfileName;", ctx);
  }
  check("F. hosts are matched after canonicalSiteHost: lower-cased, a leading www. stripped, no path",
    /host = String\(host \|\| ""\)\.trim\(\)\.toLowerCase\(\);\n  if \(host\.indexOf\("www\."\) === 0\) host = host\.slice\(4\);/.test(hostDef) && STMT.length > 0);
  check("F. a money_url on mrearthrose.net gets supplement_vitality automatically (https://mrearthrose.net/warhorse)", profileFor("https://mrearthrose.net/warhorse") === "supplement_vitality", profileFor("https://mrearthrose.net/warhorse"));
  check("F. www.mrearthrose.net and MrEarthRose.NET do too", profileFor("https://www.mrearthrose.net/warhorse") === "supplement_vitality" && profileFor("http://MrEarthRose.NET/") === "supplement_vitality");
  check("F. mrearthrose.com still does", profileFor("https://mrearthrose.com/") === "supplement_vitality");
  check("F. bizforceai.net and blacksuncircle.com get no profile", profileFor("https://bizforceai.net/suppressed.html") === null && profileFor("https://blacksuncircle.com/") === null &&
    profileFor("https://www.blacksuncircle.com/book") === null);
  check("F. no host besides the three is mapped (swordvitality.com untouched)", (function () {
    const ctx = {}; vm.createContext(ctx); const m = vm.runInContext(mapDef + "\nCOMPLIANCE_PROFILE_BY_HOST;", ctx);
    return JSON.stringify(Object.keys(m).sort()) === JSON.stringify(["mrearthrose.com", "mrearthrose.net", "swordvitality.com"]) && Object.keys(m).every(k => m[k] === "supplement_vitality");
  })());

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
