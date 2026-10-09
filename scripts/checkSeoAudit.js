"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkSeoAudit — POST /api/agents/seo/audit measures before it explains.

   The route is lifted from server.js and run whole: its own startToolRun,
   its own flags, its own prompt and parse. Around it, and nothing else:
     - the fetcher is lib/guardedFetch.js's createGuardedFetch with the stub
       resolver and dialler checkGuardedFetch uses, so every page, robots.txt
       and sitemap below is served by a local server through the REAL guards;
     - the model is a script that records every prompt it is sent;
     - the database is a recorder. No network, no model, no rows.

   WHAT THIS PROVES
     1. Measured values and flag ids, exactly, for: a clean page; alt="" vs no
        alt; zero and two H1s; h2 then h4; canonical elsewhere and to self with
        a trailing slash; noindex in meta and in a header; a robots.txt
        disallow, and one overridden by a longer Allow; robots.txt 404; a
        sitemap that lists the page, one that does not, a sitemapindex ("not
        checked", never false) and a sitemap 404; bad JSON-LD; 301 then 200,
        and two redirects; a final 404, audited rather than refused; a blocked
        address (422, the unchanged message, no model call); a client-rendered
        shell (one content flag, no H1 flag).
     2. The explanation: cited points kept, uncited and unknown-id points
        dropped and counted; a sentence unique to the body, robots.txt and the
        sitemap never reaches the model; a throwing model and an unreadable
        reply both give 200 with measured intact and the run completed.
     3. The wiring: the TOOL_INPUT_SPECS entry, absence from
        CHAIN_NON_DISPATCHABLE_TOOLS, the middleware, and extractSeoPageData
        unchanged from BEFORE.

   MUTATE=<name> edits the lifted source (server.js on disk is never touched).
   MUTATE=all runs each in its own process and passes only if every one fails.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const http = require("http");
const net = require("net");
const { execSync, spawnSync } = require("child_process");
const { decodeHTML, decodeHTMLAttribute } = require("entities");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const BEFORE = "85bd811";
const MUTATE = process.env.MUTATE || "";
const gf = require(path.join(REPO, "lib", "guardedFetch.js"));

const MUTATIONS = {
  // the model is sent the page's visible text
  "text-to-model": [["\"AUDIT:\\n\" + seoAuditModelInput(measured, flags) +",
    "\"AUDIT:\\n\" + seoAuditModelInput(measured, flags) + \"\\nPAGE TEXT:\\n\" + (page.body ? extractSeoPageData(page.body).visibleText : \"\") +"]],
  // a point that cites nothing real is kept
  "keep-uncited": [["    if (!cited.length) { dropped++; return; }\n", "    if (!cited.length) { dropped++; }\n"]],
  // alt="" is counted as a missing alt
  "alt-empty-missing": [["missing_alt_attribute: data.imageAlts.filter(function (img) { return !img.has_alt; }).length",
    "missing_alt_attribute: data.imageAlts.filter(function (img) { return !img.has_alt || img.alt === \"\"; }).length"]],
  // a client-rendered shell is flagged for its H1 as well
  "h1-on-shell": [["    if (m.client_rendering.appears_client_rendered) {\n",
    "    if (m.client_rendering.appears_client_rendered) {\n      if (m.h1.count !== 1) raise(\"F8\", \"A page should have exactly one H1.\", m.h1.count + \" H1 element(s).\");\n"]],
  // a model that throws fails the audit
  "fail-on-throw": [["      } catch (modelErr) {\n", "      } catch (modelErr) {\n        throw modelErr;\n"]],
  // not_measured is left out of the response
  "omit-not-measured": [["        not_measured: SEO_AUDIT_NOT_MEASURED,\n", ""]],
  // a sitemapindex is reported as not listing the page
  "index-as-absent": [["    pageListed = \"not checked\";\n", "    pageListed = false;\n"]]
};

if (MUTATE === "all") {
  const names = Object.keys(MUTATIONS);
  let survived = 0;
  for (const name of names) {
    const r = spawnSync(process.execPath, [__filename], { env: Object.assign({}, process.env, { MUTATE: name }), encoding: "utf8", timeout: 300000 });
    const fails = (r.stdout.match(/^ {4}FAIL {2}.*$/gm) || []);
    const caught = r.status !== 0 && fails.length > 0;
    if (!caught) survived++;
    console.log((caught ? "    caught    " : "    SURVIVED  ") + name.padEnd(18) + " " + fails.length + " failing check(s)" +
      (fails.length ? "  e.g. " + fails[0].trim().slice(6, 110) : (r.stderr ? "  stderr: " + r.stderr.trim().split("\n")[0] : "")));
  }
  console.log(survived === 0 ? "\nALL CHECKS PASSED — every one of " + names.length + " mutations was caught" : "\nCHECKS FAILED: " + survived + " mutation(s) survived");
  process.exit(survived === 0 ? 0 : 1);
}

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}
function same(label, actual, expected) {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  check(label, a === e, "got " + a + ", want " + e);
}

/* ── the source ─────────────────────────────────────────────────────────── */
let SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [from, to] of edits) {
    if (SRC.split(from).length !== 2) { console.log("    FAIL  mutation anchor not found exactly once: " + from.slice(0, 80)); process.exit(1); }
    SRC = SRC.replace(from, () => to);
  }
  console.log("\n!! MUTATION: " + MUTATE);
}

/* Every top-level definition the route reaches, in source order. Destructured
   requires (guardedFetch and friends, the entity decoders) are not
   definitions and are supplied below. */
function closure(src, root) {
  const have = new Map(); const queue = [...new Set(root.match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || s.STUBS.has(name)) continue;
    const def = s.definitionOf(src, name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(def.match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !s.STUBS.has(id)) queue.push(id); });
  }
  return [...have.values()].sort((a, b) => src.indexOf(a) - src.indexOf(b)).join("\n\n") + "\n\n" + root;
}
const ROUTE_CODE = s.routeCode(SRC, "seo/audit");
const LIFTED = closure(SRC, ROUTE_CODE);

/* ── the fixture web ────────────────────────────────────────────────────── */
const PUBLIC_V4 = "93.184.216.34";
const SITES = {};
const BODY_SENTENCE = "Zephyrine marmalade orbits the quiet lighthouse at dusk.";
const ROBOTS_SENTENCE = "# Quillfeather robots comment that must never reach a model";
const SITEMAP_SENTENCE = "<!-- Tamberlane sitemap remark that must never reach a model -->";

function htmlPage(o) {
  o = o || {};
  const head = (o.title === null ? "" : "<title>" + (o.title || "Earth Rose Wellness — Holistic Care in Portland") + "</title>") +
    (o.description === null ? "" : "<meta name=\"description\" content=\"" + (o.description ||
      "Holistic wellness care in Portland: herbal consultations, nutrition plans and gentle movement classes for every age.") + "\">") +
    (o.viewport === null ? "" : "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">") +
    (o.canonical === undefined ? "<link rel=\"canonical\" href=\"https://" + o.host + "/\">" : (o.canonical === null ? "" : "<link rel=\"canonical\" href=\"" + o.canonical + "\">")) +
    (o.robotsMeta ? "<meta name=\"robots\" content=\"" + o.robotsMeta + "\">" : "") +
    (o.jsonld === undefined ? "<script type=\"application/ld+json\">{\"@context\":\"https://schema.org\",\"@type\":\"Organization\",\"name\":\"Earth Rose\"}</script>" : o.jsonld);
  const body = o.body !== undefined ? o.body :
    (o.headings !== undefined ? o.headings : "<h1>Holistic care in Portland</h1><h2>Consultations</h2><h3>Herbal</h3><h2>Classes</h2>") +
    "<p>" + BODY_SENTENCE + " We offer consultations and classes for families across the city, with plenty of room for questions.</p>" +
    (o.images !== undefined ? o.images : "<img src=\"/a.jpg\" alt=\"Herbal tea\">") +
    "<a href=\"/about\">About</a> <a href=\"https://elsewhere.example/x\" rel=\"nofollow\">Partner</a> <a href=\"javascript:void(0)\">Menu</a> <a href=\"mailto:hi@x.example\">Mail</a>";
  return "<!doctype html><html" + (o.lang === null ? "" : " lang=\"en\"") + "><head>" + head + "</head><body>" + body + "</body></html>";
}
const robotsTxt = (host, extra) => ROBOTS_SENTENCE + "\nUser-agent: *\n" + (extra || "Disallow: /cart\n") + "Sitemap: https://" + host + "/sitemap.xml\n";
const urlset = (urls) => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + SITEMAP_SENTENCE + "\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">" +
  urls.map(u => "<url><loc>" + u + "</loc></url>").join("") + "</urlset>";
const sitemapIndex = (urls) => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<sitemapindex xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">" +
  urls.map(u => "<sitemap><loc>" + u + "</loc></sitemap>").join("") + "</sitemapindex>";

/* A site: its host, and per path [status, headers, body]. */
function site(name, routes) {
  const host = name + ".test";
  const defaults = {
    "/": [200, { "Content-Type": "text/html; charset=utf-8" }, htmlPage({ host: host })],
    "/robots.txt": [200, { "Content-Type": "text/plain" }, robotsTxt(host)],
    "/sitemap.xml": [200, { "Content-Type": "application/xml" }, urlset(["https://" + host + "/", "https://" + host + "/about"])]
  };
  SITES[host] = Object.assign(defaults, routes || {});
  return "https://" + host + "/";
}
const H = { "Content-Type": "text/html; charset=utf-8" };
const NOTFOUND = [404, { "Content-Type": "text/html" }, "<h1>Not found</h1>"];

const URLS = {
  clean: site("clean"),
  alts: site("alts", { "/": [200, H, htmlPage({ host: "alts.test", images: "<img src=\"/1.jpg\" alt=\"Logo\"><img src=\"/2.jpg\" alt=\"\"><img src=\"/3.jpg\">" })] }),
  noh1: site("noh1", { "/": [200, H, htmlPage({ host: "noh1.test", headings: "<h2>Consultations</h2><h3>Herbal</h3>" })] }),
  twoh1: site("twoh1", { "/": [200, H, htmlPage({ host: "twoh1.test", headings: "<h1>First</h1><h1>Second</h1><h2>Next</h2>" })] }),
  skip: site("skip", { "/": [200, H, htmlPage({ host: "skip.test", headings: "<h1>Top</h1><h2>Section</h2><h4>Deep</h4><h2>Again</h2>" })] }),
  canonElse: site("canonelse", { "/": [200, H, htmlPage({ host: "canonelse.test", canonical: "https://other.example/page" })] }),
  canonSelf: site("canonself", { "/page": [200, H, htmlPage({ host: "canonself.test", canonical: "/page/#top" })],
    "/sitemap.xml": [200, { "Content-Type": "application/xml" }, urlset(["https://canonself.test/page/"])] }),
  noindexMeta: site("noindexmeta", { "/": [200, H, htmlPage({ host: "noindexmeta.test", robotsMeta: "noindex, follow" })] }),
  noindexHeader: site("noindexheader", { "/": [200, Object.assign({ "X-Robots-Tag": "noindex" }, H), htmlPage({ host: "noindexheader.test" })] }),
  disallow: site("disallow", { "/private/page": [200, H, htmlPage({ host: "disallow.test", canonical: null })],
    "/robots.txt": [200, { "Content-Type": "text/plain" }, robotsTxt("disallow.test", "Disallow: /private\n")],
    "/sitemap.xml": [200, { "Content-Type": "application/xml" }, urlset(["https://disallow.test/private/page"])] }),
  allowLonger: site("allowlonger", { "/private/ok/page": [200, H, htmlPage({ host: "allowlonger.test", canonical: null })],
    "/robots.txt": [200, { "Content-Type": "text/plain" }, robotsTxt("allowlonger.test", "Disallow: /private\nAllow: /private/ok\n")],
    "/sitemap.xml": [200, { "Content-Type": "application/xml" }, urlset(["https://allowlonger.test/private/ok/page"])] }),
  robots404: site("robots404", { "/robots.txt": NOTFOUND }),
  sitemapMissing: site("sitemapmissing", { "/sitemap.xml": [200, { "Content-Type": "application/xml" }, urlset(["https://sitemapmissing.test/elsewhere"])] }),
  sitemapIndex: site("sitemapindex", { "/sitemap.xml": [200, { "Content-Type": "text/xml; charset=utf-8" }, sitemapIndex(["https://sitemapindex.test/a.xml", "https://sitemapindex.test/b.xml"])] }),
  sitemap404: site("sitemap404", { "/sitemap.xml": NOTFOUND }),
  badJson: site("badjson", { "/": [200, H, htmlPage({ host: "badjson.test", jsonld: "<script type=\"application/ld+json\">{\"@type\":\"Organization\",}</script><script type=\"application/ld+json\">{\"@graph\":[{\"@type\":\"WebSite\"},{\"@type\":[\"LocalBusiness\",\"Store\"]}]}</script>" })] }),
  redirect: site("redirect", { "/": [301, { Location: "/home" }, ""], "/home": [200, H, htmlPage({ host: "redirect.test", canonical: "https://redirect.test/home" })],
    "/sitemap.xml": [200, { "Content-Type": "application/xml" }, urlset(["https://redirect.test/home"])] }),
  twoRedirects: site("tworedirects", { "/": [301, { Location: "/a" }, ""], "/a": [302, { Location: "/b" }, ""], "/b": [200, H, htmlPage({ host: "tworedirects.test", canonical: "/b" })],
    "/sitemap.xml": [200, { "Content-Type": "application/xml" }, urlset(["https://tworedirects.test/b"])] }),
  final404: site("final404", { "/": NOTFOUND }),
  shell: site("shell", { "/": [200, H, "<!doctype html><html lang=\"en\"><head><title>Earth Rose Wellness — Holistic Care in Portland</title>" +
    "<meta name=\"description\" content=\"Holistic wellness care in Portland: herbal consultations, nutrition plans and gentle movement classes for every age.\">" +
    "<meta name=\"viewport\" content=\"width=device-width\"><link rel=\"canonical\" href=\"https://shell.test/\"></head><body><div id=\"root\"></div>" +
    "<img src=\"/spinner.gif\"><script src=\"/static/js/main.js\"></script></body></html>"] })
};

const server = http.createServer(function (req, res) {
  const host = String(req.headers.host || "").replace(/:\d+$/, "");
  const r = (SITES[host] || {})[req.url.split("?")[0]] || NOTFOUND;
  res.writeHead(r[0], r[1]);
  res.end(r[2]);
});
function resolve(hostname, options, cb) {
  if (hostname === "internal.test") return cb(null, [{ address: "10.0.0.5", family: 4 }]);
  if (SITES[hostname]) return cb(null, [{ address: PUBLIC_V4, family: 4 }]);
  const e = new Error("getaddrinfo ENOTFOUND " + hostname); e.code = "ENOTFOUND"; return cb(e);
}
function dial(options) {
  const host = String(options.host || options.hostname || "");
  return net.connect({ host: host, port: server.address().port, lookup: function (h, o, cb) {
    options.lookup(h, o, function (err) {
      if (err) return cb(err);
      return o && o.all ? cb(null, [{ address: "127.0.0.1", family: 4 }]) : cb(null, "127.0.0.1", 4);
    });
  } });
}
const fetchStub = gf.createGuardedFetch({ resolve: resolve, dial: dial });

/* ── running the route ──────────────────────────────────────────────────── */
function fakeDb() {
  const writes = [];
  function q(table) {
    const st = {};
    const b = {};
    ["select", "eq", "neq", "order", "limit"].forEach(k => { b[k] = () => b; });
    b.insert = (p) => { st.insert = p; writes.push({ table: table, op: "insert", payload: p }); return b; };
    b.update = (p) => { writes.push({ table: table, op: "update", payload: p }); return b; };
    b.single = () => Promise.resolve({ data: st.insert ? { id: "task-1" } : null, error: null });
    b.then = (ok, bad) => Promise.resolve({ data: null, error: null }).then(ok, bad);
    return b;
  }
  return { client: { from: q }, writes: writes };
}
/* model: a string (every call gets it), an array (call n gets entry n), or a
   function that throws. */
async function audit(url, model) {
  const db = fakeDb();
  const prompts = [];
  let handler = null;
  const ctx = {
    supabase: db.client, nowIso: () => "2026-10-09T12:00:00.000Z", process: { env: {} }, require: require, Buffer: Buffer, URL: URL,
    console: { log() {}, warn() {}, error() {} }, setTimeout: setTimeout,
    requireAuth: "requireAuth", requireActiveSubscription: "requireActiveSubscription", aiLimiter: "aiLimiter",
    resolvePreferredLanguage: async () => null,
    buildLanguageInstruction: () => "",
    guardedFetch: fetchStub, guardedFetchPublicMessage: gf.publicMessage, guardedFetchLogLine: gf.logLine, GUARDED_FETCH_UNREACHABLE: gf.UNREACHABLE_MESSAGE,
    decodeHTML: decodeHTML, decodeHTMLAttribute: decodeHTMLAttribute,
    callAnthropicText: async (prompt, maxTokens, userId, modelName, ledger) => {
      prompts.push({ prompt: prompt, maxTokens: maxTokens, model: modelName, ledger: ledger });
      if (typeof model === "function") return model(prompts.length);
      return { text: Array.isArray(model) ? model[prompts.length - 1] : model, stopReason: "end_turn" };
    },
    app: { post() { handler = { middleware: Array.prototype.slice.call(arguments, 1, -1), fn: arguments[arguments.length - 1] }; } }
  };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx, { filename: "server.js (seo/audit)" });
  const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(p) { this.body = JSON.parse(JSON.stringify(p)); return this; } };
  let nextErr = null;
  await handler.fn({ user: { id: "00000000-0000-0000-0000-0000000000aa" }, body: { url: url } }, res, (e) => { nextErr = e || new Error("next"); });
  return { status: res.statusCode, body: res.body, prompts: prompts, writes: db.writes, nextErr: nextErr && String(nextErr.message || nextErr), middleware: handler.middleware };
}
const ids = (r) => (r.body && r.body.flags || []).map(f => f.id);
const flag = (r, id) => (r.body && r.body.flags || []).filter(f => f.id === id)[0] || null;
const GOOD = "POINT: Keep the title as it is. | CITES: title\nPOINT: Shorten the redirect path. | CITES: redirect_chain, F2";

(async function main() {
  await new Promise(r => server.listen(0, "127.0.0.1", r));

  console.log("\n══ 1. a clean page ══");
  const clean = await audit(URLS.clean, GOOD);
  const m = clean.body.measured;
  same("1. status 200 and no flags", [clean.status, ids(clean)], [200, []]);
  same("1. final status, URL, https, redirect count and chain", [m.final_status, m.final_url, m.final_url_is_https, m.redirect_count, m.redirect_chain],
    [200, "https://clean.test/", true, 0, [{ url: "https://clean.test/", status: 200 }]]);
  same("1. title", m.title, { value: "Earth Rose Wellness — Holistic Care in Portland", length: 47 });
  same("1. meta description", m.meta_description, { value: "Holistic wellness care in Portland: herbal consultations, nutrition plans and gentle movement classes for every age.", length: 116 });
  same("1. canonical to self", m.canonical, { value: "https://clean.test/", resolved: "https://clean.test", matches_final_url: true });
  same("1. robots directives", m.robots_directives, { meta_robots: { value: null, noindex: false, nofollow: false }, x_robots_tag: { value: null, noindex: false, nofollow: false }, noindex: false, nofollow: false });
  same("1. lang and viewport", [m.lang, m.viewport], [{ present: true, value: "en" }, { present: true, value: "width=device-width, initial-scale=1" }]);
  same("1. H1", m.h1, { count: 1, values: ["Holistic care in Portland"] });
  same("1. heading sequence in document order, no skips", [m.heading_sequence, m.heading_skips],
    [[{ level: 1, text: "Holistic care in Portland" }, { level: 2, text: "Consultations" }, { level: 3, text: "Herbal" }, { level: 2, text: "Classes" }], []]);
  same("1. images", m.images, { total: 1, with_alt_text: 1, decorative_empty_alt: 0, missing_alt_attribute: 0 });
  same("1. links", m.links, { total: 4, internal: 1, external: 1, nofollow: 1, empty_or_javascript: 1, other: 1 });
  same("1. JSON-LD", m.json_ld, { blocks: 1, parsed: 1, unparsed: 0, types: ["Organization"] });
  same("1. robots.txt", m.robots_txt, { url: "https://clean.test/robots.txt", status: 200, refusal: null, read: true, path_checked: "/", path_disallowed: false, matched_rule: null, sitemap_declared: "https://clean.test/sitemap.xml" });
  same("1. sitemap", m.sitemap, { url_tried: "https://clean.test/sitemap.xml", source: "robots.txt", status: 200, refusal: null, read: true, kind: "urlset", loc_count: 2, page_listed: true });
  same("1. client rendering", [m.client_rendering.appears_client_rendered, m.client_rendering.heuristic, m.client_rendering.script_count, m.client_rendering.empty_app_root], [false, true, 0, null]);
  same("1. not_measured is the fixed list", clean.body.not_measured, ["Search rankings", "Traffic", "Backlinks", "Competitors", "Page speed and Core Web Vitals",
    "Content rendered by JavaScript", "Other pages on the site", "Whether any search engine has indexed the page"]);
  same("1. provenance says a model call was made and no page text was sent", [clean.body.provenance.model_call_made, clean.body.provenance.page_text_sent_to_model,
    Array.isArray(clean.body.provenance.measured_from), Array.isArray(clean.body.provenance.inferred_by_model)], [true, false, true, true]);
  same("1. the response's top-level objects", Object.keys(clean.body), ["success", "url", "measured", "flags", "explanation", "explanation_error", "points_dropped",
    "not_measured", "provenance", "task_id", "persisted"]);
  same("1. one model call, default model, 2000 tokens, the seo ledger", [clean.prompts.length, clean.prompts[0].model, clean.prompts[0].maxTokens, clean.prompts[0].ledger],
    [1, undefined, 2000, { user_id: "00000000-0000-0000-0000-0000000000aa", agent_type: "seo", route: "POST /api/agents/seo/audit" }]);
  const ins = clean.writes.filter(w => w.op === "insert"), upd = clean.writes.filter(w => w.op === "update");
  same("1. one ai_tasks row: seo / seo/audit, completed with the response", [ins.length, ins[0].table, ins[0].payload.agent_type, ins[0].payload.task_type, ins[0].payload.prompt,
    upd.length, upd[0].payload.status, JSON.stringify(upd[0].payload.output.measured) === JSON.stringify(m)],
    [1, "ai_tasks", "seo", "seo/audit", "SEO · Audit: https://clean.test/", 1, "completed", true]);
  same("1. task_id and persisted", [clean.body.task_id, clean.body.persisted], ["task-1", true]);
  same("1. the route runs requireAuth, requireActiveSubscription, aiLimiter", clean.middleware, ["requireAuth", "requireActiveSubscription", "aiLimiter"]);

  console.log("\n══ 2. images ══");
  const alts = await audit(URLS.alts, GOOD);
  same("2. alt=\"Logo\", alt=\"\" and no alt are three separate counts", alts.body.measured.images, { total: 3, with_alt_text: 1, decorative_empty_alt: 1, missing_alt_attribute: 1 });
  same("2. only the missing alt is flagged", [ids(alts), flag(alts, "F16") && flag(alts, "F16").evidence], [["F16"], "1 of 3 image(s) have no alt attribute."]);

  console.log("\n══ 3. headings ══");
  const noh1 = await audit(URLS.noh1, GOOD), twoh1 = await audit(URLS.twoh1, GOOD), skip = await audit(URLS.skip, GOOD);
  same("3. zero H1s → F8", [noh1.body.measured.h1, ids(noh1), flag(noh1, "F8").evidence], [{ count: 0, values: [] }, ["F8"], "0 H1 element(s)."]);
  same("3. two H1s → F8", [twoh1.body.measured.h1, ids(twoh1), flag(twoh1, "F8").evidence], [{ count: 2, values: ["First", "Second"] }, ["F8"], "2 H1 element(s): \"First\", \"Second\"."]);
  same("3. h2 then h4 → F9, in document order", [skip.body.measured.heading_skips, ids(skip)], [[{ from: "h2", to: "h4", at_heading: 3, text: "Deep" }], ["F9"]]);
  same("3. a step back up is not a skip", skip.body.measured.heading_sequence.map(h => h.level), [1, 2, 4, 2]);

  console.log("\n══ 4. canonical ══");
  const ce = await audit(URLS.canonElse, GOOD), cs = await audit(URLS.canonSelf.replace(/\/$/, "/page"), GOOD);
  same("4. canonical elsewhere → F10", [ce.body.measured.canonical, ids(ce)], [{ value: "https://other.example/page", resolved: "https://other.example/page", matches_final_url: false }, ["F10"]]);
  same("4. a relative canonical to self with a trailing slash and fragment matches", [cs.body.measured.canonical, ids(cs)],
    [{ value: "/page/#top", resolved: "https://canonself.test/page", matches_final_url: true }, []]);

  console.log("\n══ 5. noindex ══");
  const nm = await audit(URLS.noindexMeta, GOOD), nh = await audit(URLS.noindexHeader, GOOD);
  same("5. noindex in meta robots → F11", [nm.body.measured.robots_directives.meta_robots, nm.body.measured.robots_directives.noindex, ids(nm)],
    [{ value: "noindex, follow", noindex: true, nofollow: false }, true, ["F11"]]);
  same("5. noindex in X-Robots-Tag → F11", [nh.body.measured.robots_directives.x_robots_tag, nh.body.measured.robots_directives.noindex, ids(nh), flag(nh, "F11").evidence],
    [{ value: "noindex", noindex: true, nofollow: false }, true, ["F11"], "noindex in X-Robots-Tag \"noindex\"."]);

  console.log("\n══ 6. robots.txt ══");
  const dis = await audit(URLS.disallow.replace(/\/$/, "/private/page"), GOOD), al = await audit(URLS.allowLonger.replace(/\/$/, "/private/ok/page"), GOOD);
  same("6. Disallow: /private disallows /private/page → F12", [dis.body.measured.robots_txt.path_disallowed, dis.body.measured.robots_txt.matched_rule, ids(dis)], [true, "Disallow: /private", ["F12"]]);
  same("6. a longer Allow wins over a shorter Disallow", [al.body.measured.robots_txt.path_disallowed, al.body.measured.robots_txt.matched_rule, ids(al)], [false, "Allow: /private/ok", []]);
  const r404 = await audit(URLS.robots404, GOOD);
  same("6. robots.txt 404 → F13, and the sitemap falls back to /sitemap.xml", [r404.body.measured.robots_txt.status, r404.body.measured.robots_txt.read,
    r404.body.measured.robots_txt.path_disallowed, r404.body.measured.sitemap.source, r404.body.measured.sitemap.page_listed, ids(r404)],
    [404, false, null, "default /sitemap.xml", true, ["F13"]]);

  console.log("\n══ 7. sitemap ══");
  const sm = await audit(URLS.sitemapMissing, GOOD), si = await audit(URLS.sitemapIndex, GOOD), s404 = await audit(URLS.sitemap404, GOOD);
  same("7. a urlset without the page → page_listed false, F15", [sm.body.measured.sitemap.kind, sm.body.measured.sitemap.loc_count, sm.body.measured.sitemap.page_listed, ids(sm)],
    ["urlset", 1, false, ["F15"]]);
  same("7. a sitemapindex → \"not checked\", never false, and no flag", [si.body.measured.sitemap.kind, si.body.measured.sitemap.loc_count, si.body.measured.sitemap.page_listed, ids(si)],
    ["sitemapindex", 2, "not checked", []]);
  same("7. a sitemap 404 → F14", [s404.body.measured.sitemap.status, s404.body.measured.sitemap.read, s404.body.measured.sitemap.page_listed, ids(s404),
    flag(s404, "F14").evidence], [404, false, null, ["F14"], "https://sitemap404.test/sitemap.xml: HTTP 404."]);

  console.log("\n══ 8. JSON-LD ══");
  const bj = await audit(URLS.badJson, GOOD);
  same("8. one block that does not parse → F17, basis error; types from the one that does, @graph included",
    [bj.body.measured.json_ld, ids(bj), flag(bj, "F17").basis], [{ blocks: 2, parsed: 1, unparsed: 1, types: ["WebSite", "LocalBusiness", "Store"] }, ["F17"], "error"]);

  console.log("\n══ 9. redirects and status ══");
  const rd = await audit(URLS.redirect, GOOD), rd2 = await audit(URLS.twoRedirects, GOOD);
  same("9. 301 then 200: the chain, one redirect, no flag", [rd.body.measured.redirect_chain, rd.body.measured.redirect_count, rd.body.measured.final_url, ids(rd)],
    [[{ url: "https://redirect.test/", status: 301 }, { url: "https://redirect.test/home", status: 200 }], 1, "https://redirect.test/home", []]);
  same("9. two redirects → F2", [rd2.body.measured.redirect_count, ids(rd2)], [2, ["F2"]]);
  const f404 = await audit(URLS.final404, GOOD);
  same("9. a final 404 is audited (200), F1 with basis error, and nothing read from its body",
    [f404.status, f404.body.measured.final_status, f404.body.measured.page_html_read, f404.body.measured.title, f404.body.measured.h1, ids(f404), flag(f404, "F1").basis, f404.prompts.length],
    [200, 404, false, null, null, ["F1"], "error", 1]);

  console.log("\n══ 10. a blocked address ══");
  const blk = await audit("https://internal.test/", GOOD);
  same("10. 422 with the unchanged unreachable message", [blk.status, blk.body], [422, { error: gf.UNREACHABLE_MESSAGE }]);
  same("10. no model call", blk.prompts.length, 0);
  const blkUpd = blk.writes.filter(w => w.op === "update");
  same("10. the run is marked failed with that message, never the internal reason", [blkUpd.length, blkUpd[0] && blkUpd[0].payload.status, blkUpd[0] && blkUpd[0].payload.error],
    [1, "failed", gf.UNREACHABLE_MESSAGE]);
  const lit = await audit("http://169.254.169.254/latest/meta-data/", GOOD);
  same("10. a metadata literal likewise", [lit.status, lit.body, lit.prompts.length], [422, { error: gf.UNREACHABLE_MESSAGE }, 0]);

  console.log("\n══ 11. a client-rendered shell ══");
  const sh = await audit(URLS.shell, GOOD);
  same("11. appears_client_rendered, with its evidence", [sh.body.measured.client_rendering.appears_client_rendered, sh.body.measured.client_rendering.visible_text_length,
    sh.body.measured.client_rendering.script_count, sh.body.measured.client_rendering.empty_app_root], [true, 0, 1, "root"]);
  same("11. one content flag (F20) and no H1, heading or image flag", ids(sh), ["F20"]);

  console.log("\n══ 12. the explanation ══");
  const mixed = await audit(URLS.twoRedirects, [
    "1. POINT: Cut the redirect chain to one hop. | CITES: F2, redirect_chain",
    "POINT: Your rankings will rise. | CITES:",
    "POINT: Competitors outrank you. | CITES: F99, backlinks",
    "- POINT: Keep the title. | CITES: f2, title, made_up",
    "Some prose the model added."
  ].join("\n"));
  same("12. cited points kept, in order, with only the known ids", mixed.body.explanation, [
    { priority: 1, point: "Cut the redirect chain to one hop.", cites: ["F2", "redirect_chain"] },
    { priority: 2, point: "Keep the title.", cites: ["F2", "title"] }]);
  same("12. an uncited point and one citing only unknown ids are dropped and counted", mixed.body.points_dropped, 2);
  same("12. explanation_error is null when the explanation stands", mixed.body.explanation_error, null);
  const prompt = clean.prompts[0].prompt;
  check("12. a sentence unique to the body never reaches the model", prompt.indexOf("Zephyrine") === -1);
  check("12. nor robots.txt as written", prompt.indexOf("Quillfeather") === -1);
  check("12. nor the sitemap as written", prompt.indexOf("Tamberlane") === -1);
  check("12. the model is sent the measurements and flags", prompt.indexOf("\"final_status\": 200") !== -1 && prompt.indexOf("\"flags\": []") !== -1);
  check("12. the instruction forbids rankings, traffic and competitors", /Do not estimate or mention search rankings, traffic, backlinks, competitors/.test(prompt));

  const throwing = await audit(URLS.twoRedirects, () => { throw new Error("upstream 529"); });
  const tb = throwing.body || {};
  same("12. a throwing model: 200, explanation null, the reason given, measured intact", [throwing.status, throwing.nextErr, tb.explanation, /upstream 529/.test(tb.explanation_error || ""),
    JSON.stringify(tb.measured) === JSON.stringify(rd2.body.measured), ids(throwing), tb.provenance && tb.provenance.model_call_made], [200, null, null, true, true, ["F2"], true]);
  same("12. and the run is completed, not failed", throwing.writes.filter(w => w.op === "update").map(w => w.payload.status), ["completed"]);
  const garbled = await audit(URLS.twoRedirects, ["Here are my thoughts on your page.", "Still no structure, sorry."]);
  same("12. an unreadable reply after the one retry: 200, explanation null, measured intact", [garbled.status, garbled.body.explanation, !!garbled.body.explanation_error,
    JSON.stringify(garbled.body.measured) === JSON.stringify(rd2.body.measured), garbled.prompts.length], [200, null, true, true, 2]);
  same("12. and that run is completed too", garbled.writes.filter(w => w.op === "update").map(w => w.payload.status), ["completed"]);

  console.log("\n══ 13. wiring ══");
  same("13. a missing URL is a 400 before anything is spent", await audit("", GOOD).then(r => [r.status, r.prompts.length, r.writes.length]), [400, 0, 0]);
  const specs = /  "seo\/audit": \[\n    toolField\("url", "string", true, [^\n]*\["website"\]\)\n  \],/.test(SRC);
  check("13. TOOL_INPUT_SPECS has seo/audit with one required field url (alias website)", specs);
  const nonDispatch = /var CHAIN_NON_DISPATCHABLE_TOOLS = \[([^\]]*)\]/.exec(SRC);
  check("13. seo/audit is NOT in CHAIN_NON_DISPATCHABLE_TOOLS", nonDispatch && nonDispatch[1].indexOf("seo/audit") === -1);
  const before = execSync("git show " + BEFORE + ":server.js", { cwd: REPO, maxBuffer: 1 << 26 }).toString("utf8").replace(/\r\n/g, "\n");
  same("13. extractSeoPageData is unchanged from " + BEFORE, s.definitionOf(SRC, "extractSeoPageData") === s.definitionOf(before, "extractSeoPageData"), true);
  check("13. the removed /api/seo/audit route is still absent", SRC.indexOf("app.post(\"/api/seo/audit\"") === -1);

  server.close();
  console.log("\n" + passes + " passed, " + failures + " failed");
  console.log(failures === 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED");
  process.exit(failures === 0 ? 0 : 1);
})().catch(function (e) {
  console.log("    FAIL  threw: " + (e && e.stack || e));
  process.exit(1);
});
