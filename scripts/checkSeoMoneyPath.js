/* ═══════════════════════════════════════════════════════════════════════════
   checkSeoMoneyPath.js — an internal SEO post can name a page on this platform
   as its money link, and an arrival through that link is counted.

   THE GAP. An internal post's money link could only be one of the seller's
   /listing/ pages, and the generator required exactly one whenever the seller
   had any. So no article published here could send its reader to
   /suppressed.html, the page written for the businesses BizForce serves; and
   engine_visits, which counts arrivals, accepted only a Lead Radar ref.

   WHAT THIS PROVES, with no model call, no database write and no send — the
   route, the executor and the visits route are lifted from the working copy and
   from BASELINE, the commit before this change, and run against a recording
   stub database and a scripted model:
     1. money_path that is not on the allowlist — another path, another case, an
        absolute URL, no leading slash, a number, an array — is refused with 422
        naming the allowlist. The model is never called and nothing is written.
        Absent, null and "" are no money_path at all.
     2. money_path with money_url is refused with 422, naming both. Neither wins.
     3. Generation with money_path: the prompt names the page and what it is,
        carries no listing catalog and no listing rule; a post linking the page
        is filed with money_path and no money_url or site; a post that does not
        link it — or links only a listing — is refused, nothing filed.
     4. Publish with money_path: the post is published here (internal, status
        published, site null) and its money link — body and internal_links —
        carries ?ref=bl-<token>. A body without the link, a money_path no longer
        on the allowlist, and a payload with both keys each throw and write
        nothing.
     5. The token is bl- and ten hex of SHA-256 over "blog:<user_id>:<slug>":
        the same post the same token, another slug or author another, and no
        slug or id text in it.
     6. Without money_path nothing changed: for internal posts with and without
        listings, with a topic, and external posts with and without a compliance
        profile, the prompt the model receives, the response and every row
        written are identical to BASELINE; and the executor, on internal,
        external and failing proposals, writes and returns exactly what
        BASELINE does.
     7. POST /api/engine-visits accepts bl- and still accepts lr-, writing only
        { ref, landing_path }; refuses a malformed ref; answers 503 naming
        migration 130 when the table's constraint refuses a ref, and 503 naming
        128 when the table is missing.
     8. Migration 130's constraint accepts exactly what the route accepts, over
        every lr- and bl- token above and the malformed set, and finds 128's
        check by what it checks rather than by name.

   MUTATIONS — each must turn the named section red:
     MUTATE=allowlist    any root-relative path is accepted               → 1
     MUTATE=silent       an off-allowlist path is dropped, not refused     → 1
     MUTATE=both         money_path with money_url is not refused          → 2
     MUTATE=listingrule  an own-page post is still told to link a listing  → 3
     MUTATE=gencheck     generation does not check the money link          → 3
     MUTATE=pubcheck     publish does not check the money link             → 4
     MUTATE=noref        publish does not add the arrival parameter        → 4
     MUTATE=personal     the token is the slug itself                      → 5
     MUTATE=leak         an internal post with no listings gets the own-page rule → 6
     MUTATE=lronly       the route accepts lr- only                        → 7
     MUTATE=blonly       the route accepts bl- only                        → 7
     MUTATE=migration    migration 130 still pins lr- only                 → 8
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";
require("dotenv").config();
const fs = require("fs");
const vm = require("vm");
const path = require("path");
const crypto = require("crypto");
const { execSync } = require("child_process");
const REPO = path.join(__dirname, "..");
const { createResidueGuard, resolveSubjectAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();
const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);
/* Nothing here writes; the guard is built so a future edit that adds a write
   has somewhere to record it, and its read-back runs regardless. */
const residue = createResidueGuard({ supabase: supabase, name: "seoMoneyPath", subject: SUBJECT_USER_ID, tables: [] });
residue.install();

/* The commit before money_path existed. Pinned, not HEAD. */
const BASELINE = "6f94afe";

const MUTATIONS = ["allowlist", "silent", "both", "listingrule", "gencheck", "pubcheck", "noref", "personal", "leak", "lronly", "blonly", "migration"];
const MUTATE = process.env.MUTATE || "";
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", ")); process.exit(2); }

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}
function mutate(src, from, to, what) {
  if (src.split(from).length !== 2) { console.error("MUTATION REFUSED (" + what + "): anchor not found exactly once."); process.exit(3); }
  return src.replace(from, () => to);
}

let SERVER = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
const SERVER0 = execSync("git show " + BASELINE + ":server.js", { cwd: REPO, maxBuffer: 1 << 26 }).toString("utf8").replace(/\r\n/g, "\n");
let MIG130 = fs.readFileSync(path.join(REPO, "supabase", "migrations", "130_engine_visits_blog_ref.sql"), "utf8").replace(/\r\n/g, "\n");

if (MUTATE === "allowlist") SERVER = mutate(SERVER,
  "if (typeof rawMoneyPath !== \"string\" || !Object.prototype.hasOwnProperty.call(SEO_OWN_MONEY_PAGES, rawMoneyPath.trim())) {",
  "if (typeof rawMoneyPath !== \"string\" || rawMoneyPath.trim().charAt(0) !== \"/\") {", "allowlist");
if (MUTATE === "allowlist") SERVER = mutate(SERVER, "    if (!Object.prototype.hasOwnProperty.call(SEO_OWN_MONEY_PAGES, moneyPath)) {\n        throw",
  "    if (false) {\n        throw", "allowlist");
if (MUTATE === "silent") SERVER = mutate(SERVER,
  "      if (typeof rawMoneyPath !== \"string\" || !Object.prototype.hasOwnProperty.call(SEO_OWN_MONEY_PAGES, rawMoneyPath.trim())) {\n        return res.status(422).json({",
  "      if (typeof rawMoneyPath !== \"string\" || !Object.prototype.hasOwnProperty.call(SEO_OWN_MONEY_PAGES, rawMoneyPath.trim())) {\n        if (true) { moneyPath = null; } else return res.status(422).json({", "silent");
if (MUTATE === "silent") SERVER = mutate(SERVER, "      moneyPath = rawMoneyPath.trim();\n    }", "      else moneyPath = rawMoneyPath.trim();\n    }", "silent");
if (MUTATE === "both") SERVER = mutate(SERVER, "    if (moneyPath && externalMode) {", "    if (false) {", "both");
if (MUTATE === "listingrule") SERVER = mutate(SERVER,
  "        : (ownPageMode\n            ? \"- Link to the money page above EXACTLY ONCE, with href=",
  "        : (false\n            ? \"- Link to the money page above EXACTLY ONCE, with href=", "listingrule");
if (MUTATE === "gencheck") SERVER = mutate(SERVER, "      if (!bodyLinksToMoneyUrl(publishedBody, moneyPath)) {", "      if (false) {", "gencheck");
if (MUTATE === "pubcheck") SERVER = mutate(SERVER, "      if (!bodyLinksToMoneyUrl(body, moneyPath)) {", "      if (false) {", "pubcheck");
if (MUTATE === "noref") SERVER = mutate(SERVER, "      storedBody = withBlogArrivalTracking(body, moneyPath, arrivalToken);", "      storedBody = body;", "noref");
if (MUTATE === "personal") SERVER = mutate(SERVER,
  "return \"bl-\" + crypto.createHash(\"sha256\").update(\"blog:\" + String(userId || \"\") + \":\" + String(slug || \"\")).digest(\"hex\").slice(0, 10);",
  "return \"bl-\" + String(slug || \"\").slice(0, 10);", "personal");
if (MUTATE === "leak") SERVER = mutate(SERVER,
  "        : (ownPageMode\n            ? \"- Link to the money page above EXACTLY ONCE, with href=",
  "        : (ownPageMode || !existingListings.length\n            ? \"- Link to the money page above EXACTLY ONCE, with href=", "leak");
if (MUTATE === "lronly") SERVER = mutate(SERVER, "var ENGINE_VISIT_REF = /^(?:lr|bl)-[0-9a-f]{10}$/;", "var ENGINE_VISIT_REF = /^lr-[0-9a-f]{10}$/;", "lronly");
if (MUTATE === "blonly") SERVER = mutate(SERVER, "var ENGINE_VISIT_REF = /^(?:lr|bl)-[0-9a-f]{10}$/;", "var ENGINE_VISIT_REF = /^bl-[0-9a-f]{10}$/;", "blonly");
if (MUTATE === "migration") MIG130 = mutate(MIG130, "check (ref ~ '^(lr|bl)-[0-9a-f]{10}$')", "check (ref ~ '^lr-[0-9a-f]{10}$')", "migration");
if (MUTATE) console.log("\n!! MUTATION: " + MUTATE);

/* _shared caches definitions by whether the source is the working copy, so a
   mutated copy and BASELINE would share a cache slot. A fresh module per lift
   keeps them apart. The compliance profiles are lifted for real rather than
   stubbed: the external fixtures run the actual compliance rules. */
const SHARED = require.resolve("./_shared");
function shared() {
  delete require.cache[SHARED];
  const s = require(SHARED);
  s.STUBS.delete("COMPLIANCE_PROFILES");
  s.STUBS.delete("COMPLIANCE_DISCLAIMER");
  return s;
}
/* _shared.closureFor joins definitions in the order it discovered them, and a
   const read during another's initialiser must already exist. Ordering them as
   server.js does reproduces the order the module itself evaluates them in. */
/* Built once per (source, root): the walk over a 40,000-line file is the slow
   part, and every run of the same source lifts the same text. */
const CLOSURES = new Map();
function closure(s, src, root) {
  if (!CLOSURES.has(src)) CLOSURES.set(src, new Map());
  const bySrc = CLOSURES.get(src);
  if (!bySrc.has(root)) bySrc.set(root, closureUncached(s, src, root));
  return bySrc.get(root);
}
function closureUncached(s, src, root) {
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

/* ── a database that records what it is asked to write ── */
const HANDLE = "check-handle";
const LISTINGS = [{ id: "11111111-2222-3333-4444-555555555555", title: "Wool Hat", slug: "wool-hat", category: "apparel", description: "A hand-knitted wool hat." }];
const POSTS = [{ id: "post-older", title: "An older post", slug: "older-post", keyword: "older question", external_url: null }];
function fakeDb(opts) {
  const writes = [];
  const listings = opts && opts.noListings ? [] : LISTINGS;
  function q(table) {
    const st = { table: table, insert: null };
    const b = {};
    ["select", "eq", "neq", "gte", "lte", "gt", "in", "is", "not", "order", "limit", "ilike"].forEach(k => { b[k] = () => b; });
    b.insert = (p) => { st.insert = p; writes.push({ table: table, payload: JSON.parse(JSON.stringify(p)) }); return b; };
    b.maybeSingle = () => Promise.resolve({ data: table === "bf_profiles" ? { username: HANDLE } : null, error: null });
    b.single = () => Promise.resolve(st.insert ? { data: Object.assign({ id: "row-1" }, st.insert), error: null } : { data: null, error: null });
    b.then = (res, rej) => Promise.resolve({
      data: table === "marketplace_listings" ? listings : (table === "content_library" ? POSTS : []), error: null
    }).then(res, rej);
    return b;
  }
  return { client: { from: q }, writes: writes };
}

function baseCtx(db, modelText) {
  const prompts = [];
  const ctx = {
    supabase: db.client, nowIso: () => "2026-10-05T12:00:00.000Z", process: { env: {} }, require: require, Buffer: Buffer, URL: URL,
    console: { log() {}, warn() {}, error() {} },
    requireAuth: 0, requireActiveSubscription: 0, aiLimiter: 0,
    resolvePreferredLanguage: async () => null,
    buildLanguageInstruction: () => "",
    AGENT_SYSTEM_PROMPTS: { seo: "SEO SYSTEM" },
    callAnthropicText: async (prompt) => { prompts.push(prompt); return { text: modelText, stopReason: "end_turn" }; }
  };
  return { ctx: ctx, prompts: prompts };
}

function liftRoute(src, db, modelText) {
  const s = shared();
  const b = baseCtx(db, modelText);
  let handler = null;
  b.ctx.app = { post() { handler = arguments[arguments.length - 1]; } };
  vm.createContext(b.ctx);
  vm.runInContext(closure(s, src, s.routeCode(src, "seo/generate-post")), b.ctx);
  if (!handler) throw new Error("EXTRACTION FAILED: generate-post");
  return { handler: handler, prompts: b.prompts };
}
async function generate(src, body, modelText, opts) {
  const db = fakeDb(opts);
  const r = liftRoute(src, db, modelText);
  const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(p) { this.body = JSON.parse(JSON.stringify(p)); return this; } };
  let nextErr = null;
  await r.handler({ user: { id: SUBJECT_USER_ID }, body: body }, res, (e) => { nextErr = e || new Error("next"); });
  return { status: res.statusCode, body: res.body, prompt: r.prompts[0] || null, calls: r.prompts.length, writes: db.writes, nextErr: nextErr && String(nextErr.message || nextErr) };
}

function liftPublish(src, db) {
  const s = shared();
  const sig = "  publish_blog_post: async function (proposal) {";
  const at = src.indexOf(sig);
  if (at < 0) throw new Error("EXTRACTION FAILED: publish_blog_post");
  const open = src.indexOf("{", at + sig.length - 1);
  const fn = "var __publish = async function (proposal) " + src.slice(open, s.braceMatch(src, open)) + ";";
  const b = baseCtx(db, "");
  vm.createContext(b.ctx);
  vm.runInContext(closure(s, src, fn), b.ctx);
  return b.ctx.__publish;
}
async function publish(src, payload, opts) {
  const db = fakeDb(opts);
  const fn = liftPublish(src, db);
  let result = null, thrown = null;
  try { result = await fn({ id: "proposal-1", user_id: SUBJECT_USER_ID, payload: JSON.parse(JSON.stringify(payload)) }); }
  catch (e) { thrown = String((e && e.message) || e); }
  return { result: result, thrown: thrown, writes: db.writes };
}

/* ── the model's answer, in the delimited format the route parses ── */
function article(links, extra) {
  const pad = "<p>" + "Owned channels keep working when a platform withdraws its approval, because nothing about them depends on that approval. ".repeat(4) + "</p>";
  const body = "<h2>Where customers come from when ads are closed</h2>" + pad + "<p>" + links.map(h => '<a href="' + h + '">this page</a>').join(" and ") + "</p>" + pad +
    "<h2>Frequently asked questions</h2><h3>Can I still be found?</h3><p>Yes, through search.</p><h3>Does it take long?</h3><p>It builds over months.</p><h3>Do I need ads?</h3><p>No.</p>" + (extra || "");
  return "---TITLE---\nWhat to do when your ad account is disabled\n---SLUG---\nwhat-to-do-when-your-ad-account-is-disabled\n---META_DESCRIPTION---\nA plain answer.\n" +
    "---KEYWORD---\nwhat to do when your ad account is disabled\n---INTERNAL_LINKS---\n" + links.join(", ") + "\n---REASONING---\nA question people ask.\n---BODY---\n" + body;
}
const OWN = "/suppressed.html";
const SLUG = "what-to-do-when-your-ad-account-is-disabled";
function expectedBl(userId, slug) { return "bl-" + crypto.createHash("sha256").update("blog:" + userId + ":" + slug).digest("hex").slice(0, 10); }

/* ── the visits route, lifted with a database that records its inserts ── */
function visitsRoute(src, insertError) {
  const s = shared();
  const start = src.indexOf("app.post(\"/api/engine-visits\", async function (req, res) {");
  if (start < 0) throw new Error("EXTRACTION FAILED: the engine-visits route");
  const open = src.indexOf("{", start);
  const body = src.slice(src.indexOf("async function", start), s.braceMatch(src, open));
  const inserts = [];
  const db = { from(t) { return { insert(p) { inserts.push({ table: t, payload: p }); return Promise.resolve({ error: insertError || null }); } }; } };
  const ctx = { supabase: db, console: { log() {}, warn() {}, error() {} } };
  vm.runInNewContext(["ENGINE_VISIT_REF", "ENGINE_VISIT_PATH"].map(n => s.definitionOf(src, n)).join("\n") + "\nthis.handler = " + body + ";", ctx);
  return { handler: ctx.handler, inserts: inserts };
}
async function visit(h, body) {
  let status = 200, payload;
  const res = { status(c) { status = c; return res; }, json(p) { payload = p; return res; }, end() { return res; } };
  await h.handler({ body: body, ip: "203.0.113.7", headers: { "user-agent": "FixtureBrowser/1.0" } }, res);
  return { status: status, payload: payload };
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);

  console.log("\n══ 1. money_path off the allowlist is refused ══");
  const offList = ["/pricing", "/Suppressed.html", "/suppressed.html/", "https://bizforceai.net/suppressed.html", "suppressed.html", "/suppressed.html?ref=x", 42, ["/suppressed.html"]];
  const off = [];
  for (const p of offList) {
    const r = await generate(SERVER, { money_path: p, topic: "ad account disabled" }, article([OWN]));
    off.push(r.status === 422 && r.calls === 0 && r.writes.length === 0 && /Allowed: \/suppressed\.html/.test((r.body || {}).error || "") ? "422" : r.status + "/" + r.calls + "/" + r.writes.length);
  }
  console.log("    " + JSON.stringify(offList) + " → " + JSON.stringify(off));
  check("1. every off-allowlist money_path is 422 naming the allowlist, with no model call and nothing filed", off.every(x => x === "422"), JSON.stringify(off));
  const firstErr = (await generate(SERVER, { money_path: "/pricing" }, article([OWN]))).body;
  console.log("    e.g. " + JSON.stringify(firstErr));
  const absent = [];
  for (const v of [undefined, null, ""]) {
    const body = { topic: "wool care" }; if (v !== undefined) body.money_path = v;
    const a = await generate(SERVER, body, article(["/listing/wool-hat"])), b0 = await generate(SERVER0, { topic: "wool care" }, article(["/listing/wool-hat"]));
    absent.push(a.status === b0.status && a.prompt === b0.prompt && JSON.stringify(a.writes) === JSON.stringify(b0.writes));
  }
  check("1. absent, null and \"\" are no money_path: prompt, status and rows identical to " + BASELINE + " with no money_path", absent.every(Boolean), JSON.stringify(absent));

  console.log("\n══ 2. money_path and money_url together ══");
  const both = await generate(SERVER, { money_path: OWN, money_url: "https://example.com/product" }, article([OWN, "https://example.com/product"]));
  console.log("    " + both.status + " " + JSON.stringify(both.body));
  check("2. refused with 422 naming both, no model call, nothing filed",
    both.status === 422 && both.calls === 0 && both.writes.length === 0 && /money_url or money_path, not both/.test((both.body || {}).error || ""), both.status + "/" + both.calls);

  console.log("\n══ 3. generation with money_path ══");
  const g = await generate(SERVER, { money_path: OWN, topic: "what to do when your ad account is disabled" }, article([OWN, "/blog/" + HANDLE + "/older-post"]));
  const pr = g.prompt || "";
  check("3. the prompt names " + OWN + " as the money page, with what the page is and what it will not do",
    pr.indexOf("- href=" + OWN) !== -1 && /what the page is: BizForce AI's page/.test(pr) && /does not promise traffic, rankings or sales/.test(pr));
  check("3. no listing catalog and no listing rule in it",
    pr.indexOf("marketplace listings (the money pages)") === -1 && pr.indexOf("/listing/wool-hat") === -1 && pr.indexOf("EXACTLY ONE of the seller's listings") === -1 &&
    pr.indexOf("with href=\"" + OWN + "\" copied character for character") !== -1, pr.length);
  check("3. the seller's own published posts are still offered as internal links", pr.indexOf("href=/blog/" + HANDLE + "/older-post") !== -1);
  const prop = (g.writes[0] || {}).payload || {};
  console.log("    " + g.status + "; filed payload keys " + JSON.stringify(Object.keys(prop.payload || {})));
  check("3. a post linking the page is filed with money_path and no money_url or site",
    g.status === 201 && g.writes.length === 1 && g.writes[0].table === "agent_proposals" && prop.payload.money_path === OWN &&
    !("money_url" in prop.payload) && !("site" in prop.payload) && prop.action_type === "publish_blog_post", g.status + " " + JSON.stringify(g.body).slice(0, 200));
  const noLink = await generate(SERVER, { money_path: OWN }, article(["/blog/" + HANDLE + "/older-post"]));
  const listingOnly = await generate(SERVER, { money_path: OWN }, article(["/listing/wool-hat"]));
  const absLink = await generate(SERVER, { money_path: OWN }, article(["https://bizforceai.net/suppressed.html"]));
  console.log("    no link " + noLink.status + ", listing only " + listingOnly.status + ", absolute URL " + absLink.status + ": " + JSON.stringify((noLink.body || {}).error));
  check("3. a post without the link, with only a listing link, or with the page as an absolute URL is 422 and nothing is filed",
    [noLink, listingOnly, absLink].every(r => r.status === 422 && r.writes.length === 0 && /money page \/suppressed\.html/.test((r.body || {}).error || "")),
    [noLink, listingOnly, absLink].map(r => r.status + "/" + r.writes.length).join(","));

  console.log("\n══ 4. publish with money_path ══");
  const token = expectedBl(SUBJECT_USER_ID, SLUG);
  const tracked = OWN + "?ref=" + token;
  const p = await publish(SERVER, prop.payload || {});
  const row = (p.writes[0] || {}).payload || {};
  console.log("    returned " + JSON.stringify(p.result || p.thrown));
  console.log("    stored money href(s): " + JSON.stringify((String(row.body || "").match(/href="[^"]*suppressed[^"]*"/g) || [])) + "; internal_links " + JSON.stringify(row.internal_links));
  check("4. published here: one content_library row, status published, site null, published_at set, publicly visible",
    !p.thrown && p.writes.length === 1 && p.writes[0].table === "content_library" && row.status === "published" && row.site === null && !!row.published_at &&
    p.result.publicly_visible === true && p.result.external_post === false, p.thrown || JSON.stringify(p.result));
  check("4. the body's money link is " + tracked + " and no bare " + OWN + " link is left",
    String(row.body || "").indexOf('href="' + tracked + '"') !== -1 && String(row.body || "").indexOf('href="' + OWN + '"') === -1, String(row.body || "").slice(0, 80));
  check("4. internal_links carries the tracked link and the other links unchanged",
    Array.isArray(row.internal_links) && row.internal_links.indexOf(tracked) !== -1 && row.internal_links.indexOf("/blog/" + HANDLE + "/older-post") !== -1 && row.internal_links.indexOf(OWN) === -1,
    JSON.stringify(row.internal_links));
  const variant = await publish(SERVER, Object.assign({}, prop.payload, { body: String(prop.payload.body).replace('href="' + OWN + '"', 'href="/Suppressed.html/"') }));
  check("4. a case or trailing-slash variant the check tolerates is stored as the canonical tracked path",
    !variant.thrown && String(((variant.writes[0] || {}).payload || {}).body || "").indexOf('href="' + tracked + '"') !== -1, variant.thrown);
  const pubNoLink = await publish(SERVER, Object.assign({}, prop.payload, { body: String(prop.payload.body).split('href="' + OWN + '"').join('href="/blog/' + HANDLE + '/older-post"') }));
  const pubOff = await publish(SERVER, Object.assign({}, prop.payload, { money_path: "/pricing" }));
  const pubBoth = await publish(SERVER, Object.assign({}, prop.payload, { money_url: "https://example.com/product" }));
  console.log("    no link: " + pubNoLink.thrown + "\n    off-list: " + pubOff.thrown + "\n    both: " + pubBoth.thrown);
  check("4. a body without the link, an off-allowlist money_path and both keys each throw and write nothing",
    /money page \/suppressed\.html/.test(pubNoLink.thrown || "") && /not a page a post may name/.test(pubOff.thrown || "") && /both money_url and money_path/.test(pubBoth.thrown || "") &&
    pubNoLink.writes.length + pubOff.writes.length + pubBoth.writes.length === 0,
    [pubNoLink, pubOff, pubBoth].map(r => (r.thrown ? "threw" : "wrote") + "/" + r.writes.length).join(","));

  console.log("\n══ 5. the token ══");
  const s5 = shared();
  const tctx = { crypto: crypto }; vm.createContext(tctx);
  vm.runInContext(s5.definitionOf(SERVER, "blogRefToken") + "\nthis.f = blogRefToken;", tctx);
  const t1 = tctx.f(SUBJECT_USER_ID, SLUG);
  console.log("    token for the fixture post: " + t1);
  check("5. bl- and ten hex of SHA-256 over \"blog:<user_id>:<slug>\", the token the published link carries", t1 === token && /^bl-[0-9a-f]{10}$/.test(t1), t1);
  check("5. the same post the same token; another slug, another author, another token",
    tctx.f(SUBJECT_USER_ID, SLUG) === t1 && tctx.f(SUBJECT_USER_ID, SLUG + "-2") !== t1 && tctx.f("00000000-0000-0000-0000-000000000000", SLUG) !== t1);
  check("5. no slug or account text in it", ["what", "ad-a", "disabled", SUBJECT_USER_ID.slice(0, 8)].every(x => t1.indexOf(x) === -1), t1);

  console.log("\n══ 6. without money_path, nothing changed against " + BASELINE + " ══");
  const CASES = [
    ["internal, with listings, no topic", { }, article(["/listing/wool-hat", "/blog/" + HANDLE + "/older-post"]), null],
    ["internal, with listings, topic", { topic: "how to wash a wool hat" }, article(["/listing/wool-hat"]), null],
    ["internal, no listings", { topic: "wool care" }, article(["/blog/" + HANDLE + "/older-post"]), { noListings: true }],
    ["internal, the model links nothing", { }, article([]), null],
    ["external, example.com", { money_url: "https://example.com/product", money_anchor: "the product", site_name: "Example", site_context: "A shop." }, article(["https://example.com/product"]), null],
    ["external, auto compliance (swordvitality.com)", { money_url: "https://swordvitality.com/store/x.html" }, article(["https://swordvitality.com/store/x.html"]), null],
    ["external, money link missing", { money_url: "https://example.com/product" }, article(["/listing/wool-hat"]), null],
    ["external, bad money_url", { money_url: "example.com" }, article([]), null]
  ];
  for (const [label, body, text, opts] of CASES) {
    const a = await generate(SERVER, body, text, opts), b0 = await generate(SERVER0, body, text, opts);
    check("6. generate · " + label + " — prompt, status, response and rows identical (" + a.status + ")",
      a.prompt === b0.prompt && a.status === b0.status && JSON.stringify(a.body) === JSON.stringify(b0.body) && JSON.stringify(a.writes) === JSON.stringify(b0.writes) && a.nextErr === b0.nextErr,
      a.status + " vs " + b0.status + (a.prompt !== b0.prompt ? " (prompt differs)" : ""));
  }
  const internalProp = (await generate(SERVER0, {}, article(["/listing/wool-hat", "/blog/" + HANDLE + "/older-post"]))).writes[0].payload.payload;
  const externalProp = (await generate(SERVER0, { money_url: "https://example.com/product" }, article(["https://example.com/product"]))).writes[0].payload.payload;
  const PUB = [
    ["internal", internalProp, null], ["internal, no listings", internalProp, { noListings: true }], ["external", externalProp, null],
    ["internal, short body", Object.assign({}, internalProp, { body: "<p>short</p>" }), null],
    ["external, money link gone", Object.assign({}, externalProp, { body: String(externalProp.body).split("https://example.com/product").join("/listing/wool-hat") }), null],
    ["internal, bad slug", Object.assign({}, internalProp, { slug: "Bad Slug" }), null]
  ];
  for (const [label, payload, opts] of PUB) {
    const a = await publish(SERVER, payload, opts), b0 = await publish(SERVER0, payload, opts);
    check("6. publish · " + label + " — row written and result identical (" + (a.thrown ? "throws" : a.result.status) + ")",
      JSON.stringify(a.writes) === JSON.stringify(b0.writes) && JSON.stringify(a.result) === JSON.stringify(b0.result) && a.thrown === b0.thrown,
      (a.thrown || "") + " | " + (b0.thrown || ""));
  }

  console.log("\n══ 7. POST /api/engine-visits ══");
  const LR = "lr-" + crypto.createHash("sha256").update("leadradar:at://did:plc:fixture/app.bsky.feed.post/3k").digest("hex").slice(0, 10);
  const lrRoute = visitsRoute(SERVER), blRoute = visitsRoute(SERVER);
  const rl = await visit(lrRoute, { ref: LR, path: "/" }), rb = await visit(blRoute, { ref: token, path: OWN, slug: SLUG, user: SUBJECT_USER_ID });
  console.log("    lr " + rl.status + " " + JSON.stringify(lrRoute.inserts) + "\n    bl " + rb.status + " " + JSON.stringify(blRoute.inserts));
  check("7. an lr- arrival is still 204 and writes exactly { ref, landing_path }",
    rl.status === 204 && lrRoute.inserts.length === 1 && JSON.stringify(lrRoute.inserts[0].payload) === JSON.stringify({ ref: LR, landing_path: "/" }));
  check("7. a bl- arrival at " + OWN + " is 204 and writes exactly { ref, landing_path }, whatever else the body carries",
    rb.status === 204 && blRoute.inserts.length === 1 && JSON.stringify(blRoute.inserts[0].payload) === JSON.stringify({ ref: token, landing_path: OWN }));
  const BAD = ["BL-0123456789", "bl-012345678", "bl-0123456789a", "bx-0123456789", "bl-012345678g", "lr-", "bl_0123456789", ""];
  const badRoute = visitsRoute(SERVER), refused = [];
  for (const r of BAD) refused.push((await visit(badRoute, { ref: r, path: OWN })).status);
  check("7. a malformed ref is 400 and writes nothing", refused.every(x => x === 400) && badRoute.inserts.length === 0, JSON.stringify(refused));
  const behind = await visit(visitsRoute(SERVER, { code: "23514", message: "violates check constraint \"engine_visits_ref_check\"" }), { ref: token, path: OWN });
  const missing = await visit(visitsRoute(SERVER, { code: "PGRST205", message: "no table" }), { ref: LR, path: "/" });
  console.log("    constraint behind: " + behind.status + " " + JSON.stringify(behind.payload) + "\n    table missing: " + missing.status + " " + JSON.stringify(missing.payload));
  check("7. a constraint refusal is 503 naming migration 130; a missing table is still 503 naming 128",
    behind.status === 503 && /migration 130/.test((behind.payload || {}).error || "") && missing.status === 503 && /migration 128/.test((missing.payload || {}).error || ""));

  console.log("\n══ 8. migration 130 ══");
  const conRe = new RegExp((/add constraint engine_visits_ref_check check \(ref ~ '([^']+)'\)/.exec(MIG130) || [])[1] || "^$");
  const routeRe = (function () { const c = {}; vm.runInNewContext(shared().definitionOf(SERVER, "ENGINE_VISIT_REF") + "\nthis.v = ENGINE_VISIT_REF;", c); return c.v; })();
  console.log("    route " + routeRe + "   table " + conRe);
  const SAMPLES = [LR, token, t1, tctx.f("a", "b"), "lr-0000000000", "bl-ffffffffff"].concat(BAD);
  const agree = SAMPLES.map(x => routeRe.test(x) === conRe.test(x));
  check("8. the constraint accepts exactly what the route accepts, over every token above and the malformed set",
    agree.every(Boolean) && conRe.test(LR) && conRe.test(token) && !conRe.test("BL-0123456789"), JSON.stringify(SAMPLES.filter((x, i) => !agree[i])));
  check("8. 128's check is found by what it checks and dropped; nothing else about the table changes",
    /pg_get_constraintdef\(oid\) like '%\(ref ~%'/.test(MIG130) && /drop constraint %I/.test(MIG130) &&
    !/add column|drop column|alter column|landing_path ~|disable row level security|grant /i.test(MIG130.replace(/^--.*$/gm, "")));
  const live = await supabase.from("engine_visits").select("id").limit(1);
  console.log("    live database: engine_visits " + (live.error ? "does not exist (" + (live.error.code || live.error.message) + ")" : "exists") +
    "; whether 130 is applied cannot be read without a write, and this check does not write");

  console.log("\n══ cleanup ══");
  const cleanupResult = await residue.cleanup("end of run");
  if (cleanupResult.leftovers.length) failures++;
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
