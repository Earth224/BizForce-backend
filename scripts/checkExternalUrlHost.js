/* ══════════════════════════════════════════════════════════════════════════
   checkExternalUrlHost.js — POST /api/content-library/:id/external-published
   takes only a URL on the post's own site.

   WHY IT MATTERS. The URL is not a note. When generate-post next writes an
   article for the same property, it lists every post on that site with an
   external_url as a link target and tells the model to copy each href exactly.
   A URL on another host would go into published work as an off-site or broken
   link. The route used to accept any http(s) URL.

   THE HOST RULE. The URL's host is reduced the way site values are stored —
   canonicalSiteHost: lowercase, leading www. removed — and must equal the
   row's site. So www.<site> is accepted, because the system already treats it
   as the same property. Any other subdomain is refused, because a subdomain is
   often a different property or a third-party host, and a wrong accept costs a
   bad link where a wrong refusal costs a retry.

   WHAT THIS PROVES, with the route lifted out of server.js and run against the
   live database, on fixture rows only:
     1. A URL on the post's site is accepted, and both columns are written.
     2. A URL on another host is refused with 422, naming the host it got and
        the site it expected, and the row is unchanged.
     3. www.<site> is accepted.
     4. A subdomain of the site is refused, naming the subdomain.
     5. A URL whose userinfo imitates the site (https://<site>@other/) is
        refused: the host is the part after the @.
     6. external_url: null clears both columns, and is not host-checked.
     7. A row with no site is still refused as before.
     8. The caller cannot mark another user's row: 404, and that row is
        unchanged.

   FIXTURES. Three content_library rows under the subject account on the site
   bizforce-check.invalid (.invalid can never resolve), one with no site, and
   one under the seed account (supabase/seeds/check_entitled_account.sql) as
   "another user". Never the owner's: if scoping broke, the only row a stray
   write could reach is one this script made. Each account has its own residue
   guard, and every fixture is recorded the moment it is created.

   MUTATE=no-host-check  runs the route with the host check removed.
                         2, 4 and 5 must go red.
   ══════════════════════════════════════════════════════════════════════════ */

require("dotenv").config();

const { createResidueGuard, resolveSubjectAccount, resolveEntitledAccount } = require("./checkRunResidue");
const SUBJECT_USER_ID = resolveSubjectAccount();

const fs = require("fs");
const vm = require("vm");
const path = require("path");
const { braceMatch } = require("./_shared");
const REPO = path.join(__dirname, "..");

const { createClient } = require("@supabase/supabase-js");
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY
);

const MUTATIONS = ["no-host-check"];
const MUTATE = process.env.MUTATE || "";
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", "));
  process.exit(2);
}

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const SITE = "bizforce-check.invalid";
const ROUTE = "/api/content-library/:id/external-published";

/* ── the route, lifted from the working copy ───────────────────────────── */
const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8").replace(/\r\n/g, "\n");
function routeSource(src, method, route) {
  const start = src.indexOf("app." + method + '("' + route + '"');
  if (start < 0) throw new Error("route not found: " + route);
  const end = braceMatch(src, src.indexOf("{", src.indexOf("async function", start)));
  if (src.slice(end, end + 2) !== ");") throw new Error("route did not end where expected: " + route);
  return src.slice(start, end + 2);
}
function functionSource(src, name) {
  const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(src);
  if (!m) throw new Error("function " + name + " was not found");
  return src.slice(m.index, braceMatch(src, src.indexOf(") {", m.index) + 2));
}

let routeCode = routeSource(SRC, "post", ROUTE);
const HOST_CHECK = /\n    if \(!clearing\) \{\n      var expectedSite[\s\S]*?\n    \}\n/;
if (!HOST_CHECK.test(routeCode)) {
  console.error("EXTRACTION FAILED: the host check was not found in the route.");
  process.exit(3);
}
if (MUTATE === "no-host-check") {
  routeCode = routeCode.replace(HOST_CHECK, "\n");
  console.log("\n!! MUTATION: the host check is removed — 2, 4 and 5 must fail.");
}

function build() {
  let handler = null;
  const ctx = {
    supabase: supabase, URL: URL, console: { log() {}, warn() {}, error() {} },
    requireAuth: 0,
    app: { post: function () { handler = arguments[arguments.length - 1]; } }
  };
  vm.createContext(ctx);
  vm.runInContext(functionSource(SRC, "safeText") + "\n\n" + functionSource(SRC, "canonicalSiteHost") + "\n\n" + routeCode, ctx);
  if (!handler) throw new Error("handler not captured");
  return handler;
}
const handler = build();

async function call(userId, id, body) {
  const res = { statusCode: 200, body: undefined,
    status: function (c) { this.statusCode = c; return this; },
    json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null;
  await handler({ user: { id: userId }, params: { id: id }, body: body, query: {}, headers: {} }, res,
    function (e) { nextErr = e || new Error("next() called"); });
  return { status: nextErr ? 500 : res.statusCode, body: res.body, err: nextErr };
}
async function row(id) {
  const r = await supabase.from("content_library").select("id, user_id, site, external_url, external_published_at").eq("id", id).maybeSingle();
  if (r.error) throw r.error;
  return r.data;
}

const residue = createResidueGuard({
  supabase: supabase, name: "externalUrlHost", subject: SUBJECT_USER_ID, tables: ["content_library"]
});
residue.install();
let seedResidue = null;

async function fixture(guard, userId, site, label) {
  const ins = await supabase.from("content_library").insert({
    user_id: userId, type: "blog", status: "draft", site: site,
    title: "Check fixture: " + label + " (scripts/checkExternalUrlHost.js)",
    body: "Fixture row for the external-URL host check. Removed at the end of the run."
  }).select("id").single();
  if (ins.error) throw new Error("could not create fixture " + label + ": " + ins.error.message);
  guard.record("content_library", ins.data.id);
  return ins.data.id;
}

(async function main() {
  await residue.sweepPrevious(SUBJECT_USER_ID);
  const seed = await resolveEntitledAccount(supabase);
  seedResidue = createResidueGuard({ supabase: supabase, name: "externalUrlHost-other", subject: seed.id, tables: ["content_library"] });
  seedResidue.install();
  await seedResidue.sweepPrevious(seed.id);

  console.log("\n══ route under test: " + (MUTATE ? "MUTATED (" + MUTATE + ")" : "server.js as it stands") + " ══");
  const post = await fixture(residue, SUBJECT_USER_ID, SITE, "external post");
  const noSite = await fixture(residue, SUBJECT_USER_ID, null, "platform post");
  const theirs = await fixture(seedResidue, seed.id, SITE, "another user's post");
  console.log("    fixtures: subject " + post + " (site " + SITE + "), subject " + noSite + " (no site), other user " + theirs);

  console.log("\n══ 1. a URL on the post's site ══");
  let r = await call(SUBJECT_USER_ID, post, { external_url: "https://" + SITE + "/blog/first-post" });
  let x = await row(post);
  console.log("    HTTP " + r.status + " | row: " + JSON.stringify({ external_url: x.external_url, external_published_at: x.external_published_at }));
  check("1. accepted (200)", r.status === 200, r.status + " " + JSON.stringify(r.body));
  check("1. external_url and external_published_at are both written",
    x.external_url === "https://" + SITE + "/blog/first-post" && !!x.external_published_at, JSON.stringify(x));

  console.log("\n══ 2. a URL on another host ══");
  r = await call(SUBJECT_USER_ID, post, { external_url: "https://elsewhere.invalid/blog/first-post" });
  let y = await row(post);
  console.log("    HTTP " + r.status + " " + JSON.stringify(r.body));
  check("2. refused (422)", r.status === 422, r.status);
  check("2. the refusal names the host it got and the site it expected",
    !!r.body && /elsewhere\.invalid/.test(r.body.error || "") && (r.body.error || "").indexOf(SITE) !== -1,
    r.body && r.body.error);
  check("2. the row is unchanged", y.external_url === x.external_url && y.external_published_at === x.external_published_at, JSON.stringify(y));

  console.log("\n══ 3. www.<site> ══");
  r = await call(SUBJECT_USER_ID, post, { external_url: "https://www." + SITE + "/blog/www-post" });
  x = await row(post);
  console.log("    HTTP " + r.status + " | external_url " + x.external_url);
  check("3. accepted, and stored as sent", r.status === 200 && x.external_url === "https://www." + SITE + "/blog/www-post", r.status + " " + x.external_url);

  console.log("\n══ 4. a subdomain of the site ══");
  r = await call(SUBJECT_USER_ID, post, { external_url: "https://blog." + SITE + "/first-post" });
  y = await row(post);
  console.log("    HTTP " + r.status + " " + JSON.stringify(r.body));
  check("4. refused (422), naming the subdomain", r.status === 422 && !!r.body && (r.body.error || "").indexOf("blog." + SITE) !== -1, r.status + " " + JSON.stringify(r.body));
  check("4. the row is unchanged", y.external_url === x.external_url, y.external_url);

  console.log("\n══ 5. userinfo that imitates the site ══");
  r = await call(SUBJECT_USER_ID, post, { external_url: "https://" + SITE + "@elsewhere.invalid/blog/first-post" });
  y = await row(post);
  console.log("    HTTP " + r.status + " " + JSON.stringify(r.body));
  check("5. refused (422): the host is elsewhere.invalid", r.status === 422 && !!r.body && /elsewhere\.invalid/.test(r.body.error || ""), r.status + " " + JSON.stringify(r.body));
  check("5. the row is unchanged", y.external_url === x.external_url, y.external_url);

  console.log("\n══ 6. null clears ══");
  r = await call(SUBJECT_USER_ID, post, { external_url: null });
  x = await row(post);
  console.log("    HTTP " + r.status + " | row: " + JSON.stringify({ external_url: x.external_url, external_published_at: x.external_published_at }));
  check("6. accepted (200)", r.status === 200, r.status + " " + JSON.stringify(r.body));
  check("6. both columns are null again", x.external_url === null && x.external_published_at === null, JSON.stringify(x));

  console.log("\n══ 7. a row with no site ══");
  r = await call(SUBJECT_USER_ID, noSite, { external_url: "https://" + SITE + "/blog/anything" });
  const z = await row(noSite);
  console.log("    HTTP " + r.status + " " + JSON.stringify(r.body));
  check("7. refused (422) with the no-site message, as before",
    r.status === 422 && !!r.body && /has no site value/.test(r.body.error || ""), r.status + " " + JSON.stringify(r.body));
  check("7. nothing written", z.external_url === null && z.external_published_at === null, JSON.stringify(z));

  console.log("\n══ 8. another user's row ══");
  r = await call(SUBJECT_USER_ID, theirs, { external_url: "https://" + SITE + "/blog/not-yours" });
  const t = await row(theirs);
  console.log("    HTTP " + r.status + " " + JSON.stringify(r.body));
  check("8. 404 for a row that is not the caller's", r.status === 404, r.status + " " + JSON.stringify(r.body));
  check("8. that row is unchanged", t.external_url === null && t.external_published_at === null && t.user_id === seed.id, JSON.stringify(t));

  console.log("\n══ cleanup ══");
  const mine = await residue.cleanup("end of run");
  const other = await seedResidue.cleanup("end of run");
  if (mine.leftovers.length || other.leftovers.length) failures++;

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("\nThe check threw: " + ((err && err.stack) || err));
  process.exit(1);
});
