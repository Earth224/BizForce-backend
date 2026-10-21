/* ══════════════════════════════════════════════════════════════════════════
   checkSocialFailClosed.js — social listing, publishing and connecting stay
   shut, and nothing in server.js can reach a social platform.

   THE DEFECT. Every Zernio call was made with the app's one API key, and
   nothing recorded which user connected which account. GET
   /api/social/accounts listed the whole workspace to any signed-in user, and
   POST /api/social-drafts published to the first account on the platform,
   whoever owned it. Zero rows had ever published when SOCIAL_ACCOUNTS_SCOPED
   (a constant, false) closed all three routes. The code behind those gates
   could never run, and setting ZERNIO_API_KEY did not open it, so launch
   audit #22c deleted it; each route now does only what it did while closed.

   WHAT THIS PROVES
     0. Statically: server.js names zernio.com nowhere, reads no
        ZERNIO_API_KEY or ZERNIO_PROFILE_ID, and declares none of the deleted
        names (fetchZernioAccounts, getZernioAccountId, ZERNIO_PLATFORM_MAP,
        SOCIAL_ACCOUNTS_SCOPED); none of the three routes calls fetch.
     1. GET /api/social/accounts returns { accounts: [] } with
        listing_status "unavailable_pending_per_user_scoping", and makes no
        outbound request.
     2. POST /api/social-drafts makes no outbound request and answers
        published: false.
     3. POST /api/social/connect/:platform answers 503 and makes no outbound
        request.
     4. The chosen behaviour for a draft: it is SAVED, as one
        social_post_drafts row with status "not_published", no
        zernio_post_id and no scheduled_for, owned by the caller.
     5. The frontend says so: integrations.html marks Zernio and the six
        social platforms "Removed", with no "Connecting was built" and no
        connect button, and its guide tips no longer list Zernio among the
        services that run on BizForce.

   HOW. Each route, and the helpers it closes over, is lifted out of
   server.js and run in a vm with a recording fetch and a recording fake
   Supabase. ZERNIO_API_KEY is set inside the vm, so code that read it and
   called out would be seen. Nothing is sent and no database is touched.

   MUTATE=zernio-call-restored    the accounts route calls zernio.com again.
                                  1 must go red.
   MUTATE=publish-claims-published the draft is saved as "published".
                                  4 must go red.
   MUTATE=connect-returns-url     the connect route hands out a URL again.
                                  3 must go red.
   MUTATE=integrations-zernio-runs  the Zernio card says "Runs on BizForce".
   MUTATE=integrations-connect-built a social card says connecting was built.
                                  5 must go red for both.
   The mutations are applied to the extracted source, never to server.js. A
   search text that does not match exactly once is an ERROR, never a catch.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const vm = require("vm");
const path = require("path");
const { braceMatch } = require("./_shared");
const REPO = path.join(__dirname, "..");

const MUTATIONS = ["zernio-call-restored", "publish-claims-published", "connect-returns-url", "integrations-zernio-runs", "integrations-connect-built"];
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const INTEGRATIONS = "integrations.html", GUIDE = "scripts/termaximus-guide.js";
/* Frontend mutations, applied in memory to the file named. */
const FRONT_MUTANTS = {
  // the Zernio card says it runs on BizForce again
  "integrations-zernio-runs": [INTEGRATIONS, "BizForce posts nothing through it.</p>\n          <span class=\"int-status\">Removed</span>",
    "BizForce posts nothing through it.</p>\n          <span class=\"int-status\">Runs on BizForce</span>"],
  // a social card says connecting was built and is only paused
  "integrations-connect-built": [INTEGRATIONS, "BizForce does not post to Facebook. Connecting an account was removed because it could not be tied to the person who connected it.</p>\n          <span class=\"int-status\">Removed</span>",
    "Schedule posts and manage your Facebook business page.</p>\n          <span class=\"int-status\">Unavailable</span>\n          <div class=\"int-card-footer\">\n            <button class=\"int-connect-btn\" disabled>Unavailable</button>\n            <span class=\"int-note\">Connecting was built and is turned off for now, while each connected account is tied to the person who connected it.</span>\n          </div>"]
};
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");
// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") MUT.runAllMutations(__filename, MUTATIONS);
if (MUTATE && MUTATIONS.indexOf(MUTATE) === -1) {
  console.error("Unknown MUTATE=" + MUTATE + ". Known: " + MUTATIONS.join(", "));
  process.exit(2);
}

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

const SRC = fs.readFileSync(path.join(REPO, "server.js"), "utf8");

function routeSource(method, route) {
  const sig = "app." + method + '("' + route + '"';
  const start = SRC.indexOf(sig);
  if (start < 0) throw new Error("route not found: " + method + " " + route);
  if (SRC.indexOf(sig, start + 1) >= 0) throw new Error("route registered twice: " + route);
  const end = braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("async function", start)));
  if (SRC.slice(end, end + 2) !== ");") throw new Error("route did not end where expected: " + route);
  return { start: start, text: SRC.slice(start, end + 2) };
}
function functionSource(name) {
  const m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(SRC);
  if (!m) throw new Error("function " + name + " was not found");
  return SRC.slice(m.index, braceMatch(SRC, SRC.indexOf(") {", m.index) + 2));
}
const uncommented = (text) => text.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'])\/\/[^\n]*/g, "$1");

const R_ACCOUNTS = routeSource("get", "/api/social/accounts");
const R_DRAFTS   = routeSource("post", "/api/social-drafts");
const R_CONNECT  = routeSource("post", "/api/social/connect/:platform");

/* ── 0. static: no way to a social platform is left ─────────────────────── */
console.log("\n══ 0. server.js reaches no social platform ══");
{
  const CODE = uncommented(SRC);
  const hits = [];
  let i = -1;
  while ((i = SRC.indexOf("zernio.com", i + 1)) >= 0) hits.push(SRC.slice(0, i).split("\n").length);
  check("0. server.js names zernio.com nowhere", hits.length === 0, "lines " + hits.join(", "));
  check("0. no code reads ZERNIO_API_KEY or ZERNIO_PROFILE_ID", !/process\.env\.ZERNIO_/.test(CODE), (CODE.match(/process\.env\.ZERNIO_\w+/g) || []).join(", "));
  const gone = ["fetchZernioAccounts", "getZernioAccountId", "ZERNIO_PLATFORM_MAP", "SOCIAL_ACCOUNTS_SCOPED"].filter(function (n) { return new RegExp("\\b" + n + "\\b").test(CODE); });
  check("0. the deleted names are declared and used nowhere in code", gone.length === 0, gone.join(", "));
  [["GET /api/social/accounts", R_ACCOUNTS], ["POST /api/social-drafts", R_DRAFTS], ["POST /api/social/connect/:platform", R_CONNECT]].forEach(function (t) {
    check("0. " + t[0] + " calls no fetch", !/\bfetch\(/.test(uncommented(t[1].text)));
  });
}

/* ── the vm ──────────────────────────────────────────────────────────────── */
const HELPERS = [functionSource("nowIso"), functionSource("safeText")].join("\n\n");

function fakeDb() {
  const inserts = [];
  function builder(table) {
    let payload = null;
    const q = {
      insert: function (p) { payload = p; inserts.push({ table: table, payload: p }); return q; },
      select: function () { return q; },
      single: async function () { return { data: Object.assign({ id: "draft-1" }, payload), error: null }; }
    };
    return q;
  }
  return { client: { from: builder }, inserts: inserts };
}

async function run(routeText, req) {
  const outbound = [];
  const db = fakeDb();
  let handler = null;
  const ctx = {
    console: { log: function () {}, warn: function () {}, error: function () {} },
    process: { env: { ZERNIO_API_KEY: "check-key" } },   // code that read the key and called out would be seen
    requireAuth: function () {},
    supabase: db.client,
    JSON: JSON, Date: Date, String: String, Array: Array, Object: Object, encodeURIComponent: encodeURIComponent,
    fetch: async function (url) {
      outbound.push(String(url));
      return { ok: true, status: 200,
        json: async function () { return { accounts: [{ _id: "someone-elses", platform: "instagram", name: "Another Tenant" }], url: "https://zernio.example/oauth", post: { _id: "zp-1" } }; },
        text: async function () { return JSON.stringify({ post: { _id: "zp-1" } }); } };
    },
    app: { get: function () { handler = arguments[arguments.length - 1]; }, post: function () { handler = arguments[arguments.length - 1]; } }
  };
  vm.createContext(ctx);
  vm.runInContext(HELPERS + "\n\n" + routeText, ctx);
  if (!handler) throw new Error("handler not captured");
  const res = { statusCode: 200, body: undefined,
    status: function (c) { this.statusCode = c; return this; },
    json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null;
  await handler(Object.assign({ body: {}, params: {}, headers: {}, user: { id: "user-b" } }, req), res, function (e) { nextErr = e || new Error("next() called"); });
  return { status: res.statusCode, body: res.body, outbound: outbound, inserts: db.inserts, nextErr: nextErr };
}

const MUTANTS = {
  "zernio-call-restored": [R_ACCOUNTS, "    return res.json({ accounts: [], listing_status:",
    "    await fetch(\"https://zernio.com/api/v1/accounts\");\n    return res.json({ accounts: [], listing_status:"],
  "publish-claims-published": [R_DRAFTS, "        status:         \"not_published\",", "        status:         \"published\","],
  "connect-returns-url": [R_CONNECT, "    return res.status(503).json({ error: \"Social account connections are temporarily unavailable.\" });",
    "    return res.json({ ok: true, url: \"https://zernio.example/oauth\" });"]
};
function source(route) {
  const m = MUTANTS[MUTATE];
  return m && m[0] === route ? MUT.replaceOnce(route.text, m[1], m[2], MUTATE) : route.text;
}

(async function () {
  if (MUTATE) console.log("\n>>> MUTATE=" + MUTATE);

  console.log("\n══ 1. GET /api/social/accounts ══");
  const a = await run(source(R_ACCOUNTS), {});
  console.log("    HTTP " + a.status + " " + JSON.stringify(a.body) + " | outbound: " + JSON.stringify(a.outbound));
  check("1. returns an empty account list", a.status === 200 && a.body && Array.isArray(a.body.accounts) && a.body.accounts.length === 0, JSON.stringify(a.body));
  check("1. says why: listing_status is unavailable_pending_per_user_scoping", a.body && a.body.listing_status === "unavailable_pending_per_user_scoping", a.body && a.body.listing_status);
  check("1. never calls out", a.outbound.length === 0, JSON.stringify(a.outbound));

  console.log("\n══ 2 & 4. POST /api/social-drafts ══");
  const d = await run(source(R_DRAFTS), { body: { platform: "instagram", content: "Check draft text", status: "pending", scheduled_for: "2026-10-01T09:00:00.000Z" } });
  console.log("    HTTP " + d.status + " " + JSON.stringify({ published: d.body && d.body.published, message: d.body && d.body.message, status: d.body && d.body.draft && d.body.draft.status }) + " | outbound: " + JSON.stringify(d.outbound));
  check("2. does not call out (no account lookup, no publish)", d.outbound.length === 0, JSON.stringify(d.outbound));
  check("2. answers published: false, with a message saying publishing is off", d.body && d.body.published === false && /not published/i.test(d.body.message || ""), JSON.stringify(d.body && { published: d.body.published, message: d.body.message }));
  const ins = d.inserts;
  const row = ins[0] && ins[0].payload;
  console.log("    inserts: " + JSON.stringify(ins.map(function (x) { return { table: x.table, status: x.payload.status, zernio_post_id: x.payload.zernio_post_id, scheduled_for: x.payload.scheduled_for, user_id: x.payload.user_id }; })));
  check("4. the draft is SAVED: exactly one social_post_drafts insert", ins.length === 1 && ins[0].table === "social_post_drafts", ins.length);
  check("4. the row is honest: status not_published, zernio_post_id null, scheduled_for null", !!row && row.status === "not_published" && row.zernio_post_id === null && row.scheduled_for === null, JSON.stringify(row && { status: row.status, zernio_post_id: row.zernio_post_id, scheduled_for: row.scheduled_for }));
  check("4. owned by the caller, with the text kept", !!row && row.user_id === "user-b" && row.content === "Check draft text", JSON.stringify(row && { user_id: row.user_id }));
  check("4. answers 201 with the saved draft", d.status === 201 && d.body && d.body.draft && d.body.draft.status === "not_published", d.status);

  console.log("\n══ 3. POST /api/social/connect/:platform ══");
  const c = await run(source(R_CONNECT), { params: { platform: "facebook" } });
  console.log("    HTTP " + c.status + " " + JSON.stringify(c.body) + " | outbound: " + JSON.stringify(c.outbound));
  check("3. answers 503 saying connections are temporarily unavailable", c.status === 503 && /temporarily unavailable/i.test((c.body && c.body.error) || ""), c.status + " " + JSON.stringify(c.body));
  check("3. never calls out", c.outbound.length === 0, JSON.stringify(c.outbound));
  check("3. returns no connect URL", !(c.body && c.body.url), c.body && c.body.url);

  /* ── 5. the integrations page says what is now true ─────────────────── */
  console.log("\n══ 5. integrations.html and its tips ══");
  const front = {};
  [INTEGRATIONS, GUIDE].forEach(function (f) { front[f] = fs.readFileSync(path.join(FRONTEND, f), "utf8").replace(/\r\n/g, "\n"); });
  if (FRONT_MUTANTS[MUTATE]) { const fm = FRONT_MUTANTS[MUTATE]; front[fm[0]] = MUT.replaceOnce(front[fm[0]], fm[1], fm[2], MUTATE); }
  const cards = {};
  (front[INTEGRATIONS].match(/<div class="int-card">[\s\S]*?<span class="int-status">[^<]*<\/span>/g) || []).forEach(function (card) {
    cards[(/<p class="int-card-name">([^<]*)<\/p>/.exec(card) || ["", ""])[1]] = (/<span class="int-status">([^<]*)<\/span>/.exec(card) || ["", ""])[1];
  });
  const SOCIAL = ["Zernio", "Facebook", "Instagram", "TikTok", "X / Twitter", "YouTube", "LinkedIn"];
  const wrong = SOCIAL.filter(function (n) { return cards[n] !== "Removed"; });
  check("5. Zernio and the six social platforms are each marked Removed (" + SOCIAL.length + ")", wrong.length === 0, wrong.map(function (n) { return n + "=" + cards[n]; }).join(", "));
  check("5. no card says connecting was built, and no connect button is left", !/Connecting was built/.test(front[INTEGRATIONS]) && !/int-connect-btn/.test(front[INTEGRATIONS]));
  const tips = (/"integrations\.html": \[([\s\S]*?)\n    \]/.exec(front[GUIDE]) || ["", ""])[1];
  check("5. the integrations tips no longer say Zernio runs on BizForce or that connecting was built",
    tips.length > 0 && !/Zernio and email|connecting was built/.test(tips) && /Zernio and the six social platforms it posted to/.test(tips), tips.slice(0, 200));

  console.log("\n" + (failures ? failures + " FAILED" : "ALL PASS") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
})().catch(function (e) { console.log("    FAIL  the harness stopped: " + ((e && e.message) || e)); console.error(e); process.exit(1); });
