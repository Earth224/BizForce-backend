/* ══════════════════════════════════════════════════════════════════════════
   checkSocialFailClosed.js — social listing, publishing and connecting stay
   shut until connected accounts are tied to the user who connected them.

   THE DEFECT. Every Zernio call is made with the app's one API key, and
   nothing records which user connected which account. GET
   /api/social/accounts listed the whole workspace to any signed-in user, and
   POST /api/social-drafts published to the first account on the platform,
   whoever owned it. Zero rows had ever published when SOCIAL_ACCOUNTS_SCOPED
   closed all three routes.

   WHAT THIS PROVES
     0. Statically: server.js reaches zernio.com in exactly three places, and
        every route that can reach one checks SOCIAL_ACCOUNTS_SCOPED before
        it. SOCIAL_ACCOUNTS_SCOPED is false.
     1. GET /api/social/accounts returns { accounts: [] } with
        listing_status "unavailable_pending_per_user_scoping", and makes no
        outbound request.
     2. POST /api/social-drafts makes no outbound request (so neither
        getZernioAccountId nor the publish is reached) and answers
        published: false.
     3. POST /api/social/connect/:platform answers 503 and makes no outbound
        request.
     4. The chosen behaviour for a draft: it is SAVED, as one
        social_post_drafts row with status "not_published", no
        zernio_post_id and no scheduled_for, owned by the caller.

   HOW. Each route, and the helpers it closes over, is lifted out of
   server.js and run in a vm with a recording fetch and a recording fake
   Supabase. ZERNIO_API_KEY is set inside the vm, so an open route WOULD
   reach Zernio — that is what makes the mutations bite. Nothing is sent and
   no database is touched.

   MUTATE=open-accounts  removes the gate from GET /api/social/accounts.
                         1 must go red.
   MUTATE=open-publish   removes the gate from POST /api/social-drafts.
                         2 and 4 must go red.
   MUTATE=open-connect   removes the gate from the connect route.
                         3 must go red.
   The mutations are applied to the extracted source, never to server.js.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const vm = require("vm");
const path = require("path");
const { braceMatch } = require("./_shared");
const REPO = path.join(__dirname, "..");

const MUTATIONS = ["open-accounts", "open-publish", "open-connect"];
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
function statementSource(re, what) {
  const m = re.exec(SRC);
  if (!m) throw new Error(what + " was not found");
  return m[0];
}
function mutate(src, from, to) {
  if (src.split(from).length !== 2) throw new Error("mutation target not found exactly once: " + from);
  return src.replace(from, to);
}

const GATE = "if (!SOCIAL_ACCOUNTS_SCOPED) {";
const R_ACCOUNTS = routeSource("get", "/api/social/accounts");
const R_DRAFTS   = routeSource("post", "/api/social-drafts");
const R_CONNECT  = routeSource("post", "/api/social/connect/:platform");

/* ── 0. static: every way to Zernio, and the gate in front of it ─────────── */
console.log("\n══ 0. every Zernio call site is behind the gate ══");
{
  const hits = [];
  let i = -1;
  while ((i = SRC.indexOf("zernio.com", i + 1)) >= 0) hits.push(SRC.slice(0, i).split("\n").length);
  check("0. server.js names zernio.com exactly three times", hits.length === 3, "lines " + hits.join(", "));

  const scoped = statementSource(/^const SOCIAL_ACCOUNTS_SCOPED = (true|false);$/m, "SOCIAL_ACCOUNTS_SCOPED");
  check("0. SOCIAL_ACCOUNTS_SCOPED is false", /= false;$/.test(scoped), scoped);

  /* The helpers that call Zernio, and every place they are called from. A new
     caller outside these three routes would be an ungated way in. */
  const helperDefs = { fetchZernioAccounts: functionSource("fetchZernioAccounts"), getZernioAccountId: functionSource("getZernioAccountId") };
  const callers = {};
  Object.keys(helperDefs).forEach(function (name) {
    const re = new RegExp("\\b" + name + "\\(", "g");
    let m;
    while ((m = re.exec(SRC))) {
      if (SRC.slice(m.index - 9, m.index) === "function ") continue;
      const line = SRC.slice(0, m.index).split("\n").length;
      const where = [R_ACCOUNTS, R_DRAFTS, R_CONNECT].find(function (r) { return m.index > r.start && m.index < r.start + r.text.length; });
      const inHelper = helperDefs.getZernioAccountId && SRC.indexOf(helperDefs.getZernioAccountId) < m.index && m.index < SRC.indexOf(helperDefs.getZernioAccountId) + helperDefs.getZernioAccountId.length;
      callers[name + "@" + line] = where ? where.text.slice(0, where.text.indexOf("(")) + ' "' + where.text.split('"')[1] + '"' : (inHelper ? "getZernioAccountId" : "ELSEWHERE");
    }
  });
  const outside = Object.keys(callers).filter(function (k) { return callers[k] === "ELSEWHERE"; });
  check("0. the Zernio helpers are called only from the three routes (or each other)", outside.length === 0, JSON.stringify(callers));

  [["GET /api/social/accounts", R_ACCOUNTS, "fetchZernioAccounts("],
   ["POST /api/social-drafts", R_DRAFTS, "getZernioAccountId("],
   ["POST /api/social-drafts", R_DRAFTS, "zernio.com"],
   ["POST /api/social/connect/:platform", R_CONNECT, "zernio.com"]].forEach(function (t) {
    const g = t[1].text.indexOf(GATE), c = t[1].text.indexOf(t[2]);
    check("0. " + t[0] + ": the gate comes before " + t[2].replace("(", ""), g >= 0 && c > g && t[1].text.indexOf(GATE, g + 1) < 0, "gate@" + g + " call@" + c);
  });
}

/* ── the vm ──────────────────────────────────────────────────────────────── */
const HELPERS = [functionSource("nowIso"), functionSource("safeText"),
  statementSource(/^var ZERNIO_PLATFORM_MAP = \{[\s\S]*?\n\};$/m, "ZERNIO_PLATFORM_MAP"),
  functionSource("fetchZernioAccounts"), functionSource("getZernioAccountId")].join("\n\n");

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
    process: { env: { ZERNIO_API_KEY: "check-key" } },   // an open route WOULD reach Zernio
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
  vm.runInContext("const SOCIAL_ACCOUNTS_SCOPED = false;\n\n" + HELPERS + "\n\n" + routeText, ctx);
  if (!handler) throw new Error("handler not captured");
  const res = { statusCode: 200, body: undefined,
    status: function (c) { this.statusCode = c; return this; },
    json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let nextErr = null;
  await handler(Object.assign({ body: {}, params: {}, headers: {}, user: { id: "user-b" } }, req), res, function (e) { nextErr = e || new Error("next() called"); });
  return { status: res.statusCode, body: res.body, outbound: outbound, inserts: db.inserts, nextErr: nextErr };
}

function opened(route, name) { return MUTATE === name ? mutate(route.text, GATE, "if (false) {") : route.text; }

(async function () {
  if (MUTATE) console.log("\n>>> MUTATE=" + MUTATE);

  console.log("\n══ 1. GET /api/social/accounts ══");
  const a = await run(opened(R_ACCOUNTS, "open-accounts"), {});
  console.log("    HTTP " + a.status + " " + JSON.stringify(a.body) + " | outbound: " + JSON.stringify(a.outbound));
  check("1. returns an empty account list", a.status === 200 && a.body && Array.isArray(a.body.accounts) && a.body.accounts.length === 0, JSON.stringify(a.body));
  check("1. says why: listing_status is unavailable_pending_per_user_scoping", a.body && a.body.listing_status === "unavailable_pending_per_user_scoping", a.body && a.body.listing_status);
  check("1. never calls Zernio", a.outbound.length === 0, JSON.stringify(a.outbound));

  console.log("\n══ 2 & 4. POST /api/social-drafts ══");
  const d = await run(opened(R_DRAFTS, "open-publish"), { body: { platform: "instagram", content: "Check draft text", status: "pending", scheduled_for: "2026-10-01T09:00:00.000Z" } });
  console.log("    HTTP " + d.status + " " + JSON.stringify({ published: d.body && d.body.published, message: d.body && d.body.message, status: d.body && d.body.draft && d.body.draft.status }) + " | outbound: " + JSON.stringify(d.outbound));
  check("2. does not call Zernio (no account lookup, no publish)", d.outbound.length === 0, JSON.stringify(d.outbound));
  check("2. answers published: false, with a message saying publishing is off", d.body && d.body.published === false && /not published/i.test(d.body.message || ""), JSON.stringify(d.body && { published: d.body.published, message: d.body.message }));
  const ins = d.inserts;
  const row = ins[0] && ins[0].payload;
  console.log("    inserts: " + JSON.stringify(ins.map(function (x) { return { table: x.table, status: x.payload.status, zernio_post_id: x.payload.zernio_post_id, scheduled_for: x.payload.scheduled_for, user_id: x.payload.user_id }; })));
  check("4. the draft is SAVED: exactly one social_post_drafts insert", ins.length === 1 && ins[0].table === "social_post_drafts", ins.length);
  check("4. the row is honest: status not_published, zernio_post_id null, scheduled_for null", !!row && row.status === "not_published" && row.zernio_post_id === null && row.scheduled_for === null, JSON.stringify(row && { status: row.status, zernio_post_id: row.zernio_post_id, scheduled_for: row.scheduled_for }));
  check("4. owned by the caller, with the text kept", !!row && row.user_id === "user-b" && row.content === "Check draft text", JSON.stringify(row && { user_id: row.user_id }));
  check("4. answers 201 with the saved draft", d.status === 201 && d.body && d.body.draft && d.body.draft.status === "not_published", d.status);

  console.log("\n══ 3. POST /api/social/connect/:platform ══");
  const c = await run(opened(R_CONNECT, "open-connect"), { params: { platform: "facebook" } });
  console.log("    HTTP " + c.status + " " + JSON.stringify(c.body) + " | outbound: " + JSON.stringify(c.outbound));
  check("3. answers 503 saying connections are temporarily unavailable", c.status === 503 && /temporarily unavailable/i.test((c.body && c.body.error) || ""), c.status + " " + JSON.stringify(c.body));
  check("3. never calls Zernio", c.outbound.length === 0, JSON.stringify(c.outbound));
  check("3. returns no connect URL", !(c.body && c.body.url), c.body && c.body.url);

  console.log("\n" + (failures ? failures + " FAILED" : "ALL PASS") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
})().catch(function (e) { console.error(e); process.exit(1); });
