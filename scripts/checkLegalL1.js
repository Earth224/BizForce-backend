/* checkLegalL1: Block L1, the legal and compliance fixes from the architect's review (Nov 14 2026, L1).

   WHAT IT PROVES, each from the code itself (lib/legalPages.js, lib/legal.js, lib/yourData.js, lib/youtubeApi.js,
   lib/googleAuth.js, lib/renewalEmails.js, lib/dailyClaim.js, server.js and the frontend's pages), never from a copy:
     A. THE LEGAL TEXT, built from the sources under test: Privacy section 9 "Google and YouTube" in two parts, Google's
        Limited Use sentence word for word, the revoke and Google Privacy Policy links, the two permissions named (and
        lib/googleAuth.js asks for exactly those two), every figure from the code, the false "does not sign in"
        sentence gone; the YouTube Terms clause; the Do Not Track and Global Privacy Control paragraph (and no route
        reads either signal); the real backup retention; "card order" gone; the video-player cookie line; the terms
        and price emails in Terms 3 and 15 and Privacy 10; the version, date and CHANGE_SUMMARY; the four frontend
        pages equal the build.
     B. THE EMBEDS: youtube-nocookie.com for YouTube, dnt=1 for Vimeo, on profile.html and seller.html; PAGE_SERVICES
        follows; the CSP is reported.
     C. THE YOUTUBE DATA RULES: disconnect revokes at Google and deletes every piece of authorized data at once (the
        quota ledger and another member's rows kept); the daily pass deletes a connection Google refuses, with ONE
        notice; refreshes the channel name; the 30-day rules; claimed once a day; in the 04:45 chain.
     D. THE EMAILS: confirmation, yearly, price-change and terms-change contents; each at most once per member per
        occasion; through the real sendEmail with the contact footer and the postal address; the owner-only price
        route and its 7-30 day window; the webhook sends the confirmation; nothing logs an address.
     E. CONSENT RECORDS: account deletion keeps the automatic-renewal consent time and version.

   MUTATIONS: MUTATE=<name> applies one in memory; MUTATE=all runs each in its own process. The twelve the brief
   named, and test-accounts-mailed. Nothing here opens a socket or writes a row. */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const Module = require("module");
const MUT = require("./_shared");

const REPO = path.join(__dirname, "..");
const FE = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const lf = (s) => s.replace(/\r\n/g, "\n");
const read = (f) => lf(fs.readFileSync(path.join(REPO, f), "utf8"));
const readFe = (f) => lf(fs.readFileSync(path.join(FE, f), "utf8"));

const FILES = {
  legal: read("lib/legal.js"), pages: read("lib/legalPages.js"), yourData: read("lib/yourData.js"), api: read("lib/youtubeApi.js"),
  auth: read("lib/googleAuth.js"), mail: read("lib/renewalEmails.js"), claim: read("lib/dailyClaim.js"), server: read("server.js"),
  profile: readFe("profile.html"), seller: readFe("seller.html")
};
const FILE_NAMES = { legal: "lib/legal.js", pages: "lib/legalPages.js", yourData: "lib/yourData.js", api: "lib/youtubeApi.js", auth: "lib/googleAuth.js",
  mail: "lib/renewalEmails.js", claim: "lib/dailyClaim.js", server: "server.js" };

const MUTATIONS = {
  "limited-use-removed": ["pages", "    LIMITED_USE_SENTENCE,\n", ""],
  "revoke-link-removed": ["pages",
    "\"Revoking access: choose Disconnect on the Social Agent page in BizForce, or remove BizForce from your Google Account at \" + GOOGLE_PERMISSIONS_URL + \". \" +",
    "\"Revoking access: choose Disconnect on the Social Agent page in BizForce. \" +"],
  "youtube-terms-clause-removed": ["pages", "      YOUTUBE_TOS_TERMS_SENTENCE,\n", ""],
  "false-signin-sentence-back": ["pages", "and Lead Radar does not use any member's YouTube or Google account.", "and BizForce does not sign in to anyone's YouTube or Google account."],
  "disconnect-keeps-data": ["server", "    var purgedNow = await ya.purgeYoutubeData(youtubeDeps(), req.user.id, { notices: true });\n",
    "    var purgedNow = { videos: 0, proposals: 0, notices: 0 };\n"],
  "invalid-grant-ignored": ["api", "  if (refused) {\n", "  if (false) {\n"],
  "yearly-reminder-twice": ["mail", "templateFor(OCCASION.yearly, [s.user_id, year])", "templateFor(OCCASION.yearly, [s.user_id, year, startedMs])"],
  "price-notice-window-ignored": ["mail", "  if (!win.ok) return { status: 400, body: { error: win.error, code: \"window\", days: win.days === undefined ? null : win.days } };\n", ""],
  "price-route-not-admin": ["server", "app.post(\"/api/admin/price-change-notice\", requireAuth, requireAdmin, async", "app.post(\"/api/admin/price-change-notice\", requireAuth, async"],
  "terms-email-every-run": ["mail", "templateFor(OCCASION.termsChange, [legal.TERMS_VERSION, u.id])", "templateFor(OCCASION.termsChange, [legal.TERMS_VERSION, u.id, startedMs])"],
  "consent-erased-on-delete": ["yourData", "        email_verified_at: null, updated_at: now.toISOString()",
    "        email_verified_at: null, auto_renew_consent_at: null, auto_renew_consent_version: null, updated_at: now.toISOString()"],
  // Beyond the brief's twelve: test accounts (which cannot receive mail) and the owner are not subscribers.
  "test-accounts-mailed": ["mail", "      if (!member || uncounted(member)) continue;\n", "      if (!member) continue;\n"],
  "youtube-cookie-embed-back": ["profile", "\"https://www.youtube-nocookie.com/embed/\"+id", "\"https://www.youtube.com/embed/\"+id"]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + NAMES.join(", ")); process.exit(2); }
if (MUTATE) { const m = MUTATIONS[MUTATE]; FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE); }

/* Every console line the code under test prints is captured, so "no address logged" can be proved. */
const LOGS = [];
const OUT = (s) => process.stdout.write(s + "\n");
console.log = function () { LOGS.push([].slice.call(arguments).join(" ")); };
console.warn = console.log; console.error = console.log;
let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; OUT("    pass  " + label); }
  else { failures++; OUT("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
process.on("unhandledRejection", (e) => { failures++; OUT("    FAIL  unhandled rejection: " + (e && e.message)); });
const J = JSON.stringify;

/* A network tripwire: nothing here may open a socket or ask DNS. */
const TRIPPED = [];
(function () {
  const http = require("http"), https = require("https"), net = require("net"), dns = require("dns");
  const wire = (o, n) => { o[n] = function () { TRIPPED.push(n); throw new Error("checkLegalL1: " + n + " is not allowed"); }; };
  wire(http, "request"); wire(https, "request"); wire(net, "connect"); wire(net, "createConnection"); wire(dns, "lookup");
  globalThis.fetch = function () { TRIPPED.push("fetch"); return Promise.reject(new Error("checkLegalL1: fetch is not allowed")); };
})();

/* Compiles a source string as the module it is, with some of its requires answered from `map`. */
function compile(src, file, map) {
  const filename = path.join(REPO, file);
  const m = new Module(filename, module);
  m.filename = filename;
  m.paths = Module._nodeModulePaths(path.dirname(filename));
  const real = m.require.bind(m);
  m.require = function (r) { return Object.prototype.hasOwnProperty.call(map, r) ? map[r] : real(r); };
  m._compile(src, filename);
  return m.exports;
}
const LEGAL = compile(FILES.legal, FILE_NAMES.legal, {});
const DC = compile(FILES.claim, FILE_NAMES.claim, {});
const GA = compile(FILES.auth, FILE_NAMES.auth, {});
const YA = compile(FILES.api, FILE_NAMES.api, { "./googleAuth": GA, "./dailyClaim": DC });
const RE = compile(FILES.mail, FILE_NAMES.mail, { "./legal": LEGAL, "./dailyClaim": DC });
const YD = compile(FILES.yourData, FILE_NAMES.yourData, {});
const LP = compile(FILES.pages, FILE_NAMES.pages, { "./legal": LEGAL, "./yourData": YD, "./youtubeApi": YA, "./renewalEmails": RE });

function decode(s) {
  return s.replace(/&#39;/g, "'").replace(/&quot;/g, "\"").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&middot;/g, "-").replace(/&larr;/g, "<-").replace(/&amp;/g, "&");
}
function textOf(html) { return decode(String(html).replace(/<script[\s\S]*?<\/script>/g, " ").replace(/<style[\s\S]*?<\/style>/g, " ").replace(/<a [^>]*>|<\/a>/g, "").replace(/<[^>]+>/g, " ")).replace(/\s+/g, " "); }
function between(html, a, b) { const i = html.indexOf(a), j = html.indexOf(b, i + 1); return i === -1 || j === -1 ? "" : html.slice(i, j); }

/* ── a small in-memory Supabase ─────────────────────────────────────────── */
function makeDb(seed) {
  const t = Object.assign({}, seed || {});
  let nextId = 1;
  const rows = (n) => { if (!t[n]) t[n] = []; return t[n]; };
  function from(name) {
    const q = { op: null, cols: null, filters: [], or: null, payload: null, single: null, range: null, limit: null, order: null, returning: false, head: false, count: false };
    const api = {
      select(c, o) { if (!q.op) q.op = "select"; else q.returning = true; q.cols = c; if (o && o.head) q.head = true; if (o && o.count) q.count = true; return api; },
      insert(p) { q.op = "insert"; q.payload = p; return api; },
      update(p) { q.op = "update"; q.payload = p; return api; },
      upsert(p) { q.op = "upsert"; q.payload = p; return api; },
      delete() { q.op = "delete"; return api; },
      eq(c, v) { q.filters.push(["eq", c, v]); return api; }, neq(c, v) { q.filters.push(["neq", c, v]); return api; },
      in(c, v) { q.filters.push(["in", c, v]); return api; }, is(c, v) { q.filters.push(["is", c, v]); return api; },
      not(c, op, v) { q.filters.push(["not", c, op, v]); return api; },
      lt(c, v) { q.filters.push(["lt", c, v]); return api; }, gt(c, v) { q.filters.push(["gt", c, v]); return api; },
      gte(c, v) { q.filters.push(["gte", c, v]); return api; }, like(c, v) { q.filters.push(["like", c, v]); return api; },
      or(s) { q.or = s; return api; }, order(c, o) { q.order = [c, !(o && o.ascending === false)]; return api; },
      limit(n) { q.limit = n; return api; }, range(a, b) { q.range = [a, b]; return api; },
      maybeSingle() { q.single = "maybe"; return api; }, single() { q.single = "one"; return api; },
      then(ok, bad) { return Promise.resolve().then(run).then(ok, bad); }
    };
    function match(r) {
      const ok = q.filters.every((f) => {
        const v = r[f[1]];
        if (f[0] === "eq") return String(v) === String(f[2]);
        if (f[0] === "neq") return String(v) !== String(f[2]);
        if (f[0] === "in") return f[2].map(String).indexOf(String(v)) !== -1;
        if (f[0] === "is") return f[2] === null ? v == null : v === f[2];
        if (f[0] === "not") return f[2] === "is" && f[3] === null ? v != null : true;
        if (f[0] === "lt") return v != null && String(v) < String(f[2]);
        if (f[0] === "gt") return v != null && String(v) > String(f[2]);
        if (f[0] === "gte") return v != null && String(v) >= String(f[2]);
        if (f[0] === "like") return v != null && String(v).indexOf(String(f[2]).replace(/%$/, "")) === 0;
        return true;
      });
      if (!ok) return false;
      if (q.or) { const d = /neq\.(\d{4}-\d{2}-\d{2})/.exec(q.or); return !d || r.last_run_on == null || r.last_run_on !== d[1]; }
      return true;
    }
    function project(r) {
      if (!q.cols || q.cols.trim() === "*") return Object.assign({}, r);
      const o = {}; q.cols.split(",").map((c) => c.trim()).forEach((c) => { o[c] = r[c] === undefined ? null : r[c]; }); return o;
    }
    function shape(list) {
      const data = list.map(project);
      if (q.single === "maybe") return { data: data[0] || null, error: null };
      if (q.single === "one") return data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116", message: "not one row" } };
      return { data: q.op === "select" || q.returning ? data : null, error: null };
    }
    function run() {
      const all = rows(name);
      if (q.op === "select") {
        let hit = all.filter(match);
        if (q.order) { const [c, asc] = q.order; hit = hit.slice().sort((a, b) => (String(a[c]) < String(b[c]) ? -1 : String(a[c]) > String(b[c]) ? 1 : 0) * (asc ? 1 : -1)); }
        const total = hit.length;
        if (q.range) hit = hit.slice(q.range[0], q.range[1] + 1);
        if (q.limit != null) hit = hit.slice(0, q.limit);
        const out = q.head ? { data: null, error: null } : shape(hit);
        if (q.count) out.count = total;
        return out;
      }
      if (q.op === "insert") {
        const list = Array.isArray(q.payload) ? q.payload : [q.payload];
        const made = [];
        for (const p of list) {
          const r = Object.assign({ id: name === "job_runs" ? undefined : "row-" + (nextId++), created_at: new Date(NOW).toISOString() }, p);
          if (name === "job_runs" && all.some((x) => x.job_name === r.job_name)) return { data: null, error: { code: "23505", message: "duplicate key value violates unique constraint \"job_runs_pkey\"" } };
          made.push(r);
        }
        made.forEach((r) => all.push(r));
        return shape(made);
      }
      if (q.op === "update") { const hit = all.filter(match); hit.forEach((r) => Object.assign(r, q.payload)); return shape(hit); }
      if (q.op === "delete") { const hit = all.filter(match); t[name] = all.filter((r) => hit.indexOf(r) === -1); return shape(hit); }
      return { data: null, error: { message: "fake: no op " + q.op } };
    }
    return api;
  }
  return { from, t, rpc: async () => ({ data: null, error: null }) };
}

const NOW = Date.parse("2026-11-20T04:45:00.000Z");
const DAY = 24 * 60 * 60 * 1000;
const iso = (ms) => new Date(ms).toISOString();
const ME = "00000000-0000-4000-8000-0000000000a1";
const OTHER = "00000000-0000-4000-8000-0000000000b2";
const CHANNEL = "UCabcdefghijklmnopqrstuv";
const OTHER_CHANNEL = "UCzyxwvutsrqponmlkjihgfe";
const YT_ID = "Ab3_x-9Kq2Z";
const OWNER_ID = require("../lib/ownerAccount").OWNER_ACCOUNT_ID;

/* Sealing for the fake: reversible, never the plain text in a row. */
const CRYPT = {
  encrypt(p) { return { ciphertext: Buffer.from(String(p), "utf8").toString("hex"), iv: "0".repeat(24), authTag: "0".repeat(32) }; },
  decrypt(x) { return Buffer.from(String(x.ciphertext), "hex").toString("utf8"); }
};

/* Google's token and revoke endpoints, stubbed on lib/googleAuth.js deps.request. GRANTS: refresh token -> ok | invalid_grant | down. */
const GOOGLE = { calls: [], grants: {} };
GA.deps.request = async function (url, options) {
  const form = (options && options.form) || {};
  GOOGLE.calls.push({ url: url, form: Object.assign({}, form) });
  if (url === GA.REVOKE_URL) return { status: 200, json: null };
  if (url === GA.TOKEN_URL) {
    const how = GOOGLE.grants[form.refresh_token] || "ok";
    if (how === "invalid_grant") return { status: 400, json: { error: "invalid_grant" } };
    if (how === "down") return { status: 503, json: { error: "unavailable" } };
    return { status: 200, json: { access_token: "fresh-access-" + form.refresh_token, expires_in: 3600, scope: GA.SCOPE } };
  }
  return { status: 404, json: null };
};
/* YouTube's channels.list, on deps.jsonRequest. */
const YOUTUBE = { calls: [], title: "Maple Street Bakery Renamed", id: CHANNEL };
async function youtubeRequest(url) {
  YOUTUBE.calls.push(url);
  if (url.indexOf("/channels?") !== -1) return { status: 200, json: { items: [{ id: YOUTUBE.id, snippet: { title: YOUTUBE.title } }] } };
  return { status: 404, json: null };
}
function ytDeps(db) {
  return { supabase: db, storage: null, crypt: CRYPT, jsonRequest: youtubeRequest, streamUpload: null, now: () => NOW,
    config: () => ({ clientId: "check-client", clientSecret: "check-secret" }), limits: {}, claims: () => null, env: {} };
}
function connRow(user, refresh, over) {
  const r = CRYPT.encrypt(refresh), a = CRYPT.encrypt("access-" + refresh);
  return Object.assign({ id: "conn-" + user.slice(-2) + "-" + refresh, user_id: user, channel_id: CHANNEL, channel_title: "Maple Street Bakery",
    refresh_ciphertext: r.ciphertext, refresh_iv: r.iv, refresh_auth_tag: r.authTag, access_ciphertext: a.ciphertext, access_iv: a.iv, access_auth_tag: a.authTag,
    access_expires_at: iso(NOW + 50 * 60 * 1000), token_version: 0, granted_scopes: GA.SCOPE, status: "connected",
    last_ok_at: iso(NOW - 2 * DAY), created_at: iso(NOW - 40 * DAY), updated_at: iso(NOW - 2 * DAY) }, over || {});
}

/* ── the server's own code, lifted ─────────────────────────────────────── */
function lift(src, signature) {
  const start = src.indexOf(signature);
  if (start === -1) return null;
  const end = MUT.braceMatch(src, src.indexOf("{", start + signature.length - 1));
  return end === -1 ? null : src.slice(start, end);
}
function liftRoute(src, signature) {
  const code = lift(src, signature);
  if (!code) return null;
  const tail = src.slice(src.indexOf(signature) + code.length, src.indexOf(signature) + code.length + 2);
  return tail === ");" ? code + ");" : null;
}
function mountRoute(code, ctxExtra) {
  const routes = {};
  const ctx = Object.assign({ console: console, Object: Object, Date: Date, JSON: JSON, Promise: Promise, Error: Error, String: String, Number: Number }, ctxExtra);
  ctx.app = {};
  ["get", "post", "put", "delete"].forEach((m) => { ctx.app[m] = function (p) { const a = [].slice.call(arguments, 1); routes[m + " " + p] = { middleware: a.slice(0, -1), handler: a[a.length - 1] }; }; });
  vm.createContext(ctx);
  vm.runInContext(code, ctx, { filename: "server.js (lifted)" });
  return routes;
}
function fakeRes() {
  return { statusCode: 200, body: undefined, headers: {}, set(k, v) { this.headers[k] = v; return this; }, status(c) { this.statusCode = c; return this; },
    json(b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
}
/* Runs a route's middleware in order, as Express does, then its handler. */
async function callRoute(route, req) {
  const res = fakeRes();
  let err = null;
  for (const mw of route.middleware) {
    let nexted = false;
    await mw(req, res, function (e) { if (e) err = e; nexted = true; });
    if (!nexted || err) return { status: res.statusCode, body: res.body || {}, err: err, stoppedAt: mw.name };
  }
  await route.handler(req, res, function (e) { err = e || new Error("next"); });
  return { status: res.statusCode, body: res.body || {}, err: err };
}

/* The real sendEmail and markSendFailed, run against the fake database and a fake Resend that records each message. */
const RESEND_SENT = [];
function realSendEmail(db) {
  const code = [lift(FILES.server, "async function sendEmail(options) {"), lift(FILES.server, "async function markSendFailed(sendRowId, message) {")];
  if (code.some((c) => !c)) return null;
  const ctx = {
    supabase: db, console: console, process: { env: { RESEND_API_KEY: "re_check_key" } }, nowIso: () => iso(NOW),
    Resend: function () { this.emails = { send: async function (m) { RESEND_SENT.push(m); return { data: { id: "re_" + RESEND_SENT.length } }; } }; },
    emailUnsubscribeUrl: () => "https://bizforceai.net/unsubscribe?token=check", emailConsentGranted: async () => false,
    require: (r) => (r === "./lib/legal" ? LEGAL : require(r)), String: String, Object: Object
  };
  vm.createContext(ctx);
  vm.runInContext(code.join("\n") + "\nthis.sendEmail = sendEmail;", ctx, { filename: "server.js (sendEmail)" });
  return ctx.sendEmail;
}
function mailDeps(db, sendEmail) {
  return { supabase: db, sendEmail: sendEmail, contactFor: async (userId) => "contact-" + userId, now: () => NOW,
    facts: RE.factsFrom({ name: "All Access", price: 199, interval: "month" }, "https://bizforceai.net") };
}
function ledger(db, prefix) { return (db.t.email_sends || []).filter((r) => String(r.template).indexOf(prefix) === 0); }

async function main() {
  OUT("checkLegalL1" + (MUTATE ? " (MUTATE=" + MUTATE + ")" : ""));

  /* ══ A. the legal text ══ */
  OUT("\n== A. the legal text ==");
  const facts = LP.codeFacts();
  const built = LP.buildLegalPages(facts);
  const P = built["privacy.html"], T = built["terms.html"];
  const PT = textOf(P), TT = textOf(T);
  const s9 = between(P, "<h2 id=\"youtube\">", "<h2 id=\"changes\">");
  const partA = between(s9, "<h3 id=\"youtube-connect\">", "<h3 id=\"youtube-radar\">");
  const partB = s9.slice(s9.indexOf("<h3 id=\"youtube-radar\">"));
  const LIMITED = "BizForce's use and transfer to any other app of information received from Google APIs will adhere to the Google API Services User Data Policy " +
    "(https://developers.google.com/terms/api-services-user-data-policy), including the Limited Use requirements.";
  check("A1. section 9 is \"9. Google and YouTube\", in two parts: Connect YouTube, then Lead Radar", s9.indexOf("9. Google and YouTube</h2>") !== -1 &&
    partA.indexOf("Connect YouTube (your own channel)") !== -1 && partB.indexOf("Lead Radar (public YouTube comments)") !== -1);
  check("A2. part A carries Google's Limited Use sentence word for word, its address a link", textOf(partA).indexOf(LIMITED) !== -1 &&
    partA.indexOf("(<a href=\"https://developers.google.com/terms/api-services-user-data-policy\">https://developers.google.com/terms/api-services-user-data-policy</a>)") !== -1);
  check("A3. part A links the revoke page, https://security.google.com/settings/security/permissions",
    partA.indexOf("<a href=\"https://security.google.com/settings/security/permissions\">https://security.google.com/settings/security/permissions</a>") !== -1 &&
    textOf(partA).indexOf("choose Disconnect on the Social Agent page in BizForce, or remove BizForce from your Google Account at https://security.google.com/settings/security/permissions.") !== -1);
  check("A4. part A says BizForce uses YouTube API Services and links Google's Privacy Policy", textOf(partA).indexOf("BizForce uses YouTube API Services.") !== -1 &&
    partA.indexOf("<a href=\"https://policies.google.com/privacy\">https://policies.google.com/privacy</a>") !== -1);
  check("A5. part A names the two permissions in plain words, and lib/googleAuth.js asks for exactly those two scopes",
    textOf(partA).indexOf("read-only access (Google lists it as \"View your YouTube account\")") !== -1 && textOf(partA).indexOf("upload access (\"Manage your YouTube videos\")") !== -1 &&
    GA.SCOPE === "https://www.googleapis.com/auth/youtube.upload https://www.googleapis.com/auth/youtube.readonly", GA.SCOPE);
  const nums = "every " + YA.CHANNEL_REFRESH_DAYS + " days, and deletes the connection if it cannot be refreshed for " + YA.AUTHORIZED_DATA_DAYS + " days";
  check("A6. part A's figures are lib/youtubeApi.js's (" + YA.CHANNEL_REFRESH_DAYS + ", " + YA.AUTHORIZED_DATA_DAYS + ", " + YA.DISCONNECT_PROMISE_DAYS + " days)",
    textOf(partA).indexOf(nums) !== -1 && textOf(partA).indexOf("After a disconnect, BizForce deletes the stored YouTube data within " + YA.DISCONNECT_PROMISE_DAYS +
      " days; after a removal on Google's side, within " + YA.AUTHORIZED_DATA_DAYS + " days.") !== -1);
  check("A7. part A: how it is used, never for ads, sale or AI training; shared only with Google and YouTube; never exported; the support address",
    ["not used for advertising, not sold, not used to train AI models, and not read by people except with your permission, for security, or where the law requires.",
      "Shared with: only Google and YouTube, to carry out what you approve.", "The access Google grants is never shown back to you or exported.",
      "Questions: write to " + LEGAL.CONTACT_EMAIL + "."].every((x) => textOf(partA).indexOf(x) !== -1));
  check("A8. the false sentence is gone; part B says \"Lead Radar does not use any member's YouTube or Google account.\"",
    PT.indexOf("does not sign in to anyone's YouTube or Google account") === -1 && textOf(partB).indexOf("Lead Radar does not use any member's YouTube or Google account.") !== -1);
  check("A9. Terms section 7 carries the YouTube Terms clause, its address a link",
    textOf(between(T, "<h2 id=\"content\">", "<h2 id=\"bizcash\">")).indexOf("If you use BizForce's YouTube features, you agree to be bound by the YouTube Terms of Service (https://www.youtube.com/t/terms).") !== -1 &&
    T.indexOf("(<a href=\"https://www.youtube.com/t/terms\">https://www.youtube.com/t/terms</a>)") !== -1);
  const s7 = textOf(between(P, "<h2 id=\"rights\">", "<h2 id=\"children\">"));
  check("A10. Privacy section 7 has the Do Not Track and Global Privacy Control paragraph", s7.indexOf("Do Not Track and Global Privacy Control: BizForce does not sell or share your personal information or track you across other sites, so there is nothing for these signals to switch off.") !== -1 &&
    s7.indexOf("when your browser sends one (Sec-GPC: 1), nothing changes, because nothing is sold or shared.") !== -1);
  const srv = FILES.server.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
  check("A11. ...and that is true in code: no route reads Sec-GPC or DNT, and the no_sale protection says no tracker is loaded",
    !/sec-gpc|["']dnt["']/i.test(srv) && YD.PROTECTIONS.some((p) => p.key === "no_sale" && p.text.indexOf("no page loads a tracker") !== -1));
  const s6 = textOf(between(P, "<h2 id=\"retention\">", "<h2 id=\"rights\">"));
  const bk = read("lib/backup.js");
  check("A12. Privacy section 6 states the real backup retention (emailed, no other copy, not deleted automatically), not \"until they are deleted\"",
    s6.indexOf("each one is encrypted and emailed to the owner's own mailbox; BizForce keeps no other copy and does not delete them automatically") !== -1 &&
    s6.indexOf("still contain your data until they are deleted") === -1 && /var toEmail = \(env\.BACKUP_EMAIL_TO \|\| ""\)\.trim\(\);/.test(bk) &&
    !/storage\.from\(|\.upload\(/.test(bk));
  check("A13. \"card order\" is gone from the settings line, and the agent card order is named", PT.indexOf("card order") === -1 &&
    YD.DATA.filter((d) => d.table === "user_preferences")[0].what.indexOf("the order of your agent cards") !== -1);
  check("A14. Privacy section 3 says the YouTube and Vimeo players may set their own cookies", textOf(between(P, "<h2 id=\"share\">", "<h2 id=\"protect\">"))
    .indexOf("The YouTube and Vimeo video players on storefronts may set their own cookies when a video plays.") !== -1);
  const t3 = textOf(between(T, "<h2 id=\"subscription\">", "<h2 id=\"refunds\">"));
  check("A15. Terms section 3: the price-change email " + RE.PRICE_NOTICE_MIN_DAYS + " to " + RE.PRICE_NOTICE_MAX_DAYS + " days ahead (the route's window) and the yearly reminder",
    t3.indexOf("If we raise the price, we will email you " + RE.PRICE_NOTICE_MIN_DAYS + " to " + RE.PRICE_NOTICE_MAX_DAYS + " days before the new price applies, with how to cancel, and you can cancel before then.") !== -1 &&
    t3.indexOf("Each year we email you a reminder of your plan, its price and how to cancel.") !== -1 && t3.indexOf("we will tell you before the new price applies") === -1);
  check("A16. Terms section 15 and Privacy section 10 say the change is also emailed", textOf(between(T, "<h2 id=\"changes\">", "<h2 id=\"contact\">")).indexOf(LP.TERMS_CHANGE_EMAIL_SENTENCE) !== -1 &&
    textOf(between(P, "<h2 id=\"changes\">", "<h2 id=\"contact\">")).indexOf(LP.TERMS_CHANGE_EMAIL_SENTENCE) !== -1);
  check("A17. TERMS_VERSION 2026-11-14, \"Last updated November 14, 2026\", and the CHANGE_SUMMARY word for word", LEGAL.TERMS_VERSION === "2026-11-14" &&
    LEGAL.TERMS_UPDATED === "Last updated November 14, 2026" && LEGAL.CHANGE_SUMMARY === "We added how BizForce handles your YouTube and Google data, yearly and price-change reminders for your subscription, and how we answer Do Not Track and Global Privacy Control.");
  const pagesEqual = ["terms.html", "privacy.html", "refund.html", "contact.html"].filter((f) => lf(readFe(f)) !== lf(built[f]));
  check("A18. the four frontend pages equal what these sources build", pagesEqual.length === 0, pagesEqual.join(", "));

  /* ══ B. the embeds ══ */
  OUT("\n== B. the embeds ==");
  const embedSrc = between(FILES.profile, "function getEmbedSrc(v) {", "\n}\n");
  check("B1. profile.html plays YouTube from https://www.youtube-nocookie.com/embed/ and Vimeo with dnt=1", embedSrc.indexOf("\"https://www.youtube-nocookie.com/embed/\"+id") !== -1 &&
    embedSrc.indexOf("\"https://player.vimeo.com/video/\"+id+\"?autoplay=1&dnt=1\"") !== -1);
  const card = between(FILES.seller, "function renderVideoCard(v) {", "\n}\n");
  check("B2. seller.html does the same", card.indexOf("'<iframe src=\"https://www.youtube-nocookie.com/embed/' + esc(yt) + '\"") !== -1 &&
    card.indexOf("'<iframe src=\"https://player.vimeo.com/video/' + esc(vm) + '?dnt=1\"") !== -1);
  check("B3. no page embeds a youtube.com player any more", [FILES.profile, FILES.seller].every((s) => s.indexOf("www.youtube.com/embed") === -1));
  const ps = YD.PAGE_SERVICES.filter((s) => s.name === "YouTube and Vimeo")[0];
  check("B4. PAGE_SERVICES names the hosts the pages use: www.youtube-nocookie.com and player.vimeo.com", ps && J(ps.hosts) === J(["www.youtube-nocookie.com", "player.vimeo.com"]), ps && J(ps.hosts));
  const headers = readFe("_headers");
  const frame = (/frame-src (https:[^;]+);/.exec(headers) || [])[1] || "";
  check("B5. the CSP's frame-src swaps www.youtube.com for www.youtube-nocookie.com and allows nothing more", frame === "https://www.youtube-nocookie.com https://player.vimeo.com", frame);

  /* ══ C. the YouTube data rules ══ */
  OUT("\n== C. the YouTube data rules ==");
  {
    const db = makeDb({
      member_youtube_connections: [connRow(ME, "refresh-me"), connRow(OTHER, "refresh-other", { channel_id: OTHER_CHANNEL })],
      member_videos: [
        { id: "v1", user_id: ME, status: "uploaded", youtube_video_id: YT_ID, uploaded_at: iso(NOW - DAY), session_ciphertext: null, session_iv: null, session_auth_tag: null, created_at: iso(NOW - 3 * DAY) },
        { id: "v2", user_id: ME, status: "ready", youtube_video_id: null, uploaded_at: null, session_ciphertext: "ab", session_iv: "0".repeat(24), session_auth_tag: "0".repeat(32), created_at: iso(NOW - DAY) },
        { id: "v3", user_id: OTHER, status: "uploaded", youtube_video_id: YT_ID, uploaded_at: iso(NOW - DAY), created_at: iso(NOW - 3 * DAY) }],
      agent_proposals: [
        { id: "p1", user_id: ME, action_type: "publish_youtube_video", status: "pending", payload: { channel_id: CHANNEL } },
        { id: "p2", user_id: ME, action_type: "delete_youtube_video", status: "executed", payload: { channel_id: CHANNEL } },
        { id: "p3", user_id: ME, action_type: "publish_youtube_video", status: "executing", payload: { channel_id: CHANNEL } },
        { id: "p4", user_id: ME, action_type: "publish_bluesky_post", status: "pending", payload: {} },
        { id: "p5", user_id: OTHER, action_type: "publish_youtube_video", status: "pending", payload: { channel_id: OTHER_CHANNEL } }],
      notifications: [{ id: "n1", user_id: ME, type: "youtube_reconnect", message: "old" }, { id: "n2", user_id: ME, type: "welcome", message: "hi" },
        { id: "n3", user_id: OTHER, type: "youtube_reconnect", message: "theirs" }],
      oauth_states: [{ id: "s1", user_id: ME, purpose: "youtube_google" }, { id: "s2", user_id: ME, purpose: "store_shopify" }],
      youtube_api_calls: [{ id: 1, user_id: ME, created_on: "2026-11-19", caller: "social_search", units: 100 }]
    });
    const code = liftRoute(FILES.server, "app.post(\"/api/youtube/disconnect\", requireAuth, async function (req, res, next) {");
    let routes = {};
    try {
      routes = code ? mountRoute(code, { supabase: db, youtubeDeps: () => ytDeps(db), requireAuth: function requireAuth(q, s, n) { n(); },
        process: { env: { GOOGLE_OAUTH_CLIENT_ID: "check-client", GOOGLE_OAUTH_CLIENT_SECRET: "check-secret" } },
        require: (r) => (r === "./lib/googleAuth" ? GA : r === "./lib/youtubeApi" ? YA : r === "./lib/apiKeyCrypto" ? CRYPT : require(r)) }) : {};
    } catch (e) { OUT("    (disconnect route did not mount: " + e.message + ")"); }
    const route = routes["post /api/youtube/disconnect"];
    GOOGLE.calls.length = 0;
    const r = route ? await callRoute(route, { user: { id: ME }, body: {} }) : { status: 0, body: {} };
    const t = db.t;
    check("C1. disconnect answers 200, removed and revoked", r.status === 200 && r.body.removed === true && r.body.revoked === true, J([r.status, r.body.removed, r.body.revoked, r.err && r.err.message]));
    check("C2. ...revoking at Google first, with the stored refresh token", GOOGLE.calls.length === 1 && GOOGLE.calls[0].url === GA.REVOKE_URL && GOOGLE.calls[0].form.token === "refresh-me");
    check("C3. ...and deletes the connection, this sign-in's states and the YouTube reconnect notices at once",
      !t.member_youtube_connections.some((c) => c.user_id === ME) && !t.oauth_states.some((s) => s.purpose === "youtube_google") &&
      t.oauth_states.some((s) => s.purpose === "store_shopify") && !t.notifications.some((n) => n.user_id === ME && n.type === "youtube_reconnect") &&
      t.notifications.some((n) => n.id === "n2"));
    const v1 = t.member_videos.filter((v) => v.id === "v1")[0], v2 = t.member_videos.filter((v) => v.id === "v2")[0];
    check("C4. ...clears every video's YouTube id, upload time and sealed session", v1.youtube_video_id === null && v1.uploaded_at === null &&
      v2.session_ciphertext === null && v2.session_iv === null && v2.session_auth_tag === null, J([v1, v2]));
    check("C5. ...deletes the YouTube proposals but one executing, and nothing else", J(t.agent_proposals.map((p) => p.id).sort()) === J(["p3", "p4", "p5"]),
      J(t.agent_proposals.map((p) => p.id)));
    check("C6. ...keeps the quota ledger and every row of another member", t.youtube_api_calls.length === 1 && t.member_youtube_connections.some((c) => c.user_id === OTHER) &&
      t.member_videos.filter((v) => v.id === "v3")[0].youtube_video_id === YT_ID && t.notifications.some((n) => n.id === "n3"));
    check("C7. ...and says what it deleted", J(r.body.youtube_data_deleted) === J({ videos: 2, proposals: 2, notices: 1 }), J(r.body.youtube_data_deleted));
  }
  {
    // A refused grant: the connection and its data are deleted with ONE notice, and the next day sends none.
    const seedNote = { id: "n9", user_id: OTHER, type: "youtube_reconnect", message: "sent when it was marked" };
    const db = makeDb({
      member_youtube_connections: [connRow(ME, "revoked-me"), connRow(OTHER, "revoked-other", { status: "needs_reconnect", channel_id: OTHER_CHANNEL })],
      member_videos: [{ id: "v1", user_id: ME, status: "uploaded", youtube_video_id: YT_ID, uploaded_at: iso(NOW - DAY), created_at: iso(NOW - 3 * DAY) }],
      agent_proposals: [{ id: "p1", user_id: ME, action_type: "publish_youtube_video", status: "pending", payload: { channel_id: CHANNEL }, created_at: iso(NOW - DAY) }],
      notifications: [seedNote], job_runs: []
    });
    GOOGLE.grants["revoked-me"] = "invalid_grant"; GOOGLE.grants["revoked-other"] = "invalid_grant";
    const out = await YA.youtubeDataTick(ytDeps(db), NOW);
    const notesMe = db.t.notifications.filter((n) => n.user_id === ME && n.type === "youtube_reconnect");
    check("C8. the daily pass deletes a connection Google refuses (invalid_grant), with its videos' YouTube ids and its proposals",
      out.claimed === true && db.t.member_youtube_connections.length === 0 && db.t.member_videos[0].youtube_video_id === null && db.t.agent_proposals.length === 0 && out.refused === 2, J(out));
    check("C9. ...the member gets ONE notice to reconnect, and one already told gets no second", notesMe.length === 1 &&
      db.t.notifications.filter((n) => n.user_id === OTHER).length === 1, J(db.t.notifications.map((n) => n.user_id.slice(-2) + ":" + n.type)));
    check("C10. ...the notice names no channel (no data from Google kept in it)", notesMe.length === 1 && notesMe[0].message.indexOf("Maple Street") === -1 &&
      notesMe[0].message.indexOf("your YouTube channel") !== -1, notesMe[0] && notesMe[0].message);
    const again = await YA.youtubeDataTick(ytDeps(db), NOW + 60 * 1000);
    const nextDay = await YA.youtubeDataTick(ytDeps(db), NOW + DAY);
    check("C11. ...claimed once a day through job_runs youtube_data_check; the next day finds nothing and sends no notice", again.claimed === false && nextDay.claimed === true &&
      nextDay.refused === 0 && db.t.notifications.filter((n) => n.user_id === ME).length === 1 &&
      db.t.job_runs.filter((j) => j.job_name === "youtube_data_check").length === 1, J([again, nextDay]));
  }
  {
    // The refresh and the 30-day rules.
    const db = makeDb({
      member_youtube_connections: [
        connRow(ME, "fine-me", { last_ok_at: iso(NOW - 10 * DAY) }),
        connRow(OTHER, "down-old", { channel_id: OTHER_CHANNEL, last_ok_at: iso(NOW - 31 * DAY) }),
        connRow("00000000-0000-4000-8000-0000000000c3", "down-young", { channel_id: OTHER_CHANNEL, last_ok_at: iso(NOW - 20 * DAY) })],
      member_videos: [
        { id: "old", user_id: ME, status: "uploaded", youtube_video_id: YT_ID, uploaded_at: iso(NOW - 31 * DAY), created_at: iso(NOW - 32 * DAY) },
        { id: "new", user_id: ME, status: "uploaded", youtube_video_id: YT_ID, uploaded_at: iso(NOW - 10 * DAY), created_at: iso(NOW - 11 * DAY) },
        { id: "sess", user_id: ME, status: "ready", youtube_video_id: null, session_ciphertext: "ab", session_iv: "0".repeat(24), session_auth_tag: "0".repeat(32), created_at: iso(NOW - 31 * DAY) }],
      agent_proposals: [
        { id: "pold", user_id: ME, action_type: "publish_youtube_video", status: "executed", created_at: iso(NOW - 31 * DAY) },
        { id: "pnew", user_id: ME, action_type: "publish_youtube_video", status: "pending", created_at: iso(NOW - 5 * DAY) },
        { id: "prun", user_id: ME, action_type: "publish_youtube_video", status: "executing", created_at: iso(NOW - 31 * DAY) }],
      notifications: [], job_runs: [], youtube_api_calls: []
    });
    GOOGLE.grants["down-old"] = "down"; GOOGLE.grants["down-young"] = "down";
    YOUTUBE.calls.length = 0;
    const out = await YA.youtubeDataTick(ytDeps(db), NOW);
    const mine = db.t.member_youtube_connections.filter((c) => c.user_id === ME)[0];
    check("C12. a working connection gets a fresh token and its channel name read again from YouTube (" + YA.CHANNEL_REFRESH_DAYS + " days old), the quota reserved first",
      mine && mine.channel_title === YOUTUBE.title && mine.last_ok_at === iso(NOW) && YOUTUBE.calls.length === 1 &&
      db.t.youtube_api_calls.length === 1 && db.t.youtube_api_calls[0].units === 1 && mine.token_version === 1, J([out, mine && mine.channel_title, YOUTUBE.calls.length]));
    check("C13. a connection that cannot be refreshed is deleted at " + YA.AUTHORIZED_DATA_DAYS + " days without a refresh, and kept before that",
      !db.t.member_youtube_connections.some((c) => c.user_id === OTHER) && db.t.member_youtube_connections.some((c) => c.user_id.slice(-2) === "c3"), J(out));
    const vid = (id) => db.t.member_videos.filter((v) => v.id === id)[0];
    check("C14. a video's YouTube id is cleared " + YA.AUTHORIZED_DATA_DAYS + " days after its upload, a newer one kept; an old unfinished session cleared",
      vid("old").youtube_video_id === null && vid("new").youtube_video_id === YT_ID && vid("sess").session_ciphertext === null);
    check("C15. a YouTube proposal is deleted " + YA.AUTHORIZED_DATA_DAYS + " days after it was filed, never while executing", J(db.t.agent_proposals.map((p) => p.id).sort()) === J(["pnew", "prun"]),
      J(db.t.agent_proposals.map((p) => p.id)));
  }
  const chain = /cron\.schedule\("45 4 \* \* \*"[\s\S]*?\.then\(facebookChoosingPurgeTick\)\.then\(youtubeDataCheckTick\)\.then\(renewalEmailsTick\);/.test(FILES.server);
  check("C16. the 04:45 UTC chain runs youtubeDataCheckTick after Facebook's cleanup, then renewalEmailsTick, last", chain &&
    /async function youtubeDataCheckTick\(\) \{\n  try \{\n    return await require\("\.\/lib\/youtubeApi"\)\.youtubeDataTick\(youtubeDeps\(\)\);/.test(FILES.server));

  /* ══ D. the emails ══ */
  OUT("\n== D. the emails ==");
  const F = RE.factsFrom({ name: "All Access", price: 199, interval: "month" }, "https://bizforceai.net");
  const conf = RE.confirmationEmail(F);
  check("D1. the confirmation states the plan, $199, every month, automatic renewal until cancelled, how to cancel online, the refund policy, the Terms and Refunds links",
    ["Your plan: All Access, $199 every month.", "It renews automatically every month", "until you cancel.", "open Billing, and choose \"Manage / Cancel Subscription\"",
      "Billing: https://bizforceai.net/billing.html", "Refunds: " + LEGAL.REFUND_POLICY.join(" "), "Terms of Service: https://bizforceai.net/terms",
      "Refund policy: https://bizforceai.net/refund"].every((x) => conf.text.indexOf(x) !== -1) && conf.html.indexOf("<a href=\"https://bizforceai.net/refund\">") !== -1, conf.text);
  const yearlyMail = RE.yearlyEmail(F);
  check("D2. the yearly reminder states the same facts", yearlyMail.text.indexOf("This is your yearly reminder") !== -1 &&
    ["Your plan: All Access, $199 every month.", "Manage / Cancel Subscription", "Terms of Service: https://bizforceai.net/terms"].every((x) => yearlyMail.text.indexOf(x) !== -1));
  const tc = RE.termsChangeEmail(F);
  check("D3. the terms-change email: the version, what changed (CHANGE_SUMMARY), the Terms and Privacy links", tc.text.indexOf("November 14, 2026 (version 2026-11-14)") !== -1 &&
    tc.text.indexOf("What changed: " + LEGAL.CHANGE_SUMMARY) !== -1 && tc.text.indexOf("Terms of Service: https://bizforceai.net/terms") !== -1 &&
    tc.text.indexOf("Privacy Policy: https://bizforceai.net/privacy") !== -1);

  // Through the REAL sendEmail: the ledger row, the contact footer and the postal address.
  const db = makeDb({
    users: [{ id: ME, email: "member.one@example.invalid", role: "user", terms_version: "2026-11-08" }],
    subscriptions: [], email_sends: [], job_runs: []
  });
  const send = realSendEmail(db);
  const deps = mailDeps(db, send || (async () => ({ sent: false, reason: "no sendEmail" })));
  const c1 = await RE.sendConfirmation(deps, ME, "sub_check_1");
  const c2 = await RE.sendConfirmation(deps, ME, "sub_check_1");
  const both = await Promise.all([RE.sendConfirmation(deps, ME, "sub_check_2"), RE.sendConfirmation(deps, ME, "sub_check_2")]);
  check("D4. the confirmation is sent once per subscription: a redelivery and two at once send nothing more", c1.sent === true && c2.sent === false && c2.reason === "already_sent" &&
    both.filter((b) => b.sent).length === 1 && ledger(db, "account:renewal_confirmation:").length === 2, J([c1, c2, both]));
  const row = ledger(db, "account:renewal_confirmation:sub_check_1")[0] || {};
  const msg = RESEND_SENT[0] || {};
  check("D5. ...through the real sendEmail: an email_sends row with the occasion's template, sent, never marketing", row.status === "sent" && row.contact_id === "contact-" + ME &&
    String(row.template).indexOf("marketing:") === -1, J(row));
  check("D6. ...ending with the contact footer: the contact address and the postal address, in both bodies",
    String(msg.text).indexOf(LEGAL.POSTAL_ADDRESS) !== -1 && String(msg.html).indexOf(LEGAL.escapeHtml(LEGAL.POSTAL_ADDRESS)) !== -1 &&
    String(msg.text).indexOf("Questions? Write to " + LEGAL.CONTACT_EMAIL + ".") !== -1);
  const hook = between(FILES.server, "async function handleStripeEvent(event) {", "    // Recorded here rather than at the end of the branch.");
  check("D7. the Stripe webhook sends it on checkout.session.completed, after the subscription row is active, logged and never thrown",
    /const \{ error: subscriptionError \} = await supabase\.from\("subscriptions"\)\.upsert\([\s\S]*?status: "active"[\s\S]*?try \{\n        await require\("\.\/lib\/renewalEmails"\)\.sendConfirmation\(renewalEmailDeps\(\), userId, session\.subscription \|\| null\);\n      \} catch \(confirmErr\) \{/.test(hook));

  // The yearly reminder.
  db.t.users.push({ id: OTHER, email: "member.two@example.invalid", role: "user", terms_version: "2026-11-14" },
    { id: "u-young", email: "young@example.invalid", role: "user" }, { id: "u-cancel", email: "cancel@example.invalid", role: "user" },
    { id: "u-two", email: "two@example.invalid", role: "user" },
    { id: "u-test", email: "harness-l1@bizforceai.invalid", role: "user" }, { id: OWNER_ID, email: "owner@example.invalid", role: "admin" });
  db.t.subscriptions.push({ user_id: ME, status: "active", cancel_at_period_end: false, created_at: iso(NOW - 366 * DAY) },
    { user_id: "u-young", status: "active", cancel_at_period_end: false, created_at: iso(NOW - 300 * DAY) },
    { user_id: "u-cancel", status: "active", cancel_at_period_end: true, created_at: iso(NOW - 400 * DAY) },
    { user_id: "u-two", status: "past_due", cancel_at_period_end: false, created_at: iso(NOW - 740 * DAY) },
    { user_id: OTHER, status: "canceled", cancel_at_period_end: false, created_at: iso(NOW - 400 * DAY) },
    { user_id: "u-test", status: "active", cancel_at_period_end: false, created_at: iso(NOW - 400 * DAY) },
    { user_id: OWNER_ID, status: "active", cancel_at_period_end: false, created_at: iso(NOW - 400 * DAY) });
  db.t.email_sends.push({ id: "old-y1", template: "account:renewal_yearly:u-two:1", status: "sent" });
  const y1 = await RE.yearlyReminderTick(deps, NOW);
  const y2 = await RE.yearlyReminderTick(deps, NOW + DAY);
  const y3 = await RE.yearlyReminderTick(deps, NOW + 2 * DAY);
  const yl = ledger(db, "account:renewal_yearly:").filter((r) => r.id !== "old-y1").map((r) => r.template).sort();
  check("D8. the yearly reminder goes once every 12 months from the start: year 1 for a 12-month subscription, year 2 for a 24-month one, none under 12 months, none when cancelling, none to a test account or the owner",
    y1.sent === 2 && J(yl) === J(["account:renewal_yearly:" + ME + ":1", "account:renewal_yearly:u-two:2"]), J([y1, yl]));
  check("D9. ...and only once: the next days send none", y2.sent === 0 && y3.sent === 0 && y2.already === 2, J([y2, y3]));
  const yMsg = RESEND_SENT.filter((m) => m.subject === "A yearly reminder about your BizForce AI subscription");
  check("D10. ...with the plan's facts and the postal address", yMsg.length === 2 && yMsg.every((m) => m.text.indexOf("Your plan: All Access, $199 every month.") !== -1 && m.text.indexOf(LEGAL.POSTAL_ADDRESS) !== -1));

  // The price-change notice: the window, once each, never Stripe.
  check("D11. the price notice window: 6 and 31 days refused, 7 and 30 accepted", !RE.priceNoticeWindow(iso(NOW + 6 * DAY).slice(0, 10), NOW).ok &&
    RE.priceNoticeWindow(iso(NOW + 7 * DAY).slice(0, 10), NOW).ok && RE.priceNoticeWindow(iso(NOW + 30 * DAY).slice(0, 10), NOW).ok &&
    !RE.priceNoticeWindow(iso(NOW + 31 * DAY).slice(0, 10), NOW).ok && !RE.priceNoticeWindow("2026-02-30", NOW).ok);
  const adminCode = liftRoute(FILES.server, "app.post(\"/api/admin/price-change-notice\", requireAuth,");
  const requireAdminCode = lift(FILES.server, "async function requireAdmin(req, res, next) {");
  let priceRoute = null;
  try {
    const r2 = adminCode && requireAdminCode ? mountRoute(requireAdminCode + "\n" + adminCode, { requireAuth: function requireAuth(q, s, n) { n(); },
      renewalEmailDeps: () => deps, require: (r) => (r === "./lib/renewalEmails" ? RE : require(r)), Date: { now: () => NOW } }) : {};
    priceRoute = r2["post /api/admin/price-change-notice"];
  } catch (e) { OUT("    (price route did not mount: " + e.message + ")"); }
  const before = RESEND_SENT.length;
  const soon = iso(NOW + 5 * DAY).slice(0, 10), ok = iso(NOW + 14 * DAY).slice(0, 10);
  const nonAdmin = priceRoute ? await callRoute(priceRoute, { user: { id: OTHER, role: "user" }, body: { new_price: 249, effective_date: ok } }) : { status: 0 };
  check("D12. the price route is owner only: a member who is not an admin gets 403 and nothing is sent", nonAdmin.status === 403 && RESEND_SENT.length === before, J([nonAdmin.status, RESEND_SENT.length - before]));
  const tooSoon = priceRoute ? await callRoute(priceRoute, { user: { id: ME, role: "admin" }, body: { new_price: 249, effective_date: soon } }) : { status: 0 };
  check("D13. a date fewer than 7 days away is refused (400) and nothing is sent", tooSoon.status === 400 && tooSoon.body.code === "window" && RESEND_SENT.length === before, J(tooSoon.body));
  const p1 = priceRoute ? await callRoute(priceRoute, { user: { id: ME, role: "admin" }, body: { new_price: 249, effective_date: ok } }) : { status: 0, body: {} };
  const p2 = priceRoute ? await callRoute(priceRoute, { user: { id: ME, role: "admin" }, body: { new_price: 249, effective_date: ok } }) : { status: 0, body: {} };
  const pMsg = RESEND_SENT.filter((m) => m.subject === "The price of your BizForce AI subscription is changing");
  check("D14. in the window, every billed subscriber is emailed once (active, trialing or past due; cancelled ones, test accounts and the owner not), and again sends none",
    p1.status === 200 && p1.body.sent === 4 && p1.body.not_customers === 2 && p2.body.sent === 0 && p2.body.already === 4 && pMsg.length === 4, J([p1.body, p2.body]));
  check("D15. ...it states the old and new price, the date and how to cancel, and never changes Stripe", pMsg.length > 0 &&
    pMsg[0].text.indexOf("from $199 to $249 every month, starting " + RE.longDate(ok) + ".") !== -1 && pMsg[0].text.indexOf("Manage / Cancel Subscription") !== -1 &&
    p1.body.stripe_price_changed === false && /This does not change any price in Stripe/.test(p1.body.note) && !/stripe\./.test(FILES.mail));

  // The terms-change email.
  const tdb = makeDb({ users: [
    { id: "t-old", email: "old@example.invalid", role: "user", terms_version: "2026-11-08" },
    { id: "t-null", email: "null@example.invalid", role: "user", terms_version: null },
    { id: "t-now", email: "now@example.invalid", role: "user", terms_version: "2026-11-14" },
    { id: "t-gone", email: "deleted-t-gone@deleted.invalid", role: "deleted", terms_version: null },
    { id: "t-test", email: "someone+bftest9@example.invalid", role: "user", terms_version: null }], email_sends: [], job_runs: [] });
  for (let i = 0; i < RE.TERMS_PER_RUN + 5; i++) tdb.t.users.push({ id: "t-many-" + String(i).padStart(3, "0"), email: "many" + i + "@example.invalid", role: "user", terms_version: "2026-10-01" });
  const tdeps = mailDeps(tdb, realSendEmail(tdb));
  const r1 = await RE.termsChangeTick(tdeps, NOW);
  const r1b = await RE.termsChangeTick(tdeps, NOW + 60 * 1000);
  const r2t = await RE.termsChangeTick(tdeps, NOW + DAY);
  const r3 = await RE.termsChangeTick(tdeps, NOW + 2 * DAY);
  const sentTo = ledger(tdb, "account:terms_change:2026-11-14:").map((r) => r.template.split(":").pop());
  check("D16. the terms-change email: at most " + RE.TERMS_PER_RUN + " a run, then the rest the next day, claimed once a day", r1.sent === RE.TERMS_PER_RUN && r1b.claimed === false &&
    r2t.sent === 7 && r3.sent === 0, J([r1.sent, r1b, r2t.sent, r3.sent]));
  check("D17. ...one per member per version: never twice, never to a member who already accepted it, never to a deleted account or a test account",
    sentTo.length === RE.TERMS_PER_RUN + 7 && new Set(sentTo).size === sentTo.length && sentTo.indexOf("t-now") === -1 && sentTo.indexOf("t-gone") === -1 && sentTo.indexOf("t-test") === -1 &&
    sentTo.indexOf("t-old") !== -1 && sentTo.indexOf("t-null") !== -1, J([sentTo.length, new Set(sentTo).size]));
  check("D18. every renewal and terms email is transactional: skipConsentCheck, an \"account:\" template, through sendEmail",
    (FILES.mail.match(/skipConsentCheck: true/g) || []).length === 1 && /var r = await deps\.sendEmail\(\{ contactId: contactId, to: email, subject: mail\.subject, html: mail\.html, text: mail\.text, template: template, skipConsentCheck: true \}\);/.test(FILES.mail) &&
    RE.TEMPLATE_PREFIX === "account:" && /sendEmail: sendEmail,\n    contactFor: findOrCreateUserContact,/.test(FILES.server));
  check("D19. nothing logged an email address", !LOGS.some((l) => /@example\.invalid|@deleted\.invalid/.test(l)), LOGS.filter((l) => /@/.test(l)).slice(0, 2).join(" | "));

  /* ══ E. consent records ══ */
  OUT("\n== E. consent records ==");
  {
    const user = { id: ME, email: "member.one@example.invalid", role: "user", password_hash: "hash", auto_renew_consent_at: "2026-10-27T10:00:00.000Z", auto_renew_consent_version: "2026-10-26" };
    const ddb = makeDb({ users: [user], profiles: [{ user_id: ME, username: "memberone" }], subscriptions: [{ user_id: ME, status: "canceled", created_at: iso(NOW - 60 * DAY) }] });
    const storage = { from: () => ({ list: async () => ({ data: [], error: null }), remove: async () => ({ data: [], error: null }) }) };
    let out;
    try {
      out = await YD.deleteAccount({ supabase: ddb, storage: storage, publicUrlBase: "https://check.supabase.co", userId: ME, body: { username: "memberone", password: "pw" },
        comparePassword: async () => true, activeSubscriptions: async () => [], ownerAccountId: "owner", now: new Date(NOW) });
    } catch (e) { out = { status: 599, body: { error: e.message } }; }
    const u = ddb.t.users[0];
    check("E1. account deletion keeps the automatic-renewal consent time and version on the kept account record", out && out.status === 200 && u.role === "deleted" &&
      u.auto_renew_consent_at === "2026-10-27T10:00:00.000Z" && u.auto_renew_consent_version === "2026-10-26", J([out && out.status, out && out.body && out.body.error, u.auto_renew_consent_at]));
    const usersEntry = YD.DATA.filter((d) => d.table === "users")[0], subsEntry = YD.DATA.filter((d) => d.table === "subscriptions")[0];
    check("E2. ...that record is never removed (tombstone), and the subscription record is kept", usersEntry.onDelete === "tombstone" && subsEntry.onDelete === "keep" &&
      ddb.t.users.length === 1 && ddb.t.subscriptions.length === 1 && !/from\("users"\)\.delete\(/.test(FILES.yourData));
  }

  check("Z. nothing opened a socket, asked DNS or fetched", TRIPPED.length === 0, TRIPPED.join(","));
  OUT("\n" + passes + " passed, " + failures + " failed");
  process.exit(failures ? 1 : 0);
}
main().catch((e) => { OUT("    FAIL  checkLegalL1 crashed: " + (e && e.stack)); process.exit(1); });
