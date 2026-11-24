"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkThreadsConnect (LR-2, NAMED Nov 23 2026). A member connects their OWN
   Threads account; Lead Radar searches with the member's own token and
   replies, from that account, only with text the member approved.

   lib/threadsAuth.js, lib/threadsApi.js and lib/threadsRoutes.js are compiled
   from memory in a vm (so MUTATE can edit them) and run for real against:
   a fake Express app (mountThreadsRoutes registers on it), an in-memory
   Supabase whose threads_connections enforces migration 204e's CHECK, the
   real lib/apiKeyCrypto.js under a check-only key, and a stub Meta that
   answers with the Threads documentation's own example bodies. Every socket
   and DNS lookup is a tripwire; no model is called; nothing is written to any
   database.

   WHAT THIS PROVES
     P. Migration 204e: the columns the code writes exist, and the CHECK
        fragments the stub enforces are the migration's.
     A. threadsAuth: configured needs BOTH env vars; the authorize URL and its
        four scopes; the signed state (round trip, tampered, expired, another
        app secret, not a member id); a nonce spent once; the callback query;
        the code exchange's form; th_exchange_token and th_refresh_token; no
        secret in any error; refreshDue.
     R. The four routes, their paths and their guards (connect M, callback P,
        status F, disconnect F); 503 "Threads is not set up yet" with code
        threads_not_set_up while either env var is missing.
     C. The callback: the short token is never stored, the long-lived one is
        sealed BEFORE Threads is asked who the account is; the row is the
        state's member's; replayed, tampered, expired, denied and mismatched
        answers store nothing and redirect to ?threads=error; no token, code
        or state in a log line or the redirect; a reconnect keeps
        keyword_search_state.
     S. Status and disconnect: the five states, never a token; only the
        caller's row is deleted.
     K. keywordSearch: RECENT, since clamped to 7 days, the Bearer header
        (never the token in a URL), the docs' example parsed; the member's own
        posts dropped and ownOnly when they were all of them; a permission
        error is the pre-approval state, not a throw; 190 and 429 throw;
        keywordSearchState's transitions.
     Y. replyTo: container with reply_to_id and the EXACT text, status wait,
        ONE publish, permalink; refusals send nothing; a publish of unknown
        outcome is never retried; a container in ERROR is never published.
     B. The search budget: 2,200 per 24 hours per member, sliding, separate
        per member, exhaustSearches.
     T. accessToken: expired and refused refreshes mark needs_reconnect; a due
        refresh stores a new sealed token; an unreachable refresh uses the old.
     F. The two tiles (integrations.html, agents/social.html): the same
        script, run in a fake DOM: 503 shows "Threads is not set up yet",
        own_posts_only shows "Waiting for Meta's approval", Connect follows
        only a threads.net URL, Disconnect, ?threads=connected|error;
        textContent only; the static integrations card states unchanged.
     Z. Zero network.

   MUTATE=<name> edits the source in memory (nothing on disk changes).
   MUTATE=all runs each in its own process and passes only if every one fails
   at least one check. A mutation whose search text does not match exactly
   once is an ERROR, never counted as caught.
   Run: node scripts/checkThreadsConnect.js
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const net = require("net");
const dns = require("dns");
const crypto = require("crypto");
const Module = require("module");
const MUT = require("./_shared");

/* ── the network tripwire, before anything can open a socket ──────────────── */
const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkThreadsConnect: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkThreadsConnect: no network"); };

const REPO = path.join(__dirname, "..");
const FE = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const read = (f) => fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n");
const readFe = (f) => fs.readFileSync(path.join(FE, f), "utf8").replace(/\r\n/g, "\n");

/* Each mutation is a list of edits: [file, search, replacement]. */
const MUTATIONS = {
  // sign-in
  "configured-one-var": [["auth", "  if (!id || !secret) return null;", "  if (!id) return null;"]],
  "scope-no-search": [["auth", "\"threads_basic\", \"threads_keyword_search\", \"threads_content_publish\"", "\"threads_basic\", \"threads_content_publish\""]],
  "scope-no-replies": [["auth", ", \"threads_manage_replies\"]", "]"]],
  "state-unsigned": [["auth", "  if (mac.length !== want.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(want))) return { ok: false };\n", ""]],
  "state-no-expiry": [["auth", "  if (p.e <= nowMs) return { ok: false };\n", ""]],
  "state-any-user": [["auth", "!UUID_RE.test(String(p.u)) || ", ""]],
  "nonce-reusable": [["auth", "  if (spentNonces.has(nonce)) return false;\n", ""]],
  "denied-accepted": [["auth", "  if (denied || !code ||", "  if (!code ||"]],
  "long-lived-grant": [["auth", "q.append(\"grant_type\", \"th_exchange_token\");", "q.append(\"grant_type\", \"ig_exchange_token\");"]],
  "refresh-grant": [["auth", "q.append(\"grant_type\", \"th_refresh_token\");", "q.append(\"grant_type\", \"ig_refresh_token\");"]],
  "exchange-no-redirect": [["auth", "      redirect_uri: redirect\n", "      redirect_uri: \"\"\n"]],
  "secret-in-error": [["auth", "    throw new ThreadsError(\"unreachable\", codeOnFail);\n", "    throw new ThreadsError(\"unreachable\", codeOnFail + \" \" + url);\n"]],
  "refresh-too-early": [["auth", "  return nowMs - stored >= REFRESH_MIN_AGE_MS;", "  return true;"]],
  // routes
  "connect-free": [["routes", "app.get(\"/api/social/threads/connect\", deps.requireAuth, deps.requireActiveSubscription, limiter,", "app.get(\"/api/social/threads/connect\", deps.requireAuth, limiter,"]],
  // NAMED (Nov 24 2026, LR-2B): the anchor now names the connect route; the same 503 line is in the three Meta routes too.
  "not-set-up-200": [["routes", "      if (!config) return res.status(503).json({ error: TA.MESSAGES.notSetUp, code: \"threads_not_set_up\" });\n      var state = TA.signState(", "      if (!config) return res.json({ url: null });\n      var state = TA.signState("]],
  "short-token-stored": [["routes", "        grant = await TA.longLived(config, short.shortToken);\n", "        grant = { accessToken: short.shortToken, expiresIn: 3600 };\n"]],
  "me-before-seal": [["routes", "      // Sealed first: the long-lived token is encrypted before Threads is asked anything.\n",
    "      await TAPI.readMe(grant.accessToken).catch(function () { return null; });\n      // Sealed first: the long-lived token is encrypted before Threads is asked anything.\n"]],
  "nonce-unspent": [["routes", "if (!st.ok || !TA.useNonce(st.nonce, st.expiresMs, nowMs)) return backTo(res, \"error\");", "if (!st.ok) return backTo(res, \"error\");"]],
  "me-mismatch-ok": [["routes", "      if (short.threadsUserId && short.threadsUserId !== me.threads_user_id) return backTo(res, \"error\");\n", ""]],
  "keyword-state-reset": [["routes", "        granted_scopes:    short.scopes || null,\n", "        granted_scopes:    short.scopes || null,\n        keyword_search_state: \"unknown\",\n"]],
  "redirect-elsewhere": [["routes", "\"/integrations.html?threads=\" + outcome", "\"/agents/social.html?threads=\" + outcome"]],
  "disconnect-any-row": [["routes", ".delete().eq(\"user_id\", req.user.id).select(\"id\");", ".delete().neq(\"user_id\", \"\").select(\"id\");"]],
  "status-leaks-row": [["routes", "      return res.json(TAPI.statusView(row, TA.configured(env) !== null, now()));", "      return res.json(Object.assign({}, row, TAPI.statusView(row, TA.configured(env) !== null, now())));"]],
  // search
  "search-top": [["api", "params.append(\"search_type\", \"RECENT\");", "params.append(\"search_type\", \"TOP\");"]],
  "since-unclamped": [["api", "  var ms = isFinite(asked) && asked > floor ? asked : floor;", "  var ms = isFinite(asked) ? asked : floor;"]],
  "token-in-url": [["api", "  var answer = await api(SEARCH_URL + \"?\" + params.toString(), { method: \"GET\", headers: bearer(token) });",
    "  params.append(\"access_token\", token);\n  var answer = await api(SEARCH_URL + \"?\" + params.toString(), { method: \"GET\" });"]],
  "own-posts-kept": [["api", "  var others = all.filter(function (p) { return !own || p.username.toLowerCase() !== own; });", "  var others = all;"]],
  "own-only-never": [["api", "ownOnly: all.length > 0 && others.length === 0 && !!own,", "ownOnly: false,"]],
  "permission-thrown": [["api", "    if (permissionRefused(answer) && !tokenRefused(answer)) return { posts: [], ownOnly: true, ownCount: 0, permission: true };\n", ""]],
  "approved-downgrades": [["api", "  if (result.ownOnly === true && prev !== \"approved\") return \"own_posts_only\";", "  if (result.ownOnly === true) return \"own_posts_only\";"]],
  "others-not-approved": [["api", "  if (Array.isArray(result.posts) && result.posts.length > 0) return \"approved\";\n", ""]],
  // replies
  "reply-no-target": [["api", "    reply_to_id: target\n", "    reply_to_id: \"\"\n"]],
  "reply-text-trimmed": [["api", "    text: text,\n    reply_to_id: target", "    text: text.trim(),\n    reply_to_id: target"]],
  "reply-empty-ok": [["api", "  if (typeof text !== \"string\" || text.trim().length === 0 || Array.from(text).length > TEXT_MAX) throw new ThreadsApiError(\"bad_input\", \"text\");", "  if (typeof text !== \"string\") throw new ThreadsApiError(\"bad_input\", \"text\");"]],
  "no-status-wait": [["api", "  await waitFinished(token, containerId);\n", ""]],
  "publish-retried": [["api", "    // It may have gone out: never sent again from here.\n    throw new ThreadsApiError(\"unknown_outcome\", \"publish_request\");",
    "    published = await deps.request(API_BASE + \"/\" + uid + \"/threads_publish\", { method: \"POST\", timeoutMs: API_TIMEOUT_MS, headers: bearer(token), form: { creation_id: containerId } });"]],
  "error-container-published": [["api", "    if (status === \"ERROR\" || status === \"EXPIRED\" || status === \"PUBLISHED\") throw", "    if (status === \"ERROR\" || status === \"EXPIRED\" || status === \"PUBLISHED\") return; if (false) throw"]],
  // budget and tokens
  "budget-limit": [["api", "const SEARCHES_PER_DAY = 2200;", "const SEARCHES_PER_DAY = 2201;"]],
  "budget-not-sliding": [["api", "return t > nowMs - BUDGET_WINDOW_MS && t <= nowMs;", "return t <= nowMs;"]],
  "budget-shared": [["api", "  var list = recent(String(userId), nowMs);\n  if (list.length >= SEARCHES_PER_DAY)", "  var list = recent(\"all\", nowMs);\n  if (list.length >= SEARCHES_PER_DAY)"]],
  "expired-used": [["api", "  if (!isFinite(ends) || ends <= nowMs) {\n    await markNeedsReconnect(ctx, row, \"expired\");", "  if (!isFinite(ends)) {\n    await markNeedsReconnect(ctx, row, \"expired\");"]],
  "refresh-unstored": [["api", "  var swapped = await ctx.supabase.from(\"threads_connections\").update(update)", "  var swapped = { error: null, data: [{ id: row.id }] }; (void update) || ctx.supabase.from(\"threads_connections\").update(update)"]],
  "waiting-is-ready": [["api", "  if (row.keyword_search_state === \"own_posts_only\") return \"waiting_approval\";\n", ""]],
  // the tiles
  "fe-social-503-silent": [["social", "        if (res.status === 503) { draw({ state: \"not_set_up\" }); tell(NOT_SET_UP, true); return; }", "        if (res.status === 503) { return; }"]],
  "fe-integrations-waiting-hidden": [["integrations", "      showIf(\"thWaiting\", state === \"waiting_approval\");", "      showIf(\"thWaiting\", false);"]],
  "fe-any-url": [["integrations", "url.indexOf(\"https://threads.net/oauth/authorize?\") !== 0", "false"]],
  "fe-innerhtml": [["social", "      if (name) name.textContent = linked", "      if (name) name.innerHTML = linked"]],
  // NAMED (Nov 24 2026, LR-2B): Meta's Uninstall and Delete callbacks, the deletion code and its page
  "meta-unsigned": [["routes", "  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) return { ok: false, reason: \"bad_signature\" };\n", ""]],
  "meta-not-constant-time": [["routes", "!crypto.timingSafeEqual(got, want)", "got.toString(\"hex\") !== want.toString(\"hex\")"]],
  "meta-any-algorithm": [["routes", "  if (String(payload.algorithm || \"\").toUpperCase() !== \"HMAC-SHA256\") return { ok: false, reason: \"algorithm\" };\n", ""]],
  "meta-no-age": [["routes", "    if (issuedAt < nowS - SIGNED_MAX_AGE_S || issuedAt > nowS + SIGNED_FUTURE_S) return { ok: false, reason: \"stale\" };\n", ""]],
  "meta-replay-newer": [["routes", "    return signed.issuedAt === null || !row.created_at ||", "    return true ||"]],
  "meta-deletion-keeps-leads": [["routes", "        var leads = await supabase.from(\"member_leads\").delete().eq(\"user_id\", uid).eq(\"source\", \"threads\");", "        var leads = { error: null };"]],
  "meta-deletion-keeps-replies": [["routes", "        var replies = await supabase.from(\"member_lead_replies\").delete().eq(\"user_id\", uid).eq(\"platform\", \"threads\");", "        var replies = { error: null };"]],
  "meta-deletion-all-sources": [["routes", ".delete().eq(\"user_id\", uid).eq(\"source\", \"threads\");", ".delete().eq(\"user_id\", uid);"]],
  "meta-code-after-failure": [["routes", "        if (leads.error) throw leads.error;\n", ""]],
  "meta-code-unsigned": [["routes", "  if (!crypto.timingSafeEqual(Buffer.from(m[3]), Buffer.from(want))) return null;\n", ""]],
  "meta-unlimited": [["routes", "  app.post(\"/api/social/threads/data-deletion\", metaLimiter, async", "  app.post(\"/api/social/threads/data-deletion\", async"]],
  "meta-wrong-url": [["routes", "\"/threads-deletion.html?code=\"", "\"/threads-deletion?code=\""]],
  "meta-access-missing": [["access", "\"post /api/social/threads/data-deletion\"", "\"post /api/social/threads/data-deletion-x\""]],
  "meta-page-indexed": [["page", "<meta name=\"robots\" content=\"noindex\"/>", ""]],
  "meta-page-wrong-route": [["page", "/api/social/threads/deletion-status?code=", "/api/social/threads/status?code="]],
  "fe-social-tile-gone": [["social", "    <section class=\"context-card bsky-card\" id=\"thConnect\" aria-label=\"Threads\">", "    <section class=\"context-card bsky-card\" id=\"thConnectGone\" aria-label=\"Threads\">"]]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + NAMES.join(", ")); process.exit(2); }

const OUT = function (s) { process.stdout.write(s + "\n"); };
let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; OUT("    pass  " + label); }
  else { failures++; OUT("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const UNHANDLED = [];
process.on("unhandledRejection", function (e) { UNHANDLED.push(e); });

const FILES = {
  auth: read("lib/threadsAuth.js"),
  api: read("lib/threadsApi.js"),
  routes: read("lib/threadsRoutes.js"),
  migration: read("supabase/migrations/204_lr2_member_lead_radar.sql"),
  social: readFe("agents/social.html"),
  integrations: readFe("integrations.html"),
  access: read("lib/routeAccess.js"),                       // NAMED (Nov 24 2026, LR-2B)
  page: readFe("threads-deletion.html"),                    // NAMED (Nov 24 2026, LR-2B)
  sitemaps: readFe("sitemap.xml") + readFe("sitemap-pages.xml")
};
if (MUTATE) {
  MUTATIONS[MUTATE].forEach(function (m) { FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE + " in " + m[0]); });
  OUT("\n!! MUTATION: " + MUTATE);
}

const LOGS = [];
const LOGGER = { error: function () { LOGS.push([].slice.call(arguments).map(String).join(" ")); }, warn: function () { LOGS.push([].slice.call(arguments).map(String).join(" ")); } };
["log", "warn", "error", "info"].forEach(function (k) { console[k] = function () { LOGS.push([].slice.call(arguments).map(String).join(" ")); }; });

process.env.ENCRYPTION_SECRET = crypto.createHash("sha256").update("checkThreadsConnect").digest("hex");
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const REAL_CRYPT = realRequire("./lib/apiKeyCrypto");
function compile(src, file, map) {
  const m = { exports: {} };
  const fn = vm.compileFunction(src, ["module", "exports", "require", "__dirname", "__filename"], { filename: path.join(REPO, file) });
  const localRequire = Module.createRequire(path.join(REPO, file));
  fn(m, m.exports, function (r) { return Object.prototype.hasOwnProperty.call(map, r) ? map[r] : localRequire(r); }, path.dirname(path.join(REPO, file)), path.join(REPO, file));
  return m.exports;
}
const TA = compile(FILES.auth, "lib/threadsAuth.js", {});
const TAPI = compile(FILES.api, "lib/threadsApi.js", { "./threadsAuth": TA });
const TR = compile(FILES.routes, "lib/threadsRoutes.js", { "./threadsAuth": TA, "./threadsApi": TAPI });

/* ── the clock (the docs' example post is from 2023-10-17) ───────────────── */
const T0 = Date.parse("2023-10-18T00:00:00Z");
let NOW = T0;
const clock = function () { return NOW; };
TA.deps.now = clock;
TAPI.deps.now = clock;
TAPI.deps.sleep = function (ms) { NOW += ms; return Promise.resolve(); };

/* ── the stub Meta: the Threads docs' example bodies ─────────────────────── */
const APP_ID = "990011223344";
const APP_SECRET = "check-threads-app-secret-0123456789";
const SHORT = "THQVJ...";
const LONG = "<LONG_LIVED_USER_ACCESS_TOKEN>";
const REFRESHED = "<REFRESHED_LONG_LIVED_TOKEN>";
const TUID = "1234567890";
const DOC_SEARCH = { data: [{ id: "1234567890", text: "first thread", media_type: "TEXT", permalink: "https://www.threads.net/@/post/abcdefg",
  timestamp: "2023-10-17T05:42:03+0000", username: "username", has_replies: false, is_quote_post: false, is_reply: false }] };
let CALLS = [];
let EVENTS = [];
let OVERRIDE = null;
function answer(status, json) { return Promise.resolve({ status: status, json: json, headers: {} }); }
function meta(url, opts) {
  opts = opts || {};
  CALLS.push({ url: url, opts: opts });
  EVENTS.push("meta " + (opts.method || "GET") + " " + new URL(url).pathname);
  if (OVERRIDE) { const o = OVERRIDE(url, opts); if (o) return o; }
  const u = new URL(url);
  const m = opts.method || "GET";
  if (u.host !== "graph.threads.net") return answer(404, {});
  if (m === "POST" && u.pathname === "/oauth/access_token") return answer(200, { access_token: SHORT, user_id: 1234567890 });
  if (m === "GET" && u.pathname === "/access_token") return answer(200, { access_token: LONG, token_type: "bearer", expires_in: 5183944 });
  if (m === "GET" && u.pathname === "/refresh_access_token") return answer(200, { access_token: REFRESHED, token_type: "bearer", expires_in: 5183944 });
  if (m === "GET" && u.pathname === "/v1.0/me") return answer(200, { id: TUID, username: "threadsapitestuser" });
  if (m === "GET" && u.pathname === "/v1.0/keyword_search") return answer(200, JSON.parse(JSON.stringify(DOC_SEARCH)));
  if (m === "POST" && u.pathname === "/v1.0/" + TUID + "/threads") return answer(200, { id: "1234567" });
  if (m === "GET" && u.pathname === "/v1.0/1234567" && /status/.test(u.searchParams.get("fields") || "")) return answer(200, { status: "FINISHED", id: "1234567" });
  if (m === "POST" && u.pathname === "/v1.0/" + TUID + "/threads_publish") return answer(200, { id: "1234567" });
  if (m === "GET" && u.pathname === "/v1.0/1234567" && u.searchParams.get("fields") === "permalink") return answer(200, { permalink: "https://www.threads.net/@threadsapitestuser/post/abcdefg", id: "1234567" });
  return answer(404, { error: { message: "Unsupported request", type: "GraphMethodException", code: 100 } });
}
TA.deps.request = meta;
TAPI.deps.request = meta;
function reset() { CALLS = []; EVENTS = []; OVERRIDE = null; LOGS.length = 0; }

/* ── the in-memory Supabase: threads_connections with 204e's CHECK ────────── */
const DB = { threads_connections: [], member_leads: [], member_lead_replies: [] };   // NAMED (Nov 24 2026, LR-2B): + the leads tables
let FAIL_DELETE = null;
const KS = ["unknown", "own_posts_only", "approved"];
function violates(r) {
  if (!r.user_id || !r.threads_user_id || !r.username || !r.access_ciphertext || !r.access_iv || !r.access_auth_tag || !r.access_expires_at) return "not null";
  if (!/^[0-9]{1,30}$/.test(r.threads_user_id)) return "threads_user_id";
  if (r.username.length < 1 || r.username.length > 100) return "username";
  if (!/^[0-9a-f]+$/.test(r.access_ciphertext) || !/^[0-9a-f]{24}$/.test(r.access_iv) || !/^[0-9a-f]{32}$/.test(r.access_auth_tag)) return "sealed";
  if (r.granted_scopes !== null && r.granted_scopes !== undefined && !(r.granted_scopes.length < 501 && /^[a-z_,]*$/.test(r.granted_scopes))) return "scopes";
  if (KS.indexOf(r.keyword_search_state) === -1) return "keyword_search_state";
  if (["connected", "needs_reconnect"].indexOf(r.status) === -1) return "status";
  if (r.last_error_code !== null && r.last_error_code !== undefined && r.last_error_code.length > 60) return "last_error_code";
  return null;
}
const WRITES = [];
function supa() {
  return {
    from: function (table) {
      const q = { op: "select", filters: [], payload: null };
      const match = function (r) { return q.filters.every(function (f) { return f[0] === "eq" ? r[f[1]] === f[2] : r[f[1]] !== f[2]; }); };
      const run = function () {
        if (!DB[table]) return Promise.resolve({ error: { code: "42P01" }, data: null });
        const rows = DB[table];
        if (q.op === "select") return Promise.resolve({ error: null, data: rows.filter(match).map(function (r) { return Object.assign({}, r); }) });
        if (q.op === "delete") {
          if (FAIL_DELETE === table) return Promise.resolve({ error: { code: "XX000", message: "injected" }, data: null });
          const gone = rows.filter(match);
          DB[table] = rows.filter(function (r) { return !match(r); });
          WRITES.push("delete " + gone.length);
          return Promise.resolve({ error: null, data: gone.map(function (r) { return { id: r.id }; }) });
        }
        if (q.op === "update") {
          const hit = rows.filter(match);
          for (const r of hit) { const next = Object.assign({}, r, q.payload); const v = violates(next); if (v) return Promise.resolve({ error: { code: "23514", message: v }, data: null }); }
          hit.forEach(function (r) { Object.assign(r, q.payload); });
          WRITES.push("update " + hit.length);
          return Promise.resolve({ error: null, data: hit.map(function (r) { return { id: r.id }; }) });
        }
        if (q.op === "upsert") {
          const p = q.payload;
          const old = rows.find(function (r) { return r.user_id === p.user_id; });
          const next = old ? Object.assign({}, old, p)
            : Object.assign({ id: crypto.randomUUID(), keyword_search_state: "unknown", status: "connected", created_at: new Date(NOW).toISOString(), granted_scopes: null, last_ok_at: null, last_error_at: null, last_error_code: null }, p);
          const v = violates(next);
          if (v) return Promise.resolve({ error: { code: "23514", message: v }, data: null });
          if (old) Object.assign(old, next); else rows.push(next);
          WRITES.push("upsert");
          return Promise.resolve({ error: null, data: [{ id: next.id }] });
        }
        return Promise.resolve({ error: { code: "bad" }, data: null });
      };
      const b = {
        select: function () { return b; },
        eq: function (k, v) { q.filters.push(["eq", k, v]); return b; },
        neq: function (k, v) { q.filters.push(["neq", k, v]); return b; },
        upsert: function (row) { q.op = "upsert"; q.payload = row; return b; },
        update: function (obj) { q.op = "update"; q.payload = obj; return b; },
        delete: function () { q.op = "delete"; return b; },
        maybeSingle: function () { return run().then(function (r) { return { error: r.error, data: r.data ? (r.data[0] || null) : null }; }); },
        single: function () { return run().then(function (r) { return { error: r.error || (r.data && r.data.length === 1 ? null : { code: "PGRST116" }), data: r.data ? r.data[0] || null : null }; }); },
        then: function (res, rej) { return run().then(res, rej); }
      };
      return b;
    }
  };
}
const SUPA = supa();
const CRYPT = {
  encrypt: function (p) { EVENTS.push("encrypt"); return REAL_CRYPT.encrypt(p); },
  decrypt: function (s) { return REAL_CRYPT.decrypt(s); }
};

/* ── the fake Express app ───────────────────────────────────────────────── */
const ROUTES = [];
const APP = {
  get: function (p) { ROUTES.push({ method: "GET", path: p, handlers: [].slice.call(arguments, 1) }); },
  post: function (p) { ROUTES.push({ method: "POST", path: p, handlers: [].slice.call(arguments, 1) }); }
};
function requireAuth(req, res, next) { if (!req.user) return res.status(401).json({ error: "Sign in" }); next(); }
function requireActiveSubscription(req, res, next) { if (req.member !== true) return res.status(402).json({ error: "Members only", code: "members_only" }); next(); }
const ENV = { THREADS_APP_ID: APP_ID, THREADS_APP_SECRET: APP_SECRET };
const API_BASE_URL = "https://api.bizforce.test";
const FRONT = "https://bizforce.test";
function META_LIMITER(req, res, next) { next(); }   // NAMED (Nov 24 2026, LR-2B)
TR.mountThreadsRoutes(APP, { requireAuth: requireAuth, requireActiveSubscription: requireActiveSubscription, supabase: SUPA, crypt: CRYPT,
  frontendUrl: FRONT, apiBase: API_BASE_URL, env: ENV, logger: LOGGER, now: clock, OWNER_ACCOUNT_ID: "owner", metaLimiter: META_LIMITER });
function route(method, p) { return ROUTES.find(function (r) { return r.method === method && r.path === p; }); }
async function invoke(method, p, req) {
  const r = route(method, p);
  const res = { statusCode: 200, body: undefined, location: null, headers: {}, done: false };
  res.status = function (c) { res.statusCode = c; return res; };
  res.json = function (b) { res.body = b; res.done = true; return res; };
  res.set = function (k, v) { res.headers[k.toLowerCase()] = v; return res; };
  res.redirect = function (c, u) { res.statusCode = c; res.location = u; res.done = true; return res; };
  if (!r) { res.statusCode = 404; return res; }
  req = Object.assign({ query: {}, body: {} }, req);
  let i = 0;
  async function step(err) {
    if (err) { res.passed = err; return; }
    const h = r.handlers[i++];
    if (!h) return;
    let inner = null;
    const out = h(req, res, function (e) { inner = step(e); });
    if (out && typeof out.then === "function") await out;
    if (inner) await inner;
  }
  await step();
  return res;
}

const U1 = "11111111-1111-4111-8111-111111111111";
const U2 = "22222222-2222-4222-8222-222222222222";
const member = function (id) { return { user: { id: id }, member: true }; };
const free = function (id) { return { user: { id: id }, member: false }; };

(async function main() {
  OUT("checkThreadsConnect: Threads for Lead Radar (LR-2, migration 204e)" + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));

  /* ── P. migration 204e ────────────────────────────────────────────────── */
  OUT("\n== P. migration 204e ==");
  const m204 = (/CREATE TABLE IF NOT EXISTS public\.threads_connections \(([\s\S]*?)\n\);/.exec(FILES.migration) || ["", ""])[1];
  const cols = ["user_id", "threads_user_id", "username", "access_ciphertext", "access_iv", "access_auth_tag", "access_expires_at", "granted_scopes",
    "keyword_search_state", "status", "last_ok_at", "last_error_at", "last_error_code", "created_at", "updated_at"];
  check("P1. threads_connections has every column the code writes and reads", cols.every(function (c) { return new RegExp("\\n  " + c + " ").test(m204); }), m204.slice(0, 120));
  check("P2. user_id is UNIQUE and cascades", /user_id uuid NOT NULL UNIQUE REFERENCES public\.users\(id\) ON DELETE CASCADE/.test(m204));
  check("P3. the CHECK fragments the stub enforces are the migration's", [
    "threads_user_id ~ '^[0-9]{1,30}$'", "char_length(username) BETWEEN 1 AND 100", "access_ciphertext ~ '^[0-9a-f]+$'", "access_iv ~ '^[0-9a-f]{24}$'",
    "access_auth_tag ~ '^[0-9a-f]{32}$'", "granted_scopes ~ '^[a-z_,]*$'", "keyword_search_state IN ('unknown', 'own_posts_only', 'approved')",
    "status IN ('connected', 'needs_reconnect')", "char_length(last_error_code) < 61"].every(function (f) { return FILES.migration.indexOf(f) !== -1; }));
  check("P4. RLS on and no grant to anon or authenticated", /ALTER TABLE public\.threads_connections ENABLE ROW LEVEL SECURITY;/.test(FILES.migration) &&
    /REVOKE ALL ON public\.threads_connections FROM anon, authenticated;/.test(FILES.migration));
  check("P5. the code's row columns are the table's", TAPI.ROW_COLUMNS.split(", ").every(function (c) { return c === "id" || cols.indexOf(c) !== -1; }));

  /* ── A. threadsAuth ───────────────────────────────────────────────────── */
  OUT("\n== A. threadsAuth ==");
  check("A1. configured needs both THREADS_APP_ID and THREADS_APP_SECRET",
    TA.configured({ THREADS_APP_ID: "1", THREADS_APP_SECRET: "s" }) !== null && TA.configured({ THREADS_APP_ID: "1" }) === null &&
    TA.configured({ THREADS_APP_SECRET: "s" }) === null && TA.configured({ THREADS_APP_ID: " ", THREADS_APP_SECRET: "s" }) === null && TA.configured({}) === null);
  const cfg = TA.configured(ENV);
  const st0 = TA.signState(cfg, U1, NOW);
  const az = new URL(TA.authorizeUrl(APP_ID, TA.redirectUri(API_BASE_URL), st0));
  check("A2. the authorize page is threads.net/oauth/authorize with client_id, redirect_uri, response_type=code and the state",
    az.origin + az.pathname === "https://threads.net/oauth/authorize" && az.searchParams.get("client_id") === APP_ID &&
    az.searchParams.get("redirect_uri") === API_BASE_URL + "/api/social/threads/callback" && az.searchParams.get("response_type") === "code" &&
    az.searchParams.get("state") === st0, az.toString());
  check("A3. the four scopes, comma-separated", az.searchParams.get("scope") === "threads_basic,threads_keyword_search,threads_content_publish,threads_manage_replies", az.searchParams.get("scope"));
  const rs = TA.readState(cfg, st0, NOW + 1000);
  check("A4. a signed state reads back as its member", rs.ok === true && rs.userId === U1 && typeof rs.nonce === "string" && rs.expiresMs === NOW + TA.STATE_TTL_MS);
  const flip = st0.slice(0, 5) + (st0[5] === "A" ? "B" : "A") + st0.slice(6);
  const forged = Buffer.from(JSON.stringify({ u: U2, n: "AAAAAAAAAAAAAAAAAAAAAA", e: NOW + 60000 })).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_") + "." + st0.split(".")[1];
  check("A5. a tampered or forged state is refused", TA.readState(cfg, flip, NOW).ok === false && TA.readState(cfg, forged, NOW).ok === false);
  check("A6. an expired state is refused", TA.readState(cfg, st0, NOW + TA.STATE_TTL_MS).ok === false && TA.STATE_TTL_MS === 10 * 60 * 1000);
  check("A7. a state signed under another app secret is refused", TA.readState({ appId: APP_ID, appSecret: "other" }, st0, NOW).ok === false);
  const notUuid = TA.signState(cfg, "not-a-member", NOW);
  check("A8. a state whose member is not an id is refused", TA.readState(cfg, notUuid, NOW).ok === false);
  check("A9. a nonce is spent once", TA.useNonce("NONCE-check-a9-xxxxxxx", NOW + 1000, NOW) === true && TA.useNonce("NONCE-check-a9-xxxxxxx", NOW + 1000, NOW) === false);
  check("A10. the callback query: a code and a state, or nothing; an error answer (the member said no) is never a code",
    TA.callbackShape({ code: "AQD-code", state: "x.y" }).ok === true && TA.callbackShape({ code: "AQD-code", state: "x.y", error: "access_denied" }).ok === false &&
    TA.callbackShape({ state: "x.y" }).ok === false && TA.callbackShape({ code: "a b", state: "x.y" }).ok === false);
  reset();
  const ex = await TA.exchangeCode(cfg, "AQD-code", TA.redirectUri(API_BASE_URL));
  const exCall = CALLS[0];
  check("A11. the code exchange is one form POST to graph.threads.net/oauth/access_token with the five fields",
    CALLS.length === 1 && exCall.url === "https://graph.threads.net/oauth/access_token" && exCall.opts.method === "POST" &&
    JSON.stringify(exCall.opts.form) === JSON.stringify({ client_id: APP_ID, client_secret: APP_SECRET, code: "AQD-code", grant_type: "authorization_code", redirect_uri: API_BASE_URL + "/api/social/threads/callback" }),
    JSON.stringify(exCall && exCall.opts.form));
  check("A12. the docs' answer { access_token, user_id } gives the short token and the account id", ex.shortToken === SHORT && ex.threadsUserId === TUID);
  reset();
  const ll = await TA.longLived(cfg, SHORT);
  const llu = new URL(CALLS[0].url);
  check("A13. the long-lived exchange: GET graph.threads.net/access_token, grant_type=th_exchange_token, the app secret and the short token",
    llu.origin + llu.pathname === "https://graph.threads.net/access_token" && llu.searchParams.get("grant_type") === "th_exchange_token" &&
    llu.searchParams.get("client_secret") === APP_SECRET && llu.searchParams.get("access_token") === SHORT && ll.accessToken === LONG && ll.expiresIn === 5183944);
  reset();
  const rf = await TA.refresh(LONG);
  const rfu = new URL(CALLS[0].url);
  check("A14. the refresh: GET graph.threads.net/refresh_access_token, grant_type=th_refresh_token and the token",
    rfu.origin + rfu.pathname === "https://graph.threads.net/refresh_access_token" && rfu.searchParams.get("grant_type") === "th_refresh_token" &&
    rfu.searchParams.get("access_token") === LONG && rf.accessToken === REFRESHED);
  reset();
  OVERRIDE = function () { return Promise.reject(new Error("socket hang up at https://graph.threads.net/access_token?client_secret=" + APP_SECRET)); };
  let leak = null;
  try { await TA.longLived(cfg, SHORT); } catch (e) { leak = e; }
  check("A15. a failed secret-bearing request is replaced whole: no secret, token or URL in the error",
    leak && leak.kind === "unreachable" && String(leak.message + leak.code).indexOf(APP_SECRET) === -1 && String(leak.message + leak.code).indexOf(SHORT) === -1 && String(leak.message).indexOf("graph.threads.net") === -1, leak && leak.message);
  OVERRIDE = function () { return answer(400, { error: { message: "Invalid OAuth access token.", type: "OAuthException", code: 190 } }); };
  let refused = null;
  try { await TA.refresh(LONG); } catch (e) { refused = e; }
  check("A16. a 190 answer is invalid_grant", refused && refused.kind === "invalid_grant");
  reset();
  const day = 24 * 3600 * 1000;
  check("A17. refreshDue: inside 10 days of expiry AND stored 24 hours ago; never once expired",
    TA.refreshDue({ access_expires_at: new Date(NOW + 5 * day).toISOString(), updated_at: new Date(NOW - 2 * day).toISOString() }, NOW) === true &&
    TA.refreshDue({ access_expires_at: new Date(NOW + 5 * day).toISOString(), updated_at: new Date(NOW - 3600000).toISOString() }, NOW) === false &&
    TA.refreshDue({ access_expires_at: new Date(NOW + 30 * day).toISOString(), updated_at: new Date(NOW - 2 * day).toISOString() }, NOW) === false &&
    TA.refreshDue({ access_expires_at: new Date(NOW - 1000).toISOString(), updated_at: new Date(NOW - 2 * day).toISOString() }, NOW) === false);

  /* ── R. the routes and their guards ──────────────────────────────────── */
  OUT("\n== R. routes ==");
  const want = [["GET", "/api/social/threads/connect"], ["GET", "/api/social/threads/callback"], ["GET", "/api/social/threads/status"], ["POST", "/api/social/threads/disconnect"]];
  check("R1. exactly the seven routes (NAMED (Nov 24 2026, LR-2B): + deauthorize, data-deletion, deletion-status; BEFORE four)", ROUTES.length === 7 && want.every(function (w) { return !!route(w[0], w[1]); }), ROUTES.map(function (r) { return r.method + " " + r.path; }).join(", "));
  const has = function (w, fn) { const r = route(w[0], w[1]); return !!r && r.handlers.indexOf(fn) !== -1; };
  check("R2. connect is members only (requireAuth then requireActiveSubscription)", has(want[0], requireAuth) && has(want[0], requireActiveSubscription) &&
    route(want[0][0], want[0][1]).handlers.indexOf(requireAuth) < route(want[0][0], want[0][1]).handlers.indexOf(requireActiveSubscription));
  check("R3. the callback has neither guard (Meta's redirect carries no session)", !has(want[1], requireAuth) && !has(want[1], requireActiveSubscription));
  check("R4. status and disconnect need a sign-in only", has(want[2], requireAuth) && !has(want[2], requireActiveSubscription) && has(want[3], requireAuth) && !has(want[3], requireActiveSubscription));
  let r = await invoke("GET", want[0][1], {});
  check("R5. connect signed out: 401", r.statusCode === 401);
  r = await invoke("GET", want[0][1], free(U1));
  check("R6. connect as a free account: 402", r.statusCode === 402);
  const savedEnv = Object.assign({}, ENV);
  for (const k of ["THREADS_APP_ID", "THREADS_APP_SECRET"]) {
    delete ENV[k];
    reset();
    r = await invoke("GET", want[0][1], member(U1));
    check("R7. connect without " + k + ": 503 { error: \"Threads is not set up yet\", code: \"threads_not_set_up\" } and no request",
      r.statusCode === 503 && r.body && r.body.error === "Threads is not set up yet" && r.body.code === "threads_not_set_up" && CALLS.length === 0, JSON.stringify(r.body));
    Object.assign(ENV, savedEnv);
  }
  reset();
  r = await invoke("GET", want[0][1], member(U1));
  const cu = r.body && typeof r.body.url === "string" ? new URL(r.body.url) : null;
  check("R8. connect as a member: { url } of Threads' sign-in, no request made, not cached", r.statusCode === 200 && cu && cu.origin === "https://threads.net" &&
    TA.readState(cfg, cu.searchParams.get("state"), NOW).userId === U1 && CALLS.length === 0 && r.headers["cache-control"] === "no-store", JSON.stringify(r.body));

  /* ── C. the callback ─────────────────────────────────────────────────── */
  OUT("\n== C. the callback ==");
  async function connectAs(uid) { const c = await invoke("GET", want[0][1], member(uid)); return new URL(c.body.url).searchParams.get("state"); }
  DB.threads_connections = [];
  let state = await connectAs(U1);
  reset();
  r = await invoke("GET", want[1][1], { query: { code: "AQD-code", state: state } });
  const row = DB.threads_connections.find(function (x) { return x.user_id === U1; });
  check("C1. redirects to FRONTEND/integrations.html?threads=connected", r.statusCode === 302 && r.location === FRONT + "/integrations.html?threads=connected", r.location);
  check("C2. one row, the state's member's, the account /me named", DB.threads_connections.length === 1 && row && row.threads_user_id === TUID && row.username === "threadsapitestuser" && row.status === "connected");
  check("C3. the stored token is the LONG-lived one, sealed (it decrypts to it; the short one is stored nowhere)",
    row && REAL_CRYPT.decrypt({ ciphertext: row.access_ciphertext, iv: row.access_iv, authTag: row.access_auth_tag }) === LONG &&
    JSON.stringify(DB).indexOf(SHORT) === -1 && JSON.stringify(DB).indexOf(LONG) === -1);
  check("C4. the token is sealed before Threads is asked who the account is", EVENTS.indexOf("encrypt") !== -1 && EVENTS.indexOf("encrypt") < EVENTS.indexOf("meta GET /v1.0/me"), EVENTS.join(" | "));
  check("C5. /me is read with the long-lived token, in the Authorization header", CALLS.some(function (c) { return /\/v1\.0\/me\?/.test(c.url) && c.opts.headers && c.opts.headers.Authorization === "Bearer " + LONG && c.url.indexOf(LONG) === -1; }));
  check("C6. expiry stored from expires_in (less a minute) and keyword_search_state starts unknown",
    row && Date.parse(row.access_expires_at) === NOW + 5183944 * 1000 - 60000 && row.keyword_search_state === "unknown");
  reset();
  r = await invoke("GET", want[1][1], { query: { code: "AQD-code", state: state } });
  check("C7. the same state again: ?threads=error and no request to Meta", r.location === FRONT + "/integrations.html?threads=error" && CALLS.length === 0);
  reset();
  r = await invoke("GET", want[1][1], { query: { code: "AQD-code", state: flip } });
  check("C8. a tampered state: ?threads=error and no request", r.location === FRONT + "/integrations.html?threads=error" && CALLS.length === 0);
  state = await connectAs(U2);
  NOW += TA.STATE_TTL_MS + 1;
  reset();
  r = await invoke("GET", want[1][1], { query: { code: "AQD-code", state: state } });
  check("C9. an expired state: ?threads=error, no request, no row for that member", r.location === FRONT + "/integrations.html?threads=error" && CALLS.length === 0 && !DB.threads_connections.some(function (x) { return x.user_id === U2; }));
  state = await connectAs(U2);
  reset();
  r = await invoke("GET", want[1][1], { query: { error: "access_denied", error_reason: "user_denied", state: state } });
  check("C10. the member said no: ?threads=error and nothing stored", r.location === FRONT + "/integrations.html?threads=error" && CALLS.length === 0 && DB.threads_connections.length === 1);
  state = await connectAs(U2);
  reset();
  OVERRIDE = function (u) { return /\/v1\.0\/me/.test(u) ? answer(200, { id: "999", username: "someoneelse" }) : null; };
  r = await invoke("GET", want[1][1], { query: { code: "AQD-code", state: state } });
  check("C11. /me naming another account than the exchange did: ?threads=error, nothing stored", r.location === FRONT + "/integrations.html?threads=error" && DB.threads_connections.length === 1);
  state = await connectAs(U2);
  reset();
  OVERRIDE = function (u) { return /oauth\/access_token/.test(u) ? answer(400, { error: { message: "Invalid verification code format.", type: "OAuthException", code: 100 } }) : null; };
  r = await invoke("GET", want[1][1], { query: { code: "AQD-code", state: state } });
  check("C12. a refused code: ?threads=error, nothing stored", r.location === FRONT + "/integrations.html?threads=error" && DB.threads_connections.length === 1);
  const allLogs = LOGS.join("\n");
  check("C13. no token, code, state or app secret in any log line or redirect", [SHORT, LONG, "AQD-code", APP_SECRET, state].every(function (s) { return allLogs.indexOf(s) === -1; }) && r.location.indexOf("AQD") === -1, allLogs.slice(0, 200));
  // A reconnect keeps what was learned about the search.
  DB.threads_connections[0].keyword_search_state = "approved";
  state = await connectAs(U1);
  reset();
  r = await invoke("GET", want[1][1], { query: { code: "AQD-code", state: state } });
  check("C14. a reconnect updates the same row and keeps keyword_search_state", r.location === FRONT + "/integrations.html?threads=connected" &&
    DB.threads_connections.length === 1 && DB.threads_connections[0].keyword_search_state === "approved");

  /* ── S. status and disconnect ────────────────────────────────────────── */
  OUT("\n== S. status and disconnect ==");
  r = await invoke("GET", want[2][1], free(U1));
  check("S1. status (a free account may read it): { state, username, keyword_search } and nothing else",
    r.statusCode === 200 && JSON.stringify(Object.keys(r.body).sort()) === JSON.stringify(["keyword_search", "state", "username"]) &&
    r.body.state === "ready" && r.body.username === "threadsapitestuser" && r.body.keyword_search === "approved", JSON.stringify(r.body));
  check("S2. status never carries a token or its parts", JSON.stringify(r.body).indexOf(DB.threads_connections[0].access_ciphertext) === -1 && !/cipher|auth_tag|access_iv/.test(JSON.stringify(r.body)));
  DB.threads_connections[0].keyword_search_state = "own_posts_only";
  r = await invoke("GET", want[2][1], free(U1));
  check("S3. own_posts_only is waiting_approval", r.body.state === "waiting_approval" && r.body.keyword_search === "own_posts_only");
  r = await invoke("GET", want[2][1], free(U2));
  check("S4. no row: not_connected", r.body.state === "not_connected" && r.body.username === null && r.body.keyword_search === "unknown");
  delete ENV.THREADS_APP_ID;
  r = await invoke("GET", want[2][1], free(U1));
  Object.assign(ENV, savedEnv);
  check("S5. not set up: not_set_up (status still answers)", r.statusCode === 200 && r.body.state === "not_set_up");
  const expiredRow = Object.assign({}, DB.threads_connections[0], { access_expires_at: new Date(NOW - 1000).toISOString() });
  check("S6. expired or needs_reconnect: needs_reconnect", TAPI.stateOf(expiredRow, true, NOW) === "needs_reconnect" &&
    TAPI.stateOf(Object.assign({}, DB.threads_connections[0], { status: "needs_reconnect" }), true, NOW) === "needs_reconnect");
  DB.threads_connections.push(Object.assign({}, DB.threads_connections[0], { id: crypto.randomUUID(), user_id: U2 }));
  r = await invoke("POST", want[3][1], free(U2));
  check("S7. disconnect: { disconnected: true }, only the caller's row deleted", r.statusCode === 200 && r.body && r.body.disconnected === true &&
    DB.threads_connections.length === 1 && DB.threads_connections[0].user_id === U1, JSON.stringify(r.body));
  r = await invoke("POST", want[3][1], {});
  check("S8. disconnect signed out: 401", r.statusCode === 401);

  /* ── K. keyword search ───────────────────────────────────────────────── */
  OUT("\n== K. keyword search ==");
  reset();
  let ks = await TAPI.keywordSearch(LONG, "first thread", new Date(NOW - 30 * day).toISOString(), "threadsapitestuser");
  const ku = new URL(CALLS[0].url);
  check("K1. GET graph.threads.net/v1.0/keyword_search with q and search_type=RECENT", ku.origin + ku.pathname === "https://graph.threads.net/v1.0/keyword_search" &&
    ku.searchParams.get("q") === "first thread" && ku.searchParams.get("search_type") === "RECENT", CALLS[0].url);
  check("K2. since is clamped to the last 7 days (unix seconds)", Number(ku.searchParams.get("since")) === Math.floor((NOW - 7 * day) / 1000), ku.searchParams.get("since"));
  check("K3. the token in the Authorization header, never in the URL", (CALLS[0].opts.headers || {}).Authorization === "Bearer " + LONG && CALLS[0].url.indexOf(LONG) === -1 && !ku.searchParams.has("access_token"));
  check("K4. the docs' example post is read: id, text, username, timestamp, permalink", ks.posts.length === 1 && ks.posts[0].id === "1234567890" && ks.posts[0].text === "first thread" &&
    ks.posts[0].username === "username" && ks.posts[0].timestamp === "2023-10-17T05:42:03.000Z" && ks.posts[0].permalink === "https://www.threads.net/@/post/abcdefg" && ks.ownOnly === false, JSON.stringify(ks));
  reset();
  ks = await TAPI.keywordSearch(LONG, "first thread", new Date(NOW - day).toISOString(), "threadsapitestuser");
  check("K5. a later since is kept as given", Number(new URL(CALLS[0].url).searchParams.get("since")) === Math.floor((NOW - day) / 1000));
  reset();
  ks = await TAPI.keywordSearch(LONG, "first thread", null, "USERNAME");
  check("K6. every result the member's own (case ignored): ownOnly, and none returned as a lead", ks.ownOnly === true && ks.posts.length === 0 && ks.ownCount === 1);
  OVERRIDE = function () { return answer(200, { data: [DOC_SEARCH.data[0], Object.assign({}, DOC_SEARCH.data[0], { id: "1234567891", username: "neighbour_bakery" })] }); };
  ks = await TAPI.keywordSearch(LONG, "first thread", null, "username");
  check("K7. mixed results: only other people's posts, ownOnly false", ks.ownOnly === false && ks.posts.length === 1 && ks.posts[0].username === "neighbour_bakery");
  OVERRIDE = function () { return answer(200, { data: [] }); };
  ks = await TAPI.keywordSearch(LONG, "first thread", null, "username");
  check("K8. no results says nothing about approval", ks.ownOnly === false && ks.posts.length === 0);
  OVERRIDE = function () { return answer(200, { data: [Object.assign({}, DOC_SEARCH.data[0], { timestamp: "2023-10-01T00:00:00+0000", username: "old_post" })] }); };
  ks = await TAPI.keywordSearch(LONG, "first thread", null, "username");
  check("K9. a post older than since is dropped", ks.posts.length === 0);
  OVERRIDE = function () { return answer(403, { error: { message: "(#10) Application does not have permission for this action", type: "OAuthException", code: 10, fbtrace_id: "AbCdEf" } }); };
  try { ks = await TAPI.keywordSearch(LONG, "first thread", null, "username"); } catch (x) { ks = { thrown: x && x.kind }; }
  check("K10. a permission error is the pre-approval state, not a throw", ks.ownOnly === true && ks.permission === true && ks.posts.length === 0);
  let kerr = null;
  OVERRIDE = function () { return answer(400, { error: { message: "Error validating access token", type: "OAuthException", code: 190 } }); };
  try { await TAPI.keywordSearch(LONG, "first thread", null, "username"); } catch (e) { kerr = e; }
  check("K11. a refused token throws auth", kerr && kerr.kind === "auth");
  kerr = null;
  OVERRIDE = function () { return answer(429, { error: { message: "Application request limit reached", type: "OAuthException", code: 4 } }); };
  try { await TAPI.keywordSearch(LONG, "first thread", null, "username"); } catch (e) { kerr = e; }
  check("K12. a rate limit throws rate_limited", kerr && kerr.kind === "rate_limited");
  kerr = null;
  reset();
  try { await TAPI.keywordSearch(LONG, "   ", null, "username"); } catch (e) { kerr = e; }
  check("K13. an empty query sends nothing", kerr && kerr.kind === "bad_input" && CALLS.length === 0);
  const S = TAPI.keywordSearchState;
  check("K14. keywordSearchState: others seen -> approved; all own -> own_posts_only; permission -> own_posts_only; nothing -> unchanged",
    S("unknown", { posts: [{}], ownOnly: false }) === "approved" && S("unknown", { posts: [], ownOnly: true }) === "own_posts_only" &&
    S("own_posts_only", { posts: [{}], ownOnly: false }) === "approved" && S("approved", { posts: [], ownOnly: true, permission: true }) === "own_posts_only" &&
    S("unknown", { posts: [], ownOnly: false }) === "unknown" && S("own_posts_only", { posts: [], ownOnly: false }) === "own_posts_only");
  check("K15. once approved, a search whose only results are the member's own does not move it back", S("approved", { posts: [], ownOnly: true, permission: false }) === "approved");
  const krow = DB.threads_connections[0];
  krow.keyword_search_state = "unknown";
  const recOk = await TAPI.recordKeywordState({ supabase: SUPA, now: clock }, krow, "own_posts_only");
  check("K16. recordKeywordState stores the new state on the member's row", recOk === true && DB.threads_connections[0].keyword_search_state === "own_posts_only");

  /* ── Y. the reply ────────────────────────────────────────────────────── */
  OUT("\n== Y. the reply ==");
  reset();
  const TEXT = "  Happy to help: we deliver in Austin on weekdays.  ";
  const rep = await TAPI.replyTo(LONG, TUID, "1234567890", TEXT);
  const posts = CALLS.filter(function (c) { return c.opts.method === "POST"; });
  check("Y1. a TEXT container with reply_to_id at /{threads-user-id}/threads, then one threads_publish with creation_id",
    posts.length === 2 && posts[0].url === "https://graph.threads.net/v1.0/" + TUID + "/threads" && posts[0].opts.form.media_type === "TEXT" &&
    posts[0].opts.form.reply_to_id === "1234567890" && posts[1].url === "https://graph.threads.net/v1.0/" + TUID + "/threads_publish" &&
    posts[1].opts.form.creation_id === "1234567", JSON.stringify(posts.map(function (p) { return [p.url, p.opts.form]; })));
  check("Y2. the text is sent exactly as given, not trimmed or rewritten", posts[0] && posts[0].opts.form.text === TEXT);
  check("Y3. the container's status is read before the publish", EVENTS.indexOf("meta GET /v1.0/1234567") !== -1 && EVENTS.indexOf("meta GET /v1.0/1234567") < EVENTS.indexOf("meta POST /v1.0/" + TUID + "/threads_publish"), EVENTS.join(" | "));
  check("Y4. { id, permalink } from the docs' answers", rep.id === "1234567" && rep.permalink === "https://www.threads.net/@threadsapitestuser/post/abcdefg");
  check("Y5. every call carries the token in the header, never the URL", CALLS.every(function (c) { return (c.opts.headers || {}).Authorization === "Bearer " + LONG && c.url.indexOf(LONG) === -1; }));
  for (const bad of [["", "empty"], ["   ", "blank"], ["x".repeat(501), "501 characters"], [null, "not text"]]) {
    reset();
    let e = null;
    try { await TAPI.replyTo(LONG, TUID, "1234567890", bad[0]); } catch (x) { e = x; }
    check("Y6. a reply that is " + bad[1] + " sends nothing", e && e.kind === "bad_input" && CALLS.length === 0);
  }
  reset();
  let e7 = null;
  try { await TAPI.replyTo(LONG, TUID, "not-an-id", "hello"); } catch (x) { e7 = x; }
  check("Y7. a target that is not a post id sends nothing", e7 && e7.kind === "bad_input" && CALLS.length === 0);
  const ok500 = await TAPI.replyTo(LONG, TUID, "1234567890", "y".repeat(500));
  check("Y8. 500 characters is allowed", ok500.id === "1234567");
  reset();
  OVERRIDE = function (u, o) { return /threads_publish/.test(u) ? Promise.reject(new Error("socket hang up")) : null; };
  let e9 = null;
  try { await TAPI.replyTo(LONG, TUID, "1234567890", "hello"); } catch (x) { e9 = x; }
  check("Y9. a publish that may have gone out is never retried: unknown_outcome, ONE publish request",
    e9 && e9.kind === "unknown_outcome" && CALLS.filter(function (c) { return /threads_publish/.test(c.url); }).length === 1, e9 && e9.kind);
  reset();
  OVERRIDE = function (u) { return /fields=status/.test(u) ? answer(200, { status: "ERROR", error_message: "FAILED_PROCESSING", id: "1234567" }) : null; };
  let e10 = null;
  try { await TAPI.replyTo(LONG, TUID, "1234567890", "hello"); } catch (x) { e10 = x; }
  check("Y10. a container in ERROR is never published", e10 && e10.kind === "refused" && !CALLS.some(function (c) { return /threads_publish/.test(c.url); }));
  reset();
  let polls = 0;
  OVERRIDE = function (u) { if (/fields=status/.test(u)) { polls++; return answer(200, { status: polls < 3 ? "IN_PROGRESS" : "FINISHED", id: "1234567" }); } return null; };
  const waited = await TAPI.replyTo(LONG, TUID, "1234567890", "hello");
  check("Y11. IN_PROGRESS is waited out, then published once", waited.id === "1234567" && polls === 3 && CALLS.filter(function (c) { return /threads_publish/.test(c.url); }).length === 1);
  reset();
  OVERRIDE = function (u) { return /fields=permalink/.test(u) ? answer(500, {}) : null; };
  const noLink = await TAPI.replyTo(LONG, TUID, "1234567890", "hello");
  check("Y12. an unreadable permalink still reports the sent reply (permalink null)", noLink.id === "1234567" && noLink.permalink === null);

  /* ── B. the search budget ────────────────────────────────────────────── */
  OUT("\n== B. the search budget ==");
  const BU = "33333333-3333-4333-8333-333333333333";
  let lastOk = null, n = 0;
  for (let i = 0; i < 2200; i++) { const t = TAPI.takeSearch(BU, NOW + i); if (t.ok) n++; lastOk = t; }
  const over = TAPI.takeSearch(BU, NOW + 2200);
  check("B1. 2,200 searches in 24 hours, then refused without spending", n === 2200 && lastOk.remaining === 0 && over.ok === false && TAPI.searchesLeft(BU, NOW + 2200) === 0 && TAPI.SEARCHES_PER_DAY === 2200);
  check("B2. another member's budget is their own", TAPI.takeSearch("44444444-4444-4444-8444-444444444444", NOW + 2200).ok === true);
  const later = TAPI.takeSearch(BU, NOW + 24 * 3600 * 1000 + 5);
  check("B3. the window slides: the oldest search frees a slot 24 hours later", later.ok === true);
  const EX = "55555555-5555-4555-8555-555555555555";
  TAPI.exhaustSearches(EX, NOW);
  check("B4. exhaustSearches (Meta said rate-limited) fills the window", TAPI.takeSearch(EX, NOW + 1).ok === false && TAPI.takeSearch(EX, NOW + 24 * 3600 * 1000 + 1).ok === true);

  /* ── T. the token ────────────────────────────────────────────────────── */
  OUT("\n== T. accessToken ==");
  const CTX = { supabase: SUPA, crypt: CRYPT, now: clock };
  const base = DB.threads_connections[0];
  base.status = "connected";
  base.access_expires_at = new Date(NOW + 40 * day).toISOString();
  base.updated_at = new Date(NOW - 2 * day).toISOString();
  reset();
  let at = await TAPI.accessToken(CTX, Object.assign({}, base));
  check("T1. a token not due is used as stored, with no request", at.token === LONG && CALLS.length === 0);
  base.access_expires_at = new Date(NOW + 5 * day).toISOString();
  reset();
  at = await TAPI.accessToken(CTX, Object.assign({}, base));
  check("T2. a due token is refreshed and the new one stored sealed", at.token === REFRESHED &&
    REAL_CRYPT.decrypt({ ciphertext: base.access_ciphertext, iv: base.access_iv, authTag: base.access_auth_tag }) === REFRESHED &&
    Date.parse(base.access_expires_at) === NOW + 5183944 * 1000 - 60000);
  base.access_expires_at = new Date(NOW + 5 * day).toISOString();
  base.updated_at = new Date(NOW - 2 * day).toISOString();
  reset();
  OVERRIDE = function () { return Promise.reject(new Error("down")); };
  at = await TAPI.accessToken(CTX, Object.assign({}, base));
  check("T3. a refresh that cannot reach Threads uses the valid token as it is", at.token === REFRESHED && base.status === "connected");
  reset();
  OVERRIDE = function () { return answer(400, { error: { message: "Error validating access token", type: "OAuthException", code: 190 } }); };
  let te = null;
  try { await TAPI.accessToken(CTX, Object.assign({}, base)); } catch (x) { te = x; }
  check("T4. a refused refresh marks needs_reconnect", te && te.kind === "auth" && base.status === "needs_reconnect" && base.last_error_code === "refresh_refused");
  base.status = "connected";
  base.access_expires_at = new Date(NOW - 1000).toISOString();
  reset();
  te = null;
  try { await TAPI.accessToken(CTX, Object.assign({}, base)); } catch (x) { te = x; }
  check("T5. an expired token is never used: needs_reconnect, no request", te && te.kind === "auth" && te.code === "expired" && base.status === "needs_reconnect" && CALLS.length === 0);

  /* ── F. the tiles ────────────────────────────────────────────────────── */
  OUT("\n== F. the tiles ==");
  function tileScript(html) {
    const a = html.indexOf("NAMED (Nov 23 2026, LR-2): the Threads tile.");
    if (a === -1) return "";
    const s0 = html.lastIndexOf("<script>", a);
    const s1 = html.indexOf("</script>", a);
    return html.slice(s0 + "<script>".length, s1);
  }
  const scripts = { social: tileScript(FILES.social), integrations: tileScript(FILES.integrations) };
  async function runTile(page, opts) {
    const html = FILES[page];
    const ids = {};
    (html.match(/ id="th[A-Za-z]+"[^>]*>/g) || []).forEach(function (t) { const id = /id="([^"]+)"/.exec(t)[1]; ids[id] = { id: id, hidden: / hidden[ >]/.test(t), textContent: "", disabled: false, attrs: {}, listeners: {},
      setAttribute: function (k, v) { this.attrs[k] = v; }, removeAttribute: function (k) { delete this.attrs[k]; },
      addEventListener: function (k, f) { this.listeners[k] = f; } }; });
    const fetched = [];
    let assigned = null;
    const sandbox = {
      document: { readyState: "complete", getElementById: function (id) { return ids[id] || null; }, addEventListener: function () {} },
      localStorage: { getItem: function () { return opts.signedIn === false ? null : "tok"; } },
      URLSearchParams: URLSearchParams,
      window: { location: { search: opts.search || "", assign: function (u) { assigned = u; } } },
      fetch: function (u, init) {
        fetched.push({ url: u, method: init.method, auth: init.headers.Authorization });
        const p = new URL(u).pathname;
        const a = opts.answers[p] || { status: 404, body: {} };
        return Promise.resolve({ ok: a.status >= 200 && a.status < 300, status: a.status, json: function () { return Promise.resolve(a.body); } });
      }
    };
    vm.runInNewContext(scripts[page], sandbox);
    for (let i = 0; i < 10; i++) await new Promise(function (res) { setImmediate(res); });
    if (opts.click && ids[opts.click] && ids[opts.click].listeners.click) {
      ids[opts.click].listeners.click();
      for (let i = 0; i < 10; i++) await new Promise(function (res) { setImmediate(res); });
    }
    return { ids: ids, fetched: fetched, assigned: assigned };
  }
  check("F1. both pages carry the same tile script", scripts.social.length > 500 && scripts.social === scripts.integrations);
  for (const page of ["integrations", "social"]) {
    const html = FILES[page];
    check("F2. " + page + ": the tile, Connect and Disconnect, the not-set-up and waiting lines",
      /id="thConnect"/.test(html) && /id="thConnectBtn"[^>]*>Connect Threads</.test(html) && /id="thDisconnectBtn" hidden>Disconnect</.test(html) &&
      /id="thUnavailable" hidden>Threads is not set up yet</.test(html) && /id="thWaiting" hidden>Waiting for Meta's approval/.test(html));
    const ST = "/api/social/threads/status", CO = "/api/social/threads/connect", DI = "/api/social/threads/disconnect";
    let t = await runTile(page, { answers: { [ST]: { status: 200, body: { state: "not_set_up", username: null, keyword_search: "unknown" } }, [CO]: { status: 503, body: { error: "Threads is not set up yet", code: "threads_not_set_up" } } }, click: "thConnectBtn" });
    check("F3. " + page + ": not set up shows \"Threads is not set up yet\" and Connect off; a 503 says it too",
      t.ids.thUnavailable.hidden === false && t.ids.thConnectBtn.disabled === true && t.ids.thConnectMsg.textContent === "Threads is not set up yet" && t.assigned === null);
    t = await runTile(page, { answers: { [ST]: { status: 200, body: { state: "waiting_approval", username: "threadsapitestuser", keyword_search: "own_posts_only" } } } });
    check("F4. " + page + ": own_posts_only shows \"Waiting for Meta's approval\" and the account",
      t.ids.thWaiting.hidden === false && t.ids.thState.textContent === "Waiting for Meta's approval" && t.ids.thName.textContent === "Connected as @threadsapitestuser" &&
      t.ids.thDisconnectBtn.hidden === false && t.ids.thConnectBtn.hidden === true);
    t = await runTile(page, { answers: { [ST]: { status: 200, body: { state: "ready", username: "threadsapitestuser", keyword_search: "approved" } } } });
    check("F5. " + page + ": ready shows Connected and no waiting line", t.ids.thWaiting.hidden === true && t.ids.thState.textContent === "Connected" && t.ids.thUnavailable.hidden === true);
    t = await runTile(page, { answers: { [ST]: { status: 200, body: { state: "not_connected", username: null, keyword_search: "unknown" } }, [CO]: { status: 200, body: { url: "https://threads.net/oauth/authorize?client_id=1&state=x" } } }, click: "thConnectBtn" });
    check("F6. " + page + ": Connect asks the connect route with the session and goes to Threads' sign-in",
      t.assigned === "https://threads.net/oauth/authorize?client_id=1&state=x" && t.fetched.some(function (f) { return /\/api\/social\/threads\/connect$/.test(f.url) && f.method === "GET" && f.auth === "Bearer tok"; }));
    t = await runTile(page, { answers: { [ST]: { status: 200, body: { state: "not_connected" } }, [CO]: { status: 200, body: { url: "https://evil.example/oauth/authorize?x" } } }, click: "thConnectBtn" });
    check("F7. " + page + ": a URL that is not Threads' sign-in is never followed", t.assigned === null);
    t = await runTile(page, { answers: { [ST]: { status: 200, body: { state: "not_connected" } }, [CO]: { status: 402, body: { error: "Members only" } } }, click: "thConnectBtn" });
    check("F8. " + page + ": a free account is told it is for members", t.ids.thConnectMsg.textContent === "Connecting Threads is for members." && t.assigned === null);
    t = await runTile(page, { answers: { [ST]: { status: 200, body: { state: "ready", username: "u" } }, [DI]: { status: 200, body: { disconnected: true } } }, click: "thDisconnectBtn" });
    check("F9. " + page + ": Disconnect posts the disconnect route", t.fetched.some(function (f) { return /\/api\/social\/threads\/disconnect$/.test(f.url) && f.method === "POST"; }) && /^Disconnected\./.test(t.ids.thConnectMsg.textContent));
    t = await runTile(page, { search: "?threads=error", answers: { [ST]: { status: 200, body: { state: "not_connected" } } } });
    const tc = await runTile(page, { search: "?threads=connected", answers: { [ST]: { status: 200, body: { state: "ready", username: "u" } } } });
    check("F10. " + page + ": back from Meta, ?threads=error and ?threads=connected are each said", /was not connected/.test(t.ids.thConnectMsg.textContent) && tc.ids.thConnectMsg.textContent === "Threads is connected.");
  }
  check("F11. the tile script writes text only (no innerHTML, outerHTML or insertAdjacentHTML)", scripts.social.length > 0 && !/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(scripts.social));
  const staticCards = {};
  (FILES.integrations.match(/<div class="int-card">[\s\S]*?<span class="int-status">[^<]*<\/span>/g) || []).forEach(function (card) {
    staticCards[(/<p class="int-card-name">([^<]*)<\/p>/.exec(card) || ["", ""])[1]] = (/<span class="int-status">([^<]*)<\/span>/.exec(card) || ["", ""])[1];
  });
  check("F12. integrations.html: the fixed-state cards are unchanged (Threads is not one of them; On the Social page is still exactly four)",
    !("Threads" in staticCards) && Object.keys(staticCards).filter(function (k) { return staticCards[k] === "On the Social page"; }).sort().join(",") === "Facebook,Instagram,TikTok,YouTube", JSON.stringify(staticCards));

  /* ── M. Meta's callbacks (NAMED Nov 24 2026, LR-2B) ───────────────────── */
  OUT("\n== M. Meta's Uninstall and Delete callbacks ==");
  {
    const b64u = function (buf) { return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
    const sign = function (payload, secret) {
      const p = b64u(JSON.stringify(payload));
      return b64u(crypto.createHmac("sha256", secret || APP_SECRET).update(p).digest()) + "." + p;
    };
    const nowS = function () { return Math.floor(NOW / 1000); };
    const OTHER_TUID = "5550001112";
    const seed = function () {
      DB.threads_connections = [
        { id: crypto.randomUUID(), user_id: U1, threads_user_id: TUID, username: "u1", created_at: new Date(NOW - 3600000).toISOString() },
        { id: crypto.randomUUID(), user_id: U2, threads_user_id: OTHER_TUID, username: "u2", created_at: new Date(NOW - 3600000).toISOString() }];
      DB.member_leads = [{ id: "l1", user_id: U1, source: "threads" }, { id: "l2", user_id: U1, source: "bluesky" }, { id: "l3", user_id: U2, source: "threads" }];
      DB.member_lead_replies = [{ id: "r1", user_id: U1, platform: "threads" }, { id: "r2", user_id: U1, platform: "bluesky" }, { id: "r3", user_id: U2, platform: "threads" }];
      FAIL_DELETE = null;
    };
    const snap = function () { return JSON.stringify([DB.threads_connections.map(function (x) { return x.user_id; }), DB.member_leads.map(function (x) { return x.id; }), DB.member_lead_replies.map(function (x) { return x.id; })]); };
    const DE = "/api/social/threads/deauthorize", DD = "/api/social/threads/data-deletion", DS = "/api/social/threads/deletion-status";
    const good = function () { return { algorithm: "HMAC-SHA256", issued_at: nowS(), user_id: TUID }; };

    const three = [["POST", DE], ["POST", DD], ["GET", DS]];
    check("M1. the three routes are public (no sign-in, no membership) and each is rate-limited first",
      three.every(function (w) { const rt = route(w[0], w[1]); return !!rt && rt.handlers[0] === META_LIMITER && rt.handlers.indexOf(requireAuth) === -1 && rt.handlers.indexOf(requireActiveSubscription) === -1; }) &&
      FILES.routes.indexOf("require(\"express-rate-limit\")({ windowMs: 15 * 60 * 1000, max: 30,") !== -1);
    check("M2. lib/routeAccess.js lists all three as P", ["\"post /api/social/threads/deauthorize\"", "\"post /api/social/threads/data-deletion\"", "\"get /api/social/threads/deletion-status\""].every(function (k) {
      const at = FILES.access.indexOf(k), pub = FILES.access.indexOf("const PUBLIC"), free = FILES.access.indexOf("const FREE");
      return at !== -1 && pub !== -1 && at > pub && (free === -1 || at < free);
    }));

    seed();
    let before = snap();
    let r1 = await invoke("POST", DE, { body: {} });
    let r2 = await invoke("POST", DD, { body: {} });
    check("M3. no signed_request: 400 on both, nothing deleted", r1.statusCode === 400 && r2.statusCode === 400 && r2.body.code === "missing" && snap() === before, JSON.stringify([r1.statusCode, r2.body]));
    r1 = await invoke("POST", DE, { body: { signed_request: sign(good(), "not-the-app-secret") } });
    r2 = await invoke("POST", DD, { body: { signed_request: sign(good(), "not-the-app-secret") } });
    check("M4. signed with another secret: 400 bad_signature on both, nothing deleted", r1.statusCode === 400 && r1.body.code === "bad_signature" && r2.statusCode === 400 && r2.body.code === "bad_signature" && snap() === before,
      JSON.stringify([r1.body, r2.body]));
    const real = sign(good());
    const forged = real.split(".")[0] + "." + b64u(JSON.stringify(Object.assign(good(), { user_id: OTHER_TUID })));
    r2 = await invoke("POST", DD, { body: { signed_request: forged } });
    const noSig = await invoke("POST", DD, { body: { signed_request: real.split(".")[1] } });
    check("M5. a payload changed after signing, or no signature part, is refused; nothing deleted", r2.statusCode === 400 && r2.body.code === "bad_signature" && noSig.statusCode === 400 && snap() === before, JSON.stringify([r2.body, noSig.body]));
    check("M6. the signature is compared in constant time (crypto.timingSafeEqual)", FILES.routes.indexOf("!crypto.timingSafeEqual(got, want)") !== -1);
    r2 = await invoke("POST", DD, { body: { signed_request: sign(Object.assign(good(), { algorithm: "none" })) } });
    const badUid = await invoke("POST", DD, { body: { signed_request: sign(Object.assign(good(), { user_id: "u1; drop" })) } });
    check("M7. an algorithm other than HMAC-SHA256, or a user_id that is not digits, is refused", r2.statusCode === 400 && r2.body.code === "algorithm" && badUid.statusCode === 400 && badUid.body.code === "user_id" && snap() === before,
      JSON.stringify([r2.body, badUid.body]));
    const old = await invoke("POST", DD, { body: { signed_request: sign(Object.assign(good(), { issued_at: nowS() - TR.SIGNED_MAX_AGE_S - 60 })) } });
    const ahead = await invoke("POST", DD, { body: { signed_request: sign(Object.assign(good(), { issued_at: nowS() + 3600 })) } });
    check("M8. a replay older than a day, or an issued_at an hour ahead, is refused as stale; nothing deleted", old.statusCode === 400 && old.body.code === "stale" && ahead.statusCode === 400 && ahead.body.code === "stale" && snap() === before,
      JSON.stringify([old.body, ahead.body]));
    const early = await invoke("POST", DD, { body: { signed_request: sign(Object.assign(good(), { issued_at: nowS() - 7200 })) } });
    check("M9. a request issued before the member's current connection was made deletes nothing (a replay cannot remove a reconnect)",
      early.statusCode === 200 && snap() === before, JSON.stringify([early.statusCode, early.body]));

    r1 = await invoke("POST", DE, { body: { signed_request: sign(good()) } });
    check("M10. deauthorize, correctly signed: 200 { ok: true }; only that member's connection is gone, their leads and replies stay",
      r1.statusCode === 200 && r1.body && r1.body.ok === true && r1.headers["cache-control"] === "no-store" &&
      JSON.stringify(DB.threads_connections.map(function (x) { return x.user_id; })) === JSON.stringify([U2]) && DB.member_leads.length === 3 && DB.member_lead_replies.length === 3, JSON.stringify([r1.statusCode, r1.body, snap()]));

    seed();
    r2 = await invoke("POST", DD, { body: { signed_request: sign(good()) } });
    const codeOk = r2.body && typeof r2.body.confirmation_code === "string" ? r2.body.confirmation_code : "";
    check("M11. data-deletion, correctly signed: the member's Threads leads, Threads replies and connection are deleted; their Bluesky rows and the other member's stay",
      r2.statusCode === 200 && JSON.stringify(DB.threads_connections.map(function (x) { return x.user_id; })) === JSON.stringify([U2]) &&
      JSON.stringify(DB.member_leads.map(function (x) { return x.id; })) === JSON.stringify(["l2", "l3"]) && JSON.stringify(DB.member_lead_replies.map(function (x) { return x.id; })) === JSON.stringify(["r2", "r3"]), snap());
    check("M12. the answer is Meta's shape: { url: FRONTEND/threads-deletion.html?code=<code>, confirmation_code: <code> }; the code holds no personal data",
      r2.body && Object.keys(r2.body).sort().join(",") === "confirmation_code,url" && r2.body.url === FRONT + "/threads-deletion.html?code=" + codeOk &&
      /^td-[0-9a-z]{1,10}-[0-9a-f]{20}$/.test(codeOk) && codeOk.indexOf(TUID) === -1 && codeOk.indexOf(U1.slice(0, 8)) === -1, JSON.stringify(r2.body));
    let st = await invoke("GET", DS, { query: { code: codeOk } });
    const flipped = codeOk.slice(0, -1) + (codeOk.slice(-1) === "0" ? "1" : "0");
    const stBad = await invoke("GET", DS, { query: { code: flipped } });
    const stNone = await invoke("GET", DS, { query: {} });
    check("M13. the deletion page's lookup: the real code is done at the deletion's time; a changed code or none is not found",
      st.statusCode === 200 && st.body.found === true && st.body.done === true && st.body.at === new Date(nowS() * 1000).toISOString() &&
      stBad.statusCode === 404 && stBad.body.found === false && stNone.statusCode === 404, JSON.stringify([st.body, stBad.statusCode, stNone.statusCode]));
    const again = await invoke("POST", DD, { body: { signed_request: sign(good()) } });
    check("M14. a second request for a member already deleted: 200 with a code, nothing else touched", again.statusCode === 200 && /^td-/.test(again.body.confirmation_code) &&
      DB.member_leads.length === 2 && DB.threads_connections.length === 1);

    seed();
    FAIL_DELETE = "member_leads";
    r2 = await invoke("POST", DD, { body: { signed_request: sign(good()) } });
    FAIL_DELETE = null;
    check("M15. a failed delete: 500 and no confirmation code; the connection stays so Meta's next try can finish",
      r2.statusCode === 500 && !(r2.body && r2.body.confirmation_code) && DB.threads_connections.some(function (x) { return x.user_id === U1; }), JSON.stringify([r2.statusCode, r2.body]));
    const logged = LOGS.join("\n");
    check("M16. nothing logs a signed_request, a Threads user id or a code", logged.indexOf(TUID) === -1 && logged.indexOf(codeOk) === -1 && logged.indexOf(sign(good()).split(".")[0]) === -1);

    const saved = Object.assign({}, ENV);
    delete ENV.THREADS_APP_SECRET;
    seed(); before = snap();
    const ns = [await invoke("POST", DE, { body: { signed_request: sign(good()) } }), await invoke("POST", DD, { body: { signed_request: sign(good()) } }), await invoke("GET", DS, { query: { code: codeOk } })];
    Object.assign(ENV, saved);
    check("M17. while Threads is not set up, all three answer 503 and nothing is deleted", ns.every(function (x) { return x.statusCode === 503; }) && snap() === before, ns.map(function (x) { return x.statusCode; }).join(","));

    const pg = FILES.page;
    check("M18. threads-deletion.html: noindex, in no sitemap, the site's styles, reads ?code= and asks the deletion-status route",
      pg.indexOf("<meta name=\"robots\" content=\"noindex\"/>") !== -1 && FILES.sitemaps.indexOf("threads-deletion") === -1 &&
      pg.indexOf("/api/social/threads/deletion-status?code=") !== -1 && pg.indexOf("get('code')") !== -1 && pg.indexOf("BF-SCROLLBARS:BEGIN") !== -1 &&
      pg.indexOf("data-bf-legal-footer") !== -1 && pg.indexOf("font-family:system-ui") !== -1);
    check("M19. the page writes the server's answer as fixed text only (the date is formatted, never the raw body)",
      pg.indexOf("d.error") === -1 && pg.indexOf("innerHTML = html") !== -1 && pg.indexOf("new Date(d.at)") !== -1);
  }


  /* ── Z. zero network ─────────────────────────────────────────────────── */
  OUT("\n== Z. zero network ==");
  check("Z1. no socket and no DNS lookup", NETWORK.length === 0, NETWORK.join(", "));
  check("Z2. no unhandled rejection", UNHANDLED.length === 0, UNHANDLED.map(String).join(" | "));

  OUT("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (failures + passes) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
})().catch(function (err) {
  OUT("    FAIL  the check itself threw: " + (err && err.stack ? err.stack.split("\n").slice(0, 3).join(" / ") : err));
  process.exit(1);
});
