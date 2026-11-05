"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkMastodonConnect — a member connects their OWN Mastodon account with a
   personal access token, and the Social agent posts to it, through the
   approval gate or the member's own "Post approved drafts automatically".

   server.js's six /api/social/mastodon/* routes, POST /api/proposals and the
   publish_mastodon_post executor are lifted and run in a vm against an
   in-memory Supabase that enforces migration 165's CHECKs (the host, account
   id and acct patterns, hex-only ciphertext, iv and tag, the two ranges, one
   row per member). lib/memberMastodon.js runs for real, and so does
   lib/guardedFetch.js's JSON mode: only its DNS resolver and its request
   function are stand-ins, so every guard (https on 443, every address
   checked, no redirect followed, 1 MB at most) is the real one. Behind the
   stand-in request is a stub Mastodon that records every request. Nothing
   leaves the machine: every socket and DNS lookup is a tripwire, and no model
   is called.

   WHAT THIS PROVES
     P. Migration 165: the 18 columns, every CHECK, RLS on with no policy, the
        setting log's platform CHECK; 165 is the highest migration and used
        once; lib/memberMastodon.js's three patterns equal the SQL's.
     N. normalizeInstance: good hosts kept, lowercased; http, IP literals,
        localhost, single labels, ports, paths, credentials and non-ASCII
        refused (the last with the xn-- message).
     T. The token shape, and its help text.
     A. Connect: the token is sealed BEFORE the server is asked (no key, no
        request), never in a response, a log line or the database in the
        clear; one row per member; the limiter numbers and middleware.
     V. verify's two calls: verify_credentials with the token, the instance
        rules WITHOUT it; 500 and 23 when the rules are missing or out of range.
     C. A refused token, a rate limit, no answer, a redirect, a body over 1 MB,
        a private address and a non-JSON answer each store nothing; classify.
     B. The back-off: no request while it is in force, cleared on success,
        and separate from Bluesky's in both directions.
     D. Status and disconnect (with its note), only the caller's row.
     U. Automation, as Bluesky's: off by default, logged, per member, gated.
     F. propose-post: 403 for anyone unconnected, the owner included; the
        count (links at least the reserved length) and the claims screen;
        never posted unless auto_post; posted at once when it is on.
     E. The executor: re-validation, Idempotency-Key = the draft id, replay,
        one attempt, and 401 to needs_reconnect with exactly one notice.
     S. MASTODON_ACCESS_TOKEN is never read on a member or Social path.
     K. countForMastodon is never below Mastodon's own count (property tests
        over links, emoji and combining marks), and the Social agent uses it.
     X. Export and backup.
     J. The pages: the card's labels, textContent only, the token field
        cleared; the filing line; the proposals card.
     L. Privacy and Terms, word for word, in lib/legalPages.js and the pages.
     G. The guide tip.
     Z. Zero network.

   MUTATE=<name> edits the source in memory (nothing on disk changes).
   MUTATE=all runs each in its own process and passes only if every one fails
   at least one check. A mutation whose search text does not match exactly
   once is an ERROR, never counted as caught.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const net = require("net");
const dns = require("dns");
const { EventEmitter } = require("events");
const { PassThrough } = require("stream");
const Module = require("module");
const s = require("./_shared");

/* ── the network tripwire, before anything can open a socket ──────────────── */
const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkMastodonConnect: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkMastodonConnect: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const MUTATIONS = {
  // the token is stored as typed
  "plaintext-token-stored": [["SRC", "          token_ciphertext:            sealed.ciphertext,\n", "          token_ciphertext:            token.value,\n"]],
  // the token comes back in the connect response
  "token-in-response": [["SRC", "      return res.json(mm.statusOf(saved.data));\n",
    "      return res.json(Object.assign(mm.statusOf(saved.data), { access_token: token.value }));\n"]],
  // the token is written to the server log
  "token-logged": [["SRC", "      var verified = await mm.verify(host, token.value);\n",
    "      console.log(\"[social/mastodon/connect] verifying \" + host + \" with \" + token.value);\n      var verified = await mm.verify(host, token.value);\n"]],
  // an http:// server address is accepted
  "http-instance-allowed": [["MM", String.raw`  if (/^https:\/\//i.test(s)) s = s.slice(8);` + "\n",
    String.raw`  if (/^https?:\/\//i.test(s)) s = s.replace(/^https?:\/\//i, "");` + "\n"]],
  // an IP literal is accepted as a server
  "ip-literal-allowed": [["MM", "  if (net.isIP(s)) return null;\n", "  if (net.isIP(s)) return s;\n"]],
  // a name that resolves to a private address is connected to
  "private-address-allowed": [["GF", "            const verdict = isBlockedAddress(a.address);\n", "            const verdict = null;\n"]],
  // the JSON mode follows a redirect
  "redirect-followed": [["GF", "          if (json && status >= 300 && status < 400) {\n", "          if (false) {\n"]],
  // the JSON mode reads a body of any size
  "no-size-limit": [["GF", "          if (json && isFinite(declared) && declared > json.limit) {\n", "          if (false) {\n"],
    ["GF", "            if (json && bytes > json.limit) {\n", "            if (false) {\n"]],
  // filing posts at once with automation off
  "posts-without-approval": [["SRC", "      if (proposal.payload.posts_as.automatic === true) {\n        var auto = await autoExecuteFiledProposal(proposal, executePublishMastodonPost);\n",
    "      if (true) {\n        var auto = await autoExecuteFiledProposal(proposal, executePublishMastodonPost);\n"]],
  // automation skips the claims screen, at filing and in the executor
  "automation-skips-claims": [
    ["SRC", "      var mastoClaims = blueskyClaimsRefusal(text);\n", "      var mastoClaims = row.auto_post === true ? null : blueskyClaimsRefusal(text);\n"],
    ["SRC", "  var mastoClaimsRefused = blueskyClaimsRefusal(text);\n",
      "  var mastoClaimsRefused = payload.posts_as && payload.posts_as.automatic === true ? null : blueskyClaimsRefusal(text);\n"]],
  // a link counts only its own length, so a short one counts under Mastodon's 23
  "count-undercounts-links": [["MM", "      total += Math.max(link.length, reserved) + (m[0].length - link.length);\n",
    "      total += link.length + (m[0].length - link.length);\n"]],
  // the post request carries no Idempotency-Key
  // NAMED (Nov 5 2026, images in social posts): BEFORE the anchor was the one-line post with the body inline. AFTER the body is
  // built first (statusBody, media_ids only with images), so the anchor is the post line that sends it; the mutation is the same.
  "idempotency-key-missing": [["MM", "  var made = await client.post(\"/api/v1/statuses\", statusBody, { \"Idempotency-Key\": idempotencyKey });\n",
    "  var made = await client.post(\"/api/v1/statuses\", statusBody, {});\n"]],
  // a published draft is posted again
  "replay-posts-again": [["SRC", "  var mastoPublished = draft.status === \"published\" && !!draft.platform_post_uri;\n", "  var mastoPublished = false;\n"],
    ["SRC", "  var mastoPending = draft.status === \"pending_approval\";\n", "  var mastoPending = draft.status === \"pending_approval\" || draft.status === \"published\";\n"]],
  // a member's post goes out with the platform's outreach token
  "platform-token-for-member": [["SRC", "  var outcome = await mm.withToken(row, require(\"./lib/apiKeyCrypto\").decrypt, function (client) {\n",
    "  var outcome = await mm.withToken(row, function () { return process.env.MASTODON_ACCESS_TOKEN; }, function (client) {\n"]],
  // a refused token is tried again
  "retry-on-401": [["MM", "    var value = await fn(makeClient(host, function () { return token; }));\n",
    "    var value;\n    try { value = await fn(makeClient(host, function () { return token; })); }\n    catch (first) { value = await fn(makeClient(host, function () { return token; })); }\n"]],
  // the needs_reconnect mark is not conditional, so every failure notifies again
  "notice-every-failure": [["SRC", "      .eq(\"user_id\", userId)\n      .eq(\"status\", \"connected\")\n      .select(\"id\");\n",
    "      .eq(\"user_id\", userId)\n      .select(\"id\");\n"]],
  // the export reads every column of the connection
  "export-leaks-token": [["YD", "    owner: [\"user_id\"], key: \"instance_host\", select: \"instance_host, acct, created_at\", onDelete: \"delete\" },\n",
    "    owner: [\"user_id\"], key: \"instance_host\", onDelete: \"delete\" },\n"]],
  // Mastodon shares Bluesky's back-off
  "bluesky-backoff-shared": [["MM", "const api = {\n  // Every request: lib/guardedFetch.js's JSON mode, unless a check replaces it.\n",
    "backoffUntil = require(\"./memberBluesky\").backoffUntil;\nnoteRateLimit = require(\"./memberBluesky\").noteRateLimit;\nclearBackoff = require(\"./memberBluesky\").clearBackoff;\n" +
    "const api = {\n  // Every request: lib/guardedFetch.js's JSON mode, unless a check replaces it.\n"]],
  // a token the server refused is stored anyway
  "stored-without-verify": [["SRC", "      if (!verified.ok) {\n        if (verified.kind === \"rejected\") {\n          return res.status(400).json({ error: mm.MESSAGES.rejected",
    "      if (!verified.ok && verified.kind === \"rejected\") verified = { ok: true, account_id: \"1\", acct: \"unverified\", max_characters: 500, characters_reserved_per_url: 23 };\n" +
    "      if (!verified.ok) {\n        if (verified.kind === \"rejected\") {\n          return res.status(400).json({ error: mm.MESSAGES.rejected"]],
  // the Privacy page loses the Mastodon sentence
  "privacy-sentence-removed": [["FE:privacy.html", "If you connect your Mastodon account, BizForce stores your server&#39;s address", "BizForce stores"]],
  // the card writes a server message as markup
  "innerHTML-on-page": [["FE:scripts/mastodon-connect.js", "    node.textContent = text || \"\";\n", "    node.innerHTML = text || \"\";\n"]],
  // added: the owner, unconnected, falls back to the platform's outreach token
  "owner-platform-fallback": [["SRC", "  if (!read.data) return { kind: \"none\" };\n",
    "  if (!read.data) return process.env.MASTODON_ACCESS_TOKEN ? { kind: \"member\", row: { id: \"platform\", user_id: userId, instance_host: \"mastodon.social\", account_id: \"1\", acct: \"platform\", status: \"connected\", auto_post: false } } : { kind: \"none\" };\n"]],
  // added: a proposal filed as one account posts from whichever is connected now
  "posts-as-unchecked": [["SRC", "  if (filedAs.account !== \"member\" || filedAs.acct !== row.acct || filedAs.host !== row.instance_host) {\n", "  if (false) {\n"]],
  // added: the token is sent to the instance rules, which need none
  "instance-read-with-token": [["MM", "    var info = await makeClient(host, null).get(\"/api/v2/instance\");\n",
    "    var info = await makeClient(host, function () { return token; }).get(\"/api/v2/instance\");\n"]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const clone = v => v === undefined ? undefined : JSON.parse(JSON.stringify(v));
const lf = t => t.replace(/\r\n/g, "\n");

/* ── the sources, mutated in memory ───────────────────────────────────────── */
const SOURCES = {
  SRC: lf(fs.readFileSync(path.join(REPO, "server.js"), "utf8")),
  MM: lf(fs.readFileSync(path.join(REPO, "lib/memberMastodon.js"), "utf8")),
  GF: lf(fs.readFileSync(path.join(REPO, "lib/guardedFetch.js"), "utf8")),
  YD: lf(fs.readFileSync(path.join(REPO, "lib/yourData.js"), "utf8"))
};
const FE_FILES = ["agents/social.html", "proposals.html", "scripts/mastodon-connect.js", "scripts/social-publish.js", "scripts/termaximus-guide.js",
  "privacy.html", "terms.html"];
FE_FILES.forEach(f => { SOURCES["FE:" + f] = lf(fs.readFileSync(path.join(FRONTEND, f), "utf8")); });
const MIGRATION = lf(fs.readFileSync(path.join(REPO, "supabase/migrations/165_member_mastodon_connections.sql"), "utf8"));
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [where, from, to] of edits) SOURCES[where] = s.replaceOnce(SOURCES[where], from, to, MUTATE + " in " + where);
  console.log("\n!! MUTATION: " + MUTATE);
}
const SRC = SOURCES.SRC;
const FE = f => SOURCES["FE:" + f];

/* A lib file compiled from its (possibly mutated) text, requiring its own siblings from disk. */
function loadLib(rel, text) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(text, file);
  return m.exports;
}
const TEST_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
process.env.ENCRYPTION_SECRET = TEST_KEY;
const CRYPTO = require(path.join(REPO, "lib/apiKeyCrypto.js"));
const MB = require(path.join(REPO, "lib/memberBluesky.js"));
const GF = loadLib("lib/guardedFetch.js", SOURCES.GF);
const MM = loadLib("lib/memberMastodon.js", SOURCES.MM);
const YDATA = loadLib("lib/yourData.js", SOURCES.YD);

/* ── the stub Mastodon, behind lib/guardedFetch.js's real JSON mode ────────
   Test tokens only: none of these is a real credential. Each is the shape
   Mastodon makes (letters, digits, _ and -). */
const TOK = {
  alice: "aliceTestToken_0123456789abcdefghijklmnopq",
  bob: "bobTestToken_0123456789abcdefghijklmnopqrs",
  owner: "ownerTestToken_0123456789abcdefghijklmnop",
  carol: "carolTestToken_0123456789abcdefghijklmnop",
  platform: "platformOutreachToken_0123456789abcdefghij"
};
const PUBLIC = "93.184.216.34";
const STUB = {
  names: {
    "mastodon.social": PUBLIC, "fosstodon.org": PUBLIC, "noinfo.example": PUBLIC, "badinfo.example": PUBLIC,
    "redirect.example": PUBLIC, "big.example": PUBLIC, "html.example": PUBLIC, "private.example": "10.0.0.5"
  },
  accounts: {
    "mastodon.social": { [TOK.alice]: { id: "109000000000000001", username: "alice" }, [TOK.owner]: { id: "5", username: "owner" },
      [TOK.carol]: { id: "77", username: "carol" }, [TOK.platform]: { id: "1", username: "platform" } },
    "fosstodon.org": { [TOK.bob]: { id: "2", username: "bob" } },
    "noinfo.example": { [TOK.carol]: { id: "78", username: "carol" } },
    "badinfo.example": { [TOK.carol]: { id: "79", username: "carol" } },
    "private.example": { [TOK.carol]: { id: "80", username: "carol" } },
    "big.example": { [TOK.carol]: { id: "81", username: "carol" } }
  },
  rules: { "mastodon.social": { max_characters: 500, characters_reserved_per_url: 23 }, "fosstodon.org": { max_characters: 1000, characters_reserved_per_url: 23 },
    "badinfo.example": { max_characters: 0, characters_reserved_per_url: 5000 } },
  seen: [], statuses: [], keys: {}, verifyMode: null, postMode: null,
  reset() { this.seen = []; this.statuses = []; this.keys = {}; this.verifyMode = null; this.postMode = null; }
};
const json = (status, body, headers) => ({ status, headers: Object.assign({ "content-type": "application/json; charset=utf-8" }, headers || {}), body: Buffer.from(JSON.stringify(body)) });
function bearer(headers) {
  const v = headers.Authorization || headers.authorization;
  return typeof v === "string" && v.indexOf("Bearer ") === 0 ? v.slice(7) : null;
}
function serve(q) {
  const tok = bearer(q.headers);
  if (q.host === "redirect.example") return { status: 302, headers: { location: "https://mastodon.social" + q.path, "content-type": "text/html" }, body: Buffer.from("") };
  if (q.host === "html.example") return { status: 200, headers: { "content-type": "text/html" }, body: Buffer.from("<html><title>x</title></html>") };
  if (q.path === "/api/v1/accounts/verify_credentials" && q.method === "GET") {
    if (STUB.verifyMode === "rate") return json(429, { error: "Too many requests" }, { "retry-after": "60" });
    if (STUB.verifyMode === "down") return json(503, { error: "down" });
    const acct = (STUB.accounts[q.host] || {})[tok];
    if (!acct) return json(401, { error: "The access token is invalid" });
    if (q.host === "big.example") return json(200, Object.assign({ pad: "x".repeat(2 * 1024 * 1024) }, acct, { acct: acct.username }));
    return json(200, Object.assign({}, acct, { acct: acct.username, display_name: acct.username }));
  }
  if (q.path === "/api/v2/instance" && q.method === "GET") {
    const rules = STUB.rules[q.host];
    if (!rules) return json(404, { error: "Record not found" });
    return json(200, { domain: q.host, configuration: { statuses: Object.assign({ max_media_attachments: 4 }, rules) } });
  }
  if (q.path === "/api/v1/statuses" && q.method === "POST") {
    const acct = (STUB.accounts[q.host] || {})[tok];
    if (!acct) return json(401, { error: "The access token is invalid" });
    if (STUB.postMode === "rate") return json(429, { error: "Too many requests" }, { "retry-after": "120" });
    if (STUB.postMode === "error") return json(500, { error: "Internal error" });
    if (STUB.postMode === "revoked") return json(401, { error: "The access token was revoked" });
    const key = q.headers["Idempotency-Key"];
    if (key && STUB.keys[q.host + " " + key]) return json(200, STUB.keys[q.host + " " + key]);
    const id = String(110000000000000000 + STUB.statuses.length + 1);
    const made = STUB.postMode === "foreign"
      ? { id, url: "https://elsewhere.example/@" + acct.username + "/" + id, uri: "https://elsewhere.example/users/" + acct.username + "/statuses/" + id }
      : { id, url: "https://" + q.host + "/@" + acct.username + "/" + id, uri: "https://" + q.host + "/users/" + acct.username + "/statuses/" + id };
    STUB.statuses.push({ host: q.host, acct: acct.username, token: tok, body: JSON.parse(q.body), key: key, made });
    if (key) STUB.keys[q.host + " " + key] = made;
    return json(200, Object.assign({ visibility: "public", content: "<p>…</p>" }, made));
  }
  return json(404, { error: "Not found" });
}
function fakeResolve(hostname, options, cb) {
  const address = STUB.names[hostname];
  if (!address) { const e = new Error("getaddrinfo ENOTFOUND " + hostname); e.code = "ENOTFOUND"; return cb(e); }
  return cb(null, [{ address, family: 4 }]);
}
/* Stands in for https.request: asks the fetcher's OWN lookup where to go, as
   Node would, and answers only if that lookup let it through. */
function fakeRequest(options) {
  const req = new EventEmitter();
  req.destroy = function () {};
  req.end = function (payload) {
    options.lookup(options.hostname, { all: true }, function (err, addresses) {
      if (err) return setImmediate(() => req.emit("error", err));
      const q = { host: options.hostname, address: addresses[0].address, protocol: options.protocol, port: options.port, agent: options.agent,
        method: options.method, path: options.path, headers: Object.assign({}, options.headers), body: payload ? Buffer.from(payload).toString("utf8") : null };
      STUB.seen.push(q);
      const answer = serve(q);
      const res = new PassThrough();
      res.statusCode = answer.status;
      res.headers = answer.headers;
      setImmediate(() => { req.emit("response", res); res.end(answer.body); });
    });
  };
  return req;
}
MM.api.transport = GF.createGuardedFetch({ resolve: fakeResolve, request: fakeRequest }).json;
const CLOCK = { now: Date.parse("2026-11-03T12:00:00.000Z") };
MM.api.now = () => CLOCK.now;
const seenPath = p => STUB.seen.filter(q => q.path === p);

/* ── the fake database, with migration 165's and 136's CHECKs ─────────────── */
const DRAFT_STATUSES = ["pending", "not_published", "scheduled", "pending_approval", "published", "publish_failed"];
const HOST_SQL = (/instance_host ~ '([^']+)'/.exec(MIGRATION) || [])[1];
const ID_SQL = (/account_id ~ '([^']+)'/.exec(MIGRATION) || [])[1];
const ACCT_SQL = (/\(acct ~ '([^']+)'/.exec(MIGRATION) || [])[1];
function violates(table, row) {
  if (table === "member_mastodon_connections") {
    const host = String(row.instance_host);
    if (host.length < 4 || host.length > 253 || !new RegExp(HOST_SQL).test(host)) return "member_mastodon_connections_host_check";
    if (!new RegExp(ID_SQL).test(String(row.account_id))) return "member_mastodon_connections_account_id_check";
    if (!new RegExp(ACCT_SQL).test(String(row.acct))) return "member_mastodon_connections_acct_check";
    if (!/^[0-9a-f]+$/.test(String(row.token_ciphertext))) return "member_mastodon_connections_ciphertext_check";
    if (!/^[0-9a-f]{24}$/.test(String(row.token_iv))) return "member_mastodon_connections_iv_check";
    if (!/^[0-9a-f]{32}$/.test(String(row.token_auth_tag))) return "member_mastodon_connections_auth_tag_check";
    if (!(row.max_characters >= 1 && row.max_characters <= 100000)) return "member_mastodon_connections_max_chars_check";
    if (!(row.characters_reserved_per_url >= 0 && row.characters_reserved_per_url <= 1000)) return "member_mastodon_connections_url_chars_check";
    if (["connected", "needs_reconnect", "disconnected"].indexOf(row.status) === -1) return "member_mastodon_connections_status_check";
    if (row.last_error_code != null && String(row.last_error_code).length > 60) return "member_mastodon_connections_error_code_check";
    if (typeof row.auto_post !== "boolean") return "auto_post not null";
  }
  if (table === "member_social_setting_changes") {
    if (["bluesky", "mastodon"].indexOf(row.platform) === -1 || row.setting !== "auto_post" || typeof row.new_value !== "boolean") return "member_social_setting_changes_platform_check";
  }
  if (table === "social_post_drafts") {
    if (DRAFT_STATUSES.indexOf(row.status) === -1) return "social_post_drafts_status_check";
    if (row.status === "published" && (row.platform_post_uri == null || row.published_at == null)) return "social_post_drafts_published_check";
  }
  return null;
}
const DEFAULTS = {
  member_mastodon_connections: () => ({ status: "connected", auto_post: false, auto_post_changed_at: null, max_characters: 500, characters_reserved_per_url: 23,
    last_ok_at: null, last_error_at: null, last_error_code: null, created_at: "2026-11-03T09:00:00.000Z" }),
  member_social_setting_changes: () => ({ old_value: null }),
  notifications: () => ({ read: false, created_at: "2026-11-03T12:00:00.000Z" })
};
function fakeDb(seed) {
  const db = { tables: {}, log: [], seq: 0 };
  Object.keys(seed || {}).forEach(t => { db.tables[t] = seed[t].map(clone); });
  const rows = t => db.tables[t] || (db.tables[t] = []);
  function project(row, cols) {
    if (!cols || cols.trim() === "*") return clone(row);
    const out = {};
    cols.split(",").map(c => c.trim()).filter(Boolean).forEach(c => { out[c] = row[c] === undefined ? null : row[c]; });
    return out;
  }
  const keep = (q, r) => q.filters.every(f => f[0] === "eq" ? r[f[1]] === f[2] : f[0] === "neq" ? r[f[1]] !== f[2] : f[0] === "in" ? f[2].indexOf(r[f[1]]) !== -1 : f[0] === "is" ? r[f[1]] === f[2] : true);
  function finish(q, list) {
    const cols = q.op === "select" ? q.cols : q.retCols;
    let out = list;
    if (q.orderKey) out = out.slice().sort((x, y) => (String(x[q.orderKey]) < String(y[q.orderKey]) ? -1 : 1) * (q.asc === false ? -1 : 1));
    if (q.from !== null) out = out.slice(q.from, q.to + 1);
    const data = (q.op === "select" || q.returning) ? out.map(r => project(r, cols)) : null;
    if (q.single === "single") return data && data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116", message: (data ? data.length : 0) + " rows" } };
    if (q.single === "maybe") return data && data.length > 1 ? { data: null, error: { message: "more than one row" } } : { data: data ? data[0] || null : null, error: null };
    return { data: data, error: null };
  }
  function insertOne(table, payload) {
    const row = Object.assign({ id: "00000000-0000-4000-8000-" + String(++db.seq).padStart(12, "0") }, DEFAULTS[table] ? DEFAULTS[table]() : {}, clone(payload));
    const bad = violates(table, row);
    if (bad) return { error: { code: "23514", message: "violates check constraint \"" + bad + "\"" } };
    if (table === "member_mastodon_connections" && rows(table).some(r => r.user_id === row.user_id)) {
      return { error: { code: "23505", message: "duplicate key value violates unique constraint \"member_mastodon_connections_user_id_key\"" } };
    }
    rows(table).push(row);
    return { row };
  }
  function answer(q) {
    db.log.push(q);
    if (q.op === "insert") {
      const list = Array.isArray(q.payload) ? q.payload : [q.payload];
      const made = [];
      for (const p of list) { const r = insertOne(q.table, p); if (r.error) return Promise.resolve({ data: null, error: r.error }); made.push(r.row); }
      return Promise.resolve(finish(q, made));
    }
    if (q.op === "upsert") {
      const keys = String((q.opts && q.opts.onConflict) || "id").split(",");
      const found = rows(q.table).find(r => keys.every(k => r[k] === q.payload[k]));
      if (found) {
        const merged = Object.assign({}, found, clone(q.payload));
        const bad = violates(q.table, merged);
        if (bad) return Promise.resolve({ data: null, error: { code: "23514", message: "violates check constraint \"" + bad + "\"" } });
        Object.assign(found, clone(q.payload));
        return Promise.resolve(finish(q, [found]));
      }
      const r = insertOne(q.table, q.payload);
      if (r.error) return Promise.resolve({ data: null, error: r.error });
      return Promise.resolve(finish(q, [r.row]));
    }
    const hits = rows(q.table).filter(r => keep(q, r));
    if (q.op === "update") {
      for (const r of hits) { const bad = violates(q.table, Object.assign({}, r, q.payload)); if (bad) return Promise.resolve({ data: null, error: { code: "23514", message: bad } }); }
      hits.forEach(r => Object.assign(r, clone(q.payload)));
      return Promise.resolve(finish(q, hits));
    }
    if (q.op === "delete") {
      db.tables[q.table] = rows(q.table).filter(r => hits.indexOf(r) === -1);
      return Promise.resolve(finish(q, hits));
    }
    return Promise.resolve(finish(q, hits));
  }
  function from(table) {
    const q = { table, op: "select", cols: "*", retCols: "*", payload: null, opts: null, filters: [], single: false, returning: false, orderKey: null, asc: true, from: null, to: null };
    const b = {
      select(cols) { if (q.op === "select") q.cols = cols || "*"; else { q.returning = true; q.retCols = cols || "*"; } return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; },
      upsert(p, o) { q.op = "upsert"; q.payload = p; q.opts = o; return b; },
      delete() { q.op = "delete"; return b; },
      eq(c, v) { q.filters.push(["eq", c, v]); return b; },
      neq(c, v) { q.filters.push(["neq", c, v]); return b; },
      in(c, v) { q.filters.push(["in", c, v]); return b; },
      is(c, v) { q.filters.push(["is", c, v]); return b; },
      or() { return b; }, not() { return b; }, gte() { return b; }, lte() { return b; }, lt() { return b; }, gt() { return b; },
      order(k, o) { q.orderKey = k; q.asc = !(o && o.ascending === false); return b; },
      limit(n) { q.from = 0; q.to = n - 1; return b; },
      range(a, z) { q.from = a; q.to = z; return b; },
      single() { q.single = "single"; return answer(q); },
      maybeSingle() { q.single = "maybe"; return answer(q); },
      then(res, rej) { return answer(q).then(res, rej); }
    };
    return b;
  }
  db.client = {
    from,
    async rpc() { return { data: 0, error: null }; },
    storage: { from() { return { async list() { return { data: [], error: null }; }, async remove() { return { data: [], error: null }; } }; } }
  };
  db.rows = rows;
  db.writes = () => db.log.filter(q => q.op !== "select");
  return db;
}

/* ── server.js, lifted ────────────────────────────────────────────────────── */
const SPANS = [];
{
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(SRC))) { const end = s.braceMatch(SRC, SRC.indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
}
/* One pass over server.js: where each top-level function and declaration
   starts (the first of each name, as a regex search would find it). */
const FN_AT = new Map(), DECL_AT = new Map();
{
  let m;
  const fre = /^(?:async )?function ([A-Za-z_$][A-Za-z0-9_$]*)\(/gm;
  while ((m = fre.exec(SRC))) if (!FN_AT.has(m[1])) FN_AT.set(m[1], m.index);
  const dre = /^(?:var|const|let) ([A-Za-z_$][A-Za-z0-9_$]*)[ \t]*=[ \t]*/gm;
  while ((m = dre.exec(SRC))) {
    const at = m.index;
    if (!DECL_AT.has(m[1]) && !SPANS.some(([x, y]) => at > x && at < y)) DECL_AT.set(m[1], { index: at, length: m[0].length });
  }
}
function definitionOf(name) {
  if (FN_AT.has(name)) { const at = FN_AT.get(name); return SRC.slice(at, s.braceMatch(SRC, SRC.indexOf(") {", at) + 2)); }
  const d = DECL_AT.get(name);
  if (!d) return null;
  const m = { index: d.index, 0: { length: d.length } };
  const brk = /;\n/g; brk.lastIndex = m.index + m[0].length;
  let b;
  while ((b = brk.exec(SRC))) {
    const next = SRC[b.index + b[0].length];
    if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SRC.slice(m.index, b.index + 1);
  }
  return null;
}
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout", "fetch",
  "requireAuth", "requireActiveSubscription", "aiLimiter", "bskyGate", "RichText", "rateLimit", "refuseUnlessSubscribed", "anthropic", "Anthropic"]);
// The rule the brief sets: // starts a comment only when no ":" (nor a quote or backslash) is right before it.
const uncommented = code => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closureParts(root) {
  const have = new Map();
  const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOf(name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(uncommented(def).match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return have;
}
function closure(root) {
  return [...closureParts(root).values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
}
function routeText(method, route) {
  const sig = "app." + method + "(\"" + route + "\"";
  const start = SRC.indexOf(sig);
  if (start < 0) throw new Error(method.toUpperCase() + " " + route + " not found");
  if (SRC.indexOf(sig, start + 1) !== -1) throw new Error(method.toUpperCase() + " " + route + " is defined twice");
  const end = s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("function (req, res, next)", start)));
  if (SRC.slice(end, end + 2) !== ");") throw new Error(method.toUpperCase() + " " + route + " did not end where expected");
  return SRC.slice(start, end + 2);
}
const R = {
  connect: ["post", "/api/social/mastodon/connect"], status: ["get", "/api/social/mastodon/status"],
  disconnect: ["post", "/api/social/mastodon/disconnect"], autoGet: ["get", "/api/social/mastodon/automation"],
  autoPut: ["put", "/api/social/mastodon/automation"], propose: ["post", "/api/social/mastodon/propose-post"],
  proposals: ["post", "/api/proposals"]
};
const API_ROOT = "\n\nthis.api = { executePublishMastodonPost: executePublishMastodonPost, recordMastodonSession: recordMastodonSession," +
  " mastodonPostingAccount: mastodonPostingAccount, measureSocialPost: measureSocialPost, SOCIAL_PLATFORMS: SOCIAL_PLATFORMS, mastodonSpecFor: mastodonSpecFor };";
let LIFTED, MEMBER_PATHS, MEMBER_PARTS;
try {
  // Every member and Social path: the Mastodon routes and executor, the Social agent's post route, and all they call.
  // Lifted once; the vm runs the same text (the Social post route is mounted and never hit, so no model is called).
  const root = Object.keys(R).map(k => routeText(R[k][0], R[k][1])).join("\n\n") + "\n\n" + routeText("post", "/api/agents/social/post") + API_ROOT;
  MEMBER_PARTS = closureParts(root);
  LIFTED = MEMBER_PATHS = [...MEMBER_PARTS.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
} catch (e) {
  console.log("    FAIL  the routes could not be lifted from server.js: " + e.message);
  process.exit(1);
}

const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";
const ALICE = "bbbbbbbb-0000-4000-8000-000000000002";
const BOB = "cccccccc-0000-4000-8000-000000000003";
const PLAIN = "dddddddd-0000-4000-8000-000000000004";
const tid = n => "11111111-0000-4000-8000-" + String(n).padStart(12, "0");
const POST = "Saturday wheel class at 10am, two seats left: https://example.com/classes";
const CLAIM = "Our new clay tea treats diabetes, naturally.";
// 493 by String.length, 504 with the short link counted as Mastodon's 23: over 500, under fosstodon's 1000.
const LINKY = "x".repeat(480) + " https://a.co";
const runOutput = (post, platform) => ({ success: true, platform: platform || "mastodon", platform_label: "Mastodon", post: post, hook_note: "Leads with the day." });
const task = (n, user, post, platform) => ({ id: tid(n), user_id: user, agent_type: "social", task_type: "social/post", status: "completed", output: runOutput(post, platform) });
function seed() {
  return {
    users: [{ id: OWNER, role: "admin" }, { id: ALICE, role: "user" }, { id: BOB, role: "user" }, { id: PLAIN, role: "user" }],
    ai_tasks: [task(1, ALICE, POST), task(2, BOB, POST), task(3, OWNER, POST), task(4, PLAIN, POST), task(5, ALICE, CLAIM),
      task(6, ALICE, LINKY), task(7, ALICE, POST + " (second)"), task(8, ALICE, POST + " (third)"), task(9, ALICE, POST, "bluesky"),
      task(10, BOB, LINKY), task(11, ALICE, POST + " (fourth)"), task(12, ALICE, POST + " (fifth)"), task(13, BOB, POST + " (second)")],
    social_post_drafts: [], agent_proposals: [], member_mastodon_connections: [], member_social_setting_changes: [], notifications: []
  };
}

const LOGS = [];
function build(seedTables) {
  const db = fakeDb(seedTables || seed());
  const limiters = [];
  const state = { unsubscribed: false };
  const logTo = function () { LOGS.push([].slice.call(arguments).map(String).join(" ")); };
  const ctx = {
    supabase: db.client, Date, JSON, Math, Promise, Number, Object, Array, String, Intl, Buffer, RegExp, Error, TypeError, Set, Map,
    nowIso: () => "2026-11-03T12:00:00.000Z",
    // The platform's outreach token is set, so any path that read it would show.
    process: { env: { MASTODON_ACCESS_TOKEN: TOK.platform } },
    require: p => p === "./lib/memberMastodon" ? MM : p === "./lib/apiKeyCrypto" ? CRYPTO : p === "./lib/guardedFetch" ? GF :
      require(p.indexOf("./") === 0 ? path.join(REPO, p) : p),
    fetch: async (u) => { NETWORK.push("fetch " + u); throw new Error("no network"); },
    console: { log: logTo, error: logTo, warn: logTo, info: logTo },
    setImmediate, setTimeout, clearTimeout, AsyncLocalStorage: require("async_hooks").AsyncLocalStorage,
    requireAuth: function requireAuth() {}, requireActiveSubscription: function requireActiveSubscription() {}, aiLimiter: function aiLimiter() {},
    rateLimit: function (o) { limiters.push(o); return function mastodonConnectLimiter() {}; },
    refuseUnlessSubscribed: async function (req, res) { if (state.unsubscribed) { res.status(402).json({ error: "subscribe" }); return true; } return false; }
  };
  const routes = {};
  const mount = method => function (p) { routes[method + " " + p] = { handler: arguments[arguments.length - 1], middleware: [].slice.call(arguments, 1, -1).map(f => f.name) }; };
  ctx.app = { post: mount("post"), put: mount("put"), get: mount("get") };
  vm.createContext(ctx);
  vm.runInContext(LIFTED, ctx);
  async function hit(key, user, body) {
    const [method, route] = R[key];
    const res = { code: 200, body: null, status(x) { this.code = x; return this; }, json(x) { this.body = clone(x); return this; } };
    const role = (db.rows("users").find(u => u.id === user) || {}).role || "user";
    await routes[method + " " + route].handler({ user: { id: user, role: role }, body: body || {}, params: {}, query: {} }, res, e => { res.error = e; res.code = 500; res.body = { error: String(e && e.message || e) }; });
    return res;
  }
  // approve: what POST /api/proposals/:id/approve does: claim, then the executor.
  async function approve(proposal) {
    try { return { result: await ctx.api.executePublishMastodonPost(clone(Object.assign({}, proposal, { status: "executing" }))) }; } catch (e) { return { error: e }; }
  }
  return { db, ctx, routes, hit, approve, limiters, state };
}
async function connected(b, user, instance, token) {
  const r = await b.hit("connect", user, { instance: instance, access_token: token });
  if (r.code !== 200) throw new Error("could not connect " + instance + ": " + r.code + " " + JSON.stringify(r.body));
  return r;
}
const conn = (b, user) => b.db.rows("member_mastodon_connections").find(r => r.user_id === user);
const everything = b => JSON.stringify(b.db.tables);
const noTokenIn = text => Object.keys(TOK).every(k => String(text).indexOf(TOK[k]) === -1);
const masked = row => row && Object.assign({}, row, { token_ciphertext: "…", token_iv: "…", token_auth_tag: "…" });

(async function main() {
  /* ── P. the migration ───────────────────────────────────────────────────── */
  console.log("\n══ P. migration 165 ══");
  const sql = MIGRATION.replace(/--[^\n]*/g, "");
  const COLUMNS = ["id", "user_id", "instance_host", "account_id", "acct", "token_ciphertext", "token_iv", "token_auth_tag", "max_characters",
    "characters_reserved_per_url", "status", "auto_post", "auto_post_changed_at", "last_ok_at", "last_error_at", "last_error_code", "created_at", "updated_at"];
  const body = (/CREATE TABLE public\.member_mastodon_connections \(([\s\S]*?)\n\);/.exec(sql) || ["", ""])[1];
  const declared = body.split("\n").map(l => (/^  ([a-z_]+) (uuid|text|integer|boolean|timestamptz)\b/.exec(l) || [])[1]).filter(Boolean);
  check("P1. member_mastodon_connections has exactly the 18 columns, in order", JSON.stringify(declared) === JSON.stringify(COLUMNS), declared.join(","));
  check("P2. one row per member (user_id UNIQUE, cascading), auto_post default false, status default connected, 500 and 23 by default",
    /user_id uuid NOT NULL UNIQUE REFERENCES public\.users\(id\) ON DELETE CASCADE/.test(body) && /auto_post boolean NOT NULL DEFAULT false/.test(body) &&
    /status text NOT NULL DEFAULT 'connected'/.test(body) && /max_characters integer NOT NULL DEFAULT 500/.test(body) &&
    /characters_reserved_per_url integer NOT NULL DEFAULT 23/.test(body));
  check("P3. ciphertext, iv and tag are lowercase hex only, so a token (it has _ and letters past f) cannot be stored as typed",
    /token_ciphertext ~ '\^\[0-9a-f\]\+\$'/.test(body) && /token_iv ~ '\^\[0-9a-f\]\{24\}\$'/.test(body) && /token_auth_tag ~ '\^\[0-9a-f\]\{32\}\$'/.test(body) &&
    !/^[0-9a-f]+$/.test(TOK.alice));
  check("P4. the ranges (1 to 100000 characters, 0 to 1000 per link), the status values and the error code length",
    /CHECK \(max_characters BETWEEN 1 AND 100000\)/.test(body) && /CHECK \(characters_reserved_per_url BETWEEN 0 AND 1000\)/.test(body) &&
    /CHECK \(status IN \('connected', 'needs_reconnect', 'disconnected'\)\)/.test(body) && /char_length\(last_error_code\) <= 60/.test(body) &&
    /char_length\(instance_host\) BETWEEN 4 AND 253/.test(body));
  check("P5. RLS is enabled and no policy is created",
    /ALTER TABLE public\.member_mastodon_connections ENABLE ROW LEVEL SECURITY;/.test(sql) && !/CREATE POLICY/i.test(sql));
  check("P6. the setting log's platform CHECK becomes bluesky or mastodon, after the old platform CHECKs are dropped",
    /ADD CONSTRAINT member_social_setting_changes_platform_check CHECK \(platform IN \('bluesky', 'mastodon'\)\);/.test(sql) &&
    /DROP CONSTRAINT %I/.test(sql) && /pg_get_constraintdef\(oid\) LIKE '%platform%'/.test(sql));
  check("P7. lib/memberMastodon.js's host, account id and acct patterns equal the SQL's, character for character",
    HOST_SQL === MM.HOST_PATTERN && ID_SQL === MM.ACCOUNT_ID_PATTERN && ACCT_SQL === MM.ACCT_PATTERN, [HOST_SQL, MM.HOST_PATTERN].join(" | "));
  const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d{3}_/.test(f)).sort();
  /* NAMED (campaign sharing, Nov 4 2026): BEFORE "the only migration numbered 165, and the highest" (every number <= 165).
     AFTER 166_campaign_sharing.sql follows it, so the pin is "the only one numbered 165, every other one but 166 is lower,
     and 164 came before it"; "the highest" is now checkCampaignSharing M2's, for 166. */
  check("M3. 165_member_mastodon_connections.sql is the only migration numbered 165, every one before it is lower (164 was the last before it)",
    migFiles.filter(f => /^165_/.test(f)).length === 1 && migFiles.indexOf("165_member_mastodon_connections.sql") !== -1 &&
    // NAMED (Nov 4 2026, the Media Library, migration 167): the allowlist adds 167_member_media.sql; "the highest" is checkMediaLibrary M2's.
    // NAMED (Nov 5 2026, images in social posts, migration 168): the allowlist adds 168_social_post_images.sql; "the highest" is checkSocialImages M2's.
    migFiles.filter(f => !/^(166_campaign_sharing|167_member_media|168_social_post_images)\.sql$/.test(f)).every(f => Number(f.split("_")[0]) <= 165) && migFiles.some(f => /^164_/.test(f)), migFiles.slice(-3).join(","));
  check("P8. the header says the owner applied it by hand", /Applied by the owner by hand in the Supabase SQL editor on Nov 3, 2026\. This file is the text as run\./.test(MIGRATION));

  /* ── N. the server a member types ───────────────────────────────────────── */
  console.log("\n══ N. normalizeInstance ══");
  const good = [["mastodon.social", "mastodon.social"], ["https://Mastodon.Social/", "mastodon.social"], ["  fosstodon.org  ", "fosstodon.org"],
    ["mastodon.social:443", "mastodon.social"], ["https://hachyderm.io:443/", "hachyderm.io"], ["xn--mnchen-3ya.social", "xn--mnchen-3ya.social"],
    ["sub.domain-with-dash.example", "sub.domain-with-dash.example"]];
  for (const [input, want] of good) {
    const got = MM.normalizeInstance(input);
    check("N. " + JSON.stringify(input) + " becomes " + want + ", which the SQL host CHECK accepts",
      got === want && new RegExp(HOST_SQL).test(got) && got.length >= 4 && got.length <= 253, got);
  }
  const bad = ["http://mastodon.social", "HTTP://mastodon.social", "ftp://mastodon.social", "//mastodon.social", "1.2.3.4", "https://93.184.216.34",
    "[::1]", "https://[::1]/", "::1", "localhost", "https://localhost", "evil.localhost", "mastodon", "mastodon.social:8443", "mastodon.social:80",
    "mastodon.social:", "mastodon.social/@alice", "mastodon.social//", "mastodon.social?x=1", "mastodon.social#top", "alice@mastodon.social",
    "user:pw@mastodon.social", "https://user:pw@mastodon.social", "münchen.social", "mastodon.sociál", "mastodon social", "mastodon.social\\x",
    "mastodon.s0cial1", "-bad.example", "a.b", "", "   ", null, 7, "x".repeat(250) + ".social"];
  const accepted = bad.filter(i => MM.normalizeInstance(i) !== null);
  check("N. " + bad.length + " addresses refused: http, other schemes, IP literals, localhost, a single label, other ports, paths, query, fragment, credentials, non-ASCII, spaces",
    accepted.length === 0, JSON.stringify(accepted));
  check("N. http:// in particular is refused, and so is an IP literal", MM.normalizeInstance("http://mastodon.social") === null && MM.normalizeInstance("1.2.3.4") === null &&
    MM.normalizeInstance("203.0.113.9") === null);
  check("N. a name with accents gets the xn-- message; anything else the plain one",
    MM.instanceMessage("münchen.social") === MM.MESSAGES.instanceAscii && /xn--/.test(MM.MESSAGES.instanceAscii) && MM.instanceMessage("http://x") === MM.MESSAGES.instance);

  /* ── T. the token shape ─────────────────────────────────────────────────── */
  console.log("\n══ T. the token ══");
  check("T1. a token as Mastodon makes them is accepted", MM.checkToken("  " + TOK.alice + " ").ok === true && MM.checkToken(TOK.alice).value === TOK.alice);
  const tokenBad = [["", "token_required"], [undefined, "token_required"], ["short_token", "token_format"], ["has a space in it 0123456789", "token_format"],
    ["x".repeat(201), "token_format"], ["Summer2026!Summer2026!", "token_format"]];
  check("T2. empty, short, spaced, over 200 and punctuated tokens are refused with the right code",
    tokenBad.every(([v, code]) => MM.checkToken(v).ok === false && MM.checkToken(v).code === code), JSON.stringify(tokenBad.map(([v]) => MM.checkToken(v).code)));
  check("T3. the help names Preferences, Development, New application, only write:statuses and read:accounts, and \"Your access token\"",
    /Preferences, then Development, then New application/.test(MM.TOKEN_HELP) && /Tick only write:statuses and read:accounts/.test(MM.TOKEN_HELP) &&
    /"Your access token"/.test(MM.TOKEN_HELP) && MM.MESSAGES.tokenFormat.indexOf(MM.TOKEN_HELP) !== -1 && MM.MESSAGES.tokenMissing.indexOf(MM.TOKEN_HELP) !== -1);
  check("T4. the platform is \"mastodon\" and TOKEN_RE is ^[A-Za-z0-9_-]{20,200}$", MM.PLATFORM === "mastodon" && String(MM.TOKEN_RE) === "/^[A-Za-z0-9_-]{20,200}$/");

  /* ── A. connect ─────────────────────────────────────────────────────────── */
  console.log("\n══ A. connect: sealed first, stored encrypted, never echoed ══");
  STUB.reset(); LOGS.length = 0;
  let b = build();
  let r = await b.hit("connect", ALICE, { instance: "https://Mastodon.Social/", access_token: TOK.alice });
  let row = conn(b, ALICE);
  check("A1. connect: 200 with exactly { connected, account, status, since, max_characters }",
    r.code === 200 && JSON.stringify(Object.keys(r.body || {})) === JSON.stringify(["connected", "account", "status", "since", "max_characters"]) &&
    r.body.connected === true && r.body.account === "@alice@mastodon.social" && r.body.status === "connected" && r.body.since === "2026-11-03T09:00:00.000Z" &&
    r.body.max_characters === 500, r.code + " " + JSON.stringify(r.body));
  check("A2. one row: the host, the id and username the server gave, connected, automation off, the server's rules",
    row && row.instance_host === "mastodon.social" && row.account_id === "109000000000000001" && row.acct === "alice" && row.status === "connected" &&
    row.auto_post === false && row.max_characters === 500 && row.characters_reserved_per_url === 23 && row.last_ok_at === "2026-11-03T12:00:00.000Z" &&
    row.last_error_code === null, JSON.stringify(masked(row)));
  let decrypted = null;
  try { decrypted = CRYPTO.decrypt({ ciphertext: row.token_ciphertext, iv: row.token_iv, authTag: row.token_auth_tag }); } catch (e) { decrypted = "THREW"; }
  check("A3. the stored ciphertext is AES-256-GCM under ENCRYPTION_SECRET and decrypts to exactly the token typed",
    row && /^[0-9a-f]+$/.test(row.token_ciphertext) && /^[0-9a-f]{24}$/.test(row.token_iv) && /^[0-9a-f]{32}$/.test(row.token_auth_tag) && decrypted === TOK.alice);
  check("A4. the token is nowhere in the database in the clear", noTokenIn(everything(b)));
  const st = await b.hit("status", ALICE);
  const au = await b.hit("autoGet", ALICE);
  check("A5. the token is in no response (connect, status, automation), and no ciphertext either",
    [r, st, au].every(x => noTokenIn(JSON.stringify(x.body)) && JSON.stringify(x.body).indexOf(row.token_ciphertext) === -1 && !/token/i.test(Object.keys(x.body || {}).join(","))));
  check("A6. the token is in no log line", LOGS.every(l => noTokenIn(l) && l.indexOf(row.token_ciphertext) === -1), LOGS.filter(l => !noTokenIn(l)).length + " lines");
  r = await b.hit("connect", ALICE, { instance: "mastodon.social", access_token: TOK.alice });
  check("A7. connecting again replaces the row (one per member) and keeps the original date",
    r.code === 200 && b.db.rows("member_mastodon_connections").filter(x => x.user_id === ALICE).length === 1 && r.body.since === "2026-11-03T09:00:00.000Z", r.code);
  const ups = b.db.log.filter(q => q.table === "member_mastodon_connections" && q.op === "upsert");
  check("A8. the write is one upsert on user_id that clears the error fields and holds no plaintext token",
    ups.length === 2 && ups.every(q => q.opts && q.opts.onConflict === "user_id" && q.payload.status === "connected" && q.payload.last_error_code === null &&
      q.payload.last_error_at === null && noTokenIn(JSON.stringify(q.payload))));
  STUB.reset();
  b = build();
  delete process.env.ENCRYPTION_SECRET;
  r = await b.hit("connect", ALICE, { instance: "mastodon.social", access_token: TOK.alice });
  process.env.ENCRYPTION_SECRET = TEST_KEY;
  check("A9. sealed BEFORE the server is asked: with no ENCRYPTION_SECRET, 503 no_encryption_key, no request at all, nothing written",
    r.code === 503 && r.body.code === "no_encryption_key" && r.body.error === MM.MESSAGES.noSecret && STUB.seen.length === 0 && b.db.writes().length === 0,
    r.code + " " + JSON.stringify(r.body) + " seen " + STUB.seen.length);
  const lim = b.limiters.find(o => o && o.max === 5);
  check("A10. connect is limited to 5 an hour per account (mastodon-connect:<id>), behind requireAuth and requireActiveSubscription",
    lim && lim.windowMs === 3600000 && lim.keyGenerator({ user: { id: ALICE } }) === "mastodon-connect:" + ALICE &&
    JSON.stringify(b.routes["post /api/social/mastodon/connect"].middleware) === JSON.stringify(["requireAuth", "requireActiveSubscription", "mastodonConnectLimiter"]),
    JSON.stringify(b.routes["post /api/social/mastodon/connect"].middleware));
  const refusals = [
    ["no server", { access_token: TOK.alice }, "instance_format", MM.MESSAGES.instance],
    ["an http:// server", { instance: "http://mastodon.social", access_token: TOK.alice }, "instance_format", MM.MESSAGES.instance],
    ["an IP literal", { instance: "93.184.216.34", access_token: TOK.alice }, "instance_format", MM.MESSAGES.instance],
    ["a name with accents", { instance: "münchen.social", access_token: TOK.alice }, "instance_format", MM.MESSAGES.instanceAscii],
    ["no token", { instance: "mastodon.social" }, "token_required", MM.MESSAGES.tokenMissing],
    ["a password, not a token", { instance: "mastodon.social", access_token: "Summer2026!" }, "token_format", MM.MESSAGES.tokenFormat]
  ];
  for (const [label, bodyIn, code, msg] of refusals) {
    STUB.reset();
    b = build();
    r = await b.hit("connect", ALICE, bodyIn);
    check("A. " + label + ": 400 " + code + ", the exact message, saved false, no request, nothing written",
      r.code === 400 && r.body.code === code && r.body.error === msg && r.body.saved === false && STUB.seen.length === 0 && b.db.writes().length === 0,
      r.code + " " + JSON.stringify(r.body));
  }

  /* ── V. verify's two calls ──────────────────────────────────────────────── */
  console.log("\n══ V. verify: the account with the token, the rules without it ══");
  STUB.reset();
  b = build();
  await connected(b, BOB, "fosstodon.org", TOK.bob);
  check("V1. exactly two requests: GET verify_credentials, then GET /api/v2/instance",
    STUB.seen.length === 2 && STUB.seen[0].method === "GET" && STUB.seen[0].path === "/api/v1/accounts/verify_credentials" &&
    STUB.seen[1].method === "GET" && STUB.seen[1].path === "/api/v2/instance", JSON.stringify(STUB.seen.map(q => q.method + " " + q.path)));
  check("V2. the first carries the token as a Bearer header; the second carries no Authorization at all",
    bearer(STUB.seen[0].headers) === TOK.bob && bearer(STUB.seen[1].headers) === null && !Object.keys(STUB.seen[1].headers).some(h => h.toLowerCase() === "authorization"));
  check("V3. both went through the guard as https on 443 to the address it checked, with no shared agent",
    STUB.seen.every(q => q.protocol === "https:" && q.port === 443 && q.agent === false && q.address === PUBLIC && q.host === "fosstodon.org"));
  check("V4. the server's own rules are stored: 1000 characters, 23 per link", conn(b, BOB).max_characters === 1000 && conn(b, BOB).characters_reserved_per_url === 23);
  await connected(b, ALICE, "noinfo.example", TOK.carol);
  check("V5. no instance rules (404): 500 and 23", conn(b, ALICE).max_characters === 500 && conn(b, ALICE).characters_reserved_per_url === 23 && conn(b, ALICE).acct === "carol");
  await connected(b, PLAIN, "badinfo.example", TOK.carol);
  check("V6. rules outside 165's ranges (0 and 5000): 500 and 23", conn(b, PLAIN).max_characters === 500 && conn(b, PLAIN).characters_reserved_per_url === 23);
  const v = await MM.verify("mastodon.social", TOK.alice);
  // NAMED (Nov 5 2026, images in social posts, migration 168): BEFORE { ok, account_id, acct, max_characters, characters_reserved_per_url }.
  // AFTER the same plus image_size_limit and media_description_limit, read from the same /api/v2/instance answer (here the 168
  // defaults, 16777216 and 1500, as this fake server sends no media_attachments); scripts/checkSocialImages.js covers the reading.
  check("V7. verify returns the id, the username and the rules (post length and media), and nothing else",
    JSON.stringify(v) === JSON.stringify({ ok: true, account_id: "109000000000000001", acct: "alice", max_characters: 500, characters_reserved_per_url: 23,
      image_size_limit: 16777216, media_description_limit: 1500 }), JSON.stringify(v));

  /* ── C. failures store nothing; classify ─────────────────────────────────── */
  console.log("\n══ C. a refused token, a limit, no answer and every guard refusal store nothing ══");
  const failing = [
    ["a token the server refuses (401)", "mastodon.social", TOK.bob, null, 400, "mastodon_rejected", 1],
    ["the server limiting requests (429)", "mastodon.social", TOK.alice, "rate", 503, "mastodon_rate_limited", 1],
    ["the server down (503)", "mastodon.social", TOK.alice, "down", 503, "mastodon_unreachable", 1],
    ["a name that does not resolve", "nowhere.example", TOK.alice, null, 503, "mastodon_unreachable", 0],
    ["a redirect (never followed)", "redirect.example", TOK.carol, null, 503, "mastodon_unreachable", 1],
    ["a body over 1 MB", "big.example", TOK.carol, null, 503, "mastodon_unreachable", 1],
    ["a name that resolves to a private address", "private.example", TOK.carol, null, 503, "mastodon_unreachable", 0],
    ["an HTML answer", "html.example", TOK.carol, null, 503, "mastodon_unreachable", 1]
  ];
  for (const [label, host, token, mode, code, reason, requests] of failing) {
    STUB.reset(); STUB.verifyMode = mode; LOGS.length = 0;
    b = build();
    r = await b.hit("connect", ALICE, { instance: host, access_token: token });
    check("C. " + label + ": " + code + " " + reason + ", saved false", r.code === code && r.body.code === reason && r.body.saved === false && noTokenIn(JSON.stringify(r.body)),
      r.code + " " + JSON.stringify(r.body));
    check("C. " + label + ": " + requests + " request(s) served, nothing written, no row, no token in a log",
      STUB.seen.length === requests && b.db.writes().length === 0 && !conn(b, ALICE) && LOGS.every(noTokenIn),
      STUB.seen.map(q => q.host + q.path).join(",") + " / " + b.db.writes().length);
  }
  STUB.reset();
  b = build();
  r = await b.hit("connect", ALICE, { instance: "redirect.example", access_token: TOK.carol });
  check("C. the redirect's target (mastodon.social) was never asked", r.code === 503 && STUB.seen.every(q => q.host === "redirect.example"), JSON.stringify(STUB.seen.map(q => q.host)));
  STUB.reset();
  b = build();
  r = await b.hit("connect", ALICE, { instance: "mastodon.social", access_token: TOK.bob });
  check("C. the refusal says the server did not accept the token, names the host and the help, and nothing was saved",
    r.body.error === MM.MESSAGES.rejected + " (mastodon.social). " + MM.TOKEN_HELP + ". Nothing was saved.", r.body.error);
  const NOW = CLOCK.now;
  const cases = [
    [{ status: 401 }, { kind: "rejected" }], [{ status: 403 }, { kind: "rejected" }],
    [{ status: 429, headers: { "retry-after": "30" } }, { kind: "rate_limited", waitMs: 30000 }],
    [{ status: 429, headers: { "x-ratelimit-reset": new Date(NOW + 600000).toISOString() } }, { kind: "rate_limited", waitMs: 600000 }],
    [{ status: 429, headers: {} }, { kind: "rate_limited", waitMs: 15 * 60 * 1000 }],
    [{ status: 429, headers: { "retry-after": "999999" } }, { kind: "rate_limited", waitMs: 2 * 60 * 60 * 1000 }],
    [{ status: 429, headers: { "x-ratelimit-reset": new Date(NOW + 9 * 3600000).toISOString() } }, { kind: "rate_limited", waitMs: 2 * 60 * 60 * 1000 }],
    [{ status: 429, headers: { "retry-after": "soon" } }, { kind: "rate_limited", waitMs: 15 * 60 * 1000 }],
    [{ status: 500 }, { kind: "unreachable" }], [{ status: 404 }, { kind: "unreachable" }], [{ thrown: true }, { kind: "unreachable" }], [null, { kind: "unreachable" }]
  ];
  check("C. classify: 401 and 403 rejected; 429 rate_limited with Retry-After, else X-RateLimit-Reset, else 15 minutes, at most 2 hours; anything else unreachable",
    cases.every(([o, want]) => JSON.stringify(MM.classify(o, NOW)) === JSON.stringify(want)), JSON.stringify(cases.map(([o]) => MM.classify(o, NOW))));
  check("C. classify reads no message text", !/message|\.error\b|body/.test(SOURCES.MM.slice(SOURCES.MM.indexOf("function waitFrom"), SOURCES.MM.indexOf("var mastodonBackoffs"))));

  /* ── D. status and disconnect ───────────────────────────────────────────── */
  console.log("\n══ D. status and disconnect ══");
  STUB.reset();
  b = build();
  r = await b.hit("status", ALICE);
  check("D1. not connected: { connected: false, account: null, status: disconnected, since: null, max_characters: null }",
    r.code === 200 && JSON.stringify(r.body) === JSON.stringify({ connected: false, account: null, status: "disconnected", since: null, max_characters: null }), JSON.stringify(r.body));
  await connected(b, ALICE, "mastodon.social", TOK.alice);
  await connected(b, BOB, "fosstodon.org", TOK.bob);
  r = await b.hit("status", ALICE);
  check("D2. connected: exactly the five keys", JSON.stringify(r.body) === JSON.stringify({ connected: true, account: "@alice@mastodon.social", status: "connected",
    since: "2026-11-03T09:00:00.000Z", max_characters: 500 }), JSON.stringify(r.body));
  const statusRead = b.db.log.filter(q => q.table === "member_mastodon_connections" && q.op === "select").pop();
  check("D3. status reads only the safe columns, scoped to the caller, behind requireAuth only",
    statusRead.cols === "instance_host, acct, status, created_at, max_characters" && statusRead.filters.some(f => f[1] === "user_id" && f[2] === ALICE) &&
    JSON.stringify(b.routes["get /api/social/mastodon/status"].middleware) === JSON.stringify(["requireAuth"]), statusRead.cols);
  conn(b, ALICE).status = "needs_reconnect";
  r = await b.hit("status", ALICE);
  check("D4. needs reconnecting: connected false, the account kept", r.body.connected === false && r.body.status === "needs_reconnect" && r.body.account === "@alice@mastodon.social");
  r = await b.hit("disconnect", ALICE);
  check("D5. disconnect deletes alice's row only, and the note says how to cancel the token itself",
    r.code === 200 && r.body.removed === true && !conn(b, ALICE) && !!conn(b, BOB) && r.body.connected === false &&
    r.body.note === "Disconnected. To cancel the token itself, delete the BizForce application under Preferences, Development on your Mastodon server.", JSON.stringify(r.body));
  check("D6. disconnect is open without a subscription (requireAuth only)", JSON.stringify(b.routes["post /api/social/mastodon/disconnect"].middleware) === JSON.stringify(["requireAuth"]));
  r = await b.hit("disconnect", ALICE);
  check("D7. disconnecting again is harmless: removed false", r.code === 200 && r.body.removed === false);

  /* ── U. automation ──────────────────────────────────────────────────────── */
  console.log("\n══ U. automation, as Bluesky's ══");
  STUB.reset();
  b = build();
  await connected(b, ALICE, "mastodon.social", TOK.alice);
  await connected(b, BOB, "fosstodon.org", TOK.bob);
  r = await b.hit("autoGet", ALICE);
  check("U1. off by default, never changed, available", r.body.auto_post === false && r.body.available === true && r.body.changes.length === 0, JSON.stringify(r.body));
  r = await b.hit("autoPut", ALICE, { auto_post: true });
  const logRows = b.db.rows("member_social_setting_changes");
  check("U2. turned on: one log row, platform mastodon, false to true, with its time",
    r.code === 200 && r.body.auto_post === true && logRows.length === 1 && logRows[0].platform === "mastodon" && logRows[0].old_value === false &&
    logRows[0].new_value === true && r.body.changes[0].changed_at === "2026-11-03T12:00:00.000Z", JSON.stringify(logRows));
  await b.hit("autoPut", ALICE, { auto_post: true });
  check("U3. the same value again logs nothing", b.db.rows("member_social_setting_changes").length === 1);
  check("U4. per member: bob's is still off", (await b.hit("autoGet", BOB)).body.auto_post === false);
  b.state.unsubscribed = true;
  r = await b.hit("autoPut", BOB, { auto_post: true });
  check("U5. turning it on needs an active subscription: 402, nothing changed", r.code === 402 && conn(b, BOB).auto_post === false, r.code);
  r = await b.hit("autoPut", ALICE, { auto_post: false });
  check("U6. turning it off is always allowed, and logged (true to false)",
    r.code === 200 && r.body.auto_post === false && r.body.changes[0].old_value === true && r.body.changes[0].new_value === false, JSON.stringify(r.body));
  b.state.unsubscribed = false;
  r = await b.hit("autoPut", PLAIN, { auto_post: true });
  check("U7. with no connection it cannot be turned on: 400", r.code === 400 && /Connect your Mastodon account first/.test(r.body.error), r.code);
  r = await b.hit("autoPut", OWNER, { auto_post: true });
  check("U8. the unconnected owner cannot turn it on either: 400", r.code === 400, r.code);
  conn(b, BOB).status = "needs_reconnect";
  r = await b.hit("autoPut", BOB, { auto_post: true });
  check("U9. needs reconnecting: 409", r.code === 409 && /needs reconnecting/.test(r.body.error), r.code);
  r = await b.hit("autoPut", ALICE, { auto_post: "yes" });
  check("U10. auto_post must be a boolean", r.code === 400);
  check("U11. the switch is behind requireAuth (the subscription is asked in the handler, when turning it on)",
    JSON.stringify(b.routes["put /api/social/mastodon/automation"].middleware) === JSON.stringify(["requireAuth"]) &&
    /refuseUnlessSubscribed\(req, res, "turn on automatic Mastodon posting"\)/.test(SRC) && /route:put \/api\/social\/mastodon\/automation", \{ G3:/.test(SRC));

  /* ── F. propose-post ────────────────────────────────────────────────────── */
  console.log("\n══ F. propose-post: the member's own account, counted, screened, never auto unless on ══");
  STUB.reset();
  b = build();
  await connected(b, ALICE, "mastodon.social", TOK.alice);
  await connected(b, BOB, "fosstodon.org", TOK.bob);
  let before = b.db.writes().length;
  r = await b.hit("propose", OWNER, { task_id: tid(3) });
  check("F1. the owner with no connection: 403 not_connected, nothing written, no request (no platform fallback)",
    r.code === 403 && r.body.code === "not_connected" && /Connect your own Mastodon account on the Social Agent page first/.test(r.body.error) &&
    b.db.writes().length === before && STUB.statuses.length === 0, r.code + " " + JSON.stringify(r.body));
  r = await b.hit("propose", PLAIN, { task_id: tid(4) });
  check("F2. any other unconnected member: the same 403", r.code === 403 && r.body.code === "not_connected", r.code);
  STUB.reset();
  r = await b.hit("propose", ALICE, { task_id: tid(1) });
  const pA = r.body && r.body.proposal;
  check("F3. alice files: 201, pending, the draft pending_approval for mastodon, NOTHING requested",
    r.code === 201 && pA.status === "pending" && pA.action_type === "publish_mastodon_post" && r.body.draft.status === "pending_approval" &&
    r.body.draft.platform === "mastodon" && STUB.seen.length === 0 && !r.body.automatic, r.code + " " + JSON.stringify(r.body).slice(0, 300));
  check("F4. the payload: draft_id, task_id, the run's exact text, posts_as { member, alice, mastodon.social, automatic false }, and what was measured",
    pA.payload.draft_id === r.body.draft.id && pA.payload.task_id === tid(1) && pA.payload.text === POST &&
    JSON.stringify(pA.payload.posts_as) === JSON.stringify({ account: "member", acct: "alice", host: "mastodon.social", automatic: false }) &&
    pA.payload.measured.length === MM.countForMastodon(POST, 23) && pA.payload.measured.limit === 500 && pA.payload.measured.reserved_per_url === 23,
    JSON.stringify(pA.payload));
  check("F5. the note says nothing was posted and names the account", /Nothing has been posted/.test(r.body.note) && /@alice@mastodon\.social/.test(r.body.note), r.body.note);
  before = b.db.rows("agent_proposals").length;
  r = await b.hit("propose", ALICE, { task_id: tid(6) });
  check("F6. 493 by String.length but 504 with the short link counted as 23: refused at alice's 500, never cut, nothing filed",
    r.code === 400 && /counts 504 characters/.test(r.body.error) && /each link as at least 23/.test(r.body.error) && /limit of 500/.test(r.body.error) &&
    b.db.rows("agent_proposals").length === before && b.db.rows("social_post_drafts").every(d => d.content !== LINKY), r.code + " " + JSON.stringify(r.body));
  r = await b.hit("propose", BOB, { task_id: tid(10) });
  check("F7. the same text is filed for bob, whose server allows 1000", r.code === 201 && r.body.proposal.payload.measured.limit === 1000, r.code);
  r = await b.hit("propose", ALICE, { task_id: tid(5) });
  check("F8. a claim (\"treats diabetes\"): the claims screen refuses, 400, nothing filed",
    r.code === 400 && r.body.code === "claims_screen" && /diabetes/.test(r.body.error) && b.db.rows("agent_proposals").length === before + 1, r.code + " " + JSON.stringify(r.body));
  r = await b.hit("propose", ALICE, { task_id: tid(9) });
  check("F9. a run drafted for Bluesky is not filed for Mastodon", r.code === 400 && /not Mastodon/.test(r.body.error), r.code);
  r = await b.hit("propose", ALICE, { task_id: tid(2) });
  check("F10. another member's run is not found", r.code === 404, r.code);
  r = await b.hit("propose", ALICE, { task_id: tid(7), text: "a different text from the body" });
  check("F11. text in the body is never read: the stored run's text is filed", r.code === 201 && r.body.proposal.payload.text === POST + " (second)", r.code);
  check("F12. propose-post is behind requireAuth, requireActiveSubscription and aiLimiter",
    JSON.stringify(b.routes["post /api/social/mastodon/propose-post"].middleware) === JSON.stringify(["requireAuth", "requireActiveSubscription", "aiLimiter"]));
  // automation on
  await b.hit("autoPut", ALICE, { auto_post: true });
  STUB.reset();
  r = await b.hit("propose", ALICE, { task_id: tid(8) });
  check("F13. ON: filing posts at once from alice's own token; the proposal is executed and the draft published with the post's address",
    r.code === 201 && r.body.automatic === true && r.body.posted === true && r.body.proposal.status === "executed" && r.body.draft.status === "published" &&
    STUB.statuses.length === 1 && STUB.statuses[0].token === TOK.alice && STUB.statuses[0].host === "mastodon.social" &&
    r.body.draft.platform_post_uri === STUB.statuses[0].made.url && r.body.proposal.payload.posts_as.automatic === true &&
    /Posted automatically from @alice@mastodon\.social/.test(r.body.note), r.code + " " + JSON.stringify(r.body).slice(0, 300));
  STUB.reset();
  before = b.db.rows("agent_proposals").length;
  r = await b.hit("propose", ALICE, { task_id: tid(5) });
  check("F14. ON, a claim: still refused, nothing filed, nothing requested",
    r.code === 400 && r.body.code === "claims_screen" && b.db.rows("agent_proposals").length === before && STUB.seen.length === 0, r.code + " " + JSON.stringify(r.body));
  r = await b.hit("propose", ALICE, { task_id: tid(6) });
  check("F15. ON, over the limit: still refused, nothing requested", r.code === 400 && STUB.seen.length === 0, r.code);
  {
    // The executor's own screen, which automation runs too.
    const p = clone(b.db.rows("agent_proposals").find(q => q.status === "executed"));
    const d = b.db.rows("social_post_drafts").find(q => q.id === p.payload.draft_id);
    const t = b.db.rows("ai_tasks").find(q => q.id === p.payload.task_id);
    d.status = "pending_approval"; d.platform_post_uri = null; d.content = CLAIM; t.output.post = CLAIM;
    p.payload.text = CLAIM;
    STUB.reset();
    const x = await b.approve(p);
    check("F16. the executor screens again, automatic or not: a claim in the stored text is refused there, nothing requested",
      x.error && /claims screen refused/.test(x.error.message) && STUB.seen.length === 0, x.error ? x.error.message : "posted");
  }
  STUB.reset();
  conn(b, ALICE).status = "needs_reconnect";
  r = await b.hit("propose", ALICE, { task_id: tid(11) });
  check("F17. needs reconnecting: 409 needs_reconnect, nothing requested", r.code === 409 && r.body.code === "needs_reconnect" && STUB.seen.length === 0, r.code);
  r = await b.hit("proposals", ALICE, { agent_type: "social", action_type: "publish_mastodon_post", title: "x", payload: { text: "x" } });
  check("F18. POST /api/proposals refuses publish_mastodon_post (it is filed only through propose-post)", r.code === 400, r.code + " " + JSON.stringify(r.body));

  /* ── E. the executor ────────────────────────────────────────────────────── */
  console.log("\n══ E. the executor: re-validated, one request, once ══");
  STUB.reset();
  b = build();
  await connected(b, ALICE, "mastodon.social", TOK.alice);
  await connected(b, BOB, "fosstodon.org", TOK.bob);
  let p1 = (await b.hit("propose", ALICE, { task_id: tid(1) })).body.proposal;
  STUB.reset();
  let x = await b.approve(p1);
  const posted = STUB.statuses[0];
  check("E1. approved: one POST /api/v1/statuses with alice's own token, the exact text, public",
    x.result && STUB.seen.length === 1 && STUB.seen[0].method === "POST" && STUB.seen[0].path === "/api/v1/statuses" && posted && posted.token === TOK.alice &&
    JSON.stringify(posted.body) === JSON.stringify({ status: POST, visibility: "public" }), x.error ? x.error.message : JSON.stringify(STUB.seen.map(q => q.path)));
  check("E2. the Idempotency-Key header is the draft id", posted && posted.key === p1.payload.draft_id, posted && posted.key);
  check("E3. it went through the guard: https, 443, the checked address, Content-Type application/json",
    STUB.seen[0].protocol === "https:" && STUB.seen[0].port === 443 && STUB.seen[0].address === PUBLIC && STUB.seen[0].headers["Content-Type"] === "application/json");
  const dA = b.db.rows("social_post_drafts").find(d => d.id === p1.payload.draft_id);
  check("E4. the draft is published with the post's https address on alice's server, no cid, and last_ok_at noted",
    dA.status === "published" && dA.platform_post_uri === posted.made.url && /^https:\/\/mastodon\.social\//.test(dA.platform_post_uri) && dA.platform_post_cid === null &&
    dA.published_at === "2026-11-03T12:00:00.000Z" && conn(b, ALICE).last_ok_at === "2026-11-03T12:00:00.000Z", JSON.stringify(dA));
  check("E5. the result is { id, url, published_at, draft_id }",
    x.result && JSON.stringify(Object.keys(x.result)) === JSON.stringify(["id", "url", "published_at", "draft_id"]) && x.result.url === posted.made.url && x.result.id === posted.made.id,
    JSON.stringify(x.result));
  STUB.reset();
  x = await b.approve(p1);
  check("E6. replay: already published returns { already_published, url } and sends NOTHING",
    x.result && x.result.already_published === true && x.result.url === dA.platform_post_uri && STUB.seen.length === 0, x.error ? x.error.message : JSON.stringify(x.result));
  // re-validation, each refused before any request
  const fresh = async (n) => (await b.hit("propose", ALICE, { task_id: tid(n) })).body.proposal;
  let pv = await fresh(7);
  STUB.reset();
  x = await b.approve(Object.assign({}, pv, { payload: Object.assign({}, pv.payload, { posts_as: { account: "member", acct: "bob", host: "fosstodon.org", automatic: false } }) }));
  check("E7. a proposal edited to name bob's account: refused, nothing sent, bob's token never used",
    x.error && /filed to post as @bob@fosstodon\.org/.test(x.error.message) && STUB.seen.length === 0, x.error ? x.error.message : "posted");
  x = await b.approve(Object.assign({}, pv, { payload: Object.assign({}, pv.payload, { text: POST + " (edited)" }) }));
  check("E8. stored text that differs from the draft: refused, nothing sent", x.error && /differs from the draft/.test(x.error.message) && STUB.seen.length === 0,
    x.error ? x.error.message : "posted");
  b.db.rows("ai_tasks").find(t => t.id === tid(7)).output.post = POST + " (rewritten)";
  x = await b.approve(pv);
  check("E9. a source run whose post now differs: refused, nothing sent", x.error && /differs from the post the source run drafted/.test(x.error.message) && STUB.seen.length === 0,
    x.error ? x.error.message : "posted");
  b.db.rows("ai_tasks").find(t => t.id === tid(7)).output.post = POST + " (second)";
  conn(b, ALICE).max_characters = 40;
  x = await b.approve(pv);
  check("E10. the server's limit lowered since filing: counted against the CURRENT limit, refused, nothing sent",
    x.error && /over the server's limit of 40/.test(x.error.message) && STUB.seen.length === 0, x.error ? x.error.message : "posted");
  conn(b, ALICE).max_characters = 500;
  x = await b.approve(Object.assign({}, pv, { user_id: BOB }));
  check("E11. a proposal row naming bob reads bob's own draft and connection only: refused, nothing sent", x.error && STUB.seen.length === 0, x.error ? x.error.message : "posted");
  await b.hit("disconnect", ALICE);
  x = await b.approve(pv);
  check("E12. filed, then disconnected: refused at approval, nothing sent", x.error && /no connected Mastodon account/.test(x.error.message) && STUB.seen.length === 0,
    x.error ? x.error.message : "posted");
  // a failure: one attempt, publish_failed
  await connected(b, ALICE, "mastodon.social", TOK.alice);
  pv = await fresh(8);
  STUB.reset(); STUB.postMode = "error";
  x = await b.approve(pv);
  check("E13. the server answers 500: one attempt only, the draft publish_failed, the error says nothing is retried",
    x.error && /Mastodon did not take it \(http_500\)/.test(x.error.message) && /Nothing is retried automatically/.test(x.error.message) &&
    seenPath("/api/v1/statuses").length === 1 && b.db.rows("social_post_drafts").find(d => d.id === pv.payload.draft_id).status === "publish_failed" &&
    conn(b, ALICE).status === "connected" && conn(b, ALICE).last_error_code === "http_500", x.error ? x.error.message : "posted");
  pv = await fresh(11);
  STUB.reset(); STUB.postMode = "foreign";
  x = await b.approve(pv);
  check("E14. a post address on another host is never recorded: publish_failed, no_status_url",
    x.error && /no_status_url/.test(x.error.message) && b.db.rows("social_post_drafts").find(d => d.id === pv.payload.draft_id).platform_post_uri == null,
    x.error ? x.error.message : "posted");
  // a refused token
  const p401 = await fresh(12);
  const p401b = await fresh(1);
  STUB.reset(); STUB.postMode = "revoked";
  x = await b.approve(p401);
  const notes = () => b.db.rows("notifications").filter(n => n.user_id === ALICE);
  check("E15. 401 at the post: exactly one request, the error says reconnect, needs_reconnect with token_refused",
    x.error && /refused the access token for @alice@mastodon\.social \(token_refused\)/.test(x.error.message) && seenPath("/api/v1/statuses").length === 1 &&
    conn(b, ALICE).status === "needs_reconnect" && conn(b, ALICE).last_error_code === "token_refused", x.error ? x.error.message : "posted");
  check("E16. one in-app notice, type mastodon_reconnect, \"Reconnect your Mastodon account\", with no token in it",
    notes().length === 1 && notes()[0].type === "mastodon_reconnect" && notes()[0].title === "Reconnect your Mastodon account" &&
    /nothing will be tried again/.test(notes()[0].message) && noTokenIn(JSON.stringify(notes())), JSON.stringify(notes()));
  STUB.reset();
  x = await b.approve(p401b);
  check("E17. the next approval is refused before any request, and no second notice", x.error && /needs reconnecting/.test(x.error.message) && STUB.seen.length === 0 && notes().length === 1,
    x.error ? x.error.message : "posted");
  await b.ctx.api.recordMastodonSession(ALICE, "@alice@mastodon.social", { ok: false, reason: "session_failed", code: "token_refused" });
  check("E18. a second refused token recorded directly still raises no second notice", notes().length === 1, notes().length);
  STUB.reset(); STUB.postMode = null;
  r = await b.hit("connect", ALICE, { instance: "mastodon.social", access_token: TOK.alice });
  check("E19. reconnecting clears it: connected, no error code", r.code === 200 && conn(b, ALICE).status === "connected" && conn(b, ALICE).last_error_code === null, r.code);
  {
    // An unreadable token is a session failure too, with no request.
    const rowNow = clone(conn(b, ALICE));
    STUB.reset();
    const out = await MM.withToken(rowNow, () => { throw new Error("bad tag"); }, async () => "called");
    check("E20. a token that cannot be decrypted: session_failed token_unreadable, no request", out.ok === false && out.reason === "session_failed" &&
      out.code === "token_unreadable" && STUB.seen.length === 0, JSON.stringify(out));
    const forged = Object.assign({}, rowNow, { instance_host: "127.0.0.1" });
    const out2 = await MM.withToken(forged, CRYPTO.decrypt, async () => "called");
    check("E21. a stored host that no longer passes normalizeInstance: refused before decrypting, no request", out2.ok === false && out2.code === "host_invalid" && STUB.seen.length === 0);
  }
  const gatedList = /const SUBSCRIPTION_GATED_PROPOSAL_ACTIONS = \[([^\]]*)\]/.exec(SRC);
  const execs = SRC.slice(SRC.indexOf("const PROPOSAL_EXECUTORS = {"), s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("const PROPOSAL_EXECUTORS = {"))) + 1);
  const GR = require(path.join(REPO, "lib/gateRules.js"));
  check("E22. registered: PROPOSAL_EXECUTORS, SUBSCRIPTION_GATED_PROPOSAL_ACTIONS, and gateRules (action type, channel mastodon)",
    /\n  publish_mastodon_post: executePublishMastodonPost,?\n/.test(execs) && gatedList && /"publish_mastodon_post"/.test(gatedList[1]) &&
    GR.ACTION_TYPES.indexOf("publish_mastodon_post") !== -1 && GR.CHANNELS.indexOf("mastodon") !== -1 && GR.channelFor("publish_mastodon_post") === "mastodon");
  check("E23. withToken has one call and no loop, sleep or timer",
    !/\bwhile\s*\(|\bfor\s*\(|setTimeout|setInterval/.test(SOURCES.MM.slice(SOURCES.MM.indexOf("async function withToken"), SOURCES.MM.indexOf("/* ── how long a post is"))));

  /* ── B. the back-off ────────────────────────────────────────────────────── */
  console.log("\n══ B. the back-off: no request while it holds, and separate from Bluesky's ══");
  STUB.reset();
  b = build();
  await connected(b, ALICE, "mastodon.social", TOK.alice);
  await connected(b, BOB, "fosstodon.org", TOK.bob);
  const q1 = (await b.hit("propose", ALICE, { task_id: tid(1) })).body.proposal;
  const q2 = (await b.hit("propose", ALICE, { task_id: tid(7) })).body.proposal;
  const q3 = (await b.hit("propose", ALICE, { task_id: tid(8) })).body.proposal;
  STUB.reset(); STUB.postMode = "rate";
  x = await b.approve(q1);
  check("B1. a 429 with Retry-After 120: one request, a rate-limit error naming when, still connected, no notice",
    x.error && /Mastodon rate limit on @alice@mastodon\.social \(call_rate_limited\)/.test(x.error.message) && /2026-11-03T12:02:00\.000Z/.test(x.error.message) &&
    seenPath("/api/v1/statuses").length === 1 && conn(b, ALICE).status === "connected" && conn(b, ALICE).last_error_code === "call_rate_limited" &&
    b.db.rows("notifications").length === 0, x.error ? x.error.message : "posted");
  check("B2. the back-off is Mastodon's own: Bluesky's back-off for alice is untouched",
    MM.backoffUntil(ALICE, CLOCK.now) === CLOCK.now + 120000 && MB.backoffUntil(ALICE, CLOCK.now) === 0, MB.backoffUntil(ALICE, CLOCK.now));
  STUB.reset(); STUB.postMode = null;
  x = await b.approve(q2);
  check("B3. while it holds: refused with code backoff, and NO request at all", x.error && /\(backoff\)/.test(x.error.message) && STUB.seen.length === 0,
    x.error ? x.error.message : "posted");
  CLOCK.now += 121000;
  x = await b.approve(q3);
  check("B4. once it has passed: one request, posted, and the back-off cleared", x.result && STUB.statuses.length === 1 && MM.backoffUntil(ALICE, CLOCK.now) === 0,
    x.error ? x.error.message : JSON.stringify(x.result));
  MB.noteRateLimit(BOB, 600000, CLOCK.now);
  const qb = (await b.hit("propose", BOB, { task_id: tid(2) })).body.proposal;
  STUB.reset();
  x = await b.approve(qb);
  check("B5. a Bluesky back-off for bob never holds bob's Mastodon post", x.result && STUB.statuses.length === 1 && STUB.statuses[0].token === TOK.bob,
    x.error ? x.error.message : "held");
  MB.clearBackoff(BOB);
  CLOCK.now = Date.parse("2026-11-03T12:00:00.000Z");

  /* ── S. the platform's token is never read ──────────────────────────────── */
  console.log("\n══ S. MASTODON_ACCESS_TOKEN is outreach only ══");
  {
    const code = uncommented(MEMBER_PATHS);
    const parts = MEMBER_PARTS;
    check("S1. no member or Social path names MASTODON_ACCESS_TOKEN (the six routes, the executor, the Social agent's post route and everything they call)",
      code.indexOf("MASTODON_ACCESS_TOKEN") === -1 && parts.size > 20, "names lifted: " + parts.size);
    check("S2. none reads process.env by a computed name either", !/process\.env\[/.test(code));
    check("S3. sendMastodonReply (outreach) is not among them", !parts.has("sendMastodonReply"));
    check("S4. lib/memberMastodon.js and the two pages never name it",
      uncommented(SOURCES.MM).indexOf("MASTODON_ACCESS_TOKEN") === -1 && FE("scripts/mastodon-connect.js").indexOf("MASTODON_") === -1 &&
      FE("scripts/social-publish.js").indexOf("MASTODON_") === -1);
    check("S5. the comment rule: \"//\" after \":\" is not a comment, so an https:// address keeps the line it is on",
      uncommented('var u = "https://x.example"; var t = process.env.MASTODON_ACCESS_TOKEN;').indexOf("MASTODON_ACCESS_TOKEN") !== -1 &&
      uncommented("var a = 1; // MASTODON_ACCESS_TOKEN").indexOf("MASTODON_ACCESS_TOKEN") === -1);
  }

  /* ── K. counting ────────────────────────────────────────────────────────── */
  console.log("\n══ K. countForMastodon is never below Mastodon's count ══");
  const C = MM.countForMastodon;
  const exact = [["hello", 5], ["https://a.co", 23], ["https://example.com/" + "p".repeat(30), 50], ["see https://a.co.", 4 + 23 + 1], ["http://", 7],
    ["\u{1F468}\u200D\u{1F469}\u200D\u{1F467}", 5], ["e\u0301", 2], ["two https://a.co https://b.co", 4 + 23 + 1 + 23], ["", 0], ["https://a.co?", 24]];
  check("K1. the rule exactly: code points, each link the larger of its own length and 23, trailing punctuation as itself",
    exact.every(([t, n]) => C(t, 23) === n), JSON.stringify(exact.map(([t]) => C(t, 23))));
  check("K2. the reserved length is the server's: 30 per link, and 0 counts a link as itself", C("https://a.co", 30) === 30 && C("https://a.co", 0) === 12 && C("https://a.co") === 23);
  // A model of Mastodon's own count: graphemes, with every link exactly the reserved length.
  const SEG = new Intl.Segmenter("en", { granularity: "grapheme" });
  const graphemes = t => { let n = 0; for (const _ of SEG.segment(t)) n++; return n; };
  let seedN = 0x5eed;
  const rand = () => { seedN = (seedN + 0x6D2B79F5) | 0; let t = Math.imul(seedN ^ (seedN >>> 15), 1 | seedN); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const pick = a => a[Math.floor(rand() * a.length)];
  const WORDS = ["clay", "Saturday", "10am", "café", "naïve", "日本語", "über", "#pottery", "@alice", "x"];
  const EMOJI = ["\u{1F600}", "\u{1F468}\u200D\u{1F469}\u200D\u{1F467}", "\u{1F1EF}\u{1F1F5}", "\u{1F44D}\u{1F3FD}", "\u2764\uFE0F", "\u{1F3F3}\uFE0F\u200D\u{1F308}"];
  const MARKS = ["e\u0301", "a\u0308\u0304", "n\u0303", "\u0915\u094D\u0937", "Z\u0351\u0352\u0353\u0354"];
  const LINK_TAIL = ["", "/", "/path", "/a/b/c?x=1&y=2", "/" + "long".repeat(10), "/#frag", "/p_q-r~s"];
  const link = () => pick(["https://", "http://"]) + pick(["a.co", "example.com", "mastodon.social", "x.org"]) + pick(LINK_TAIL);
  let worst = null, trials = 0;
  for (let i = 0; i < 3000; i++) {
    const pieces = [], model = [];
    const n = 1 + Math.floor(rand() * 12);
    for (let j = 0; j < n; j++) {
      const kind = rand();
      if (kind < 0.3) { const l = link(); const end = pick(["", "", ".", "?", "!", ","]); pieces.push(l + end); model.push("L".repeat(23) + end); }
      else if (kind < 0.5) { const e = pick(EMOJI); pieces.push(e); model.push(e); }
      else if (kind < 0.7) { const m = pick(MARKS); pieces.push(m); model.push(m); }
      else { const w = pick(WORDS); pieces.push(w); model.push(w); }
    }
    const text = pieces.join(" "), mastodon = graphemes(model.join(" "));
    trials++;
    if (C(text, 23) < mastodon) { worst = { text, ours: C(text, 23), mastodon }; break; }
  }
  check("K3. " + trials + " random posts of links, emoji (ZWJ, flags, skin tones) and combining marks: never below Mastodon's own count", worst === null, JSON.stringify(worst));
  check("K4. a post of only short links counts each at 23, as Mastodon does, not at its own length",
    C("https://a.co https://b.co", 23) === 47 && graphemes("L".repeat(23) + " " + "L".repeat(23)) === 47);
  {
    const API = build().ctx.api;
    const spec = API.SOCIAL_PLATFORMS.mastodon;
    check("K5. SOCIAL_PLATFORMS.mastodon: 500, hard, counted by countForMastodon, 23 per link",
      spec && spec.label === "Mastodon" && spec.max === 500 && spec.kind === "hard" && spec.counter === "mastodon" && spec.reserved_per_url === 23, JSON.stringify(spec));
    const m = API.measureSocialPost(LINKY, spec);
    check("K6. measureSocialPost counts LINKY as 504, over 500 (not 493), and says links count as at least 23",
      m.length === 504 && m.within_limit === false && m.chars_over_limit === 4 && m.links_count_as_at_least === 23, JSON.stringify(m).slice(0, 200));
    const b2 = build();
    await connected(b2, BOB, "fosstodon.org", TOK.bob);
    const own = await b2.ctx.api.mastodonSpecFor(BOB, spec);
    const none = await b2.ctx.api.mastodonSpecFor(ALICE, spec);
    check("K7. a connected member is measured against their own server (1000, 23), anyone else against 500 and 23",
      own.max === 1000 && own.reserved_per_url === 23 && /fosstodon\.org/.test(own.note) && none === spec, JSON.stringify(own));
    check("K8. the Social agent's instruction says each link counts as at least the reserved number",
      /- Each link counts as at least " \+ [^\n]*" characters, however short it is\./.test(SRC) || /Each link counts as at least/.test(routeText("post", "/api/agents/social/post")));
    check("K9. the Social page's tool offers \"Mastodon - 500 characters by default (your server may allow more)\", with a plain hyphen",
      FE("agents/social.html").indexOf('"label": "Mastodon - 500 characters by default (your server may allow more)"') !== -1);
  }

  /* ── X. export and backup ───────────────────────────────────────────────── */
  console.log("\n══ X. export, deletion and backup ══");
  STUB.reset();
  b = build();
  await connected(b, ALICE, "mastodon.social", TOK.alice);
  await b.hit("autoPut", ALICE, { auto_post: true });
  await connected(b, BOB, "fosstodon.org", TOK.bob);
  const aliceRow = clone(conn(b, ALICE));
  b.db.rows("profiles").push({ id: "p1", user_id: ALICE, username: "alice" });
  b.db.rows("users").find(u => u.id === ALICE).password_hash = "hash";
  const chunks = [];
  const manifest = await YDATA.exportAccountData({ supabase: b.db.client, userId: ALICE, write: t => chunks.push(t), now: new Date("2026-11-03T12:00:00Z") });
  const exported = chunks.join("");
  let file = null; try { file = JSON.parse(exported); } catch (e) { file = null; }
  const exRows = file && file.tables && file.tables.member_mastodon_connections;
  check("X1. the export: member_mastodon_connections is exactly [{ instance_host, acct, created_at }]",
    Array.isArray(exRows) && exRows.length === 1 && JSON.stringify(exRows[0]) === JSON.stringify({ instance_host: "mastodon.social", acct: "alice", created_at: "2026-11-03T09:00:00.000Z" }),
    JSON.stringify(exRows));
  check("X2. the export holds no token, ciphertext, iv, auth tag or account id",
    noTokenIn(exported) && exported.indexOf(aliceRow.token_ciphertext) === -1 && exported.indexOf(aliceRow.token_iv) === -1 &&
    exported.indexOf(aliceRow.token_auth_tag) === -1 && exported.indexOf("token_") === -1 && exported.indexOf("109000000000000001") === -1);
  check("X3. NEVER_EXPORTED says the token stays and only the account, server and date leave; the Mastodon setting log is exported",
    manifest.not_exported.indexOf("Your Mastodon access token: stored encrypted; the export shows only the account, the server and the date you connected.") !== -1 &&
    file && Array.isArray(file.tables.member_social_setting_changes) && file.tables.member_social_setting_changes.some(x => x.platform === "mastodon"));
  const del = await YDATA.deleteAccount({ supabase: b.db.client, storage: b.db.client.storage, publicUrlBase: "https://x.supabase.co/storage/v1/object/public/",
    userId: ALICE, body: { username: "alice", password: "pw" }, comparePassword: async (pw) => pw === "pw", activeSubscriptions: async () => [],
    ownerAccountId: OWNER, now: new Date("2026-11-03T12:00:00Z") });
  check("X4. deleting the account deletes alice's connection, and not bob's",
    del.status === 200 && !conn(b, ALICE) && !!conn(b, BOB), del.status + " " + JSON.stringify(del.body).slice(0, 200));
  check("X5. the connection is in FINAL_DELETES", YDATA.FINAL_DELETES.indexOf("member_mastodon_connections") !== -1);
  const backup = require(path.join(REPO, "lib/backup.js"));
  check("X6. backups EXCLUDE the connection (a token never leaves the database), with the reason",
    backup.EXCLUDED_TABLES.member_mastodon_connections === "members' Mastodon access tokens (encrypted); members connect again" &&
    backup.BACKUP_TABLES.indexOf("member_mastodon_connections") === -1);
  const schema = require(path.join(REPO, "lib/schemaCheck.js"));
  const tables = schema.SCHEMA_TABLES || [];
  check("X7. lib/schemaCheck.js names the table and its migration", JSON.stringify(tables).indexOf('["member_mastodon_connections","165_member_mastodon_connections.sql"]') !== -1);

  /* ── J. the pages ───────────────────────────────────────────────────────── */
  console.log("\n══ J. the Social agent page, the filing line and proposals ══");
  const social = FE("agents/social.html");
  const card = (/<section class="context-card bsky-card" id="mastoConnect"[\s\S]*?<\/section>/.exec(social) || [""])[0];
  check("J1. the Connect Mastodon card: the heading, the steps, \"Your server\" (mastodon.social), \"Access token\" (password, autocomplete off) and Connect",
    /<h2 class="section-label">Connect Mastodon<\/h2>/.test(card) && /Preferences, then Development, then New application/.test(card) &&
    /tick only write:statuses and read:accounts/.test(card) && /"Your access token"/.test(card) &&
    /<label>Your server<input type="text" id="mastoInstance" placeholder="mastodon\.social"/.test(card) &&
    /<label>Access token<input type="password" id="mastoToken" autocomplete="off" \/><\/label>/.test(card) && />Connect<\/button>/.test(card) &&
    /Never enter your Mastodon password/.test(card));
  check("J2. Disconnect, the switch (unchecked in the markup) and the reconnect slot",
    />Disconnect<\/button>/.test(card) && /<input type="checkbox" id="mastoAutoPost" \/> <span>Post approved drafts automatically<\/span>/.test(card) &&
    /id="mastoReconnect" hidden/.test(card) && /id="mastoConnected" hidden/.test(card));
  check("J3. the card follows the mentions section, and the Bluesky card keeps its honest line right before its </section>",
    /id="bskyMentions"[\s\S]*?<\/section>\n    <section class="context-card bsky-card" id="mastoConnect"/.test(social) &&
    /<p class="bsky-quiet" id="bskyOtherPlatforms">[^<]*<\/p>\n    <\/section>/.test(social));
  check("J4. social.html loads mastodon-connect.js right after bluesky-mentions.js",
    /<script src="\/scripts\/bluesky-mentions\.js"><\/script>\n<script src="\/scripts\/mastodon-connect\.js"><\/script>/.test(social));
  check("J5. mastodon-connect.js never writes markup: no innerHTML, outerHTML, insertAdjacentHTML or document.write",
    !/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(FE("scripts/mastodon-connect.js")));

  // The card, in jsdom, against the real routes.
  const { JSDOM } = require("jsdom");
  STUB.reset();
  b = build();
  const stored = [];
  const dom = new JSDOM("<!doctype html><html><head></head><body>" + card + "</body></html>", { runScripts: "outside-only", url: "https://bizforce.example/agents/social.html" });
  const w = dom.window;
  const sent = [];
  let override = null;
  w.localStorage.setItem("bf_token", "t");
  const realSet = w.localStorage.setItem.bind(w.localStorage);
  Object.defineProperty(w.localStorage, "setItem", { value: (k, val) => { stored.push([k, val]); realSet(k, val); } });
  w.fetch = function (url, init) {
    const method = (init && init.method) || "GET";
    const p = String(url).replace(/^https?:\/\/[^/]+/, "");
    const bodyIn = init && init.body ? JSON.parse(init.body) : undefined;
    sent.push({ method, path: p, body: bodyIn });
    if (override) { const o = override; override = null; return o === "reject" ? Promise.reject(new Error("network down")) : Promise.resolve(o); }
    const key = Object.keys(R).find(k => R[k][0] === method.toLowerCase() && R[k][1] === p);
    const pr = key ? b.hit(key, ALICE, bodyIn).then(res => ({ ok: res.code >= 200 && res.code < 300, status: res.code, json: () => Promise.resolve(clone(res.body)) }))
      : Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({ error: "unplanned " + method + " " + p }) });
    pr.catch(() => {});
    return pr;
  };
  w.eval(FE("scripts/mastodon-connect.js"));
  const flush = async () => { for (let i = 0; i < 60; i++) await new Promise(res => setImmediate(res)); };
  await flush();
  const $ = id => w.document.getElementById(id);
  check("J6. not connected: the form shows; connected, automation, reconnect and Disconnect are hidden",
    !$("mastoForm").hidden && $("mastoConnected").hidden && $("mastoAutomation").hidden && $("mastoReconnect").hidden && $("mastoDisconnectBtn").hidden);
  $("mastoInstance").value = "mastodon.social"; $("mastoToken").value = TOK.bob;
  await w.bfMastodonConnect.connect(); await flush();
  check("J7. a refused token: the server's exact message, the token field cleared, still the form",
    $("mastoConnectMsg").textContent === MM.MESSAGES.rejected + " (mastodon.social). " + MM.TOKEN_HELP + ". Nothing was saved." && $("mastoToken").value === "" && !$("mastoForm").hidden,
    $("mastoConnectMsg").textContent);
  $("mastoToken").value = TOK.alice;
  override = { ok: false, status: 400, json: () => Promise.resolve({ error: '<img id="inj" src="x"> refused' }) };
  await w.bfMastodonConnect.connect(); await flush();
  check("J8. a server message holding markup is shown as text: no element made, the token field cleared",
    !$("inj") && $("mastoConnectMsg").textContent === '<img id="inj" src="x"> refused' && $("mastoToken").value === "", $("mastoConnectMsg").innerHTML);
  $("mastoToken").value = TOK.alice;
  override = "reject";
  await w.bfMastodonConnect.connect(); await flush();
  check("J9. the network failing: the token field cleared all the same", $("mastoToken").value === "" && /network down/.test($("mastoConnectMsg").textContent));
  $("mastoToken").value = TOK.alice;
  await w.bfMastodonConnect.connect(); await flush();
  const connectSent = sent.filter(q => q.path === "/api/social/mastodon/connect");
  check("J10. connect sends exactly { instance, access_token }, and nothing else ever carries the token",
    connectSent.length === 4 && JSON.stringify(Object.keys(connectSent[3].body)) === JSON.stringify(["instance", "access_token"]) &&
    sent.filter(q => q.path !== "/api/social/mastodon/connect").every(q => noTokenIn(JSON.stringify(q.body || {}))));
  check("J11. connected: \"Connected as @alice@mastodon.social\", \"since\" a date, \"Posts up to 500 characters\", the form hidden, the field cleared",
    $("mastoConnectedAs").textContent === "Connected as @alice@mastodon.social" && /^since /.test($("mastoSince").textContent) &&
    /^Posts up to 500 characters/.test($("mastoLimit").textContent) && $("mastoForm").hidden && $("mastoToken").value === "" &&
    !$("mastoDisconnectBtn").hidden && !$("mastoAutomation").hidden && $("mastoAutoPost").checked === false, $("mastoConnectedAs").textContent);
  check("J12. the token was never put in localStorage", stored.every(([k, val]) => noTokenIn(String(k) + String(val))));
  await w.bfMastodonConnect.setAutomation(true); await flush();
  check("J13. the switch: PUT { auto_post: true }, the server's answer drawn, the change shown",
    sent.some(q => q.method === "PUT" && q.path === "/api/social/mastodon/automation" && JSON.stringify(q.body) === JSON.stringify({ auto_post: true })) &&
    $("mastoAutoPost").checked === true && /^Turned on on /.test($("mastoAutoLog").textContent) && conn(b, ALICE).auto_post === true, $("mastoAutoLog").textContent);
  conn(b, ALICE).status = "needs_reconnect";
  await w.bfMastodonConnect.loadStatus(); await flush();
  check("J14. needs reconnecting: the exact warning naming the account, the form back, Disconnect kept",
    !$("mastoReconnect").hidden && $("mastoReconnectText").textContent ===
      "Mastodon stopped accepting the token saved for @alice@mastodon.social, so nothing is being posted from it. Make a new token and connect again below." &&
    !$("mastoForm").hidden && !$("mastoDisconnectBtn").hidden && $("mastoAutomation").hidden, $("mastoReconnectText").textContent);
  await w.bfMastodonConnect.disconnect(); await flush();
  check("J15. disconnect: the row is gone, the server's note is shown, the form is back",
    !conn(b, ALICE) && $("mastoStatusMsg").textContent === "Disconnected. To cancel the token itself, delete the BizForce application under Preferences, Development on your Mastodon server." &&
    !$("mastoForm").hidden && $("mastoReconnect").hidden && $("mastoDisconnectBtn").hidden, $("mastoStatusMsg").textContent);

  // social-publish.js's filing line.
  {
    const fakeEl = id => ({ id, innerHTML: "", textContent: "", className: "", children: [], appendChild(c) { this.children.push(c); return c; } });
    const run = async (answers) => {
      const sctx = { window: {}, console, localStorage: { getItem() { return "t"; } },
        document: { readyState: "complete", head: fakeEl("head"), createElement() { return fakeEl(null); }, addEventListener() {} },
        fetch: (u) => { const p = String(u).replace(/^https?:\/\/[^/]+/, ""); return Promise.resolve({ ok: !!answers[p], status: answers[p] ? 200 : 404, json: () => Promise.resolve(answers[p] || { error: "no" }) }); } };
      vm.createContext(sctx);
      vm.runInContext(FE("scripts/social-publish.js"), sctx);
      const slot = fakeEl("slot");
      await sctx.window.bfSocialPublish.drawMastodonFiling(slot, { task_id: tid(1), persisted: true });
      return { slot, sp: sctx.window.bfSocialPublish };
    };
    const on = await run({ "/api/social/mastodon/status": { connected: true, account: "@alice@mastodon.social", status: "connected", since: "x", max_characters: 500 },
      "/api/social/mastodon/automation": { auto_post: false, changes: [], available: true } });
    check("J16. under a Mastodon result: \"Posts as @alice@mastodon.social\", File for approval, and nothing posted by filing",
      /Posts as @alice@mastodon\.social/.test(on.slot.innerHTML) && /data-sp-masto-file/.test(on.slot.innerHTML) && /Nothing is posted by filing/.test(on.slot.innerHTML),
      on.slot.innerHTML);
    const none = await run({ "/api/social/mastodon/status": { connected: false, account: null, status: "disconnected", since: null, max_characters: null } });
    check("J17. unconnected (the owner included): one quiet line to connect, no button",
      none.slot.innerHTML.indexOf(none.sp.MASTO_CONNECT_LINE) !== -1 && !/data-sp-masto-file/.test(none.slot.innerHTML), none.slot.innerHTML);
    // NAMED (Nov 5 2026, images in social posts): BEFORE the call's body was the literal { task_id: taskId }. AFTER it is
    // filingBody(taskId, box), which is exactly { task_id } when no image is attached (proved here on a box with none), and adds
    // media_ids only when images are (scripts/checkSocialImages.js, in jsdom).
    check("J18. the filing request sends only the task id, to propose-post, when no image is attached",
      FE("scripts/social-publish.js").indexOf('api("POST", "/api/social/mastodon/propose-post", filingBody(taskId, box))') !== -1 &&
      JSON.stringify(on.sp.filingBody("t-1", {})) === JSON.stringify({ task_id: "t-1" }));
  }

  // proposals.html's card.
  {
    const PROP = FE("proposals.html");
    const fnSrc = name => { const i = PROP.indexOf("function " + name + "("); return i < 0 ? "" : PROP.slice(i, s.braceMatch(PROP, PROP.indexOf("{", i)) + 1); };
    const pctx = {}; vm.createContext(pctx);
    // NAMED (Nov 5 2026, images in social posts): the lift adds postImagesFields, which the card now calls (it draws nothing without images).
    vm.runInContext(["escapeHtml", "postImagesFields", "mastodonPostPayloadFields", "mastodonResultHtml"].map(fnSrc).join("\n"), pctx);
    const cardHtml = pctx.mastodonPostPayloadFields({ text: "<b>hi</b> " + POST, posts_as: { account: "member", acct: "alice", host: "mastodon.social", automatic: false },
      measured: { length: 88, limit: 500, reserved_per_url: 23 } });
    check("J19. proposals: \"Posts as @alice@mastodon.social\", \"88 of 500 characters\", and the text escaped",
      cardHtml.indexOf("Posts as @alice@mastodon.social") !== -1 && cardHtml.indexOf("88 of 500 characters") !== -1 && cardHtml.indexOf("<b>hi</b>") === -1 &&
      cardHtml.indexOf("&lt;b&gt;hi&lt;/b&gt;") !== -1, cardHtml.slice(0, 300));
    const linked = pctx.mastodonResultHtml({ id: "1", url: "https://mastodon.social/@alice/1", published_at: "2026-11-03T12:00:00.000Z" });
    const unsafe = pctx.mastodonResultHtml({ id: "1", url: "javascript:alert(1)" });
    check("J20. the result links an https post address, and never anything else",
      /<a class="pf-value masto-post-link" href="https:\/\/mastodon\.social\/@alice\/1"/.test(linked) && unsafe.indexOf("<a ") === -1 && /no post address recorded/.test(unsafe), linked);
    check("J21. the card is wired into both branches", /p\.action_type === "publish_mastodon_post"[^\n]*\n\s*execHtml = mastodonResultHtml\(p\.execution_result\);/.test(PROP) &&
      /p\.action_type === "publish_mastodon_post"\) \{\n\s*fieldsHtml = mastodonPostPayloadFields\(p\.payload \|\| \{\}\);/.test(PROP));
  }

  /* ── L. legal ───────────────────────────────────────────────────────────── */
  console.log("\n══ L. Privacy and Terms, word for word ══");
  const PRIVACY = "If you connect your Mastodon account, BizForce stores your server's address, your account name and id, your server's post length limit, and the access token you made for BizForce, encrypted; the token is used only to post to your account when you approve a proposal, or when your own \"Post approved drafts automatically\" setting for Mastodon is on, and your posts go to the server you chose, under its rules. The token is never shown back to you or exported (your data download says only which account and server you connected and when); you can disconnect at any time, you can also cancel the token in your Mastodon settings, and it is deleted with your account.";
  const TERMS = "If you connect your own Mastodon account, you are responsible for everything posted from it and for following your server's rules. BizForce posts to it only when you approve a proposal, or when you have turned on \"Post approved drafts automatically\" for Mastodon.";
  const LP = require(path.join(REPO, "lib/legalPages.js"));
  const LEGAL = require(path.join(REPO, "lib/legal.js"));
  check("L1. lib/legalPages.js: MASTODON_PRIVACY_SENTENCE is the brief's sentence, word for word", LP.MASTODON_PRIVACY_SENTENCE === PRIVACY);
  check("L2. lib/legalPages.js: MASTODON_TERMS_SENTENCE is the brief's sentence, word for word", LP.MASTODON_TERMS_SENTENCE === TERMS);
  check("L3. privacy.html carries the privacy sentence, after the Bluesky sentences", FE("privacy.html").indexOf(LEGAL.escapeHtml(PRIVACY)) !== -1 &&
    FE("privacy.html").indexOf(LEGAL.escapeHtml(LP.BLUESKY_MENTIONS_PRIVACY_SENTENCE)) < FE("privacy.html").indexOf(LEGAL.escapeHtml(PRIVACY)));
  check("L4. terms.html carries the terms sentence, after the Bluesky one", FE("terms.html").indexOf(LEGAL.escapeHtml(TERMS)) !== -1 &&
    FE("terms.html").indexOf(LEGAL.escapeHtml(LP.BLUESKY_TERMS_SENTENCE)) < FE("terms.html").indexOf(LEGAL.escapeHtml(TERMS)));
  check("L5. privacy.html lists the connection among what is collected", FE("privacy.html").indexOf(LEGAL.escapeHtml(YDATA.DATA ? (YDATA.DATA.find(d => d.table === "member_mastodon_connections") || {}).what || "" : "")) !== -1 ||
    FE("privacy.html").indexOf("Your connected Mastodon account: connected as @account on your server since the date you connected it.") !== -1);
  /* NAMED (campaign sharing, Nov 4 2026): BEFORE "2026-11-03", the version this change set. AFTER "2026-11-04", the version
     campaign sharing set when it added its Terms sentence; still an exact pin. */
  // NAMED (Nov 5 2026, images in social posts): BEFORE "2026-11-04" (campaign sharing). AFTER "2026-11-05", the version the social
  // images privacy sentence set.
  check("L6. TERMS_VERSION is the latest change's, 2026-11-05 (images in social posts; this change set 2026-11-03)", LEGAL.TERMS_VERSION === "2026-11-05", LEGAL.TERMS_VERSION);

  /* ── G. the guide tip ───────────────────────────────────────────────────── */
  console.log("\n══ G. the guide ══");
  {
    const guide = FE("scripts/termaximus-guide.js");
    const block = (/"social\.html": \[\n([\s\S]*?)\n    \]/.exec(guide) || ["", ""])[1];
    const tips = (block.match(/"(?:[^"\\]|\\.)*"/g) || []).map(t => JSON.parse(t));
    check("G1. social.html keeps 5 tips, and tip 5 says Bluesky and Mastodon connect so far",
      tips.length === 5 && tips[4] === "Bluesky and Mastodon connect so far, and posts cannot be scheduled; plans for the other platforms are yours to carry out.", JSON.stringify(tips[4]));
    check("G2. no tip still says only Bluesky connects", guide.indexOf("Only Bluesky connects") === -1);
  }

  /* ── Z. no network ──────────────────────────────────────────────────────── */
  console.log("\n══ Z. no network ══");
  check("Z. zero sockets, DNS lookups and fetches; every request went to the stub", NETWORK.length === 0, JSON.stringify(NETWORK));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check threw: " + (e && e.stack || e)); process.exit(1); });
