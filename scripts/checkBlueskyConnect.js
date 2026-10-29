"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkBlueskyConnect — a member connects their OWN Bluesky account with an
   app password, and the Social agent posts and edits the profile from it,
   through the approval gate or the member's own automation setting.

   server.js's connect, status, disconnect, automation and propose-profile
   routes, POST /api/agents/social/propose-post, POST /api/proposals, and the
   publish_social_post and update_bluesky_profile executors are lifted and run
   in a vm against an in-memory Supabase that enforces migration 152's CHECKs
   (hex-only ciphertext, iv and tag; one row per member and platform). Bluesky
   is a stub (lib/memberBluesky.js api.createAgent is replaced) that records
   every login, post and profile write, and the platform's gate is a stub that
   records every call. lib/apiKeyCrypto.js runs for real under a test key.
   Nothing leaves the machine: every socket and DNS lookup is a tripwire.

   WHAT THIS PROVES
     P. Migration 152: both tables, unique (user_id, platform), the hex CHECKs
        that make a plaintext app password unstorable, status values,
        auto_post default false, RLS on and no policy.
     A. The password is stored encrypted (AES-256-GCM, decrypts to what was
        typed), never in a response, a log line or the export.
     B. A bad handle, a wrongly formatted app password and a likely main
        password are refused, with the app-password help; nothing is sent to
        Bluesky and nothing is stored. Connecting is limited to 5 an hour.
     C. Bluesky refusing (400 with the exact message), unreachable (503),
        rate limiting (503) and a missing ENCRYPTION_SECRET (503, Bluesky never
        contacted) each store nothing.
     D. Status returns exactly { connected, handle, status, since }.
     E. Disconnect deletes only the caller's row; deleting the account
        (lib/yourData.js deleteAccount) deletes the connection and the setting
        log; the export holds only platform, handle and date.
     F. A member's post goes out from their own session, never the platform's
        and never another member's; the unconnected owner keeps the platform
        account; a connected owner posts from the connection; anyone else is
        refused; a proposal filed as one account never posts as another.
     G. Automation OFF: filing posts nothing until approval. ON: filing posts
        at once through the executor, and the grapheme and claims screens
        still refuse. The setting is per member, logged on every change.
     H. Profile edits always wait for approval, even with automation on; the
        update sets only displayName and description, never the avatar or
        banner; 64/256 graphemes and the claims screen refuse.
     I. A session failure marks needs_reconnect with ONE notice and one login,
        and is never retried; a later post is refused before any login.
     J. The pages: the Connect card with the steps, the bsky.app link, the
        fields, Connect, Disconnect, the switch and the reconnect state, run
        against the real routes in jsdom; "Posts as @handle" on proposals;
        the honest "coming, through each platform's own sign-in" line for
        every other platform, on the Social and Content agent pages.
     K. Privacy and Terms say what is stored, why, and who is responsible.
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
const Module = require("module");
const s = require("./_shared");

/* ── the network tripwire, before anything can open a socket ──────────────── */
const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkBlueskyConnect: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkBlueskyConnect: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const MUTATIONS = {
  // the app password is stored as typed
  "plaintext-stored": [["SRC", "          app_password_ciphertext: sealed.ciphertext,\n", "          app_password_ciphertext: password.value,\n"]],
  // the app password comes back in the connect response
  "password-in-response": [["SRC", "      return res.json(mb.statusOf(saved.data));\n",
    "      return res.json(Object.assign(mb.statusOf(saved.data), { app_password: password.value }));\n"]],
  // a connected member's post goes out from the platform's account
  "platform-for-connected-member": [["SRC", "  if (account.kind === \"member\") {\n    // The member's own session: one login, one post, no retry (lib/memberBluesky.js).\n",
    "  if (false) {\n    // The member's own session: one login, one post, no retry (lib/memberBluesky.js).\n"]],
  // automation skips the claims screen, at filing and in the executor
  "automation-skips-claims": [
    ["SRC", "      var claimsRefusal = blueskyClaimsRefusal(text);\n",
      "      var claimsRefusal = account.kind === \"member\" && account.row.auto_post === true ? null : blueskyClaimsRefusal(text);\n"],
    ["SRC", "  var claimsRefused = blueskyClaimsRefusal(text);\n",
      "  var claimsRefused = payload.posts_as && payload.posts_as.automatic === true ? null : blueskyClaimsRefusal(text);\n"]],
  // a profile edit is applied without waiting for approval
  "profile-without-approval": [["SRC", "      return res.status(201).json({\n        proposal: profileProposal.data,\n",
    "      await autoExecuteFiledProposal(profileProposal.data, executeUpdateBlueskyProfile);\n      return res.status(201).json({\n        proposal: profileProposal.data,\n"]],
  // a refused login is tried again
  "session-retry-loop": [["MB", "    await agent.login({ identifier: row.handle, password: password });\n  } catch (err) {\n    var kind = classify(err);\n",
    "    for (var attempt = 0; ; attempt++) {\n      try { await agent.login({ identifier: row.handle, password: password }); break; }\n      catch (again) { if (attempt >= 2) throw again; }\n    }\n  } catch (err) {\n    var kind = classify(err);\n"]],
  // the export reads every column of the connection
  "export-leaks-password": [["YD", "    owner: [\"user_id\"], key: \"platform\", select: \"platform, handle, created_at\", onDelete: \"delete\" },\n",
    "    owner: [\"user_id\"], key: \"platform\", onDelete: \"delete\" },\n"]],
  // anything is accepted as an app password
  "main-password-accepted": [["MB", "  if (APP_PASSWORD_RE.test(value)) return { ok: true, value: value };\n", "  return { ok: true, value: value };\n"]],
  // the needs_reconnect mark is not conditional, so every failure notifies again
  "notice-every-failure": [["SRC", "      .eq(\"platform\", \"bluesky\")\n      .eq(\"status\", \"connected\")\n      .select(\"id\");\n",
    "      .eq(\"platform\", \"bluesky\")\n      .select(\"id\");\n"]],
  // a refused verification is stored anyway
  "stored-without-verify": [["SRC", "        if (verified.kind === \"rejected\") {\n          return res.status(400).json({ error: mb.MESSAGES.rejected, code: \"bluesky_rejected\", saved: false });\n        }\n",
    "        if (verified.kind === \"rejected\") {\n          verified = { ok: true, did: \"did:plc:unverified\", handle: handle };\n        }\n"]],
  // the platform's Bluesky line is gone from the other platforms
  "honest-line-removed": [["FE:agents/social.html", "are coming, through each platform's own sign-in.</p>", "are available.</p>"]]
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
  MB: lf(fs.readFileSync(path.join(REPO, "lib/memberBluesky.js"), "utf8")),
  YD: lf(fs.readFileSync(path.join(REPO, "lib/yourData.js"), "utf8"))
};
const FE_FILES = ["agents/social.html", "agents/content.html", "proposals.html", "scripts/bluesky-connect.js", "scripts/social-publish.js",
  "privacy.html", "terms.html"];
FE_FILES.forEach(f => { SOURCES["FE:" + f] = lf(fs.readFileSync(path.join(FRONTEND, f), "utf8")); });
const MIGRATION = lf(fs.readFileSync(path.join(REPO, "supabase/migrations/152_member_social_connections.sql"), "utf8"));
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
const MB = loadLib("lib/memberBluesky.js", SOURCES.MB);
const YDATA = loadLib("lib/yourData.js", SOURCES.YD);

/* ── the stub Bluesky ─────────────────────────────────────────────────────── */
const PW = { alice: "abcd-efgh-ijkl-mnop", bob: "qrst-uvwx-yz12-3456", owner: "own1-own2-own3-own4" };
const BSKY = {
  accounts: {
    "alice.bsky.social": { did: "did:plc:alice111", password: PW.alice },
    "bob.example.com":   { did: "did:plc:bob22222", password: PW.bob },
    "owner.bsky.social": { did: "did:plc:owner333", password: PW.owner }
  },
  logins: [], posts: [], profiles: [],
  loginMode: null, postMode: null,
  record: { displayName: "Old name", description: "Old description", avatar: { ref: "blob-avatar" }, banner: { ref: "blob-banner" }, pinnedPost: { uri: "at://x" } },
  reset() { this.logins = []; this.posts = []; this.profiles = []; this.loginMode = null; this.postMode = null; }
};
function bskyError(status, name, message) { const e = new Error(message); e.status = status; e.error = name; return e; }
MB.api.createAgent = function () {
  const agent = {
    session: null,
    async login(cred) {
      BSKY.logins.push({ identifier: cred.identifier, password: cred.password });
      if (BSKY.loginMode === "unreachable") throw new TypeError("fetch failed");
      if (BSKY.loginMode === "rate") throw bskyError(429, "RateLimitExceeded", "Rate Limit Exceeded");
      if (BSKY.loginMode === "rejected") throw bskyError(401, "AuthenticationRequired", "Invalid identifier or password");
      const acct = BSKY.accounts[cred.identifier];
      if (!acct || acct.password !== cred.password) throw bskyError(401, "AuthenticationRequired", "Invalid identifier or password");
      agent.session = { did: acct.did, handle: cred.identifier };
    },
    async post(record) {
      BSKY.posts.push({ did: agent.session && agent.session.did, record: clone(record) });
      if (BSKY.postMode === "expired") throw bskyError(401, "ExpiredToken", "Token has expired");
      if (BSKY.postMode === "rate") throw bskyError(429, "RateLimitExceeded", "slow down");
      return { uri: "at://" + agent.session.did + "/app.bsky.feed.post/3k" + BSKY.posts.length, cid: "bafy" + BSKY.posts.length };
    },
    async upsertProfile(fn) {
      const next = fn(clone(BSKY.record));
      BSKY.profiles.push({ did: agent.session && agent.session.did, next: clone(next) });
    }
  };
  return agent;
};

/* ── the fake database, with migration 152's and 136's CHECKs ─────────────── */
const DRAFT_STATUSES = ["pending", "not_published", "scheduled", "pending_approval", "published", "publish_failed"];
function violates(table, row) {
  if (table === "member_social_connections") {
    if (row.platform !== "bluesky") return "member_social_connections_platform_check";
    if (["connected", "needs_reconnect", "disconnected"].indexOf(row.status) === -1) return "member_social_connections_status_check";
    if (typeof row.handle !== "string" || row.handle.length < 3 || row.handle.length > 253) return "member_social_connections_handle_check";
    if (typeof row.did !== "string" || row.did.indexOf("did:") !== 0) return "member_social_connections_did_check";
    if (!/^[0-9a-f]+$/.test(String(row.app_password_ciphertext))) return "member_social_connections_ciphertext_check";
    if (!/^[0-9a-f]{24}$/.test(String(row.app_password_iv))) return "member_social_connections_iv_check";
    if (!/^[0-9a-f]{32}$/.test(String(row.app_password_auth_tag))) return "member_social_connections_auth_tag_check";
    if (typeof row.auto_post !== "boolean") return "auto_post not null";
  }
  if (table === "member_social_setting_changes") {
    if (row.platform !== "bluesky" || row.setting !== "auto_post" || typeof row.new_value !== "boolean") return "member_social_setting_changes_check";
  }
  if (table === "social_post_drafts") {
    if (DRAFT_STATUSES.indexOf(row.status) === -1) return "social_post_drafts_status_check";
    if (row.status === "published" && (row.platform_post_uri == null || row.published_at == null)) return "social_post_drafts_published_check";
  }
  return null;
}
const DEFAULTS = {
  member_social_connections: () => ({ status: "connected", auto_post: false, auto_post_changed_at: null, last_ok_at: null, last_error_at: null, last_error_code: null, created_at: "2026-10-28T09:00:00.000Z" }),
  member_social_setting_changes: () => ({ old_value: null }),
  notifications: () => ({ read: false, created_at: "2026-10-28T12:00:00.000Z" })
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
    if (table === "member_social_connections" && rows(table).some(r => r.user_id === row.user_id && r.platform === row.platform)) {
      return { error: { code: "23505", message: "duplicate key value violates unique constraint \"member_social_connections_user_platform_unique\"" } };
    }
    rows(table).push(row);
    return { row };
  }
  function answer(q) {
    db.log.push(q);
    if (db.failOn) { const e = db.failOn(q); if (e) return Promise.resolve({ data: null, error: { message: e } }); }
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
function definitionOf(name) {
  let m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(SRC);
  if (m) return SRC.slice(m.index, s.braceMatch(SRC, SRC.indexOf(") {", m.index) + 2));
  const re = new RegExp("^(?:var|const|let) " + name + "[ \t]*=[ \t]*", "gm");
  while ((m = re.exec(SRC)) && SPANS.some(([x, y]) => m.index > x && m.index < y)) { /* a local */ }
  if (!m) return null;
  const brk = /;\n/g; brk.lastIndex = m.index + m[0].length;
  let b;
  while ((b = brk.exec(SRC))) {
    const next = SRC[b.index + b[0].length];
    if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SRC.slice(m.index, b.index + 1);
  }
  return null;
}
const STUBS = new Set(["supabase", "nowIso", "console", "process", "require", "module", "app", "Buffer", "setTimeout", "fetch",
  "requireAuth", "requireActiveSubscription", "aiLimiter", "bskyGate", "RichText", "rateLimit", "refuseUnlessSubscribed"]);
const uncommented = code => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closure(root) {
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
  return [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root;
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
  connect: ["post", "/api/social/bluesky/connect"], status: ["get", "/api/social/bluesky/status"],
  disconnect: ["post", "/api/social/bluesky/disconnect"], autoGet: ["get", "/api/social/bluesky/automation"],
  autoPut: ["put", "/api/social/bluesky/automation"], profile: ["post", "/api/social/bluesky/propose-profile"],
  propose: ["post", "/api/agents/social/propose-post"], proposals: ["post", "/api/proposals"]
};
let LIFTED;
try {
  LIFTED = closure(Object.keys(R).map(k => routeText(R[k][0], R[k][1])).join("\n\n") +
    "\n\nthis.api = { executePublishSocialPost: executePublishSocialPost, executeUpdateBlueskyProfile: executeUpdateBlueskyProfile," +
    " recordBlueskySession: recordBlueskySession, blueskyPostingAccount: blueskyPostingAccount };");
} catch (e) {
  console.log("    FAIL  the routes could not be lifted from server.js: " + e.message);
  process.exit(1);
}

const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";
const ALICE = "bbbbbbbb-0000-4000-8000-000000000002";
const BOB = "cccccccc-0000-4000-8000-000000000003";
const PLAIN = "dddddddd-0000-4000-8000-000000000004";
const tid = n => "11111111-0000-4000-8000-" + String(n).padStart(12, "0");
const FAMILY = "\u{1F468}\u200D\u{1F469}\u200D\u{1F467}";
const POST = "Saturday wheel class at 10am, two seats left: https://example.com/classes";
const CLAIM = "Our new clay tea treats diabetes, naturally.";
const runOutput = post => ({ success: true, platform: "bluesky", platform_label: "Bluesky", post: post, hook_note: "Leads with the day." });
const task = (n, user, post) => ({ id: tid(n), user_id: user, agent_type: "social", task_type: "social/post", status: "completed", output: runOutput(post) });
function seed() {
  return {
    users: [{ id: OWNER, role: "admin" }, { id: ALICE, role: "user" }, { id: BOB, role: "user" }, { id: PLAIN, role: "user" }],
    ai_tasks: [task(1, ALICE, POST), task(2, BOB, POST), task(3, OWNER, POST), task(4, PLAIN, POST), task(5, ALICE, CLAIM),
      task(6, ALICE, FAMILY.repeat(301)), task(7, ALICE, POST + " (second)"), task(8, ALICE, POST + " (third)")],
    social_post_drafts: [], agent_proposals: [], member_social_connections: [], member_social_setting_changes: [], notifications: []
  };
}

const LOGS = [];
function build(seedTables, opts) {
  opts = opts || {};
  const db = fakeDb(seedTables || seed());
  const gate = { calls: 0, posts: [] };
  gate.call = async function (fn) {
    gate.calls++;
    return { ok: true, value: await fn({ post: async (r) => { gate.posts.push(clone(r)); return { uri: "at://did:plc:platform/app.bsky.feed.post/3kp", cid: "bafyplatform" }; } }) };
  };
  const limiters = [];
  const state = { unsubscribed: false };
  const { RichText } = require(require.resolve("@atproto/api", { paths: [REPO] }));
  const ctx = {
    supabase: db.client, bskyGate: gate, RichText, Date, JSON, Math, Promise, Number, Object, Array, String, Intl, Buffer, RegExp, Error, TypeError,
    nowIso: () => "2026-10-28T12:00:00.000Z",
    process: { env: {} },
    require: p => p === "./lib/memberBluesky" ? MB : p === "./lib/apiKeyCrypto" ? CRYPTO : require(p.indexOf("./") === 0 ? path.join(REPO, p) : p),
    fetch: async (u) => { NETWORK.push("fetch " + u); throw new Error("no network"); },
    console: { log: m => LOGS.push([].slice.call(arguments).join(" ")), error: function () { LOGS.push([].slice.call(arguments).map(String).join(" ")); },
      warn: function () { LOGS.push([].slice.call(arguments).map(String).join(" ")); } },
    requireAuth: function requireAuth() {}, requireActiveSubscription: function requireActiveSubscription() {}, aiLimiter: function aiLimiter() {},
    rateLimit: function (o) { limiters.push(o); return function blueskyConnectLimiter() {}; },
    refuseUnlessSubscribed: async function (req, res) { if (state.unsubscribed) { res.status(402).json({ error: "subscribe" }); return true; } return false; }
  };
  ctx.console.log = function () { LOGS.push([].slice.call(arguments).map(String).join(" ")); };
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
  async function execute(name, proposal) {
    try { return { result: await ctx.api[name](clone(proposal)) }; } catch (e) { return { error: e }; }
  }
  // approve: what POST /api/proposals/:id/approve does for these two action types
  async function approve(proposal) {
    const name = proposal.action_type === "update_bluesky_profile" ? "executeUpdateBlueskyProfile" : "executePublishSocialPost";
    return execute(name, Object.assign({}, proposal, { status: "executing" }));
  }
  return { db, gate, ctx, routes, hit, execute, approve, limiters, state };
}
async function connected(b, user, handle, pw) {
  const r = await b.hit("connect", user, { handle: handle, app_password: pw });
  if (r.code !== 200) throw new Error("could not connect " + handle + ": " + r.code + " " + JSON.stringify(r.body));
  return r;
}
const conn = (b, user) => b.db.rows("member_social_connections").find(r => r.user_id === user);
const everything = b => JSON.stringify(b.db.tables);

(async function main() {
  /* ── P. the migration ───────────────────────────────────────────────────── */
  console.log("\n══ P. migration 152 ══");
  const sql = MIGRATION.replace(/--[^\n]*/g, "");
  check("P1. member_social_connections is created with every column the brief names",
    /CREATE TABLE IF NOT EXISTS public\.member_social_connections \(/.test(sql) &&
    ["user_id", "platform", "handle", "did", "app_password_ciphertext", "app_password_iv", "app_password_auth_tag", "status", "auto_post",
      "last_ok_at", "last_error_at", "last_error_code", "created_at", "updated_at"].every(c => new RegExp("\\n  " + c + "\\s").test(sql)));
  check("P2. unique (user_id, platform), platform bluesky only, status connected | needs_reconnect | disconnected",
    /UNIQUE \(user_id, platform\)/.test(sql) && /CHECK \(platform IN \('bluesky'\)\)/.test(sql) &&
    /CHECK \(status IN \('connected', 'needs_reconnect', 'disconnected'\)\)/.test(sql));
  check("P3. ciphertext, iv and auth tag must be lowercase hex, so an app password (it has dashes) cannot be stored as typed",
    /app_password_ciphertext ~ '\^\[0-9a-f\]\+\$'/.test(sql) && /app_password_iv ~ '\^\[0-9a-f\]\{24\}\$'/.test(sql) &&
    /app_password_auth_tag ~ '\^\[0-9a-f\]\{32\}\$'/.test(sql) && !/^[0-9a-f]+$/.test(PW.alice));
  check("P4. no plaintext password column, auto_post defaults false, the user FK cascades",
    !/\n  (app_)?password\s/.test(sql) && /auto_post\s+boolean\s+NOT NULL DEFAULT false/.test(sql) &&
    /user_id\s+uuid\s+NOT NULL REFERENCES public\.users\(id\) ON DELETE CASCADE/.test(sql));
  check("P5. RLS is enabled on both tables and no policy is created",
    /ALTER TABLE public\.member_social_connections ENABLE ROW LEVEL SECURITY;/.test(sql) &&
    /ALTER TABLE public\.member_social_setting_changes ENABLE ROW LEVEL SECURITY;/.test(sql) && !/CREATE POLICY/i.test(sql));
  const migs = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d{3}_/.test(f)).sort();
  check("P6. 152 is the next free number, used once", migs.filter(f => f.indexOf("152_") === 0).length === 1 &&
    migs.indexOf("152_member_social_connections.sql") === migs.indexOf("151_learning_loop.sql") + 1, migs.slice(-3).join(","));

  /* ── A. stored encrypted ────────────────────────────────────────────────── */
  console.log("\n══ A. the app password is stored encrypted, and nowhere else ══");
  BSKY.reset(); LOGS.length = 0;
  let b = build();
  let r = await b.hit("connect", ALICE, { handle: "@Alice.bsky.social ", app_password: PW.alice });
  let row = conn(b, ALICE);
  check("A1. connect: 200 with exactly { connected, handle, status, since }",
    r.code === 200 && JSON.stringify(Object.keys(r.body || {})) === JSON.stringify(["connected", "handle", "status", "since"]) &&
    r.body.connected === true && r.body.handle === "@alice.bsky.social" && r.body.status === "connected" && r.body.since === "2026-10-28T09:00:00.000Z",
    r.code + " " + JSON.stringify(r.body));
  check("A2. one login, with the handle normalized and the password as typed",
    BSKY.logins.length === 1 && BSKY.logins[0].identifier === "alice.bsky.social" && BSKY.logins[0].password === PW.alice, JSON.stringify(BSKY.logins.map(l => l.identifier)));
  check("A3. one row: alice's handle, the did Bluesky's session gave, status connected, automation off",
    row && row.handle === "alice.bsky.social" && row.did === "did:plc:alice111" && row.status === "connected" && row.auto_post === false && row.last_ok_at === "2026-10-28T12:00:00.000Z",
    JSON.stringify(row && Object.assign({}, row, { app_password_ciphertext: "…" })));
  let decrypted = null;
  try { decrypted = CRYPTO.decrypt({ ciphertext: row.app_password_ciphertext, iv: row.app_password_iv, authTag: row.app_password_auth_tag }); } catch (e) { decrypted = "THREW " + e.message; }
  check("A4. the stored ciphertext is AES-256-GCM under ENCRYPTION_SECRET and decrypts to exactly the password typed",
    row && /^[0-9a-f]+$/.test(row.app_password_ciphertext) && /^[0-9a-f]{24}$/.test(row.app_password_iv) && /^[0-9a-f]{32}$/.test(row.app_password_auth_tag) && decrypted === PW.alice, decrypted);
  check("A5. the plaintext is nowhere in the database", everything(b).indexOf(PW.alice) === -1);
  const st = await b.hit("status", ALICE);
  const auto = await b.hit("autoGet", ALICE);
  check("A6. the password is in no response (connect, status, automation) and no ciphertext either",
    [r, st, auto].every(x => JSON.stringify(x.body).indexOf(PW.alice) === -1 && JSON.stringify(x.body).indexOf(row.app_password_ciphertext) === -1 &&
      JSON.stringify(x.body).indexOf("app_password") === -1), JSON.stringify([r.body, st.body]));
  check("A7. the password is in no log line", LOGS.every(l => l.indexOf(PW.alice) === -1 && l.indexOf(row.app_password_ciphertext) === -1), LOGS.filter(l => l.indexOf(PW.alice) !== -1).join(" | "));
  r = await b.hit("connect", ALICE, { handle: "alice.bsky.social", app_password: PW.alice });
  check("A8. connecting again replaces the row (one per member and platform) and keeps the original date",
    r.code === 200 && b.db.rows("member_social_connections").filter(x => x.user_id === ALICE).length === 1 && r.body.since === "2026-10-28T09:00:00.000Z", r.code);

  /* ── B. refused before Bluesky is asked ─────────────────────────────────── */
  console.log("\n══ B. a bad handle, a wrong format and a likely main password are refused ══");
  const HELP = "Use an app password from Bluesky Settings → Privacy and security → App passwords";
  const refusals = [
    ["no handle", { app_password: PW.alice }, "handle_format", /Enter your Bluesky handle/],
    ["a handle with a space", { handle: "alice bsky", app_password: PW.alice }, "handle_format", /Enter your Bluesky handle/],
    ["no app password", { handle: "alice.bsky.social" }, "app_password_required", new RegExp(HELP)],
    ["three groups (abcd-efgh-ijkl)", { handle: "alice.bsky.social", app_password: "abcd-efgh-ijkl" }, "app_password_format", new RegExp("four groups of four[\\s\\S]*" + HELP)],
    ["uppercase groups", { handle: "alice.bsky.social", app_password: "ABCD-EFGH-IJKL-MNOP" }, "app_password_format", new RegExp(HELP)],
    ["a main password (Summer2026!)", { handle: "alice.bsky.social", app_password: "Summer2026!" }, "looks_like_main_password", new RegExp("main account password[\\s\\S]*" + HELP)],
    ["a long passphrase", { handle: "alice.bsky.social", app_password: "correct horse battery staple" }, "looks_like_main_password", new RegExp(HELP)]
  ];
  for (const [label, body, code, re] of refusals) {
    BSKY.reset();
    b = build();
    r = await b.hit("connect", ALICE, body);
    check("B. " + label + ": 400 " + code + ", with the help text, saved false", r.code === 400 && r.body.code === code && re.test(r.body.error) && r.body.saved === false,
      r.code + " " + JSON.stringify(r.body));
    check("B. " + label + ": Bluesky not contacted, nothing written", BSKY.logins.length === 0 && b.db.writes().length === 0, BSKY.logins.length + " / " + b.db.writes().length);
  }
  check("B. the main-password message ends with the brief's sentence", MB.MESSAGES.mainPassword.indexOf(HELP) !== -1);
  b = build();
  const lim = b.limiters.find(o => o && o.max === 5);
  check("B. connect is rate-limited to 5 an hour, per account, behind requireAuth and requireActiveSubscription",
    lim && lim.windowMs === 3600000 && lim.keyGenerator({ user: { id: ALICE } }) === "bsky-connect:" + ALICE &&
    JSON.stringify(b.routes["post /api/social/bluesky/connect"].middleware) === JSON.stringify(["requireAuth", "requireActiveSubscription", "blueskyConnectLimiter"]),
    JSON.stringify(b.routes["post /api/social/bluesky/connect"].middleware));

  /* ── C. a failed verification stores nothing ────────────────────────────── */
  console.log("\n══ C. verification that fails stores nothing ══");
  const failing = [
    ["a wrong app password", null, PW.bob, 400, "bluesky_rejected", /^Bluesky didn't accept that handle and app password$/],
    ["Bluesky unreachable", "unreachable", PW.alice, 503, "bluesky_unreachable", /couldn't be reached/],
    ["Bluesky rate limiting", "rate", PW.alice, 503, "bluesky_rate_limited", /limiting sign-ins/]
  ];
  for (const [label, mode, pw, code, reason, re] of failing) {
    BSKY.reset(); BSKY.loginMode = mode;
    b = build();
    r = await b.hit("connect", ALICE, { handle: "alice.bsky.social", app_password: pw });
    check("C. " + label + ": " + code + " " + reason, r.code === code && r.body.code === reason && re.test(r.body.error) && r.body.saved === false, r.code + " " + JSON.stringify(r.body));
    check("C. " + label + ": one login, nothing written, no row", BSKY.logins.length === 1 && b.db.writes().length === 0 && !conn(b, ALICE),
      BSKY.logins.length + " / " + JSON.stringify(b.db.writes().map(q => q.op + " " + q.table)));
  }
  BSKY.reset();
  b = build();
  delete process.env.ENCRYPTION_SECRET;
  r = await b.hit("connect", ALICE, { handle: "alice.bsky.social", app_password: PW.alice });
  process.env.ENCRYPTION_SECRET = TEST_KEY;
  check("C. no ENCRYPTION_SECRET: 503, Bluesky never contacted, nothing written",
    r.code === 503 && r.body.code === "no_encryption_key" && BSKY.logins.length === 0 && b.db.writes().length === 0, r.code + " " + JSON.stringify(r.body));

  /* ── D. status ──────────────────────────────────────────────────────────── */
  console.log("\n══ D. status returns only the safe fields ══");
  BSKY.reset();
  b = build();
  r = await b.hit("status", ALICE);
  check("D1. not connected: { connected: false, handle: null, status: disconnected, since: null }",
    r.code === 200 && JSON.stringify(r.body) === JSON.stringify({ connected: false, handle: null, status: "disconnected", since: null }), JSON.stringify(r.body));
  await connected(b, ALICE, "alice.bsky.social", PW.alice);
  r = await b.hit("status", ALICE);
  check("D2. connected: exactly the four keys, and the handle with its @",
    JSON.stringify(r.body) === JSON.stringify({ connected: true, handle: "@alice.bsky.social", status: "connected", since: "2026-10-28T09:00:00.000Z" }), JSON.stringify(r.body));
  const statusRead = b.db.log.filter(q => q.table === "member_social_connections" && q.op === "select").pop();
  check("D3. status reads only handle, status and created_at, scoped to the caller",
    statusRead && statusRead.cols === "handle, status, created_at" && statusRead.filters.some(f => f[0] === "eq" && f[1] === "user_id" && f[2] === ALICE), statusRead && statusRead.cols);
  conn(b, ALICE).status = "needs_reconnect";
  r = await b.hit("status", ALICE);
  check("D4. needs reconnecting: connected false, status needs_reconnect, the handle kept",
    JSON.stringify(r.body) === JSON.stringify({ connected: false, handle: "@alice.bsky.social", status: "needs_reconnect", since: "2026-10-28T09:00:00.000Z" }), JSON.stringify(r.body));
  r = await b.hit("status", BOB);
  check("D5. another member's status says nothing about alice", r.body.connected === false && r.body.handle === null, JSON.stringify(r.body));

  /* ── E. disconnect, account deletion and the export ─────────────────────── */
  console.log("\n══ E. disconnect, delete and export ══");
  BSKY.reset();
  b = build();
  await connected(b, ALICE, "alice.bsky.social", PW.alice);
  await connected(b, BOB, "bob.example.com", PW.bob);
  r = await b.hit("disconnect", ALICE);
  check("E1. disconnect: alice's row is deleted and bob's is untouched",
    r.code === 200 && r.body.removed === true && !conn(b, ALICE) && !!conn(b, BOB) && r.body.connected === false && /no longer holds your app password/.test(r.body.note), JSON.stringify(r.body));
  check("E2. disconnect is open without a subscription (requireAuth only)", JSON.stringify(b.routes["post /api/social/bluesky/disconnect"].middleware) === JSON.stringify(["requireAuth"]));
  r = await b.hit("disconnect", ALICE);
  check("E3. disconnecting again is harmless: removed false", r.code === 200 && r.body.removed === false);

  b = build();
  await connected(b, ALICE, "alice.bsky.social", PW.alice);
  await b.hit("autoPut", ALICE, { auto_post: true });
  await connected(b, BOB, "bob.example.com", PW.bob);
  const aliceRow = conn(b, ALICE);
  b.db.rows("profiles").push({ id: "p1", user_id: ALICE, username: "alice" });
  b.db.rows("users").find(u => u.id === ALICE).password_hash = "hash";
  const chunks = [];
  const manifest = await YDATA.exportAccountData({ supabase: b.db.client, userId: ALICE, write: t => chunks.push(t), now: new Date("2026-10-28T12:00:00Z") });
  const exported = chunks.join("");
  let file = null; try { file = JSON.parse(exported); } catch (e) { file = null; }
  const exRows = file && file.tables && file.tables.member_social_connections;
  check("E4. the export: member_social_connections is exactly [{ platform, handle, created_at }] — connected as @handle since the date",
    Array.isArray(exRows) && exRows.length === 1 && JSON.stringify(exRows[0]) === JSON.stringify({ platform: "bluesky", handle: "alice.bsky.social", created_at: "2026-10-28T09:00:00.000Z" }),
    JSON.stringify(exRows));
  check("E5. the export holds no password, ciphertext, iv, auth tag or did anywhere",
    exported.indexOf(PW.alice) === -1 && exported.indexOf(aliceRow.app_password_ciphertext) === -1 && exported.indexOf(aliceRow.app_password_iv) === -1 &&
    exported.indexOf(aliceRow.app_password_auth_tag) === -1 && exported.indexOf("app_password") === -1 && exported.indexOf("did:plc:alice111") === -1);
  check("E6. the export carries the setting log, and NEVER_EXPORTED says only the handle and date leave",
    file && Array.isArray(file.tables.member_social_setting_changes) && file.tables.member_social_setting_changes.length === 1 &&
    manifest.not_exported.some(x => /Bluesky app password: stored encrypted; the export shows only the handle and the date you connected/.test(x)));
  const del = await YDATA.deleteAccount({ supabase: b.db.client, storage: b.db.client.storage, publicUrlBase: "https://x.supabase.co/storage/v1/object/public/",
    userId: ALICE, body: { username: "alice", password: "pw" }, comparePassword: async (p) => p === "pw", activeSubscriptions: async () => [],
    ownerAccountId: OWNER, now: new Date("2026-10-28T12:00:00Z") });
  check("E7. deleting the account deletes alice's connection and setting log, and not bob's",
    del.status === 200 && !conn(b, ALICE) && !!conn(b, BOB) && b.db.rows("member_social_setting_changes").every(x => x.user_id !== ALICE), del.status + " " + JSON.stringify(del.body).slice(0, 200));
  check("E8. both tables are in the delete lists, the connection with the sign-in credentials",
    YDATA.FINAL_DELETES.indexOf("member_social_connections") !== -1 && YDATA.DELETE_ORDER.indexOf("member_social_setting_changes") !== -1);
  const backup = require(path.join(REPO, "lib/backup.js"));
  check("E9. backups: the connection is EXCLUDED (a credential never leaves the database), the setting log is backed up",
    Object.prototype.hasOwnProperty.call(backup.EXCLUDED_TABLES, "member_social_connections") && backup.BACKUP_TABLES.indexOf("member_social_setting_changes") !== -1);

  /* ── F. whose account a post goes out from ──────────────────────────────── */
  console.log("\n══ F. a member's post goes out from their own session ══");
  BSKY.reset();
  b = build();
  await connected(b, ALICE, "alice.bsky.social", PW.alice);
  await connected(b, BOB, "bob.example.com", PW.bob);
  BSKY.reset();
  r = await b.hit("propose", ALICE, { task_id: tid(1) });
  const pA = r.body && r.body.proposal;
  check("F1. alice files: 201, pending, payload posts_as { member, alice.bsky.social, automatic false }, nothing posted",
    r.code === 201 && pA.status === "pending" && JSON.stringify(pA.payload.posts_as) === JSON.stringify({ account: "member", handle: "alice.bsky.social", automatic: false }) &&
    BSKY.posts.length === 0 && BSKY.logins.length === 0 && b.gate.calls === 0 && /from your Bluesky account @alice\.bsky\.social/.test(r.body.note), r.code + " " + JSON.stringify(r.body));
  let x = await b.approve(pA);
  check("F2. approved: one login as alice with alice's password, one post from alice's did, the platform gate never called",
    x.result && BSKY.logins.length === 1 && BSKY.logins[0].identifier === "alice.bsky.social" && BSKY.logins[0].password === PW.alice &&
    BSKY.posts.length === 1 && BSKY.posts[0].did === "did:plc:alice111" && BSKY.posts[0].record.text === POST && b.gate.calls === 0,
    x.error ? x.error.message : JSON.stringify(BSKY.logins.map(l => l.identifier)) + " gate " + b.gate.calls);
  const dA = b.db.rows("social_post_drafts").find(d => d.id === pA.payload.draft_id);
  check("F3. the draft is published with the post uri from alice's account, and last_ok_at noted",
    dA.status === "published" && dA.platform_post_uri === x.result.uri && /^at:\/\/did:plc:alice111\//.test(dA.platform_post_uri) && conn(b, ALICE).last_ok_at === "2026-10-28T12:00:00.000Z",
    JSON.stringify(dA));
  BSKY.reset();
  r = await b.hit("propose", BOB, { task_id: tid(2) });
  x = await b.approve(r.body.proposal);
  check("F4. bob's post goes out from bob's own session, never alice's",
    x.result && BSKY.logins.length === 1 && BSKY.logins[0].identifier === "bob.example.com" && BSKY.logins[0].password === PW.bob &&
    BSKY.posts.length === 1 && BSKY.posts[0].did === "did:plc:bob22222" && BSKY.logins.every(l => l.password !== PW.alice), JSON.stringify(BSKY.logins.map(l => l.identifier)));
  BSKY.reset();
  r = await b.hit("propose", ALICE, { task_id: tid(7) });
  const forged = Object.assign({}, r.body.proposal, { payload: Object.assign({}, r.body.proposal.payload, { posts_as: { account: "member", handle: "bob.example.com", automatic: false } }) });
  x = await b.approve(forged);
  check("F5. alice's proposal edited to name bob's account: refused, nothing posted, bob's session never opened",
    x.error && /filed to post as @bob\.example\.com, and it would now post as @alice\.bsky\.social/.test(x.error.message) && BSKY.logins.length === 0 && BSKY.posts.length === 0,
    x.error ? x.error.message : "posted");
  const forgedOwner = Object.assign({}, r.body.proposal, { user_id: BOB });
  x = await b.approve(forgedOwner);
  check("F6. a proposal row naming bob reads bob's own draft and connection only: alice's draft is not his, nothing posted",
    x.error && BSKY.posts.length === 0 && BSKY.logins.length === 0, x.error ? x.error.message : "posted");

  BSKY.reset();
  r = await b.hit("propose", OWNER, { task_id: tid(3) });
  check("F7. the unconnected owner files for the platform's account: posts_as { platform }",
    r.code === 201 && JSON.stringify(r.body.proposal.payload.posts_as) === JSON.stringify({ account: "platform" }) && /from the platform's Bluesky account/.test(r.body.note), JSON.stringify(r.body));
  x = await b.approve(r.body.proposal);
  check("F8. …and it posts through the platform gate, with no member session", x.result && b.gate.calls === 1 && BSKY.logins.length === 0 && BSKY.posts.length === 0,
    x.error ? x.error.message : "gate " + b.gate.calls);
  const ownerPending = (await b.hit("propose", OWNER, { task_id: tid(3) })).body.proposal;
  await connected(b, OWNER, "owner.bsky.social", PW.owner);
  BSKY.reset(); b.gate.calls = 0;
  x = await b.approve(ownerPending);
  check("F9. the owner connects after filing for the platform: that proposal is refused, nothing posted anywhere",
    x.error && /filed to post as the platform's Bluesky account, and it would now post as @owner\.bsky\.social/.test(x.error.message) && b.gate.calls === 0 && BSKY.posts.length === 0,
    x.error ? x.error.message : "posted");
  r = await b.hit("propose", OWNER, { task_id: tid(3) });
  x = await b.approve(r.body.proposal);
  check("F10. a connected owner posts from the owner's connection, not the platform's",
    x.result && r.body.proposal.payload.posts_as.handle === "owner.bsky.social" && BSKY.posts.length === 1 && BSKY.posts[0].did === "did:plc:owner333" && b.gate.calls === 0,
    x.error ? x.error.message : "gate " + b.gate.calls);
  const before = b.db.writes().length;
  r = await b.hit("propose", PLAIN, { task_id: tid(4) });
  check("F11. an unconnected member who is not the owner: 403 telling them to connect, nothing written",
    r.code === 403 && r.body.code === "not_connected" && /Connect your own Bluesky account on the Social Agent page/.test(r.body.error) && b.db.writes().length === before, r.code + " " + JSON.stringify(r.body));
  BSKY.reset();
  const pending = (await b.hit("propose", ALICE, { task_id: tid(8) })).body.proposal;
  await b.hit("disconnect", ALICE);
  x = await b.approve(pending);
  check("F12. filed, then disconnected: refused at approval, nothing posted, no session",
    x.error && /limited to the owner account/.test(x.error.message) && BSKY.logins.length === 0 && BSKY.posts.length === 0 && b.gate.calls === 0, x.error ? x.error.message : "posted");

  /* ── G. the approval gate and the member's automation ──────────────────── */
  console.log("\n══ G. automation off keeps the gate; on skips only the approve step ══");
  BSKY.reset();
  b = build();
  await connected(b, ALICE, "alice.bsky.social", PW.alice);
  await connected(b, BOB, "bob.example.com", PW.bob);
  r = await b.hit("autoGet", ALICE);
  check("G1. automation is off by default, never changed", r.body.auto_post === false && r.body.available === true && r.body.changes.length === 0, JSON.stringify(r.body));
  BSKY.reset();
  r = await b.hit("propose", ALICE, { task_id: tid(1) });
  check("G2. OFF: filing leaves a pending proposal and a pending_approval draft, and posts nothing",
    r.code === 201 && r.body.proposal.status === "pending" && !r.body.automatic && r.body.draft.status === "pending_approval" && BSKY.posts.length === 0 && BSKY.logins.length === 0,
    r.code + " " + JSON.stringify(r.body).slice(0, 200));
  r = await b.hit("autoPut", ALICE, { auto_post: true });
  check("G3. turned on: auto_post true, one log row (false → true) with its time",
    r.code === 200 && r.body.auto_post === true && r.body.changes.length === 1 && r.body.changes[0].old_value === false && r.body.changes[0].new_value === true &&
    r.body.changes[0].changed_at === "2026-10-28T12:00:00.000Z", JSON.stringify(r.body));
  r = await b.hit("autoPut", ALICE, { auto_post: true });
  check("G4. setting the same value again logs nothing", b.db.rows("member_social_setting_changes").length === 1);
  check("G5. the setting is per member: bob's is still off", (await b.hit("autoGet", BOB)).body.auto_post === false);
  BSKY.reset();
  r = await b.hit("propose", ALICE, { task_id: tid(7) });
  const autoDraft = r.body && r.body.draft;
  check("G6. ON: filing posts at once from alice's session; the proposal is executed and the draft published with its uri",
    r.code === 201 && r.body.automatic === true && r.body.posted === true && r.body.proposal.status === "executed" && autoDraft.status === "published" &&
    BSKY.posts.length === 1 && BSKY.posts[0].did === "did:plc:alice111" && b.gate.calls === 0 && r.body.proposal.payload.posts_as.automatic === true &&
    /Posted automatically from @alice\.bsky\.social/.test(r.body.note), r.code + " " + JSON.stringify(r.body).slice(0, 300));
  BSKY.reset();
  const filedBefore = b.db.rows("agent_proposals").length;
  r = await b.hit("propose", ALICE, { task_id: tid(5) });
  check("G7. ON, a claim (\"treats diabetes\"): the claims screen still refuses, 400, nothing filed, nothing posted",
    r.code === 400 && r.body.code === "claims_screen" && /claims screen refused/.test(r.body.error) && /diabetes/.test(r.body.error) &&
    b.db.rows("agent_proposals").length === filedBefore && BSKY.posts.length === 0 && BSKY.logins.length === 0, r.code + " " + JSON.stringify(r.body));
  r = await b.hit("propose", ALICE, { task_id: tid(6) });
  check("G8. ON, 301 graphemes: still refused, nothing filed, nothing posted",
    r.code === 400 && /301 graphemes, over Bluesky's limit of 300/.test(r.body.error) && b.db.rows("agent_proposals").length === filedBefore && BSKY.posts.length === 0, r.code + " " + JSON.stringify(r.body));
  {
    // The executor's own screen, which automation runs too: a stored text that would not pass is refused there.
    const p = clone(b.db.rows("agent_proposals").find(q => q.status === "executed"));
    const t = b.db.rows("ai_tasks").find(q => q.id === tid(5));
    const d = b.db.rows("social_post_drafts").find(q => q.id === p.payload.draft_id);
    d.status = "pending_approval"; d.content = CLAIM; t.output.post = CLAIM;
    p.payload.text = CLAIM; p.payload.source_task_id = tid(5);
    BSKY.reset();
    x = await b.approve(p);
    check("G9. the executor screens again, automatic or not: a claim in the stored text is refused there, nothing posted",
      x.error && /claims screen refused/.test(x.error.message) && BSKY.posts.length === 0 && BSKY.logins.length === 0, x.error ? x.error.message : "posted");
  }
  b.state.unsubscribed = true;
  r = await b.hit("autoPut", BOB, { auto_post: true });
  check("G10. turning it on needs an active subscription: 402, nothing changed", r.code === 402 && conn(b, BOB).auto_post === false, r.code);
  r = await b.hit("autoPut", ALICE, { auto_post: false });
  check("G11. turning it off is always allowed, and logged (true → false)",
    r.code === 200 && r.body.auto_post === false && r.body.changes[0].old_value === true && r.body.changes[0].new_value === false, JSON.stringify(r.body));
  b.state.unsubscribed = false;
  r = await b.hit("autoPut", PLAIN, { auto_post: true });
  check("G12. with no connection it cannot be turned on", r.code === 400 && /Connect your Bluesky account first/.test(r.body.error), r.code);
  r = await b.hit("autoPut", ALICE, { auto_post: "yes" });
  check("G13. auto_post must be a boolean", r.code === 400);
  r = await b.hit("autoPut", OWNER, { auto_post: true });
  check("G14. the platform's account is never automated: the unconnected owner cannot turn it on", r.code === 400);

  /* ── H. profile edits ───────────────────────────────────────────────────── */
  console.log("\n══ H. profile edits always need approval ══");
  BSKY.reset();
  b = build();
  await connected(b, ALICE, "alice.bsky.social", PW.alice);
  await b.hit("autoPut", ALICE, { auto_post: true });
  BSKY.reset();
  r = await b.hit("profile", ALICE, { display_name: "Alice's Pottery", description: "Wheel classes on Saturdays." });
  const pp = r.body && r.body.proposal;
  check("H1. filed with automation ON: still pending, Bluesky not contacted",
    r.code === 201 && pp.status === "pending" && pp.action_type === "update_bluesky_profile" && BSKY.logins.length === 0 && BSKY.profiles.length === 0 &&
    JSON.stringify(pp.payload) === JSON.stringify({ display_name: "Alice's Pottery", description: "Wheel classes on Saturdays.", posts_as: { account: "member", handle: "alice.bsky.social", automatic: false } }),
    r.code + " " + JSON.stringify(r.body));
  check("H2. the note says nothing changed and the avatar and banner are never touched", /Nothing has changed on Bluesky/.test(r.body.note) && /avatar and banner are never touched/.test(r.body.note));
  x = await b.approve(pp);
  const next = BSKY.profiles[0] && BSKY.profiles[0].next;
  check("H3. approved: one session as alice, and the record keeps the avatar, banner and pinned post exactly",
    x.result && BSKY.logins.length === 1 && BSKY.profiles.length === 1 && BSKY.profiles[0].did === "did:plc:alice111" &&
    JSON.stringify(next.avatar) === JSON.stringify(BSKY.record.avatar) && JSON.stringify(next.banner) === JSON.stringify(BSKY.record.banner) &&
    JSON.stringify(next.pinnedPost) === JSON.stringify(BSKY.record.pinnedPost), x.error ? x.error.message : JSON.stringify(next));
  check("H4. …and sets only displayName and description",
    next && next.displayName === "Alice's Pottery" && next.description === "Wheel classes on Saturdays." &&
    JSON.stringify(Object.keys(next).sort()) === JSON.stringify(Object.keys(BSKY.record).sort()), JSON.stringify(next));
  BSKY.reset();
  r = await b.hit("profile", ALICE, { description: "New text only" });
  x = await b.approve(r.body.proposal);
  check("H5. only a description: the display name is left as Bluesky has it", x.result && BSKY.profiles[0].next.displayName === "Old name" && BSKY.profiles[0].next.description === "New text only");
  const profileRefusals = [
    ["a 65-grapheme display name", { display_name: FAMILY.repeat(65) }, /65 graphemes, over Bluesky's limit of 64/],
    ["a 257-grapheme description", { description: "x".repeat(257) }, /257 graphemes, over Bluesky's limit of 256/],
    ["a claim in the description", { description: "Our tea treats diabetes." }, /claims screen refused/],
    ["nothing to change", {}, /Give a display_name, a description, or both/],
    ["a display name that is not text", { display_name: 7 }, /must be text/]
  ];
  for (const [label, body, re] of profileRefusals) {
    const n = b.db.rows("agent_proposals").length;
    r = await b.hit("profile", ALICE, body);
    check("H6. " + label + ": 400, nothing filed", r.code === 400 && re.test(r.body.error) && b.db.rows("agent_proposals").length === n, r.code + " " + JSON.stringify(r.body));
  }
  r = await b.hit("profile", ALICE, { display_name: FAMILY.repeat(64), description: "y".repeat(256) });
  check("H7. exactly 64 and 256 graphemes are filed", r.code === 201, r.code + " " + JSON.stringify(r.body));
  r = await b.hit("profile", OWNER, { display_name: "Platform" });
  check("H8. the unconnected owner: 403 — the platform's profile is never edited", r.code === 403 && /platform's account is never edited/.test(r.body.error), r.code);
  r = await b.hit("proposals", ALICE, { agent_type: "social", action_type: "update_bluesky_profile", title: "x", payload: { display_name: "x" } });
  check("H9. POST /api/proposals refuses update_bluesky_profile", r.code === 400 && /propose-profile/.test(r.body.error), r.code);
  const gatedList = /const SUBSCRIPTION_GATED_PROPOSAL_ACTIONS = \[([^\]]*)\]/.exec(SRC);
  const execs = SRC.slice(SRC.indexOf("const PROPOSAL_EXECUTORS = {"), s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("const PROPOSAL_EXECUTORS = {"))) + 1);
  check("H10. registered as an executor and subscription gated at approval",
    /\n  update_bluesky_profile: executeUpdateBlueskyProfile,\n/.test(execs) && gatedList && /"update_bluesky_profile"/.test(gatedList[1]));
  check("H11. no code path files a profile update into autoExecuteFiledProposal",
    SRC.split("autoExecuteFiledProposal(").length === 3 && SRC.indexOf("autoExecuteFiledProposal(proposal, executePublishSocialPost)") !== -1);

  /* ── I. a session failure ───────────────────────────────────────────────── */
  console.log("\n══ I. a session failure: needs_reconnect, one notice, no retry ══");
  BSKY.reset();
  b = build();
  await connected(b, ALICE, "alice.bsky.social", PW.alice);
  const p1 = (await b.hit("propose", ALICE, { task_id: tid(1) })).body.proposal;
  const p2 = (await b.hit("propose", ALICE, { task_id: tid(7) })).body.proposal;
  BSKY.reset(); BSKY.loginMode = "rejected";
  x = await b.approve(p1);
  const c1 = conn(b, ALICE);
  check("I1. the login is refused: the post fails saying reconnect, and nothing is retried",
    x.error && /refused the session for @alice\.bsky\.social \(login_rejected\)/.test(x.error.message) && /Nothing is retried automatically/.test(x.error.message), x.error ? x.error.message : "posted");
  check("I2. exactly one login attempt and no post", BSKY.logins.length === 1 && BSKY.posts.length === 0, BSKY.logins.length);
  check("I3. the connection is needs_reconnect with last_error_code login_rejected",
    c1.status === "needs_reconnect" && c1.last_error_code === "login_rejected" && c1.last_error_at === "2026-10-28T12:00:00.000Z", JSON.stringify(Object.assign({}, c1, { app_password_ciphertext: "…" })));
  const notes = () => b.db.rows("notifications").filter(n => n.user_id === ALICE);
  check("I4. one in-app notice to alice, telling her to reconnect, with no password in it",
    notes().length === 1 && notes()[0].type === "bluesky_reconnect" && /Reconnect your Bluesky account/.test(notes()[0].title) &&
    /nothing will be tried again/.test(notes()[0].message) && notes()[0].message.indexOf(PW.alice) === -1, JSON.stringify(notes()));
  check("I5. the draft is publish_failed", b.db.rows("social_post_drafts").find(d => d.id === p1.payload.draft_id).status === "publish_failed");
  BSKY.reset();
  x = await b.approve(p2);
  check("I6. the next approval is refused before any login, and no second notice",
    x.error && /needs to be reconnected/.test(x.error.message) && BSKY.logins.length === 0 && notes().length === 1, x.error ? x.error.message : "posted");
  r = await b.hit("propose", ALICE, { task_id: tid(8) });
  check("I7. filing is refused too, 409 needs_reconnect", r.code === 409 && r.body.code === "needs_reconnect", r.code);
  await b.ctx.api.recordBlueskySession(ALICE, "alice.bsky.social", { ok: false, reason: "session_failed", code: "login_rejected" });
  check("I8. a second session failure recorded directly still raises no second notice", notes().length === 1, notes().length);
  r = await b.hit("connect", ALICE, { handle: "alice.bsky.social", app_password: PW.alice });
  check("I9. reconnecting with a working app password clears it: connected, no error code",
    r.code === 200 && conn(b, ALICE).status === "connected" && conn(b, ALICE).last_error_code === null, r.code);
  {
    const p3 = (await b.hit("propose", ALICE, { task_id: tid(8) })).body.proposal;
    BSKY.reset(); BSKY.postMode = "expired";
    x = await b.approve(p3);
    check("I10. a session refused at the post (ExpiredToken): one login, one post attempt, needs_reconnect, a second notice for this new failure",
      x.error && BSKY.logins.length === 1 && BSKY.posts.length === 1 && conn(b, ALICE).status === "needs_reconnect" && conn(b, ALICE).last_error_code === "session_refused" &&
      notes().length === 2, (x.error ? x.error.message : "posted") + " notes " + notes().length);
  }
  {
    BSKY.reset();
    const bb = build();
    await connected(bb, BOB, "bob.example.com", PW.bob);
    const p = (await bb.hit("propose", BOB, { task_id: tid(2) })).body.proposal;
    BSKY.reset(); BSKY.postMode = "rate";
    x = await bb.approve(p);
    check("I11. a rate limit is not a session failure: still connected, no notice, call_rate_limited noted, tried once",
      x.error && /rate limit on @bob\.example\.com/.test(x.error.message) && conn(bb, BOB).status === "connected" && conn(bb, BOB).last_error_code === "call_rate_limited" &&
      bb.db.rows("notifications").length === 0 && BSKY.logins.length === 1 && BSKY.posts.length === 1, x.error ? x.error.message : "posted");
  }
  check("I12. lib/memberBluesky.js withSession has one login and one call, and no loop, sleep or timer",
    (SOURCES.MB.match(/await agent\.login\(/g) || []).length === 2 && !/\bwhile\s*\(|\bfor\s*\(|setTimeout|setInterval/.test(SOURCES.MB.slice(SOURCES.MB.indexOf("async function withSession"))));

  /* ── J. the pages ───────────────────────────────────────────────────────── */
  console.log("\n══ J. the Social agent page, proposals and the honest line ══");
  const social = FE("agents/social.html");
  const card = (/<section class="context-card bsky-card" id="bskyConnect"[\s\S]*?<\/section>/.exec(social) || [""])[0];
  check("J1. social.html has the Connect Bluesky card: steps, a link to bsky.app's app-password settings, handle and app-password fields, Connect",
    /<h2 class="section-label">Connect Bluesky<\/h2>/.test(card) && /href="https:\/\/bsky\.app\/settings\/app-passwords"/.test(card) &&
    /Settings → Privacy and security → App passwords/.test(card) && /<input type="text" id="bskyHandle"/.test(card) &&
    /<input type="password" id="bskyAppPassword"[^>]*autocomplete="off"/.test(card) && />Connect<\/button>/.test(card) && /Never enter your main Bluesky password/.test(card));
  check("J2. …Disconnect, the switch \"Post approved drafts automatically\" (unchecked in the markup), and the reconnect slot",
    />Disconnect<\/button>/.test(card) && /<input type="checkbox" id="bskyAutoPost" \/> <span>Post approved drafts automatically<\/span>/.test(card) &&
    /id="bskyReconnect" hidden/.test(card) && /Profile changes always wait for your approval/.test(card));
  check("J3. the other platforms keep the honest line: coming, through each platform's own sign-in",
    /<p class="bsky-quiet" id="bskyOtherPlatforms">X, Instagram, LinkedIn, TikTok and Facebook are coming, through each platform's own sign-in\.<\/p>/.test(card));
  const intro = (/<p id="connectIntro"[^>]*>([^<]*)<\/p>/.exec(FE("agents/content.html")) || ["", ""])[1];
  check("J4. content.html: Bluesky points to the Social Agent page, never a main password, and Facebook and Instagram stay coming",
    intro === "Bluesky connects on the Social Agent page, with an app password you make in Bluesky, never your main password. Facebook and Instagram are coming, through each platform's own sign-in.", intro);
  check("J5. social.html loads agent-profile.js, social-publish.js, then bluesky-connect.js",
    /<script src="\/scripts\/agent-profile\.js"><\/script>\n<script src="\/scripts\/social-publish\.js"><\/script>\n<script src="\/scripts\/bluesky-connect\.js"><\/script>/.test(social));

  // The card, in jsdom, against the real routes.
  const { JSDOM } = require("jsdom");
  BSKY.reset();
  b = build();
  const stored = [];
  const dom = new JSDOM("<!doctype html><html><head></head><body>" + card + "</body></html>", { runScripts: "outside-only", url: "https://bizforce.example/agents/social.html" });
  const w = dom.window;
  const sent = [];
  w.localStorage.setItem("bf_token", "t");
  const realSet = w.localStorage.setItem.bind(w.localStorage);
  Object.defineProperty(w.localStorage, "setItem", { value: (k, v) => { stored.push([k, v]); realSet(k, v); } });
  w.fetch = function (url, init) {
    const method = (init && init.method) || "GET";
    const p = String(url).replace(/^https?:\/\/[^/]+/, "");
    const body = init && init.body ? JSON.parse(init.body) : undefined;
    sent.push({ method, path: p, body });
    const key = Object.keys(R).find(k => R[k][0] === method.toLowerCase() && R[k][1] === p);
    const pr = key ? b.hit(key, ALICE, body).then(res => ({ ok: res.code >= 200 && res.code < 300, status: res.code, json: () => Promise.resolve(clone(res.body)) }))
      : Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({ error: "unplanned " + method + " " + p }) });
    pr.catch(() => {});
    return pr;
  };
  w.eval(FE("scripts/bluesky-connect.js"));
  const flush = async () => { for (let i = 0; i < 40; i++) await new Promise(res => setImmediate(res)); };
  await flush();
  const $ = id => w.document.getElementById(id);
  check("J6. not connected: the form shows; connected, automation and profile are hidden",
    !$("bskyForm").hidden && $("bskyConnected").hidden && $("bskyAutomation").hidden && $("bskyProfile").hidden && $("bskyDisconnectBtn").hidden);
  $("bskyHandle").value = "alice.bsky.social"; $("bskyAppPassword").value = PW.bob;
  await w.bfBlueskyConnect.connect(); await flush();
  check("J7. a refused password: the server's exact message, the field cleared, still the form",
    $("bskyConnectMsg").textContent === "Bluesky didn't accept that handle and app password" && $("bskyAppPassword").value === "" && !$("bskyForm").hidden, $("bskyConnectMsg").textContent);
  $("bskyAppPassword").value = PW.alice;
  await w.bfBlueskyConnect.connect(); await flush();
  const connectSent = sent.filter(q => q.path === "/api/social/bluesky/connect");
  check("J8. connect sends exactly { handle, app_password } to the connect route, and nothing else ever carries the password",
    connectSent.length === 2 && JSON.stringify(Object.keys(connectSent[1].body)) === JSON.stringify(["handle", "app_password"]) &&
    sent.filter(q => q.path !== "/api/social/bluesky/connect").every(q => JSON.stringify(q.body || {}).indexOf(PW.alice) === -1));
  check("J9. connected: \"Connected as @alice.bsky.social\", the form hidden, the field cleared, Disconnect and the switch shown",
    $("bskyConnectedAs").textContent === "Connected as @alice.bsky.social" && $("bskyForm").hidden && $("bskyAppPassword").value === "" &&
    !$("bskyDisconnectBtn").hidden && !$("bskyAutomation").hidden && $("bskyAutoPost").checked === false, $("bskyConnectedAs").textContent);
  check("J10. the password was never put in localStorage", stored.every(([k, v]) => String(v).indexOf(PW.alice) === -1 && String(v).indexOf(PW.bob) === -1), JSON.stringify(stored));
  await w.bfBlueskyConnect.setAutomation(true); await flush();
  check("J11. the switch: PUT { auto_post: true }, the server's answer drawn, the change shown",
    sent.some(q => q.method === "PUT" && JSON.stringify(q.body) === JSON.stringify({ auto_post: true })) && $("bskyAutoPost").checked === true &&
    /^Turned on on /.test($("bskyAutoLog").textContent) && conn(b, ALICE).auto_post === true, $("bskyAutoLog").textContent);
  conn(b, ALICE).status = "needs_reconnect";
  await w.bfBlueskyConnect.loadStatus(); await flush();
  check("J12. needs reconnecting: the warning names the handle, the form is back, and Disconnect stays",
    !$("bskyReconnect").hidden && /@alice\.bsky\.social/.test($("bskyReconnectText").textContent) && !$("bskyForm").hidden && !$("bskyDisconnectBtn").hidden && $("bskyAutomation").hidden);
  await w.bfBlueskyConnect.disconnect(); await flush();
  check("J13. disconnect: the row is gone and the form is back", !conn(b, ALICE) && !$("bskyForm").hidden && $("bskyReconnect").hidden && $("bskyDisconnectBtn").hidden);

  // proposals.html's "Posts as".
  const PROP = FE("proposals.html");
  const fnSrc = name => { const i = PROP.indexOf("function " + name + "("); return i < 0 ? "" : PROP.slice(i, s.braceMatch(PROP, PROP.indexOf("{", i)) + 1); };
  const pctx = { Intl }; vm.createContext(pctx);
  vm.runInContext(["escapeHtml", "graphemeCountText", "postsAsText", "socialPostPayloadFields", "blueskyProfilePayloadFields"].map(fnSrc).join("\n"), pctx);
  const memberCard = pctx.socialPostPayloadFields({ text: POST, posts_as: { account: "member", handle: "alice.bsky.social", automatic: false } });
  const platformCard = pctx.socialPostPayloadFields({ text: POST });
  const evilCard = pctx.socialPostPayloadFields({ text: POST, posts_as: { account: "member", handle: "<b>x</b>" } });
  check("J14. proposals.html: a member's Bluesky proposal says \"Posts as @handle\"", memberCard.indexOf("Posts as @alice.bsky.social, as a new post") !== -1, memberCard.slice(0, 300));
  check("J15. …an old or platform proposal says the platform's account, and a handle is escaped",
    /Posts as the platform(&#39;|')s Bluesky account/.test(platformCard) && evilCard.indexOf("<b>") === -1, platformCard.slice(0, 300));
  const profileCard = pctx.blueskyProfilePayloadFields({ display_name: "A", description: "B", posts_as: { account: "member", handle: "alice.bsky.social" } });
  check("J16. a profile proposal names the account, the two fields, and says the picture and banner are unchanged",
    /Updates @alice\.bsky\.social/.test(profileCard) && /display name/.test(profileCard) && /picture, banner and everything else on the profile/.test(profileCard), profileCard);

  // social-publish.js's filing line for a connected member with automation on.
  {
    const fakeEl = id => ({ id, innerHTML: "", textContent: "", className: "", children: [], appendChild(c) { this.children.push(c); return c; } });
    const answers = { "/api/social/bluesky/status": { connected: true, handle: "@alice.bsky.social", status: "connected", since: "x" },
      "/api/social/bluesky/automation": { auto_post: true, changes: [], available: true } };
    const sctx = { window: {}, console, localStorage: { getItem() { return "t"; } },
      document: { readyState: "complete", head: fakeEl("head"), createElement() { return fakeEl(null); }, addEventListener() {} },
      fetch: (u) => { const p = String(u).replace(/^https?:\/\/[^/]+/, ""); return Promise.resolve({ ok: !!answers[p], status: answers[p] ? 200 : 404, json: () => Promise.resolve(answers[p] || { error: "no" }) }); } };
    vm.createContext(sctx);
    vm.runInContext(FE("scripts/social-publish.js"), sctx);
    const slot = fakeEl("slot");
    await sctx.window.bfSocialPublish.drawFiling(slot, { task_id: tid(1), persisted: true });
    check("J17. the filing button under a Bluesky result says \"Posts as @alice.bsky.social\" and, with automation on, that filing posts at once",
      /Posts as @alice\.bsky\.social/.test(slot.innerHTML) && /Post this now/.test(slot.innerHTML) && /data-sp-file/.test(slot.innerHTML) &&
      /is on: filing posts exactly this text at once/.test(slot.innerHTML), slot.innerHTML);
  }

  /* ── K. legal ───────────────────────────────────────────────────────────── */
  console.log("\n══ K. Privacy and Terms ══");
  const LP = require(path.join(REPO, "lib/legalPages.js"));
  const esc = require(path.join(REPO, "lib/legal.js")).escapeHtml;
  check("K1. Privacy says what is stored (handle, DID, the app password encrypted), its only use, disconnecting and deletion",
    /stores your Bluesky handle, its account id \(DID\) and the app password you made for BizForce, encrypted/.test(LP.BLUESKY_PRIVACY_SENTENCE) &&
    /used only to post or update your Bluesky profile when you approve a proposal, or when your own/.test(LP.BLUESKY_PRIVACY_SENTENCE) &&
    /disconnect at any time/.test(LP.BLUESKY_PRIVACY_SENTENCE) && /deleted with your account/.test(LP.BLUESKY_PRIVACY_SENTENCE) &&
    FE("privacy.html").indexOf(esc(LP.BLUESKY_PRIVACY_SENTENCE)) !== -1);
  check("K2. Terms: the member is responsible for what is posted, and BizForce posts only through approval or the member's own setting",
    /you are responsible for everything posted from it/.test(LP.BLUESKY_TERMS_SENTENCE) && /only when you approve a proposal, or when you have turned on/.test(LP.BLUESKY_TERMS_SENTENCE) &&
    FE("terms.html").indexOf(esc(LP.BLUESKY_TERMS_SENTENCE)) !== -1);
  check("K3. privacy.html lists the connection among what is collected, with the password never exported",
    FE("privacy.html").indexOf("Your connected Bluesky account: connected as @handle since the date you connected it. The app password is stored encrypted and is never exported.") !== -1);

  /* ── the platform account and Lead Radar are unchanged ──────────────────── */
  const GATE = lf(fs.readFileSync(path.join(REPO, "lib/bskyGate.js"), "utf8"));
  const RADAR = lf(fs.readFileSync(path.join(REPO, "leadRadar.js"), "utf8"));
  const { execFileSync } = require("child_process");
  const atBase = f => { try { return lf(execFileSync("git", ["show", "553d7da:" + f], { cwd: REPO, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 })); } catch (e) { return null; } };
  check("L1. lib/bskyGate.js and leadRadar.js are byte-identical to 553d7da (the platform login and Lead Radar are unchanged)",
    atBase("lib/bskyGate.js") === GATE && atBase("leadRadar.js") === RADAR);

  /* ── Z. no network ──────────────────────────────────────────────────────── */
  console.log("\n══ Z. no network ══");
  check("Z. zero sockets, DNS lookups and fetches", NETWORK.length === 0, JSON.stringify(NETWORK));

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check threw: " + (e && e.stack || e)); process.exit(1); });
