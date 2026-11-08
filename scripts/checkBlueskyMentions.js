"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkBlueskyMentions — the Bluesky Mentions inbox: read when asked, never
   stored; a reply drafted from the post's text only, and posted only after
   approval (migration 164, lib/memberBluesky.js, server.js).

   server.js's three /api/social/bluesky/mentions routes, the
   reply_bluesky_mention executor, blueskyPostingAccount and
   recordBlueskySession are lifted and run in a vm against an in-memory
   Supabase that enforces migration 164's reply CHECK with the migration's own
   patterns. Bluesky is a stub (lib/memberBluesky.js api.createAgent is
   replaced, and every method the route calls is recorded), the platform's
   gate is a stub, and the model (callAnthropicText) is a stub that records the
   exact message it was sent. Nothing leaves the machine: every socket and DNS
   lookup is a tripwire.

   WHAT THIS PROVES
     M. Migration 164 is the text as run, its patterns are the library's, and
        it is the highest migration.
     L. mentionTargets, replyRefsFor, mentionItem and the member back-off, on
        the SDK's shapes.
     R. The routes: auth, subscription, the limiters' numbers and keys.
     I. The inbox: one login and one listNotifications call; mention, reply
        and quote only; no updateSeen or other write call; nothing from the
        notifications written anywhere; the owner on the platform account; a
        member with no connection refused 403; needs_reconnect 409.
     D. Drafting: a bad uri refused before any login; not_yours refused; the
        references taken from Bluesky, never the body; the run's input holds
        only the references and the reason; the model message holds the post's
        text, the business details and the guidance, and no handle, DID,
        display name or address; over 300 graphemes refused, never cut.
     F. Filing: the draft and the proposal; never run automatically, even with
        "Post approved drafts automatically" on; the claims screen.
     E. The executor re-checks everything, posts one reply with the stored
        references, replays as already_published, fails without retrying.
     B. The back-off: no login while in force, cleared on success; the
        platform gate is never touched by a member.
     P. The page: the Mentions card, its labels, textContent only.
     K. Privacy and Terms, word for word, in the built pages.
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
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkBlueskyMentions: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkBlueskyMentions: no network"); };

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const MUTATIONS = {
  // the inbox writes what it read into a table
  "mention-stored": [["SRC", "      var nextCursor = typeof data.cursor === \"string\"",
    "      await supabase.from(\"bluesky_mentions\").insert(items);\n      var nextCursor = typeof data.cursor === \"string\""]],
  // a filed reply is posted at once when the member's automation is on
  "auto-executes-reply": [["SRC", "      // Never run automatically: a reply always waits for approval.\n",
    "      if (account.kind === \"member\" && account.row.auto_post === true) { await autoExecuteFiledProposal(proposal, executeReplyBlueskyMention); }\n"]],
  // the executor no longer runs the claims screen
  "executor-skips-claims": [["SRC", "  var replyClaims = blueskyClaimsRefusal(text);\n", "  var replyClaims = null;\n"]],
  // a draft over 300 graphemes is cut to fit instead of refused
  "truncates-instead-of-refuse": [["SRC", "      var graphemes = countGraphemes(reply);\n",
    "      if (countGraphemes(reply) > BLUESKY_MAX_GRAPHEMES) { reply = Array.from(GRAPHEME_SEGMENTER.segment(reply)).slice(0, BLUESKY_MAX_GRAPHEMES).map(function (x) { return x.segment; }).join(\"\"); }\n      var graphemes = countGraphemes(reply);\n"]],
  // the reply references are read from the request
  "refs-from-body": [["SRC", "      var refs = mb.replyRefsFor(got.post);\n",
    "      var refs = req.body.parent ? { parent: req.body.parent, root: req.body.root || req.body.parent } : mb.replyRefsFor(got.post);\n"]],
  // any post can be answered, whether or not it mentions the account
  "target-check-removed": [["SRC", "      if (!mb.mentionTargets(got.post, got.accountDid)) {\n", "      if (false) {\n"]],
  // the author's handle and display name go to the model
  "author-handle-to-model": [["SRC", "      var postText = blueskyQuotedText(got.post.record && got.post.record.text, got.post.author);\n",
    "      var postText = \"From @\" + got.post.author.handle + \" (\" + got.post.author.displayName + \"): \" + blueskyQuotedText(got.post.record && got.post.record.text, got.post.author);\n"]],
  // the post's text is kept in the run's stored input
  "text-in-run-input": [["SRC", "        reason: reason\n      };\n", "        reason: reason, text: got.post.record.text\n      };\n"]],
  // a member in back-off is logged in anyway
  "login-during-backoff": [["MB", "  var held = backoffUntil(userId, api.now());\n", "  var held = 0;\n"]],
  // reading the inbox marks the notifications seen
  "marks-seen": [["SRC", "        return agent.listNotifications(params);\n",
    "        return agent.listNotifications(params).then(function (r) { return agent.updateSeenNotifications().then(function () { return r; }); });\n"]],
  // a member with no connection reads through the platform's account
  "platform-for-non-admin": [["SRC", "  return role === \"admin\" ? { kind: \"platform\" } : { kind: \"none\" };\n", "  return { kind: \"platform\" };\n"]],
  // the page draws a post's text as HTML
  "innerHTML-on-page": [["FE:scripts/bluesky-mentions.js", "    li.appendChild(el(\"p\", \"bsky-mention-text\", typeof item.text === \"string\" ? item.text : \"\"));\n",
    "    var tx = el(\"p\", \"bsky-mention-text\"); tx.innerHTML = String(item.text); li.appendChild(tx);\n"]],
  // the Mentions sentence is gone from the built Privacy Policy
  "privacy-sentence-removed": [["FE:privacy.html", "Your Mentions inbox is read from Bluesky each time you ask and is not stored. ", ""]],
  // the executor posts whatever reply references the proposal names
  "executor-skips-refs": [["SRC", "  if (!sameRefs(fromPayload, fromRun) || !sameRefs(fromPayload, draft)) {\n", "  if (false) {\n"]],
  // a bad uri is sent to Bluesky
  "uri-unchecked": [["SRC", "      if (!mb.isPostUri(uri)) {\n        return res.status(400)", "      if (false) {\n        return res.status(400)"]],
  // a published reply is posted again on replay
  "replay-posts-again": [["SRC", "  if (draft.platform_post_uri && draft.status === \"published\") {\n    return { already_published: true, uri: draft.platform_post_uri, cid: draft.platform_post_cid || null };\n  }\n  if (draft.status !== \"pending_approval\") throw fail(",
    "  if (draft.status !== \"pending_approval\" && draft.status !== \"published\") throw fail("]],
  // the over-limit draft is not refused at filing
  "propose-skips-graphemes": [["SRC", "      var graphemes = countGraphemes(text);\n      if (graphemes > BLUESKY_MAX_GRAPHEMES) {\n        recordGateDecision(userId, \"social_post\", \"ai_task:\" + task.id, { G8: { result: \"fail\", code: \"over_grapheme_limit\" } }, { facts: replyGateFacts });\n",
    "      var graphemes = 0;\n      if (graphemes > BLUESKY_MAX_GRAPHEMES) {\n        recordGateDecision(userId, \"social_post\", \"ai_task:\" + task.id, { G8: { result: \"fail\", code: \"over_grapheme_limit\" } }, { facts: replyGateFacts });\n"]]
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
  MB: lf(fs.readFileSync(path.join(REPO, "lib/memberBluesky.js"), "utf8"))
};
const FE_FILES = ["agents/social.html", "scripts/bluesky-mentions.js", "scripts/bluesky-connect.js", "scripts/termaximus-guide.js", "proposals.html",
  "privacy.html", "terms.html"];
FE_FILES.forEach(f => { SOURCES["FE:" + f] = lf(fs.readFileSync(path.join(FRONTEND, f), "utf8")); });
const MIGRATION = lf(fs.readFileSync(path.join(REPO, "supabase/migrations/164_bluesky_reply_refs.sql"), "utf8"));
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [where, from, to] of edits) SOURCES[where] = s.replaceOnce(SOURCES[where], from, to, MUTATE + " in " + where);
  console.log("\n!! MUTATION: " + MUTATE);
}
const SRC = SOURCES.SRC;
const FE = f => SOURCES["FE:" + f];

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
const CLOCK = { t: Date.parse("2026-11-03T12:00:00.000Z") };
MB.api.now = () => CLOCK.t;

/* ── the Bluesky world ────────────────────────────────────────────────────── */
const ALICE_DID = "did:plc:alice111", BOB_DID = "did:plc:bob22222", PLATFORM_DID = "did:plc:platform9";
const CAROL = { did: "did:plc:carol333", handle: "carol.example.com", displayName: "Carol Potter", avatar: "https://cdn.example/a.jpg", labels: [{ val: "x" }] };
const DAVE = { did: "did:plc:dave4444", handle: "dave.bsky.social", displayName: "Dave Kiln", avatar: "https://cdn.example/d.jpg" };
const EVE = { did: "did:plc:eve55555", handle: "eve.bsky.social", displayName: "Eve" };
const ALICE_AUTHOR = { did: ALICE_DID, handle: "alice.bsky.social", displayName: "Alice Studio" };
const cid = n => "bafyrei" + "abcdefghijklmnopqrstuvwxyz".split("").map((c, i) => "abcdefghijklmnopqrstuvwxyz"[(i + n) % 26]).join("");
const uriOf = (did, rkey) => "at://" + did + "/app.bsky.feed.post/" + rkey;
const POSTS = {};
function addPost(key, author, rkey, record, n) {
  const p = { uri: uriOf(author.did, rkey), cid: cid(n), author: clone(author), record: Object.assign({ $type: "app.bsky.feed.post", createdAt: "2026-11-03T10:00:00.000Z" }, record), indexedAt: "2026-11-03T10:0" + (n % 10) + ":00.000Z" };
  POSTS[key] = p;
  return p;
}
const OWN = addPost("OWN", ALICE_AUTHOR, "3kown1", { text: "Saturday wheel class at 10am, two seats left." }, 1);
const MENTION_TEXT = "Hey @alice.bsky.social, do you run kids classes? Carol Potter here, see https://example.com/x and at://did:plc:zz/app.bsky.feed.post/q";
const MENTION = addPost("MENTION", CAROL, "3kmen1", { text: MENTION_TEXT,
  facets: [{ index: { byteStart: 4, byteEnd: 22 }, features: [{ $type: "app.bsky.richtext.facet#mention", did: ALICE_DID }] }] }, 2);
const REPLY_TEXT = "Is the Saturday class good for complete beginners?";
const REPLY = addPost("REPLY", CAROL, "3krep1", { text: REPLY_TEXT,
  reply: { root: { uri: OWN.uri, cid: OWN.cid }, parent: { uri: OWN.uri, cid: OWN.cid } } }, 3);
const QUOTE = addPost("QUOTE", DAVE, "3kquo1", { text: "This studio is lovely.", embed: { $type: "app.bsky.embed.record", record: { uri: OWN.uri, cid: OWN.cid } } }, 4);
const QUOTE_MEDIA = addPost("QUOTE_MEDIA", DAVE, "3kquo2", { text: "Look at this.",
  embed: { $type: "app.bsky.embed.recordWithMedia", record: { record: { uri: OWN.uri, cid: OWN.cid } }, media: { $type: "app.bsky.embed.images" } } }, 5);
const SELF = addPost("SELF", ALICE_AUTHOR, "3kself", { text: "Note to self @alice.bsky.social",
  facets: [{ index: { byteStart: 13, byteEnd: 31 }, features: [{ $type: "app.bsky.richtext.facet#mention", did: ALICE_DID }] }] }, 6);
const OTHER = addPost("OTHER", CAROL, "3koth1", { text: "I love alice.bsky.social pottery (no facet)." }, 7);
const THREAD_ROOT = addPost("THREAD_ROOT", EVE, "3kroot", { text: "Who teaches pottery nearby?" }, 8);
const OWN_IN_THREAD = addPost("OWN_IN_THREAD", ALICE_AUTHOR, "3kown2", { text: "We do, on Saturdays.",
  reply: { root: { uri: THREAD_ROOT.uri, cid: THREAD_ROOT.cid }, parent: { uri: THREAD_ROOT.uri, cid: THREAD_ROOT.cid } } }, 9);
const NESTED = addPost("NESTED", CAROL, "3knest", { text: "How much is a class?",
  reply: { root: { uri: THREAD_ROOT.uri, cid: THREAD_ROOT.cid }, parent: { uri: OWN_IN_THREAD.uri, cid: OWN_IN_THREAD.cid } } }, 10);
const LOOKALIKE = addPost("LOOKALIKE", CAROL, "3klook", { text: "Replying to someone else",
  reply: { root: { uri: uriOf("did:plc:alice1112", "3kx"), cid: cid(11) }, parent: { uri: uriOf("did:plc:alice1112", "3kx"), cid: cid(11) } } }, 11);
const PLATFORM_MENTION = addPost("PLATFORM_MENTION", CAROL, "3kplat", { text: "Hello BizForce",
  facets: [{ index: { byteStart: 0, byteEnd: 5 }, features: [{ $type: "app.bsky.richtext.facet#mention", did: PLATFORM_DID }] }] }, 12);
const BADCID = addPost("BADCID", CAROL, "3kbadc", { text: "bad cid @alice",
  facets: [{ index: { byteStart: 8, byteEnd: 14 }, features: [{ $type: "app.bsky.richtext.facet#mention", did: ALICE_DID }] }] }, 13);
BADCID.cid = "not-a-cid";

const note = (reason, post, extra) => Object.assign({ uri: post.uri, cid: post.cid, author: clone(post.author), reason: reason, record: clone(post.record),
  isRead: false, indexedAt: post.indexedAt, labels: [{ val: "spam?" }] }, extra || {});
const NOTES = [note("mention", MENTION), note("reply", REPLY), note("quote", QUOTE),
  note("like", OWN, { author: clone(DAVE), reasonSubject: OWN.uri }), note("follow", OWN, { author: clone(EVE) }), note("repost", OWN, { author: clone(DAVE) })];

const PW = { alice: "abcd-efgh-ijkl-mnop", bob: "qrst-uvwx-yz12-3456" };
const BSKY = {
  accounts: { "alice.bsky.social": { did: ALICE_DID, password: PW.alice }, "bob.example.com": { did: BOB_DID, password: PW.bob } },
  logins: [], calls: [], posts: [], loginMode: null, callMode: null,
  reset() { this.logins = []; this.calls = []; this.posts = []; this.loginMode = null; this.callMode = null; }
};
function bskyError(status, name, headers) { const e = new Error("bluesky said " + status); e.status = status; e.error = name; if (headers) e.headers = headers; return e; }
function worldAgent(log, session) {
  const agent = {
    session: session || null,
    async listNotifications(params) {
      log.push({ m: "listNotifications", params: clone(params) });
      if (BSKY.callMode === "rate") throw bskyError(429, "RateLimitExceeded", { "retry-after": "600" });
      if (BSKY.callMode === "expired") throw bskyError(401, "ExpiredToken");
      return { success: true, headers: {}, data: { notifications: clone(NOTES), cursor: params && params.cursor ? null : "cursor-page-2", seenAt: "2026-11-01T00:00:00.000Z" } };
    },
    async getPosts(params) {
      log.push({ m: "getPosts", params: clone(params) });
      if (BSKY.callMode === "rate") throw bskyError(429, "RateLimitExceeded");
      const found = (params.uris || []).map(u => Object.values(POSTS).find(p => p.uri === u)).filter(Boolean);
      return { success: true, headers: {}, data: { posts: clone(found) } };
    },
    async post(record) {
      log.push({ m: "post", record: clone(record) });
      BSKY.posts.push({ did: agent.session && agent.session.did, record: clone(record) });
      if (BSKY.callMode === "postfail") throw bskyError(400, "InvalidRequest");
      return { uri: uriOf((agent.session && agent.session.did) || "did:plc:none", "3kposted" + BSKY.posts.length), cid: cid(20 + BSKY.posts.length) };
    },
    // NAMED (Nov 5 2026, images in social posts): BEFORE no uploadBlob (the Proxy below would only record it). AFTER a real one, as
    // the post executor now calls it for a post with images; replies carry none in this build, so it is never called here.
    async uploadBlob(bytes, o) {
      log.push({ m: "uploadBlob", size: bytes.length });
      return { success: true, data: { blob: { $type: "blob", ref: { $link: "bafkblob" }, mimeType: o && o.encoding, size: bytes.length } } };
    }
  };
  // Every other method is recorded by name: none may be called.
  return new Proxy(agent, {
    get(target, prop) {
      if (prop in target) return target[prop];
      if (typeof prop !== "string" || prop === "then") return undefined;
      return function () { log.push({ m: prop }); return Promise.resolve({ success: true, data: {} }); };
    }
  });
}
MB.api.createAgent = function () {
  const holder = { session: null };
  const a = worldAgent(BSKY.calls, null);
  // login is the member session's own, recorded separately.
  const target = Object.getPrototypeOf(a) ? a : a;
  return new Proxy({}, {
    get(t, prop) {
      if (prop === "login") return async function (cred) {
        BSKY.logins.push({ identifier: cred.identifier });
        if (BSKY.loginMode === "rate") throw bskyError(429, "RateLimitExceeded", { "retry-after": "900" });
        const acct = BSKY.accounts[cred.identifier];
        if (!acct || acct.password !== cred.password) throw bskyError(401, "AuthenticationRequired");
        holder.session = { did: acct.did, handle: cred.identifier };
      };
      if (prop === "session") return holder.session;
      const v = target[prop];
      if (typeof v === "function") return function () { a.session = holder.session; return v.apply(a, arguments); };
      return v;
    }
  });
};

/* ── the fake database, with migration 164's CHECK, read from the file ───── */
const SQL_PATTERNS = (MIGRATION.match(/~ '([^']+)'/g) || []).map(x => x.slice(3, -1));
const SQL_URI = SQL_PATTERNS[0], SQL_CID = SQL_PATTERNS[2];
const DB_URI = new RegExp(SQL_URI), DB_CID = new RegExp(SQL_CID);
const DRAFT_STATUSES = ["pending", "not_published", "scheduled", "pending_approval", "published", "publish_failed"];
const REPLY_COLS = ["reply_parent_uri", "reply_parent_cid", "reply_root_uri", "reply_root_cid"];
function violates(table, row) {
  if (table === "social_post_drafts") {
    if (DRAFT_STATUSES.indexOf(row.status) === -1) return "social_post_drafts_status_check";
    if (row.status === "published" && (row.platform_post_uri == null || row.published_at == null)) return "social_post_drafts_published_check";
    const set = REPLY_COLS.filter(c => row[c] != null).length;
    if (set !== 0 && !(set === 4 && row.platform === "bluesky" && row.reply_parent_uri.length <= 1024 && row.reply_root_uri.length <= 1024 &&
      DB_URI.test(row.reply_parent_uri) && DB_URI.test(row.reply_root_uri) && DB_CID.test(row.reply_parent_cid) && DB_CID.test(row.reply_root_cid))) {
      return "social_post_drafts_reply_refs_check";
    }
  }
  return null;
}
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
  const keep = (q, r) => q.filters.every(f => f[0] === "eq" ? r[f[1]] === f[2] : f[0] === "neq" ? r[f[1]] !== f[2] : f[0] === "in" ? f[2].indexOf(r[f[1]]) !== -1 : true);
  function finish(q, list) {
    const cols = q.op === "select" ? q.cols : q.retCols;
    let out = list;
    if (q.from !== null) out = out.slice(q.from, q.to + 1);
    const data = (q.op === "select" || q.returning) ? out.map(r => project(r, cols)) : null;
    if (q.single === "single") return data && data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116", message: (data ? data.length : 0) + " rows" } };
    if (q.single === "maybe") return data && data.length > 1 ? { data: null, error: { message: "more than one row" } } : { data: data ? data[0] || null : null, error: null };
    return { data: data, error: null };
  }
  function answer(q) {
    db.log.push(q);
    if (q.op === "insert") {
      const list = Array.isArray(q.payload) ? q.payload : [q.payload];
      const made = [];
      for (const p of list) {
        const row = Object.assign({ id: "00000000-0000-4000-8000-" + String(++db.seq).padStart(12, "0") }, clone(p));
        const bad = violates(q.table, row);
        if (bad) return Promise.resolve({ data: null, error: { code: "23514", message: "violates check constraint \"" + bad + "\"" } });
        rows(q.table).push(row); made.push(row);
      }
      return Promise.resolve(finish(q, made));
    }
    const hits = rows(q.table).filter(r => keep(q, r));
    if (q.op === "update") {
      for (const r of hits) { const bad = violates(q.table, Object.assign({}, r, q.payload)); if (bad) return Promise.resolve({ data: null, error: { code: "23514", message: bad } }); }
      hits.forEach(r => Object.assign(r, clone(q.payload)));
      return Promise.resolve(finish(q, hits));
    }
    if (q.op === "delete") { db.tables[q.table] = rows(q.table).filter(r => hits.indexOf(r) === -1); return Promise.resolve(finish(q, hits)); }
    return Promise.resolve(finish(q, hits));
  }
  function from(table) {
    const q = { table, op: "select", cols: "*", retCols: "*", payload: null, filters: [], single: false, returning: false, from: null, to: null };
    const b = {
      select(cols) { if (q.op === "select") q.cols = cols || "*"; else { q.returning = true; q.retCols = cols || "*"; } return b; },
      insert(p) { q.op = "insert"; q.payload = p; return b; },
      update(p) { q.op = "update"; q.payload = p; return b; },
      upsert(p) { q.op = "insert"; q.payload = p; return b; },
      delete() { q.op = "delete"; return b; },
      eq(c, v) { q.filters.push(["eq", c, v]); return b; },
      neq(c, v) { q.filters.push(["neq", c, v]); return b; },
      in(c, v) { q.filters.push(["in", c, v]); return b; },
      is() { return b; }, or() { return b; }, not() { return b; }, gte() { return b; }, lte() { return b; }, lt() { return b; }, gt() { return b; },
      order() { return b; },
      limit(n) { q.from = 0; q.to = n - 1; return b; },
      range(a, z) { q.from = a; q.to = z; return b; },
      single() { q.single = "single"; return answer(q); },
      maybeSingle() { q.single = "maybe"; return answer(q); },
      then(res, rej) { return answer(q).then(res, rej); }
    };
    return b;
  }
  db.client = { from, async rpc() { return { data: 0, error: null }; } };
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
  "requireAuth", "requireActiveSubscription", "aiLimiter", "bskyGate", "RichText", "rateLimit", "refuseUnlessSubscribed",
  "callAnthropicText", "memberGuidanceFor", "loadProfileForTool", "resolvePreferredLanguage", "recordGateDecision", "memberGateCheck",
  "buildAgentSystemPrompt", "buildLanguageInstruction"]);
// A // is a comment only when no ":" (or quote or backslash) is right before it, so "https://" survives.
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
  inbox: ["get", "/api/social/bluesky/mentions"],
  draft: ["post", "/api/social/bluesky/mentions/draft-reply"],
  propose: ["post", "/api/social/bluesky/mentions/propose-reply"]
};
let LIFTED, SCRIPT;
try {
  LIFTED = closure(Object.keys(R).map(k => routeText(R[k][0], R[k][1])).join("\n\n") +
    "\n\nthis.api = { executeReplyBlueskyMention: executeReplyBlueskyMention, blueskyPostingAccount: blueskyPostingAccount };");
  SCRIPT = new vm.Script(LIFTED, { filename: "server.js (lifted)" });
} catch (e) {
  console.log("    FAIL  the routes could not be lifted from server.js: " + e.message);
  process.exit(1);
}

const OWNER = "aaaaaaaa-0000-4000-8000-000000000001";
const ALICE = "bbbbbbbb-0000-4000-8000-000000000002";
const BOB = "cccccccc-0000-4000-8000-000000000003";
const PLAIN = "dddddddd-0000-4000-8000-000000000004";
const RECON = "eeeeeeee-0000-4000-8000-000000000005";
const BUSINESS = "Clay Corner Studio";
const GUIDANCE = "MEMBER GUIDANCE MARKER: keep replies warm.";
const CLAIM = "Our clay tea treats diabetes, naturally.";
function connRow(id, user, handle, did, pw, extra) {
  const sealed = CRYPTO.encrypt(pw);
  return Object.assign({ id: id, user_id: user, platform: "bluesky", handle: handle, did: did, app_password_ciphertext: sealed.ciphertext,
    app_password_iv: sealed.iv, app_password_auth_tag: sealed.authTag, status: "connected", auto_post: false, created_at: "2026-10-28T09:00:00.000Z" }, extra || {});
}
function seed() {
  return {
    users: [{ id: OWNER, role: "admin" }, { id: ALICE, role: "user" }, { id: BOB, role: "user" }, { id: PLAIN, role: "user" }, { id: RECON, role: "user" }],
    member_social_connections: [
      connRow("10000000-0000-4000-8000-000000000001", ALICE, "alice.bsky.social", ALICE_DID, PW.alice),
      connRow("10000000-0000-4000-8000-000000000002", BOB, "bob.example.com", BOB_DID, PW.bob, { auto_post: true }),
      connRow("10000000-0000-4000-8000-000000000003", RECON, "recon.bsky.social", "did:plc:recon666", PW.alice, { status: "needs_reconnect" })
    ],
    ai_tasks: [], social_post_drafts: [], agent_proposals: [], notifications: []
  };
}

const LOGS = [];
const MODEL = { calls: [], next: "REPLY: Yes, complete beginners are welcome on Saturday." };
function build(seedTables) {
  const db = fakeDb(seedTables || seed());
  const gate = { calls: 0, log: [] };
  gate.call = async function (fn) { gate.calls++; return { ok: true, value: await fn(worldAgent(gate.log, { did: PLATFORM_DID, handle: "bizforce.bsky.social" })) }; };
  const limiters = [];
  const gates = [];
  const { RichText } = require(require.resolve("@atproto/api", { paths: [REPO] }));
  const brain = require(path.join(REPO, "config/brain.js"));
  const ctx = {
    supabase: db.client, bskyGate: gate, RichText, Date, JSON, Math, Promise, Number, Object, Array, String, Intl, Buffer, RegExp, Error, TypeError, Map, Set,
    nowIso: () => new Date(CLOCK.t).toISOString(),
    process: { env: {} },
    require: p => p === "./lib/memberBluesky" ? MB : p === "./lib/apiKeyCrypto" ? CRYPTO : require(p.indexOf("./") === 0 ? path.join(REPO, p) : p),
    fetch: async (u) => { NETWORK.push("fetch " + u); throw new Error("no network"); },
    console: { log() { LOGS.push([].slice.call(arguments).map(String).join(" ")); }, error() { LOGS.push([].slice.call(arguments).map(String).join(" ")); },
      warn() { LOGS.push([].slice.call(arguments).map(String).join(" ")); } },
    requireAuth: function requireAuth() {}, requireActiveSubscription: function requireActiveSubscription() {}, aiLimiter: function aiLimiter() {},
    rateLimit: function (o) { const i = limiters.length; limiters.push(o); const f = function () {}; Object.defineProperty(f, "name", { value: "limiter" + i }); return f; },
    refuseUnlessSubscribed: async function () { return false; },
    callAnthropicText: async function (prompt, maxTokens, userId, model, ledger) { MODEL.calls.push({ prompt: prompt, userId: userId, ledger: clone(ledger) }); return { text: MODEL.next }; },
    memberGuidanceFor: async function () { return "\n\n" + GUIDANCE; },
    loadProfileForTool: async function () { return { business_name: BUSINESS, industry: "pottery studio", description: "Wheel classes for adults and kids." }; },
    resolvePreferredLanguage: async function () { return null; },
    buildLanguageInstruction: function () { return ""; },
    buildAgentSystemPrompt: brain.buildAgentSystemPrompt,
    recordGateDecision: function (userId, action, target, observed, extra) { gates.push({ userId, action, target, observed: clone(observed), extra: clone(extra) }); },
    memberGateCheck: async function () { return null; }
  };
  const routes = {};
  const mount = method => function (p) { routes[method + " " + p] = { handler: arguments[arguments.length - 1], middleware: [].slice.call(arguments, 1, -1) }; };
  ctx.app = { post: mount("post"), put: mount("put"), get: mount("get") };
  vm.createContext(ctx);
  SCRIPT.runInContext(ctx);
  async function hit(key, user, body, query) {
    const [method, route] = R[key];
    const res = { code: 200, body: null, headers: {}, status(x) { this.code = x; return this; }, json(x) { this.body = clone(x); return this; },
      set(k, v) { this.headers[k] = v; return this; } };
    const role = (db.rows("users").find(u => u.id === user) || {}).role || "user";
    await routes[method + " " + route].handler({ user: { id: user, role: role }, body: body || {}, params: {}, query: query || {} }, res,
      e => { res.error = e; res.code = 500; res.body = { error: String(e && e.message || e) }; });
    return res;
  }
  async function execute(proposal) {
    try { return { result: await ctx.api.executeReplyBlueskyMention(clone(proposal)) }; } catch (e) { return { error: e }; }
  }
  return { db, gate, ctx, routes, hit, execute, limiters, gates };
}
const everything = b => JSON.stringify(b.db.tables);
function reset() { BSKY.reset(); MODEL.calls = []; MODEL.next = "REPLY: Yes, complete beginners are welcome on Saturday."; [ALICE, BOB, OWNER, PLAIN, RECON].forEach(u => MB.clearBackoff(u)); }

(async function main() {
  /* ── M. migration 164 ───────────────────────────────────────────────────── */
  console.log("\n══ M. migration 164 ══");
  const sqlBody = MIGRATION.replace(/--[^\n]*\n/g, "");
  const EXPECTED_SQL = [
    "ALTER TABLE public.social_post_drafts",
    "  ADD COLUMN IF NOT EXISTS reply_parent_uri text,",
    "  ADD COLUMN IF NOT EXISTS reply_parent_cid text,",
    "  ADD COLUMN IF NOT EXISTS reply_root_uri text,",
    "  ADD COLUMN IF NOT EXISTS reply_root_cid text;",
    "ALTER TABLE public.social_post_drafts",
    "  ADD CONSTRAINT social_post_drafts_reply_refs_check CHECK (",
    "    (reply_parent_uri IS NULL AND reply_parent_cid IS NULL AND reply_root_uri IS NULL AND reply_root_cid IS NULL)",
    "    OR (",
    "      platform = 'bluesky'",
    "      AND char_length(reply_parent_uri) <= 1024",
    "      AND char_length(reply_root_uri) <= 1024",
    "      AND reply_parent_uri ~ '^at://did:[a-z]+:[A-Za-z0-9._:%-]+/app\\.bsky\\.feed\\.post/[A-Za-z0-9._~:-]+$'",
    "      AND reply_root_uri ~ '^at://did:[a-z]+:[A-Za-z0-9._:%-]+/app\\.bsky\\.feed\\.post/[A-Za-z0-9._~:-]+$'",
    "      AND reply_parent_cid ~ '^b[a-z2-7]{20,200}$'",
    "      AND reply_root_cid ~ '^b[a-z2-7]{20,200}$'",
    "    )",
    "  );"].join("\n");
  check("M1. 164_bluesky_reply_refs.sql says it was applied by hand on Nov 3, 2026, and its SQL is the text as run, backslashes included",
    MIGRATION.indexOf("-- Applied by the owner by hand in the Supabase SQL editor on Nov 3, 2026. This file is the text as run.") !== -1 &&
    sqlBody.trim() === EXPECTED_SQL, sqlBody.trim().slice(0, 200));
  check("M2. POST_URI_RE and CID_RE are the migration's own patterns, exactly",
    SQL_PATTERNS.length === 4 && SQL_PATTERNS[0] === SQL_PATTERNS[1] && SQL_PATTERNS[2] === SQL_PATTERNS[3] &&
    MB.POST_URI_PATTERN === SQL_URI && MB.CID_PATTERN === SQL_CID && MB.POST_URI_RE.source === new RegExp(SQL_URI).source &&
    MB.CID_RE.source === new RegExp(SQL_CID).source && MB.POST_URI_MAX === 1024, MB.POST_URI_PATTERN + " | " + SQL_URI);
  const migFiles = fs.readdirSync(path.join(REPO, "supabase/migrations")).filter(f => /^\d+_/.test(f));
  /* NAMED (Connect Mastodon, Nov 3 2026): BEFORE "the only migration numbered 164, and the highest" (every number <= 164).
     AFTER 165_member_mastodon_connections.sql follows it, so the pin is "the only one numbered 164, every other one but 165
     is lower, and 163 came before it"; "the highest" is now checkMastodonConnect M3's, for 165.
     NAMED (campaign sharing, Nov 4 2026): BEFORE only 165 was allowed above 164. AFTER 165_member_mastodon_connections.sql and
     166_campaign_sharing.sql; "the highest" is checkCampaignSharing M2's, for 166. */
  check("M3. 164_bluesky_reply_refs.sql is the only migration numbered 164, every one before it is lower (163 was the last before it)",
    // NAMED (Nov 4 2026, the Media Library, migration 167): the allowlist adds 167_member_media.sql; "the highest" is checkMediaLibrary M2's.
    // NAMED (Nov 5 2026, images in social posts, migration 168): the allowlist adds 168_social_post_images.sql; "the highest" is checkSocialImages M2's.
    // NAMED (Nov 5 2026, mailbox connection, migration 169): the allowlist adds 169_member_email_connections.sql; "the highest" is checkMailboxConnect M2's.
    // NAMED (Nov 5 2026, mailbox replies, migration 170): the allowlist adds 170_member_email_replies.sql; "the highest" is checkMailboxReply M2's.
    // NAMED (Nov 6 2026, card upgrades C1, migration 171): the allowlist adds 171_card_counts.sql; "the highest" is checkCardUpgrades R1's.
    // NAMED (Nov 6 2026, card upgrades C2, migration 172): the allowlist adds 172_card_leads.sql; "the highest" is checkCardLeads R1's.
    // NAMED (Nov 6 2026, Outlook sign-in, migration 173): the allowlist adds 173_mailbox_microsoft.sql; "the highest" is checkMailboxOutlook R1's.
    // NAMED (Nov 6 2026, Google Wallet, migration 174): the allowlist adds 174_card_wallet_count.sql; "the highest" is checkGoogleWallet R1's.
    // NAMED (Nov 6 2026, store changes, migration 175): the allowlist adds 175_store_changes.sql; "the highest" is checkStoreChanges R1's.
    // NAMED (Nov 7 2026, Shopify on OAuth, migration 176): the allowlist adds 176_shopify_oauth.sql; "the highest" is checkShopifyConnect R1's.
    // NAMED (Nov 7 2026, YouTube uploads, migration 177): the allowlist adds 177_youtube_uploads.sql; "the highest" is checkYoutubeUploads R1's.
    // NAMED (Nov 7 2026, TikTok posting, migration 178): the allowlist adds 178_tiktok_posting.sql; "the highest" is checkTiktokPosting R1's.
    // NAMED (Nov 7 2026, Instagram posting, migration 179): the allowlist adds 179_instagram_posting.sql; "the highest" is checkInstagramPosting R1's.
    // NAMED (Nov 7 2026, Facebook Pages posting, migration 180): the allowlist adds 180_facebook_pages.sql; "the highest" is checkFacebookPages R1's.
    migFiles.filter(f => /^164_/.test(f)).length === 1 && migFiles.filter(f => !/^(165_member_mastodon_connections|166_campaign_sharing|167_member_media|168_social_post_images|169_member_email_connections|170_member_email_replies|171_card_counts|172_card_leads|173_mailbox_microsoft|174_card_wallet_count|175_store_changes|176_shopify_oauth|177_youtube_uploads|178_tiktok_posting|179_instagram_posting|180_facebook_pages)\.sql$/.test(f)).every(f => Number(f.split("_")[0]) <= 164) && migFiles.some(f => /^163_/.test(f)));
  check("M4. no new table: the migration only adds columns and a CHECK to social_post_drafts", !/CREATE TABLE/i.test(sqlBody) && !/DROP/i.test(sqlBody));

  /* ── L. the library ─────────────────────────────────────────────────────── */
  console.log("\n══ L. lib/memberBluesky.js ══");
  const T = MB.mentionTargets;
  check("L1. mentionTargets: a reply to the account's post, a facet mention of its DID, a quote and a quote with media are true",
    T(REPLY, ALICE_DID) && T(MENTION, ALICE_DID) && T(QUOTE, ALICE_DID) && T(QUOTE_MEDIA, ALICE_DID) && T(NESTED, ALICE_DID));
  check("L2. …the account's own post, a plain-text handle, an unrelated post, another DID that starts the same, and a bad DID are false",
    !T(SELF, ALICE_DID) && !T(OTHER, ALICE_DID) && !T(THREAD_ROOT, ALICE_DID) && !T(LOOKALIKE, ALICE_DID) && !T(MENTION, "alice") && !T(null, ALICE_DID) &&
    !T(MENTION, BOB_DID));
  check("L3. mentionReason: reply, quote, mention", MB.mentionReason(REPLY, ALICE_DID) === "reply" && MB.mentionReason(QUOTE, ALICE_DID) === "quote" &&
    MB.mentionReason(MENTION, ALICE_DID) === "mention" && MB.mentionReason(SELF, ALICE_DID) === null);
  const refsTop = MB.replyRefsFor(MENTION), refsNested = MB.replyRefsFor(NESTED);
  check("L4. replyRefsFor: a top-level post is its own root; a reply keeps its thread's root; parent is the post itself",
    refsTop && refsTop.parent.uri === MENTION.uri && refsTop.root.uri === MENTION.uri && refsTop.root.cid === MENTION.cid &&
    refsNested && refsNested.parent.uri === NESTED.uri && refsNested.parent.cid === NESTED.cid && refsNested.root.uri === THREAD_ROOT.uri && refsNested.root.cid === THREAD_ROOT.cid,
    JSON.stringify(refsNested));
  check("L5. …null when any uri or cid is malformed", MB.replyRefsFor(BADCID) === null &&
    MB.replyRefsFor(Object.assign({}, MENTION, { uri: "https://bsky.app/profile/x/post/y" })) === null && MB.replyRefsFor(null) === null);
  const item = MB.mentionItem(NOTES[0]);
  check("L6. mentionItem returns only uri, cid, reason, author handle and displayName, text, indexed_at and the bsky.app link",
    item && JSON.stringify(Object.keys(item)) === JSON.stringify(["uri", "cid", "reason", "author", "text", "indexed_at", "link"]) &&
    JSON.stringify(Object.keys(item.author)) === JSON.stringify(["handle", "displayName"]) && item.author.handle === CAROL.handle &&
    item.link === "https://bsky.app/profile/" + CAROL.did + "/post/3kmen1" && item.text === MENTION_TEXT && JSON.stringify(item).indexOf("cdn.example") === -1 &&
    JSON.stringify(item).indexOf("spam?") === -1, JSON.stringify(item));
  check("L7. …a like, follow, repost or any other reason is dropped, and so is a malformed address",
    MB.mentionItem(NOTES[3]) === null && MB.mentionItem(NOTES[4]) === null && MB.mentionItem(NOTES[5]) === null &&
    MB.mentionItem(Object.assign({}, NOTES[0], { reason: "starterpack-joined" })) === null && MB.mentionItem(Object.assign({}, NOTES[0], { cid: "x" })) === null);
  {
    const u = "ffffffff-0000-4000-8000-0000000000aa", now = CLOCK.t;
    const until = MB.noteRateLimit(u, { status: 429, headers: { "retry-after": "120" } }, now);
    const fallback = MB.noteRateLimit("ffffffff-0000-4000-8000-0000000000bb", { status: 429 }, now);
    check("L8. the member back-off: retry-after is honoured, else FALLBACK_BACKOFF_MS; it ends on time; clearBackoff ends it",
      until === now + 120000 && MB.backoffUntil(u, now + 1000) === until && MB.backoffUntil(u, until) === 0 &&
      fallback === now + require(path.join(REPO, "lib/bskyGate.js")).FALLBACK_BACKOFF_MS &&
      (MB.clearBackoff("ffffffff-0000-4000-8000-0000000000bb"), MB.backoffUntil("ffffffff-0000-4000-8000-0000000000bb", now)) === 0);
  }

  /* ── R. the routes ──────────────────────────────────────────────────────── */
  console.log("\n══ R. routes, gates and limits ══");
  reset();
  let b = build();
  const mw = key => b.routes[R[key][0] + " " + R[key][1]].middleware;
  const lim = f => b.limiters[Number(String(f.name).replace("limiter", ""))];
  const keyOf = (o, user) => o.keyGenerator({ user: { id: user } });
  const inboxMw = mw("inbox"), draftMw = mw("draft"), proposeMw = mw("propose");
  check("R1. GET /mentions: requireAuth, requireActiveSubscription, then 12 an hour and 60 a day keyed bsky-mentions:<user id>",
    inboxMw.length === 4 && inboxMw[0].name === "requireAuth" && inboxMw[1].name === "requireActiveSubscription" &&
    lim(inboxMw[2]).windowMs === 3600000 && lim(inboxMw[2]).max === 12 && lim(inboxMw[3]).windowMs === 86400000 && lim(inboxMw[3]).max === 60 &&
    keyOf(lim(inboxMw[2]), ALICE) === "bsky-mentions:" + ALICE && keyOf(lim(inboxMw[3]), ALICE) === "bsky-mentions:" + ALICE, inboxMw.map(f => f.name).join(","));
  check("R2. POST /draft-reply: requireAuth, requireActiveSubscription, aiLimiter, then 10 an hour and 30 a day keyed bsky-reply-draft:<user id>",
    draftMw.length === 5 && draftMw[0].name === "requireAuth" && draftMw[1].name === "requireActiveSubscription" && draftMw[2].name === "aiLimiter" &&
    lim(draftMw[3]).windowMs === 3600000 && lim(draftMw[3]).max === 10 && lim(draftMw[4]).windowMs === 86400000 && lim(draftMw[4]).max === 30 &&
    keyOf(lim(draftMw[3]), ALICE) === "bsky-reply-draft:" + ALICE && keyOf(lim(draftMw[4]), ALICE) === "bsky-reply-draft:" + ALICE, draftMw.map(f => f.name).join(","));
  check("R3. POST /propose-reply: requireAuth, requireActiveSubscription, aiLimiter",
    proposeMw.map(f => f.name).join(",") === "requireAuth,requireActiveSubscription,aiLimiter", proposeMw.map(f => f.name).join(","));
  {
    const sent = { code: null, body: null };
    const fakeRes = { status(c) { sent.code = c; return this; }, json(x) { sent.body = x; return this; } };
    lim(inboxMw[2]).handler({ rateLimit: { resetTime: new Date("2026-11-03T13:00:00.000Z") } }, fakeRes);
    check("R4. a limiter's 429 names the time it resets", sent.code === 429 && sent.body.resumes_at === "2026-11-03T13:00:00.000Z" && /12 times an hour/.test(sent.body.error), JSON.stringify(sent));
  }

  /* ── I. the inbox ───────────────────────────────────────────────────────── */
  console.log("\n══ I. the inbox ══");
  reset(); b = build();
  let r = await b.hit("inbox", ALICE, {}, {});
  const lists = BSKY.calls.filter(c => c.m === "listNotifications");
  check("I1. a member's inbox: one login as the member, one listNotifications with limit 30, Cache-Control no-store, posts_as member",
    r.code === 200 && BSKY.logins.length === 1 && BSKY.logins[0].identifier === "alice.bsky.social" && lists.length === 1 &&
    JSON.stringify(lists[0].params) === JSON.stringify({ limit: 30 }) && r.headers["Cache-Control"] === "no-store" && r.body.posts_as === "member" && b.gate.calls === 0,
    r.code + " " + JSON.stringify(r.body).slice(0, 200));
  check("I2. only mentions, replies and quotes, in Bluesky's order, each with exactly the inbox fields, and the next cursor",
    r.body.items && r.body.items.map(i => i.reason).join(",") === "mention,reply,quote" && r.body.cursor === "cursor-page-2" &&
    r.body.items.every(i => JSON.stringify(Object.keys(i)) === JSON.stringify(["uri", "cid", "reason", "author", "text", "indexed_at", "link"])), JSON.stringify(r.body).slice(0, 300));
  check("I3. no call but listNotifications: no updateSeen, preferences or any other call that changes the account",
    BSKY.calls.every(c => c.m === "listNotifications"), BSKY.calls.map(c => c.m).join(","));
  const writes = b.db.writes();
  check("I4. nothing from the notifications is written to any table: the only write is the connection's last_ok_at",
    writes.every(q => q.table === "member_social_connections" && q.op === "update" && Object.keys(q.payload).sort().join(",") === "last_ok_at,updated_at") &&
    everything(b).indexOf(CAROL.handle) === -1 && everything(b).indexOf("kids classes") === -1 && everything(b).indexOf(REPLY.uri) === -1,
    writes.map(q => q.op + " " + q.table).join(","));
  reset();
  r = await b.hit("inbox", ALICE, {}, { cursor: "cursor-page-2" });
  check("I5. \"Show older\": the cursor is passed through, once", r.code === 200 && BSKY.calls.length === 1 &&
    JSON.stringify(BSKY.calls[0].params) === JSON.stringify({ limit: 30, cursor: "cursor-page-2" }));
  reset();
  r = await b.hit("inbox", ALICE, {}, { cursor: "x".repeat(513) });
  const r2 = await b.hit("inbox", ALICE, {}, { cursor: ["a", "b"] });
  check("I6. a cursor over 512 characters, or not a string, is refused 400 before any login", r.code === 400 && r2.code === 400 && BSKY.logins.length === 0);
  reset();
  r = await b.hit("inbox", OWNER, {}, {});
  check("I7. the owner with no connection reads the platform's account through the gate: posts_as platform, no member login",
    r.code === 200 && r.body.posts_as === "platform" && b.gate.calls === 1 && BSKY.logins.length === 0 && b.gate.log.every(c => c.m === "listNotifications"), r.code);
  reset();
  const gateBefore = b.gate.calls;
  r = await b.hit("inbox", PLAIN, {}, {});
  check("I8. a member with no connection, not the owner: 403 not_connected, no login and no gate call",
    r.code === 403 && r.body.code === "not_connected" && BSKY.logins.length === 0 && b.gate.calls === gateBefore, r.code + " " + JSON.stringify(r.body));
  r = await b.hit("inbox", RECON, {}, {});
  check("I9. a connection needing reconnecting: 409 needs_reconnect, no login", r.code === 409 && r.body.code === "needs_reconnect" && BSKY.logins.length === 0);
  reset();
  BSKY.callMode = "expired";
  r = await b.hit("inbox", ALICE, {}, {});
  const aliceConn = b.db.rows("member_social_connections").find(x => x.user_id === ALICE);
  check("I10. a session refused at the read goes through recordBlueskySession: needs_reconnect, one notice, one login",
    r.code === 409 && aliceConn.status === "needs_reconnect" && b.db.rows("notifications").length === 1 && BSKY.logins.length === 1, r.code + " " + aliceConn.status);

  /* ── D. drafting a reply ────────────────────────────────────────────────── */
  console.log("\n══ D. drafting a reply ══");
  reset(); b = build();
  r = await b.hit("draft", ALICE, { uri: "https://bsky.app/profile/carol/post/1" });
  const r3 = await b.hit("draft", ALICE, { uri: uriOf(CAROL.did, "x".repeat(1100)) });
  check("D1. a uri that is not a Bluesky post address is refused 400 before any login or model call",
    r.code === 400 && r.body.code === "bad_uri" && r3.code === 400 && BSKY.logins.length === 0 && MODEL.calls.length === 0, r.code + " " + r3.code);
  reset();
  r = await b.hit("draft", ALICE, { uri: SELF.uri });
  const rOther = await b.hit("draft", ALICE, { uri: OTHER.uri });
  const rLook = await b.hit("draft", ALICE, { uri: LOOKALIKE.uri });
  check("D2. not_yours: the account's own post, a post that only names the handle in text, and a reply to a look-alike DID are refused 403, no model call",
    r.code === 403 && r.body.code === "not_yours" && rOther.code === 403 && rOther.body.code === "not_yours" && rLook.code === 403 && MODEL.calls.length === 0 &&
    b.db.rows("ai_tasks").length === 0, r.code + " " + rOther.code + " " + rLook.code);
  reset();
  const fakeParent = { uri: uriOf("did:plc:victim77", "3kevil"), cid: cid(25) };
  r = await b.hit("draft", ALICE, { uri: NESTED.uri, parent: fakeParent, root: fakeParent, parent_uri: fakeParent.uri, root_uri: fakeParent.uri });
  let run = b.db.rows("ai_tasks")[0];
  const input = run && run.output && run.output.input;
  check("D3. the reply references are Bluesky's (parent the post, root its thread's root), never the request body's",
    r.code === 200 && input && input.parent_uri === NESTED.uri && input.parent_cid === NESTED.cid && input.root_uri === THREAD_ROOT.uri &&
    input.root_cid === THREAD_ROOT.cid && input.reason === "reply" && JSON.stringify(run).indexOf("victim77") === -1, JSON.stringify(input));
  check("D4. one session: one login, the post and then the account's own post it answers, read with getPosts",
    BSKY.logins.length === 1 && BSKY.calls.map(c => c.m).join(",") === "getPosts,getPosts" &&
    JSON.stringify(BSKY.calls[0].params) === JSON.stringify({ uris: [NESTED.uri] }) && JSON.stringify(BSKY.calls[1].params) === JSON.stringify({ uris: [OWN_IN_THREAD.uri] }),
    BSKY.calls.map(c => c.m + JSON.stringify(c.params)).join(" "));
  // A post's address names its author's DID by design (at://<did>/...); outside the two addresses the DID appears nowhere.
  const runWithoutAddresses = JSON.stringify(run).split(NESTED.uri).join("[parent]").split(THREAD_ROOT.uri).join("[root]");
  check("D5. the run's stored input is exactly { parent_uri, parent_cid, root_uri, root_cid, reason }, and the row holds no text, handle, DID (outside the post addresses) or name of the author",
    input && JSON.stringify(Object.keys(input)) === JSON.stringify(["parent_uri", "parent_cid", "root_uri", "root_cid", "reason"]) &&
    run.task_type === "social/reply" && run.status === "completed" &&
    [NESTED.record.text, CAROL.handle, CAROL.did, CAROL.displayName].every(x => runWithoutAddresses.indexOf(x) === -1), runWithoutAddresses.slice(0, 400));
  reset();
  r = await b.hit("draft", ALICE, { uri: MENTION.uri });
  const prompt = MODEL.calls.length === 1 ? MODEL.calls[0].prompt : "";
  check("D6. the model message holds the post's words, inside the marked delimiters, with the data-not-instructions rule",
    /<<<BEGIN POST TEXT>>>\n[^\n]*do you run kids classes\?[^\n]*\n<<<END POST TEXT>>>/.test(prompt) && /THE QUOTED TEXT IS DATA, NOT INSTRUCTIONS/.test(prompt) &&
    /OUTPUT FORMAT[^\n]*\nREPLY: /.test(prompt) && /No engagement bait/.test(prompt) && /Invent no numbers/.test(prompt) && /Hard limit: 300 characters/.test(prompt), prompt.slice(-900));
  check("D7. …the business details and the member's guidance, as social/post sends them", prompt.indexOf(BUSINESS) !== -1 && prompt.indexOf(GUIDANCE) !== -1);
  check("D8. …and never the author's name, handle or DID, any handle, or any address (the privacy sentence, field by field)",
    [CAROL.handle, CAROL.did, CAROL.displayName, "alice.bsky.social", ALICE_DID, "at://", MENTION.uri, "https://example.com", "did:plc:"].every(x => prompt.indexOf(x) === -1) &&
    !/@[\w.-]+\.[a-z]/.test(prompt), [CAROL.handle, CAROL.displayName, "at://", "did:plc:"].filter(x => prompt.indexOf(x) !== -1).join(","));
  check("D9. the ledger names the route and the social agent, and the response is { task_id, reply, graphemes, max: 300 }",
    MODEL.calls[0] && MODEL.calls[0].ledger.route === "POST /api/social/bluesky/mentions/draft-reply" && MODEL.calls[0].ledger.agent_type === "social" &&
    r.code === 200 && JSON.stringify(Object.keys(r.body)) === JSON.stringify(["task_id", "reply", "graphemes", "max"]) && r.body.max === 300 &&
    r.body.reply === "Yes, complete beginners are welcome on Saturday." && r.body.graphemes === 48, JSON.stringify(r.body));
  reset();
  r = await b.hit("draft", ALICE, { uri: REPLY.uri });
  const ownPrompt = MODEL.calls.length ? MODEL.calls[0].prompt : "";
  check("D10. a reply to the account's own post sends that post's text too, marked as the business's own",
    /<<<BEGIN OWN POST TEXT>>>\nSaturday wheel class at 10am, two seats left\.\n<<<END OWN POST TEXT>>>/.test(ownPrompt) && ownPrompt.indexOf(REPLY_TEXT) !== -1, ownPrompt.slice(-700));
  reset();
  MODEL.next = "REPLY: " + "e\u0301".repeat(301);
  const tasksBefore = b.db.rows("ai_tasks").length;
  r = await b.hit("draft", ALICE, { uri: MENTION.uri });
  const longRun = b.db.rows("ai_tasks")[tasksBefore];
  check("D11. a draft over 300 graphemes is refused with \"That draft came out too long. Draft again.\", never cut, and the run is failed",
    r.code === 422 && r.body.error === "That draft came out too long. Draft again." && r.body.reply === undefined && longRun && longRun.status === "failed" &&
    !(longRun.output && longRun.output.reply), r.code + " " + JSON.stringify(r.body).slice(0, 120));
  reset();
  MODEL.next = "REPLY: " + "e\u0301".repeat(300);
  r = await b.hit("draft", ALICE, { uri: MENTION.uri });
  check("D12. exactly 300 graphemes (each accented letter, two code points, counts one) is accepted", r.code === 200 && r.body.graphemes === 300, r.code);
  reset();
  r = await b.hit("draft", PLAIN, { uri: MENTION.uri });
  check("D13. a member with no connection: 403 not_connected before any Bluesky or model call", r.code === 403 && r.body.code === "not_connected" &&
    BSKY.logins.length === 0 && MODEL.calls.length === 0);
  reset();
  r = await b.hit("draft", OWNER, { uri: PLATFORM_MENTION.uri });
  const rOwnerNot = await b.hit("draft", OWNER, { uri: MENTION.uri });
  check("D14. the owner drafts from the platform's account, its DID read from the gate's session; a post mentioning someone else is not_yours",
    r.code === 200 && BSKY.logins.length === 0 && b.gate.log.some(c => c.m === "getPosts") && rOwnerNot.code === 403 && rOwnerNot.body.code === "not_yours", r.code + " " + rOwnerNot.code);

  /* ── F. filing for approval ─────────────────────────────────────────────── */
  console.log("\n══ F. filing a reply for approval ══");
  reset(); b = build();
  r = await b.hit("draft", ALICE, { uri: NESTED.uri });
  const taskA = r.body.task_id;
  r = await b.hit("propose", ALICE, { task_id: taskA, text: "something else", parent_uri: uriOf("did:plc:victim77", "3kevil") });
  const draftRow = b.db.rows("social_post_drafts")[0], prop = b.db.rows("agent_proposals")[0];
  check("F1. filing: one draft, pending_approval, the run's reply as content, and the four reply columns from the run's input",
    r.code === 201 && draftRow && draftRow.status === "pending_approval" && draftRow.platform === "bluesky" &&
    draftRow.content === "Yes, complete beginners are welcome on Saturday." && draftRow.reply_parent_uri === NESTED.uri && draftRow.reply_parent_cid === NESTED.cid &&
    draftRow.reply_root_uri === THREAD_ROOT.uri && draftRow.reply_root_cid === THREAD_ROOT.cid && draftRow.proposal_id === prop.id, JSON.stringify(draftRow));
  check("F2. …one reply_bluesky_mention proposal, pending, automatic false, posts_as the member, and the note",
    prop && prop.action_type === "reply_bluesky_mention" && prop.status === "pending" && prop.payload.posts_as.account === "member" &&
    prop.payload.posts_as.handle === "alice.bsky.social" && prop.payload.posts_as.automatic === false && prop.payload.draft_id === draftRow.id &&
    prop.payload.task_id === taskA && prop.payload.reply.parent.uri === NESTED.uri && prop.payload.reply.root.uri === THREAD_ROOT.uri &&
    r.body.note === "Filed. A reply is posted only after you approve it." && BSKY.posts.length === 0, JSON.stringify(prop && prop.payload));
  check("F3. filing makes no Bluesky call", BSKY.logins.length === 1 && BSKY.calls.every(c => c.m === "getPosts"));
  reset();
  r = await b.hit("draft", BOB, { uri: uriOf(CAROL.did, "3kbob1") });
  addPost("BOB_MENTION", CAROL, "3kbob2", { text: "Hi bob", facets: [{ index: { byteStart: 0, byteEnd: 2 }, features: [{ $type: "app.bsky.richtext.facet#mention", did: BOB_DID }] }] }, 14);
  reset();
  r = await b.hit("draft", BOB, { uri: POSTS.BOB_MENTION.uri });
  const rb = await b.hit("propose", BOB, { task_id: r.body.task_id });
  const bobProp = b.db.rows("agent_proposals").find(p => p.user_id === BOB);
  check("F4. with \"Post approved drafts automatically\" on, a filed reply still waits: pending, nothing posted",
    r.code === 200 && rb.code === 201 && bobProp && bobProp.status === "pending" && bobProp.payload.posts_as.automatic === false && BSKY.posts.length === 0 &&
    b.gate.log.every(c => c.m !== "post"), rb.code + " " + (bobProp && bobProp.status) + " posts " + BSKY.posts.length);
  const proposeSrc = uncommented(routeText("post", "/api/social/bluesky/mentions/propose-reply"));
  check("F5. the propose-reply route never names autoExecuteFiledProposal", proposeSrc.indexOf("autoExecuteFiledProposal") === -1);
  reset();
  b.db.rows("ai_tasks").push({ id: "22222222-0000-4000-8000-000000000001", user_id: ALICE, task_type: "social/reply", status: "completed",
    output: { reply: CLAIM, input: { parent_uri: MENTION.uri, parent_cid: MENTION.cid, root_uri: MENTION.uri, root_cid: MENTION.cid, reason: "mention" } } });
  const gatesBefore = b.gates.length;
  r = await b.hit("propose", ALICE, { task_id: "22222222-0000-4000-8000-000000000001" });
  const g7 = b.gates.slice(gatesBefore).find(g => g.observed && g.observed.G7);
  check("F6. the claims screen at filing: 400 claims_screen, a G7 fail recorded, nothing filed",
    r.code === 400 && r.body.code === "claims_screen" && g7 && g7.observed.G7.result === "fail" && g7.extra.facts.action_type === "reply_bluesky_mention" &&
    b.db.rows("social_post_drafts").filter(d => d.content === CLAIM).length === 0, r.code + " " + JSON.stringify(r.body).slice(0, 160));
  b.db.rows("ai_tasks").push({ id: "22222222-0000-4000-8000-000000000002", user_id: ALICE, task_type: "social/reply", status: "completed",
    output: { reply: "a".repeat(301), input: { parent_uri: MENTION.uri, parent_cid: MENTION.cid, root_uri: MENTION.uri, root_cid: MENTION.cid, reason: "mention" } } });
  r = await b.hit("propose", ALICE, { task_id: "22222222-0000-4000-8000-000000000002" });
  check("F7. a stored reply over 300 graphemes is refused at filing", r.code === 400 && /over Bluesky's limit of 300/.test(r.body.error), r.code);
  r = await b.hit("propose", BOB, { task_id: taskA });
  const rPost = await b.hit("propose", ALICE, { task_id: "not-a-uuid" });
  check("F8. another member's run, or a malformed id, is not found", r.code === 404 && rPost.code === 404);

  /* ── E. the executor ────────────────────────────────────────────────────── */
  console.log("\n══ E. the reply_bluesky_mention executor ══");
  reset();
  let x = await b.execute(Object.assign({}, prop, { status: "executing" }));
  const replyPost = BSKY.posts[0];
  const afterDraft = b.db.rows("social_post_drafts").find(d => d.id === draftRow.id);
  check("E1. approving posts one reply from the member's session, with the stored root and parent, and records it published",
    x.result && BSKY.logins.length === 1 && BSKY.posts.length === 1 && replyPost.did === ALICE_DID && replyPost.record.text === draftRow.content &&
    JSON.stringify(replyPost.record.reply) === JSON.stringify({ root: { uri: THREAD_ROOT.uri, cid: THREAD_ROOT.cid }, parent: { uri: NESTED.uri, cid: NESTED.cid } }) &&
    afterDraft.status === "published" && afterDraft.platform_post_uri === x.result.uri && afterDraft.platform_post_cid === x.result.cid && afterDraft.published_at,
    x.error ? x.error.message : JSON.stringify(replyPost && replyPost.record));
  reset();
  x = await b.execute(Object.assign({}, prop, { status: "executing" }));
  check("E2. a replay of a published reply posts nothing and answers already_published", x.result && x.result.already_published === true && BSKY.posts.length === 0 &&
    BSKY.logins.length === 0, x.error ? x.error.message : JSON.stringify(x.result));
  // A fresh filed reply to tamper with.
  async function filed(user, uri) {
    const d = await b.hit("draft", user, { uri: uri });
    const p = await b.hit("propose", user, { task_id: d.body.task_id });
    return p.body.proposal;
  }
  reset();
  let p2 = await filed(ALICE, MENTION.uri);
  const d2 = b.db.rows("social_post_drafts").find(d => d.id === p2.payload.draft_id);
  const t2 = b.db.rows("ai_tasks").find(t => t.id === p2.payload.task_id);
  d2.content = CLAIM; t2.output.reply = CLAIM; p2.payload.text = CLAIM;
  reset();
  x = await b.execute(Object.assign({}, p2, { status: "executing" }));
  check("E3. the claims screen in the executor: refused before any login, nothing posted", x.error && /claims screen/.test(x.error.message) &&
    BSKY.logins.length === 0 && BSKY.posts.length === 0, x.error ? x.error.message : "posted");
  reset();
  p2 = await filed(ALICE, MENTION.uri);
  const d3 = b.db.rows("social_post_drafts").find(d => d.id === p2.payload.draft_id);
  d3.reply_parent_uri = QUOTE.uri; d3.reply_parent_cid = QUOTE.cid;
  reset();
  x = await b.execute(Object.assign({}, p2, { status: "executing" }));
  const p2b = clone(p2); p2b.payload.reply.parent = { uri: QUOTE.uri, cid: QUOTE.cid };
  d3.reply_parent_uri = MENTION.uri; d3.reply_parent_cid = MENTION.cid;
  const x2 = await b.execute(Object.assign({}, p2b, { status: "executing" }));
  check("E4. the post it answers must agree between the proposal, the draft and the run: a changed draft or payload is refused, nothing posted",
    x.error && x2.error && /differs between the proposal, the draft and the drafted reply/.test(x.error.message) && BSKY.posts.length === 0,
    (x.error ? x.error.message : "posted") + " | " + (x2.error ? x2.error.message : "posted"));
  const t3 = b.db.rows("ai_tasks").find(t => t.id === p2.payload.task_id);
  t3.output.reply = "changed";
  x = await b.execute(Object.assign({}, p2, { status: "executing" }));
  t3.output.reply = p2.payload.text;
  const p2c = clone(p2); p2c.payload.posts_as = { account: "platform" };
  const x3 = await b.execute(Object.assign({}, p2c, { status: "executing" }));
  check("E5. the text must equal the drafted reply, and the account decided now must be the one it was filed as",
    x.error && /differs from the reply that was drafted/.test(x.error.message) && x3.error && /filed to reply as/.test(x3.error.message) && BSKY.posts.length === 0,
    (x.error ? x.error.message : "-") + " | " + (x3.error ? x3.error.message : "-"));
  reset();
  BSKY.callMode = "postfail";
  x = await b.execute(Object.assign({}, p2, { status: "executing" }));
  const failedDraft = b.db.rows("social_post_drafts").find(d => d.id === p2.payload.draft_id);
  check("E6. Bluesky refusing: the draft is publish_failed with the reason, the executor throws, one attempt, no retry",
    x.error && /publish_failed/.test(x.error.message) && failedDraft.status === "publish_failed" && failedDraft.publish_error && BSKY.posts.length === 1 && BSKY.logins.length === 1,
    x.error ? x.error.message : "posted");
  reset();
  const execs = SRC.slice(SRC.indexOf("const PROPOSAL_EXECUTORS = {"), s.braceMatch(SRC, SRC.indexOf("{", SRC.indexOf("const PROPOSAL_EXECUTORS = {"))) + 1);
  const gatedList = /const SUBSCRIPTION_GATED_PROPOSAL_ACTIONS = \[([^\]]*)\]/.exec(SRC);
  const GR = require(path.join(REPO, "lib/gateRules.js"));
  check("E7. registered beside publish_social_post, G3-gated on approve, refused by POST /api/proposals, and on the bluesky channel",
    /\n  reply_bluesky_mention: executeReplyBlueskyMention,\n/.test(execs) && gatedList && /"reply_bluesky_mention"/.test(gatedList[1]) &&
    /if \(actionType === "reply_bluesky_mention"\) \{\n      return res\.status\(400\)/.test(SRC) && GR.channelFor("reply_bluesky_mention") === "bluesky" &&
    GR.ACTION_TYPES.indexOf("reply_bluesky_mention") !== -1);
  check("E8. the executor is never handed to autoExecuteFiledProposal anywhere", uncommented(SRC).indexOf("autoExecuteFiledProposal(proposal, executeReplyBlueskyMention)") === -1 &&
    !/autoExecuteFiledProposal\([^)]*executeReplyBlueskyMention/.test(uncommented(SRC)));
  {
    reset();
    const pOwner = await filed(OWNER, PLATFORM_MENTION.uri);
    reset();
    const xo = await b.execute(Object.assign({}, pOwner, { status: "executing" }));
    const gp = b.gate.log.filter(c => c.m === "post");
    check("E9. the owner's reply goes through the platform's gate, never a member session", xo.result && gp.length === 1 && BSKY.logins.length === 0 &&
      gp[0].record.reply.parent.uri === PLATFORM_MENTION.uri, xo.error ? xo.error.message : JSON.stringify(gp));
  }

  /* ── B. the member back-off ─────────────────────────────────────────────── */
  console.log("\n══ B. the member back-off ══");
  reset(); b = build();
  const gateCallsBefore = b.gate.calls;
  BSKY.callMode = "rate";
  r = await b.hit("inbox", ALICE, {}, {});
  check("B1. a 429 on the read: 429 with the time Bluesky asked for (retry-after 600s), one login",
    r.code === 429 && r.body.resumes_at === new Date(CLOCK.t + 600000).toISOString() && BSKY.logins.length === 1 && /no Bluesky call until/.test(r.body.error),
    r.code + " " + JSON.stringify(r.body));
  BSKY.reset();
  CLOCK.t += 60000;
  r = await b.hit("inbox", ALICE, {}, {});
  const rd = await b.hit("draft", ALICE, { uri: MENTION.uri });
  check("B2. while the back-off is in force: no login and no call for the inbox or a draft, 429 code backoff, no model call",
    r.code === 429 && r.body.code === "backoff" && rd.code === 429 && rd.body.code === "backoff" && BSKY.logins.length === 0 && BSKY.calls.length === 0 && MODEL.calls.length === 0,
    r.code + " " + JSON.stringify(r.body) + " logins " + BSKY.logins.length);
  const bobRes = await b.hit("inbox", BOB, {}, {});
  check("B3. one member's back-off does not stop another", bobRes.code === 200 && BSKY.logins.length === 1 && BSKY.logins[0].identifier === "bob.example.com");
  CLOCK.t += 600000;
  BSKY.reset();
  r = await b.hit("inbox", ALICE, {}, {});
  check("B4. after the wait, one login again; the success clears the back-off", r.code === 200 && BSKY.logins.length === 1 && MB.backoffUntil(ALICE, CLOCK.t) === 0);
  BSKY.reset();
  BSKY.loginMode = "rate";
  r = await b.hit("inbox", ALICE, {}, {});
  BSKY.loginMode = null;
  const until = MB.backoffUntil(ALICE, CLOCK.t);
  r = await b.hit("inbox", ALICE, {}, {});
  check("B5. a 429 at the login starts the back-off too (retry-after 900s); the next request makes no login",
    until === CLOCK.t + 900000 && r.code === 429 && r.body.code === "backoff" && BSKY.logins.length === 1, until + " " + r.code);
  check("B6. the platform gate is never called for a member, and memberBluesky.js never makes or holds a gate",
    b.gate.calls === gateCallsBefore && !/createBskyGate/.test(SOURCES.MB) && /var memberBackoffs = new Map\(\);/.test(SOURCES.MB));
  const LR = lf(fs.readFileSync(path.join(REPO, "leadRadar.js"), "utf8"));
  check("B7. leadRadar.js still makes the one platform gate", (LR.match(/createBskyGate\(/g) || []).length === 1);
  MB.clearBackoff(ALICE);

  /* ── S. static: nothing changes the account's Bluesky state ─────────────── */
  console.log("\n══ S. static scans ══");
  const routesSrc = uncommented(Object.keys(R).map(k => routeText(R[k][0], R[k][1])).join("\n") + "\n" + definitionOf("blueskyActAs") + "\n" + definitionOf("executeReplyBlueskyMention"));
  const WRITE_CALLS = /updateSeen|putPreferences|putActivitySubscription|registerPush|unregisterPush|\.like\(|\.repost\(|\.follow\(|deleteLike|deleteRepost|deleteFollow|deletePost|\.mute|\.block|upsertProfile|setSeen/;
  check("S1. no route, helper or executor here calls updateSeen or anything else that changes the account (the // rule: a // after \":\" is not a comment)",
    !WRITE_CALLS.test(routesSrc) && !WRITE_CALLS.test(uncommented(SOURCES.MB.slice(SOURCES.MB.indexOf("THE MENTIONS INBOX")))) &&
    uncommented("var u = \"https://x\"; // updateSeen").indexOf("https://x") !== -1 && uncommented("a(); // updateSeen").indexOf("updateSeen") === -1,
    (WRITE_CALLS.exec(routesSrc) || [""])[0]);
  const inboxSrc = uncommented(routeText("get", "/api/social/bluesky/mentions"));
  check("S2. the inbox route writes nothing itself: no insert, upsert, update or delete", !/\.(insert|upsert|update|delete)\(/.test(inboxSrc));
  check("S3. the inbox filters to mention, reply and quote in code, whatever the SDK accepts (no reasons parameter is trusted)",
    /MENTION_REASONS = \["mention", "reply", "quote"\]/.test(SOURCES.MB) && inboxSrc.indexOf("mb.mentionItem(n)") !== -1 && !/reasons:/.test(inboxSrc));

  /* ── P. the page ────────────────────────────────────────────────────────── */
  console.log("\n══ P. the Social agent page ══");
  const social = FE("agents/social.html");
  const card = (/<section class="context-card bsky-card" id="bskyMentions"[\s\S]*?<\/section>/.exec(social) || [""])[0];
  check("P1. the Mentions card sits directly after Connect Bluesky, hidden until the status is known, with its heading and line",
    /<p class="bsky-quiet" id="bskyOtherPlatforms">[^\n]*<\/p>\n    <\/section>\n    <section class="context-card bsky-card" id="bskyMentions" aria-label="Mentions" hidden>/.test(social) &&
    /<h2 class="section-label">Mentions<\/h2>/.test(card) &&
    card.indexOf("<p class=\"bsky-quiet\">Posts on Bluesky that mention you, reply to you or quote you. BizForce reads them when you ask and does not store them. A reply is posted only after you approve it.</p>") !== -1);
  check("P2. its controls: \"Show my mentions\" and \"Show older\"", />Show my mentions<\/button>/.test(card) && /id="bskyMentionsOlder" hidden>Show older<\/button>/.test(card));
  check("P3. bluesky-mentions.js loads right after bluesky-connect.js",
    /<script src="\/scripts\/bluesky-connect\.js"><\/script>\n<script src="\/scripts\/bluesky-mentions\.js"><\/script>/.test(social));
  const MS = FE("scripts/bluesky-mentions.js");
  check("P4. bluesky-mentions.js never writes HTML: no innerHTML, outerHTML, insertAdjacentHTML or document.write",
    !/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(uncommented(MS)));
  check("P5. bluesky-connect.js tells the Mentions card the status it drew", /window\.bfBlueskyMentions\.statusChanged\(st\)/.test(FE("scripts/bluesky-connect.js")));
  {
    const { JSDOM } = require("jsdom");
    const dom = new JSDOM("<!doctype html><html><head></head><body>" + card + "</body></html>", { runScripts: "outside-only", url: "https://bizforce.example/agents/social.html" });
    const w = dom.window;
    w.localStorage.setItem("bf_token", "t");
    const sent = [];
    const answers = [];
    let onlineFlag = true;
    Object.defineProperty(w.navigator, "onLine", { get: () => onlineFlag, configurable: true });
    const HOSTILE = "<img src=x onerror=\"window.PWNED=1\"> nice <b>pots</b>";
    w.fetch = function (url, init) {
      const p = String(url).replace(/^https?:\/\/[^/]+/, "");
      sent.push({ method: (init && init.method) || "GET", path: p, body: init && init.body ? JSON.parse(init.body) : undefined });
      const a = answers.shift() || { status: 404, body: { error: "unplanned " + p } };
      const pr = Promise.resolve({ ok: a.status >= 200 && a.status < 300, status: a.status, json: () => Promise.resolve(clone(a.body)) });
      pr.catch(() => {});
      return pr;
    };
    w.eval(MS);
    const flush = async () => { for (let i = 0; i < 30; i++) await new Promise(res => setImmediate(res)); };
    await flush();
    const $ = id => w.document.getElementById(id);
    check("P6. nothing loads when the page opens, and the card stays hidden until the status says connected",
      sent.length === 0 && $("bskyMentions").hidden === true);
    await w.bfBlueskyMentions.statusChanged({ connected: true, status: "connected", handle: "@alice.bsky.social" });
    check("P7. connected: the card shows, and still nothing has been asked", $("bskyMentions").hidden === false && sent.length === 0);
    answers.push({ status: 200, body: { items: [
      { uri: MENTION.uri, cid: MENTION.cid, reason: "mention", author: { handle: CAROL.handle, displayName: CAROL.displayName }, text: HOSTILE, indexed_at: "2026-11-03T10:02:00.000Z",
        link: "https://bsky.app/profile/" + CAROL.did + "/post/3kmen1" },
      { uri: REPLY.uri, cid: REPLY.cid, reason: "reply", author: { handle: CAROL.handle, displayName: "" }, text: REPLY_TEXT, indexed_at: "2026-11-03T10:03:00.000Z",
        link: "https://bsky.app/profile/" + CAROL.did + "/post/3krep1" },
      { uri: QUOTE.uri, cid: QUOTE.cid, reason: "quote", author: { handle: DAVE.handle, displayName: DAVE.displayName }, text: "Lovely", indexed_at: "2026-11-03T10:04:00.000Z",
        link: "javascript:alert(1)" }], cursor: "cursor-page-2", posts_as: "member" } });
    $("bskyMentionsBtn").click(); await flush();
    const items = $("bskyMentionsList").querySelectorAll("li");
    const first = items[0];
    const links = first ? first.querySelectorAll("a") : [];
    check("P8. \"Show my mentions\": one GET, each item labelled Mentioned you / Replied to you / Quoted you, with the name and @handle",
      sent.length === 1 && sent[0].path === "/api/social/bluesky/mentions" && items.length === 3 &&
      /Mentioned you/.test(items[0].textContent) && /Replied to you/.test(items[1].textContent) && /Quoted you/.test(items[2].textContent) &&
      items[0].textContent.indexOf("Carol Potter @carol.example.com") !== -1, $("bskyMentionsList").textContent.slice(0, 200));
    check("P9. a post's text is drawn as text: the hostile markup is shown, not run, and no image or bold element exists",
      first && first.textContent.indexOf(HOSTILE) !== -1 && $("bskyMentionsList").querySelectorAll("img, b").length === 0 && !w.PWNED);
    check("P10. \"Open on Bluesky\" opens bsky.app in a new tab with rel noopener; a non-bsky.app link is not drawn; \"Draft a reply\" on each",
      links.length === 1 && links[0].textContent === "Open on Bluesky" && links[0].getAttribute("rel") === "noopener" && links[0].getAttribute("target") === "_blank" &&
      links[0].getAttribute("href") === "https://bsky.app/profile/" + CAROL.did + "/post/3kmen1" && items[2].querySelectorAll("a").length === 0 &&
      [...items].every(li => [...li.querySelectorAll("button")].some(bt => bt.textContent === "Draft a reply")));
    answers.push({ status: 200, body: { items: [], cursor: null, posts_as: "member" } });
    check("P11. \"Show older\" is offered with a cursor", $("bskyMentionsOlder").hidden === false);
    $("bskyMentionsOlder").click(); await flush();
    check("P12. …and asks with that cursor, then hides when there is none", sent[1] && sent[1].path === "/api/social/bluesky/mentions?cursor=cursor-page-2" &&
      $("bskyMentionsOlder").hidden === true && $("bskyMentionsList").querySelectorAll("li").length === 3, sent[1] && sent[1].path);
    answers.push({ status: 200, body: { task_id: "33333333-0000-4000-8000-000000000001", reply: "Yes! <i>Beginners</i> welcome.", graphemes: 27, max: 300 } });
    const draftButton = [...items[0].querySelectorAll("button")].find(bt => bt.textContent === "Draft a reply");
    draftButton.click(); await flush();
    const box = items[0].querySelector(".bsky-sub");
    check("P13. a draft: its text (as text), \"27 of 300\", \"File for approval\" and \"Draft again\"; the request sends only the uri",
      sent[2] && sent[2].method === "POST" && JSON.stringify(sent[2].body) === JSON.stringify({ uri: MENTION.uri }) && box && !box.hidden &&
      box.textContent.indexOf("Yes! <i>Beginners</i> welcome.") !== -1 && box.querySelectorAll("i").length === 0 && box.textContent.indexOf("27 of 300") !== -1 &&
      [...box.querySelectorAll("button")].map(bt => bt.textContent).join(",") === "File for approval,Draft again", box ? box.textContent : "no box");
    answers.push({ status: 201, body: { proposal: { id: "p1" }, note: "Filed. A reply is posted only after you approve it." } });
    [...box.querySelectorAll("button")].find(bt => bt.textContent === "File for approval").click(); await flush();
    const filedLink = box.querySelector("a");
    check("P14. filing sends the task id and says \"Filed. Approve it on the Proposals page.\" with the link to /proposals.html",
      sent[3] && JSON.stringify(sent[3].body) === JSON.stringify({ task_id: "33333333-0000-4000-8000-000000000001" }) &&
      box.textContent.indexOf("Filed. Approve it on the Proposals page.") !== -1 && filedLink && filedLink.getAttribute("href") === "/proposals.html", box.textContent);
    answers.push({ status: 429, body: { error: "Your mentions can be loaded 12 times an hour. Nothing was sent to Bluesky.", reason: "rate_limited", resumes_at: "2026-11-03T13:00:00.000Z" } });
    $("bskyMentionsBtn").click(); await flush();
    const when = new Date("2026-11-03T13:00:00.000Z").toLocaleString();
    check("P15. a 429 shows the server's message and the time to try again", $("bskyMentionsMsg").textContent ===
      "Your mentions can be loaded 12 times an hour. Nothing was sent to Bluesky. Try again after " + when + ".", $("bskyMentionsMsg").textContent);
    onlineFlag = false;
    const before = sent.length;
    $("bskyMentionsBtn").click(); await flush();
    check("P16. offline: \"Mentions load when you are back online.\" and nothing is sent", sent.length === before && $("bskyMentionsMsg").textContent === "Mentions load when you are back online.");
    onlineFlag = true;
    await w.bfBlueskyMentions.statusChanged({ connected: false, status: "needs_reconnect", handle: "@alice.bsky.social" });
    check("P17. needs reconnecting: the reconnect wording instead of the inbox", $("bskyMentions").hidden === false && $("bskyMentionsReconnect").hidden === false &&
      $("bskyMentionsBody").hidden === true && /stopped accepting the app password saved for @alice\.bsky\.social/.test($("bskyMentionsReconnectText").textContent));
    answers.push({ status: 200, body: { user: { role: "user" } } });
    await w.bfBlueskyMentions.statusChanged({ connected: false, status: "disconnected", handle: null }); await flush();
    const memberHidden = $("bskyMentions").hidden;
    answers.push({ status: 200, body: { user: { role: "admin" } } });
    await w.bfBlueskyMentions.statusChanged({ connected: false, status: "disconnected", handle: null }); await flush();
    check("P18. not connected: hidden for a member; shown for the owner, whose inbox is the platform's", memberHidden === true && $("bskyMentions").hidden === false);
  }
  const PROP = FE("proposals.html");
  const fnSrc = name => { const i = PROP.indexOf("function " + name + "("); return i < 0 ? "" : PROP.slice(i, s.braceMatch(PROP, PROP.indexOf("{", i)) + 1); };
  {
    const pctx = { Intl }; vm.createContext(pctx);
    vm.runInContext("var BSKY_POST_URI = new RegExp(\"^at://(did:[a-z0-9]+:[A-Za-z0-9._:%-]+)/app[.]bsky[.]feed[.]post/([A-Za-z0-9._~:-]+)$\");\n" +
      ["escapeHtml", "graphemeCountText", "postsAsText", "bskyPostUrl", "blueskyReplyPayloadFields"].map(fnSrc).join("\n"), pctx);
    const html = pctx.blueskyReplyPayloadFields({ text: "<b>hi</b>", posts_as: { account: "member", handle: "alice.bsky.social" }, reply: { parent: { uri: MENTION.uri, cid: MENTION.cid } } });
    check("P19. proposals.html shows a reply: who it posts as, the post it answers linked on bsky.app, that it waits for approval, the text escaped",
      html.indexOf("Posts as @alice.bsky.social, as a reply") !== -1 && html.indexOf("https://bsky.app/profile/" + CAROL.did + "/post/3kmen1") !== -1 &&
      html.indexOf("a reply always waits for your approval") !== -1 && html.indexOf("<b>hi</b>") === -1, html.slice(0, 300));
  }
  const guideTips = (/"social\.html": \[([\s\S]*?)\]/.exec(FE("scripts/termaximus-guide.js")) || ["", ""])[1].split("\n").map(t => t.trim()).filter(Boolean);
  const mentionTip = guideTips.find(t => t.indexOf("Show my mentions") !== -1) || "";
  check("P20. the Social guide keeps 5 tips; one names \"Show my mentions\", under 160 characters, never \"live\"",
    guideTips.length === 5 && mentionTip && JSON.parse(mentionTip.replace(/,$/, "")).length <= 160 && !/\blive\b/i.test(mentionTip), mentionTip);

  /* ── K. Privacy and Terms ───────────────────────────────────────────────── */
  console.log("\n══ K. Privacy and Terms ══");
  const LP = require(path.join(REPO, "lib/legalPages.js"));
  const LEGAL = require(path.join(REPO, "lib/legal.js"));
  const esc = LEGAL.escapeHtml;
  const PRIVACY = "If you connect your Bluesky account, BizForce stores your Bluesky handle, its account id (DID) and the app password you made for BizForce, encrypted; it is used only to post or update your Bluesky profile when you approve a proposal, or when your own \"Post approved drafts automatically\" setting is on, and to read the posts that mention you, reply to you or quote you when you open your Mentions inbox. It is never shown back to you or exported (your data download says only which handle you connected and when), you can disconnect at any time, and it is deleted with your account.";
  const MENTIONS = "Your Mentions inbox is read from Bluesky each time you ask and is not stored. If you ask for a reply to be drafted, BizForce sends the AI model (Anthropic) only that post's text, and the text of your own post it answers if there is one, with your business details and guidance, never the author's name, handle or account id; BizForce keeps the draft and the address of the post it answers with your other drafts, and a reply is posted only when you approve it.";
  const TERMS = "If you connect your own Bluesky account, you are responsible for everything posted from it. BizForce posts to it only when you approve a proposal, or when you have turned on \"Post approved drafts automatically\"; a profile change and a reply always wait for your approval.";
  check("K1. BLUESKY_PRIVACY_SENTENCE is the new wording, word for word", LP.BLUESKY_PRIVACY_SENTENCE === PRIVACY, LP.BLUESKY_PRIVACY_SENTENCE);
  check("K2. BLUESKY_MENTIONS_PRIVACY_SENTENCE is the brief's wording, word for word", LP.BLUESKY_MENTIONS_PRIVACY_SENTENCE === MENTIONS, LP.BLUESKY_MENTIONS_PRIVACY_SENTENCE);
  check("K3. BLUESKY_TERMS_SENTENCE ends \"a profile change and a reply always wait for your approval.\"", LP.BLUESKY_TERMS_SENTENCE === TERMS, LP.BLUESKY_TERMS_SENTENCE);
  const priv = FE("privacy.html");
  check("K4. the built privacy.html carries both sentences, the Mentions one directly after the Bluesky one",
    priv.indexOf(esc(PRIVACY)) !== -1 && priv.indexOf(esc(MENTIONS)) !== -1 &&
    /<\/li>\s*<li>/.test(priv.slice(priv.indexOf(esc(PRIVACY)) + esc(PRIVACY).length, priv.indexOf(esc(MENTIONS)))) &&
    priv.indexOf(esc(MENTIONS)) - priv.indexOf(esc(PRIVACY)) - esc(PRIVACY).length < 40);
  check("K5. the built terms.html carries the Terms sentence", FE("terms.html").indexOf(esc(TERMS)) !== -1);
  /* NAMED (campaign sharing, Nov 4 2026): BEFORE TERMS_VERSION "2026-11-03" and "Last updated November 3, 2026", the version
     this change set. AFTER "2026-11-04" and "Last updated November 4, 2026", the version campaign sharing set when it added
     its Terms sentence; still an exact pin, so a revert to this change's version or earlier fails. */
  // NAMED (Nov 5 2026, images in social posts): BEFORE "2026-11-04" (campaign sharing). AFTER "2026-11-05", the version the social
  // images privacy sentence set.
  // NAMED (Nov 6 2026, card upgrades C1): BEFORE "2026-11-05" (images in social posts). AFTER "2026-11-06", the version the
  // card visits privacy sentence set.
  // NAMED (Nov 7 2026, Shopify on OAuth, migration 176): BEFORE "2026-11-06" (card visits). AFTER "2026-11-07", the version the Shopify privacy sentence set.
  check("K6. the terms version is the latest change's, Nov 7 2026 (Shopify on OAuth; this change set Nov 3)", LEGAL.TERMS_VERSION === "2026-11-07" && LEGAL.TERMS_UPDATED === "Last updated November 7, 2026");
  check("K7. the model message matches the privacy sentence: post text, own post text, business details and guidance; never the author's name, handle or account id",
    prompt.indexOf("kids classes") !== -1 && ownPrompt.indexOf("Saturday wheel class") !== -1 && prompt.indexOf(BUSINESS) !== -1 && prompt.indexOf(GUIDANCE) !== -1 &&
    [CAROL.displayName, CAROL.handle, CAROL.did].every(v => prompt.indexOf(v) === -1));

  /* ── Z. zero network ────────────────────────────────────────────────────── */
  console.log("\n══ Z. zero network ══");
  check("Z. no socket, DNS lookup or fetch was attempted", NETWORK.length === 0, NETWORK.join(","));

  console.log("\n" + passes + " passed, " + failures + " failed.");
  process.exit(failures ? 1 : 0);
})().catch(e => { console.log("    FAIL  the check crashed: " + (e && e.stack || e)); process.exit(1); });
