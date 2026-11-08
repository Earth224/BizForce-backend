/* checkInstagramPosting: Instagram posting (migration 179). Connect Instagram through Instagram Login (a single-use
   state, no PKCE), the short-lived token swapped at once for the long-lived one and sealed before Instagram is asked who
   the account is (Business and Creator accounts only), refreshed inside its last 10 days once it is a day old under a
   compare-and-set; filing JPEG photos (1 to 10, alt text frozen) or a Reel (MP4 or MOV), never running them; and on
   approval: the instagram_posts row first, every file's fingerprint right before its container, a Reel by a 2-hour
   signed link used only in one request body, children then the parent, a 60-second poll, and ONE publish under a
   compare-and-set claim, with status recovery. Then the file lifecycle, the library's "in use", the pages and the
   registries.

   Everything runs offline. lib/instagramAuth.js, lib/instagramApi.js, lib/memberVideos.js, lib/memberMedia.js and
   lib/guardedFetch.js are loaded from their own source (a mutation edits the text first). A fake Instagram answers
   behind the REAL guarded transport (guardedFetch.createGuardedFetch with a stub resolver and request). The database is
   in memory and enforces migration 179's CHECKs. A clock drives the library (the poll sleeps on it, never for real).
   A network tripwire fails the run on any socket, DNS question or fetch: no call reaches Meta or Instagram. The routes
   are server.js's own Instagram section, run in a vm. The page is scripts/oauth-return.js and scripts/instagram.js in a
   fake DOM.

   Sections:
     O. connect: start, finish, status, disconnect, the 503 when unconfigured
     T. tokens: the refresh window, the 24-hour minimum, the compare-and-set, single flight, needs_reconnect, the daily job
     F. filing: propose-post, JPEG only, 1 to 10, Reels, the caption, the claims, the cap, never automatic, the registry
     U. the post: the row first, fingerprints, the signed link, children then parent, the poll, publish once, recovery
     L. the lifecycle: retention, deleting a video, the Media Library's "in use"
     P. the pages: the Social page, the shared return, the panel, proposals, integrations, the intros
     G. legal, yourData, README, registries, the migration; R1, the highest migration.

   Run: node scripts/checkInstagramPosting.js     MUTATE=<name> for one mutation, MUTATE=all for every one. */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const crypto = require("crypto");
const Module = require("module");
const MUT = require("./_shared");
const { EventEmitter } = require("events");
const { PassThrough } = require("stream");

const REPO = path.join(__dirname, "..");
const FE = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const read = (f) => fs.readFileSync(path.join(REPO, f), "utf8");
const readFe = (f) => fs.readFileSync(path.join(FE, f), "utf8").replace(/\r\n/g, "\n");

/* Each mutation is a list of edits: [file, search, replacement]. */
const MUTATIONS = {
  // sign-in and tokens
  "state-reusable": [["server", ".eq(\"purpose\", ia.PURPOSE)\n        .is(\"consumed_at\", null).gt(\"expires_at\", consumedAt)", ".eq(\"purpose\", ia.PURPOSE)\n        .gt(\"expires_at\", consumedAt)"]],
  "short-token-stored": [["server", "        grant = await ia.longLived(config, short.shortToken);\n", "        grant = { accessToken: short.shortToken, expiresIn: 3600 };\n"]],
  "unsealed-before-me": [["server", "      // Sealed first: the long-lived token is encrypted before Instagram is asked anything.\n",
    "      await ig.readMe(instagramDeps(), grant.accessToken).catch(function () { return null; });\n      // Sealed first: the long-lived token is encrypted before Instagram is asked anything.\n"]],
  "personal-account-accepted": [["server", "      if (!ig.professional(me)) return res.status(422)", "      if (false) return res.status(422)"]],
  "refresh-too-early": [["auth", "  return nowMs - stored >= REFRESH_MIN_AGE_MS;", "  return true;"]],
  "refresh-cas-missing": [["api", ".eq(\"id\", row.id).eq(\"user_id\", row.user_id).eq(\"token_version\", version).select(\"id\");", ".eq(\"id\", row.id).eq(\"user_id\", row.user_id).select(\"id\");"]],
  "refresh-job-missing": [["server", "      }).then(videoRetentionTick).then(instagramRefreshTick);", "      }).then(videoRetentionTick);"]],
  // filing
  "png-accepted": [["api", "  if (!buf || buf.length < 4 || buf[0] !== 0xff || buf[1] !== 0xd8 || buf[2] !== 0xff) return false;", "  if (!buf || buf.length < 4) return false;"]],
  "eleven-items-accepted": [["api", "value.length > ITEMS_MAX) return { error: MESSAGES.items };", "value.length > ITEMS_MAX + 1) return { error: MESSAGES.items };"]],
  "webm-reel-accepted": [["api", "const REEL_MIMES = Object.freeze([\"video/mp4\", \"video/quicktime\"]);", "const REEL_MIMES = Object.freeze([\"video/mp4\", \"video/quicktime\", \"video/webm\"]);"]],
  "caption-hashtags-unchecked": [["api", "  if (!(typeof tags === \"number\" && hashtagCount(caption) <= tags)) return { ok: false, error: MESSAGES.caption };\n", ""]],
  // the executor
  "sha-unchecked-before-container": [["api", "        await readPhoto(deps, ownerId, mediaRows[p.items[0].id], p.items[0]);\n", ""]],
  "signed-url-logged": [["api", "        if (link.indexOf(\"https://\") !== 0) throw new InstagramApiError(\"unread\", \"signed_url\");\n",
    "        if (link.indexOf(\"https://\") !== 0) throw new InstagramApiError(\"unread\", \"signed_url\");\n        console.log(\"[instagram] reel link \" + link);\n"]],
  "signed-url-long-lived": [["api", "const SIGNED_URL_SECONDS = 7200;", "const SIGNED_URL_SECONDS = 604800;"]],
  "row-after-container": [
    ["api", "  if (!row) {\n    var today;", "  var deferRow = !row;\n  if (!row) row = { container_id: null };\n  if (false) {\n    var today;"],
    ["api", "    // Stored the moment it exists: a replay polls this one and never makes another.\n",
      "    if (deferRow) { var lateAt = nowIso(deps); var late = await deps.supabase.from(\"instagram_posts\").insert({ user_id: ownerId, proposal_id: proposal.id, kind: p.kind, status: \"creating\", " +
      "video_id: p.kind === \"reel\" ? p.video.id : null, created_at: lateAt, updated_at: lateAt }).select(POST_COLUMNS).single(); row = late.data; }\n" +
      "    // Stored the moment it exists: a replay polls this one and never makes another.\n"]],
  "second-parent-on-replay": [["api", "  if (!row.container_id) {\n    var parent;", "  if (true) {\n    var parent;"]],
  "publish-twice": [["api", "  if (st.code === \"PUBLISHED\") return recoverPublished(deps, conn, claimed, caption);\n", "  if (st.code === \"PUBLISHED\") st = { code: \"FINISHED\", text: null };\n"]],
  "published-without-check": [["api", "    st = await containerStatus(deps, conn, claimed.container_id);\n", "    st = { code: \"FINISHED\", text: null };\n"]],
  "status-claim-missing": [["api", ".eq(\"id\", row.id).eq(\"updated_at\", row.updated_at).eq(\"status\", \"processing\").select(\"id\");", ".eq(\"id\", row.id).select(\"id\");"]],
  "limit-unchecked": [["api", "  if (limit.usage >= limit.total) {", "  if (false) {"]],
  "instagram-cap-missing": [["api", "  if (await postsToday(deps, userId) >= POSTS_PER_DAY) return { status: 409, body: { error: MESSAGES.dailyCap, code: \"daily_cap\" } };\n", ""]],
  "auto-executed": [["api", "  if (ins.error) throw ins.error;\n  return { status: 201, body: { proposal: ins.data",
    "  if (ins.error) throw ins.error;\n  await executePublish(deps, Object.assign({}, ins.data, { status: \"executing\" })).catch(function () { return null; });\n  return { status: 201, body: { proposal: ins.data"]],
  // lifecycle, pages, legal
  "file-deleted-before-instagram": [["videos", "return r.path && !named[r.id] && bothIg.published[r.id] && !bothIg.holding[r.id]; })", "return r.path && !named[r.id] && !bothIg.holding[r.id]; })"]],
  "library-delete-while-posting": [["media", "    if (igHit) uses.push(", "    if (false) uses.push("]],
  "wrong-dispatcher": [["server", "  publish_instagram_post: executePublishInstagramPost,\n", "  publish_instagram_post: executePublishTiktokPost,\n"]],
  "unconfigured-not-503": [["server", "  return res.status(503).json({ error: require(\"./lib/instagramAuth\").MESSAGES.notConfigured,", "  return res.status(200).json({ error: require(\"./lib/instagramAuth\").MESSAGES.notConfigured,"]],
  "facebook-claimed-connectable": [["page", "X, LinkedIn and Facebook are coming, through each platform's own sign-in.", "X and LinkedIn are coming, through each platform's own sign-in. Facebook can be connected below."]],
  "privacy-sentence-removed": [["legal", "      INSTAGRAM_PRIVACY_SENTENCE,\n", ""]],
  "innerHTML-on-page": [["ui", "    if (text !== undefined && text !== null) node.textContent = text;", "    if (text !== undefined && text !== null) node.innerHTML = text;"]],
  // the others the code earns
  "scopes-unchecked": [["auth", "  if (!grantsInstagram(g.permissions)) throw new InstagramError(\"no_scopes\", \"scope_missing\");\n", ""]],
  "refresh-window-ignored": [["auth", "  if (ends - nowMs > REFRESH_WINDOW_MS) return false;\n", ""]],
  "refresh-not-single-flight": [["api", "  var running = refreshesInFlight.get(key);", "  var running = null;"]],
  "reconnect-notice-repeated": [["api", ".eq(\"id\", row.id).eq(\"user_id\", row.user_id).eq(\"status\", \"connected\").select(\"id\");", ".eq(\"id\", row.id).eq(\"user_id\", row.user_id).select(\"id\");"]],
  "expiry-ignored": [["api", "  if (!isFinite(expires) || expires <= deps.now()) {\n    await markNeedsReconnect(deps, row, \"expired\");", "  if (false) {\n    await markNeedsReconnect(deps, row, \"expired\");"]],
  "mpo-accepted": [["api", "    if (marker === 0xe2 && body.indexOf(\"MPF\\u0000\") === 0) return false;\n", ""]],
  "mentions-unchecked": [["api", "  if (mentionCount(caption) > MENTION_MAX) return { ok: false, error: MESSAGES.caption };\n", ""]],
  "failed-posts-counted": [["api", ".eq(\"user_id\", userId).neq(\"status\", \"failed\").gte(\"created_at\", since);", ".eq(\"user_id\", userId).gte(\"created_at\", since);"]],
  "carousel-sha-unchecked": [["api", "          await readPhoto(deps, ownerId, mediaRows[it.id], it);\n", ""]],
  "reel-sha-unchecked": [["api", "        if (!(await verifyVideo(deps, video, p.video))) throw new InstagramApiError(\"fingerprint\", \"video_sha\");\n", ""]],
  "alt-text-dropped": [["api", "caption: cap.caption, alt_text: p.items[0].alt });", "caption: cap.caption });"]],
  "poll-unbounded": [["api", "const POLL_MAX_MS = 60 * 1000;", "const POLL_MAX_MS = 600 * 1000;"]],
  "lease-ignored": [["api", "  if (lease && isFinite(before) && deps.now() - before < CLAIM_LEASE_MS) return null;\n", ""]],
  "instagram-cap-missing-at-send": [["api", "    if (today >= POSTS_PER_DAY) throw fail(MESSAGES.dailyCap);\n", ""]],
  "account-changed-ignored": [["api", "  if (conn.ig_user_id !== p.ig_user_id) throw fail(MESSAGES.accountChanged);\n", ""]],
  "published-lookup-skipped": [["api", "  if (found) return recordPublished(deps, conn, row, found);\n", ""]],
  "delete-while-instagram-holds": [["videos", "  if (ig.holding[row.id]) return { status: 409,", "  if (false) return { status: 409,"]],
  "delete-ignores-instagram-proposal": [["videos", "\"publish_tiktok_post\", \"publish_instagram_post\"]);", "\"publish_tiktok_post\"]);"]],
  "library-live-post-ignored": [["media", "    var liveIds = (live.data || []).map(function (r) { return r.proposal_id; }).filter(function (pid) { return pid && !igProposals[pid]; });", "    var liveIds = [];"]],
  "disconnect-deletes-all-states": [["server", "var statesDropped = await supabase.from(\"oauth_states\").delete().eq(\"user_id\", req.user.id).eq(\"purpose\", ia.PURPOSE);",
    "var statesDropped = await supabase.from(\"oauth_states\").delete().eq(\"user_id\", req.user.id);"]],
  "terms-sentence-removed": [["legal", "      TIKTOK_TERMS_SENTENCE,\n      INSTAGRAM_TERMS_SENTENCE\n", "      TIKTOK_TERMS_SENTENCE\n"]],
  "content-facebook-connectable": [["content", "Facebook is coming, through its own sign-in.</p>", "Facebook connects there too.</p>"]],
  "marker-ignored": [["oauth", "    if (!pending || pending.name !== name) return false;\n", "    if (!pending) return false;\n"]],
  "replacestate-skipped": [["ui", "    }).then(function (res) {\n      strip();\n", "    }).then(function (res) {\n"]],
  "foreign-authorize-followed": [["ui", "url.indexOf(AUTH_PREFIX) === 0", "url.indexOf(\"https://\") === 0"]],
  "non-jpeg-picked": [["ui", "      if (item.mime !== \"image/jpeg\") { tell(\"igPrepareMsg\", JPEG_ONLY, true); return; }\n", ""]],
  "webm-choosable": [["ui", "        opt.disabled = !reelOk;\n", ""]],
  "permalink-unchecked-on-page": [["ui", "typeof p.permalink === \"string\" && PERMALINK_RE.test(p.permalink)) {", "typeof p.permalink === \"string\") {"]],
  "card-caption-unescaped": [["proposals", "'<pre class=\"exec-block ig-caption\">' + escapeHtml(String(payload.caption == null ? \"\" : payload.caption))",
    "'<pre class=\"exec-block ig-caption\">' + String(payload.caption == null ? \"\" : payload.caption)"]],
  "content-refusal-disconnects": [["api", "  return c === 190 || c === 102 || c === 10 ||", "  return (e && e.type === \"OAuthException\") || c === 190 || c === 102 || c === 10 ||"]],
  "rate-limit-refusal": [["auth", "    if (refusedGrant(j) || status === 401) throw", "    if (refusedGrant(j) || status === 400 || status === 401) throw"]],
  "export-key-missing": [["yourData", "owner: [\"user_id\"], key: \"created_at\", select: \"kind, status, permalink", "owner: [\"user_id\"], select: \"kind, status, permalink"]],
  "card-link-unchecked": [["proposals", "/.test(result.permalink) ? result.permalink : null;", "/.test(result.permalink) || true ? result.permalink : null;"]]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + NAMES.join(", ")); process.exit(2); }

const LOGS = [];
const OUT = function (s) { process.stdout.write(s + "\n"); };
let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; OUT("    pass  " + label); }
  else { failures++; OUT("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
const UNHANDLED = [];
process.on("unhandledRejection", function (e) { UNHANDLED.push(e); });

const FILES = {
  server: read("server.js"),
  auth: read("lib/instagramAuth.js"),
  api: read("lib/instagramApi.js"),
  videos: read("lib/memberVideos.js"),
  media: read("lib/memberMedia.js"),
  fetch: read("lib/guardedFetch.js"),
  legal: read("lib/legalPages.js"),
  migration: read("supabase/migrations/179_instagram_posting.sql"),
  yourData: read("lib/yourData.js"),
  backup: read("lib/backup.js"),
  schema: read("lib/schemaCheck.js"),
  guideAsk: read("lib/guideAsk.js"),
  readme: read("README.md"),
  privacy: readFe("privacy.html"),
  terms: readFe("terms.html"),
  page: readFe("agents/social.html"),
  content: readFe("agents/content.html"),
  ui: readFe("scripts/instagram.js"),
  oauth: readFe("scripts/oauth-return.js"),
  proposals: readFe("proposals.html"),
  integrations: readFe("integrations.html"),
  guide: readFe("scripts/termaximus-guide.js")
};
if (MUTATE) {
  MUTATIONS[MUTATE].forEach(function (m) { FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE + " in " + m[0]); });
  OUT("\n!! MUTATION: " + MUTATE);
}
["log", "warn", "error", "info"].forEach(function (k) { console[k] = function () { LOGS.push([].slice.call(arguments).map(String).join(" ")); }; });

const J = JSON.stringify;
const SECRET_HEX = crypto.createHash("sha256").update("checkInstagramPosting").digest("hex");
process.env.ENCRYPTION_SECRET = SECRET_HEX;
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const CRYPT = realRequire("./lib/apiKeyCrypto");
function compile(src, file, map) {
  const m = { exports: {} };
  const fn = vm.compileFunction(src, ["module", "exports", "require", "__dirname", "__filename"], { filename: path.join(REPO, file) });
  const localRequire = Module.createRequire(path.join(REPO, file));
  fn(m, m.exports, function (r) { return Object.prototype.hasOwnProperty.call(map, r) ? map[r] : localRequire(r); }, path.dirname(path.join(REPO, file)), path.join(REPO, file));
  return m.exports;
}
/* The Instagram stub of the moment: every request the libraries make goes to it. */
let CURRENT = null;
const GF_PROXY = { guardedJsonRequest: function (u, o) { return CURRENT.jsonRequest(u, o); } };
const GF = compile(FILES.fetch, "lib/guardedFetch.js", {});
const IA = compile(FILES.auth, "lib/instagramAuth.js", { "./guardedFetch": GF_PROXY });
const MV = compile(FILES.videos, "lib/memberVideos.js", {});
const MM = compile(FILES.media, "lib/memberMedia.js", {});
const IG = compile(FILES.api, "lib/instagramApi.js", { "./instagramAuth": IA, "./memberVideos": MV, "./memberMedia": MM });
const LP = compile(FILES.legal, "lib/legalPages.js", {});

const APP = { id: "1234567890123456", secret: "check-ig-secret-" + "7".repeat(16) };
const CONFIGURED = { INSTAGRAM_APP_ID: APP.id, INSTAGRAM_APP_SECRET: APP.secret, SUPABASE_URL: "https://check.supabase.co" };
const BASE = "https://check.supabase.co";
const USER = "00000000-0000-4000-8000-000000000001";
const OTHER = "00000000-0000-4000-8000-000000000002";
const SHORT = "IGQshort-check-" + "a1".repeat(10);
const LONG = "IGQlong-check-" + "b2".repeat(10);
const LONG2 = "IGQlong2-check-" + "c3".repeat(10);
const WINNER = "IGQwinner-check-" + "d4".repeat(10);
const CODE = "AQcheck-code-" + "e5".repeat(10);
const IG_ID = "17841400000000001";
const IG_ID2 = "17841400000000002";
const USERNAME = "maplestreet";
const SIGNED_MARK = "check-signed-token-";
const REDIRECT = "https://bizforceai.net/agents/social.html";
const PAGE_PATH = "/agents/social.html";
const SECRETS = [SHORT, LONG, LONG2, WINNER, CODE, APP.secret, SIGNED_MARK];
function noSecretIn(text) { return SECRETS.every(function (s) { return String(text).indexOf(s) === -1; }); }
const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F2FF}\u{FE0F}]/u;
const NOT_SET_UP = "Instagram connection isn't set up yet.";
const LIMITS = { label: "Instagram", max: 2200, kind: "hard", truncates_at: 125, hashtag_max: 30, hashtag_practical: 5 };
const sha = function (b) { return crypto.createHash("sha256").update(b).digest("hex"); };
const DAY = 86400000;

function filler(n, seed) {
  const out = Buffer.alloc(n);
  let x = seed || 7;
  for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) >>> 0; out[i] = x >>> 24; }
  return out;
}
/* A plain JPEG: SOI, APP0 JFIF, then SOS and data. */
function jpeg(n, seed) {
  const head = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]), Buffer.from("JFIF\u0000", "latin1"), Buffer.alloc(9), Buffer.from([0xff, 0xda])]);
  return Buffer.concat([head, filler(Math.max(0, (n || 2048) - head.length), seed)]);
}
/* An MPO: APP2 "MPF\0" before the image data. */
function mpo(n, seed) {
  const head = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe2, 0x00, 0x0a]), Buffer.from("MPF\u0000", "latin1"), Buffer.alloc(4), Buffer.from([0xff, 0xda])]);
  return Buffer.concat([head, filler(Math.max(0, (n || 2048) - head.length), seed)]);
}
function png(n, seed) {
  const head = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([head, filler(Math.max(0, (n || 2048) - head.length), seed)]);
}
function mp4(n, seed) {
  const head = Buffer.concat([Buffer.from([0, 0, 0, 0x18]), Buffer.from("ftypisom", "latin1"), Buffer.from([0, 0, 2, 0]), Buffer.from("isomiso2", "latin1")]);
  return Buffer.concat([head, filler(Math.max(0, (n || 4096) - head.length), seed)]);
}

/* ── the clock ───────────────────────────────────────────────────────────── */
const CLOCK = { t: Date.parse("2026-11-07T12:00:00.000Z"), slept: 0 };
function iso(ms) { return new Date(ms).toISOString(); }

/* ── an in-memory database, with migration 179's CHECKs, and Storage ─────── */
function uuid() { return crypto.randomUUID(); }
const HEX = /^[0-9a-f]+$/;
const EV = [];
function makeStorage() {
  const objects = {};
  const calls = [];
  function webStream(buf) {
    let at = 0;
    return new ReadableStream({
      pull: function (controller) {
        if (at >= buf.length) { controller.close(); return; }
        const n = Math.min(65536, buf.length - at);
        controller.enqueue(new Uint8Array(buf.subarray(at, at + n)));
        at += n;
      }
    });
  }
  const video = {
    download: function (p) {
      return {
        asStream: async function () {
          calls.push({ op: "stream", path: p });
          EV.push("storage:stream");
          const o = objects["bf-video/" + p];
          if (!o) return { data: null, error: { message: "Object not found", statusCode: "404" } };
          return { data: webStream(o.buf), error: null };
        }
      };
    },
    createSignedUrl: async function (p, seconds) {
      calls.push({ op: "sign", path: p, seconds: seconds });
      EV.push("storage:sign:" + seconds);
      return { data: { signedUrl: BASE + "/storage/v1/object/sign/bf-video/" + p + "?token=" + SIGNED_MARK + calls.length }, error: null };
    },
    remove: async function (paths) {
      calls.push({ op: "remove", bucket: "bf-video", paths: paths.slice() });
      paths.forEach(function (p) { delete objects["bf-video/" + p]; });
      return { data: paths.map(function (p) { return { name: p }; }), error: null };
    },
    list: async function () { return { data: [], error: null }; }
  };
  const pub = {
    download: async function (p) {
      calls.push({ op: "download", path: p });
      EV.push("storage:read:" + p);
      const o = objects["bf-public/" + p];
      if (!o) return { data: null, error: { message: "Object not found" } };
      const buf = o.buf;
      return { data: { arrayBuffer: async function () { return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length); } }, error: null };
    },
    remove: async function (paths) { calls.push({ op: "remove", bucket: "bf-public", paths: paths.slice() }); return { data: [], error: null }; }
  };
  return { from: function (b) { if (b === "bf-video") return video; if (b === "bf-public") return pub; throw new Error("unexpected bucket " + b); }, objects: objects, calls: calls };
}
function makeDb() {
  const t = { member_instagram_connections: [], instagram_posts: [], member_media: [], member_videos: [], oauth_states: [], agent_proposals: [], notifications: [],
    job_runs: [], business_profiles: [], social_post_drafts: [] };
  const fail = {};
  function rows(name) { if (!t[name]) t[name] = []; return t[name]; }
  function sealedOk(c, i, a) { return HEX.test(c || "") && /^[0-9a-f]{24}$/.test(i || "") && /^[0-9a-f]{32}$/.test(a || ""); }
  function uniqueViolation(name, row, except) {
    const others = rows(name).filter(function (r) { return r !== except; });
    if (name === "member_instagram_connections" && others.some(function (r) { return r.user_id === row.user_id; })) return "member_instagram_connections_user_id_key";
    if (name === "instagram_posts" && others.some(function (r) { return r.proposal_id === row.proposal_id; })) return "instagram_posts_proposal_id_key";
    if (name === "member_videos" && row.path != null && others.some(function (r) { return r.path === row.path; })) return "member_videos_path_key";
    if (name === "job_runs" && others.some(function (r) { return r.job_name === row.job_name; })) return "job_runs_pkey";
    return null;
  }
  function checkViolation(name, row) {
    if (name === "member_instagram_connections") {
      if (!/^[0-9]{1,30}$/.test(row.ig_user_id || "")) return "member_instagram_connections_ig_user_id_check";
      if (!(String(row.username || "").length >= 1 && String(row.username).length <= 100)) return "member_instagram_connections_username_check";
      if (["BUSINESS", "MEDIA_CREATOR"].indexOf(row.account_type) === -1) return "member_instagram_connections_account_type_check";
      if (!sealedOk(row.access_ciphertext, row.access_iv, row.access_auth_tag)) return "member_instagram_connections_access_check";
      if (!row.access_expires_at) return "member_instagram_connections_access_expires_at_not_null";
      if (!(Number.isInteger(row.token_version) && row.token_version >= 0)) return "member_instagram_connections_token_version_check";
      if (row.granted_scopes != null && !(String(row.granted_scopes).length <= 500 && /^[a-z_,]*$/.test(row.granted_scopes))) return "member_instagram_connections_scopes_check";
      if (["connected", "needs_reconnect"].indexOf(row.status) === -1) return "member_instagram_connections_status_check";
      if (row.last_error_code != null && String(row.last_error_code).length > 60) return "member_instagram_connections_error_code_check";
    }
    if (name === "instagram_posts") {
      if (["image", "carousel", "reel"].indexOf(row.kind) === -1) return "instagram_posts_kind_check";
      if (row.container_id != null && !/^[0-9]{1,30}$/.test(row.container_id)) return "instagram_posts_container_check";
      if (["creating", "processing", "published", "failed"].indexOf(row.status) === -1) return "instagram_posts_status_check";
      if (row.media_id != null && !/^[0-9]{1,30}$/.test(row.media_id)) return "instagram_posts_media_check";
      if (row.permalink != null && !(String(row.permalink).length <= 300 && String(row.permalink).indexOf("https://www.instagram.com/") === 0)) return "instagram_posts_permalink_check";
      if (row.error != null && String(row.error).length > 300) return "instagram_posts_error_check";
      if ((row.status === "published") !== (row.media_id != null && row.published_at != null)) return "instagram_posts_published_check";
      if (!(row.kind !== "reel" || row.video_id != null || ["published", "failed"].indexOf(row.status) !== -1)) return "instagram_posts_reel_video_check";
      if (!row.user_id || !row.proposal_id) return "instagram_posts_not_null";
    }
    if (name === "oauth_states") {
      if (["mailbox_microsoft", "store_shopify", "youtube_google", "tiktok_login", "instagram_login"].indexOf(row.purpose) === -1) return "oauth_states_purpose_check";
      if (["store_shopify", "tiktok_login", "instagram_login"].indexOf(row.purpose) === -1 && (row.verifier_ciphertext == null || row.verifier_iv == null || row.verifier_auth_tag == null)) return "oauth_states_verifier_shape_check";
    }
    return null;
  }
  function defaults(name, row) {
    const r = Object.assign({ id: uuid(), created_at: new Date(CLOCK.t).toISOString() }, row);
    if (name === "member_instagram_connections") { if (r.status === undefined) r.status = "connected"; if (r.token_version === undefined) r.token_version = 0; }
    if (name === "instagram_posts") {
      if (r.status === undefined) r.status = "creating";
      ["container_id", "media_id", "permalink", "video_id", "error", "published_at"].forEach(function (k) { if (r[k] === undefined) r[k] = null; });
      if (r.updated_at === undefined) r.updated_at = r.created_at;
    }
    if (name === "oauth_states") { if (r.consumed_at === undefined) r.consumed_at = null; if (r.flow_context === undefined) r.flow_context = null; }
    return r;
  }
  function project(r, cols) {
    if (!cols || cols.trim() === "*") return Object.assign({}, r);
    const o = {};
    cols.split(",").map(function (c) { return c.trim(); }).forEach(function (c) { o[c] = r[c] === undefined ? null : r[c]; });
    return o;
  }
  function from(name) {
    const q = { op: null, cols: null, count: false, head: false, filters: [], or: null, payload: null, onConflict: null, single: null, returning: false, limit: null };
    const api = {
      select: function (cols, opts) { if (!q.op) q.op = "select"; else q.returning = true; q.cols = cols; if (opts && opts.count) q.count = true; if (opts && opts.head) q.head = true; return api; },
      insert: function (p) { q.op = "insert"; q.payload = p; return api; },
      update: function (p) { q.op = "update"; q.payload = p; return api; },
      upsert: function (p, o) { q.op = "upsert"; q.payload = p; q.onConflict = o && o.onConflict; return api; },
      delete: function () { q.op = "delete"; return api; },
      eq: function (c, v) { q.filters.push(["eq", c, v]); return api; },
      neq: function (c, v) { q.filters.push(["neq", c, v]); return api; },
      in: function (c, v) { q.filters.push(["in", c, v]); return api; },
      is: function (c, v) { q.filters.push(["is", c, v]); return api; },
      not: function (c, op, v) { q.filters.push(["not", c, op, v]); return api; },
      gt: function (c, v) { q.filters.push(["gt", c, v]); return api; },
      gte: function (c, v) { q.filters.push(["gte", c, v]); return api; },
      lt: function (c, v) { q.filters.push(["lt", c, v]); return api; },
      lte: function (c, v) { q.filters.push(["lte", c, v]); return api; },
      or: function (s) { q.or = s; return api; },
      order: function () { return api; }, limit: function (n) { q.limit = n; return api; }, range: function () { return api; },
      maybeSingle: function () { q.single = "maybe"; return api; },
      single: function () { q.single = "one"; return api; },
      then: function (ok, bad) { return Promise.resolve().then(run).then(ok, bad); }
    };
    function match(r) {
      if (!q.filters.every(function (f) {
        if (f[0] === "eq") return String(r[f[1]]) === String(f[2]);
        if (f[0] === "neq") return String(r[f[1]]) !== String(f[2]);
        if (f[0] === "in") return f[2].map(String).indexOf(String(r[f[1]])) !== -1;
        if (f[0] === "is") return f[2] === null ? r[f[1]] == null : r[f[1]] === f[2];
        if (f[0] === "not") return f[2] === "is" && f[3] === null ? r[f[1]] != null : true;
        if (f[0] === "gt") return r[f[1]] != null && String(r[f[1]]) > String(f[2]);
        if (f[0] === "gte") return r[f[1]] != null && String(r[f[1]]) >= String(f[2]);
        if (f[0] === "lt") return r[f[1]] != null && String(r[f[1]]) < String(f[2]);
        if (f[0] === "lte") return r[f[1]] != null && String(r[f[1]]) <= String(f[2]);
        return true;
      })) return false;
      if (q.or) { const d = /neq\.(\d{4}-\d{2}-\d{2})/.exec(q.or)[1]; return r.last_run_on == null || r.last_run_on !== d; }
      return true;
    }
    function shape(list) {
      const data = list.map(function (r) { return project(r, q.cols); });
      if (q.single === "maybe") return data.length > 1 ? { data: null, error: { code: "PGRST116" } } : { data: data[0] || null, error: null };
      if (q.single === "one") return data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116", message: "not one row" } };
      return { data: q.op === "select" || q.returning ? data : null, error: null };
    }
    function run() {
      if (q.op !== "select") EV.push("db:" + name + ":" + q.op);
      const all = rows(name);
      if (q.op === "select") {
        if (fail[name]) { const e = fail[name]; delete fail[name]; return { data: null, error: e }; }
        let hit = all.filter(match);
        if (q.limit != null) hit = hit.slice(0, q.limit);
        const out = q.head ? { data: null, error: null } : shape(hit);
        if (q.count) out.count = hit.length;
        return out;
      }
      if (q.op === "insert") {
        const list = Array.isArray(q.payload) ? q.payload : [q.payload];
        const made = [];
        for (const p of list) {
          const r = defaults(name, p);
          const u = uniqueViolation(name, r, null); if (u) return { data: null, error: { code: "23505", message: u } };
          const c = checkViolation(name, r); if (c) return { data: null, error: { code: "23514", message: c } };
          made.push(r);
        }
        made.forEach(function (r) { all.push(r); });
        return shape(made);
      }
      if (q.op === "update") {
        const hit = all.filter(match);
        for (const r of hit) {
          const next = Object.assign({}, r, q.payload);
          const u = uniqueViolation(name, next, r); if (u) return { data: null, error: { code: "23505", message: u } };
          const c = checkViolation(name, next); if (c) return { data: null, error: { code: "23514", message: c } };
        }
        hit.forEach(function (r) { Object.assign(r, q.payload); });
        return shape(hit);
      }
      if (q.op === "upsert") {
        const keys = String(q.onConflict).split(",");
        const p = q.payload;
        const prev = all.find(function (r) { return keys.every(function (k) { return r[k] != null && String(r[k]) === String(p[k]); }); });
        if (prev) {
          const next = Object.assign({}, prev, p);
          const c = checkViolation(name, next); if (c) return { data: null, error: { code: "23514", message: c } };
          Object.assign(prev, p);
          return shape([prev]);
        }
        const r = defaults(name, p);
        const c = checkViolation(name, r); if (c) return { data: null, error: { code: "23514", message: c } };
        all.push(r);
        return shape([r]);
      }
      if (q.op === "delete") {
        const hit = all.filter(match);
        t[name] = all.filter(function (r) { return hit.indexOf(r) === -1; });
        return shape(hit);
      }
      return { data: null, error: { message: "fake: no op" } };
    }
    return api;
  }
  return { from: from, t: t, fail: fail, storage: makeStorage() };
}

/* ── Instagram, stubbed behind the real guarded fetcher ─────────────────── */
function reply(status, body) {
  const h = {};
  if (body !== null && body !== undefined) h["content-type"] = "application/json; charset=UTF-8";
  return { status: status, headers: h, raw: body === null || body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body), "utf8") };
}
function headerOf(hdrs, name) {
  const k = Object.keys(hdrs || {}).filter(function (x) { return x.toLowerCase() === name.toLowerCase(); })[0];
  return k ? String(hdrs[k]) : null;
}
const PUBLIC_V4 = "142.250.80.10";
const REFUSED_TOKEN = { error: { message: "Error validating access token: Session has expired.", type: "OAuthException", code: 190 } };
function makeInstagram(opts) {
  const o = Object.assign({}, opts || {});
  const g = { opts: o, requests: [], tokenCalls: [], longCalls: [], refreshCalls: [], containers: {}, order: [], publishes: [], media: [], n: 0, atFirstContainer: null, db: o.db || null };
  function record(method, u, headers, body) {
    const auth = headerOf(headers, "Authorization");
    const entry = { method: method, host: u.hostname, path: u.pathname, search: u.search, url: u.href, bearer: auth ? auth.replace(/^Bearer /, "") : null,
      contentType: headerOf(headers, "Content-Type"), body: body ? body.toString("utf8") : "" };
    g.requests.push(entry);
    return entry;
  }
  function form(entry) { return new URLSearchParams(entry.body); }
  function answer(method, u, headers, body) {
    const entry = record(method, u, headers, body);
    const q = u.searchParams;
    if (u.hostname === "api.instagram.com" && u.pathname === "/oauth/access_token" && method === "POST") {
      const f = form(entry);
      g.tokenCalls.push({ keys: Array.from(f.keys()).sort().join(","), client_id: f.get("client_id"), secret_ok: f.get("client_secret") === APP.secret,
        grant_type: f.get("grant_type"), redirect_uri: f.get("redirect_uri"), code: f.get("code"), formType: entry.contentType });
      EV.push("ig:token");
      if (o.exchange === "invalid") return reply(400, { error_type: "OAuthException", code: 400, error_message: "This authorization code has been used" });
      if (o.exchange === "down") return reply(503, { error: "busy" });
      const perms = o.permissions === undefined ? ["instagram_business_basic", "instagram_business_content_publish"] : o.permissions;
      const grant = { access_token: SHORT, user_id: IG_ID, permissions: perms };
      return reply(200, o.wrapped ? { data: [grant] } : grant);
    }
    if (u.hostname === "graph.instagram.com" && u.pathname === "/access_token" && method === "GET") {
      g.longCalls.push({ grant_type: q.get("grant_type"), secret_ok: q.get("client_secret") === APP.secret, short_ok: q.get("access_token") === SHORT });
      EV.push("ig:long");
      if (o.longLived === "down") return reply(500, { error: { message: "An unexpected error has occurred.", code: 2 } });
      return reply(200, { access_token: LONG, token_type: "bearer", expires_in: 5183944 });
    }
    if (u.hostname === "graph.instagram.com" && u.pathname === "/refresh_access_token" && method === "GET") {
      g.refreshCalls.push({ grant_type: q.get("grant_type"), token: q.get("access_token") });
      EV.push("ig:refresh");
      if (typeof o.onRefresh === "function") o.onRefresh();
      if (o.refresh === "invalid") return reply(400, REFUSED_TOKEN);
      if (o.refresh === "down") return reply(503, { error: { message: "busy", code: 2 } });
      if (o.refresh === "limited") return reply(400, { error: { message: "Application request limit reached", type: "OAuthException", code: 4 } });
      return reply(200, { access_token: LONG2, token_type: "bearer", expires_in: 5183944 });
    }
    if (u.hostname !== "graph.instagram.com" || u.pathname.indexOf("/v26.0/") !== 0) return reply(404, { error: { message: "no stub for " + u.pathname } });
    if (o.reject && o.reject.indexOf(entry.bearer) !== -1) return reply(401, REFUSED_TOKEN);
    const parts = u.pathname.slice("/v26.0/".length).split("/");
    if (parts[0] === "me" && method === "GET") {
      EV.push("ig:me");
      g.meBearer = entry.bearer;
      return reply(200, { user_id: o.meId || IG_ID, username: USERNAME, account_type: o.accountType || "BUSINESS" });
    }
    if (parts.length === 2 && parts[1] === "media" && method === "POST") {
      const f = form(entry);
      if (!g.atFirstContainer && g.db) g.atFirstContainer = { posts: g.db.t.instagram_posts.map(function (r) { return Object.assign({}, r); }) };
      EV.push("ig:container:" + (f.get("is_carousel_item") === "true" ? "child" : (f.get("media_type") || "IMAGE")));
      if (o.containerError) return reply(400, { error: { message: o.containerError, type: "OAuthException", code: 9004 } });
      g.n++;
      const id = String(17900000000000000 + g.n * 10);
      const c = { id: id, owner: parts[0], form: {}, seq: [], published: false };
      f.forEach(function (v, k) { c.form[k] = v; });
      c.seq = typeof o.seqFor === "function" ? (o.seqFor(c) || []).slice() : (o.seq || []).slice();
      g.containers[id] = c;
      g.order.push(id);
      return reply(200, { id: id });
    }
    if (parts.length === 2 && parts[1] === "media" && method === "GET") {
      EV.push("ig:media-list");
      g.listSearch = u.search;
      return reply(200, { data: g.media.slice().reverse().slice(0, 10) });
    }
    if (parts.length === 2 && parts[1] === "content_publishing_limit" && method === "GET") {
      EV.push("ig:limit");
      return reply(200, { data: [{ quota_usage: o.usage === undefined ? 3 : o.usage, config: { quota_total: 100, quota_duration: 86400 } }] });
    }
    if (parts.length === 2 && parts[1] === "media_publish" && method === "POST") {
      const f = form(entry);
      const cid = f.get("creation_id");
      EV.push("ig:publish");
      g.publishes.push(cid);
      if (o.publishRefuse) return reply(400, { error: { message: o.publishRefuse, code: 9007 } });
      const c = g.containers[cid];
      g.n++;
      const mediaId = String(18000000000000000 + g.n * 10);
      if (c) { c.published = true; c.mediaId = mediaId; }
      g.media.push({ id: mediaId, timestamp: new Date(CLOCK.t).toISOString().replace(/\.\d{3}Z$/, "+0000"), caption: c ? c.form.caption : "" });
      if (o.publishLost && g.publishes.length <= o.publishLost) return { error: Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }) };
      return reply(200, { id: mediaId });
    }
    if (parts.length === 1 && method === "GET" && q.get("fields") === "status_code,status") {
      EV.push("ig:status");
      const c = g.containers[parts[0]];
      if (!c) return reply(400, { error: { message: "Unsupported get request.", code: 100 } });
      let code;
      if (c.published && !o.lagging) code = "PUBLISHED";
      else if (c.seq.length) code = c.seq.shift();
      else code = o.after || "FINISHED";
      return reply(200, code === "ERROR" ? { status_code: code, status: o.errorText || "Error: the video format is not supported.", id: c.id } : { status_code: code, id: c.id });
    }
    if (parts.length === 1 && method === "GET" && q.get("fields") === "permalink") {
      EV.push("ig:permalink");
      return reply(200, { permalink: o.permalink || ("https://www.instagram.com/p/Check" + parts[0].slice(-6) + "/"), id: parts[0] });
    }
    return reply(404, { error: { message: "no stub for " + u.pathname } });
  }
  function resolve(hostname, lookupOptions, cb) { return cb(null, [{ address: PUBLIC_V4, family: 4 }]); }
  function transport(options) {
    const req = new EventEmitter();
    const chunks = [];
    let destroyed = false;
    const u = new URL("https://" + options.hostname + options.path);
    req.destroy = function () { destroyed = true; };
    req.setTimeout = function () { return req; };
    req.write = function (c) { chunks.push(Buffer.from(c)); return true; };
    req.end = function (payload) {
      if (payload) chunks.push(Buffer.from(payload));
      process.nextTick(function () {
        options.lookup(options.hostname, { all: true }, function (err) {
          if (err) return req.emit("error", err);
          if (destroyed) return;
          const r = answer(options.method, u, options.headers, Buffer.concat(chunks));
          if (r.error) return req.emit("error", r.error);
          const res = new PassThrough();
          res.statusCode = r.status;
          res.headers = r.headers;
          req.emit("response", res);
          res.end(r.raw);
        });
      });
    };
    return req;
  }
  const guarded = GF.createGuardedFetch({ resolve: resolve, request: transport });
  g.jsonRequest = function (url, options) { return guarded.json(url, options); };
  g.of = function (pred) { return g.requests.filter(pred); };
  g.containerPosts = function () { return g.of(function (r) { return r.method === "POST" && /\/v26\.0\/\d+\/media$/.test(r.path); }); };
  g.statusCalls = function () { return g.of(function (r) { return r.method === "GET" && /fields=status_code/.test(r.search); }); };
  return g;
}

/* THE NETWORK TRIPWIRE: no socket, no real DNS question, no fetch, in this whole run. */
const TRIPPED = [];
(function tripwire() {
  const http = require("http"), https = require("https"), net = require("net"), tls = require("tls"), dns = require("dns");
  function wire(obj, name, label) {
    obj[name] = function () { TRIPPED.push(label); throw new Error("checkInstagramPosting: " + label + " is not allowed in this check"); };
  }
  wire(http, "request", "http.request"); wire(http, "get", "http.get");
  wire(https, "request", "https.request"); wire(https, "get", "https.get");
  wire(net, "connect", "net.connect"); wire(net, "createConnection", "net.createConnection");
  wire(tls, "connect", "tls.connect");
  wire(dns, "lookup", "dns.lookup"); wire(dns, "resolve", "dns.resolve"); wire(dns.promises, "lookup", "dns.promises.lookup");
  globalThis.fetch = function () { TRIPPED.push("fetch"); return Promise.reject(new Error("checkInstagramPosting: fetch is not allowed in this check")); };
})();

/* ── the routes, run from server.js's own source ─────────────────────────── */
function sliceOf(src, start, end) {
  const a = src.indexOf(start), b = src.indexOf(end, a);
  return a === -1 || b === -1 ? "" : src.slice(a, b);
}
const IG_SECTION = sliceOf(FILES.server, "/* ── Instagram posting (migration 179; lib/instagramAuth.js, lib/instagramApi.js) ──",
  "/* ── YouTube uploads (migration 177; lib/googleAuth.js, lib/youtubeApi.js, lib/memberVideos.js) ──");
const CRON_START = "  if (require.main === module) {\n    cron.schedule(\"45 4 * * *\", function () {\n      cardLeads.cardLeadsPurgeTick(supabase)";
const CRON_SECTION = sliceOf(FILES.server, CRON_START, "    console.log(\"[startup] card leads purge scheduled");
function requireAuth() {} function requireActiveSubscription() {} function aiLimiter() {}
function claimsStub(text) {
  return /guaranteed/i.test(String(text)) ? { error: "That makes a promise BizForce can't check (\"guaranteed\").", violations: [{ phrase: "guaranteed" }] } : null;
}
function mountRoutes(env) {
  env = env || {};
  const db = env.db || makeDb();
  const ig = makeInstagram(Object.assign({ db: db }, env.ig || {}));
  CURRENT = ig;
  const routes = {};
  const prompts = [];
  const crypt = {
    encrypt: function (p) { EV.push(p === LONG ? "encrypt:long" : (p === SHORT ? "encrypt:short" : "encrypt:other")); return CRYPT.encrypt(p); },
    decrypt: function (x) { return CRYPT.decrypt(x); }
  };
  const ctx = {
    supabase: Object.assign(function () {}, { from: db.from, storage: db.storage }),
    process: { env: Object.assign({ ENCRYPTION_SECRET: SECRET_HEX }, env.env || {}) },
    console: console,
    rateLimit: function (o) { return { limiter: o }; },
    requireAuth: requireAuth, requireActiveSubscription: requireActiveSubscription, aiLimiter: aiLimiter,
    nowIso: function () { return new Date().toISOString(); },
    FRONTEND_URL: "https://bizforceai.net",
    SOCIAL_PLATFORMS: { instagram: LIMITS },
    blueskyClaimsRefusal: claimsStub,
    callAnthropicText: async function (prompt) {
      prompts.push(prompt);
      return { text: env.draft !== undefined ? env.draft : "CAPTION: Spring cakes, baked fresh every morning. #bakery #cakes" };
    },
    setTimeout: function (f) { setImmediate(f); return 0; },
    Promise: Promise, Buffer: Buffer, URL: URL, Date: Date, JSON: JSON, Object: Object, Array: Array, String: String, Number: Number, Math: Math,
    require: function (r) {
      if (r === "./lib/apiKeyCrypto") return crypt;
      if (r === "./lib/guardedFetch") return Object.assign({}, GF, GF_PROXY);
      if (r === "./lib/instagramAuth") return IA;
      if (r === "./lib/instagramApi") return IG;
      if (r === "./lib/memberVideos") return MV;
      if (r === "./lib/memberMedia") return MM;
      return realRequire(r);
    },
    app: {}
  };
  ["get", "post", "put", "delete"].forEach(function (m) {
    ctx.app[m] = function (p) { const args = [].slice.call(arguments, 1); routes[m + " " + p] = { middleware: args.slice(0, -1), handler: args[args.length - 1] }; };
  });
  vm.createContext(ctx);
  vm.runInContext(IG_SECTION, ctx, { filename: "server.js (Instagram section)" });
  return { db: db, ig: ig, routes: routes, ctx: ctx, prompts: prompts, storage: db.storage };
}
async function hit(m, key, req) {
  CURRENT = m.ig;
  const r = m.routes[key];
  if (!r) return { status: 0, body: {}, headers: {}, err: new Error("no route " + key) };
  const res = { statusCode: 200, body: undefined, headers: {}, set: function (k, v) { this.headers[k] = v; return this; },
    status: function (c) { this.statusCode = c; return this; }, json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let err = null;
  try { await r.handler(Object.assign({ user: { id: USER }, body: {}, params: {} }, req), res, function (e) { err = e || new Error("next"); }); }
  catch (e) { err = e; res.statusCode = 599; }
  return { status: res.statusCode, body: res.body || {}, headers: res.headers, err: err };
}
async function attempt(p) { try { return { ok: true, v: await p }; } catch (e) { return { ok: false, msg: e && e.message, code: e && e.code, kind: e && e.kind }; } }
async function begin(m) {
  const r = await hit(m, "post /api/instagram/start", {});
  const url = r.body && r.body.authorize_url ? new URL(r.body.authorize_url) : null;
  return { r: r, url: url, state: url ? url.searchParams.get("state") : null };
}
async function connect(m) {
  const b = await begin(m);
  const f = await hit(m, "post /api/instagram/finish", { body: { code: CODE, state: b.state } });
  return { b: b, f: f };
}
function seal(p) { const s = CRYPT.encrypt(p); return { ciphertext: s.ciphertext, iv: s.iv, authTag: s.authTag }; }
function seedConnection(db, over, nowMs) {
  const n = nowMs === undefined ? CLOCK.t : nowMs;
  const a = seal((over && over.token) || LONG);
  const row = Object.assign({ id: uuid(), user_id: USER, ig_user_id: IG_ID, username: USERNAME, account_type: "BUSINESS",
    access_ciphertext: a.ciphertext, access_iv: a.iv, access_auth_tag: a.authTag,
    access_expires_at: iso(n + 50 * DAY), token_version: 0, granted_scopes: "instagram_business_basic,instagram_business_content_publish",
    status: "connected", last_ok_at: null, last_error_at: null, last_error_code: null, created_at: iso(n - 10 * DAY), updated_at: iso(n - 10 * DAY) }, over || {});
  delete row.token;
  db.t.member_instagram_connections.push(row);
  return row;
}
function mediaPath(userId) { return "media/" + userId + "/" + crypto.randomBytes(16).toString("hex") + ".jpg"; }
function seedPhoto(db, buf, over) {
  const userId = (over && over.user_id) || USER;
  const row = Object.assign({ id: uuid(), user_id: userId, path: mediaPath(userId), kind: "image", mime: "image/jpeg", bytes: buf.length, sha256: sha(buf),
    label: "Spring cakes", alt_text: "Three spring cakes on a wooden table", created_at: iso(CLOCK.t - DAY) }, over || {});
  db.t.member_media.push(row);
  db.storage.objects["bf-public/" + row.path] = { buf: buf };
  return row;
}
function videoPath(userId) { return "video/" + userId + "/" + crypto.randomBytes(16).toString("hex") + ".mp4"; }
function seedVideo(db, buf, over) {
  const userId = (over && over.user_id) || USER;
  const p = over && over.path !== undefined ? over.path : videoPath(userId);
  const row = Object.assign({ id: uuid(), user_id: userId, path: p, mime: "video/mp4", bytes: buf.length, sha256: sha(buf), label: "Spring cakes",
    status: "ready", youtube_video_id: null, session_ciphertext: null, session_iv: null, session_auth_tag: null, uploaded_at: null,
    tiktok_publish_id: null, tiktok_status: null, tiktok_posted_at: null, tiktok_post_id: null,
    tiktok_upload_ciphertext: null, tiktok_upload_iv: null, tiktok_upload_auth_tag: null, tiktok_upload_expires_at: null,
    created_at: iso(CLOCK.t - DAY) }, over || {});
  db.t.member_videos.push(row);
  if (row.path) db.storage.objects["bf-video/" + row.path] = { buf: buf };
  return row;
}
function seedPosts(db, n, status, ageMs) {
  for (let i = 0; i < n; i++) {
    const st = status || "processing";
    db.t.instagram_posts.push({ id: uuid(), user_id: USER, proposal_id: uuid(), kind: "image", container_id: st === "creating" ? null : String(17000000000000000 + i), status: st,
      media_id: st === "published" ? String(18100000000000000 + i) : null, permalink: null, video_id: null, error: st === "failed" ? "x" : null,
      created_at: iso(CLOCK.t - (ageMs || 3600000)), updated_at: iso(CLOCK.t - (ageMs || 3600000)), published_at: st === "published" ? iso(CLOCK.t - (ageMs || 3600000)) : null });
  }
}
const CAPTION = "Spring cakes, baked fresh every morning. #bakery";
function photoPayload(rows, over) {
  return Object.assign({ kind: rows.length === 1 ? "image" : "carousel", items: rows.map(function (r) { return { id: r.id, sha256: r.sha256, bytes: r.bytes, alt: r.alt_text }; }),
    caption: CAPTION, ig_user_id: IG_ID }, over || {});
}
function reelPayload(v, over) {
  return Object.assign({ kind: "reel", video: { id: v.id, sha256: v.sha256, bytes: Number(v.bytes), mime: v.mime }, caption: CAPTION, ig_user_id: IG_ID }, over || {});
}
function proposalOf(payload) {
  return { id: uuid(), user_id: USER, action_type: "publish_instagram_post", status: "executing", payload: payload };
}
function libDeps(db, ig, extra) {
  CURRENT = ig;
  return Object.assign({ supabase: db, storage: db.storage, crypt: CRYPT, jsonRequest: ig.jsonRequest,
    now: function () { return CLOCK.t; }, sleep: function (ms) { CLOCK.t += ms; CLOCK.slept += ms; return Promise.resolve(); },
    config: function () { return IA.configured(CONFIGURED); }, limits: LIMITS, claims: claimsStub, base: BASE }, extra || {});
}
function accessOf(row) { try { return CRYPT.decrypt({ ciphertext: row.access_ciphertext, iv: row.access_iv, authTag: row.access_auth_tag }); } catch (e) { return null; } }
async function flush() { for (let i = 0; i < 80; i++) await new Promise(function (r) { setImmediate(r); }); }
function stripComments(src) { return String(src).replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, ""); }
function postOf(db, proposalId) { return db.t.instagram_posts.filter(function (r) { return r.proposal_id === proposalId; })[0]; }
function connOf(db) { return db.t.member_instagram_connections.filter(function (r) { return r.user_id === USER; })[0]; }
function fresh(opts) {
  const db = makeDb();
  const ig = makeInstagram(Object.assign({ db: db }, opts || {}));
  return { db: db, ig: ig, deps: libDeps(db, ig) };
}

/* ── the page ────────────────────────────────────────────────────────────── */
function runPage(search, answers, marker, extra) {
  const dom = { els: {}, fetches: [], events: [], innerHTML: [], assigned: [], session: {} };
  if (marker) dom.session.bf_oauth_return = marker;
  function node(tag) {
    const n = { tagName: String(tag).toUpperCase(), children: [], _t: "", className: "", hidden: false, disabled: false, value: "", checked: false, type: "", id: "",
      attrs: {}, listeners: {}, src: "", alt: "", href: "", target: "", rel: "", width: 0, height: 0, loading: "",
      appendChild: function (c) { this.children.push(c); c.parentNode = this; return c; },
      removeChild: function (c) { this.children = this.children.filter(function (x) { return x !== c; }); return c; },
      setAttribute: function (k, v) { this.attrs[k] = String(v); },
      addEventListener: function (t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
      fire: function (t) { (this.listeners[t] || []).forEach(function (f) { f({}); }); },
      click: function () { this.fire("click"); } };
    Object.defineProperty(n, "firstChild", { get: function () { return this.children[0] || null; } });
    Object.defineProperty(n, "textContent", { get: function () { return this._t + this.children.map(function (c) { return c.textContent; }).join(""); },
      set: function (v) { this._t = String(v); this.children = []; } });
    Object.defineProperty(n, "innerHTML", { get: function () { return this._t; }, set: function (v) { dom.innerHTML.push(String(v)); this._t = String(v); this.children = []; } });
    if (n.tagName === "SELECT") {
      Object.defineProperty(n, "options", { get: function () { return this.children; } });
      Object.defineProperty(n, "value", { get: function () { const s = this.children.filter(function (c) { return c.selected; })[0]; return s ? s.value : ""; },
        set: function (v) { this.children.forEach(function (c) { c.selected = c.value === v && !c.disabled; }); } });
    }
    return n;
  }
  const document = { readyState: "complete", addEventListener: function () {},
    getElementById: function (id) { if (!dom.els[id]) { dom.els[id] = node(id === "igVideo" ? "select" : "div"); dom.els[id].id = id; } return dom.els[id]; },
    createElement: node, createTextNode: function (s) { return { tagName: "#text", children: [], textContent: String(s) }; } };
  dom.get = function (id) { return document.getElementById(id); };
  const location = { search: search, assign: function (u) { dom.assigned.push(u); } };
  const window = { location: location, history: { replaceState: function (s, t, u) { dom.events.push("replaceState:" + u); } } };
  if (extra && extra.picker) window.BFMediaPicker = { open: function () { return Promise.resolve(extra.picker.shift()); } };
  function fetch(url, init) {
    const p = String(url).replace(/^https:\/\/[^/]+/, "");
    const method = (init && init.method) || "GET";
    dom.fetches.push({ path: p, method: method, body: init && init.body ? JSON.parse(init.body) : undefined });
    dom.events.push("fetch:" + method + " " + p);
    const a = answers(p, method);
    if (a === "reject") return Promise.reject(new Error("offline"));
    return Promise.resolve({ ok: a.status < 300, status: a.status, json: function () { return Promise.resolve(a.body); } });
  }
  const sessionStorage = { getItem: function (k) { return Object.prototype.hasOwnProperty.call(dom.session, k) ? dom.session[k] : null; },
    setItem: function (k, v) { dom.session[k] = String(v); }, removeItem: function (k) { delete dom.session[k]; } };
  const ctx = { document: document, localStorage: { getItem: function () { return "tok"; } }, sessionStorage: sessionStorage, fetch: fetch, URLSearchParams: URLSearchParams,
    encodeURIComponent: encodeURIComponent, console: { log: function () {}, error: function () {}, warn: function () {} }, Promise: Promise, JSON: JSON, String: String,
    Array: Array, Date: Date, Math: Math, Number: Number, Error: Error, Object: Object };
  window.document = document;
  vm.createContext(ctx);
  ctx.window = new Proxy(window, { get: function (t, k) { return k in t ? t[k] : ctx[k]; }, set: function (t, k, v) { t[k] = v; return true; } });
  vm.runInContext(FILES.oauth, ctx, { filename: "scripts/oauth-return.js" });
  vm.runInContext(FILES.ui, ctx, { filename: "scripts/instagram.js" });
  dom.window = window;
  return dom;
}
function findAll(root, pred, out) {
  out = out || [];
  if (!root) return out;
  if (pred(root)) out.push(root);
  (root.children || []).forEach(function (c) { findAll(c, pred, out); });
  return out;
}
const STATUS_CONNECTED = { instagram_available: true, connected: true, status: "connected", username: USERNAME, account_type: "BUSINESS", since: "2026-11-01T10:00:00.000Z", reconnect_message: null };
function pageAnswers(over) {
  const map = Object.assign({
    "GET /api/instagram/status": { status: 200, body: STATUS_CONNECTED },
    "GET /api/instagram/posts": { status: 200, body: { posts: [], note: "To remove an Instagram post, delete it in the Instagram app." } },
    "POST /api/instagram/finish": { status: 200, body: STATUS_CONNECTED },
    "POST /api/instagram/start": { status: 200, body: { authorize_url: "https://www.instagram.com/oauth/authorize?client_id=1&state=x" } },
    "GET /api/videos": { status: 200, body: { videos: [] } },
    "POST /api/instagram/propose-post": { status: 201, body: { note: "Filed for approval. Nothing has been sent to Instagram." } }
  }, over || {});
  return function (p, method) { return map[method + " " + p] || { status: 404, body: { error: "no answer" } }; };
}

(async function main() {
  OUT("checkInstagramPosting: Instagram posting (migration 179)" + (MUTATE ? "" : ""));
  check("the Instagram section and the 04:45 chain of server.js were found", IG_SECTION.length > 5000 && CRON_SECTION.length > 500, J([IG_SECTION.length, CRON_SECTION.length]));

  /* ── O ── */
  OUT("\n══ O. connect ══");
  let m = mountRoutes({ env: CONFIGURED });
  EV.length = 0;
  const st = await begin(m);
  const stRow = m.db.t.oauth_states[0];
  const params = st.url ? Array.from(st.url.searchParams.keys()).join(",") : "";
  check("O1. start: exactly Instagram's authorize page, with client_id, redirect_uri, response_type=code, both scopes and a 43-character state; no-store",
    !!st.url && st.url.origin + st.url.pathname === "https://www.instagram.com/oauth/authorize" && params === "client_id,redirect_uri,response_type,scope,state" &&
    st.url.searchParams.get("client_id") === APP.id && st.url.searchParams.get("redirect_uri") === REDIRECT && st.url.searchParams.get("response_type") === "code" &&
    st.url.searchParams.get("scope") === "instagram_business_basic,instagram_business_content_publish" && /^[A-Za-z0-9_-]{43}$/.test(st.state || "") &&
    st.r.headers["Cache-Control"] === "no-store", st.url ? st.url.href.replace(st.state, "STATE") : J(st.r));
  check("O2. ...only the state's sha256 is stored, purpose instagram_login, no verifier, expiring in 10 minutes",
    !!stRow && stRow.purpose === "instagram_login" && stRow.state_hash === sha(st.state) && J(m.db.t.oauth_states).indexOf(st.state) === -1 &&
    stRow.verifier_ciphertext === undefined && Math.abs(Date.parse(stRow.expires_at) - Date.parse(stRow.created_at) - 600000) < 5, J(stRow));
  let fin = await hit(m, "post /api/instagram/finish", { body: { code: CODE, state: st.state } });
  const c1 = connOf(m.db);
  const tc = m.ig.tokenCalls[0] || {}, lc = m.ig.longCalls[0] || {};
  check("O3. finish: the code exchanged by a form POST with the app's id and secret, the exact redirect URI and grant type",
    fin.status === 200 && tc.keys === "client_id,client_secret,code,grant_type,redirect_uri" && tc.client_id === APP.id && tc.secret_ok && tc.grant_type === "authorization_code" &&
    tc.redirect_uri === REDIRECT && tc.code === CODE && /^application\/x-www-form-urlencoded/.test(tc.formType || ""), J([fin.status, fin.body, tc]));
  check("O4. ...the short-lived token swapped at once for the long-lived one (ig_exchange_token, with the secret); the stored token is the long-lived one, sealed; the short one is never stored",
    lc.grant_type === "ig_exchange_token" && lc.secret_ok && lc.short_ok && !!c1 && accessOf(c1) === LONG && J(m.db.t).indexOf(SHORT) === -1 && J(m.db.t).indexOf(LONG) === -1,
    J([lc, c1 && accessOf(c1) === SHORT ? "short stored" : "-"]));
  const order = ["ig:token", "ig:long", "encrypt:long", "ig:me", "db:member_instagram_connections:upsert"].map(function (e) { return EV.indexOf(e); });
  check("O5. ...sealed BEFORE Instagram is asked who the account is (/me with the long-lived token), and the row written last",
    order.every(function (x) { return x !== -1; }) && order.every(function (x, i) { return i === 0 || x > order[i - 1]; }) && m.ig.meBearer === LONG &&
    EV.filter(function (e) { return e === "ig:me"; }).length === 1, J(EV));
  check("O6. ...the row: ig_user_id from /me, the username, BUSINESS, version 0, connected, both scopes; the answer never carries a token",
    !!c1 && c1.ig_user_id === IG_ID && c1.username === USERNAME && c1.account_type === "BUSINESS" && c1.token_version === 0 && c1.status === "connected" &&
    c1.granted_scopes === "instagram_business_basic,instagram_business_content_publish" && fin.body.connected === true && fin.body.username === USERNAME &&
    noSecretIn(J(fin.body)) && Object.keys(fin.body).sort().join() === "account_type,connected,instagram_available,reconnect_message,since,status,username", J(fin.body));
  const again = await hit(m, "post /api/instagram/finish", { body: { code: CODE, state: st.state } });
  check("O7. the same state again: 400 state_invalid, Instagram not asked", again.status === 400 && again.body.code === "state_invalid" && m.ig.tokenCalls.length === 1, J([again.status, again.body, m.ig.tokenCalls.length]));
  m = mountRoutes({ env: CONFIGURED, ig: { accountType: "PERSONAL" } });
  let cn = await connect(m);
  check("O8. a personal account: 422 with the plain words, nothing saved", cn.f.status === 422 && cn.f.body.code === "personal_account" &&
    cn.f.body.error === "Instagram posting works with Business and Creator accounts. You can switch to one for free in the Instagram app's settings. Nothing was saved." &&
    m.db.t.member_instagram_connections.length === 0, J([cn.f.status, cn.f.body]));
  m = mountRoutes({ env: CONFIGURED, ig: { accountType: "MEDIA_CREATOR", wrapped: true } });
  cn = await connect(m);
  check("O9. a Creator account, with the exchange answered inside data[0]: connected", cn.f.status === 200 && connOf(m.db) && connOf(m.db).account_type === "MEDIA_CREATOR", J([cn.f.status, cn.f.body]));
  m = mountRoutes({ env: CONFIGURED, ig: { permissions: ["instagram_business_basic"] } });
  cn = await connect(m);
  check("O10. publishing not granted: 422 no_scopes, the long-lived exchange never made, nothing saved", cn.f.status === 422 && cn.f.body.code === "no_scopes" &&
    m.ig.longCalls.length === 0 && m.db.t.member_instagram_connections.length === 0, J([cn.f.status, cn.f.body]));
  m = mountRoutes({ env: CONFIGURED, ig: { exchange: "invalid" } });
  cn = await connect(m);
  const badCode = cn.f;
  m = mountRoutes({ env: CONFIGURED, ig: { longLived: "down" } });
  cn = await connect(m);
  check("O11. a refused code: 400; the long-lived exchange down: 502 unreachable; nothing saved either way, and no secret in any log line",
    badCode.status === 400 && badCode.body.code === "state_invalid" && cn.f.status === 502 && cn.f.body.code === "unreachable" && m.db.t.member_instagram_connections.length === 0 &&
    LOGS.every(noSecretIn), J([badCode.status, cn.f.status, cn.f.body]));
  const badShape = await hit(m, "post /api/instagram/finish", { body: { code: "a b", state: "short" } });
  check("O12. an incomplete finish body: 400 bad_request, Instagram not asked", badShape.status === 400 && badShape.body.code === "bad_request");
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  m.db.t.oauth_states.push({ id: uuid(), user_id: USER, purpose: "instagram_login", state_hash: "a".repeat(64), expires_at: iso(Date.now() + 60000), created_at: iso(Date.now()), consumed_at: null });
  m.db.t.oauth_states.push({ id: uuid(), user_id: USER, purpose: "youtube_google", state_hash: "b".repeat(64), verifier_ciphertext: "ab", verifier_iv: "0".repeat(24), verifier_auth_tag: "0".repeat(32), expires_at: iso(Date.now() + 60000), created_at: iso(Date.now()), consumed_at: null });
  const stat = await hit(m, "get /api/instagram/status", {});
  check("O13. status: connected, the username and type; never a token or ciphertext", stat.status === 200 && stat.body.connected === true && stat.body.instagram_available === true &&
    J(stat.body).indexOf("cipher") === -1 && J(stat.body).indexOf("access") === -1, J(stat.body));
  m.routes = mountRoutes({ db: m.db, env: {} }).routes;
  const disc = await hit(m, "post /api/instagram/disconnect", {});
  check("O14. disconnect, even unconfigured: the row and only Instagram's sign-in states deleted (another platform's kept), the note word for word",
    disc.status === 200 && disc.body.removed === true && m.db.t.member_instagram_connections.length === 0 &&
    J(m.db.t.oauth_states.map(function (r) { return r.purpose; })) === J(["youtube_google"]) &&
    disc.body.note === "Disconnected. To remove BizForce from your Instagram account too, open Instagram's settings, then Apps and websites.", J([disc.status, disc.body]));
  m = mountRoutes({ env: {} });
  const un = [];
  for (const k of ["post /api/instagram/start", "post /api/instagram/finish", "post /api/instagram/propose-post", "post /api/instagram/draft-caption", "get /api/instagram/posts", "get /api/instagram/posts/:id/status"]) {
    un.push(await hit(m, k, { body: { code: CODE, state: "S".repeat(43), idea: "cakes" }, params: { id: uuid() } }));
  }
  const unStat = await hit(m, "get /api/instagram/status", {});
  check("O15. unconfigured: every route but status and disconnect answers 503 \"Instagram connection isn't set up yet.\"; status says instagram_available false",
    un.every(function (r) { return r.status === 503 && r.body.error === NOT_SET_UP && r.body.code === "not_configured"; }) && unStat.status === 200 && unStat.body.instagram_available === false &&
    m.ig.requests.length === 0, J(un.map(function (r) { return r.status; })));
  const mw = function (k) { return (m.routes[k] || { middleware: [] }).middleware; };
  check("O16. connect, propose and draft need an active subscription; status, disconnect and the posts list need only sign-in",
    ["post /api/instagram/start", "post /api/instagram/finish", "post /api/instagram/propose-post", "post /api/instagram/draft-caption"].every(function (k) { return mw(k)[1] === requireActiveSubscription; }) &&
    ["get /api/instagram/status", "post /api/instagram/disconnect", "get /api/instagram/posts", "get /api/instagram/posts/:id/status"].every(function (k) { return mw(k).length === 1 && mw(k)[0] === requireAuth; }) &&
    mw("post /api/instagram/start")[2] === mw("post /api/instagram/finish")[2] && mw("post /api/instagram/start")[2].limiter.max === 10 &&
    mw("post /api/instagram/propose-post")[2].limiter.max === 30 && mw("post /api/instagram/draft-caption")[2] === aiLimiter);

  /* ── T ── */
  OUT("\n══ T. tokens ══");
  const now = CLOCK.t;
  check("T1. refreshDue: inside the 10-day window AND stored a day ago; not 11 days out, not an hour after it was stored, not once expired",
    IA.refreshDue({ access_expires_at: iso(now + 9 * DAY), updated_at: iso(now - 2 * DAY) }, now) === true &&
    IA.refreshDue({ access_expires_at: iso(now + 11 * DAY), updated_at: iso(now - 2 * DAY) }, now) === false &&
    IA.refreshDue({ access_expires_at: iso(now + 9 * DAY), updated_at: iso(now - 3600000) }, now) === false &&
    IA.refreshDue({ access_expires_at: iso(now - 1000), updated_at: iso(now - 2 * DAY) }, now) === false &&
    IA.REFRESH_WINDOW_MS === 10 * DAY && IA.REFRESH_MIN_AGE_MS === DAY);
  let f = fresh();
  let conn = seedConnection(f.db, { access_expires_at: iso(now + 5 * DAY), updated_at: iso(now - 2 * DAY) });
  let got = await attempt(IG.accessToken(f.deps, conn));
  let stored = connOf(f.db);
  check("T2. a due token: refreshed (ig_refresh_token), the new one sealed, version + 1, a new expiry; the call uses it",
    got.ok && got.v.token === LONG2 && f.ig.refreshCalls.length === 1 && f.ig.refreshCalls[0].grant_type === "ig_refresh_token" && f.ig.refreshCalls[0].token === LONG &&
    accessOf(stored) === LONG2 && stored.token_version === 1 && Date.parse(stored.access_expires_at) > now + 50 * DAY && J(f.db.t).indexOf(LONG2) === -1, got.ok ? J(stored) : got.msg);
  f = fresh();
  conn = seedConnection(f.db, { access_expires_at: iso(now + 5 * DAY), updated_at: iso(now - 3600000) });
  got = await attempt(IG.accessToken(f.deps, conn));
  check("T3. stored an hour ago: not refreshed yet, the token used as it is", got.ok && got.v.token === LONG && f.ig.refreshCalls.length === 0, got.ok ? J(f.ig.refreshCalls) : got.msg);
  f = fresh();
  conn = seedConnection(f.db, { access_expires_at: iso(now + 50 * DAY), updated_at: iso(now - 20 * DAY) });
  got = await attempt(IG.accessToken(f.deps, conn));
  check("T4. 50 days left: not refreshed", got.ok && f.ig.refreshCalls.length === 0);
  f = fresh();
  conn = seedConnection(f.db, { access_expires_at: iso(now + 5 * DAY), updated_at: iso(now - 2 * DAY) });
  f.ig.opts.onRefresh = function () { const r = connOf(f.db); const w = seal(WINNER); Object.assign(r, { access_ciphertext: w.ciphertext, access_iv: w.iv, access_auth_tag: w.authTag, token_version: 1 }); };
  got = await attempt(IG.accessToken(f.deps, conn));
  stored = connOf(f.db);
  check("T5. a race lost (another refresh wrote first): nothing more written, the winner's token used", got.ok && got.v.token === WINNER && accessOf(stored) === WINNER && stored.token_version === 1,
    got.ok ? J([got.v.token === LONG2 ? "ours" : "-", stored.token_version, accessOf(stored) === LONG2 ? "overwrote" : "-"]) : got.msg);
  f = fresh();
  conn = seedConnection(f.db, { access_expires_at: iso(now + 5 * DAY), updated_at: iso(now - 2 * DAY) });
  const both = await Promise.all([attempt(IG.accessToken(f.deps, conn)), attempt(IG.accessToken(f.deps, conn))]);
  check("T6. two calls at once: ONE refresh", both.every(function (x) { return x.ok && x.v.token === LONG2; }) && f.ig.refreshCalls.length === 1, J([f.ig.refreshCalls.length]));
  f = fresh();
  conn = seedConnection(f.db, { access_expires_at: iso(now - 1000) });
  got = await attempt(IG.accessToken(f.deps, conn));
  const got2 = await attempt(IG.accessToken(f.deps, connOf(f.db)));
  await attempt(IG.markNeedsReconnect(f.deps, conn, "expired"));
  check("T7. expired: needs_reconnect and ONE notice (instagram_reconnect), however often it is seen", !got.ok && got.kind === "auth" && !got2.ok && connOf(f.db).status === "needs_reconnect" &&
    f.db.t.notifications.length === 1 && f.db.t.notifications[0].type === "instagram_reconnect" && f.ig.requests.length === 0, J([got.kind, f.db.t.notifications.length]));
  f = fresh({ refresh: "invalid" });
  conn = seedConnection(f.db, { access_expires_at: iso(now + 5 * DAY), updated_at: iso(now - 2 * DAY) });
  got = await attempt(IG.accessToken(f.deps, conn));
  const refusedOk = !got.ok && got.kind === "auth" && connOf(f.db).status === "needs_reconnect" && f.db.t.notifications.length === 1;
  f = fresh({ refresh: "down" });
  conn = seedConnection(f.db, { access_expires_at: iso(now + 5 * DAY), updated_at: iso(now - 2 * DAY) });
  got = await attempt(IG.accessToken(f.deps, conn));
  const downOk = got.ok && got.v.token === LONG && connOf(f.db).status === "connected";
  f = fresh({ refresh: "limited" });
  conn = seedConnection(f.db, { access_expires_at: iso(now + 5 * DAY), updated_at: iso(now - 2 * DAY) });
  got = await attempt(IG.accessToken(f.deps, conn));
  check("T8. a refused refresh: needs_reconnect with one notice; Instagram down, or a rate limit (400, typed OAuthException): the current token used, still connected, no notice",
    refusedOk && downOk && got.ok && got.v.token === LONG && connOf(f.db).status === "connected" && f.db.t.notifications.length === 0, J([refusedOk, downOk, got.ok ? got.v.token === LONG : got.msg]));
  f = fresh();
  const dueRow = seedConnection(f.db, { access_expires_at: iso(now + 5 * DAY), updated_at: iso(now - 2 * DAY) });
  const expRow = seedConnection(f.db, { user_id: OTHER, ig_user_id: IG_ID2, access_expires_at: iso(now - 1000) });
  const otherUser = "00000000-0000-4000-8000-000000000003";
  seedConnection(f.db, { user_id: otherUser, ig_user_id: "17841400000000003", access_expires_at: iso(now + 50 * DAY) });
  const tick = await IG.refreshTick(f.deps, now);
  const tick2 = await IG.refreshTick(f.deps, now);
  const jr = f.db.t.job_runs.filter(function (r) { return r.job_name === "instagram_token_refresh"; });
  check("T9. the daily job: claimed through job_runs instagram_token_refresh, a due token refreshed, an expired one marked to reconnect, the rest left; once a day",
    tick.claimed === true && tick.refreshed === 1 && tick.expired === 1 && accessOf(f.db.t.member_instagram_connections.filter(function (r) { return r.id === dueRow.id; })[0]) === LONG2 &&
    f.db.t.member_instagram_connections.filter(function (r) { return r.id === expRow.id; })[0].status === "needs_reconnect" && f.ig.refreshCalls.length === 1 &&
    jr.length === 1 && !!jr[0].finished_at && tick2.claimed === false, J([tick, tick2]));
  f = fresh();
  f.deps.config = function () { return null; };
  const tick3 = await IG.refreshTick(f.deps, now);
  check("T10. ...unconfigured: claimed and skipped, Instagram never asked", tick3.skipped === "not_configured" && f.ig.requests.length === 0, J(tick3));
  const orderRun = [];
  const scheduled = [];
  const cronMod = { main: null };
  cronMod.main = cronMod;
  const cctx = {
    require: Object.assign(function (r) {
      if (r === "./lib/microsoftAuth") return { oauthStatesPurgeTick: async function () { orderRun.push("states"); } };
      if (r === "./lib/shopifyAuth") return { webhookEventsPurgeTick: async function () { orderRun.push("shopify"); } };
      throw new Error("unexpected require " + r);
    }, { main: cronMod }),
    module: cronMod,
    cron: { schedule: function (spec, fn, o) { scheduled.push({ spec: spec, fn: fn, tz: o && o.timezone }); } },
    cardLeads: { cardLeadsPurgeTick: async function () { orderRun.push("leads"); }, PURGE_JOB_NAME: "card_leads_purge" },
    supabase: {}, videoRetentionTick: async function () { orderRun.push("videos"); }, instagramRefreshTick: async function () { orderRun.push("instagram"); }, console: console
  };
  vm.createContext(cctx);
  let cronOk = true;
  try { vm.runInContext(CRON_SECTION + "\n  }\n", cctx, { filename: "server.js (04:45 chain)" }); } catch (e) { cronOk = false; }
  if (scheduled[0]) { scheduled[0].fn(); await flush(); }
  check("T11. the 04:45 UTC chain runs instagramRefreshTick last, after the video retention", cronOk && scheduled.length === 1 && scheduled[0].tz === "UTC" &&
    J(orderRun) === J(["leads", "states", "shopify", "videos", "instagram"]), J(orderRun));
  m = mountRoutes({ env: CONFIGURED });
  const rt = await attempt(m.ctx.instagramRefreshTick());
  check("T12. instagramRefreshTick runs lib/instagramApi.js refreshTick on instagramDeps() and never rejects", rt.ok && rt.v && rt.v.claimed === true &&
    m.db.t.job_runs.filter(function (r) { return r.job_name === "instagram_token_refresh"; }).length === 1, rt.ok ? J(rt.v) : rt.msg);
  f = fresh({ reject: [LONG] });
  conn = seedConnection(f.db);
  const me = await attempt(IG.readMe(f.deps, LONG));
  const ph = seedPhoto(f.db, jpeg(3000, 1));
  const refusedRun = await attempt(IG.executePublish(f.deps, proposalOf(photoPayload([ph]))));
  check("T13. a token Instagram refuses on a call: needs_reconnect with its notice, and the post says to reconnect", !me.ok && me.kind === "auth" && !refusedRun.ok &&
    /stopped accepting/.test(refusedRun.msg) && connOf(f.db).status === "needs_reconnect" && f.db.t.notifications.length === 1, J([me.kind, refusedRun.msg]));

  /* ── F ── */
  OUT("\n══ F. filing ══");
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db, {}, Date.now());
  const p1 = seedPhoto(m.db, jpeg(3000, 2));
  let r = await hit(m, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: [p1.id], caption: "  " + CAPTION + " " } });
  const prop1 = m.db.t.agent_proposals[0];
  check("F1. one JPEG: 201, a pending publish_instagram_post for Instagram, not reversible; kind image with the photo's id, fingerprint, size and alt text; the caption trimmed",
    r.status === 201 && !!prop1 && prop1.status === "pending" && prop1.action_type === "publish_instagram_post" && prop1.target === "instagram" && prop1.reversible === false &&
    J(prop1.payload) === J({ kind: "image", items: [{ id: p1.id, sha256: p1.sha256, bytes: p1.bytes, alt: p1.alt_text }], caption: CAPTION, ig_user_id: IG_ID }) &&
    prop1.title.indexOf("Post to Instagram as @maplestreet (1 photo): ") === 0, J([r.status, r.body, prop1 && prop1.payload]));
  check("F2. ...never automatic: nothing sent to Instagram, no instagram_posts row; the note says so",
    m.ig.requests.length === 0 && m.db.t.instagram_posts.length === 0 && /Nothing has been sent to Instagram/.test(r.body.note || "") &&
    /To remove an Instagram post, delete it in the Instagram app\./.test(r.body.note || ""), J([m.ig.requests.length, m.db.t.instagram_posts.length]));
  const ten = [];
  for (let i = 0; i < 11; i++) ten.push(seedPhoto(m.db, jpeg(2500 + i, 10 + i)));
  r = await hit(m, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: ten.slice(0, 10).map(function (x) { return x.id; }), caption: CAPTION } });
  const carousel = m.db.t.agent_proposals[m.db.t.agent_proposals.length - 1];
  check("F3. ten photos: a carousel of 10", r.status === 201 && carousel.payload.kind === "carousel" && carousel.payload.items.length === 10, J([r.status, r.body]));
  const readsBefore = m.storage.calls.filter(function (c) { return c.op === "download"; }).length;
  r = await hit(m, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: ten.map(function (x) { return x.id; }), caption: CAPTION } });
  check("F4. eleven: 400 with the items rule, on media_ids, before any photo is read", r.status === 400 && r.body.field === "media_ids" &&
    r.body.error === IG.MESSAGES.items + " Nothing was filed." && m.storage.calls.filter(function (c) { return c.op === "download"; }).length === readsBefore, J([r.status, r.body]));
  r = await hit(m, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: [p1.id, p1.id], caption: CAPTION } });
  const dup = r;
  r = await hit(m, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: [], caption: CAPTION } });
  check("F5. the same photo twice, or none: 400", dup.status === 400 && r.status === 400);
  const pngRow = seedPhoto(m.db, png(3000, 3), { mime: "image/png" });
  const pngAsJpeg = seedPhoto(m.db, png(3000, 4));
  const mpoRow = seedPhoto(m.db, mpo(3000, 5));
  const rPng = await hit(m, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: [pngRow.id], caption: CAPTION } });
  const rPngBytes = await hit(m, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: [pngAsJpeg.id], caption: CAPTION } });
  const rMpo = await hit(m, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: [mpoRow.id], caption: CAPTION } });
  check("F6. JPEG only: a PNG row, PNG bytes under a JPEG row, and an MPO are each refused (400 not_jpeg, the plain words with the photo's name)",
    [rPng, rPngBytes, rMpo].every(function (x) { return x.status === 400 && x.body.code === "not_jpeg" && x.body.error.indexOf("Instagram accepts JPEG photos only. Choose a JPEG photo. (") === 0; }),
    J([rPng.status, rPng.body.code, rPngBytes.status, rPngBytes.body.code, rMpo.status, rMpo.body.code]));
  check("F7. isInstagramJpeg: a plain JPEG yes; PNG, MPO, JPS and too-short no", IG.isInstagramJpeg(jpeg(500, 6)) === true && IG.isInstagramJpeg(png(500, 6)) === false &&
    IG.isInstagramJpeg(mpo(500, 6)) === false && IG.isInstagramJpeg(Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe3, 0x00, 0x0c]), Buffer.from("_JPSJPS_", "latin1"), Buffer.alloc(2), Buffer.from([0xff, 0xda])])) === false &&
    IG.isInstagramJpeg(Buffer.from([0xff, 0xd8])) === false);
  const otherPhoto = seedPhoto(m.db, jpeg(3000, 7), { user_id: OTHER });
  r = await hit(m, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: [otherPhoto.id], caption: CAPTION } });
  check("F8. another member's photo: 404, as if it were not there", r.status === 404 && r.body.code === "not_found");
  const vMp4 = seedVideo(m.db, mp4(5000, 8));
  const vMov = seedVideo(m.db, mp4(5000, 9), { mime: "video/quicktime" });
  const vWebm = seedVideo(m.db, mp4(5000, 10), { mime: "video/webm" });
  r = await hit(m, "post /api/instagram/propose-post", { body: { kind: "reel", video_id: vMp4.id, caption: CAPTION } });
  const reelProp = m.db.t.agent_proposals[m.db.t.agent_proposals.length - 1];
  const rMov = await hit(m, "post /api/instagram/propose-post", { body: { kind: "reel", video_id: vMov.id, caption: CAPTION } });
  const rWebm = await hit(m, "post /api/instagram/propose-post", { body: { kind: "reel", video_id: vWebm.id, caption: CAPTION } });
  const rAgain = await hit(m, "post /api/instagram/propose-post", { body: { kind: "reel", video_id: vMp4.id, caption: CAPTION } });
  check("F9. a Reel: MP4 and MOV filed with the video's fingerprint frozen; WebM refused (400 reel_type); a second pending Reel of one video: 409",
    r.status === 201 && J(reelProp.payload) === J({ kind: "reel", video: { id: vMp4.id, sha256: vMp4.sha256, bytes: vMp4.bytes, mime: "video/mp4" }, caption: CAPTION, ig_user_id: IG_ID }) &&
    rMov.status === 201 && rWebm.status === 400 && rWebm.body.code === "reel_type" && rWebm.body.error === "Instagram Reels need an MP4 or MOV video. Nothing was filed." &&
    rAgain.status === 409 && rAgain.body.code === "pending", J([r.status, rMov.status, rWebm.status, rWebm.body.code, rAgain.status]));
  const cap = function (caption) { return hit(m, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: [p1.id], caption: caption } }); };
  const tags = function (n) { return Array.from({ length: n }, function (_, i) { return "#tag" + i; }).join(" "); };
  const ats = function (n) { return Array.from({ length: n }, function (_, i) { return "@friend" + i; }).join(" "); };
  const cLong = await cap("a".repeat(2201)), cMax = await cap("a".repeat(2200)), c31 = await cap(tags(31)), c30 = await cap(tags(30)), c21 = await cap(ats(21)), c20 = await cap(ats(20));
  const cEmail = await cap("Write to cakes@" + "example.com " + ats(20));
  const cClaims = await cap("Guaranteed fresh.");
  check("F10. the caption: at most 2200 characters, 30 hashtags and 20 @mentions (an email address is not a mention); the claims screen (422)",
    cLong.status === 400 && cLong.body.field === "caption" && cMax.status === 201 && c31.status === 400 && c30.status === 201 && c21.status === 400 && c20.status === 201 &&
    cEmail.status === 201 && cClaims.status === 422 && cClaims.body.code === "claims", J([cLong.status, cMax.status, c31.status, c30.status, c21.status, c20.status, cEmail.status, cClaims.status]));
  const mc = mountRoutes({ env: CONFIGURED });
  seedConnection(mc.db, {}, Date.now());
  const pc = seedPhoto(mc.db, jpeg(3000, 11));
  CLOCK.t = Date.now();
  seedPosts(mc.db, 10, "failed");
  const rFailedOnly = await hit(mc, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: [pc.id], caption: CAPTION } });
  seedPosts(mc.db, 9, "processing");
  const rUnder = await hit(mc, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: [pc.id], caption: CAPTION } });
  seedPosts(mc.db, 1, "published");
  const rCap = await hit(mc, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: [pc.id], caption: CAPTION } });
  CLOCK.t = now;
  check("F11. 10 posts in 24 hours: the 11th refused (409 daily_cap); failed ones don't count", rFailedOnly.status === 201 && rUnder.status === 201 && rCap.status === 409 &&
    rCap.body.code === "daily_cap" && rCap.body.error === "You can post to Instagram 10 times in 24 hours. Nothing was sent. Try again later.", J([rFailedOnly.status, rUnder.status, rCap.status]));
  const mn = mountRoutes({ env: CONFIGURED });
  const rNone = await hit(mn, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: [p1.id], caption: CAPTION } });
  seedConnection(mn.db, { status: "needs_reconnect" }, Date.now());
  const rRe = await hit(mn, "post /api/instagram/propose-post", { body: { kind: "photos", media_ids: [p1.id], caption: CAPTION } });
  const rKind = await hit(m, "post /api/instagram/propose-post", { body: { kind: "story", caption: CAPTION } });
  check("F12. not connected, needs reconnecting, or no kind: refused, nothing filed", rNone.status === 409 && rNone.body.code === "not_connected" && rRe.status === 409 &&
    rRe.body.code === "needs_reconnect" && rKind.status === 400 && rKind.body.field === "kind" && mn.db.t.agent_proposals.length === 0);
  check("F13. the generic proposals route refuses publish_instagram_post; it is subscription-gated; its executor is registered",
    FILES.server.indexOf("if (actionType === \"publish_instagram_post\") {\n      return res.status(400).json({\n        error: \"An Instagram post cannot be filed here.") !== -1 &&
    /const SUBSCRIPTION_GATED_PROPOSAL_ACTIONS = \[[^\]]*"publish_instagram_post"\];/.test(FILES.server) &&
    (/\n  publish_instagram_post: (\w+),\n/.exec(FILES.server) || [])[1] === "executePublishInstagramPost" &&
    /async function executePublishInstagramPost\(proposal\) \{\n  return require\("\.\/lib\/instagramApi"\)\.executePublish\(instagramDeps\(\), proposal\);\n\}/.test(IG_SECTION));
  check("F14. the three platform executors each go to their own dispatcher", (/\n  publish_youtube_video: (\w+),\n/.exec(FILES.server) || [])[1] === "executePublishYoutubeVideo" &&
    (/\n  publish_tiktok_post: (\w+),\n/.exec(FILES.server) || [])[1] === "executePublishTiktokPost" &&
    (/\n  publish_instagram_post: (\w+),\n/.exec(FILES.server) || [])[1] === "executePublishInstagramPost");
  const GR = realRequire("./lib/gateRules");
  check("F15. gateRules: publish_instagram_post known, channel instagram", GR.ACTION_TYPES.indexOf("publish_instagram_post") !== -1 && GR.CHANNELS.indexOf("instagram") !== -1 &&
    GR.channelFor("publish_instagram_post") === "instagram");
  const md = mountRoutes({ env: CONFIGURED });
  r = await hit(md, "post /api/instagram/draft-caption", { body: { idea: "spring cakes" } });
  check("F16. draft-caption: the idea goes to the model, the caption measured in code, nothing filed or sent", r.status === 200 && r.body.draft.caption === "Spring cakes, baked fresh every morning. #bakery #cakes" &&
    r.body.measured.caption.hashtags === 2 && r.body.measured.caption.limit === 2200 && r.body.within_limits === true && md.db.t.agent_proposals.length === 0 && md.ig.requests.length === 0 &&
    md.prompts.length === 1 && md.prompts[0].indexOf("\"spring cakes\"") !== -1, J([r.status, r.body]));

  /* ── U ── */
  OUT("\n══ U. the post ══");
  f = fresh();
  seedConnection(f.db);
  let photo = seedPhoto(f.db, jpeg(3000, 20));
  let prop = proposalOf(photoPayload([photo]));
  EV.length = 0;
  let run = await attempt(IG.executePublish(f.deps, prop));
  let row = postOf(f.db, prop.id);
  const c0 = f.ig.containers[f.ig.order[0]] || { form: {} };
  check("U1. a photo: the instagram_posts row is written BEFORE any container (status creating at Instagram's first step)",
    !!f.ig.atFirstContainer && f.ig.atFirstContainer.posts.length === 1 && f.ig.atFirstContainer.posts[0].proposal_id === prop.id && f.ig.atFirstContainer.posts[0].status === "creating" &&
    EV.indexOf("db:instagram_posts:insert") !== -1 && EV.indexOf("db:instagram_posts:insert") < EV.indexOf("ig:container:IMAGE"), J(EV));
  check("U2. ...the container: the photo's public address, the caption and its alt text", c0.form.image_url === MM.publicUrlFor(photo.path, BASE) && c0.form.caption === CAPTION &&
    c0.form.alt_text === photo.alt_text && Object.keys(c0.form).sort().join() === "alt_text,caption,image_url", J(c0.form));
  check("U3. ...the bytes read and checked right before the container, then status, the limit, ONE publish, the permalink; recorded published",
    run.ok && run.v.published === true && EV.indexOf("storage:read:" + photo.path) !== -1 && EV.lastIndexOf("storage:read:" + photo.path) < EV.indexOf("ig:container:IMAGE") &&
    EV.indexOf("ig:limit") < EV.indexOf("ig:publish") && f.ig.publishes.length === 1 && !!row && row.status === "published" && /^\d+$/.test(row.media_id || "") &&
    /^https:\/\/www\.instagram\.com\/p\//.test(row.permalink || "") && run.v.note === "To remove an Instagram post, delete it in the Instagram app.", run.ok ? J([run.v, EV]) : run.msg);
  const replay = await attempt(IG.executePublish(f.deps, prop));
  check("U4. the same proposal again: already published, nothing sent", replay.ok && replay.v.already_published === true && f.ig.publishes.length === 1 && f.ig.containerPosts().length === 1);
  f = fresh();
  seedConnection(f.db);
  photo = seedPhoto(f.db, jpeg(3000, 21));
  prop = proposalOf(photoPayload([photo]));
  f.db.storage.objects["bf-public/" + photo.path] = { buf: jpeg(3000, 99) };
  run = await attempt(IG.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  check("U5. the photo's bytes changed after filing: refused before any container, the row failed with the plain words", !run.ok && run.msg.indexOf(IG.MESSAGES.fingerprint) !== -1 &&
    f.ig.containerPosts().length === 0 && !!row && row.status === "failed" && row.error === IG.MESSAGES.fingerprint, run.ok ? J(run.v) : run.msg);
  f = fresh();
  seedConnection(f.db);
  photo = seedPhoto(f.db, jpeg(3000, 22));
  f.db.t.member_media[0].mime = "image/png";
  prop = proposalOf(photoPayload([photo]));
  run = await attempt(IG.executePublish(f.deps, prop));
  check("U6. a photo no longer JPEG by its row: refused before the row is written", !run.ok && run.msg.indexOf(IG.MESSAGES.jpegOnly) !== -1 && f.db.t.instagram_posts.length === 0 && f.ig.requests.length === 0, run.msg);
  f = fresh();
  seedConnection(f.db);
  const cps = [seedPhoto(f.db, jpeg(3000, 23)), seedPhoto(f.db, jpeg(3100, 24), { alt_text: "" }), seedPhoto(f.db, jpeg(3200, 25))];
  prop = proposalOf(photoPayload(cps));
  EV.length = 0;
  run = await attempt(IG.executePublish(f.deps, prop));
  const kids = f.ig.order.slice(0, 3).map(function (id) { return f.ig.containers[id]; });
  const parent = f.ig.containers[f.ig.order[3]] || { form: {} };
  const ev = EV.filter(function (e) { return /^storage:read:|^ig:container:/.test(e); }).map(function (e) { return e.indexOf("storage:read:") === 0 ? "read" : e.slice(13); });
  check("U7. a carousel: each photo read right before ITS child container (alt text on each), then the parent with the children in order",
    run.ok && J(ev) === J(["read", "child", "read", "child", "read", "child", "CAROUSEL"]) && kids.every(function (k, i) { return k && k.form.is_carousel_item === "true" && k.form.alt_text === cps[i].alt_text; }) &&
    parent.form.media_type === "CAROUSEL" && parent.form.children === f.ig.order.slice(0, 3).join(",") && parent.form.caption === CAPTION && postOf(f.db, prop.id).container_id === f.ig.order[3],
    run.ok ? J(ev) : run.msg);
  const statusOrder = f.ig.statusCalls().map(function (c) { return c.path.split("/").pop(); });
  check("U8. ...the children polled first, then the parent; ONE publish of the parent", J(statusOrder.slice(0, 4)) === J(f.ig.order.slice(0, 4)) && J(f.ig.publishes) === J([f.ig.order[3]]), J(statusOrder));
  f = fresh();
  seedConnection(f.db);
  const cps2 = [seedPhoto(f.db, jpeg(3000, 26)), seedPhoto(f.db, jpeg(3100, 27))];
  f.db.storage.objects["bf-public/" + cps2[1].path] = { buf: jpeg(3100, 98) };
  prop = proposalOf(photoPayload(cps2));
  run = await attempt(IG.executePublish(f.deps, prop));
  check("U9. ...the second photo changed: the first child made, then refused before the second; no parent, nothing published, the row failed",
    !run.ok && run.msg.indexOf(IG.MESSAGES.fingerprint) !== -1 && f.ig.containerPosts().length === 1 && f.ig.publishes.length === 0 && postOf(f.db, prop.id).status === "failed", run.ok ? J(run.v) : run.msg);
  f = fresh();
  seedConnection(f.db);
  let vid = seedVideo(f.db, mp4(6000, 30));
  prop = proposalOf(reelPayload(vid));
  EV.length = 0;
  LOGS.length = 0;
  run = await attempt(IG.executePublish(f.deps, prop));
  const sign = f.db.storage.calls.filter(function (c) { return c.op === "sign"; });
  const reelC = f.ig.containers[f.ig.order[0]] || { form: {} };
  check("U10. a Reel: the file streamed and hashed, THEN one signed link for 7200 seconds, used only as the container's video_url",
    run.ok && sign.length === 1 && sign[0].seconds === 7200 && sign[0].path === vid.path && EV.indexOf("storage:stream") < EV.indexOf("storage:sign:7200") &&
    EV.indexOf("storage:sign:7200") < EV.indexOf("ig:container:REELS") && reelC.form.media_type === "REELS" && reelC.form.share_to_feed === "true" &&
    (reelC.form.video_url || "").indexOf(SIGNED_MARK) !== -1 && reelC.form.caption === CAPTION, run.ok ? J([sign, reelC.form.media_type]) : run.msg);
  check("U11. ...the signed link is never stored, logged or returned", J(f.db.t).indexOf(SIGNED_MARK) === -1 && LOGS.every(function (l) { return l.indexOf(SIGNED_MARK) === -1; }) &&
    J(run.ok ? run.v : run.msg).indexOf(SIGNED_MARK) === -1 && postOf(f.db, prop.id).video_id === vid.id && postOf(f.db, prop.id).status === "published");
  f = fresh();
  seedConnection(f.db);
  vid = seedVideo(f.db, mp4(6000, 31));
  f.db.storage.objects["bf-video/" + vid.path] = { buf: mp4(6000, 97) };
  prop = proposalOf(reelPayload(vid));
  run = await attempt(IG.executePublish(f.deps, prop));
  check("U12. the video's bytes changed: refused before any signed link or container", !run.ok && run.msg.indexOf(IG.MESSAGES.fingerprint) !== -1 &&
    f.db.storage.calls.filter(function (c) { return c.op === "sign"; }).length === 0 && f.ig.containerPosts().length === 0, run.ok ? J(run.v) : run.msg);
  f = fresh({ seq: Array(200).fill("IN_PROGRESS") });
  seedConnection(f.db);
  vid = seedVideo(f.db, mp4(6000, 32));
  prop = proposalOf(reelPayload(vid));
  const t0 = CLOCK.t;
  CLOCK.slept = 0;
  run = await attempt(IG.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  check("U13. still processing after 60 seconds: { processing: true } with the plain words; polled every 5 seconds, never past 60; the row processing with its container",
    run.ok && run.v.processing === true && run.v.note === IG.MESSAGES.processing && CLOCK.slept <= 60000 && CLOCK.slept >= 50000 && CLOCK.t - t0 <= 60000 &&
    f.ig.statusCalls().length >= 11 && f.ig.statusCalls().length <= 13 && f.ig.publishes.length === 0 && row.status === "processing" && row.container_id === f.ig.order[0],
    run.ok ? J([run.v, CLOCK.slept, f.ig.statusCalls().length]) : run.msg);
  f.ig.containers[f.ig.order[0]].seq = [];
  const rerun = await attempt(IG.executePublish(f.deps, prop));
  check("U14. the same proposal run again once it's ready: no second container, the stored one published once", rerun.ok && rerun.v.published === true && f.ig.containerPosts().length === 1 &&
    J(f.ig.publishes) === J([f.ig.order[0]]) && postOf(f.db, prop.id).status === "published", rerun.ok ? J(rerun.v) : rerun.msg);
  f = fresh({ seq: ["IN_PROGRESS", "ERROR"] });
  seedConnection(f.db);
  photo = seedPhoto(f.db, jpeg(3000, 33));
  prop = proposalOf(photoPayload([photo]));
  run = await attempt(IG.executePublish(f.deps, prop));
  const errRow = postOf(f.db, prop.id);
  f = fresh({ seq: ["EXPIRED"] });
  seedConnection(f.db);
  photo = seedPhoto(f.db, jpeg(3000, 34));
  const prop2 = proposalOf(photoPayload([photo]));
  const run2 = await attempt(IG.executePublish(f.deps, prop2));
  check("U15. ERROR or EXPIRED while waiting: the row failed with Instagram's words, nothing published", !run.ok && errRow.status === "failed" &&
    errRow.error === "Instagram couldn't publish it: Error: the video format is not supported." && !run2.ok && postOf(f.db, prop2.id).status === "failed" &&
    postOf(f.db, prop2.id).error === "Instagram couldn't publish it (expired)." && f.ig.publishes.length === 0, J([errRow.error, postOf(f.db, prop2.id).error]));
  f = fresh({ seq: ["FINISHED", "EXPIRED"] });
  seedConnection(f.db);
  photo = seedPhoto(f.db, jpeg(3000, 35));
  prop = proposalOf(photoPayload([photo]));
  run = await attempt(IG.executePublish(f.deps, prop));
  check("U16. the status read again right before publishing: EXPIRED by then, so failed and NOT published", !run.ok && f.ig.publishes.length === 0 && postOf(f.db, prop.id).status === "failed",
    run.ok ? J(run.v) : run.msg);
  f = fresh({ usage: 100 });
  seedConnection(f.db);
  photo = seedPhoto(f.db, jpeg(3000, 36));
  prop = proposalOf(photoPayload([photo]));
  run = await attempt(IG.executePublish(f.deps, prop));
  check("U17. Instagram's own publishing limit used up: failed with the plain words, nothing published", !run.ok && run.msg.indexOf(IG.MESSAGES.limitReached) !== -1 &&
    f.ig.publishes.length === 0 && postOf(f.db, prop.id).error === IG.MESSAGES.limitReached, run.ok ? J(run.v) : run.msg);
  f = fresh();
  seedConnection(f.db);
  photo = seedPhoto(f.db, jpeg(3000, 37));
  seedPosts(f.db, 10, "published");
  prop = proposalOf(photoPayload([photo]));
  run = await attempt(IG.executePublish(f.deps, prop));
  check("U18. ten posts in 24 hours at approval: refused before the row, nothing sent", !run.ok && run.msg.indexOf(IG.MESSAGES.dailyCap) !== -1 && !postOf(f.db, prop.id) && f.ig.containerPosts().length === 0,
    run.ok ? J(run.v) : run.msg);
  f = fresh();
  seedConnection(f.db, { ig_user_id: IG_ID2 });
  photo = seedPhoto(f.db, jpeg(3000, 38));
  prop = proposalOf(photoPayload([photo]));
  run = await attempt(IG.executePublish(f.deps, prop));
  check("U19. a different Instagram account connected now: refused, nothing sent", !run.ok && run.msg.indexOf(IG.MESSAGES.accountChanged) !== -1 && f.ig.requests.length === 0 && f.db.t.instagram_posts.length === 0);
  f = fresh({ containerError: "The aspect ratio is not supported." });
  seedConnection(f.db);
  photo = seedPhoto(f.db, jpeg(3000, 39));
  prop = proposalOf(photoPayload([photo]));
  run = await attempt(IG.executePublish(f.deps, prop));
  check("U20. Instagram refuses the container (an OAuthException-typed content error): the row failed with Instagram's words; the account stays connected, no notice", !run.ok && postOf(f.db, prop.id).status === "failed" &&
    connOf(f.db).status === "connected" && f.db.t.notifications.length === 0 &&
    postOf(f.db, prop.id).error === "Instagram refused the post: The aspect ratio is not supported. Nothing was published.", J(postOf(f.db, prop.id)));
  // the answer to the publish is lost, though Instagram published it
  f = fresh({ publishLost: 1 });
  seedConnection(f.db);
  photo = seedPhoto(f.db, jpeg(3000, 40));
  prop = proposalOf(photoPayload([photo]));
  run = await attempt(IG.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  f.db.t.agent_proposals.push({ id: prop.id, user_id: USER, action_type: "publish_instagram_post", status: "executed", payload: prop.payload });
  CLOCK.t += 3 * 60 * 1000;
  let ps = await attempt(IG.postStatus(f.deps, USER, row.id));
  check("U21. the publish answer lost: processing; then \"Check status\" finds Instagram says PUBLISHED and records the post from the account's media by its caption, with NO second publish",
    run.ok && run.v.processing === true && ps.ok && ps.v.status === 200 && ps.v.body.status === "published" && f.ig.publishes.length === 1 &&
    postOf(f.db, prop.id).media_id === f.ig.media[0].id && /fields=id,timestamp,caption&limit=10/.test(f.ig.listSearch || ""), ps.ok ? J([run.v, ps.v, f.ig.publishes.length]) : ps.msg);
  f = fresh({ publishLost: 1 });
  seedConnection(f.db);
  photo = seedPhoto(f.db, jpeg(3000, 41));
  prop = proposalOf(photoPayload([photo]));
  run = await attempt(IG.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  f.db.t.agent_proposals.push({ id: prop.id, user_id: USER, action_type: "publish_instagram_post", status: "executed", payload: Object.assign({}, prop.payload, { caption: "A different caption" }) });
  CLOCK.t += 3 * 60 * 1000;
  ps = await attempt(IG.postStatus(f.deps, USER, row.id));
  check("U22. ...PUBLISHED but no media with that caption: failed with the plain words, never published again", ps.ok && ps.v.body.status === "failed" &&
    ps.v.body.error === "Instagram shows this post as published. Open Instagram to see it." && f.ig.publishes.length === 1, ps.ok ? J(ps.v) : ps.msg);
  // two status checks at once on a slow post
  f = fresh({ seq: Array(20).fill("IN_PROGRESS"), lagging: true });
  seedConnection(f.db);
  photo = seedPhoto(f.db, jpeg(3000, 42));
  prop = proposalOf(photoPayload([photo]));
  run = await attempt(IG.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  f.db.t.agent_proposals.push({ id: prop.id, user_id: USER, action_type: "publish_instagram_post", status: "executed", payload: prop.payload });
  f.ig.containers[row.container_id].seq = [];
  CLOCK.t += 10 * 60 * 1000;
  const pair = await Promise.all([attempt(IG.postStatus(f.deps, USER, row.id)), attempt(IG.postStatus(f.deps, USER, row.id))]);
  const codes = pair.map(function (x) { return x.ok ? x.v.status : 0; }).sort().join();
  check("U23. two \"Check status\" at once on a ready post: claimed by one (compare-and-set), ONE publish; the other answers 409 busy",
    f.ig.publishes.length === 1 && codes === "200,409" && postOf(f.db, prop.id).status === "published", J([f.ig.publishes.length, codes]));
  f = fresh({ seq: Array(20).fill("IN_PROGRESS") });
  seedConnection(f.db);
  photo = seedPhoto(f.db, jpeg(3000, 43));
  prop = proposalOf(photoPayload([photo]));
  run = await attempt(IG.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  f.db.t.agent_proposals.push({ id: prop.id, user_id: USER, action_type: "publish_instagram_post", status: "executed", payload: prop.payload });
  f.ig.containers[row.container_id].seq = [];
  CLOCK.t += 30 * 1000;
  ps = await attempt(IG.postStatus(f.deps, USER, row.id));
  check("U24. a post touched under 2 minutes ago: left alone (409 busy), nothing published", ps.ok && ps.v.status === 409 && ps.v.body.code === "busy" && f.ig.publishes.length === 0, ps.ok ? J(ps.v) : ps.msg);
  f = fresh();
  seedConnection(f.db);
  seedPosts(f.db, 1, "creating", 2 * 3600000);
  ps = await attempt(IG.postStatus(f.deps, USER, f.db.t.instagram_posts[0].id));
  const otherPs = await attempt(IG.postStatus(f.deps, OTHER, f.db.t.instagram_posts[0].id));
  check("U25. a row stuck creating an hour on: failed with the plain words; another member's id: 404", ps.ok && ps.v.body.status === "failed" && ps.v.body.error === IG.MESSAGES.stale &&
    f.db.t.instagram_posts[0].status === "failed" && otherPs.ok && otherPs.v.status === 404, ps.ok ? J(ps.v) : ps.msg);
  check("U26. a member is never shown a container id, media id or proposal", J(ps.ok ? ps.v.body : {}).indexOf("container") === -1 && J(ps.ok ? ps.v.body : {}).indexOf("proposal") === -1 &&
    Object.keys(IG.postView(f.db.t.instagram_posts[0])).sort().join() === "created_at,error,id,kind,permalink,published_at,status");
  const ms = mountRoutes({ env: CONFIGURED });
  seedConnection(ms.db, {}, Date.now());
  const sp = seedPhoto(ms.db, jpeg(3000, 44));
  CLOCK.t = Date.now();
  const sprop = proposalOf(photoPayload([sp]));
  const viaServer = await attempt(ms.ctx.executePublishInstagramPost(sprop));
  check("U27. the server's executor runs lib/instagramApi.js executePublish on instagramDeps() (the photo's address on SUPABASE_URL)", viaServer.ok && viaServer.v.published === true &&
    (ms.ig.containers[ms.ig.order[0]] || { form: {} }).form.image_url === MM.publicUrlFor(sp.path, BASE), viaServer.ok ? J(viaServer.v) : viaServer.msg);
  CLOCK.t = now;

  /* ── L ── */
  OUT("\n══ L. the lifecycle ══");
  let db = makeDb();
  const ytTt = seedVideo(db, mp4(4000, 50), { youtube_video_id: "Ab3_x-9Kq2Z", uploaded_at: iso(now - 3600000), tiktok_status: "posted", tiktok_posted_at: iso(now - 600000) });
  const all3 = seedVideo(db, mp4(4000, 51), { youtube_video_id: "Ab3_x-9Kq2Y", uploaded_at: iso(now - 3600000), tiktok_status: "posted", tiktok_posted_at: iso(now - 600000) });
  const igBusy = seedVideo(db, mp4(4000, 52), { youtube_video_id: "Ab3_x-9Kq2X", uploaded_at: iso(now - 3600000), tiktok_status: "posted", tiktok_posted_at: iso(now - 600000) });
  db.t.instagram_posts.push({ id: uuid(), user_id: USER, proposal_id: uuid(), kind: "reel", status: "published", media_id: "18000000000000001", published_at: iso(now - 600000), video_id: all3.id, created_at: iso(now - 700000), updated_at: iso(now - 600000) });
  db.t.instagram_posts.push({ id: uuid(), user_id: USER, proposal_id: uuid(), kind: "reel", status: "published", media_id: "18000000000000002", published_at: iso(now - 600000), video_id: igBusy.id, created_at: iso(now - 700000), updated_at: iso(now - 600000) });
  db.t.instagram_posts.push({ id: uuid(), user_id: USER, proposal_id: uuid(), kind: "reel", status: "processing", container_id: "17900000000000001", video_id: igBusy.id, created_at: iso(now - 300000), updated_at: iso(now - 300000) });
  const oldIg = seedVideo(db, mp4(4000, 53), { created_at: iso(now - 15 * DAY) });
  db.t.instagram_posts.push({ id: uuid(), user_id: USER, proposal_id: uuid(), kind: "reel", status: "published", media_id: "18000000000000003", published_at: iso(now - 14 * DAY), video_id: oldIg.id, created_at: iso(now - 14 * DAY), updated_at: iso(now - 14 * DAY) });
  const tickV = await MV.retentionTick({ supabase: db, storage: db.storage, now: function () { return now; } }, now);
  const vrow = function (id) { return db.t.member_videos.filter(function (x) { return x.id === id; })[0]; };
  check("L1. retention: YouTube and TikTok have it but Instagram doesn't: the file kept", !!db.storage.objects["bf-video/" + ytTt.path] && vrow(ytTt.id).status === "ready", J(tickV));
  check("L2. ...all three have it: the file deleted at once, status uploaded", !db.storage.objects["bf-video/" + all3.path] && vrow(all3.id).status === "uploaded" && vrow(all3.id).path === null);
  check("L3. ...an Instagram post of it still processing: kept", !!db.storage.objects["bf-video/" + igBusy.path] && vrow(igBusy.id).status === "ready");
  check("L4. ...14 days on, a published Reel counts as a platform that got it (uploaded, not removed)", vrow(oldIg.id).status === "uploaded" && vrow(oldIg.id).path === null, J(vrow(oldIg.id)));
  db = makeDb();
  const holdV = seedVideo(db, mp4(4000, 54));
  db.t.instagram_posts.push({ id: uuid(), user_id: USER, proposal_id: uuid(), kind: "reel", status: "creating", video_id: holdV.id, created_at: iso(now), updated_at: iso(now) });
  const delHold = await MV.deleteVideo({ supabase: db, storage: db.storage }, USER, holdV.id);
  const namedV = seedVideo(db, mp4(4000, 55));
  db.t.agent_proposals.push({ id: uuid(), user_id: USER, action_type: "publish_instagram_post", status: "pending", payload: reelPayload(namedV) });
  const delNamed = await MV.deleteVideo({ supabase: db, storage: db.storage }, USER, namedV.id);
  check("L5. deleting a video: refused while an Instagram post of it is sending (409 instagram_publishing) or a pending Instagram proposal names it (409 in_proposal)",
    delHold.status === 409 && delHold.body.code === "instagram_publishing" && !!db.storage.objects["bf-video/" + holdV.path] && delNamed.status === 409 && delNamed.body.code === "in_proposal" &&
    !!db.storage.objects["bf-video/" + namedV.path], J([delHold, delNamed]));
  db = makeDb();
  const lib = seedPhoto(db, jpeg(3000, 60));
  const lib2 = seedPhoto(db, jpeg(3000, 61));
  const lib3 = seedPhoto(db, jpeg(3000, 62));
  db.t.agent_proposals.push({ id: uuid(), user_id: USER, action_type: "publish_instagram_post", status: "pending", payload: photoPayload([lib]) });
  const liveProp = { id: uuid(), user_id: USER, action_type: "publish_instagram_post", status: "executed", payload: photoPayload([lib2]) };
  db.t.agent_proposals.push(liveProp);
  db.t.instagram_posts.push({ id: uuid(), user_id: USER, proposal_id: liveProp.id, kind: "image", status: "processing", container_id: "17900000000000002", created_at: iso(now), updated_at: iso(now) });
  const doneProp = { id: uuid(), user_id: USER, action_type: "publish_instagram_post", status: "executed", payload: photoPayload([lib3]) };
  db.t.agent_proposals.push(doneProp);
  db.t.instagram_posts.push({ id: uuid(), user_id: USER, proposal_id: doneProp.id, kind: "image", status: "published", media_id: "18000000000000009", published_at: iso(now), created_at: iso(now), updated_at: iso(now) });
  const u1 = await attempt(MM.findUses(db, USER, lib.path, BASE));
  const u2 = await attempt(MM.findUses(db, USER, lib2.path, BASE));
  const u3 = await attempt(MM.findUses(db, USER, lib3.path, BASE));
  const isIg = function (x) { return x.ok && x.v.some(function (u) { return u.place === "An Instagram post waiting for approval or still publishing" && u.title === "Instagram"; }); };
  check("L6. the Media Library: a photo in a pending Instagram post, or one Instagram is still fetching, is in use (so not deleted); a published one is not",
    isIg(u1) && isIg(u2) && u3.ok && !isIg(u3), J([u1.ok ? u1.v : u1.msg, u2.ok ? u2.v : u2.msg, u3.ok ? u3.v : u3.msg]));
  check("L7. FILE_ACTIONS and namesVideo know the Instagram post (payload.video.id)", MV.namesVideo(reelPayload(namedV), namedV.id) === true && MV.INSTAGRAM_HOLDING.join() === "creating,processing");

  /* ── P ── */
  OUT("\n══ P. the pages ══");
  const LINES = [
    "<p class=\"bsky-quiet\">Connect your own Instagram account and prepare a post: photos from your Media Library, or a Reel from Your videos. Nothing goes to Instagram until you approve it on the proposals page.</p>",
    "<p class=\"bsky-quiet\">Instagram posting works with Business and Creator accounts. You can switch to one for free in the Instagram app's settings.</p>",
    "<p class=\"bsky-quiet\">Photos must be JPEG. Reels must be MP4 or MOV.</p>",
    "<p class=\"bsky-quiet\">To remove an Instagram post, delete it in the Instagram app.</p>",
    "<p class=\"bsky-warn\" id=\"igUnavailable\" hidden>Instagram connection isn't set up yet.</p>"];
  check("P1. the Social page: the Instagram panel's lines word for word, and the scripts in order (oauth-return, youtube, tiktok, instagram)",
    LINES.every(function (l) { return FILES.page.split(l).length === 2; }) && FILES.page.indexOf("id=\"igConnect\"") !== -1 &&
    FILES.page.indexOf("<script src=\"/scripts/oauth-return.js\"></script>\n<script src=\"/scripts/youtube.js\"></script>\n<script src=\"/scripts/tiktok.js\"></script>\n<script src=\"/scripts/instagram.js\"></script>") !== -1);
  check("P2. the other-platforms line: Facebook still coming, Instagram connectable below", FILES.page.indexOf("<p class=\"bsky-quiet\" id=\"bskyOtherPlatforms\">X, LinkedIn and Facebook are coming, through each platform's own sign-in. Instagram can be connected below, and every Instagram post waits for your approval.</p>") !== -1);
  let dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers(), "instagram");
  await flush();
  const finCall = dom.fetches.filter(function (x) { return x.path === "/api/instagram/finish"; })[0];
  const finIdx = dom.events.indexOf("fetch:POST /api/instagram/finish"), rsIdx = dom.events.indexOf("replaceState:" + PAGE_PATH);
  check("P3. back from Instagram (marker instagram): code and state POSTed to finish, then the query stripped, the marker cleared, \"Connected.\"",
    !!finCall && J(finCall.body) === J({ code: CODE, state: "S".repeat(43) }) && finIdx !== -1 && rsIdx > finIdx && dom.session.bf_oauth_return === undefined &&
    dom.get("igConnectMsg").textContent === "Connected." && dom.get("igName").textContent === "Connected as @maplestreet", dom.events.join(","));
  dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers({ "POST /api/instagram/finish": { status: 400, body: { error: "That sign-in link has expired or was already used. Start again." } } }), "instagram");
  await flush();
  check("P4. ...a refused finish: still stripped, the server's words shown", dom.events.indexOf("replaceState:" + PAGE_PATH) !== -1 &&
    dom.get("igConnectMsg").textContent === "That sign-in link has expired or was already used. Start again.");
  dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers(), "tiktok");
  await flush();
  check("P5. TikTok's return (marker tiktok): Instagram neither finishes nor strips it", !dom.fetches.some(function (x) { return x.path === "/api/instagram/finish"; }) &&
    dom.events.indexOf("replaceState:" + PAGE_PATH) === -1);
  dom = runPage("?error=access_denied&state=" + "S".repeat(43), pageAnswers(), "instagram");
  await flush();
  check("P6. cancelled at Instagram: stripped, \"You cancelled the Instagram sign-in.\", no finish", dom.get("igConnectMsg").textContent === "You cancelled the Instagram sign-in." &&
    dom.events.indexOf("replaceState:" + PAGE_PATH) !== -1 && !dom.fetches.some(function (x) { return x.path === "/api/instagram/finish"; }));
  dom = runPage("", pageAnswers({ "GET /api/instagram/status": { status: 200, body: { instagram_available: true, connected: false, status: "not_connected" } },
    "POST /api/instagram/start": { status: 200, body: { authorize_url: "https://evil.example/oauth/authorize?x=1" } } }));
  await flush();
  dom.get("igConnectBtn").click();
  await flush();
  const evilAssigned = dom.assigned.slice();
  dom = runPage("", pageAnswers({ "GET /api/instagram/status": { status: 200, body: { instagram_available: true, connected: false, status: "not_connected" } } }));
  await flush();
  dom.get("igConnectBtn").click();
  await flush();
  check("P7. Connect: only an instagram.com/oauth/authorize address is followed, after the marker is set to instagram", evilAssigned.length === 0 &&
    dom.assigned.length === 1 && dom.assigned[0].indexOf("https://www.instagram.com/oauth/authorize?") === 0 && dom.session.bf_oauth_return === "instagram", J([evilAssigned, dom.assigned]));
  dom = runPage("", pageAnswers({ "GET /api/instagram/status": { status: 200, body: { instagram_available: false, connected: false, status: "not_connected" } } }));
  await flush();
  check("P8. not set up: the not-set-up line shown and Connect disabled", dom.get("igUnavailable").hidden === false && dom.get("igConnectBtn").disabled === true && dom.get("igPrepare").hidden === true);
  const HOSTILE = "<img src=x onerror=alert(1)>";
  dom = runPage("", pageAnswers({ "GET /api/instagram/posts": { status: 200, body: { posts: [
    { id: uuid(), kind: "image", status: "published", permalink: "https://evil.example/p/1", error: null, created_at: "2026-11-07T10:00:00.000Z" },
    { id: uuid(), kind: "reel", status: "published", permalink: "https://www.instagram.com/p/Abc123/", error: null, created_at: "2026-11-07T10:00:00.000Z" },
    { id: uuid(), kind: "carousel", status: "failed", permalink: null, error: HOSTILE, created_at: "2026-11-07T10:00:00.000Z" },
    { id: uuid(), kind: "image", status: "processing", permalink: null, error: null, created_at: "2026-11-07T10:00:00.000Z" }] } } }));
  await flush();
  const links = findAll(dom.get("igPostList"), function (n) { return n.tagName === "A"; });
  const checks = findAll(dom.get("igPostList"), function (n) { return n.tagName === "BUTTON" && n.textContent === "Check status"; });
  check("P9. recent posts: only an www.instagram.com address is a link; an error is text; \"Check status\" only on one still preparing",
    links.length === 1 && links[0].href === "https://www.instagram.com/p/Abc123/" && dom.get("igPostList").textContent.indexOf(HOSTILE) !== -1 && checks.length === 1, J(links.map(function (l) { return l.href; })));
  check("P10. no innerHTML anywhere: nothing set with it in these runs, and instagram.js and oauth-return.js never name it", dom.innerHTML.length === 0 &&
    !/innerHTML/.test(stripComments(FILES.ui)) && !/innerHTML/.test(stripComments(FILES.oauth)));
  const pickJpeg = { item: { id: uuid(), mime: "image/jpeg", url: "https://check.supabase.co/x.jpg", label: "Cakes", alt_text: "Three cakes" } };
  const pickPng = { item: { id: uuid(), mime: "image/png", url: "https://check.supabase.co/x.png", label: "Logo", alt_text: "" } };
  dom = runPage("", pageAnswers(), null, { picker: [pickPng, pickJpeg] });
  await flush();
  dom.get("igAddPhoto").click();
  await flush();
  const pngMsg = dom.get("igPrepareMsg").textContent;
  dom.get("igAddPhoto").click();
  await flush();
  dom.get("igCaption").value = "Spring cakes.";
  dom.get("igFileBtn").click();
  await flush();
  const filed = dom.fetches.filter(function (x) { return x.path === "/api/instagram/propose-post"; })[0];
  check("P11. a PNG picked: refused with the JPEG words; a JPEG: listed with its alt text; filed with exactly what was chosen",
    pngMsg === "Instagram accepts JPEG photos only. Choose a JPEG photo." && dom.get("igPhotoList").textContent.indexOf("Alt text: Three cakes") === -1 &&
    !!filed && J(filed.body) === J({ kind: "photos", caption: "Spring cakes.", media_ids: [pickJpeg.item.id] }), J([pngMsg, filed && filed.body]));
  dom = runPage("", pageAnswers({ "GET /api/videos": { status: 200, body: { videos: [
    { id: uuid(), status: "ready", mime: "video/mp4", bytes: 3000000, label: "Cakes" }, { id: uuid(), status: "ready", mime: "video/webm", bytes: 3000000, label: "Bread" }] } } }));
  await flush();
  dom.get("igKindReel").checked = true;
  dom.get("igKindReel").fire("change");
  await flush();
  const opts = dom.get("igVideo").children;
  check("P12. a Reel: MP4 choosable, a WebM shown but not choosable, with the Reels words", opts.length === 3 && opts[1].disabled === false && opts[2].disabled === true &&
    opts[2].textContent.indexOf("Instagram Reels need an MP4 or MOV video.") !== -1, J(opts.map(function (o) { return [o.textContent, o.disabled]; })));
  // the proposals card
  const fnSrc = function (name) { const a = FILES.proposals.indexOf("function " + name + "("); return a === -1 ? "" : FILES.proposals.slice(a, MUT.braceMatch(FILES.proposals, FILES.proposals.indexOf("{", a))); };
  const kindLine = (/var INSTAGRAM_KIND_WORDS = [^\n]*\n/.exec(FILES.proposals) || [""])[0];
  const pctx = { String: String, Number: Number, Array: Array, Object: Object, isFinite: isFinite, Math: Math, API_URL: "https://api.example", token: "tok" };
  vm.createContext(pctx);
  let cardOk = true;
  try { vm.runInContext([fnSrc("escapeHtml"), fnSrc("youtubeSize"), kindLine, fnSrc("instagramPostPayloadFields"), fnSrc("instagramResultHtml"), fnSrc("fillInstagramVideos")].join("\n"), pctx); } catch (e) { cardOk = false; }
  const card = cardOk ? pctx.instagramPostPayloadFields({ kind: "carousel", items: [{ id: "a\"b", alt: HOSTILE }], caption: HOSTILE + " cakes", ig_user_id: IG_ID }) : "";
  check("P13. the proposal card: every value escaped (the caption, the alt text, the id), the kind in words, the no-removal line", cardOk && card.indexOf("<img src=x") === -1 &&
    card.indexOf("&lt;img src=x onerror=alert(1)&gt; cakes") !== -1 && card.indexOf("Alt text: &lt;img") !== -1 && card.indexOf("data-pf-media-id=\"a&quot;b\"") !== -1 &&
    card.indexOf("a carousel of photos") !== -1 && card.indexOf("To remove an Instagram post, delete it in the Instagram app.") !== -1, card.slice(0, 300));
  const goodRes = cardOk ? pctx.instagramResultHtml({ published: true, permalink: "https://www.instagram.com/p/Abc/" }) : "";
  const badRes = cardOk ? pctx.instagramResultHtml({ published: true, permalink: "javascript:alert(1)" }) : "";
  check("P14. ...the result: only an www.instagram.com address drawn as a link", /href="https:\/\/www\.instagram\.com\/p\/Abc\/"/.test(goodRes) && badRes.indexOf("href=") === -1 && badRes.indexOf("javascript") === -1, badRes);
  check("P15. ...wired: the payload branch, the result branch, and fillInstagramVideos after each render (textContent)",
    FILES.proposals.indexOf("fieldsHtml = instagramPostPayloadFields(p.payload || {});") !== -1 && FILES.proposals.indexOf("execHtml = instagramResultHtml(p.execution_result);") !== -1 &&
    FILES.proposals.indexOf("  fillMailboxReplies(container);\n  fillInstagramVideos(container);\n}") !== -1 && /spot\.textContent = /.test(fnSrc("fillInstagramVideos")));
  const icard = function (name) { return (new RegExp("<p class=\"int-card-name\">" + name + "</p>\\s*<p class=\"int-card-desc\">([^<]*)</p>\\s*<span class=\"int-status\">([^<]*)</span>").exec(FILES.integrations) || []); };
  check("P16. Integrations: Instagram connects on the Social page (Business or Creator, JPEG photos and Reels, approval); Facebook still Removed",
    icard("Instagram")[2] === "On the Social page" && icard("Instagram")[1] === "Connect your own Instagram Business or Creator account on the Social Agent page, through Instagram's own sign-in, and publish the JPEG photos and Reels you approve. Every post waits for your approval." &&
    icard("Facebook")[2] === "Removed", J([icard("Instagram")[2], icard("Facebook")[2]]));
  check("P17. the Content page's intro: Instagram connects on the Social page; Facebook is coming, not connectable",
    FILES.content.indexOf(">Bluesky connects on the Social Agent page, with an app password you make in Bluesky, never your main password. Instagram connects on the Social Agent page too, through Instagram's own sign-in, and every Instagram post waits for your approval. Facebook is coming, through its own sign-in.</p>") !== -1);
  check("P18. the guide: Instagram named as connecting; the guide's false-promise rule no longer refuses Instagram",
    FILES.guide.indexOf("Bluesky, Mastodon, YouTube, TikTok and Instagram connect so far") !== -1 && FILES.guideAsk.indexOf("NAMED (Nov 7 2026, Instagram posting): instagram left this list") !== -1);

  /* ── G ── */
  OUT("\n══ G. legal, yourData, README, registries, the migration ══");
  const PRIVACY = "If you connect your Instagram professional account, BizForce stores your Instagram username and account id and the access Instagram grants BizForce, encrypted, and uses that access only to publish a post when you approve it and to check its status. To publish, BizForce gives Instagram the address of each photo you chose from your Media Library, or a private link to your video that stops working after 2 hours, together with the caption and alt text you approve; BizForce cannot delete an Instagram post, so you delete it in Instagram. You can disconnect at any time, and everything is deleted with your account.";
  const TERMS = "If you post to Instagram through BizForce, you confirm you have the rights to the photos, videos and music and that they follow Instagram's rules.";
  const esc = function (t) { return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); };
  let built = null;
  try { built = LP.buildLegalPages(); } catch (e) { built = null; }
  const bp = built ? built["privacy.html"] : "", bt = built ? built["terms.html"] : "";
  check("G1. the privacy sentence word for word, once, right after TikTok's", LP.INSTAGRAM_PRIVACY_SENTENCE === PRIVACY && bp.split(esc(PRIVACY)).length === 2 &&
    bp.indexOf(esc(LP.TIKTOK_PRIVACY_SENTENCE)) !== -1 && bp.indexOf(esc(LP.TIKTOK_PRIVACY_SENTENCE)) < bp.indexOf(esc(PRIVACY)));
  check("G2. the terms sentence word for word, once, right after TikTok's", LP.INSTAGRAM_TERMS_SENTENCE === TERMS && bt.split(esc(TERMS)).length === 2 &&
    bt.indexOf(esc(LP.TIKTOK_TERMS_SENTENCE)) < bt.indexOf(esc(TERMS)));
  check("G3. privacy.html and terms.html carry both, as built, and Instagram (Meta) is a named third party", FILES.privacy.split(esc(PRIVACY)).length === 2 && FILES.terms.split(esc(TERMS)).length === 2 &&
    FILES.privacy.indexOf(esc("Instagram (Meta) (publishing the posts you approve to your own Instagram account, when you connect it)")) !== -1);
  const LEGAL = realRequire("./lib/legal");
  check("G4. TERMS_VERSION is Nov 7 2026", LEGAL.TERMS_VERSION === "2026-11-07", LEGAL.TERMS_VERSION);
  const YD_IG = (compile(FILES.yourData, "lib/yourData.js", {}).DATA || []).filter(function (e) { return e.table === "instagram_posts"; })[0];
  check("G5. yourData: the connection exported as its username and date only, the posts without ids; Instagram (Meta) a third party; the never-exported lines; the delete order",
    FILES.yourData.indexOf("{ table: \"member_instagram_connections\", group: \"account\",") !== -1 && /table: "member_instagram_connections"[\s\S]*?select: "username, created_at"/.test(FILES.yourData) &&
    /table: "instagram_posts"[\s\S]*?select: "kind, status, permalink, created_at, published_at"/.test(FILES.yourData) &&
    // the id is not exported, so the export pages and tells the posts apart by created_at (with "id" every post after the first would be dropped)
    (YD_IG || {}).key === "created_at" && (YD_IG || {}).select === "kind, status, permalink, created_at, published_at" &&
    FILES.yourData.indexOf("{ name: \"Instagram (Meta)\", for: \"publishing the posts you approve to your own Instagram account, when you connect it\" }") !== -1 &&
    FILES.yourData.indexOf("\"Your Instagram access: stored encrypted; the export shows only your Instagram username and the date you connected.\"") !== -1 &&
    FILES.yourData.indexOf("\"instagram_posts\", \"member_media\", \"member_videos\"") !== -1 &&
    FILES.yourData.indexOf("\"member_tiktok_connections\", \"member_instagram_connections\", \"oauth_states\"") !== -1 &&
    FILES.yourData.indexOf("Sign in with Microsoft, Connect Shopify, Connect YouTube, Connect TikTok and Connect Instagram") !== -1);
  check("G6. schemaCheck knows both tables at 179; the backup leaves the connection out and skips the posts",
    FILES.schema.indexOf("[\"member_instagram_connections\", \"179_instagram_posting.sql\"],") !== -1 && FILES.schema.indexOf("[\"instagram_posts\", \"179_instagram_posting.sql\"],") !== -1 &&
    FILES.backup.indexOf("member_instagram_connections: \"members' Instagram access, sealed; members connect again\",") !== -1 && /\n  instagram_posts: +"/.test(FILES.backup));
  const igs = (FILES.readme.split("## Instagram app setup")[1] || "").split("\n## ")[0];
  check("G7. README: the two env var rows and the Instagram app setup (both scopes, the redirect URI, the secret only on Railway); the refresh job row",
    /\n\| `INSTAGRAM_APP_ID` \| none \| /.test(FILES.readme) && /\n\| `INSTAGRAM_APP_SECRET` \| none \| [^\n]*only on Railway/.test(FILES.readme) &&
    /`instagram_business_basic` and `instagram_business_content_publish`/.test(igs) && igs.indexOf("https://bizforceai.net/agents/social.html") !== -1 && /only on Railway/.test(igs) &&
    FILES.readme.indexOf("| `refreshTick` (`lib/instagramApi.js`)") !== -1);
  check("G8. migration 179: both tables with RLS on and nothing granted; instagram_login in the purpose check and the verifier rule; the publish-once shape",
    FILES.migration.indexOf("ALTER TABLE public.member_instagram_connections ENABLE ROW LEVEL SECURITY;") !== -1 && FILES.migration.indexOf("REVOKE ALL ON public.member_instagram_connections FROM anon, authenticated;") !== -1 &&
    FILES.migration.indexOf("ALTER TABLE public.instagram_posts ENABLE ROW LEVEL SECURITY;") !== -1 && FILES.migration.indexOf("REVOKE ALL ON public.instagram_posts FROM anon, authenticated;") !== -1 &&
    FILES.migration.indexOf("CHECK (purpose IN ('mailbox_microsoft', 'store_shopify', 'youtube_google', 'tiktok_login', 'instagram_login'))") !== -1 &&
    FILES.migration.indexOf("purpose IN ('store_shopify', 'tiktok_login', 'instagram_login')") !== -1 && FILES.migration.indexOf("proposal_id uuid NOT NULL UNIQUE,") !== -1 &&
    FILES.migration.indexOf("CHECK ((status = 'published') = (media_id IS NOT NULL AND published_at IS NOT NULL))") !== -1);
  check("G9. the server's limits: SOCIAL_PLATFORMS.instagram max 2200, 30 hashtags (the check's own copy matches)",
    /\n  instagram: \{\n    label: "Instagram",\n    max: 2200, kind: "hard",\n    truncates_at: 125,\n    hashtag_max: 30, hashtag_practical: 5,/.test(FILES.server));
  check("G10. no emoji in any Instagram file", [FILES.auth, FILES.api, FILES.ui, FILES.oauth, IG_SECTION, FILES.migration].every(function (s) { return !EMOJI.test(s); }));
  check("G11. only INSTAGRAM_APP_ID and INSTAGRAM_APP_SECRET are read for Instagram (and SUPABASE_URL for the photo address)",
    (stripComments(IG_SECTION).match(/process\.env\.[A-Z_]+/g) || []).every(function (x) { return x === "process.env.SUPABASE_URL"; }) &&
    (stripComments(FILES.auth).match(/env\.[A-Z_]+/g) || []).sort().join() === "env.INSTAGRAM_APP_ID,env.INSTAGRAM_APP_ID,env.INSTAGRAM_APP_SECRET,env.INSTAGRAM_APP_SECRET" &&
    !/process\.env/.test(stripComments(FILES.api)));
  const migFiles = fs.readdirSync(path.join(REPO, "supabase", "migrations")).filter(function (x) { return /^\d{3}_.*\.sql$/.test(x); });
  const highest = migFiles.map(function (x) { return Number(x.slice(0, 3)); }).reduce(function (acc, x) { return Math.max(acc, x); }, 0);
  check("R1. 179_instagram_posting.sql is the highest migration and the only 179", highest === 179 && migFiles.filter(function (x) { return /^179_/.test(x); }).join() === "179_instagram_posting.sql", highest);
  check("G12. no secret in any log line of this run", LOGS.every(noSecretIn), J(LOGS.filter(function (l) { return !noSecretIn(l); }).slice(0, 2)));
  check("G13. the network tripwire never fired, and no promise was left rejected", TRIPPED.length === 0 && UNHANDLED.length === 0, J(TRIPPED.concat(UNHANDLED.map(function (e) { return String(e && e.message); }))));

  OUT("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (failures + passes) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
})().catch(function (e) { OUT("    FAIL  the harness stopped: " + ((e && e.stack) || e)); process.exit(1); });
