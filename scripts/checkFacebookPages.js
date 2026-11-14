/* checkFacebookPages: Facebook Pages posting (migration 180). Connect Facebook through Facebook Login (a single-use
   state, no PKCE), the short-lived user token swapped at once for the long-lived one and sealed before Facebook is
   asked anything else; all three permissions required; one Page the member can post to (tasks include CREATE_CONTENT)
   connects at once, several wait for the member's choice (an unfinished choice is deleted after an hour by the 04:45
   chain); filing text, 1 to 10 photos (JPEG, PNG or GIF, never WebP) or one video (MP4 or MOV), never running them;
   and on approval: the facebook_posts row first, every file's fingerprint right before its address is handed over, a
   video by a 2-hour signed link used only in one request body, the row set publishing before the final call, ONE
   final call, and a replay that looks the post up instead of posting again. Removal through approval, once. Then the
   file lifecycle, the library's "in use", the pages, the Instagram 5-hashtag rule, the guide, legal and registries.

   Everything runs offline. lib/facebookAuth.js, lib/facebookApi.js, lib/memberVideos.js, lib/memberMedia.js,
   lib/instagramApi.js, lib/guideAsk.js and lib/guardedFetch.js are loaded from their own source (a mutation edits
   the text first). A fake Facebook answers behind the REAL guarded transport (guardedFetch.createGuardedFetch with a
   stub resolver and request). The database is in memory and enforces migration 180's CHECKs. A clock drives the
   library. A network tripwire fails the run on any socket, DNS question or fetch: no call reaches Meta or Facebook.
   The routes are server.js's own Facebook section, run in a vm. The page is scripts/oauth-return.js and
   scripts/facebook.js in a fake DOM.

   Sections:
     O. connect: start, finish, permissions, Pages, choosing, status, disconnect, the 503, the daily cleanup
     F. filing: propose-post, the photo and video types, 1 to 10, the message, the claims, the cap, never automatic
     U. the post: the row first, publishing before the final call, fingerprints, the signed link, publish once,
        recovery, refusals, removal
     L. the lifecycle: retention, deleting a video, the Media Library's "in use"
     P. the pages: the Social page, the shared return, the chooser, the panel, proposals, integrations, the guide,
        Instagram's hashtag rule
     G. legal, yourData, README, registries, the migration; R1, the highest migration.

   Run: node scripts/checkFacebookPages.js     MUTATE=<name> for one mutation, MUTATE=all for every one. */
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
  // sign-in, permissions, Pages
  "state-reusable": [["server", ".eq(\"purpose\", fa.PURPOSE)\n        .is(\"consumed_at\", null).gt(\"expires_at\", consumedAt)", ".eq(\"purpose\", fa.PURPOSE)\n        .gt(\"expires_at\", consumedAt)"]],
  "short-token-stored": [["server", "        grant = await fa.longLived(config, short.accessToken);\n", "        grant = { accessToken: short.accessToken, expiresIn: 3600 };\n"]],
  "unsealed-before-call": [["server", "      // Sealed first: the long-lived user token is encrypted before Facebook is asked anything else.\n",
    "      await fb.readPermissions(facebookDeps(), grant.accessToken).catch(function () { return null; });\n      // Sealed first: the long-lived user token is encrypted before Facebook is asked anything else.\n"]],
  "scopes-unchecked": [["api", "  if (!FA.grantsAll(granted)) return { status: 422,", "  if (false) return { status: 422,"]],
  "page-without-create-content": [["api", "postable: tasks.indexOf(CREATE_CONTENT) !== -1", "postable: true"]],
  "user-token-kept": [["api", "    user_ciphertext: null, user_iv: null, user_auth_tag: null, user_expires_at: null,\n    status: \"connected\",", "    status: \"connected\","]],
  "foreign-page-chosen": [["api", "  var page = postablePages(got.pages).filter(function (p) { return p.page_id === pageId; })[0];", "  var page = postablePages(got.pages)[0];"]],
  "token-in-pages-list": [["api", "return { page_id: p.page_id, name: p.name }; }); }", "return { page_id: p.page_id, name: p.name, token: p.token }; }); }"]],
  "choice-expiry-ignored": [["api", "  if (FA.choosingExpired(row, deps.now())) {", "  if (false) {"]],
  // NAMED (Nov 14 2026, L1): BEFORE the anchor ended "...facebookChoosingPurgeTick);". AFTER the chain continues with youtubeDataCheckTick, so the
  // anchor ends there; the mutation still takes Facebook's cleanup out of the chain.
  "choosing-never-cleaned": [["server", ".then(instagramRefreshTick).then(facebookChoosingPurgeTick).then(youtubeDataCheckTick)", ".then(instagramRefreshTick).then(youtubeDataCheckTick)"]],
  "choosing-purge-wrong-rows": [["api", ".delete().eq(\"status\", \"choosing\").lt(\"created_at\", cutoff)", ".delete().lt(\"created_at\", cutoff)"]],
  "long-lived-400-refused": [["auth", "if (refusedGrant(j) || status === 401 || (badRequestRefuses && status === 400)) throw", "if (refusedGrant(j) || status === 401 || status === 400) throw"]],
  "disconnect-deletes-all-states": [["server", "var statesDropped = await supabase.from(\"oauth_states\").delete().eq(\"user_id\", req.user.id).eq(\"purpose\", fa.PURPOSE);",
    "var statesDropped = await supabase.from(\"oauth_states\").delete().eq(\"user_id\", req.user.id);"]],
  "unconfigured-not-503": [["server", "  return res.status(503).json({ error: require(\"./lib/facebookAuth\").MESSAGES.notConfigured,", "  return res.status(200).json({ error: require(\"./lib/facebookAuth\").MESSAGES.notConfigured,"]],
  "removal-gated": [["server", "app.post(\"/api/facebook/posts/:id/propose-delete\", requireAuth, facebookProposeLimiter,", "app.post(\"/api/facebook/posts/:id/propose-delete\", requireAuth, requireActiveSubscription, facebookProposeLimiter,"]],
  // filing
  "webp-accepted": [["api", "const PHOTO_MIMES = Object.freeze([\"image/jpeg\", \"image/png\", \"image/gif\"]);", "const PHOTO_MIMES = Object.freeze([\"image/jpeg\", \"image/png\", \"image/gif\", \"image/webp\"]);"]],
  "eleven-photos-accepted": [["api", "value.length > ITEMS_MAX) return { error: MESSAGES.items };", "value.length > ITEMS_MAX + 1) return { error: MESSAGES.items };"]],
  "webm-video-accepted": [["api", "const VIDEO_MIMES = Object.freeze([\"video/mp4\", \"video/quicktime\"]);", "const VIDEO_MIMES = Object.freeze([\"video/mp4\", \"video/quicktime\", \"video/webm\"]);"]],
  "message-unbounded": [["api", "  if (codePoints(message) > MESSAGE_MAX) return { ok: false, error: MESSAGES.message };\n", ""]],
  "claims-skipped": [["api", "  if (refused) return { status: 422,", "  if (false) return { status: 422,"]],
  "facebook-cap-missing": [["api", "  if (await postsToday(deps, userId) >= POSTS_PER_DAY) return { status: 409, body: { error: MESSAGES.dailyCap, code: \"daily_cap\" } };\n", ""]],
  "failed-posts-counted": [["api", ".eq(\"user_id\", userId).neq(\"status\", \"failed\").gte(\"created_at\", since);", ".eq(\"user_id\", userId).gte(\"created_at\", since);"]],
  "auto-executed": [["api", "  if (ins.error) throw ins.error;\n  return { status: 201, body: { proposal: ins.data, page_name:",
    "  if (ins.error) throw ins.error;\n  await executePublish(deps, Object.assign({}, ins.data, { status: \"executing\" })).catch(function () { return null; });\n  return { status: 201, body: { proposal: ins.data, page_name:"]],
  "wrong-dispatcher": [["server", "  publish_facebook_post: executePublishFacebookPost,\n", "  publish_facebook_post: executePublishInstagramPost,\n"]],
  "gate-missing": [["server", "\"publish_instagram_post\", \"publish_facebook_post\"];", "\"publish_instagram_post\"];"]],
  "generic-route-accepts": [["server", "    if (actionType === \"publish_facebook_post\") {\n      return res.status(400)", "    if (false) {\n      return res.status(400)"]],
  // the executor
  "row-after-call": [["api", "  if (!row) {\n    var today;", "  if (!row) row = { id: \"00000000-0000-4000-8000-00000000dead\", status: \"creating\", created_at: nowIso(deps) };\n  if (false) {\n    var today;"]],
  "publishing-not-set": [["api", "      publishingRow = await markPublishing(deps, row);\n      if (!publishingRow) throw new FacebookApiError(\"busy\", \"not_creating\");\n      outcome = finalOutcome(await pagePost(deps, conn, API_BASE + \"/\" + conn.page_id + \"/feed\", { message: msg.message }), \"id\");",
    "      publishingRow = row;\n      outcome = finalOutcome(await pagePost(deps, conn, API_BASE + \"/\" + conn.page_id + \"/feed\", { message: msg.message }), \"id\");"]],
  "sha-unchecked-before-url": [["api", "      await readPhoto(deps, ownerId, mediaRows[p.items[0].id], p.items[0]);\n", ""]],
  "photos-sha-unchecked": [["api", "        await readPhoto(deps, ownerId, mediaRows[it.id], it);\n", ""]],
  "video-sha-unchecked": [["api", "      if (!(await verifyVideo(deps, video, p.video))) throw new FacebookApiError(\"fingerprint\", \"video_sha\");\n", ""]],
  "signed-url-logged": [["api", "      if (link.indexOf(\"https://\") !== 0) throw new FacebookApiError(\"unread\", \"signed_url\");\n",
    "      if (link.indexOf(\"https://\") !== 0) throw new FacebookApiError(\"unread\", \"signed_url\");\n      console.log(\"[facebook] video link \" + link);\n"]],
  "signed-url-long-lived": [["api", "const SIGNED_URL_SECONDS = 7200;", "const SIGNED_URL_SECONDS = 604800;"]],
  "post-twice-on-replay": [
    ["api", "  if (row && row.status === \"publishing\") {", "  if (false) {"],
    ["api", ".eq(\"id\", row.id).eq(\"status\", \"creating\").is(\"post_id\", null).select(POST_COLUMNS);", ".eq(\"id\", row.id).select(POST_COLUMNS);"]],
  "lookup-skipped": [["api", "  if (found) return recordPublished(deps, conn, row, found);\n", ""]],
  "facebook-cap-missing-at-send": [["api", "    if (today >= POSTS_PER_DAY) throw fail(MESSAGES.dailyCap);\n", ""]],
  "page-changed-ignored": [["api", "  if (conn.page_id !== p.page_id) throw fail(MESSAGES.pageChanged);\n", ""]],
  "content-refusal-disconnects": [["api", "  return c === 190 || c === 102 || c === 10 ||", "  return (e && e.type === \"OAuthException\") || c === 190 || c === 102 || c === 10 ||"]],
  "reconnect-notice-repeated": [["api", ".eq(\"id\", row.id).eq(\"user_id\", row.user_id).eq(\"status\", \"connected\").select(\"id\");", ".eq(\"id\", row.id).eq(\"user_id\", row.user_id).select(\"id\");"]],
  "auth-failed-left-publishing": [["api", "      if (publishingRow) await markFailed(deps, publishingRow, MESSAGES.needsReconnect);\n", ""]],
  "relative-permalink-dropped": [["api", "  var p = v.charAt(0) === \"/\" ? PAGE_HOST + v : v;", "  var p = v;"]],
  "delete-twice": [["api", "  if (row.removed_at) throw fail(MESSAGES.alreadyRemoved);\n", ""]],
  "removal-refiled": [["api", "  if (row.removed_at) return { status: 409, body: { error: MESSAGES.alreadyRemoved, code: \"already_removed\" } };\n", ""]],
  "removal-pending-twice": [["api", "  if ((pend.data || []).some(function (pr) { return pr.payload && pr.payload.facebook_post_id === row.id; })) {", "  if (false) {"]],
  // lifecycle
  "file-deleted-before-facebook": [["videos", "      .filter(function (r) { return bothFb.published[r.id] && !bothFb.holding[r.id]; })", "      .filter(function (r) { return !bothFb.holding[r.id]; })"]],
  "delete-while-facebook-holds": [["videos", "  if (fb.holding[row.id]) return { status: 409,", "  if (false) return { status: 409,"]],
  "delete-ignores-facebook-proposal": [["videos", "\"publish_instagram_post\", \"publish_facebook_post\"]);", "\"publish_instagram_post\"]);"]],
  "library-delete-while-posting": [["media", "    if (fbHit) uses.push(", "    if (false) uses.push("]],
  "library-live-post-ignored": [["media", "    var fbLiveIds = (fbLive.data || []).map(function (r) { return r.proposal_id; }).filter(function (pid) { return pid && !fbProposals[pid]; });", "    var fbLiveIds = [];"]],
  // the corrections: Instagram's hashtags, the guide, the pages
  "instagram-six-hashtags": [["igApi", "const HASHTAG_MAX = 5;", "const HASHTAG_MAX = 6;"]],
  "guide-still-unconnectable": [["guideAsk", "(twitter|x|linkedin|pinterest|threads|social)", "(twitter|x|linkedin|pinterest|threads|facebook|social)"]],
  "facebook-still-coming": [["page", "X and LinkedIn are coming, through each platform's own sign-in. Instagram and a Facebook Page can be connected below, and every post to them waits for your approval.",
    "X, LinkedIn and Facebook are coming, through each platform's own sign-in. Instagram can be connected below, and every Instagram post waits for your approval."]],
  "integrations-facebook-removed": [["integrations", "Every post, and every removal, waits for your approval.</p>\n          <span class=\"int-status\">On the Social page</span>",
    "Every post, and every removal, waits for your approval.</p>\n          <span class=\"int-status\">Removed</span>"]],
  "content-facebook-coming": [["content", "A Facebook Page connects there too, through Facebook's own sign-in, and every Facebook post waits for your approval.</p>", "Facebook is coming, through its own sign-in.</p>"]],
  "privacy-sentence-removed": [["legal", "      FACEBOOK_PRIVACY_SENTENCE,\n", ""]],
  "terms-sentence-removed": [["legal", "      INSTAGRAM_TERMS_SENTENCE,\n      FACEBOOK_TERMS_SENTENCE\n", "      INSTAGRAM_TERMS_SENTENCE\n"]],
  "export-key-missing": [["yourData", "owner: [\"user_id\"], key: \"created_at\", select: \"kind, status, permalink, created_at, published_at, removed_at\"", "owner: [\"user_id\"], select: \"kind, status, permalink, created_at, published_at, removed_at\""]],
  // the page and the proposal card
  "innerHTML-on-page": [["ui", "    if (text !== undefined && text !== null) node.textContent = text;", "    if (text !== undefined && text !== null) node.innerHTML = text;"]],
  "foreign-authorize-followed": [["ui", "url.indexOf(AUTH_PREFIX) === 0", "url.indexOf(\"https://\") === 0"]],
  "marker-wrong": [["ui", "returns().mark(\"facebook\")", "returns().mark(\"instagram\")"]],
  "webp-picked": [["ui", "      if (item.mime === \"image/webp\") { tell(\"fbPrepareMsg\", WEBP, true); return; }\n", ""]],
  "webm-choosable": [["ui", "        opt.disabled = !fits;\n", ""]],
  "permalink-unchecked-on-page": [["ui", "typeof p.permalink === \"string\" && PERMALINK_RE.test(p.permalink)) {", "typeof p.permalink === \"string\") {"]],
  "removal-without-confirm": [["ui", "remove.addEventListener(\"click\", function () { confirmBox.hidden = false; remove.disabled = true; });", "remove.addEventListener(\"click\", function () { yes.click(); });"]],
  "card-message-unescaped": [["proposals", "'<pre class=\"exec-block fb-message\">' + escapeHtml(String(payload.message == null ? \"\" : payload.message))",
    "'<pre class=\"exec-block fb-message\">' + String(payload.message == null ? \"\" : payload.message)"]],
  "card-link-unchecked": [["proposals", "/^https:\\/\\/www\\.facebook\\.com\\/[A-Za-z0-9_\\/.?=&%-]{1,270}$/.test(result.permalink) ? result.permalink : null;",
    "/^https:\\/\\/www\\.facebook\\.com\\/[A-Za-z0-9_\\/.?=&%-]{1,270}$/.test(result.permalink) || true ? result.permalink : null;"]]
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
  auth: read("lib/facebookAuth.js"),
  api: read("lib/facebookApi.js"),
  videos: read("lib/memberVideos.js"),
  media: read("lib/memberMedia.js"),
  fetch: read("lib/guardedFetch.js"),
  legal: read("lib/legalPages.js"),
  igApi: read("lib/instagramApi.js"),
  migration: read("supabase/migrations/180_facebook_pages.sql"),
  yourData: read("lib/yourData.js"),
  backup: read("lib/backup.js"),
  schema: read("lib/schemaCheck.js"),
  guideAsk: read("lib/guideAsk.js"),
  appMap: read("lib/appMap.json"),
  readme: read("README.md"),
  privacy: readFe("privacy.html"),
  terms: readFe("terms.html"),
  page: readFe("agents/social.html"),
  content: readFe("agents/content.html"),
  ui: readFe("scripts/facebook.js"),
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
const SECRET_HEX = crypto.createHash("sha256").update("checkFacebookPages").digest("hex");
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
/* The Facebook stub of the moment: every request the libraries make goes to it. */
let CURRENT = null;
const GF_PROXY = { guardedJsonRequest: function (u, o) { return CURRENT.jsonRequest(u, o); } };
const GF = compile(FILES.fetch, "lib/guardedFetch.js", {});
const FA = compile(FILES.auth, "lib/facebookAuth.js", { "./guardedFetch": GF_PROXY });
const MV = compile(FILES.videos, "lib/memberVideos.js", {});
const MM = compile(FILES.media, "lib/memberMedia.js", {});
const FB = compile(FILES.api, "lib/facebookApi.js", { "./facebookAuth": FA, "./memberVideos": MV, "./memberMedia": MM });
const IGA = compile(FILES.igApi, "lib/instagramApi.js", { "./memberVideos": MV, "./memberMedia": MM });
const LP = compile(FILES.legal, "lib/legalPages.js", {});
const GA = compile(FILES.guideAsk, "lib/guideAsk.js", {});

const APP = { id: "2345678901234567", secret: "check-fb-secret-" + "8".repeat(16) };
const CONFIGURED = { FACEBOOK_APP_ID: APP.id, FACEBOOK_APP_SECRET: APP.secret, SUPABASE_URL: "https://check.supabase.co" };
const BASE = "https://check.supabase.co";
const USER = "00000000-0000-4000-8000-000000000001";
const OTHER = "00000000-0000-4000-8000-000000000002";
const SHORT = "EAAshort-check-" + "a1".repeat(10);
const LONG = "EAAlong-check-" + "b2".repeat(10);
const PAGE_TOKEN_A = "EAApageA-check-" + "c3".repeat(10);
const PAGE_TOKEN_B = "EAApageB-check-" + "d4".repeat(10);
const PAGE_TOKEN_C = "EAApageC-check-" + "e5".repeat(10);
const CODE = "AQfbcheck-code-" + "f6".repeat(10);
const PAGE_A = "1000000000000001", PAGE_B = "1000000000000002", PAGE_C = "1000000000000003";
const NAME_A = "Maple Street Bakery", NAME_B = "Maple Street Catering", NAME_C = "Maple Street Fans";
const SIGNED_MARK = "check-signed-token-";
const REDIRECT = "https://bizforceai.net/agents/social.html";
const PAGE_PATH = "/agents/social.html";
const SECRETS = [SHORT, LONG, PAGE_TOKEN_A, PAGE_TOKEN_B, PAGE_TOKEN_C, CODE, APP.secret, SIGNED_MARK];
function noSecretIn(text) { return SECRETS.every(function (s) { return String(text).indexOf(s) === -1; }); }
const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F2FF}\u{FE0F}]/u;
const NOT_SET_UP = "Facebook connection isn't set up yet.";
const SCOPES3 = ["pages_show_list", "pages_manage_posts", "pages_read_engagement"];
const ALL_TASKS = ["ANALYZE", "ADVERTISE", "MODERATE", "CREATE_CONTENT", "MANAGE"];
const PG_A = { id: PAGE_A, name: NAME_A, access_token: PAGE_TOKEN_A, tasks: ALL_TASKS };
const PG_B = { id: PAGE_B, name: NAME_B, access_token: PAGE_TOKEN_B, tasks: ["CREATE_CONTENT", "MODERATE"] };
const PG_C = { id: PAGE_C, name: NAME_C, access_token: PAGE_TOKEN_C, tasks: ["ANALYZE", "MODERATE"] };
const sha = function (b) { return crypto.createHash("sha256").update(b).digest("hex"); };
const DAY = 86400000;
const HOUR = 3600000;

function filler(n, seed) {
  const out = Buffer.alloc(n);
  let x = seed || 7;
  for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) >>> 0; out[i] = x >>> 24; }
  return out;
}
function jpeg(n, seed) {
  const head = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]), Buffer.from("JFIF\u0000", "latin1"), Buffer.alloc(9), Buffer.from([0xff, 0xda])]);
  return Buffer.concat([head, filler(Math.max(0, (n || 2048) - head.length), seed)]);
}
function png(n, seed) {
  const head = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([head, filler(Math.max(0, (n || 2048) - head.length), seed)]);
}
function gif(n, seed) {
  const head = Buffer.from("GIF89a", "latin1");
  return Buffer.concat([head, filler(Math.max(0, (n || 2048) - head.length), seed)]);
}
function webp(n, seed) {
  const head = Buffer.concat([Buffer.from("RIFF", "latin1"), Buffer.from([0, 0, 0, 0]), Buffer.from("WEBPVP8 ", "latin1")]);
  return Buffer.concat([head, filler(Math.max(0, (n || 2048) - head.length), seed)]);
}
function mp4(n, seed) {
  const head = Buffer.concat([Buffer.from([0, 0, 0, 0x18]), Buffer.from("ftypisom", "latin1"), Buffer.from([0, 0, 2, 0]), Buffer.from("isomiso2", "latin1")]);
  return Buffer.concat([head, filler(Math.max(0, (n || 4096) - head.length), seed)]);
}

/* ── the clock ───────────────────────────────────────────────────────────── */
const CLOCK = { t: Date.parse("2026-11-07T12:00:00.000Z") };
function iso(ms) { return new Date(ms).toISOString(); }
function fbTime(ms) { return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "+0000"); }

/* ── an in-memory database, with migration 180's CHECKs, and Storage ─────── */
function uuid() { return crypto.randomUUID(); }
const HEX = /^[0-9a-f]+$/;
const EV = [];
function nul(v) { return v === undefined || v === null; }
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
  const t = { member_facebook_pages: [], facebook_posts: [], instagram_posts: [], member_media: [], member_videos: [], oauth_states: [], agent_proposals: [], notifications: [],
    job_runs: [], business_profiles: [], social_post_drafts: [] };
  const fail = {};
  function rows(name) { if (!t[name]) t[name] = []; return t[name]; }
  function sealedOk(c, i, a) { return HEX.test(c || "") && /^[0-9a-f]{24}$/.test(i || "") && /^[0-9a-f]{32}$/.test(a || ""); }
  function triple(r, w) {
    const c = r[w + "_ciphertext"], i = r[w + "_iv"], a = r[w + "_auth_tag"];
    return (nul(c) && nul(i) && nul(a)) || sealedOk(c, i, a);
  }
  function uniqueViolation(name, row, except) {
    const others = rows(name).filter(function (r) { return r !== except; });
    if (name === "member_facebook_pages" && others.some(function (r) { return r.user_id === row.user_id; })) return "member_facebook_pages_user_id_key";
    if (name === "facebook_posts" && others.some(function (r) { return r.proposal_id === row.proposal_id; })) return "facebook_posts_proposal_id_key";
    if (name === "member_videos" && row.path != null && others.some(function (r) { return r.path === row.path; })) return "member_videos_path_key";
    if (name === "job_runs" && others.some(function (r) { return r.job_name === row.job_name; })) return "job_runs_pkey";
    return null;
  }
  function checkViolation(name, row) {
    if (name === "member_facebook_pages") {
      if (!row.user_id) return "member_facebook_pages_user_id_not_null";
      if (!nul(row.page_id) && !/^[0-9]{1,30}$/.test(row.page_id)) return "member_facebook_pages_page_id_check";
      if (!nul(row.page_name) && !(String(row.page_name).length >= 1 && String(row.page_name).length <= 200)) return "member_facebook_pages_page_name_check";
      if (!triple(row, "page")) return "member_facebook_pages_page_token_check";
      if (!triple(row, "user")) return "member_facebook_pages_user_token_check";
      if (!nul(row.granted_scopes) && !(String(row.granted_scopes).length <= 500 && /^[a-z_,]*$/.test(row.granted_scopes))) return "member_facebook_pages_scopes_check";
      if (["choosing", "connected", "needs_reconnect"].indexOf(row.status) === -1) return "member_facebook_pages_status_check";
      const choosingShape = row.status === "choosing" && !nul(row.user_ciphertext) && nul(row.page_ciphertext) && nul(row.page_id);
      const pagedShape = (row.status === "connected" || row.status === "needs_reconnect") && !nul(row.page_ciphertext) && !nul(row.page_id) && !nul(row.page_name) && nul(row.user_ciphertext);
      if (!(choosingShape || pagedShape)) return "member_facebook_pages_shape_check";
      if (!nul(row.last_error_code) && String(row.last_error_code).length > 60) return "member_facebook_pages_error_code_check";
    }
    if (name === "facebook_posts") {
      if (!row.user_id || !row.proposal_id) return "facebook_posts_not_null";
      if (["text", "photo", "photos", "video"].indexOf(row.kind) === -1) return "facebook_posts_kind_check";
      if (["creating", "publishing", "published", "failed"].indexOf(row.status) === -1) return "facebook_posts_status_check";
      if (!nul(row.post_id) && !/^[0-9]{1,30}(_[0-9]{1,30})?$/.test(row.post_id)) return "facebook_posts_post_id_check";
      if (!nul(row.permalink) && !(String(row.permalink).length <= 300 && /^https:\/\/www\.facebook\.com\//.test(row.permalink))) return "facebook_posts_permalink_check";
      if (!nul(row.error) && String(row.error).length > 300) return "facebook_posts_error_check";
      if ((row.status === "published") !== (!nul(row.post_id) && !nul(row.published_at))) return "facebook_posts_published_check";
      if (!nul(row.removed_at) && row.status !== "published") return "facebook_posts_removed_check";
    }
    if (name === "oauth_states") {
      if (["mailbox_microsoft", "store_shopify", "youtube_google", "tiktok_login", "instagram_login", "facebook_login"].indexOf(row.purpose) === -1) return "oauth_states_purpose_check";
      if (["store_shopify", "tiktok_login", "instagram_login", "facebook_login"].indexOf(row.purpose) === -1 && (row.verifier_ciphertext == null || row.verifier_iv == null || row.verifier_auth_tag == null)) return "oauth_states_verifier_shape_check";
    }
    return null;
  }
  function defaults(name, row) {
    const r = Object.assign({ id: uuid(), created_at: new Date(CLOCK.t).toISOString() }, row);
    if (name === "member_facebook_pages") {
      if (r.status === undefined) r.status = "choosing";
      ["page_id", "page_name", "page_ciphertext", "page_iv", "page_auth_tag", "user_ciphertext", "user_iv", "user_auth_tag", "user_expires_at", "granted_scopes",
        "last_ok_at", "last_error_at", "last_error_code"].forEach(function (k) { if (r[k] === undefined) r[k] = null; });
      if (r.updated_at === undefined) r.updated_at = r.created_at;
    }
    if (name === "facebook_posts") {
      if (r.status === undefined) r.status = "creating";
      ["post_id", "permalink", "video_id", "error", "removed_at", "published_at"].forEach(function (k) { if (r[k] === undefined) r[k] = null; });
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

/* ── Facebook, stubbed behind the real guarded fetcher ──────────────────── */
function reply(status, body) {
  const h = {};
  if (body !== null && body !== undefined) h["content-type"] = "application/json; charset=UTF-8";
  return { status: status, headers: h, raw: body === null || body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body), "utf8") };
}
function headerOf(hdrs, name) {
  const k = Object.keys(hdrs || {}).filter(function (x) { return x.toLowerCase() === name.toLowerCase(); })[0];
  return k ? String(hdrs[k]) : null;
}
const PUBLIC_V4 = "157.240.22.35";
const REFUSED_TOKEN = { error: { message: "Error validating access token: Session has expired.", type: "OAuthException", code: 190 } };
function makeFacebook(opts) {
  const o = Object.assign({}, opts || {});
  const g = { opts: o, requests: [], tokenCalls: [], longCalls: [], accountsBearer: [], feedCalls: [], photoCalls: [], videoCalls: [], deletes: [], feed: [],
    videoIds: {}, n: 0, lost: 0, atFirstCall: null, atFinal: [], db: o.db || null };
  function record(method, u, headers, body) {
    const auth = headerOf(headers, "Authorization");
    let parsed = null;
    try { parsed = body && body.length ? JSON.parse(body.toString("utf8")) : null; } catch (e) { parsed = { unparsed: true }; }
    const entry = { method: method, host: u.hostname, path: u.pathname, search: u.search, bearer: auth ? auth.replace(/^Bearer /, "") : null,
      contentType: headerOf(headers, "Content-Type"), body: parsed };
    g.requests.push(entry);
    return entry;
  }
  function snapshotFinal() { if (g.db) g.atFinal.push(g.db.t.facebook_posts.map(function (r) { return { proposal_id: r.proposal_id, status: r.status }; })); }
  function answer(method, u, headers, body) {
    const entry = record(method, u, headers, body);
    const q = u.searchParams;
    const keys = Array.from(q.keys()).sort().join(",");
    if (u.hostname === "graph.facebook.com" && u.pathname === "/v26.0/oauth/access_token" && method === "GET") {
      if (q.get("grant_type") === "fb_exchange_token") {
        g.longCalls.push({ keys: keys, client_id: q.get("client_id"), secret_ok: q.get("client_secret") === APP.secret, short_ok: q.get("fb_exchange_token") === SHORT });
        EV.push("fb:long");
        if (o.longLived === "down") return reply(500, { error: { message: "An unexpected error has occurred.", code: 2 } });
        if (o.longLived === "limited") return reply(400, { error: { message: "Application request limit reached", type: "OAuthException", code: 4 } });
        return reply(200, { access_token: LONG, token_type: "bearer", expires_in: 5183944 });
      }
      g.tokenCalls.push({ keys: keys, client_id: q.get("client_id"), secret_ok: q.get("client_secret") === APP.secret, redirect_uri: q.get("redirect_uri"), code: q.get("code") });
      EV.push("fb:token");
      if (o.exchange === "invalid") return reply(400, { error: { message: "This authorization code has been used.", type: "OAuthException", code: 100 } });
      if (o.exchange === "down") return reply(503, { error: { message: "busy", code: 2 } });
      return reply(200, { access_token: SHORT, token_type: "bearer", expires_in: 5183 });
    }
    if ((u.hostname !== "graph.facebook.com" && u.hostname !== "graph-video.facebook.com") || u.pathname.indexOf("/v26.0/") !== 0) return reply(404, { error: { message: "no stub for " + u.pathname } });
    if (o.reject && o.reject.indexOf(entry.bearer) !== -1) { EV.push("fb:refused"); return reply(401, REFUSED_TOKEN); }
    const parts = u.pathname.slice("/v26.0/".length).split("/");
    if (parts[0] === "me" && parts[1] === "permissions" && method === "GET") {
      EV.push("fb:permissions");
      g.permBearer = entry.bearer;
      const perms = o.permissions === undefined ? SCOPES3 : o.permissions;
      return reply(200, { data: perms.map(function (p) { return { permission: p, status: "granted" }; })
        .concat([{ permission: "public_profile", status: "granted" }, { permission: "pages_messaging", status: "declined" }]) });
    }
    if (parts[0] === "me" && parts[1] === "accounts" && method === "GET") {
      EV.push("fb:accounts");
      g.accountsBearer.push(entry.bearer);
      g.accountsSearch = u.search;
      return reply(200, { data: o.pages === undefined ? [PG_A, PG_C] : o.pages });
    }
    // calls with a Page token from here on
    if (!g.atFirstCall && g.db) g.atFirstCall = { posts: g.db.t.facebook_posts.map(function (r) { return Object.assign({}, r); }) };
    if (u.hostname === "graph-video.facebook.com" && parts.length === 2 && parts[1] === "videos" && method === "POST") {
      snapshotFinal();
      EV.push("fb:video");
      g.videoCalls.push({ page: parts[0], body: entry.body, bearer: entry.bearer });
      if (o.videoRefuse) return reply(400, { error: { message: o.videoRefuse, type: "OAuthException", code: 352 } });
      g.n++;
      const vid = String(2000000000000000 + g.n);
      g.videoIds[vid] = true;
      g.feed.push({ id: vid, message: entry.body && entry.body.description, created_time: fbTime(CLOCK.t) });
      return reply(200, { id: vid });
    }
    if (u.hostname !== "graph.facebook.com") return reply(404, { error: { message: "no stub for " + u.pathname } });
    if (parts.length === 2 && parts[1] === "feed" && method === "POST") {
      snapshotFinal();
      EV.push("fb:feed");
      g.feedCalls.push({ page: parts[0], body: entry.body, bearer: entry.bearer });
      if (o.feedRefuse) return reply(400, { error: { message: o.feedRefuse, type: "OAuthException", code: 100 } });
      g.n++;
      const id = parts[0] + "_" + String(3000000000000000 + g.n);
      if (!o.feedLostNotPosted) g.feed.push({ id: id, message: entry.body && entry.body.message, created_time: fbTime(CLOCK.t) });
      if ((o.feedLost && g.lost < o.feedLost) || o.feedLostNotPosted) { g.lost++; return { error: Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }) }; }
      return reply(200, { id: id });
    }
    if (parts.length === 2 && parts[1] === "photos" && method === "POST") {
      const published = !!(entry.body && entry.body.published === true);
      if (published) snapshotFinal();
      EV.push("fb:photo:" + (published ? "published" : "unpublished"));
      g.photoCalls.push({ page: parts[0], body: entry.body, bearer: entry.bearer });
      if (o.photoRefuse) return reply(400, { error: { message: o.photoRefuse, type: "OAuthException", code: 324 } });
      g.n++;
      const photoId = String(4000000000000000 + g.n);
      if (!published) return reply(200, { id: photoId });
      const postId = parts[0] + "_" + photoId;
      g.feed.push({ id: postId, message: entry.body.message, created_time: fbTime(CLOCK.t) });
      return reply(200, { id: photoId, post_id: postId });
    }
    if (parts.length === 2 && parts[1] === "posts" && method === "GET") {
      EV.push("fb:posts-list");
      g.listSearch = u.search;
      return reply(200, { data: g.feed.slice().reverse().slice(0, 10) });
    }
    if (parts.length === 1 && method === "GET" && /^permalink_url/.test(q.get("fields") || "")) {
      EV.push("fb:permalink");
      const id = parts[0];
      if (g.videoIds[id] || o.videoPermalink) return reply(200, { permalink_url: "/" + PAGE_A + "/videos/" + id + "/", status: { video_status: o.videoStatus || "processing" }, id: id });
      return reply(200, { permalink_url: o.permalink || ("https://www.facebook.com/" + id.replace("_", "/posts/")), id: id });
    }
    if (parts.length === 1 && method === "DELETE") {
      EV.push("fb:delete");
      g.deletes.push(parts[0]);
      if (o.deleteFail) return reply(400, { error: { message: "Unsupported delete request.", type: "GraphMethodException", code: 100 } });
      return reply(200, { success: true });
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
  g.pageCalls = function () { return g.of(function (r) { return !/oauth\/access_token|\/me\//.test(r.path); }); };
  return g;
}

/* THE NETWORK TRIPWIRE: no socket, no real DNS question, no fetch, in this whole run. */
const TRIPPED = [];
(function tripwire() {
  const http = require("http"), https = require("https"), net = require("net"), tls = require("tls"), dns = require("dns");
  function wire(obj, name, label) {
    obj[name] = function () { TRIPPED.push(label); throw new Error("checkFacebookPages: " + label + " is not allowed in this check"); };
  }
  wire(http, "request", "http.request"); wire(http, "get", "http.get");
  wire(https, "request", "https.request"); wire(https, "get", "https.get");
  wire(net, "connect", "net.connect"); wire(net, "createConnection", "net.createConnection");
  wire(tls, "connect", "tls.connect");
  wire(dns, "lookup", "dns.lookup"); wire(dns, "resolve", "dns.resolve"); wire(dns.promises, "lookup", "dns.promises.lookup");
  globalThis.fetch = function () { TRIPPED.push("fetch"); return Promise.reject(new Error("checkFacebookPages: fetch is not allowed in this check")); };
})();

/* ── the routes, run from server.js's own source ─────────────────────────── */
function sliceOf(src, start, end) {
  const a = src.indexOf(start), b = src.indexOf(end, a);
  return a === -1 || b === -1 ? "" : src.slice(a, b);
}
const FB_SECTION = sliceOf(FILES.server, "/* ── Facebook Pages posting (migration 180; lib/facebookAuth.js, lib/facebookApi.js) ──",
  "/* ── YouTube uploads (migration 177; lib/googleAuth.js, lib/youtubeApi.js, lib/memberVideos.js) ──");
const CRON_START = "  if (require.main === module) {\n    cron.schedule(\"45 4 * * *\", function () {\n      cardLeads.cardLeadsPurgeTick(supabase)";
const CRON_SECTION = sliceOf(FILES.server, CRON_START, "    console.log(\"[startup] card leads purge scheduled");
function requireAuth() {} function requireActiveSubscription() {} function aiLimiter() {}
function claimsStub(text) {
  return /guaranteed/i.test(String(text)) ? { error: "That makes a promise BizForce can't check (\"guaranteed\").", violations: [{ phrase: "guaranteed" }] } : null;
}
const TOKEN_EVENTS = {};
TOKEN_EVENTS[LONG] = "encrypt:long"; TOKEN_EVENTS[SHORT] = "encrypt:short"; TOKEN_EVENTS[PAGE_TOKEN_A] = "encrypt:page"; TOKEN_EVENTS[PAGE_TOKEN_B] = "encrypt:page";
const MARKING_CRYPT = {
  encrypt: function (p) { EV.push(TOKEN_EVENTS[p] || "encrypt:other"); return CRYPT.encrypt(p); },
  decrypt: function (x) { return CRYPT.decrypt(x); }
};
function mountRoutes(env) {
  env = env || {};
  const db = env.db || makeDb();
  const fb = makeFacebook(Object.assign({ db: db }, env.fb || {}));
  CURRENT = fb;
  const routes = {};
  const prompts = [];
  const ctx = {
    supabase: Object.assign(function () {}, { from: db.from, storage: db.storage }),
    process: { env: Object.assign({ ENCRYPTION_SECRET: SECRET_HEX }, env.env || {}) },
    console: console,
    rateLimit: function (o) { return { limiter: o }; },
    requireAuth: requireAuth, requireActiveSubscription: requireActiveSubscription, aiLimiter: aiLimiter,
    nowIso: function () { return new Date().toISOString(); },
    FRONTEND_URL: "https://bizforceai.net",
    blueskyClaimsRefusal: claimsStub,
    callAnthropicText: async function (prompt) {
      prompts.push(prompt);
      return { text: env.draft !== undefined ? env.draft : "MESSAGE: Spring cakes, baked fresh every morning. Come by the shop this weekend." };
    },
    Promise: Promise, Buffer: Buffer, URL: URL, Date: Date, JSON: JSON, Object: Object, Array: Array, String: String, Number: Number, Math: Math,
    require: function (r) {
      if (r === "./lib/apiKeyCrypto") return MARKING_CRYPT;
      if (r === "./lib/guardedFetch") return Object.assign({}, GF, GF_PROXY);
      if (r === "./lib/facebookAuth") return FA;
      if (r === "./lib/facebookApi") return FB;
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
  vm.runInContext(FB_SECTION, ctx, { filename: "server.js (Facebook section)" });
  return { db: db, fb: fb, routes: routes, ctx: ctx, prompts: prompts, storage: db.storage };
}
async function hit(m, key, req) {
  CURRENT = m.fb;
  const r = m.routes[key];
  if (!r) return { status: 0, body: {}, headers: {}, err: new Error("no route " + key) };
  const res = { statusCode: 200, body: undefined, headers: {}, set: function (k, v) { this.headers[k] = v; return this; },
    status: function (c) { this.statusCode = c; return this; }, json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let err = null;
  try { await r.handler(Object.assign({ user: { id: USER }, body: {}, params: {} }, req), res, function (e) { err = e || new Error("next"); }); }
  catch (e) { err = e; res.statusCode = 599; }
  return { status: err && res.body === undefined ? 599 : res.statusCode, body: res.body || {}, headers: res.headers, err: err };
}
async function attempt(p) { try { return { ok: true, v: await p }; } catch (e) { return { ok: false, msg: e && e.message, code: e && e.code, kind: e && e.kind }; } }
async function begin(m) {
  const r = await hit(m, "post /api/facebook/start", {});
  const url = r.body && r.body.authorize_url ? new URL(r.body.authorize_url) : null;
  return { r: r, url: url, state: url ? url.searchParams.get("state") : null };
}
async function connect(m) {
  const b = await begin(m);
  const f = await hit(m, "post /api/facebook/finish", { body: { code: CODE, state: b.state } });
  return { b: b, f: f };
}
function seal(p) { const s = CRYPT.encrypt(p); return { ciphertext: s.ciphertext, iv: s.iv, authTag: s.authTag }; }
function seedConnection(db, over, nowMs) {
  const n = nowMs === undefined ? CLOCK.t : nowMs;
  const a = seal((over && over.token) || PAGE_TOKEN_A);
  const row = Object.assign({ id: uuid(), user_id: USER, page_id: PAGE_A, page_name: NAME_A,
    page_ciphertext: a.ciphertext, page_iv: a.iv, page_auth_tag: a.authTag,
    user_ciphertext: null, user_iv: null, user_auth_tag: null, user_expires_at: null, granted_scopes: SCOPES3.join(","),
    status: "connected", last_ok_at: null, last_error_at: null, last_error_code: null, created_at: iso(n - 10 * DAY), updated_at: iso(n - 10 * DAY) }, over || {});
  delete row.token;
  db.t.member_facebook_pages.push(row);
  return row;
}
function seedChoosing(db, createdMs, over) {
  const u = seal(LONG);
  const row = Object.assign({ id: uuid(), user_id: USER, page_id: null, page_name: null, page_ciphertext: null, page_iv: null, page_auth_tag: null,
    user_ciphertext: u.ciphertext, user_iv: u.iv, user_auth_tag: u.authTag, user_expires_at: iso(createdMs + 50 * DAY), granted_scopes: SCOPES3.join(","),
    status: "choosing", last_ok_at: iso(createdMs), last_error_at: null, last_error_code: null, created_at: iso(createdMs), updated_at: iso(createdMs) }, over || {});
  db.t.member_facebook_pages.push(row);
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
function seedPosts(db, n, status, atMs) {
  for (let i = 0; i < n; i++) {
    const st = status || "publishing";
    const at = iso(atMs === undefined ? CLOCK.t - HOUR : atMs);
    db.t.facebook_posts.push({ id: uuid(), user_id: USER, proposal_id: uuid(), kind: "text", status: st,
      post_id: st === "published" ? PAGE_A + "_" + String(3100000000000000 + i) : null, permalink: null, video_id: null, error: st === "failed" ? "x" : null,
      removed_at: null, created_at: at, updated_at: at, published_at: st === "published" ? at : null });
  }
}
const MESSAGE = "Spring cakes, baked fresh every morning.";
function itemOf(r) { return { id: r.id, sha256: r.sha256, bytes: r.bytes, mime: r.mime }; }
function textPayload(over) { return Object.assign({ kind: "text", message: MESSAGE, page_id: PAGE_A }, over || {}); }
function photoPayload(rows, over) { return Object.assign({ kind: rows.length === 1 ? "photo" : "photos", items: rows.map(itemOf), message: MESSAGE, page_id: PAGE_A }, over || {}); }
function videoPayload(v, over) { return Object.assign({ kind: "video", video: { id: v.id, sha256: v.sha256, bytes: Number(v.bytes), mime: v.mime }, message: MESSAGE, page_id: PAGE_A }, over || {}); }
function proposalOf(payload, action) { return { id: uuid(), user_id: USER, action_type: action || "publish_facebook_post", status: "executing", payload: payload }; }
function libDeps(db, fb, extra) {
  CURRENT = fb;
  return Object.assign({ supabase: db, storage: db.storage, crypt: MARKING_CRYPT, jsonRequest: fb.jsonRequest,
    now: function () { return CLOCK.t; }, claims: claimsStub, base: BASE }, extra || {});
}
function unsealed(row, which) { try { return CRYPT.decrypt({ ciphertext: row[which + "_ciphertext"], iv: row[which + "_iv"], authTag: row[which + "_auth_tag"] }); } catch (e) { return null; } }
async function flush() { for (let i = 0; i < 80; i++) await new Promise(function (r) { setImmediate(r); }); }
function stripComments(src) { return String(src).replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, ""); }
function postOf(db, proposalId) { return db.t.facebook_posts.filter(function (r) { return r.proposal_id === proposalId; })[0]; }
function connOf(db) { return db.t.member_facebook_pages.filter(function (r) { return r.user_id === USER; })[0]; }
function fresh(opts) {
  const db = makeDb();
  const fb = makeFacebook(Object.assign({ db: db }, opts || {}));
  return { db: db, fb: fb, deps: libDeps(db, fb) };
}

/* ── the page ────────────────────────────────────────────────────────────── */
const SELECTS = { fbVideo: true, fbPageSelect: true };
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
    getElementById: function (id) { if (!dom.els[id]) { dom.els[id] = node(SELECTS[id] ? "select" : "div"); dom.els[id].id = id; } return dom.els[id]; },
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
  vm.runInContext(FILES.ui, ctx, { filename: "scripts/facebook.js" });
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
const STATUS_CONNECTED = { facebook_available: true, connected: true, choosing: false, status: "connected", page_name: NAME_A, since: "2026-11-01T10:00:00.000Z", reconnect_message: null };
function pageAnswers(over) {
  const map = Object.assign({
    "GET /api/facebook/status": { status: 200, body: STATUS_CONNECTED },
    "GET /api/facebook/posts": { status: 200, body: { posts: [] } },
    "POST /api/facebook/finish": { status: 200, body: STATUS_CONNECTED },
    "POST /api/facebook/start": { status: 200, body: { authorize_url: "https://www.facebook.com/v26.0/dialog/oauth?client_id=1&state=x" } },
    "GET /api/videos": { status: 200, body: { videos: [] } },
    "POST /api/facebook/propose-post": { status: 201, body: { note: "Filed for approval. Nothing has been sent to Facebook." } }
  }, over || {});
  return function (p, method) { return map[method + " " + p] || { status: 404, body: { error: "no answer" } }; };
}

(async function main() {
  OUT("checkFacebookPages: Facebook Pages posting (migration 180)");
  check("the Facebook section and the 04:45 chain of server.js were found", FB_SECTION.length > 5000 && CRON_SECTION.length > 500, J([FB_SECTION.length, CRON_SECTION.length]));

  /* ── O ── */
  OUT("\n══ O. connect ══");
  let m = mountRoutes({ env: CONFIGURED });
  EV.length = 0;
  const st = await begin(m);
  const stRow = m.db.t.oauth_states[0];
  const params = st.url ? Array.from(st.url.searchParams.keys()).join(",") : "";
  check("O1. start: exactly Facebook's v26.0 dialog, with client_id, redirect_uri, state, response_type=code, the three scopes and a 43-character state; no-store",
    !!st.url && st.url.origin + st.url.pathname === "https://www.facebook.com/v26.0/dialog/oauth" && params === "client_id,redirect_uri,state,response_type,scope" &&
    st.url.searchParams.get("client_id") === APP.id && st.url.searchParams.get("redirect_uri") === REDIRECT && st.url.searchParams.get("response_type") === "code" &&
    st.url.searchParams.get("scope") === "pages_show_list,pages_manage_posts,pages_read_engagement" && /^[A-Za-z0-9_-]{43}$/.test(st.state || "") &&
    st.r.headers["Cache-Control"] === "no-store", st.url ? st.url.href.replace(st.state, "STATE") : J(st.r));
  check("O2. ...only the state's sha256 is stored, purpose facebook_login, no verifier, expiring in 10 minutes",
    !!stRow && stRow.purpose === "facebook_login" && stRow.state_hash === sha(st.state) && J(m.db.t.oauth_states).indexOf(st.state) === -1 &&
    stRow.verifier_ciphertext === undefined && Math.abs(Date.parse(stRow.expires_at) - Date.parse(stRow.created_at) - 600000) < 5, J(stRow));
  let fin = await hit(m, "post /api/facebook/finish", { body: { code: CODE, state: st.state } });
  let c1 = connOf(m.db);
  const tc = m.fb.tokenCalls[0] || {}, lc = m.fb.longCalls[0] || {};
  check("O3. finish: the code exchanged by a GET with the app's id and secret, the exact redirect URI and the code; then the long-lived exchange (fb_exchange_token, with the secret)",
    fin.status === 200 && tc.keys === "client_id,client_secret,code,redirect_uri" && tc.client_id === APP.id && tc.secret_ok && tc.redirect_uri === REDIRECT && tc.code === CODE &&
    lc.keys === "client_id,client_secret,fb_exchange_token,grant_type" && lc.client_id === APP.id && lc.secret_ok && lc.short_ok && m.fb.tokenCalls.length === 1 && m.fb.longCalls.length === 1,
    J([fin.status, fin.body, tc.keys, lc.keys]));
  const order = ["fb:token", "fb:long", "encrypt:long", "fb:permissions", "fb:accounts", "db:member_facebook_pages:upsert"].map(function (e) { return EV.indexOf(e); });
  check("O4. ...the long-lived user token sealed BEFORE Facebook is asked anything else (permissions, then the Pages, with that token), and the row written last",
    order.every(function (x) { return x !== -1; }) && order.every(function (x, i) { return i === 0 || x > order[i - 1]; }) && m.fb.permBearer === LONG &&
    J(m.fb.accountsBearer) === J([LONG]) && EV.filter(function (e) { return e === "fb:permissions"; }).length === 1 && /fields=id%2Cname%2Caccess_token%2Ctasks|fields=id,name,access_token,tasks/.test(m.fb.accountsSearch || ""), J(EV));
  check("O5. ...one Page that can be posted to (the other lacks CREATE_CONTENT): connected at once, its Page token sealed, the user token let go; tokens stored nowhere in the clear",
    !!c1 && c1.status === "connected" && c1.page_id === PAGE_A && c1.page_name === NAME_A && unsealed(c1, "page") === PAGE_TOKEN_A && c1.user_ciphertext === null && c1.user_expires_at === null &&
    c1.granted_scopes === "pages_show_list,pages_manage_posts,pages_read_engagement,public_profile" && noSecretIn(J(m.db.t)), J(c1));
  check("O6. ...the answer: connected, the Page's name, never a token, no Page list",
    fin.body.connected === true && fin.body.page_name === NAME_A && fin.body.facebook_available === true && noSecretIn(J(fin.body)) &&
    Object.keys(fin.body).sort().join() === "choosing,connected,facebook_available,page_name,reconnect_message,since,status", J(fin.body));
  const again = await hit(m, "post /api/facebook/finish", { body: { code: CODE, state: st.state } });
  check("O7. the same state again: 400 state_invalid, Facebook not asked", again.status === 400 && again.body.code === "state_invalid" && m.fb.tokenCalls.length === 1, J([again.status, again.body, m.fb.tokenCalls.length]));
  m = mountRoutes({ env: CONFIGURED, fb: { permissions: ["pages_show_list", "pages_read_engagement"] } });
  let cn = await connect(m);
  check("O8. a permission not granted: 422 with the plain words, the Pages never read, nothing saved", cn.f.status === 422 && cn.f.body.code === "no_scopes" &&
    cn.f.body.error === "Facebook didn't grant the access needed. Connect again and approve all permissions." && m.fb.accountsBearer.length === 0 &&
    m.db.t.member_facebook_pages.length === 0, J([cn.f.status, cn.f.body]));
  m = mountRoutes({ env: CONFIGURED, fb: { pages: [PG_C] } });
  cn = await connect(m);
  check("O9. no Page the member can create content on: 422 with the plain words, nothing saved", cn.f.status === 422 && cn.f.body.code === "no_page" &&
    cn.f.body.error === "No Facebook Page you manage can be posted to. Create a Page or ask for posting access, then connect again." &&
    m.db.t.member_facebook_pages.length === 0, J([cn.f.status, cn.f.body]));
  m = mountRoutes({ env: CONFIGURED, fb: { pages: [PG_A, PG_B, PG_C] } });
  EV.length = 0;
  cn = await connect(m);
  let ch = connOf(m.db);
  check("O10. two Pages to choose from: status choosing, both listed by id and name only (the third can't be posted to), the long-lived user token sealed, no Page token stored",
    cn.f.status === 200 && cn.f.body.status === "choosing" && cn.f.body.choosing === true && cn.f.body.connected === false &&
    J(cn.f.body.pages) === J([{ page_id: PAGE_A, name: NAME_A }, { page_id: PAGE_B, name: NAME_B }]) && noSecretIn(J(cn.f.body)) &&
    !!ch && ch.status === "choosing" && unsealed(ch, "user") === LONG && ch.page_ciphertext === null && ch.page_id === null && EV.indexOf("encrypt:page") === -1, J([cn.f.status, cn.f.body]));
  const pagesNow = await hit(m, "get /api/facebook/pages", {});
  check("O11. GET pages: the same two, read live with the sealed user token, never a token", pagesNow.status === 200 &&
    J(pagesNow.body.pages) === J([{ page_id: PAGE_A, name: NAME_A }, { page_id: PAGE_B, name: NAME_B }]) && m.fb.accountsBearer[m.fb.accountsBearer.length - 1] === LONG &&
    noSecretIn(J(pagesNow.body)) && pagesNow.headers["Cache-Control"] === "no-store", J([pagesNow.status, pagesNow.body]));
  const chForeign = await hit(m, "post /api/facebook/choose-page", { body: { page_id: PAGE_C } });
  const chBad = await hit(m, "post /api/facebook/choose-page", { body: { page_id: "12x" } });
  check("O12. choosing a Page the list doesn't offer (no CREATE_CONTENT, or not a Page id): 404 not_listed / 400, still choosing",
    chForeign.status === 404 && chForeign.body.code === "not_listed" && chBad.status === 400 && connOf(m.db).status === "choosing", J([chForeign.status, chForeign.body, chBad.status]));
  const chOk = await hit(m, "post /api/facebook/choose-page", { body: { page_id: PAGE_B } });
  ch = connOf(m.db);
  check("O13. choosing a listed Page: connected to it, its Page token sealed, the user token cleared",
    chOk.status === 200 && chOk.body.connected === true && chOk.body.page_name === NAME_B && !!ch && ch.status === "connected" && ch.page_id === PAGE_B &&
    unsealed(ch, "page") === PAGE_TOKEN_B && ch.user_ciphertext === null && ch.user_iv === null && ch.user_auth_tag === null && ch.user_expires_at === null && noSecretIn(J(chOk.body)),
    J([chOk.status, chOk.body]));
  const chAgain = await hit(m, "post /api/facebook/choose-page", { body: { page_id: PAGE_A } });
  check("O14. choosing again once connected: 409 not_choosing", chAgain.status === 409 && chAgain.body.code === "not_choosing", J([chAgain.status, chAgain.body]));
  m = mountRoutes({ env: CONFIGURED, fb: { pages: [PG_A, PG_B] } });
  seedChoosing(m.db, Date.now() - 2 * HOUR);
  const expired = await hit(m, "get /api/facebook/pages", {});
  check("O15. a choice left over an hour: 410 with the plain words, the row (and its user token) deleted, Facebook not asked",
    expired.status === 410 && expired.body.code === "choice_expired" && expired.body.error === "Choosing a Page took too long. Connect Facebook again." &&
    m.db.t.member_facebook_pages.length === 0 && m.fb.requests.length === 0, J([expired.status, expired.body]));
  m = mountRoutes({ env: CONFIGURED, fb: { exchange: "invalid" } });
  cn = await connect(m);
  const badCode = cn.f;
  m = mountRoutes({ env: CONFIGURED, fb: { longLived: "down" } });
  cn = await connect(m);
  const longDown = cn.f;
  m = mountRoutes({ env: CONFIGURED, fb: { longLived: "limited" } });
  cn = await connect(m);
  check("O16. a refused code: 400; the long-lived exchange down or rate-limited (a 400 that is not a refused token): 502; nothing saved; no secret in any log line",
    badCode.status === 400 && badCode.body.code === "state_invalid" && longDown.status === 502 && longDown.body.code === "unreachable" &&
    cn.f.status === 502 && cn.f.body.code === "unreachable" && m.db.t.member_facebook_pages.length === 0 && LOGS.every(noSecretIn),
    J([badCode.status, longDown.status, cn.f.status, cn.f.body]));
  const badShape = await hit(m, "post /api/facebook/finish", { body: { code: "a b", state: "short" } });
  check("O17. an incomplete finish body: 400 bad_request, Facebook not asked again", badShape.status === 400 && badShape.body.code === "bad_request");
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db, {}, Date.now());
  m.db.t.oauth_states.push({ id: uuid(), user_id: USER, purpose: "facebook_login", state_hash: "a".repeat(64), expires_at: iso(Date.now() + 60000), created_at: iso(Date.now()), consumed_at: null });
  m.db.t.oauth_states.push({ id: uuid(), user_id: USER, purpose: "instagram_login", state_hash: "b".repeat(64), expires_at: iso(Date.now() + 60000), created_at: iso(Date.now()), consumed_at: null });
  const stat = await hit(m, "get /api/facebook/status", {});
  check("O18. status: connected, the Page's name; never a token, ciphertext or Page id", stat.status === 200 && stat.body.connected === true && stat.body.facebook_available === true &&
    stat.body.page_name === NAME_A && J(stat.body).indexOf("cipher") === -1 && J(stat.body).indexOf(PAGE_A) === -1 && noSecretIn(J(stat.body)), J(stat.body));
  m.routes = mountRoutes({ db: m.db, env: {} }).routes;
  const disc = await hit(m, "post /api/facebook/disconnect", {});
  check("O19. disconnect, even unconfigured: the row and only Facebook's sign-in states deleted (Instagram's kept), the note word for word",
    disc.status === 200 && disc.body.removed === true && m.db.t.member_facebook_pages.length === 0 &&
    J(m.db.t.oauth_states.map(function (r) { return r.purpose; })) === J(["instagram_login"]) &&
    disc.body.note === "Disconnected. To remove BizForce from Facebook too, open Facebook's settings, then Business integrations.", J([disc.status, disc.body]));
  m = mountRoutes({ env: {} });
  const un = [];
  for (const k of ["post /api/facebook/start", "post /api/facebook/finish", "get /api/facebook/pages", "post /api/facebook/choose-page", "post /api/facebook/propose-post",
    "post /api/facebook/draft-caption", "get /api/facebook/posts", "get /api/facebook/posts/:id/status", "post /api/facebook/posts/:id/propose-delete"]) {
    un.push(await hit(m, k, { body: { code: CODE, state: "S".repeat(43), idea: "cakes", page_id: PAGE_A }, params: { id: uuid() } }));
  }
  const unStat = await hit(m, "get /api/facebook/status", {});
  check("O20. unconfigured: every route but status and disconnect answers 503 \"Facebook connection isn't set up yet.\"; status says facebook_available false",
    un.length === 9 && un.every(function (r) { return r.status === 503 && r.body.error === NOT_SET_UP && r.body.code === "not_configured"; }) && unStat.status === 200 &&
    unStat.body.facebook_available === false && unStat.body.connected === false && m.fb.requests.length === 0, J(un.map(function (r) { return r.status; })));
  const mw = function (k) { return (m.routes[k] || { middleware: [] }).middleware; };
  check("O21. start, finish, choose-page, propose-post and draft-caption need an active subscription; the reads, disconnect and filing a removal need only sign-in",
    ["post /api/facebook/start", "post /api/facebook/finish", "post /api/facebook/choose-page", "post /api/facebook/propose-post", "post /api/facebook/draft-caption"].every(function (k) { return mw(k)[0] === requireAuth && mw(k)[1] === requireActiveSubscription; }) &&
    ["get /api/facebook/pages", "get /api/facebook/status", "post /api/facebook/disconnect", "get /api/facebook/posts", "get /api/facebook/posts/:id/status"].every(function (k) { return mw(k).length === 1 && mw(k)[0] === requireAuth; }) &&
    mw("post /api/facebook/posts/:id/propose-delete").length === 2 && mw("post /api/facebook/posts/:id/propose-delete")[0] === requireAuth &&
    mw("post /api/facebook/posts/:id/propose-delete")[1] === mw("post /api/facebook/propose-post")[2] && mw("post /api/facebook/propose-post")[2].limiter.max === 30 &&
    mw("post /api/facebook/start")[2] === mw("post /api/facebook/finish")[2] && mw("post /api/facebook/start")[2] === mw("post /api/facebook/choose-page")[2] &&
    mw("post /api/facebook/start")[2].limiter.max === 10 && mw("post /api/facebook/draft-caption")[2] === aiLimiter && Object.keys(m.routes).length === 11, J(Object.keys(m.routes)));
  const now = CLOCK.t;
  let f = fresh();
  seedChoosing(f.db, now - 2 * HOUR);
  seedChoosing(f.db, now - 10 * 60 * 1000, { user_id: OTHER });
  seedConnection(f.db, { user_id: "00000000-0000-4000-8000-000000000003", created_at: iso(now - 30 * DAY) });
  const tick = await FB.choosingPurgeTick(f.deps, now);
  const tick2 = await FB.choosingPurgeTick(f.deps, now);
  const jr = f.db.t.job_runs.filter(function (r) { return r.job_name === "facebook_choosing_purge"; });
  check("O22. the daily cleanup: only choosing rows over an hour old deleted (a fresh choice and an old connection kept); its own job_runs row; once a day",
    tick.claimed === true && tick.deleted === 1 && f.db.t.member_facebook_pages.length === 2 && f.db.t.member_facebook_pages.every(function (r) { return r.user_id !== USER; }) &&
    jr.length === 1 && jr[0].last_run_on === iso(now).slice(0, 10) && !!jr[0].finished_at && tick2.claimed === false && f.fb.requests.length === 0, J([tick, tick2, jr]));
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
    supabase: {}, videoRetentionTick: async function () { orderRun.push("videos"); }, instagramRefreshTick: async function () { orderRun.push("instagram"); },
    facebookChoosingPurgeTick: async function () { orderRun.push("facebook"); }, console: console,
    // NAMED (Nov 14 2026, L1): YouTube's daily data check and the renewal and terms emails follow Facebook's cleanup.
    youtubeDataCheckTick: async function () { orderRun.push("youtubedata"); }, renewalEmailsTick: async function () { orderRun.push("renewal"); }
  };
  vm.createContext(cctx);
  let cronOk = true;
  try { vm.runInContext(CRON_SECTION + "\n  }\n", cctx, { filename: "server.js (04:45 chain)" }); } catch (e) { cronOk = false; }
  if (scheduled[0]) { scheduled[0].fn(); await flush(); }
  // NAMED (Nov 14 2026, L1): BEFORE "runs facebookChoosingPurgeTick last" and the order ended "facebook". AFTER it runs after Instagram's refresh and
  // before L1's two ticks, and the order ends "facebook", "youtubedata", "renewal".
  check("O23. the 04:45 UTC chain runs facebookChoosingPurgeTick after Instagram's refresh, then L1's YouTube data check and renewal emails", cronOk && scheduled.length === 1 && scheduled[0].tz === "UTC" &&
    J(orderRun) === J(["leads", "states", "shopify", "videos", "instagram", "facebook", "youtubedata", "renewal"]), J(orderRun));
  const ms0 = mountRoutes({ env: CONFIGURED });
  check("O24. the server's tick runs lib/facebookApi.js choosingPurgeTick on facebookDeps() and never rejects", typeof ms0.ctx.facebookChoosingPurgeTick === "function" &&
    /async function facebookChoosingPurgeTick\(\) \{\n  try \{\n    return await require\("\.\/lib\/facebookApi"\)\.choosingPurgeTick\(facebookDeps\(\)\);/.test(FB_SECTION) &&
    (await attempt(ms0.ctx.facebookChoosingPurgeTick())).ok);

  /* ── F ── */
  OUT("\n══ F. filing ══");
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db, {}, Date.now());
  let r = await hit(m, "post /api/facebook/propose-post", { body: { kind: "text", message: "  " + MESSAGE + " " } });
  const prop1 = m.db.t.agent_proposals[0];
  check("F1. text: 201, a pending publish_facebook_post for Facebook; the message trimmed, the Page's id frozen; the title names the Page",
    r.status === 201 && !!prop1 && prop1.status === "pending" && prop1.action_type === "publish_facebook_post" && prop1.target === "facebook" && prop1.agent_type === "social" &&
    J(prop1.payload) === J({ kind: "text", message: MESSAGE, page_id: PAGE_A }) && prop1.title === "Post to the Facebook Page " + NAME_A + " (text): " + MESSAGE, J([r.status, r.body, prop1 && prop1.payload]));
  check("F2. ...never automatic: nothing sent to Facebook, no facebook_posts row; the note says so",
    m.fb.requests.length === 0 && m.db.t.facebook_posts.length === 0 &&
    r.body.note === "Filed for approval. Nothing has been sent to Facebook. Approving it on the proposals page publishes this post to " + NAME_A + ".", J([m.fb.requests.length, m.db.t.facebook_posts.length, r.body.note]));
  const pj = seedPhoto(m.db, jpeg(3000, 2));
  const pp = seedPhoto(m.db, png(3000, 3), { mime: "image/png" });
  const pg = seedPhoto(m.db, gif(3000, 4), { mime: "image/gif" });
  r = await hit(m, "post /api/facebook/propose-post", { body: { kind: "photos", media_ids: [pj.id], message: MESSAGE } });
  const one = m.db.t.agent_proposals[m.db.t.agent_proposals.length - 1];
  const r3 = await hit(m, "post /api/facebook/propose-post", { body: { kind: "photos", media_ids: [pj.id, pp.id, pg.id], message: "" } });
  const three = m.db.t.agent_proposals[m.db.t.agent_proposals.length - 1];
  check("F3. one JPEG: kind photo with its id, fingerprint, size and type; JPEG, PNG and GIF together: kind photos (a photo post's text may be empty)",
    r.status === 201 && J(one.payload) === J({ kind: "photo", items: [itemOf(pj)], message: MESSAGE, page_id: PAGE_A }) &&
    r3.status === 201 && three.payload.kind === "photos" && J(three.payload.items) === J([itemOf(pj), itemOf(pp), itemOf(pg)]) && three.payload.message === "", J([r.status, r3.status, r3.body]));
  const eleven = [];
  for (let i = 0; i < 11; i++) eleven.push(seedPhoto(m.db, jpeg(2500 + i, 10 + i)));
  const ten = await hit(m, "post /api/facebook/propose-post", { body: { kind: "photos", media_ids: eleven.slice(0, 10).map(function (x) { return x.id; }), message: MESSAGE } });
  const readsBefore = m.storage.calls.filter(function (c) { return c.op === "download"; }).length;
  r = await hit(m, "post /api/facebook/propose-post", { body: { kind: "photos", media_ids: eleven.map(function (x) { return x.id; }), message: MESSAGE } });
  check("F4. ten photos filed; eleven: 400 with the items rule, on media_ids, before any photo is read", ten.status === 201 && r.status === 400 && r.body.field === "media_ids" &&
    r.body.error === "A Facebook post has 1 to 10 photos from your Media Library, each chosen once. Nothing was filed." &&
    m.storage.calls.filter(function (c) { return c.op === "download"; }).length === readsBefore, J([ten.status, r.status, r.body]));
  const dup = await hit(m, "post /api/facebook/propose-post", { body: { kind: "photos", media_ids: [pj.id, pj.id], message: MESSAGE } });
  const none = await hit(m, "post /api/facebook/propose-post", { body: { kind: "photos", media_ids: [], message: MESSAGE } });
  check("F5. the same photo twice, or none: 400", dup.status === 400 && none.status === 400);
  const pw = seedPhoto(m.db, webp(3000, 5), { mime: "image/webp", label: "Logo" });
  const rWebp = await hit(m, "post /api/facebook/propose-post", { body: { kind: "photos", media_ids: [pw.id], message: MESSAGE } });
  check("F6. a WebP photo: 400 webp with the plain words and the photo's name", rWebp.status === 400 && rWebp.body.code === "webp" &&
    rWebp.body.error === "Facebook doesn't accept WebP photos. Choose a JPEG, PNG or GIF. (Logo)", J([rWebp.status, rWebp.body]));
  const pngAsJpeg = seedPhoto(m.db, png(3000, 6));
  const rBytes = await hit(m, "post /api/facebook/propose-post", { body: { kind: "photos", media_ids: [pngAsJpeg.id], message: MESSAGE } });
  check("F7. PNG bytes under a JPEG row: 400 photo_type (the bytes are read and must match the type)", rBytes.status === 400 && rBytes.body.code === "photo_type", J([rBytes.status, rBytes.body]));
  const otherPhoto = seedPhoto(m.db, jpeg(3000, 7), { user_id: OTHER });
  r = await hit(m, "post /api/facebook/propose-post", { body: { kind: "photos", media_ids: [otherPhoto.id], message: MESSAGE } });
  check("F8. another member's photo: 404, as if it were not there", r.status === 404 && r.body.code === "not_found");
  const vMp4 = seedVideo(m.db, mp4(5000, 8));
  const vMov = seedVideo(m.db, mp4(5000, 9), { mime: "video/quicktime" });
  const vWebm = seedVideo(m.db, mp4(5000, 10), { mime: "video/webm" });
  r = await hit(m, "post /api/facebook/propose-post", { body: { kind: "video", video_id: vMp4.id, message: MESSAGE } });
  const vidProp = m.db.t.agent_proposals[m.db.t.agent_proposals.length - 1];
  const rMov = await hit(m, "post /api/facebook/propose-post", { body: { kind: "video", video_id: vMov.id, message: MESSAGE } });
  const rWebm = await hit(m, "post /api/facebook/propose-post", { body: { kind: "video", video_id: vWebm.id, message: MESSAGE } });
  const rAgain = await hit(m, "post /api/facebook/propose-post", { body: { kind: "video", video_id: vMp4.id, message: MESSAGE } });
  check("F9. a video: MP4 and MOV filed with the video's fingerprint frozen; WebM refused (400 video_type); a second pending post of one video: 409",
    r.status === 201 && J(vidProp.payload) === J({ kind: "video", video: { id: vMp4.id, sha256: vMp4.sha256, bytes: vMp4.bytes, mime: "video/mp4" }, message: MESSAGE, page_id: PAGE_A }) &&
    rMov.status === 201 && rWebm.status === 400 && rWebm.body.code === "video_type" && rWebm.body.error === "Facebook videos must be MP4 or MOV. Nothing was filed." &&
    rAgain.status === 409 && rAgain.body.code === "pending", J([r.status, rMov.status, rWebm.status, rWebm.body.code, rAgain.status]));
  const msg = function (text, kind) { return hit(m, "post /api/facebook/propose-post", { body: { kind: kind || "text", message: text, media_ids: [pj.id] } }); };
  const tooLong = await msg("a".repeat(63207)), atMax = await msg("a".repeat(63206)), empty = await msg("   "), claims = await msg("Guaranteed fresh.");
  check("F10. the message: at most 63206 characters (on the field, the plain words); a text post must say something; the claims screen (422)",
    tooLong.status === 400 && tooLong.body.field === "message" && tooLong.body.error === "A Facebook post's text is at most 63206 characters. Nothing was filed." &&
    atMax.status === 201 && empty.status === 400 && empty.body.error === "Write the post's text first. Nothing was filed." && claims.status === 422 && claims.body.code === "claims",
    J([tooLong.status, tooLong.body, atMax.status, empty.status, claims.status]));
  const mc = mountRoutes({ env: CONFIGURED });
  seedConnection(mc.db, {}, Date.now());
  seedPosts(mc.db, 10, "failed", Date.now() - HOUR);
  const rFailedOnly = await hit(mc, "post /api/facebook/propose-post", { body: { kind: "text", message: MESSAGE } });
  seedPosts(mc.db, 9, "publishing", Date.now() - HOUR);
  const rUnder = await hit(mc, "post /api/facebook/propose-post", { body: { kind: "text", message: MESSAGE } });
  seedPosts(mc.db, 1, "published", Date.now() - HOUR);
  const rCap = await hit(mc, "post /api/facebook/propose-post", { body: { kind: "text", message: MESSAGE } });
  check("F11. 10 posts in 24 hours: the 11th refused (409 daily_cap, the plain words); failed ones don't count", rFailedOnly.status === 201 && rUnder.status === 201 &&
    rCap.status === 409 && rCap.body.code === "daily_cap" && rCap.body.error === "You can post to Facebook 10 times in 24 hours. Nothing was sent. Try again later.",
    J([rFailedOnly.status, rUnder.status, rCap.status]));
  const mn = mountRoutes({ env: CONFIGURED });
  const rNone = await hit(mn, "post /api/facebook/propose-post", { body: { kind: "text", message: MESSAGE } });
  seedChoosing(mn.db, Date.now());
  const rChoosing = await hit(mn, "post /api/facebook/propose-post", { body: { kind: "text", message: MESSAGE } });
  mn.db.t.member_facebook_pages.length = 0;
  seedConnection(mn.db, { status: "needs_reconnect" }, Date.now());
  const rRe = await hit(mn, "post /api/facebook/propose-post", { body: { kind: "text", message: MESSAGE } });
  const rKind = await hit(m, "post /api/facebook/propose-post", { body: { kind: "story", message: MESSAGE } });
  check("F12. not connected, still choosing, needs reconnecting, or no kind: refused, nothing filed", rNone.status === 409 && rNone.body.code === "not_connected" &&
    rChoosing.status === 409 && rChoosing.body.code === "choosing" && rRe.status === 409 && rRe.body.code === "needs_reconnect" && rKind.status === 400 && rKind.body.field === "kind" &&
    mn.db.t.agent_proposals.length === 0, J([rNone.status, rChoosing.body.code, rRe.body.code, rKind.status]));
  check("F13. the generic proposals route refuses both Facebook actions; only the post is subscription-gated; both executors registered to their own dispatchers",
    FILES.server.indexOf("if (actionType === \"publish_facebook_post\") {\n      return res.status(400).json({\n        error: \"A Facebook post cannot be filed here.") !== -1 &&
    FILES.server.indexOf("if (actionType === \"delete_facebook_post\") {\n      return res.status(400).json({\n        error: \"A Facebook removal cannot be filed here.") !== -1 &&
    /const SUBSCRIPTION_GATED_PROPOSAL_ACTIONS = \[[^\]]*"publish_facebook_post"\];/.test(FILES.server) &&
    !/const SUBSCRIPTION_GATED_PROPOSAL_ACTIONS = \[[^\]]*"delete_facebook_post"/.test(FILES.server) &&
    (/\n  publish_facebook_post: (\w+),\n/.exec(FILES.server) || [])[1] === "executePublishFacebookPost" &&
    (/\n  delete_facebook_post: (\w+),\n/.exec(FILES.server) || [])[1] === "executeDeleteFacebookPost" &&
    /async function executePublishFacebookPost\(proposal\) \{\n  return require\("\.\/lib\/facebookApi"\)\.executePublish\(facebookDeps\(\), proposal\);\n\}/.test(FB_SECTION) &&
    /async function executeDeleteFacebookPost\(proposal\) \{\n  return require\("\.\/lib\/facebookApi"\)\.executeDelete\(facebookDeps\(\), proposal\);\n\}/.test(FB_SECTION));
  const GR = realRequire("./lib/gateRules");
  check("F14. gateRules: both actions known, channel facebook", GR.ACTION_TYPES.indexOf("publish_facebook_post") !== -1 && GR.ACTION_TYPES.indexOf("delete_facebook_post") !== -1 &&
    GR.CHANNELS.indexOf("facebook") !== -1 && GR.channelFor("publish_facebook_post") === "facebook" && GR.channelFor("delete_facebook_post") === "facebook");
  const md = mountRoutes({ env: CONFIGURED });
  r = await hit(md, "post /api/facebook/draft-caption", { body: { idea: "spring cakes" } });
  const mdLong = mountRoutes({ env: CONFIGURED, draft: "MESSAGE: " + "b".repeat(501) });
  const rLong = await hit(mdLong, "post /api/facebook/draft-caption", { body: { idea: "spring cakes" } });
  check("F15. draft-caption: the idea and the profile go to the model, the message measured in code (500 at most), nothing filed or sent",
    r.status === 200 && r.body.draft.message === "Spring cakes, baked fresh every morning. Come by the shop this weekend." && r.body.measured.message.limit === 500 &&
    r.body.within_limits === true && rLong.status === 200 && rLong.body.within_limits === false && md.db.t.agent_proposals.length === 0 && md.fb.requests.length === 0 &&
    md.prompts.length === 1 && md.prompts[0].indexOf("\"spring cakes\"") !== -1 && md.prompts[0].indexOf("at most 500 characters") !== -1, J([r.status, r.body]));

  /* ── U ── */
  OUT("\n══ U. the post ══");
  f = fresh();
  seedConnection(f.db);
  let prop = proposalOf(textPayload());
  EV.length = 0;
  let run = await attempt(FB.executePublish(f.deps, prop));
  let row = postOf(f.db, prop.id);
  check("U1. text: the facebook_posts row written BEFORE Facebook's first call", !!f.fb.atFirstCall && f.fb.atFirstCall.posts.length === 1 &&
    f.fb.atFirstCall.posts[0].proposal_id === prop.id && EV.indexOf("db:facebook_posts:insert") !== -1 && EV.indexOf("db:facebook_posts:insert") < EV.indexOf("fb:feed"), J(EV));
  check("U2. ...set publishing BEFORE the final call; ONE feed post with the message and the Page token", f.fb.atFinal.length === 1 &&
    J(f.fb.atFinal[0]) === J([{ proposal_id: prop.id, status: "publishing" }]) && f.fb.feedCalls.length === 1 && J(f.fb.feedCalls[0].body) === J({ message: MESSAGE }) &&
    f.fb.feedCalls[0].page === PAGE_A && f.fb.feedCalls[0].bearer === PAGE_TOKEN_A, J(f.fb.atFinal));
  check("U3. ...recorded published with Facebook's id and the post's address", run.ok && run.v.published === true && !!row && row.status === "published" &&
    /^1000000000000001_\d+$/.test(row.post_id || "") && /^https:\/\/www\.facebook\.com\/1000000000000001\/posts\/\d+$/.test(row.permalink || "") && run.v.permalink === row.permalink,
    run.ok ? J([run.v, row]) : run.msg);
  const replay = await attempt(FB.executePublish(f.deps, prop));
  check("U4. the same proposal again: already published, nothing sent", replay.ok && replay.v.already_published === true && f.fb.feedCalls.length === 1);
  f = fresh();
  seedConnection(f.db);
  let photo = seedPhoto(f.db, jpeg(3000, 20));
  prop = proposalOf(photoPayload([photo]));
  EV.length = 0;
  run = await attempt(FB.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  const pc0 = f.fb.photoCalls[0] || {};
  check("U5. one photo: its bytes read and checked right before ONE published photo call with its public address and the message; the post id recorded",
    run.ok && run.v.published === true && EV.lastIndexOf("storage:read:" + photo.path) !== -1 && EV.lastIndexOf("storage:read:" + photo.path) < EV.indexOf("fb:photo:published") &&
    f.fb.photoCalls.length === 1 && J(pc0.body) === J({ url: MM.publicUrlFor(photo.path, BASE), message: MESSAGE, published: true }) &&
    J(f.fb.atFinal[0]) === J([{ proposal_id: prop.id, status: "publishing" }]) && /^1000000000000001_4\d+$/.test(row.post_id || ""), run.ok ? J([run.v, EV]) : run.msg);
  f = fresh();
  seedConnection(f.db);
  photo = seedPhoto(f.db, jpeg(3000, 21));
  prop = proposalOf(photoPayload([photo]));
  f.db.storage.objects["bf-public/" + photo.path] = { buf: jpeg(3000, 99) };
  run = await attempt(FB.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  check("U6. the photo's bytes changed after filing: refused before its address is handed over, the row failed with the plain words", !run.ok &&
    run.msg.indexOf(FB.MESSAGES.fingerprint) !== -1 && f.fb.pageCalls().length === 0 && !!row && row.status === "failed" && row.error === FB.MESSAGES.fingerprint, run.ok ? J(run.v) : run.msg);
  f = fresh();
  seedConnection(f.db);
  const trio = [seedPhoto(f.db, jpeg(3000, 23)), seedPhoto(f.db, png(3100, 24), { mime: "image/png" }), seedPhoto(f.db, gif(3200, 25), { mime: "image/gif" })];
  prop = proposalOf(photoPayload(trio));
  EV.length = 0;
  run = await attempt(FB.executePublish(f.deps, prop));
  const ev = EV.filter(function (e) { return /^storage:read:|^fb:photo:|^fb:feed/.test(e); }).map(function (e) { return e.indexOf("storage:read:") === 0 ? "read" : e.slice(3); });
  const feedBody = (f.fb.feedCalls[0] || {}).body || {};
  const uploadedIds = f.fb.photoCalls.map(function (c, i) { return String(4000000000000000 + i + 1); });
  check("U7. several photos: each read right before ITS unpublished upload, then ONE feed post attaching them in order, with the message",
    run.ok && J(ev) === J(["read", "photo:unpublished", "read", "photo:unpublished", "read", "photo:unpublished", "feed"]) &&
    f.fb.photoCalls.every(function (c, i) { return J(c.body) === J({ url: MM.publicUrlFor(trio[i].path, BASE), published: false }); }) &&
    J(feedBody) === J({ message: MESSAGE, attached_media: uploadedIds.map(function (id) { return { media_fbid: id }; }) }) && postOf(f.db, prop.id).status === "published",
    run.ok ? J([ev, feedBody]) : run.msg);
  f = fresh();
  seedConnection(f.db);
  const duo = [seedPhoto(f.db, jpeg(3000, 26)), seedPhoto(f.db, jpeg(3100, 27))];
  f.db.storage.objects["bf-public/" + duo[1].path] = { buf: jpeg(3100, 98) };
  prop = proposalOf(photoPayload(duo));
  run = await attempt(FB.executePublish(f.deps, prop));
  check("U8. ...the second photo changed: the first uploaded unpublished, then refused before the second; no feed post, the row failed",
    !run.ok && run.msg.indexOf(FB.MESSAGES.fingerprint) !== -1 && f.fb.photoCalls.length === 1 && f.fb.feedCalls.length === 0 && postOf(f.db, prop.id).status === "failed", run.ok ? J(run.v) : run.msg);
  f = fresh();
  seedConnection(f.db);
  let vid = seedVideo(f.db, mp4(6000, 30));
  prop = proposalOf(videoPayload(vid));
  EV.length = 0;
  LOGS.length = 0;
  run = await attempt(FB.executePublish(f.deps, prop));
  const sign = f.db.storage.calls.filter(function (c) { return c.op === "sign"; });
  const vc = f.fb.videoCalls[0] || { body: {} };
  row = postOf(f.db, prop.id);
  check("U9. a video: the file streamed and hashed, THEN one signed link for 7200 seconds, used only as file_url on graph-video, with the message as description",
    run.ok && sign.length === 1 && sign[0].seconds === 7200 && sign[0].path === vid.path && EV.indexOf("storage:stream") < EV.indexOf("storage:sign:7200") &&
    EV.indexOf("storage:sign:7200") < EV.indexOf("fb:video") && Object.keys(vc.body).sort().join() === "description,file_url" && (vc.body.file_url || "").indexOf(SIGNED_MARK) !== -1 &&
    vc.body.description === MESSAGE && vc.page === PAGE_A && J(f.fb.atFinal[0]) === J([{ proposal_id: prop.id, status: "publishing" }]), run.ok ? J([sign, vc.page]) : run.msg);
  check("U10. ...published once Facebook accepts it, the video's relative address made absolute, processing reported; the row names the video",
    run.ok && run.v.published === true && run.v.processing === "processing" && !!row && row.status === "published" && row.video_id === vid.id &&
    /^2\d{15}$/.test(row.post_id || "") && row.permalink === "https://www.facebook.com/" + PAGE_A + "/videos/" + row.post_id + "/", run.ok ? J([run.v, row && row.permalink]) : run.msg);
  check("U11. ...the signed link is never stored, logged or returned", J(f.db.t).indexOf(SIGNED_MARK) === -1 && LOGS.every(function (l) { return l.indexOf(SIGNED_MARK) === -1; }) &&
    J(run.ok ? run.v : run.msg).indexOf(SIGNED_MARK) === -1);
  f = fresh();
  seedConnection(f.db);
  vid = seedVideo(f.db, mp4(6000, 31));
  f.db.storage.objects["bf-video/" + vid.path] = { buf: mp4(6000, 97) };
  prop = proposalOf(videoPayload(vid));
  run = await attempt(FB.executePublish(f.deps, prop));
  check("U12. the video's bytes changed: refused before any signed link or call, the row failed", !run.ok && run.msg.indexOf(FB.MESSAGES.fingerprint) !== -1 &&
    f.db.storage.calls.filter(function (c) { return c.op === "sign"; }).length === 0 && f.fb.pageCalls().length === 0 && postOf(f.db, prop.id).status === "failed", run.ok ? J(run.v) : run.msg);
  f = fresh({ feedLost: 1 });
  seedConnection(f.db);
  prop = proposalOf(textPayload());
  run = await attempt(FB.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  const lostFirst = run.ok && run.v.publishing === true && run.v.note === FB.MESSAGES.publishing && row.status === "publishing" && row.post_id === null;
  CLOCK.t += 30 * 1000;
  const rec = await attempt(FB.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  check("U13. the feed post's answer lost: the row left publishing (\"hasn't confirmed\"); run again, it is NEVER sent again, the Page's posts are read and the post recorded",
    lostFirst && rec.ok && rec.v.published === true && f.fb.feedCalls.length === 1 && EV.indexOf("fb:posts-list") !== -1 &&
    /fields=id%2Cmessage%2Ccreated_time&limit=10|fields=id,message,created_time&limit=10/.test(f.fb.listSearch || "") && row.status === "published" &&
    row.post_id === f.fb.feed[0].id, J([lostFirst, rec.ok ? rec.v : rec.msg, f.fb.feedCalls.length, row]));
  f = fresh({ feedLostNotPosted: true });
  seedConnection(f.db);
  prop = proposalOf(textPayload());
  run = await attempt(FB.executePublish(f.deps, prop));
  const rec2 = await attempt(FB.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  check("U14. ...and when the Page has no such post: the row failed with the plain words, still never sent twice", run.ok && run.v.publishing === true && !rec2.ok &&
    rec2.msg.indexOf("Facebook may have published this post. Check your Page before filing it again.") !== -1 && row.status === "failed" &&
    row.error === FB.MESSAGES.publishedUnknown && f.fb.feedCalls.length === 1, J([rec2.ok ? rec2.v : rec2.msg, row]));
  f = fresh({ feedRefuse: "(#100) The message is too long." });
  seedConnection(f.db);
  prop = proposalOf(textPayload());
  run = await attempt(FB.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  check("U15. Facebook refuses the post (an OAuthException that is not a token error): the row failed with Facebook's words, the connection still connected, no notice",
    !run.ok && row.status === "failed" && row.error === "Facebook refused the post: (#100) The message is too long." && connOf(f.db).status === "connected" &&
    f.db.t.notifications.length === 0, J([run.ok ? run.v : run.msg, row, connOf(f.db).status]));
  f = fresh({ reject: [PAGE_TOKEN_A] });
  seedConnection(f.db);
  prop = proposalOf(textPayload());
  run = await attempt(FB.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  const prop2 = proposalOf(textPayload());
  const run2 = await attempt(FB.executePublish(f.deps, prop2));
  check("U16. the Page token refused at the final call: the row failed (never left publishing), the connection needs_reconnect with ONE notice; the next post refused before any row",
    !run.ok && run.msg.indexOf(FB.MESSAGES.needsReconnect) !== -1 && row.status === "failed" && row.error === FB.MESSAGES.needsReconnect && connOf(f.db).status === "needs_reconnect" &&
    f.db.t.notifications.length === 1 && f.db.t.notifications[0].type === "facebook_reconnect" && noSecretIn(J(f.db.t.notifications)) &&
    !run2.ok && !postOf(f.db, prop2.id), J([row, connOf(f.db).status, f.db.t.notifications.length]));
  f = fresh();
  const stale = seedConnection(f.db);
  const n1 = await FB.markNeedsReconnect(f.deps, stale, "unauthorized");
  const n2 = await FB.markNeedsReconnect(f.deps, stale, "unauthorized");
  check("U17. needs_reconnect is set once, from connected: a second refusal raises no second notice", n1 === true && n2 === false && f.db.t.notifications.length === 1 &&
    f.db.t.notifications[0].message.indexOf(NAME_A) !== -1, J([n1, n2, f.db.t.notifications.length]));
  f = fresh();
  seedConnection(f.db, { page_id: PAGE_B, page_name: NAME_B, token: PAGE_TOKEN_B });
  prop = proposalOf(textPayload());
  run = await attempt(FB.executePublish(f.deps, prop));
  check("U18. the Page connected now isn't the one filed for: refused before any row or call", !run.ok && run.msg.indexOf(FB.MESSAGES.pageChanged) !== -1 &&
    f.db.t.facebook_posts.length === 0 && f.fb.requests.length === 0, run.ok ? J(run.v) : run.msg);
  f = fresh();
  seedConnection(f.db);
  seedPosts(f.db, 10, "published");
  prop = proposalOf(textPayload());
  run = await attempt(FB.executePublish(f.deps, prop));
  check("U19. ten posts already in 24 hours: refused at send too, no row, nothing sent", !run.ok && run.msg.indexOf(FB.MESSAGES.dailyCap) !== -1 && !postOf(f.db, prop.id) &&
    f.fb.requests.length === 0, run.ok ? J(run.v) : run.msg);
  f = fresh();
  seedConnection(f.db);
  prop = proposalOf(textPayload({ message: "Guaranteed fresh." }));
  run = await attempt(FB.executePublish(f.deps, prop));
  check("U20. the claims screen runs again at send: refused, nothing sent", !run.ok && f.fb.requests.length === 0 && f.db.t.facebook_posts.length === 0);
  // removal
  f = fresh();
  seedConnection(f.db);
  prop = proposalOf(textPayload());
  await attempt(FB.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  const pd = await attempt(FB.proposeDelete(f.deps, USER, row.id));
  const delProp = f.db.t.agent_proposals[f.db.t.agent_proposals.length - 1];
  const pdAgain = await attempt(FB.proposeDelete(f.deps, USER, row.id));
  check("U21. filing a removal: 201, a pending delete_facebook_post naming the row, the post and the Page, not reversible, never run; filed twice: 409 pending",
    pd.ok && pd.v.status === 201 && !!delProp && delProp.action_type === "delete_facebook_post" && delProp.status === "pending" && delProp.reversible === false &&
    J(delProp.payload) === J({ facebook_post_id: row.id, post_id: row.post_id, page_id: PAGE_A }) && f.fb.deletes.length === 0 &&
    pdAgain.ok && pdAgain.v.status === 409 && pdAgain.v.body.code === "pending", J([pd.ok ? pd.v : pd.msg, pdAgain.ok ? pdAgain.v : pdAgain.msg]));
  const delRun = await attempt(FB.executeDelete(f.deps, { id: delProp.id, user_id: USER, action_type: "delete_facebook_post", status: "executing", payload: delProp.payload }));
  const delRow = postOf(f.db, prop.id);
  const delAgain = await attempt(FB.executeDelete(f.deps, { id: delProp.id, user_id: USER, action_type: "delete_facebook_post", status: "executing", payload: delProp.payload }));
  check("U22. approved: ONE DELETE of that post with the Page token, removed_at set; approved again: no second DELETE, \"already removed\"",
    delRun.ok && delRun.v.removed === true && J(f.fb.deletes) === J([row.post_id]) && !!delRow.removed_at && delRow.status === "published" &&
    !delAgain.ok && delAgain.msg.indexOf(FB.MESSAGES.alreadyRemoved) !== -1 && f.fb.deletes.length === 1, J([delRun.ok ? delRun.v : delRun.msg, f.fb.deletes]));
  f.db.t.agent_proposals.forEach(function (pr) { if (pr.action_type === "delete_facebook_post") pr.status = "executed"; });
  const pdRemoved = await attempt(FB.proposeDelete(f.deps, USER, row.id));
  seedPosts(f.db, 1, "failed");
  const pdFailed = await attempt(FB.proposeDelete(f.deps, USER, f.db.t.facebook_posts[f.db.t.facebook_posts.length - 1].id));
  seedConnection(f.db, { user_id: OTHER, page_id: PAGE_B, page_name: NAME_B, token: PAGE_TOKEN_B });
  const pdOther = await attempt(FB.proposeDelete(f.deps, OTHER, row.id));
  check("U23. a removed post can't be filed for removal again (409 already_removed); a failed one: 409 not_published; another member's: 404",
    pdRemoved.ok && pdRemoved.v.status === 409 && pdRemoved.v.body.code === "already_removed" && pdFailed.ok && pdFailed.v.status === 409 && pdFailed.v.body.code === "not_published" &&
    pdOther.ok && pdOther.v.status === 404, J([pdRemoved.ok && pdRemoved.v, pdFailed.ok && pdFailed.v.status, pdOther.ok && pdOther.v.status]));
  // status
  f = fresh({ feedLost: 1 });
  seedConnection(f.db);
  prop = proposalOf(textPayload());
  await attempt(FB.executePublish(f.deps, prop));
  row = postOf(f.db, prop.id);
  f.db.t.agent_proposals.push({ id: prop.id, user_id: USER, action_type: "publish_facebook_post", status: "executed", payload: prop.payload });
  let ps = await attempt(FB.postStatus(f.deps, USER, row.id));
  check("U24. Check status on a post Facebook never confirmed: looked up with the approved message and recorded, never sent again",
    ps.ok && ps.v.status === 200 && ps.v.body.status === "published" && f.fb.feedCalls.length === 1 && postOf(f.db, prop.id).status === "published", ps.ok ? J(ps.v) : ps.msg);
  f = fresh({ videoPermalink: true, videoStatus: "ready" });
  seedConnection(f.db);
  f.db.t.facebook_posts.push({ id: uuid(), user_id: USER, proposal_id: uuid(), kind: "video", status: "published", post_id: "2000000000000099", permalink: null, video_id: null,
    error: null, removed_at: null, created_at: iso(CLOCK.t - HOUR), updated_at: iso(CLOCK.t - HOUR), published_at: iso(CLOCK.t - HOUR) });
  ps = await attempt(FB.postStatus(f.deps, USER, f.db.t.facebook_posts[0].id));
  const otherPs = await attempt(FB.postStatus(f.deps, OTHER, f.db.t.facebook_posts[0].id));
  check("U25. Check status on a published video: the address read again (made absolute) and Facebook's processing state; another member's id: 404",
    ps.ok && ps.v.body.permalink === "https://www.facebook.com/" + PAGE_A + "/videos/2000000000000099/" && ps.v.body.processing === "ready" &&
    f.db.t.facebook_posts[0].permalink === ps.v.body.permalink && otherPs.ok && otherPs.v.status === 404, ps.ok ? J(ps.v) : ps.msg);
  f = fresh();
  seedConnection(f.db);
  seedPosts(f.db, 1, "creating", CLOCK.t - 2 * HOUR);
  ps = await attempt(FB.postStatus(f.deps, USER, f.db.t.facebook_posts[0].id));
  check("U26. a row stuck creating an hour on: failed with the plain words; a member is never shown a post id or proposal",
    ps.ok && ps.v.body.status === "failed" && ps.v.body.error === FB.MESSAGES.stale && f.db.t.facebook_posts[0].status === "failed" &&
    J(ps.v.body).indexOf("proposal") === -1 && J(ps.v.body).indexOf("post_id") === -1 &&
    Object.keys(FB.postView(f.db.t.facebook_posts[0])).sort().join() === "created_at,error,id,kind,permalink,published_at,removed_at,status", ps.ok ? J(ps.v) : ps.msg);
  const ms = mountRoutes({ env: CONFIGURED });
  seedConnection(ms.db, {}, Date.now());
  const sp = seedPhoto(ms.db, jpeg(3000, 44));
  const savedClock = CLOCK.t;
  CLOCK.t = Date.now();
  const viaServer = await attempt(ms.ctx.executePublishFacebookPost(proposalOf(photoPayload([sp]))));
  CLOCK.t = savedClock;
  check("U27. the server's executor runs lib/facebookApi.js executePublish on facebookDeps() (the photo's address on SUPABASE_URL)", viaServer.ok && viaServer.v.published === true &&
    ((ms.fb.photoCalls[0] || {}).body || {}).url === MM.publicUrlFor(sp.path, BASE), viaServer.ok ? J(viaServer.v) : viaServer.msg);

  /* ── L ── */
  OUT("\n══ L. the lifecycle ══");
  let db = makeDb();
  const got3 = { youtube_video_id: "Ab3_x-9Kq2Z", uploaded_at: iso(now - HOUR), tiktok_status: "posted", tiktok_posted_at: iso(now - 600000) };
  const noFb = seedVideo(db, mp4(4000, 50), got3);
  const all4 = seedVideo(db, mp4(4000, 51), got3);
  const fbBusy = seedVideo(db, mp4(4000, 52), got3);
  [noFb, all4, fbBusy].forEach(function (v) {
    db.t.instagram_posts.push({ id: uuid(), user_id: USER, proposal_id: uuid(), kind: "reel", status: "published", media_id: "18000000000000001", published_at: iso(now - 600000), video_id: v.id, created_at: iso(now - 700000), updated_at: iso(now - 600000) });
  });
  [all4, fbBusy].forEach(function (v) {
    db.t.facebook_posts.push({ id: uuid(), user_id: USER, proposal_id: uuid(), kind: "video", status: "published", post_id: "2000000000000001", published_at: iso(now - 600000), video_id: v.id, created_at: iso(now - 700000), updated_at: iso(now - 600000) });
  });
  db.t.facebook_posts.push({ id: uuid(), user_id: USER, proposal_id: uuid(), kind: "video", status: "publishing", video_id: fbBusy.id, created_at: iso(now - 300000), updated_at: iso(now - 300000) });
  const tickV = await MV.retentionTick({ supabase: db, storage: db.storage, now: function () { return now; } }, now);
  const vrow = function (id) { return db.t.member_videos.filter(function (x) { return x.id === id; })[0]; };
  check("L1. retention: YouTube, TikTok and Instagram have it but Facebook doesn't: the file kept", !!db.storage.objects["bf-video/" + noFb.path] && vrow(noFb.id).status === "ready", J(tickV));
  check("L2. ...all four have it: the file deleted at once, status uploaded", !db.storage.objects["bf-video/" + all4.path] && vrow(all4.id).status === "uploaded" && vrow(all4.id).path === null, J(vrow(all4.id)));
  check("L3. ...another Facebook post of it still publishing: kept", !!db.storage.objects["bf-video/" + fbBusy.path] && vrow(fbBusy.id).status === "ready");
  db = makeDb();
  const holdV = seedVideo(db, mp4(4000, 54));
  db.t.facebook_posts.push({ id: uuid(), user_id: USER, proposal_id: uuid(), kind: "video", status: "creating", video_id: holdV.id, created_at: iso(now), updated_at: iso(now) });
  const delHold = await MV.deleteVideo({ supabase: db, storage: db.storage }, USER, holdV.id);
  const namedV = seedVideo(db, mp4(4000, 55));
  db.t.agent_proposals.push({ id: uuid(), user_id: USER, action_type: "publish_facebook_post", status: "pending", payload: videoPayload(namedV) });
  const delNamed = await MV.deleteVideo({ supabase: db, storage: db.storage }, USER, namedV.id);
  check("L4. deleting a video: refused while a Facebook post of it is sending (409 facebook_publishing) or a pending Facebook proposal names it (409 in_proposal)",
    delHold.status === 409 && delHold.body.code === "facebook_publishing" && !!db.storage.objects["bf-video/" + holdV.path] && delNamed.status === 409 && delNamed.body.code === "in_proposal" &&
    !!db.storage.objects["bf-video/" + namedV.path], J([delHold, delNamed]));
  db = makeDb();
  const lib1 = seedPhoto(db, jpeg(3000, 60));
  const lib2 = seedPhoto(db, jpeg(3000, 61));
  const lib3 = seedPhoto(db, jpeg(3000, 62));
  db.t.agent_proposals.push({ id: uuid(), user_id: USER, action_type: "publish_facebook_post", status: "pending", payload: photoPayload([lib1]) });
  const liveProp = { id: uuid(), user_id: USER, action_type: "publish_facebook_post", status: "executed", payload: photoPayload([lib2, lib1]) };
  db.t.agent_proposals.push(liveProp);
  db.t.facebook_posts.push({ id: uuid(), user_id: USER, proposal_id: liveProp.id, kind: "photos", status: "publishing", created_at: iso(now), updated_at: iso(now) });
  const doneProp = { id: uuid(), user_id: USER, action_type: "publish_facebook_post", status: "executed", payload: photoPayload([lib3]) };
  db.t.agent_proposals.push(doneProp);
  db.t.facebook_posts.push({ id: uuid(), user_id: USER, proposal_id: doneProp.id, kind: "photo", status: "published", post_id: PAGE_A + "_4000000000000009", published_at: iso(now), created_at: iso(now), updated_at: iso(now) });
  const u1 = await attempt(MM.findUses(db, USER, lib1.path, BASE));
  const u2 = await attempt(MM.findUses(db, USER, lib2.path, BASE));
  const u3 = await attempt(MM.findUses(db, USER, lib3.path, BASE));
  const isFb = function (x) { return x.ok && x.v.some(function (u) { return u.place === "A Facebook post waiting for approval or still publishing" && u.title === "Facebook"; }); };
  check("L5. the Media Library: a photo in a pending Facebook post, or one Facebook may still be fetching, is in use (so not deleted); a published one is not",
    isFb(u1) && isFb(u2) && u3.ok && !isFb(u3), J([u1.ok ? u1.v : u1.msg, u2.ok ? u2.v : u2.msg, u3.ok ? u3.v : u3.msg]));
  check("L6. FILE_ACTIONS and namesVideo know the Facebook post (payload.video.id); FACEBOOK_HOLDING is creating and publishing",
    MV.namesVideo(videoPayload(namedV), namedV.id) === true && MV.FACEBOOK_HOLDING.join() === "creating,publishing");

  /* ── P ── */
  OUT("\n══ P. the pages ══");
  const LINES = [
    "<p class=\"bsky-quiet\">Connect a Facebook Page you manage and prepare a post: text, photos from your Media Library, or a video from Your videos. Nothing goes to Facebook until you approve it on the proposals page.</p>",
    "<p class=\"bsky-quiet\">Photos must be JPEG, PNG or GIF. Videos must be MP4 or MOV.</p>",
    "<p class=\"bsky-quiet\">Removing a post from your Page waits for your approval too.</p>",
    "<p class=\"bsky-warn\" id=\"fbUnavailable\" hidden>Facebook connection isn't set up yet.</p>",
    "<h3 class=\"section-label\">Prepare Facebook post</h3>",
    "<button type=\"button\" class=\"action-btn\" id=\"fbConnectBtn\">Connect Facebook</button>",
    "<button type=\"button\" class=\"action-btn action-btn--ghost\" id=\"fbDraftBtn\">Draft with AI</button>",
    "<button type=\"button\" class=\"action-btn\" id=\"fbFileBtn\">File for approval</button>",
    "<h3 class=\"section-label\">Recent Facebook posts</h3>"];
  check("P1. the Social page: the Facebook panel's lines word for word, and facebook.js loaded right after instagram.js",
    LINES.every(function (l) { return FILES.page.split(l).length === 2; }) && FILES.page.indexOf("id=\"fbConnect\"") !== -1 &&
    FILES.page.indexOf("<script src=\"/scripts/instagram.js\"></script>\n<script src=\"/scripts/facebook.js\"></script>") !== -1,
    LINES.filter(function (l) { return FILES.page.split(l).length !== 2; }).join(" | "));
  check("P2. the other-platforms line: X and LinkedIn still coming; Instagram and a Facebook Page connect below, approval only (Facebook no longer \"coming\")",
    FILES.page.indexOf("<p class=\"bsky-quiet\" id=\"bskyOtherPlatforms\">X and LinkedIn are coming, through each platform's own sign-in. Instagram and a Facebook Page can be connected below, and every post to them waits for your approval.</p>") !== -1 &&
    !/Facebook (is|are) coming/.test(FILES.page));
  const icard = function (name) { return (new RegExp("<p class=\"int-card-name\">" + name + "</p>\\s*<p class=\"int-card-desc\">([^<]*)</p>\\s*<span class=\"int-status\">([^<]*)</span>").exec(FILES.integrations) || []); };
  check("P3. Integrations: Facebook is On the Social page, in its own words; the Content page's intro says a Facebook Page connects there, approval only",
    icard("Facebook")[2] === "On the Social page" &&
    icard("Facebook")[1] === "Connect a Facebook Page you manage on the Social Agent page, through Facebook's own sign-in, and publish the text, photos and videos you approve. Every post, and every removal, waits for your approval." &&
    FILES.content.indexOf(" A Facebook Page connects there too, through Facebook's own sign-in, and every Facebook post waits for your approval.</p>") !== -1 &&
    !/Facebook is coming/.test(FILES.content), J([icard("Facebook")[2]]));
  let dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers(), "facebook");
  await flush();
  const finCall = dom.fetches.filter(function (x) { return x.path === "/api/facebook/finish"; })[0];
  const finIdx = dom.events.indexOf("fetch:POST /api/facebook/finish"), rsIdx = dom.events.indexOf("replaceState:" + PAGE_PATH);
  check("P4. back from Facebook (marker facebook): code and state POSTed to finish, then the query stripped, the marker cleared, \"Connected.\", \"Posting to <Page>\"",
    !!finCall && J(finCall.body) === J({ code: CODE, state: "S".repeat(43) }) && finIdx !== -1 && rsIdx > finIdx && dom.session.bf_oauth_return === undefined &&
    dom.get("fbConnectMsg").textContent === "Connected." && dom.get("fbName").textContent === "Posting to " + NAME_A && dom.get("fbPrepare").hidden === false, dom.events.join(","));
  const CHOOSING = { facebook_available: true, connected: false, choosing: true, status: "choosing", page_name: null, since: "2026-11-07T10:00:00.000Z", reconnect_message: null,
    pages: [{ page_id: PAGE_A, name: NAME_A }, { page_id: PAGE_B, name: NAME_B }] };
  dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers({ "POST /api/facebook/finish": { status: 200, body: CHOOSING },
    "POST /api/facebook/choose-page": { status: 200, body: Object.assign({}, STATUS_CONNECTED, { page_name: NAME_B }) } }), "facebook");
  await flush();
  const optsP = dom.get("fbPageSelect").children;
  const chooserShown = dom.get("fbChoosing").hidden === false && dom.get("fbPrepare").hidden === true && optsP.length === 3 && optsP[1].value === PAGE_A && optsP[2].textContent === NAME_B &&
    dom.get("fbConnectMsg").textContent === "Signed in. Choose the Page to post to.";
  dom.get("fbPageSelect").value = PAGE_B;
  dom.get("fbChooseBtn").click();
  await flush();
  const chCall = dom.fetches.filter(function (x) { return x.path === "/api/facebook/choose-page"; })[0];
  check("P5. several Pages: the chooser lists them by name (textContent); \"Use this Page\" POSTs exactly that page_id, then \"Posting to\" it",
    chooserShown && !!chCall && J(chCall.body) === J({ page_id: PAGE_B }) && dom.get("fbName").textContent === "Posting to " + NAME_B, J([chooserShown, chCall && chCall.body]));
  dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers(), "instagram");
  await flush();
  check("P6. Instagram's return (marker instagram): Facebook neither finishes nor strips it", !dom.fetches.some(function (x) { return x.path === "/api/facebook/finish"; }) &&
    dom.events.indexOf("replaceState:" + PAGE_PATH) === -1);
  dom = runPage("?error=access_denied&state=" + "S".repeat(43), pageAnswers(), "facebook");
  await flush();
  check("P7. cancelled at Facebook: stripped, \"You cancelled the Facebook sign-in.\", no finish", dom.get("fbConnectMsg").textContent === "You cancelled the Facebook sign-in." &&
    dom.events.indexOf("replaceState:" + PAGE_PATH) !== -1 && !dom.fetches.some(function (x) { return x.path === "/api/facebook/finish"; }));
  const NOT_CONNECTED = { facebook_available: true, connected: false, choosing: false, status: "not_connected" };
  dom = runPage("", pageAnswers({ "GET /api/facebook/status": { status: 200, body: NOT_CONNECTED },
    "POST /api/facebook/start": { status: 200, body: { authorize_url: "https://www.facebook.com.evil.example/v26.0/dialog/oauth?x=1" } } }));
  await flush();
  dom.get("fbConnectBtn").click();
  await flush();
  const evilAssigned = dom.assigned.slice();
  dom = runPage("", pageAnswers({ "GET /api/facebook/status": { status: 200, body: NOT_CONNECTED } }));
  await flush();
  dom.get("fbConnectBtn").click();
  await flush();
  check("P8. Connect: only a www.facebook.com/v26.0/dialog/oauth address is followed, after the marker is set to facebook", evilAssigned.length === 0 &&
    dom.assigned.length === 1 && dom.assigned[0].indexOf("https://www.facebook.com/v26.0/dialog/oauth?") === 0 && dom.session.bf_oauth_return === "facebook", J([evilAssigned, dom.assigned, dom.session]));
  dom = runPage("", pageAnswers({ "GET /api/facebook/status": { status: 200, body: { facebook_available: false, connected: false, choosing: false, status: "not_connected" } } }));
  await flush();
  check("P9. not set up: the not-set-up line shown, Connect disabled, nothing to prepare", dom.get("fbUnavailable").hidden === false && dom.get("fbConnectBtn").disabled === true &&
    dom.get("fbPrepare").hidden === true);
  const HOSTILE = "<img src=x onerror=alert(1)>";
  const goodId = uuid();
  dom = runPage("", pageAnswers({ "GET /api/facebook/posts": { status: 200, body: { posts: [
    { id: uuid(), kind: "text", status: "published", permalink: "https://evil.example/p/1", error: null, created_at: "2026-11-07T10:00:00.000Z", removed_at: null },
    { id: goodId, kind: "photo", status: "published", permalink: "https://www.facebook.com/1000000000000001/posts/42", error: null, created_at: "2026-11-07T10:00:00.000Z", removed_at: null },
    { id: uuid(), kind: "photos", status: "failed", permalink: null, error: HOSTILE, created_at: "2026-11-07T10:00:00.000Z", removed_at: null },
    { id: uuid(), kind: "video", status: "publishing", permalink: null, error: null, created_at: "2026-11-07T10:00:00.000Z", removed_at: null },
    { id: uuid(), kind: "text", status: "published", permalink: "https://www.facebook.com/1000000000000001/posts/43", error: null, created_at: "2026-11-07T10:00:00.000Z", removed_at: "2026-11-07T11:00:00.000Z" }] } },
    ["POST /api/facebook/posts/" + goodId + "/propose-delete"]: { status: 201, body: { note: "Filed for approval. Nothing was removed yet." } } }));
  await flush();
  const list = dom.get("fbPostList");
  const links = findAll(list, function (n) { return n.tagName === "A"; });
  const checks = findAll(list, function (n) { return n.tagName === "BUTTON" && n.textContent === "Check status"; });
  const removes = findAll(list, function (n) { return n.tagName === "BUTTON" && n.textContent === "Remove from Facebook"; });
  check("P10. recent posts: only a www.facebook.com address is a link (not once removed); an error is text; \"Check status\" not on a failed or removed post; Remove only on a live published one",
    links.length === 1 && links[0].href === "https://www.facebook.com/1000000000000001/posts/42" && list.textContent.indexOf(HOSTILE) !== -1 && checks.length === 3 && removes.length === 2 &&
    list.textContent.indexOf("then removed from Facebook") !== -1, J([links.map(function (l) { return l.href; }), checks.length, removes.length]));
  const goodLi = list.children[1];
  const goodRemove = findAll(goodLi, function (n) { return n.tagName === "BUTTON" && n.textContent === "Remove from Facebook"; })[0];
  goodRemove.click();
  await flush();
  const filedEarly = dom.fetches.filter(function (x) { return /propose-delete$/.test(x.path); }).length;
  const yes = findAll(goodLi, function (n) { return n.tagName === "BUTTON" && n.textContent === "Yes, file the removal"; })[0];
  yes.click();
  await flush();
  const filedDel = dom.fetches.filter(function (x) { return /propose-delete$/.test(x.path); });
  check("P11. \"Remove from Facebook\" asks first: nothing filed on the first click; \"Yes, file the removal\" files it for approval and shows the server's note",
    filedEarly === 0 && filedDel.length === 1 && filedDel[0].path === "/api/facebook/posts/" + goodId + "/propose-delete" && filedDel[0].method === "POST" &&
    goodLi.textContent.indexOf("Filed for approval. Nothing was removed yet.") !== -1, J([filedEarly, filedDel]));
  check("P12. no innerHTML anywhere: nothing set with it in these runs, and facebook.js and oauth-return.js never name it", dom.innerHTML.length === 0 &&
    !/innerHTML/.test(stripComments(FILES.ui)) && !/innerHTML/.test(stripComments(FILES.oauth)));
  const pickWebp = { item: { id: uuid(), mime: "image/webp", url: "https://check.supabase.co/x.webp", label: "Logo", alt_text: "" } };
  const pickGif = { item: { id: uuid(), mime: "image/gif", url: "https://check.supabase.co/x.gif", label: "Sign", alt_text: "" } };
  const pickJpeg = { item: { id: uuid(), mime: "image/jpeg", url: "https://check.supabase.co/x.jpg", label: "Cakes", alt_text: "Three cakes" } };
  dom = runPage("", pageAnswers(), null, { picker: [pickWebp, pickGif, pickJpeg] });
  await flush();
  dom.get("fbAddPhoto").click();
  await flush();
  const webpMsg = dom.get("fbPrepareMsg").textContent;
  dom.get("fbAddPhoto").click();
  await flush();
  dom.get("fbAddPhoto").click();
  await flush();
  dom.get("fbKindPhotos").checked = true;
  dom.get("fbKindPhotos").fire("change");
  dom.get("fbMessage").value = "Spring cakes.";
  dom.get("fbFileBtn").click();
  await flush();
  const filed = dom.fetches.filter(function (x) { return x.path === "/api/facebook/propose-post"; })[0];
  check("P13. a WebP picked: refused with Facebook's WebP words; a GIF and a JPEG listed; filed with exactly what was chosen, in order",
    webpMsg === "Facebook doesn't accept WebP photos. Choose a JPEG, PNG or GIF." && !!filed &&
    J(filed.body) === J({ kind: "photos", message: "Spring cakes.", media_ids: [pickGif.item.id, pickJpeg.item.id] }), J([webpMsg, filed && filed.body]));
  dom = runPage("", pageAnswers({ "GET /api/videos": { status: 200, body: { videos: [
    { id: uuid(), status: "ready", mime: "video/mp4", bytes: 3000000, label: "Cakes" }, { id: uuid(), status: "ready", mime: "video/webm", bytes: 3000000, label: "Bread" }] } } }));
  await flush();
  dom.get("fbKindVideo").checked = true;
  dom.get("fbKindVideo").fire("change");
  await flush();
  const opts = dom.get("fbVideo").children;
  check("P14. a video: MP4 choosable, a WebM shown but not choosable, with Facebook's video words", opts.length === 3 && opts[1].disabled === false && opts[2].disabled === true &&
    opts[2].textContent.indexOf("Facebook videos must be MP4 or MOV.") !== -1, J(opts.map(function (o) { return [o.textContent, o.disabled]; })));
  // the proposal cards
  const fnSrc = function (name) { const a = FILES.proposals.indexOf("function " + name + "("); return a === -1 ? "" : FILES.proposals.slice(a, MUT.braceMatch(FILES.proposals, FILES.proposals.indexOf("{", a))); };
  const kindLine = (/var FACEBOOK_KIND_WORDS = [^\n]*\n/.exec(FILES.proposals) || [""])[0];
  const pctx = { String: String, Number: Number, Array: Array, Object: Object, isFinite: isFinite, Math: Math, API_URL: "https://api.example", token: "tok" };
  vm.createContext(pctx);
  let cardOk = true;
  try { vm.runInContext([fnSrc("escapeHtml"), fnSrc("youtubeSize"), kindLine, fnSrc("facebookPostPayloadFields"), fnSrc("facebookDeletePayloadFields"), fnSrc("facebookResultHtml")].join("\n"), pctx); } catch (e) { cardOk = false; }
  const card = cardOk ? pctx.facebookPostPayloadFields({ kind: "photos", items: [{ id: "a\"b" }], message: HOSTILE + " cakes", page_id: PAGE_A }) : "";
  const vcard = cardOk ? pctx.facebookPostPayloadFields({ kind: "video", video: { id: "v\"1", bytes: 3000000 }, message: "x", page_id: HOSTILE }) : "";
  const dcard = cardOk ? pctx.facebookDeletePayloadFields({ facebook_post_id: uuid(), post_id: HOSTILE, page_id: PAGE_A }) : "";
  check("P15. the proposal cards: every value escaped (the message, the photo id, the video id, the Page id, the post id), the kind in words",
    cardOk && card.indexOf("<img src=x") === -1 && card.indexOf("&lt;img src=x onerror=alert(1)&gt; cakes") !== -1 && card.indexOf("data-pf-media-id=\"a&quot;b\"") !== -1 &&
    card.indexOf("several photos") !== -1 && vcard.indexOf("data-ig-video-id=\"v&quot;1\"") !== -1 && vcard.indexOf("<img src=x") === -1 && dcard.indexOf("<img src=x") === -1 &&
    dcard.indexOf("&lt;img") !== -1, card.slice(0, 300));
  const goodRes = cardOk ? pctx.facebookResultHtml({ published: true, permalink: "https://www.facebook.com/1000000000000001/posts/42" }) : "";
  const badRes = cardOk ? pctx.facebookResultHtml({ published: true, permalink: "javascript:alert(1)" }) : "";
  const offRes = cardOk ? pctx.facebookResultHtml({ published: true, permalink: "https://evil.example/x" }) : "";
  check("P16. ...the result: only a www.facebook.com address drawn as a link; a removal says so", /href="https:\/\/www\.facebook\.com\/1000000000000001\/posts\/42"/.test(goodRes) &&
    badRes.indexOf("href=") === -1 && badRes.indexOf("javascript") === -1 && offRes.indexOf("href=") === -1 &&
    (cardOk ? pctx.facebookResultHtml({ removed: true }) : "").indexOf("Removed from Facebook") !== -1, badRes);
  check("P17. ...wired: both payload branches and the result branch", FILES.proposals.indexOf("fieldsHtml = facebookPostPayloadFields(p.payload || {});") !== -1 &&
    FILES.proposals.indexOf("fieldsHtml = facebookDeletePayloadFields(p.payload || {});") !== -1 && FILES.proposals.indexOf("execHtml = facebookResultHtml(p.execution_result);") !== -1);
  // the guide
  const MAP = JSON.parse(FILES.appMap);
  const steps = function (text) { return GA.verifyGuideAnswer(MAP, { steps: [{ text: text, page: "integrations.html", control_id: null }, { text: "Open Integrations.", page: "integrations.html", control_id: null }] }, "connect"); };
  const gFb = steps("Connect your Facebook account here."), gTt = steps("Connect your TikTok account here."), gYt = steps("Connect your YouTube account here."),
    gIg = steps("Connect your Instagram account here."), gLi = steps("Connect your LinkedIn account here.");
  check("P18. the guide: connecting Facebook, TikTok, YouTube or Instagram is no longer dropped as a false promise; LinkedIn still is",
    [gFb, gTt, gYt, gIg].every(function (x) { return x.dropped === 0 && x.steps.length === 2; }) && gLi.dropped === 1 && gLi.steps.length === 1,
    J([gFb.dropped, gTt.dropped, gYt.dropped, gIg.dropped, gLi.dropped]));
  check("P19. the guide's tips: Facebook Pages named as connecting; Zernio and two of the six social platforms",
    FILES.guide.indexOf("Bluesky, Mastodon, YouTube, TikTok, Instagram and Facebook Pages connect so far, and posts cannot be scheduled") !== -1 &&
    FILES.guide.indexOf("Zernio and two of the six social platforms it posted to") !== -1 && !/Facebook (is|are) coming/.test(FILES.guide));
  // Instagram's 5 hashtags
  const tags = function (n) { return Array.from({ length: n }, function (_, i) { return "#tag" + i; }).join(" "); };
  const igLimits = { max: 2200 };
  check("P20. Instagram's limit is 5 hashtags (since Dec 2025): 5 accepted, 6 refused; the draft instruction and the measure use it; the page says so",
    IGA.HASHTAG_MAX === 5 && IGA.checkCaption(tags(5), igLimits).ok === true && IGA.checkCaption(tags(6), igLimits).ok === false &&
    FILES.server.split("ig.HASHTAG_MAX").length - 1 >= 2 && FILES.page.split("<p class=\"bsky-quiet\">Instagram allows up to 5 hashtags per post.</p>").length === 2,
    J([IGA.HASHTAG_MAX, IGA.checkCaption(tags(6), igLimits).ok]));

  /* ── G ── */
  OUT("\n══ G. legal, yourData, README, registries, the migration ══");
  const PRIVACY = "If you connect Facebook, BizForce stores the name and id of the Page you choose and the access Facebook grants BizForce for that Page, encrypted, and uses that access only to publish or remove a post when you approve it and to check its status. To publish, BizForce gives Facebook the address of each photo you chose from your Media Library, or a private link to your video that stops working after 2 hours, together with the text you approve. You can disconnect at any time, and everything is deleted with your account.";
  const TERMS = "If you post to a Facebook Page through BizForce, you confirm you are allowed to post for that Page, that you have the rights to what you post, and that it follows Facebook's rules.";
  const esc = function (t) { return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); };
  let built = null;
  try { built = LP.buildLegalPages(); } catch (e) { built = null; }
  const bp = built ? built["privacy.html"] : "", bt = built ? built["terms.html"] : "";
  check("G1. the privacy sentence word for word, once, right after Instagram's", LP.FACEBOOK_PRIVACY_SENTENCE === PRIVACY && bp.split(esc(PRIVACY)).length === 2 &&
    bp.indexOf(esc(LP.INSTAGRAM_PRIVACY_SENTENCE)) !== -1 && bp.indexOf(esc(LP.INSTAGRAM_PRIVACY_SENTENCE)) < bp.indexOf(esc(PRIVACY)));
  check("G2. the terms sentence word for word, once, right after Instagram's", LP.FACEBOOK_TERMS_SENTENCE === TERMS && bt.split(esc(TERMS)).length === 2 &&
    bt.indexOf(esc(LP.INSTAGRAM_TERMS_SENTENCE)) !== -1 && bt.indexOf(esc(LP.INSTAGRAM_TERMS_SENTENCE)) < bt.indexOf(esc(TERMS)));
  check("G3. privacy.html and terms.html carry both, as built, and Facebook (Meta) is a named third party", FILES.privacy.split(esc(PRIVACY)).length === 2 &&
    FILES.terms.split(esc(TERMS)).length === 2 && FILES.privacy.indexOf(esc("Facebook (Meta) (publishing the posts you approve to the Facebook Page you connect)")) !== -1);
  const LEGAL = realRequire("./lib/legal");
  // NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE Nov 7 2026, this change's date. AFTER Nov 8 2026, the version
  // the Etsy privacy sentence set (this change still set Nov 7).
  // NAMED (Nov 14 2026, L1): BEFORE "2026-11-08". AFTER "2026-11-14", the version L1's Google and YouTube, renewal-email and Do Not Track text set.
  check("G4. TERMS_VERSION is the latest change's, Nov 14 2026 (L1; this change set Nov 7)", LEGAL.TERMS_VERSION === "2026-11-14", LEGAL.TERMS_VERSION);
  const YD = compile(FILES.yourData, "lib/yourData.js", {});
  const ydOf = function (t) { return (YD.DATA || []).filter(function (e) { return e.table === t; })[0] || {}; };
  check("G5. yourData: the Page exported as its name and date only, the posts without ids (keyed by created_at); Facebook (Meta) a third party; the never-exported lines; the delete order; the sign-in states",
    ydOf("member_facebook_pages").select === "page_name, created_at" && ydOf("member_facebook_pages").key === "created_at" && ydOf("member_facebook_pages").group === "account" &&
    ydOf("facebook_posts").select === "kind, status, permalink, created_at, published_at, removed_at" && ydOf("facebook_posts").key === "created_at" &&
    FILES.yourData.indexOf("{ name: \"Facebook (Meta)\", for: \"publishing the posts you approve to the Facebook Page you connect\" }") !== -1 &&
    FILES.yourData.indexOf("\"Your Facebook Page access and the Page's id: stored encrypted; the export shows only the Page's name and the date you connected.\"") !== -1 &&
    FILES.yourData.indexOf("\"Your Facebook posts' ids at Facebook: the export lists each post's kind, status, Facebook address and dates.\"") !== -1 &&
    FILES.yourData.indexOf("\"instagram_posts\", \"facebook_posts\", \"member_media\", \"member_videos\"") !== -1 &&
    FILES.yourData.indexOf("\"member_instagram_connections\", \"member_facebook_pages\", \"oauth_states\"") !== -1 &&
    // NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE "..., Connect Instagram and Connect Facebook". AFTER the line
    // names Connect Etsy last; Connect Facebook is still required in it.
    // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE "..., Connect Facebook and Connect Etsy". AFTER Connect
    // Amazon is named last; Connect Facebook is still required in it.
    FILES.yourData.indexOf("Connect YouTube, Connect TikTok, Connect Instagram, Connect Facebook, Connect Etsy and Connect Amazon") !== -1, J([ydOf("facebook_posts").key, ydOf("member_facebook_pages").select]));
  check("G6. schemaCheck knows both tables at 180; the backup leaves the Page access out and skips the posts",
    FILES.schema.indexOf("[\"member_facebook_pages\", \"180_facebook_pages.sql\"],") !== -1 && FILES.schema.indexOf("[\"facebook_posts\", \"180_facebook_pages.sql\"],") !== -1 &&
    FILES.backup.indexOf("member_facebook_pages: \"members' Facebook Page access, sealed; members connect again\",") !== -1 && /\n  facebook_posts: +"/.test(FILES.backup));
  const fbs = (FILES.readme.split("## Facebook Pages setup")[1] || "").split("\n## ")[0];
  check("G7. README: the two env var rows (the secret only on Railway) and the Facebook Pages setup (Facebook Login for Business, the three scopes, the exact redirect URI, App Review and Business verification); the cleanup job row",
    /\n\| `FACEBOOK_APP_ID` \| none \| /.test(FILES.readme) && /\n\| `FACEBOOK_APP_SECRET` \| none \| [^\n]*only on Railway/.test(FILES.readme) &&
    fbs.indexOf("Facebook Login for Business") !== -1 && /`pages_show_list`, `pages_manage_posts` and `pages_read_engagement`/.test(fbs) &&
    fbs.indexOf("exactly `https://bizforceai.net/agents/social.html`") !== -1 && /App Review/.test(fbs) && /Business verification/.test(fbs) && /only on Railway/.test(fbs) &&
    FILES.readme.indexOf("| `choosingPurgeTick` (`lib/facebookApi.js`)") !== -1);
  check("G8. migration 180: the header, both tables with RLS on and nothing granted; facebook_login in the purpose check and the verifier rule; one row per proposal; the published, removed and shape rules",
    FILES.migration.indexOf("-- Applied by the owner by hand in the Supabase SQL editor on Nov 7, 2026. This file is the text as run.\n") === 0 &&
    FILES.migration.indexOf("ALTER TABLE public.member_facebook_pages ENABLE ROW LEVEL SECURITY;") !== -1 && FILES.migration.indexOf("REVOKE ALL ON public.member_facebook_pages FROM anon, authenticated;") !== -1 &&
    FILES.migration.indexOf("ALTER TABLE public.facebook_posts ENABLE ROW LEVEL SECURITY;") !== -1 && FILES.migration.indexOf("REVOKE ALL ON public.facebook_posts FROM anon, authenticated;") !== -1 &&
    FILES.migration.indexOf("CHECK (purpose IN ('mailbox_microsoft', 'store_shopify', 'youtube_google', 'tiktok_login', 'instagram_login', 'facebook_login'))") !== -1 &&
    FILES.migration.indexOf("purpose IN ('store_shopify', 'tiktok_login', 'instagram_login', 'facebook_login')") !== -1 && FILES.migration.indexOf("proposal_id uuid NOT NULL UNIQUE,") !== -1 &&
    FILES.migration.indexOf("CHECK ((status = 'published') = (post_id IS NOT NULL AND published_at IS NOT NULL))") !== -1 &&
    FILES.migration.indexOf("CHECK (removed_at IS NULL OR status = 'published')") !== -1 && FILES.migration.indexOf("CONSTRAINT member_facebook_pages_shape_check CHECK (") !== -1 &&
    FILES.migration.indexOf("user_id uuid NOT NULL UNIQUE REFERENCES public.users(id) ON DELETE CASCADE,") !== -1);
  const pageSection = (/<section class="context-card bsky-card" id="fbConnect"[\s\S]*?<\/section>/.exec(FILES.page) || [""])[0];
  check("G9. no emoji in any Facebook file", [FILES.auth, FILES.api, FILES.ui, FB_SECTION, FILES.migration, pageSection].every(function (s) { return !EMOJI.test(s); }) && pageSection.length > 1000);
  check("G10. only FACEBOOK_APP_ID and FACEBOOK_APP_SECRET are read for Facebook (and SUPABASE_URL for the photo address)",
    (stripComments(FB_SECTION).match(/process\.env\.[A-Z_]+/g) || []).every(function (x) { return x === "process.env.SUPABASE_URL"; }) &&
    (stripComments(FILES.auth).match(/env\.[A-Z_]+/g) || []).sort().join() === "env.FACEBOOK_APP_ID,env.FACEBOOK_APP_ID,env.FACEBOOK_APP_SECRET,env.FACEBOOK_APP_SECRET" &&
    !/process\.env/.test(stripComments(FILES.api)));
  check("G11. videoPlatformConfigured counts Facebook (Your videos opens when any video platform is set up)",
    /function videoPlatformConfigured\(\) \{[\s\S]*?require\("\.\/lib\/facebookAuth"\)\.configured\(process\.env\) !== null;\n\}/.test(FILES.server));
  const migFiles = fs.readdirSync(path.join(REPO, "supabase", "migrations")).filter(function (x) { return /^\d{3}_.*\.sql$/.test(x); });
  const highest = migFiles.map(function (x) { return Number(x.slice(0, 3)); }).reduce(function (acc, x) { return Math.max(acc, x); }, 0);
  /* NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE "180_facebook_pages.sql is the highest migration and the
     only 180". AFTER it is the only 180, and only 181_etsy_store.sql is above it, by name; "the highest" is checkEtsyConnect R1's.
     NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE only 181_etsy_store.sql was above it and 181 the highest.
     AFTER 181_etsy_store.sql and 182_amazon_store.sql are above it, by name; "the highest" is checkAmazonConnect R1's. */
  // NAMED (Nov 11 2026, orbit stage 2), migration 183): it adds 183_weekly_goal_and_order_status.sql above, by name; "the highest" is checkOrbitStage2 R1's.
  check("R1. 180_facebook_pages.sql is the only 180, and only 181_etsy_store.sql, 182_amazon_store.sql and 183_weekly_goal_and_order_status.sql are above it (checkOrbitStage2 R1)", highest === 183 &&
    migFiles.filter(function (x) { return /^180_/.test(x); }).join() === "180_facebook_pages.sql" &&
    migFiles.filter(function (x) { return Number(x.slice(0, 3)) > 180; }).join() === "181_etsy_store.sql,182_amazon_store.sql,183_weekly_goal_and_order_status.sql", highest);
  check("G12. no secret in any log line of this run", LOGS.every(noSecretIn), J(LOGS.filter(function (l) { return !noSecretIn(l); }).slice(0, 2)));
  check("G13. the network tripwire never fired, and no promise was left rejected", TRIPPED.length === 0 && UNHANDLED.length === 0, J(TRIPPED.concat(UNHANDLED.map(function (e) { return String(e && e.message); }))));

  OUT("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (failures + passes) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
})().catch(function (e) { OUT("    FAIL  the harness stopped: " + ((e && e.stack) || e)); process.exit(1); });
