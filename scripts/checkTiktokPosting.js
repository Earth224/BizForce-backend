/* checkTiktokPosting: TikTok posting (migration 178). Connect TikTok through Login Kit for Web (a single-use state, no
   PKCE), Direct Post with TikTok's posting rules checked at filing and again at execution against a fresh creator_info,
   one video sent as ONE chunk with the publish and the sealed upload URL stored before the PUT, never a second init while
   a valid upload is stored, the file kept until every platform has it, and the Social page's TikTok panel.

   Everything runs offline. lib/tiktokAuth.js, lib/tiktokApi.js, lib/memberVideos.js and lib/guardedFetch.js are loaded
   from their own source (a mutation edits the text first). A fake TikTok answers behind the REAL guarded transport
   (guardedFetch.createGuardedFetch with a stub resolver and request), so the profile rules, the Content-Range and the
   empty 201 are the shipped code's. The database is in memory and enforces migration 178's CHECKs. A network tripwire
   fails the run on any socket, DNS question or fetch: no call reaches TikTok. The routes are server.js's own TikTok
   section, run in a vm. The page is scripts/youtube.js and scripts/tiktok.js together in a fake DOM.

   Sections:
     O. connect: start, finish, status, disconnect, the 503 when unconfigured
     T. tokens: the 5-minute margin, rotation, the compare-and-set, single flight, needs_reconnect
     V. TikTok's posting rules (lib/tiktokApi.js validatePost) and the label and consent lines
     F. filing: propose-post, one pending per video, the caps, the claims screen, draft-caption, never automatic
     U. the post: init, the one PUT, the stored publish, the status words, crash safety, refusals
     S. the stream profiles: tiktok and youtube
     J. retention and deleting a video
     P. the pages: the Social page, the return marker, the posting form, proposals and integrations
     G. legal, yourData, README, registries, the migration; R1, the highest migration.

   Run: node scripts/checkTiktokPosting.js     MUTATE=<name> for one mutation, MUTATE=all for every one. */
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

const MUTATIONS = {
  // NAMED, item 8 part 3a: the Instagram finish route consumes its state with the same lines, so the anchor now carries TikTok's purpose.
  "state-reusable": ["server",
    ".eq(\"purpose\", ta.PURPOSE)\n        .is(\"consumed_at\", null).gt(\"expires_at\", consumedAt)\n        .select(\"id\");", ".eq(\"purpose\", ta.PURPOSE)\n        .gt(\"expires_at\", consumedAt)\n        .select(\"id\");"],
  "scopes-unchecked": ["auth",
    "  if (exchange && !grantsTiktok(j.scope)) throw new TiktokError(\"no_scopes\", \"scope_missing\");\n", ""],
  "unsealed-before-api": ["server",
    "      // Sealed first: both tokens are encrypted before TikTok is asked anything.\n",
    "      await tk.readUser(tiktokDeps(), grant.accessToken).catch(function () { return null; });\n      // Sealed first: both tokens are encrypted before TikTok is asked anything.\n"],
  "refresh-token-dropped": ["api",
    "  if (grant.refreshToken) {\n    var refresh = sealed(deps.crypt, grant.refreshToken);", "  if (false) {\n    var refresh = sealed(deps.crypt, grant.refreshToken);"],
  "refresh-cas-missing": ["api",
    "    .eq(\"id\", row.id).eq(\"user_id\", row.user_id).eq(\"token_version\", version).select(\"id\");", "    .eq(\"id\", row.id).eq(\"user_id\", row.user_id).select(\"id\");"],
  "refresh-expiry-ignored": ["api",
    "  if (isFinite(refreshEnds) && refreshEnds <= deps.now()) {", "  if (false) {"],
  "privacy-defaulted": ["api",
    "  if (typeof b.privacy_level !== \"string\" || !b.privacy_level) return { ok: false, error: MESSAGES.privacyMissing, field: \"privacy_level\" };",
    "  if (typeof b.privacy_level !== \"string\" || !b.privacy_level) b = Object.assign({}, b, { privacy_level: (c.privacy_level_options || [])[0] });"],
  "privacy-not-in-options": ["api",
    "  if ((c.privacy_level_options || []).indexOf(b.privacy_level) === -1) return { ok: false, error: MESSAGES.privacyNotOffered, field: \"privacy_level\" };\n", ""],
  "disabled-interaction-allowed": ["api",
    "    if (v && c[names[i][1]] === true) return { ok: false, error: names[i][2] + \": \" + MESSAGES.interactionOff + \".\", field: names[i][0] };\n", ""],
  "branded-private-allowed": ["api",
    "  if (content && b.privacy_level === SELF_ONLY) return { ok: false, error: MESSAGES.brandedPrivate, field: \"privacy_level\" };\n", ""],
  "disclosure-without-option": ["api",
    "  if (disclose && !organic && !content) return { ok: false, error: MESSAGES.disclosureOption, field: \"disclose\" };\n", ""],
  "consent-line-missing": ["ui",
    "      consent.textContent = paid ? CONSENT_BRANDED : CONSENT;", "      consent.textContent = CONSENT;"],
  "creator-info-not-rechecked": ["api",
    "  var checked = validatePost(postFields(p), creator, deps.limits);", "  var checked = { ok: true, value: postFields(p) };"],
  "sha-unchecked-at-send": ["api",
    "  if (!checked.ok) throw fail(checked.error + \" Nothing was sent.\");\n  if (!(await verifyFile(deps, video))) throw fail(MESSAGES.fingerprint);\n",
    "  if (!checked.ok) throw fail(checked.error + \" Nothing was sent.\");\n"],
  "upload-unsealed": ["api",
    "  var s = sealed(deps.crypt, uploadUrl);", "  var s = { ciphertext: Buffer.from(uploadUrl).toString(\"hex\"), iv: \"0\".repeat(24), authTag: \"0\".repeat(32) };"],
  "second-init-while-valid": ["api",
    "  if (video.tiktok_publish_id) {\n    // A stored publish: ask TikTok first.", "  if (false) {\n    // A stored publish: ask TikTok first."],
  "multi-chunk-sent": ["api",
    "chunk_size: Number(video.bytes), total_chunk_count: 1 }", "chunk_size: Math.ceil(Number(video.bytes) / 2), total_chunk_count: 2 }"],
  "content-range-wrong": ["api",
    "      contentRange: \"bytes 0-\" + (total - 1) + \"/\" + total", "      contentRange: \"bytes 0-\" + total + \"/\" + total"],
  "status-unmapped": ["api",
    "  if (s === \"PROCESSING_UPLOAD\" || s === \"PROCESSING_DOWNLOAD\" || s === \"SEND_TO_USER_INBOX\") return \"processing\";",
    "  if (s === \"PROCESSING_UPLOAD\" || s === \"PROCESSING_DOWNLOAD\") return \"processing\";"],
  "posted-without-complete": ["api",
    "  if (s === \"PUBLISH_COMPLETE\") return \"posted\";", "  if (s === \"PUBLISH_COMPLETE\" || s === \"SEND_TO_USER_INBOX\") return \"posted\";"],
  "tiktok-cap-missing": ["api",
    "  if (await postsToday(deps, userId) >= MV.TIKTOK_POSTS_PER_DAY) return { status: 409, body: { error: MESSAGES.dailyCap, code: \"daily_cap\" } };\n", ""],
  "shared-post-cap": ["api",
    ".eq(\"user_id\", userId).gte(\"tiktok_posted_at\", since);", ".eq(\"user_id\", userId).gte(\"uploaded_at\", since);"],
  "file-deleted-before-both": ["videos",
    "      .not(\"youtube_video_id\", \"is\", null).eq(\"tiktok_status\", \"posted\").limit(PAGE_SIZE);", "      .not(\"youtube_video_id\", \"is\", null).limit(PAGE_SIZE);"],
  "file-kept-forever": ["videos",
    "const READY_DAYS = 14;", "const READY_DAYS = 14000;"],
  "pending-proposal-ignored": ["videos",
    // NAMED, item 8 part 3a: the early delete now also needs a published Instagram reel and no Instagram row holding the file.
    "    var bothRows = (both.data || []).filter(function (r) { return r.path && !named[r.id] && bothIg.published[r.id]", "    var bothRows = (both.data || []).filter(function (r) { return r.path && bothIg.published[r.id]"],
  "wrong-dispatcher": ["server",
    "  publish_tiktok_post: executePublishTiktokPost,\n", "  publish_tiktok_post: executePublishYoutubeVideo,\n"],
  "tiktok-host-unrestricted": ["fetch",
    "  tiktok: Object.freeze({ host: \"open-upload.tiktokapis.com\",", "  tiktok: Object.freeze({ host: STREAM_HOST,"],
  "youtube-profile-loosened": ["fetch",
    "allow308: true, emptyOkStatuses: Object.freeze([]) }),", "allow308: true, emptyOkStatuses: Object.freeze([201, 206]) }),"],
  "upload-url-logged": ["api",
    "  // Sealed and stored BEFORE the PUT:", "  console.log(\"[tiktok] upload \" + uploadUrl);\n  // Sealed and stored BEFORE the PUT:"],
  "auto-executed": ["api",
    "  if (ins.error) throw ins.error;\n  var note = \"Filed for approval.", "  if (ins.error) throw ins.error;\n  await executePublish(deps, ins.data);\n  var note = \"Filed for approval."],
  "unconfigured-not-503": ["server",
    "  return res.status(503).json({ error: require(\"./lib/tiktokAuth\").MESSAGES.notConfigured,", "  return res.status(200).json({ error: require(\"./lib/tiktokAuth\").MESSAGES.notConfigured,"],
  "replacestate-skipped": ["ui",
    "    }).then(function (res) {\n      stripQuery();\n", "    }).then(function (res) {\n"],
  "privacy-sentence-removed": ["legal",
    "      TIKTOK_PRIVACY_SENTENCE,\n", ""],
  "innerHTML-on-page": ["ui",
    "    if (text !== undefined && text !== null) node.textContent = text;", "    if (text !== undefined && text !== null) node.innerHTML = text;"],
  // the others the code earns
  "refresh-not-single-flight": ["api",
    "  var running = refreshesInFlight.get(key);", "  var running = null;"],
  "disconnect-deletes-all-states": ["server",
    "var statesDropped = await supabase.from(\"oauth_states\").delete().eq(\"user_id\", req.user.id).eq(\"purpose\", ta.PURPOSE);",
    "var statesDropped = await supabase.from(\"oauth_states\").delete().eq(\"user_id\", req.user.id);"],
  "open-id-unchecked": ["server",
    "      if (!user || user.open_id !== openId) return", "      if (!user) return"],
  "account-changed-ignored": ["api",
    "  if (conn.open_id !== p.open_id) throw fail(MESSAGES.accountChanged);\n", ""],
  "expired-upload-reused": ["api",
    "    if (!isFinite(ends) || ends <= deps.now()) { await markFailed(deps, video); throw fail(MESSAGES.expired); }\n", ""],
  "tiktok-cap-missing-at-send": ["api",
    "  if (today >= MV.TIKTOK_POSTS_PER_DAY) throw fail(MESSAGES.dailyCap);\n", ""],
  "tiktok-308-allowed": ["fetch",
    "pathPrefix: \"/upload/\", allow308: false,", "pathPrefix: \"/upload/\", allow308: true,"],
  "delete-ignores-tiktok": ["videos",
    // NAMED, item 8 part 3a: FILE_ACTIONS now also names publish_instagram_post.
    "const FILE_ACTIONS = Object.freeze([\"publish_youtube_video\", \"delete_youtube_video\", \"publish_tiktok_post\", \"publish_instagram_post\"]);",
    "const FILE_ACTIONS = Object.freeze([\"publish_youtube_video\", \"delete_youtube_video\", \"publish_instagram_post\"]);"],
  "privacy-defaulted-on-page": ["ui",
    "      opt.value = o;\n      privacy.appendChild(opt);", "      opt.value = o;\n      if (privacy.children.length === 1) { none.selected = false; opt.selected = true; }\n      privacy.appendChild(opt);"],
  "upload-not-whole": ["api",
    "function putComplete(answer) { return !!answer && answer.status === 201; }", "function putComplete(answer) { return !!answer && (answer.status === 201 || answer.status === 206); }"],
  // NAMED, item 8 part 3a: the marker is read once in scripts/oauth-return.js; the mutation now lets the first registered script (YouTube) take TikTok's answer.
  "youtube-marker-ignored": ["oauth",
    "    if (!pending || pending.name !== name) return false;\n", "    if (!pending) return false;\n"]
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
  auth: read("lib/tiktokAuth.js"),
  api: read("lib/tiktokApi.js"),
  videos: read("lib/memberVideos.js"),
  ytapi: read("lib/youtubeApi.js"),
  gauth: read("lib/googleAuth.js"),
  quota: read("lib/youtubeQuota.js"),
  fetch: read("lib/guardedFetch.js"),
  legal: read("lib/legalPages.js"),
  gateRules: read("lib/gateRules.js"),
  migration: read("supabase/migrations/178_tiktok_posting.sql"),
  yourData: read("lib/yourData.js"),
  backup: read("lib/backup.js"),
  schema: read("lib/schemaCheck.js"),
  readme: read("README.md"),
  privacy: readFe("privacy.html"),
  terms: readFe("terms.html"),
  page: readFe("agents/social.html"),
  ui: readFe("scripts/tiktok.js"),
  ytui: readFe("scripts/youtube.js"),
  // NAMED, item 8 part 3a: the shared sign-in return (scripts/oauth-return.js) now reads ?code and ?state for YouTube, TikTok and Instagram.
  oauth: readFe("scripts/oauth-return.js"),
  proposals: readFe("proposals.html"),
  integrations: readFe("integrations.html"),
  guide: readFe("scripts/termaximus-guide.js")
};
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  OUT("\n!! MUTATION: " + MUTATE);
}
["log", "warn", "error", "info"].forEach(function (k) { console[k] = function () { LOGS.push([].slice.call(arguments).map(String).join(" ")); }; });

const J = JSON.stringify;
const SECRET_HEX = crypto.createHash("sha256").update("checkTiktokPosting").digest("hex");
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
/* The TikTok stub of the moment: every request the libraries make goes to it. */
let CURRENT = null;
const GF_PROXY = {
  guardedJsonRequest: function (u, o) { return CURRENT.jsonRequest(u, o); },
  guardedStreamUpload: function (u, o) { return CURRENT.streamUpload(u, o); }
};
const GF = compile(FILES.fetch, "lib/guardedFetch.js", {});
const TA = compile(FILES.auth, "lib/tiktokAuth.js", { "./guardedFetch": GF_PROXY });
const MV = compile(FILES.videos, "lib/memberVideos.js", {});
const GA = compile(FILES.gauth, "lib/googleAuth.js", { "./guardedFetch": GF_PROXY });
const YQ = compile(FILES.quota, "lib/youtubeQuota.js", {});
const YA = compile(FILES.ytapi, "lib/youtubeApi.js", { "./googleAuth": GA, "./memberVideos": MV, "./youtubeQuota": YQ });
const TK = compile(FILES.api, "lib/tiktokApi.js", { "./tiktokAuth": TA, "./memberVideos": MV, "./youtubeApi": YA });
const LP = compile(FILES.legal, "lib/legalPages.js", {});

const CLIENT = { key: "awcheckclientkey" + "1".repeat(8), secret: "check-tiktok-secret-" + "9".repeat(16) };
const CONFIGURED = { TIKTOK_CLIENT_KEY: CLIENT.key, TIKTOK_CLIENT_SECRET: CLIENT.secret };
const USER = "00000000-0000-4000-8000-000000000001";
const OTHER = "00000000-0000-4000-8000-000000000002";
const ACCESS = "act.check-access-" + "a1".repeat(10);
const ACCESS2 = "act.check-access2-" + "b2".repeat(10);
const WINNER = "act.check-winner-" + "c3".repeat(10);
const REFRESH = "rft.check-refresh-" + "d4".repeat(10);
const REFRESH2 = "rft.check-refresh2-" + "e5".repeat(10);
const CODE = "check-code-" + "f6".repeat(10);
const OPEN_ID = "-000check-open-id_1.x";
const OPEN_ID2 = "-000check-open-id_2.y";
const NICK = "Maple Street Bakery";
const DISPLAY = "maplestreet";
const SCOPES = "user.info.basic,video.publish";
const UPLOAD_BASE = "https://open-upload.tiktokapis.com/upload/?upload_id=check-upload-";
const PUBLISH_BASE = "v_pub_file~v2-1.check";
const POST_ID = "7350000000000000001";
const PAGE_PATH = "/agents/social.html";
const REDIRECT = "https://bizforceai.net/agents/social.html";
const SECRETS = [ACCESS, ACCESS2, WINNER, REFRESH, REFRESH2, CODE, CLIENT.secret, "check-upload-"];
function noSecretIn(text) { return SECRETS.every(function (s) { return String(text).indexOf(s) === -1; }); }
const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F2FF}\u{FE0F}]/u;
const NOT_SET_UP = "TikTok connection isn't set up yet.";
const LIMITS = { label: "TikTok", caption_max: 2200, truncates_at: 100, hashtag_practical: 5 };
const OPTIONS = ["PUBLIC_TO_EVERYONE", "MUTUAL_FOLLOW_FRIENDS", "SELF_ONLY"];
const sha = function (b) { return crypto.createHash("sha256").update(b).digest("hex"); };

function filler(n, seed) {
  const out = Buffer.alloc(n);
  let x = seed || 7;
  for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) >>> 0; out[i] = x >>> 24; }
  return out;
}
function mp4(n, seed) {
  const head = Buffer.concat([Buffer.from([0, 0, 0, 0x18]), Buffer.from("ftypisom", "latin1"), Buffer.from([0, 0, 2, 0]), Buffer.from("isomiso2", "latin1")]);
  return Buffer.concat([head, filler(Math.max(0, (n || 4096) - head.length), seed)]);
}

/* ── an in-memory database, with migration 178's CHECKs, and the bf-video bucket ── */
function uuid() { return crypto.randomUUID(); }
const HEX = /^[0-9a-f]+$/;
const EV = [];   // one timeline: database writes, encryptions and TikTok requests, in order
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
  const bucket = {
    download: function (p) {
      return {
        asStream: async function () {
          calls.push({ op: "stream", path: p });
          const o = objects[p];
          if (!o) return { data: null, error: { message: "Object not found", statusCode: "404" } };
          return { data: webStream(o.queue && o.queue.length ? o.queue.shift() : o.buf), error: null };
        }
      };
    },
    remove: async function (paths) {
      calls.push({ op: "remove", paths: paths.slice() });
      paths.forEach(function (p) { delete objects[p]; });
      return { data: paths.map(function (p) { return { name: p }; }), error: null };
    },
    list: async function (prefix) {
      calls.push({ op: "list", prefix: prefix });
      return { data: [], error: null };
    }
  };
  return { from: function (b) { if (b !== "bf-video") throw new Error("unexpected bucket " + b); return bucket; }, objects: objects, calls: calls };
}
function makeDb() {
  // NAMED, item 8 part 3a: instagram_posts added; retention and deleting a video now read it.
  const t = { member_tiktok_connections: [], member_videos: [], oauth_states: [], agent_proposals: [], notifications: [], job_runs: [], business_profiles: [], instagram_posts: [] };
  const fail = {};
  function rows(name) { if (!t[name]) t[name] = []; return t[name]; }
  function sealedOk(c, i, a) { return HEX.test(c || "") && /^[0-9a-f]{24}$/.test(i || "") && /^[0-9a-f]{32}$/.test(a || ""); }
  function uniqueViolation(name, row, except) {
    const others = rows(name).filter(function (r) { return r !== except; });
    if (name === "member_tiktok_connections" && others.some(function (r) { return r.user_id === row.user_id; })) return "member_tiktok_connections_user_id_key";
    if (name === "member_videos" && row.path != null && others.some(function (r) { return r.path === row.path; })) return "member_videos_path_key";
    if (name === "job_runs" && others.some(function (r) { return r.job_name === row.job_name; })) return "job_runs_pkey";
    return null;
  }
  function checkViolation(name, row) {
    if (name === "member_tiktok_connections") {
      if (!/^[A-Za-z0-9_.-]{1,100}$/.test(row.open_id || "")) return "member_tiktok_connections_open_id_check";
      if (!(String(row.display_name || "").length >= 1 && String(row.display_name).length <= 200)) return "member_tiktok_connections_display_name_check";
      if (!sealedOk(row.refresh_ciphertext, row.refresh_iv, row.refresh_auth_tag)) return "member_tiktok_connections_refresh_check";
      if (!sealedOk(row.access_ciphertext, row.access_iv, row.access_auth_tag)) return "member_tiktok_connections_access_check";
      if (!row.access_expires_at) return "member_tiktok_connections_access_expires_at_not_null";
      if (!(Number.isInteger(row.token_version) && row.token_version >= 0)) return "member_tiktok_connections_token_version_check";
      if (row.granted_scopes != null && !(String(row.granted_scopes).length <= 500 && /^[a-z0-9_.,]*$/.test(row.granted_scopes))) return "member_tiktok_connections_scopes_check";
      if (["connected", "needs_reconnect"].indexOf(row.status) === -1) return "member_tiktok_connections_status_check";
      if (row.last_error_code != null && String(row.last_error_code).length > 60) return "member_tiktok_connections_error_code_check";
    }
    if (name === "member_videos") {
      if (["video/mp4", "video/webm", "video/quicktime"].indexOf(row.mime) === -1) return "member_videos_mime_check";
      if (!(Number(row.bytes) > 0 && Number(row.bytes) <= 52428800)) return "member_videos_bytes_check";
      if (!/^[0-9a-f]{64}$/.test(row.sha256 || "")) return "member_videos_sha_check";
      if (["ready", "uploaded", "removed"].indexOf(row.status) === -1) return "member_videos_status_check";
      if (row.status === "ready" && row.path == null) return "member_videos_ready_path_check";
      if (row.tiktok_publish_id != null && !/^[A-Za-z0-9_.~-]{1,64}$/.test(row.tiktok_publish_id)) return "member_videos_tiktok_publish_id_check";
      if (row.tiktok_status != null && ["initiated", "processing", "posted", "failed"].indexOf(row.tiktok_status) === -1) return "member_videos_tiktok_status_check";
      if (row.tiktok_post_id != null && !/^[0-9]{1,64}$/.test(row.tiktok_post_id)) return "member_videos_tiktok_post_id_check";
      const none = row.tiktok_upload_ciphertext == null && row.tiktok_upload_iv == null && row.tiktok_upload_auth_tag == null && row.tiktok_upload_expires_at == null;
      const all = sealedOk(row.tiktok_upload_ciphertext, row.tiktok_upload_iv, row.tiktok_upload_auth_tag) && row.tiktok_upload_expires_at != null;
      if (!none && !all) return "member_videos_tiktok_upload_check";
    }
    if (name === "oauth_states") {
      if (["mailbox_microsoft", "store_shopify", "youtube_google", "tiktok_login"].indexOf(row.purpose) === -1) return "oauth_states_purpose_check";
      if (["store_shopify", "tiktok_login"].indexOf(row.purpose) === -1 && (row.verifier_ciphertext == null || row.verifier_iv == null || row.verifier_auth_tag == null)) return "oauth_states_verifier_shape_check";
      if ((row.purpose === "store_shopify") !== (row.flow_context != null)) return "oauth_states_context_check";
    }
    return null;
  }
  function defaults(name, row) {
    const r = Object.assign({ id: uuid(), created_at: new Date().toISOString() }, row);
    if (name === "member_tiktok_connections") { if (r.status === undefined) r.status = "connected"; if (r.token_version === undefined) r.token_version = 0; }
    if (name === "member_videos") {
      if (r.status === undefined) r.status = "ready";
      ["youtube_video_id", "session_ciphertext", "session_iv", "session_auth_tag", "uploaded_at", "tiktok_publish_id", "tiktok_status", "tiktok_posted_at", "tiktok_post_id",
        "tiktok_upload_ciphertext", "tiktok_upload_iv", "tiktok_upload_auth_tag", "tiktok_upload_expires_at"].forEach(function (k) { if (r[k] === undefined) r[k] = null; });
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
    const q = { op: null, cols: null, count: false, head: false, filters: [], or: null, payload: null, onConflict: null, single: null, returning: false };
    const api = {
      select: function (cols, opts) { if (!q.op) q.op = "select"; else q.returning = true; q.cols = cols; if (opts && opts.count) q.count = true; if (opts && opts.head) q.head = true; return api; },
      insert: function (p) { q.op = "insert"; q.payload = p; return api; },
      update: function (p) { q.op = "update"; q.payload = p; return api; },
      upsert: function (p, o) { q.op = "upsert"; q.payload = p; q.onConflict = o && o.onConflict; return api; },
      delete: function () { q.op = "delete"; return api; },
      eq: function (c, v) { q.filters.push(["eq", c, v]); return api; },
      in: function (c, v) { q.filters.push(["in", c, v]); return api; },
      is: function (c, v) { q.filters.push(["is", c, v]); return api; },
      not: function (c, op, v) { q.filters.push(["not", c, op, v]); return api; },
      gt: function (c, v) { q.filters.push(["gt", c, v]); return api; },
      gte: function (c, v) { q.filters.push(["gte", c, v]); return api; },
      lt: function (c, v) { q.filters.push(["lt", c, v]); return api; },
      or: function (s) { q.or = s; return api; },
      order: function () { return api; }, limit: function () { return api; }, range: function () { return api; },
      maybeSingle: function () { q.single = "maybe"; return api; },
      single: function () { q.single = "one"; return api; },
      then: function (ok, bad) { return Promise.resolve().then(run).then(ok, bad); }
    };
    function match(r) {
      if (!q.filters.every(function (f) {
        if (f[0] === "eq") return String(r[f[1]]) === String(f[2]);
        if (f[0] === "in") return f[2].map(String).indexOf(String(r[f[1]])) !== -1;
        if (f[0] === "is") return f[2] === null ? r[f[1]] == null : r[f[1]] === f[2];
        if (f[0] === "not") return f[2] === "is" && f[3] === null ? r[f[1]] != null : true;
        if (f[0] === "gt") return r[f[1]] != null && String(r[f[1]]) > String(f[2]);
        if (f[0] === "gte") return r[f[1]] != null && String(r[f[1]]) >= String(f[2]);
        if (f[0] === "lt") return r[f[1]] != null && String(r[f[1]]) < String(f[2]);
        return true;
      })) return false;
      if (q.or) { const d = /neq\.(\d{4}-\d{2}-\d{2})/.exec(q.or)[1]; return r.last_run_on == null || r.last_run_on !== d; }
      return true;
    }
    function shape(list) {
      const data = list.map(function (r) { return project(r, q.cols); });
      if (q.single === "maybe") return { data: data[0] || null, error: null };
      if (q.single === "one") return data.length === 1 ? { data: data[0], error: null } : { data: null, error: { code: "PGRST116", message: "not one row" } };
      return { data: q.op === "select" || q.returning ? data : null, error: null };
    }
    function run() {
      if (q.op !== "select") EV.push("db:" + name + ":" + q.op);
      const all = rows(name);
      if (q.op === "select") {
        if (fail[name]) { const e = fail[name]; delete fail[name]; return { data: null, error: e }; }
        const hit = all.filter(match);
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

/* ── TikTok, stubbed behind the real guarded fetcher ────────────────────── */
function reply(status, body, hdrs) {
  const h = {};
  if (body !== null && body !== undefined) h["content-type"] = "application/json; charset=UTF-8";
  Object.keys(hdrs || {}).forEach(function (k) { h[k.toLowerCase()] = String(hdrs[k]); });
  return { status: status, headers: h, raw: body === null || body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body), "utf8") };
}
function headerOf(hdrs, name) {
  const k = Object.keys(hdrs || {}).filter(function (x) { return x.toLowerCase() === name.toLowerCase(); })[0];
  return k ? String(hdrs[k]) : null;
}
const OK = { code: "ok", message: "", log_id: "check" };
const PUBLIC_V4 = "142.250.80.10";
function makeTiktok(opts) {
  const o = Object.assign({}, opts || {});
  const g = { opts: o, requests: [], uploads: {}, n: 0, tokenCalls: [], inits: [], db: o.db || null, atFirstPut: null, bodyPuts: 0, revoked: null };
  function record(method, u, headers, body) {
    const auth = headerOf(headers, "Authorization");
    const entry = { method: method, host: u.hostname, path: u.pathname, search: u.search, url: u.href, contentRange: headerOf(headers, "Content-Range"),
      contentLength: headerOf(headers, "Content-Length"), contentType: headerOf(headers, "Content-Type"), bearer: auth ? auth.replace(/^Bearer /, "") : null,
      bytes: body ? body.length : 0, body: body };
    g.requests.push(entry);
    return entry;
  }
  function statusAnswer(publishId) {
    const up = Object.keys(g.uploads).map(function (k) { return g.uploads[k]; }).filter(function (x) { return x.publishId === publishId; })[0];
    let st = typeof o.status === "function" ? o.status(up) : o.status;
    if (!st) st = up && up.done ? "PUBLISH_COMPLETE" : "PROCESSING_UPLOAD";
    const d = { status: st, uploaded_bytes: up ? up.received.length : 0 };
    if (st === "PUBLISH_COMPLETE") d.publicaly_available_post_id = o.noPostId ? [] : [Number(POST_ID) > Number.MAX_SAFE_INTEGER ? POST_ID : POST_ID];
    if (st === "FAILED") d.fail_reason = o.failReason || "file_format_check_failed";
    return reply(200, { data: d, error: OK });
  }
  function answer(method, u, headers, body) {
    const entry = record(method, u, headers, body);
    if (u.hostname === "open.tiktokapis.com" && u.pathname === "/v2/oauth/token/") {
      const form = new URLSearchParams(body.toString("utf8"));
      const call = { grant_type: form.get("grant_type"), code: form.get("code"), refresh_token: form.get("refresh_token"), client_key: form.get("client_key"),
        client_secret_ok: form.get("client_secret") === CLIENT.secret, redirect_uri: form.get("redirect_uri"), keys: Array.from(form.keys()).sort().join(",") };
      g.tokenCalls.push(call);
      EV.push("tt:token:" + call.grant_type);
      if (call.grant_type === "refresh_token") {
        if (typeof o.onRefresh === "function") o.onRefresh(call);
        if (o.refresh === "invalid_grant") return reply(400, { error: "invalid_grant", error_description: "Refresh token is invalid or expired.", log_id: "x" });
        if (o.refresh === "down") return reply(503, { error: "server_error" });
        const grant = { open_id: OPEN_ID, scope: SCOPES, access_token: ACCESS2, expires_in: 86400, refresh_expires_in: 31536000, token_type: "Bearer" };
        if (o.rotate) grant.refresh_token = REFRESH2;
        return reply(200, grant);
      }
      if (o.exchange === "invalid_grant") return reply(400, { error: "invalid_grant", error_description: "Authorization code is expired." });
      const grant = { open_id: OPEN_ID, scope: o.scope === undefined ? SCOPES : o.scope, access_token: ACCESS, expires_in: 86400, refresh_token: REFRESH,
        refresh_expires_in: 31536000, token_type: "Bearer" };
      return reply(200, grant);
    }
    if (u.hostname === "open.tiktokapis.com" && u.pathname === "/v2/oauth/revoke/") {
      EV.push("tt:revoke");
      g.revoked = new URLSearchParams(body.toString("utf8"));
      if (o.revoke === "down") return { error: Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }) };
      return reply(200, null);
    }
    if (o.reject && o.reject.indexOf(entry.bearer) !== -1) return reply(401, { error: { code: "access_token_invalid", message: "The access token is invalid or not found in the request." } });
    if (u.hostname === "open.tiktokapis.com" && u.pathname === "/v2/user/info/" && method === "GET") {
      EV.push("tt:user");
      g.userSearch = u.search;
      return reply(200, { data: { user: { open_id: o.userOpenId || OPEN_ID, display_name: DISPLAY } }, error: OK });
    }
    if (u.hostname === "open.tiktokapis.com" && u.pathname === "/v2/post/publish/creator_info/query/" && method === "POST") {
      EV.push("tt:creator");
      const d = Object.assign({ creator_avatar_url: "https://p16.example/a.jpg", creator_username: "maplestreet", creator_nickname: NICK,
        privacy_level_options: OPTIONS.slice(), comment_disabled: false, duet_disabled: false, stitch_disabled: false, max_video_post_duration_sec: 300 }, o.creator || {});
      return reply(200, { data: d, error: OK });
    }
    if (u.hostname === "open.tiktokapis.com" && u.pathname === "/v2/post/publish/video/init/" && method === "POST") {
      EV.push("tt:init");
      let b = null;
      try { b = JSON.parse(body.toString("utf8")); } catch (e) { b = null; }
      g.inits.push(b);
      if (o.initError) return reply(o.initStatus || 403, { error: { code: "spam_risk_too_many_posts", message: o.initError, log_id: "x" } });
      g.n++;
      const publishId = PUBLISH_BASE + "." + g.n;
      const url = o.uploadUrl || (UPLOAD_BASE + g.n);
      g.uploads[new URL(url).search] = { publishId: publishId, total: b && b.source_info ? b.source_info.video_size : 0, received: Buffer.alloc(0), done: false };
      return reply(200, { data: { publish_id: publishId, upload_url: url }, error: OK });
    }
    if (u.hostname === "open.tiktokapis.com" && u.pathname === "/v2/post/publish/status/fetch/" && method === "POST") {
      EV.push("tt:status");
      let b = null;
      try { b = JSON.parse(body.toString("utf8")); } catch (e) { b = null; }
      g.statusFetches = (g.statusFetches || []).concat([b && b.publish_id]);
      return statusAnswer(b && b.publish_id);
    }
    if (u.hostname === "open-upload.tiktokapis.com" && u.pathname === "/upload/" && method === "PUT") {
      EV.push("tt:put");
      const up = g.uploads[u.search];
      if (!up) return reply(404, { error: { code: "not_found" } });
      const want = "bytes 0-" + (up.total - 1) + "/" + up.total;
      if (entry.contentRange !== want || Number(entry.contentLength) !== up.total) return reply(416, { error: { code: "range_not_satisfiable" } });
      up.received = Buffer.from(body);
      up.done = up.received.length === up.total;
      if (o.putStatus) return reply(o.putStatus, null);
      return o.putJson ? reply(201, { ok: true }) : reply(up.done ? 201 : 206, null);
    }
    if (u.hostname === "open-upload.tiktokapis.com" && u.pathname.indexOf("/upload/redirect") === 0) return reply(308, null, { location: "https://open-upload.tiktokapis.com/upload/x" });
    if (u.hostname === "open-upload.tiktokapis.com" && u.pathname.indexOf("/upload/html") === 0) return { status: 201, headers: { "content-type": "text/html" }, raw: Buffer.from("<p>ok</p>") };
    if (u.hostname === "open-upload.tiktokapis.com" && u.pathname.indexOf("/upload/empty200") === 0) return reply(200, null);
    if (u.hostname === "open-upload.tiktokapis.com" && u.pathname.indexOf("/upload/e201") === 0) return reply(201, null);
    if (u.hostname === "www.googleapis.com" && u.pathname.indexOf("/upload/e201") === 0) return reply(201, null);
    return reply(404, { error: { code: "no_stub", message: "no stub for " + u.pathname } });
  }
  function resolve(hostname, lookupOptions, cb) { return cb(null, [{ address: PUBLIC_V4, family: 4 }]); }
  function transport(options) {
    const req = new EventEmitter();
    const chunks = [];
    let got = 0, cut = false, destroyed = false;
    const u = new URL("https://" + options.hostname + options.path);
    const isBodyPut = options.method === "PUT" && Number(headerOf(options.headers, "Content-Length")) > 0;
    if (isBodyPut) {
      g.bodyPuts++;
      if (g.bodyPuts === 1 && g.db) {
        const row = g.db.t.member_videos.filter(function (r) { return r.tiktok_upload_ciphertext; })[0];
        let opened = null;
        try { opened = row ? CRYPT.decrypt({ ciphertext: row.tiktok_upload_ciphertext, iv: row.tiktok_upload_iv, authTag: row.tiktok_upload_auth_tag }) : null; } catch (e) { opened = "unreadable"; }
        g.atFirstPut = row ? { url: opened, publish_id: row.tiktok_publish_id, status: row.tiktok_status, expires: row.tiktok_upload_expires_at } : null;
      }
    }
    const cutThis = isBodyPut && (o.cut || 0) >= g.bodyPuts;
    req.destroy = function () { destroyed = true; };
    req.write = function (c) {
      if (destroyed || cut) return true;
      chunks.push(Buffer.from(c));
      got += c.length;
      const declared = Number(headerOf(options.headers, "Content-Length"));
      if (cutThis && got >= Math.floor(declared / 2)) {
        cut = true;
        record(options.method, u, options.headers, Buffer.concat(chunks)).cut = true;
        EV.push("tt:put-cut");
        process.nextTick(function () { req.emit("error", Object.assign(new Error("socket hang up"), { code: "ECONNRESET" })); });
      }
      return true;
    };
    req.end = function (payload) {
      if (cut) return;
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
  g.streamUpload = function (url, options) { return guarded.streamUpload(url, options); };
  g.of = function (pred) { return g.requests.filter(pred); };
  g.puts = function () { return g.of(function (r) { return r.method === "PUT" && r.host === "open-upload.tiktokapis.com" && r.bytes > 0; }); };
  g.initCalls = function () { return g.of(function (r) { return r.path === "/v2/post/publish/video/init/"; }); };
  g.creatorCalls = function () { return g.of(function (r) { return r.path === "/v2/post/publish/creator_info/query/"; }); };
  g.statusCalls = function () { return g.of(function (r) { return r.path === "/v2/post/publish/status/fetch/"; }); };
  return g;
}

/* THE NETWORK TRIPWIRE: no socket, no real DNS question, no fetch, in this whole run. */
const TRIPPED = [];
(function tripwire() {
  const http = require("http"), https = require("https"), net = require("net"), tls = require("tls"), dns = require("dns");
  function wire(obj, name, label) {
    obj[name] = function () { TRIPPED.push(label); throw new Error("checkTiktokPosting: " + label + " is not allowed in this check"); };
  }
  wire(http, "request", "http.request"); wire(http, "get", "http.get");
  wire(https, "request", "https.request"); wire(https, "get", "https.get");
  wire(net, "connect", "net.connect"); wire(net, "createConnection", "net.createConnection");
  wire(tls, "connect", "tls.connect");
  wire(dns, "lookup", "dns.lookup"); wire(dns, "resolve", "dns.resolve"); wire(dns.promises, "lookup", "dns.promises.lookup");
  globalThis.fetch = function () { TRIPPED.push("fetch"); return Promise.reject(new Error("checkTiktokPosting: fetch is not allowed in this check")); };
})();

/* ── the routes, run from server.js's own source ─────────────────────────── */
function sliceOf(src, start, end) {
  const a = src.indexOf(start), b = src.indexOf(end, a);
  return a === -1 || b === -1 ? "" : src.slice(a, b);
}
const TT_SECTION = sliceOf(FILES.server, "/* ── TikTok posting (migration 178; lib/tiktokAuth.js, lib/tiktokApi.js, lib/memberVideos.js) ──",
  // NAMED, item 8 part 3a: the Instagram section now sits between TikTok and YouTube, so the TikTok slice ends at the Instagram header.
  "/* ── Instagram posting (migration 179;");
function requireAuth() {} function requireActiveSubscription() {} function aiLimiter() {}
function claimsStub(text) {
  return /guaranteed/i.test(String(text)) ? { error: "That makes a promise BizForce can't check (\"guaranteed\").", violations: [{ phrase: "guaranteed" }] } : null;
}
function mountRoutes(env) {
  env = env || {};
  const db = env.db || makeDb();
  const tiktok = makeTiktok(Object.assign({ db: db }, env.tiktok || {}));
  CURRENT = tiktok;
  const routes = {};
  const prompts = [];
  const crypt = {
    encrypt: function (p) {
      EV.push(p === ACCESS ? "encrypt:access" : (p === REFRESH ? "encrypt:refresh" : "encrypt:other"));
      return CRYPT.encrypt(p);
    },
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
    SOCIAL_SEARCH_LIMITS: { tiktok: LIMITS },
    blueskyClaimsRefusal: claimsStub,
    callAnthropicText: async function (prompt) {
      prompts.push(prompt);
      return { text: env.draft !== undefined ? env.draft : "CAPTION: Spring cakes, baked fresh every morning. #bakery #cakes" };
    },
    Promise: Promise, Buffer: Buffer, URL: URL, Date: Date, JSON: JSON, Object: Object, Array: Array, String: String, Number: Number, Math: Math,
    require: function (r) {
      if (r === "./lib/apiKeyCrypto") return crypt;
      if (r === "./lib/guardedFetch") return Object.assign({}, GF, GF_PROXY);
      if (r === "./lib/tiktokAuth") return TA;
      if (r === "./lib/tiktokApi") return TK;
      if (r === "./lib/memberVideos") return MV;
      return realRequire(r);
    },
    app: {}
  };
  ["get", "post", "put", "delete"].forEach(function (m) {
    ctx.app[m] = function (p) { const args = [].slice.call(arguments, 1); routes[m + " " + p] = { middleware: args.slice(0, -1), handler: args[args.length - 1] }; };
  });
  vm.createContext(ctx);
  vm.runInContext(TT_SECTION, ctx, { filename: "server.js (TikTok section)" });
  return { db: db, tiktok: tiktok, routes: routes, ctx: ctx, prompts: prompts, storage: db.storage };
}
async function hit(m, key, req) {
  CURRENT = m.tiktok;
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
  const r = await hit(m, "post /api/tiktok/start", {});
  const url = r.body && r.body.authorize_url ? new URL(r.body.authorize_url) : null;
  return { r: r, url: url, state: url ? url.searchParams.get("state") : null };
}
async function connect(m, extra) {
  const b = await begin(m);
  const f = await hit(m, "post /api/tiktok/finish", { body: Object.assign({ code: CODE, state: b.state }, extra || {}) });
  return { b: b, f: f };
}
function seal(p) { const s = CRYPT.encrypt(p); return { ciphertext: s.ciphertext, iv: s.iv, authTag: s.authTag }; }
function seedConnection(db, over) {
  const a = seal(ACCESS), r = seal(REFRESH);
  const row = Object.assign({ id: uuid(), user_id: USER, open_id: OPEN_ID, display_name: DISPLAY,
    refresh_ciphertext: r.ciphertext, refresh_iv: r.iv, refresh_auth_tag: r.authTag,
    access_ciphertext: a.ciphertext, access_iv: a.iv, access_auth_tag: a.authTag,
    access_expires_at: new Date(Date.now() + 20 * 60 * 60 * 1000).toISOString(), refresh_expires_at: new Date(Date.now() + 300 * 86400000).toISOString(),
    token_version: 0, granted_scopes: SCOPES, status: "connected", last_ok_at: null, last_error_at: null, last_error_code: null,
    created_at: "2026-11-07T10:00:00.000Z", updated_at: "2026-11-07T10:00:00.000Z" }, over || {});
  db.t.member_tiktok_connections.push(row);
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
    created_at: new Date().toISOString() }, over || {});
  db.t.member_videos.push(row);
  if (row.path) db.storage.objects[row.path] = { buf: buf, created_at: new Date(Date.now() - 3 * 86400000).toISOString() };
  return row;
}
const POST = { caption: "Spring cakes, baked fresh every morning.", privacy_level: "MUTUAL_FOLLOW_FRIENDS", allow_comment: true, allow_duet: false, allow_stitch: false,
  disclose: false, brand_organic: false, brand_content: false };
async function file(m, video, body) {
  return hit(m, "post /api/tiktok/propose-post", { body: Object.assign({ video_id: video.id }, POST, body || {}) });
}
async function approve(m, proposal) { CURRENT = m.tiktok; return attempt(m.ctx.executePublishTiktokPost(proposal)); }
function rowOf(m, id) { return m.db.t.member_videos.filter(function (r) { return r.id === id; })[0]; }
function uploadOf(row) {
  try { return row && row.tiktok_upload_ciphertext ? CRYPT.decrypt({ ciphertext: row.tiktok_upload_ciphertext, iv: row.tiktok_upload_iv, authTag: row.tiktok_upload_auth_tag }) : null; } catch (e) { return "unreadable"; }
}
function accessOf(row) { try { return CRYPT.decrypt({ ciphertext: row.access_ciphertext, iv: row.access_iv, authTag: row.access_auth_tag }); } catch (e) { return null; } }
function refreshOf(row) { try { return CRYPT.decrypt({ ciphertext: row.refresh_ciphertext, iv: row.refresh_iv, authTag: row.refresh_auth_tag }); } catch (e) { return null; } }
function libDeps(db, tiktok, extra) {
  CURRENT = tiktok;
  return Object.assign({ supabase: db, storage: db.storage, crypt: CRYPT, jsonRequest: tiktok.jsonRequest, streamUpload: tiktok.streamUpload,
    now: function () { return Date.now(); }, config: function () { return TA.configured(CONFIGURED); }, limits: LIMITS, claims: claimsStub, env: {} }, extra || {});
}
async function flush() { for (let i = 0; i < 80; i++) await new Promise(function (r) { setImmediate(r); }); }
function stripComments(src) { return String(src).replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, ""); }
function payloadOf(video, over) {
  return Object.assign({ video_id: video.id, sha256: video.sha256, bytes: Number(video.bytes), mime: video.mime, caption: POST.caption, privacy_level: POST.privacy_level,
    allow_comment: true, allow_duet: false, allow_stitch: false, brand_organic: false, brand_content: false, open_id: OPEN_ID }, over || {});
}
function proposalOf(video, over) {
  return { id: uuid(), user_id: USER, action_type: "publish_tiktok_post", status: "executing", payload: payloadOf(video, over) };
}

/* ── the Social page's video list and TikTok panel in a fake DOM ─────────── */
const API = "https://dynamic-prosperity-production-5382.up.railway.app";
function runPage(search, answers, marker) {
  const dom = { els: {}, fetches: [], events: [], innerHTML: [], assigned: [], session: {} };
  if (marker) dom.session.bf_oauth_return = marker;
  function node(tag) {
    const n = { tagName: String(tag).toUpperCase(), children: [], _t: "", className: "", hidden: false, disabled: false, value: "", checked: false, type: "", id: "", name: "",
      required: false, selected: false, attrs: {}, listeners: {}, files: null, rows: 0, maxLength: -1, placeholder: "", href: "", target: "", rel: "",
      appendChild: function (c) { this.children.push(c); c.parentNode = this; return c; },
      insertBefore: function (c, ref) { const i = this.children.indexOf(ref); if (i === -1) this.children.push(c); else this.children.splice(i, 0, c); c.parentNode = this; return c; },
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
      Object.defineProperty(n, "value", { get: function () { const s = this.children.filter(function (c) { return c.selected; })[0] || this.children[0]; return s ? s.value : ""; },
        set: function (v) { this.children.forEach(function (c) { c.selected = c.value === v; }); } });
    }
    return n;
  }
  const document = { readyState: "complete", addEventListener: function () {},
    getElementById: function (id) { if (!dom.els[id]) { dom.els[id] = node("div"); dom.els[id].id = id; } return dom.els[id]; },
    createElement: node, createTextNode: function (s) { return { tagName: "#text", children: [], textContent: String(s) }; } };
  dom.get = function (id) { return document.getElementById(id); };
  const location = { search: search, assign: function (u) { dom.assigned.push(u); } };
  const window = { location: location, history: { replaceState: function (s, t, u) { dom.events.push("replaceState:" + u); } } };
  function fetch(url, init) {
    const p = String(url).replace(API, "");
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
    XMLHttpRequest: function () { throw new Error("no upload in this run"); }, encodeURIComponent: encodeURIComponent,
    console: { log: function () {}, error: function () {}, warn: function () {} }, Promise: Promise, JSON: JSON, String: String, Array: Array, Date: Date, Math: Math,
    Number: Number, Error: Error, Object: Object };
  window.document = document;
  ctx.window = window;
  vm.createContext(ctx);
  // window is the page's global: BFVideos and BFTikTok are set on it.
  ctx.window = new Proxy(window, { get: function (t, k) { return k in t ? t[k] : ctx[k]; }, set: function (t, k, v) { t[k] = v; return true; } });
  vm.runInContext(FILES.oauth, ctx, { filename: "scripts/oauth-return.js" }); // NAMED, item 8 part 3a: loaded first, as on the page
  vm.runInContext(FILES.ytui, ctx, { filename: "scripts/youtube.js" });
  vm.runInContext(FILES.ui, ctx, { filename: "scripts/tiktok.js" });
  dom.window = window;
  return dom;
}
function findAll(root, pred, out) {
  out = out || [];
  (root.children || []).forEach(function (c) { if (pred(c)) out.push(c); findAll(c, pred, out); });
  return out;
}
const PAGE_VIDEO = { id: "22222222-2222-4222-8222-222222222222", label: "Spring cakes", bytes: 3 * 1048576, mime: "video/mp4", status: "ready",
  youtube_video_id: null, youtube_url: null, uploaded_at: null, created_at: "2026-11-07T10:00:00Z", upload_unfinished: false,
  tiktok_status: null, tiktok_posted_at: null, tiktok_post_url: null, tiktok_upload_unfinished: false };
const PAGE_POSTED = Object.assign({}, PAGE_VIDEO, { id: "33333333-3333-4333-8333-333333333333", label: "Autumn menu", tiktok_status: "posted",
  tiktok_posted_at: "2026-11-07T11:00:00Z", tiktok_post_url: "https://www.tiktok.com/player/v1/" + POST_ID });
const CREATOR = { creator_nickname: NICK, creator_username: "maplestreet", privacy_level_options: OPTIONS.slice(), comment_disabled: false, duet_disabled: true, stitch_disabled: false,
  max_video_post_duration_sec: 300, privacy_words: { PUBLIC_TO_EVERYONE: "Everyone", MUTUAL_FOLLOW_FRIENDS: "Friends", FOLLOWER_OF_CREATOR: "Followers", SELF_ONLY: "Only you" } };
function pageAnswers(over) {
  return function (p, method) {
    if (over && over[method + " " + p] !== undefined) return over[method + " " + p];
    if (p === "/api/youtube/status") return { status: 200, body: { youtube_available: false, connected: false, status: "not_connected" } };
    if (p === "/api/tiktok/status") return { status: 200, body: { tiktok_available: true, connected: true, status: "connected", display_name: DISPLAY, since: "2026-11-07T10:00:00Z", reconnect_message: null } };
    if (p === "/api/videos" && method === "GET") return { status: 200, body: { videos: [PAGE_VIDEO, PAGE_POSTED], max_bytes: 52428800, ready_max: 2 } };
    if (p === "/api/tiktok/start") return { status: 200, body: { authorize_url: "https://www.tiktok.com/v2/auth/authorize/?client_key=x&state=y" } };
    if (p === "/api/tiktok/finish") return { status: 200, body: { tiktok_available: true, connected: true, status: "connected", display_name: DISPLAY, since: "2026-11-07T10:00:00Z" } };
    if (p === "/api/tiktok/creator-info") return { status: 200, body: CREATOR };
    if (p === "/api/tiktok/propose-post") return { status: 201, body: { note: "Filed for approval. Nothing has been sent to TikTok." } };
    if (p === "/api/tiktok/draft-caption") return { status: 200, body: { draft: { caption: "Fresh cakes." }, within_limits: true, note: "A draft only." } };
    return { status: 404, body: { error: "no answer for " + method + " " + p } };
  };
}

(async function main() {
  const now = Date.now();
  const iso = function (ms) { return new Date(ms).toISOString(); };

  /* ── O ── */
  OUT("\n══ O. connect ══");
  let m = mountRoutes({});
  const all8 = ["post /api/tiktok/start", "post /api/tiktok/finish", "get /api/tiktok/status", "post /api/tiktok/disconnect", "get /api/tiktok/creator-info",
    "post /api/tiktok/propose-post", "post /api/tiktok/draft-caption", "get /api/tiktok/videos/:id/status"];
  const gated = ["post /api/tiktok/start", "post /api/tiktok/finish", "post /api/tiktok/propose-post", "post /api/tiktok/draft-caption"];
  const loginOnly = ["get /api/tiktok/status", "post /api/tiktok/disconnect", "get /api/tiktok/creator-info", "get /api/tiktok/videos/:id/status"];
  check("O1. the eight routes: four behind a subscription (start, finish, propose-post, draft-caption), four login-only",
    J(Object.keys(m.routes).sort()) === J(all8.slice().sort()) &&
    gated.every(function (k) { return m.routes[k].middleware[0] === requireAuth && m.routes[k].middleware[1] === requireActiveSubscription; }) &&
    loginOnly.every(function (k) { return m.routes[k].middleware.length === 1 && m.routes[k].middleware[0] === requireAuth; }), Object.keys(m.routes).join(", "));
  check("O2. draft-caption runs behind aiLimiter; start and finish share a limiter of 10 an hour; propose-post 30 an hour",
    m.routes["post /api/tiktok/draft-caption"].middleware[2] === aiLimiter &&
    m.routes["post /api/tiktok/start"].middleware[2] === m.routes["post /api/tiktok/finish"].middleware[2] && m.routes["post /api/tiktok/start"].middleware[2].limiter.max === 10 &&
    m.routes["post /api/tiktok/propose-post"].middleware[2].limiter.max === 30);
  const unconfigured = [];
  for (const k of ["post /api/tiktok/start", "post /api/tiktok/finish", "get /api/tiktok/creator-info", "post /api/tiktok/propose-post", "post /api/tiktok/draft-caption", "get /api/tiktok/videos/:id/status"]) {
    const r = await hit(m, k, { body: { code: CODE, state: "A".repeat(43), video_id: uuid(), idea: "cakes" }, params: { id: uuid() } });
    unconfigured.push([k, r.status, r.body.error]);
  }
  check("O3. without TIKTOK_CLIENT_KEY and TIKTOK_CLIENT_SECRET every TikTok route but status and disconnect answers 503 \"TikTok connection isn't set up yet.\"",
    unconfigured.every(function (u) { return u[1] === 503 && u[2] === NOT_SET_UP; }) && m.tiktok.requests.length === 0 && m.db.t.oauth_states.length === 0,
    J(unconfigured.map(function (u) { return u[1]; })));
  let r = await hit(m, "get /api/tiktok/status", {});
  check("O4. ...and status says tiktok_available false, not connected", r.status === 200 && r.body.tiktok_available === false && r.body.connected === false && r.body.status === "not_connected");
  check("O5. only the two allowed env vars are read: TIKTOK_CLIENT_KEY and TIKTOK_CLIENT_SECRET (and nothing in the TikTok section reads process.env but through them)",
    (stripComments(FILES.auth + FILES.api).match(/env\.[A-Z_]+/g) || []).every(function (e) { return ["env.TIKTOK_CLIENT_KEY", "env.TIKTOK_CLIENT_SECRET"].indexOf(e) !== -1; }) &&
    (stripComments(TT_SECTION).match(/process\.env\.[A-Z_]+/g) || []).length === 0 && TA.configured({ TIKTOK_CLIENT_KEY: "x" }) === null && TA.configured({}) === null);

  m = mountRoutes({ env: CONFIGURED });
  let b = await begin(m);
  const st0 = m.db.t.oauth_states[0];
  const q = b.url ? b.url.searchParams : new URLSearchParams();
  check("O6. start: TikTok's authorize page with client_key, both scopes comma-separated, response_type code, the Social page as redirect_uri and a 43-character state; no PKCE",
    !!b.url && b.url.origin + b.url.pathname === "https://www.tiktok.com/v2/auth/authorize/" && q.get("client_key") === CLIENT.key && q.get("scope") === "user.info.basic,video.publish" &&
    q.get("response_type") === "code" && q.get("redirect_uri") === REDIRECT && /^[A-Za-z0-9_-]{43}$/.test(b.state || "") && !q.has("code_challenge") && !q.has("client_secret"),
    b.url ? b.url.href.replace(CLIENT.key, "KEY") : J(b.r.body));
  check("O7. ...the state's sha256 alone is stored, purpose tiktok_login, no verifier, ten minutes; the state itself never is",
    !!st0 && st0.purpose === "tiktok_login" && st0.state_hash === sha(b.state) && st0.verifier_ciphertext === undefined && st0.flow_context === null &&
    Math.abs(Date.parse(st0.expires_at) - Date.now() - 600000) < 5000 && J(m.db.t.oauth_states).indexOf(b.state) === -1 && b.r.headers["Cache-Control"] === "no-store");
  EV.length = 0;
  r = await hit(m, "post /api/tiktok/finish", { body: { code: CODE, state: b.state } });
  const conn = m.db.t.member_tiktok_connections[0];
  const tc = m.tiktok.tokenCalls[0] || {};
  check("O8. finish: the code exchanged once, with client_key, client_secret, code, grant_type authorization_code and the same redirect_uri",
    r.status === 200 && m.tiktok.tokenCalls.length === 1 && tc.grant_type === "authorization_code" && tc.code === CODE && tc.client_key === CLIENT.key && tc.client_secret_ok &&
    tc.redirect_uri === REDIRECT && tc.keys === "client_key,client_secret,code,grant_type,redirect_uri", J([r.status, r.body.code]));
  const encA = EV.indexOf("encrypt:access"), encR = EV.indexOf("encrypt:refresh"), userAt = EV.indexOf("tt:user");
  check("O9. both tokens are sealed BEFORE TikTok is asked anything (the user read)", encA !== -1 && encR !== -1 && userAt !== -1 && encA < userAt && encR < userAt, J(EV));
  check("O10. the row: open_id, display_name, both tokens sealed, about 24 hours less a minute, the refresh expiry, both scopes, connected",
    !!conn && conn.user_id === USER && conn.open_id === OPEN_ID && conn.display_name === DISPLAY && accessOf(conn) === ACCESS && refreshOf(conn) === REFRESH &&
    Math.abs(Date.parse(conn.access_expires_at) - (Date.now() + 86400000 - 60000)) < 10000 && Math.abs(Date.parse(conn.refresh_expires_at) - (Date.now() + 31536000000)) < 10000 &&
    conn.granted_scopes === SCOPES && conn.status === "connected" && conn.token_version === 0);
  check("O11. the answer is the status, never a token: connected, the name, tiktok_available", r.body.connected === true && r.body.display_name === DISPLAY && r.body.tiktok_available === true &&
    noSecretIn(J(r.body)) && J(r.body).indexOf("ciphertext") === -1 && m.tiktok.userSearch === "?fields=open_id,display_name");
  r = await hit(m, "post /api/tiktok/finish", { body: { code: CODE, state: b.state } });
  check("O12. the state is single-use: the same state again is refused (400 state_invalid), with no second exchange", r.status === 400 && r.body.code === "state_invalid" && m.tiktok.tokenCalls.length === 1);
  // expired, another member's, another purpose's
  m = mountRoutes({ env: CONFIGURED });
  b = await begin(m);
  m.db.t.oauth_states[0].expires_at = iso(Date.now() - 1000);
  const rExp = await hit(m, "post /api/tiktok/finish", { body: { code: CODE, state: b.state } });
  b = await begin(m);
  const rOther = await hit(m, "post /api/tiktok/finish", { user: { id: OTHER }, body: { code: CODE, state: b.state } });
  m.db.t.oauth_states.forEach(function (s) { if (s.state_hash === sha(b.state)) { s.purpose = "youtube_google"; } });
  const rPurpose = await hit(m, "post /api/tiktok/finish", { body: { code: CODE, state: b.state } });
  check("O13. an expired state, another member's state, or another sign-in's state: refused, nothing exchanged",
    [rExp, rOther, rPurpose].every(function (x) { return x.status === 400 && x.body.code === "state_invalid"; }) && m.tiktok.tokenCalls.length === 0);
  const rShape = await hit(m, "post /api/tiktok/finish", { body: { code: "", state: "short" } });
  check("O14. a finish without a code or a well-formed state: 400 bad_request", rShape.status === 400 && rShape.body.code === "bad_request");
  m = mountRoutes({ env: CONFIGURED, tiktok: { scope: "user.info.basic" } });
  let c = await connect(m);
  check("O15. a grant without video.publish: 422 no_scopes, nothing stored", c.f.status === 422 && c.f.body.code === "no_scopes" && m.db.t.member_tiktok_connections.length === 0);
  m = mountRoutes({ env: CONFIGURED, tiktok: { userOpenId: OPEN_ID2 } });
  c = await connect(m);
  check("O16. the user read names another account than the token's open_id: refused, nothing stored", c.f.status === 502 && m.db.t.member_tiktok_connections.length === 0);
  m = mountRoutes({ env: CONFIGURED, tiktok: { exchange: "invalid_grant" } });
  c = await connect(m);
  check("O17. a refused code exchange: 400 state_invalid, nothing stored", c.f.status === 400 && c.f.body.code === "state_invalid" && m.db.t.member_tiktok_connections.length === 0);
  // disconnect
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  m.db.t.oauth_states.push({ id: uuid(), user_id: USER, purpose: "youtube_google", state_hash: "a".repeat(64), verifier_ciphertext: "ab", verifier_iv: "0".repeat(24), verifier_auth_tag: "0".repeat(32), expires_at: iso(Date.now() + 60000), created_at: iso(Date.now()), consumed_at: null, flow_context: null });
  m.db.t.oauth_states.push({ id: uuid(), user_id: USER, purpose: "tiktok_login", state_hash: "b".repeat(64), expires_at: iso(Date.now() + 60000), created_at: iso(Date.now()), consumed_at: null, flow_context: null });
  r = await hit(m, "post /api/tiktok/disconnect", {});
  const rv = m.tiktok.revoked;
  check("O18. disconnect: TikTok's revoke with client_key, client_secret and the token; the row deleted; only tiktok_login states deleted",
    r.status === 200 && r.body.removed === true && r.body.revoked === true && !!rv && rv.get("client_key") === CLIENT.key && rv.get("client_secret") === CLIENT.secret && rv.get("token") === ACCESS &&
    m.db.t.member_tiktok_connections.length === 0 && m.db.t.oauth_states.length === 1 && m.db.t.oauth_states[0].purpose === "youtube_google" &&
    r.body.note === "Disconnected. BizForce asked TikTok to cancel its access to your account.", J(r.body));
  m = mountRoutes({ env: CONFIGURED, tiktok: { revoke: "down" } });
  seedConnection(m.db);
  r = await hit(m, "post /api/tiktok/disconnect", {});
  check("O19. ...TikTok unreachable: still disconnected (revoked false)", r.status === 200 && r.body.revoked === false && m.db.t.member_tiktok_connections.length === 0);
  m = mountRoutes({});
  seedConnection(m.db);
  r = await hit(m, "post /api/tiktok/disconnect", {});
  check("O20. ...unconfigured: still disconnected, nothing asked", r.status === 200 && m.db.t.member_tiktok_connections.length === 0 && m.tiktok.requests.length === 0);

  /* ── T ── */
  OUT("\n══ T. tokens ══");
  let db = makeDb(), tt = makeTiktok({ db: db });
  let row = seedConnection(db);
  let got = await TK.accessToken(libDeps(db, tt), row, false);
  check("T1. an access token more than 5 minutes from expiry is used as it is, nothing asked", got.token === ACCESS && tt.tokenCalls.length === 0 && TK.REFRESH_MARGIN_MS === 300000);
  db = makeDb(); tt = makeTiktok({ db: db });
  row = seedConnection(db, { access_expires_at: iso(Date.now() + 4 * 60000) });
  got = await TK.accessToken(libDeps(db, tt), row, false);
  let after = db.t.member_tiktok_connections[0];
  check("T2. within 5 minutes: refreshed with grant_type refresh_token and the stored refresh token; the new token sealed, the version bumped",
    got.token === ACCESS2 && tt.tokenCalls.length === 1 && tt.tokenCalls[0].grant_type === "refresh_token" && tt.tokenCalls[0].refresh_token === REFRESH &&
    tt.tokenCalls[0].keys === "client_key,client_secret,grant_type,refresh_token" && accessOf(after) === ACCESS2 && after.token_version === 1 &&
    Math.abs(Date.parse(after.refresh_expires_at) - (Date.now() + 31536000000)) < 10000);
  check("T3. ...TikTok sent no new refresh token: the stored one is kept", refreshOf(after) === REFRESH);
  db = makeDb(); tt = makeTiktok({ db: db, rotate: true });
  row = seedConnection(db, { access_expires_at: iso(Date.now() - 1000) });
  await TK.accessToken(libDeps(db, tt), row, false);
  check("T4. a returned refresh token is stored (sealed)", refreshOf(db.t.member_tiktok_connections[0]) === REFRESH2);
  db = makeDb();
  tt = makeTiktok({ db: db, onRefresh: function () {
    const w = seal(WINNER);
    Object.assign(db.t.member_tiktok_connections[0], { access_ciphertext: w.ciphertext, access_iv: w.iv, access_auth_tag: w.authTag, token_version: 1, access_expires_at: iso(Date.now() + 86400000) });
  } });
  row = seedConnection(db, { access_expires_at: iso(Date.now() - 1000) });
  got = await TK.accessToken(libDeps(db, tt), row, false);
  check("T5. a refresh that loses the race writes nothing: the winner's token is the one used and stored (compare-and-set on token_version)",
    got.token === WINNER && accessOf(db.t.member_tiktok_connections[0]) === WINNER && db.t.member_tiktok_connections[0].token_version === 1, got.token === ACCESS2 ? "used the loser's" : "");
  db = makeDb(); tt = makeTiktok({ db: db });
  row = seedConnection(db, { access_expires_at: iso(Date.now() - 1000) });
  const deps2 = libDeps(db, tt);
  const both = await Promise.all([TK.accessToken(deps2, row, false), TK.accessToken(deps2, row, false)]);
  check("T6. two at once: ONE refresh (single flight), both get its token", tt.tokenCalls.length === 1 && both[0].token === ACCESS2 && both[1].token === ACCESS2);
  db = makeDb(); tt = makeTiktok({ db: db, refresh: "invalid_grant" });
  row = seedConnection(db, { access_expires_at: iso(Date.now() - 1000) });
  let a = await attempt(TK.accessToken(libDeps(db, tt), row, false));
  check("T7. a refused refresh (invalid_grant): needs_reconnect, with ONE in-app notice tiktok_reconnect", !a.ok && a.kind === "auth" && db.t.member_tiktok_connections[0].status === "needs_reconnect" &&
    db.t.notifications.length === 1 && db.t.notifications[0].type === "tiktok_reconnect" && noSecretIn(J(db.t.notifications)));
  a = await attempt(TK.accessToken(libDeps(db, tt), db.t.member_tiktok_connections[0], false));
  check("T8. ...and nothing more is asked", !a.ok && tt.tokenCalls.length === 1 && db.t.notifications.length === 1);
  db = makeDb(); tt = makeTiktok({ db: db });
  row = seedConnection(db, { access_expires_at: iso(Date.now() - 1000), refresh_expires_at: iso(Date.now() - 1000) });
  a = await attempt(TK.accessToken(libDeps(db, tt), row, false));
  check("T9. a refresh token past refresh_expires_at: needs_reconnect without asking TikTok", !a.ok && a.code === "refresh_expired" && tt.tokenCalls.length === 0 &&
    db.t.member_tiktok_connections[0].status === "needs_reconnect" && db.t.notifications.length === 1);
  db = makeDb(); tt = makeTiktok({ db: db, refresh: "down" });
  row = seedConnection(db, { access_expires_at: iso(Date.now() - 1000) });
  a = await attempt(TK.accessToken(libDeps(db, tt), row, false));
  check("T10. TikTok down at refresh: refused as unreachable, the connection left connected", !a.ok && a.kind === "unreachable" && db.t.member_tiktok_connections[0].status === "connected");
  db = makeDb(); tt = makeTiktok({ db: db, reject: [ACCESS] });
  row = seedConnection(db);
  const ci = await attempt(TK.creatorInfo(libDeps(db, tt), row));
  check("T11. a 401 on a stored token: ONE forced refresh and one more try", ci.ok && tt.tokenCalls.length === 1 && tt.creatorCalls().length === 2 && tt.creatorCalls()[1].bearer === ACCESS2);

  /* ── V ── */
  OUT("\n══ V. TikTok's posting rules ══");
  const CR = { privacy_level_options: OPTIONS.slice(), comment_disabled: false, duet_disabled: true, stitch_disabled: false };
  const vp = function (over, cr) { return TK.validatePost(Object.assign({}, POST, over || {}), Object.assign({}, CR, cr || {}), LIMITS); };
  let v = vp({ privacy_level: undefined });
  check("V1. no privacy chosen: refused, \"Choose who can see this post.\" (there is no default)", !v.ok && v.error === "Choose who can see this post." && v.field === "privacy_level");
  v = vp({ privacy_level: "FOLLOWER_OF_CREATOR" });
  check("V2. a privacy TikTok doesn't offer this account: refused", !v.ok && v.field === "privacy_level" && /isn't one TikTok offers/.test(v.error));
  v = vp({ allow_duet: true });
  check("V3. Allow duet on when the account turned duets off: refused, \"Turned off in your TikTok settings\"", !v.ok && v.error === "Allow duet: Turned off in your TikTok settings." && v.field === "allow_duet");
  v = vp({ disclose: true, brand_content: true, privacy_level: "SELF_ONLY" });
  check("V4. branded content with SELF_ONLY: refused, \"Branded content can't be private.\"", !v.ok && v.error === "Branded content can't be private.");
  v = vp({ disclose: true });
  check("V5. \"Disclose video content\" on with neither option: refused", !v.ok && v.error === "Choose Your brand, Branded content, or both." && v.field === "disclose");
  v = vp({ disclose: false, brand_organic: true });
  check("V6. an option without the disclosure turned on: refused", !v.ok && v.field === "disclose");
  v = vp({ allow_comment: undefined, allow_duet: undefined, allow_stitch: undefined });
  check("V7. Allow comments, duet and stitch default OFF", v.ok && v.value.allow_comment === false && v.value.allow_duet === false && v.value.allow_stitch === false);
  v = vp({ disclose: true, brand_organic: true, brand_content: true, privacy_level: "PUBLIC_TO_EVERYONE" });
  check("V8. both options, public: allowed", v.ok && v.value.brand_organic === true && v.value.brand_content === true);
  check("V9. a caption of 2200 code points (an astral character counts once) passes; 2201, or one with < or >, is refused",
    vp({ caption: "\u{10400}".repeat(2200) }).ok && !vp({ caption: "a".repeat(2201) }).ok && !vp({ caption: "a <b>" }).ok && LIMITS.caption_max === 2200);
  check("V10. the label lines word for word", TK.labelLine({ brand_organic: true }) === "Your video will be labeled 'Promotional content'." &&
    TK.labelLine({ brand_content: true, brand_organic: true }) === "Your video will be labeled 'Paid partnership'." && TK.labelLine({}) === null);
  check("V11. the consent line word for word, with branded content naming the Branded Content Policy",
    TK.consentLine({}) === "By posting, you agree to TikTok's Music Usage Confirmation." &&
    TK.consentLine({ brand_content: true }) === "By posting, you agree to TikTok's Branded Content Policy and Music Usage Confirmation.");
  check("V12. TikTok's status words: PROCESSING_UPLOAD, PROCESSING_DOWNLOAD and SEND_TO_USER_INBOX processing; PUBLISH_COMPLETE posted; FAILED failed; anything else nothing",
    TK.mapStatus("PROCESSING_UPLOAD") === "processing" && TK.mapStatus("PROCESSING_DOWNLOAD") === "processing" && TK.mapStatus("SEND_TO_USER_INBOX") === "processing" &&
    TK.mapStatus("PUBLISH_COMPLETE") === "posted" && TK.mapStatus("FAILED") === "failed" && TK.mapStatus("NEW_WORD") === null);

  /* ── F ── */
  OUT("\n══ F. filing ══");
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  let buf = mp4(5000, 11);
  let video = seedVideo(m.db, buf);
  r = await file(m, video);
  let prop = m.db.t.agent_proposals[0];
  check("F1. propose-post files ONE pending publish_tiktok_post with the exact payload; nothing sent to TikTok but creator_info",
    r.status === 201 && !!prop && prop.status === "pending" && prop.action_type === "publish_tiktok_post" && prop.agent_type === "social" && prop.target === "tiktok" &&
    prop.reversible === false && prop.cost_amount === 0 &&
    J(prop.payload) === J({ video_id: video.id, sha256: video.sha256, bytes: buf.length, mime: "video/mp4", caption: POST.caption, privacy_level: "MUTUAL_FOLLOW_FRIENDS",
      allow_comment: true, allow_duet: false, allow_stitch: false, brand_organic: false, brand_content: false, open_id: OPEN_ID }) &&
    m.tiktok.creatorCalls().length === 1 && m.tiktok.initCalls().length === 0 && m.tiktok.puts().length === 0, J([r.status, r.body.error]));
  check("F2. ...never automatic: the proposal stays pending, no post begun", prop.status === "pending" && m.tiktok.inits.length === 0 && rowOf(m, video.id).tiktok_status === null);
  check("F3. ...the answer names the account's nickname and the privacy in words, and the consent line", /Maple Street Bakery's TikTok account, visible to: Friends\./.test(r.body.note || "") &&
    r.body.creator_nickname === NICK && r.body.consent_line === "By posting, you agree to TikTok's Music Usage Confirmation." && /^Post to TikTok as Maple Street Bakery \(Friends\)/.test(prop.title));
  r = await file(m, video);
  check("F4. one pending TikTok post per video", r.status === 409 && r.body.code === "pending" && m.db.t.agent_proposals.length === 1);
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(4000, 12));
  r = await file(m, video, { caption: "Guaranteed to sell out." });
  check("F5. the claims screen on the caption: 422 claims, nothing filed", r.status === 422 && r.body.code === "claims" && r.body.field === "caption" && m.db.t.agent_proposals.length === 0);
  r = await file(m, video, { privacy_level: "" });
  check("F6. no privacy chosen: 400, nothing filed", r.status === 400 && r.body.field === "privacy_level" && m.db.t.agent_proposals.length === 0);
  m = mountRoutes({ env: CONFIGURED, tiktok: { creator: { duet_disabled: true } } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(4000, 13));
  r = await file(m, video, { allow_duet: true });
  check("F7. the account turned duets off and the post allows them: 400, nothing filed", r.status === 400 && r.body.field === "allow_duet" && m.db.t.agent_proposals.length === 0);
  r = await file(m, video, { disclose: true, brand_content: true, privacy_level: "SELF_ONLY" });
  check("F8. branded content filed as private: 400 \"Branded content can't be private.\"", r.status === 400 && /^Branded content can't be private\./.test(r.body.error || ""));
  // the caps
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  for (let i = 0; i < 5; i++) seedVideo(m.db, mp4(1000, 100 + i), { status: "uploaded", path: null, tiktok_status: "posted", tiktok_posted_at: iso(Date.now() - 3600000), tiktok_post_id: POST_ID });
  video = seedVideo(m.db, mp4(4000, 14));
  r = await file(m, video);
  check("F9. five TikTok posts in 24 hours: the sixth is refused (409 daily_cap)", r.status === 409 && r.body.code === "daily_cap" && m.db.t.agent_proposals.length === 0);
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  for (let i = 0; i < 5; i++) seedVideo(m.db, mp4(1000, 200 + i), { status: "ready", youtube_video_id: "Ab3_x-9Kq2" + i, uploaded_at: iso(Date.now() - 3600000) });
  video = seedVideo(m.db, mp4(4000, 15));
  r = await file(m, video);
  check("F10. TikTok's cap is its own: five YouTube uploads in 24 hours don't block a TikTok post", r.status === 201, J([r.status, r.body.code]));
  // states
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  const posted = seedVideo(m.db, mp4(1000, 16), { tiktok_status: "posted", tiktok_posted_at: iso(Date.now() - 86400000 * 2), tiktok_post_id: POST_ID });
  const inflight = seedVideo(m.db, mp4(1000, 17), { tiktok_status: "processing", tiktok_publish_id: PUBLISH_BASE + ".9" });
  const gone = seedVideo(m.db, mp4(1000, 18), { status: "removed", path: null });
  const rPosted = await file(m, posted), rIn = await file(m, inflight), rGone = await file(m, gone);
  check("F11. already posted, still processing, or no file: 409 each", rPosted.body.code === "already_posted" && rIn.body.code === "in_flight" && rGone.body.code === "not_ready");
  m = mountRoutes({ env: CONFIGURED });
  video = seedVideo(m.db, mp4(1000, 19));
  r = await file(m, video);
  const rNc = r;
  seedConnection(m.db, { status: "needs_reconnect" });
  r = await file(m, video);
  check("F12. not connected, or needs reconnecting: 409, nothing asked", rNc.status === 409 && rNc.body.code === "not_connected" && r.status === 409 && r.body.code === "needs_reconnect" && m.tiktok.requests.length === 0);
  // registration
  check("F13. the generic proposals route refuses publish_tiktok_post; it is subscription-gated; its executor is registered",
    FILES.server.indexOf("if (actionType === \"publish_tiktok_post\") {\n      return res.status(400).json({\n        error: \"A TikTok post cannot be filed here.") !== -1 &&
    // NAMED, item 8 part 3a: publish_instagram_post now follows publish_tiktok_post in the list.
    /const SUBSCRIPTION_GATED_PROPOSAL_ACTIONS = \[[^\]]*"publish_tiktok_post"[^\]]*\];/.test(FILES.server) &&
    (/\n  publish_tiktok_post: (\w+),\n/.exec(FILES.server) || [])[1] === "executePublishTiktokPost" &&
    /async function executePublishTiktokPost\(proposal\) \{\n  return require\("\.\/lib\/tiktokApi"\)\.executePublish\(tiktokDeps\(\), proposal\);\n\}/.test(TT_SECTION));
  const GR = realRequire("./lib/gateRules");
  check("F14. gateRules: publish_tiktok_post known, channel tiktok", GR.ACTION_TYPES.indexOf("publish_tiktok_post") !== -1 && GR.CHANNELS.indexOf("tiktok") !== -1 &&
    GR.channelFor("publish_tiktok_post") === "tiktok");
  // draft-caption
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  m.db.t.business_profiles.push({ user_id: USER, business_name: "Maple Street Bakery", industry: "Bakery", products_services: "Cakes", target_audience: "Locals" });
  video = seedVideo(m.db, mp4(1000, 20), { label: "secret-label-xyz" });
  r = await hit(m, "post /api/tiktok/draft-caption", { body: { video_id: video.id, idea: "how we bake spring cakes" } });
  const pr = m.prompts[0] || "";
  check("F15. draft-caption: the model sees the idea and the business profile, never the file, the label or the account; the draft is measured",
    r.status === 200 && r.body.draft.caption === "Spring cakes, baked fresh every morning. #bakery #cakes" && r.body.within_limits === true &&
    pr.indexOf("how we bake spring cakes") !== -1 && pr.indexOf("Maple Street Bakery") !== -1 && pr.indexOf("secret-label-xyz") === -1 && pr.indexOf(video.path) === -1 &&
    pr.indexOf(OPEN_ID) === -1 && pr.indexOf("2200") !== -1 && m.db.t.agent_proposals.length === 0 && m.tiktok.requests.length === 0, J([r.status, r.body.error]));

  /* ── U ── */
  OUT("\n══ U. the post ══");
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  buf = mp4(300000, 21);
  video = seedVideo(m.db, buf);
  await file(m, video);
  prop = m.db.t.agent_proposals[0];
  EV.length = 0; LOGS.length = 0;
  a = await approve(m, prop);
  let vr = rowOf(m, video.id);
  const init0 = m.tiktok.inits[0] || {};
  check("U1. approved: ONE init with the filed settings: privacy, the caption as title, disable_* the opposite of allow_*, both brand toggles",
    a.ok && m.tiktok.inits.length === 1 && J(init0.post_info) === J({ title: POST.caption, privacy_level: "MUTUAL_FOLLOW_FRIENDS", disable_comment: false, disable_duet: true,
      disable_stitch: true, brand_content_toggle: false, brand_organic_toggle: false }), a.ok ? J(init0) : a.msg);
  check("U2. ...FILE_UPLOAD as ONE chunk: video_size, chunk_size the whole size, total_chunk_count 1",
    J(init0.source_info) === J({ source: "FILE_UPLOAD", video_size: buf.length, chunk_size: buf.length, total_chunk_count: 1 }));
  const put0 = m.tiktok.puts()[0] || {};
  check("U3. ONE PUT to the upload URL: Content-Type the video's, Content-Length N, Content-Range \"bytes 0-(N-1)/N\", the whole file",
    m.tiktok.puts().length === 1 && put0.host === "open-upload.tiktokapis.com" && put0.contentType === "video/mp4" && put0.contentLength === String(buf.length) &&
    put0.contentRange === "bytes 0-" + (buf.length - 1) + "/" + buf.length && sha(put0.body) === sha(buf), J([put0.contentRange, put0.contentLength]));
  const fp = m.tiktok.atFirstPut || {};
  check("U4. BEFORE the PUT: the publish_id, the upload URL sealed with an expiry under an hour, and tiktok_status initiated are stored",
    fp.url === UPLOAD_BASE + "1" && fp.publish_id === PUBLISH_BASE + ".1" && fp.status === "initiated" &&
    Date.parse(fp.expires) > Date.now() && Date.parse(fp.expires) <= Date.now() + 3600000, J(fp));
  check("U5. after 201: one status fetch; PUBLISH_COMPLETE records posted, the time and the post id; the upload cleared; the link",
    a.ok && a.v.posted === true && vr.tiktok_status === "posted" && !!vr.tiktok_posted_at && vr.tiktok_post_id === POST_ID && vr.tiktok_upload_ciphertext === null &&
    vr.tiktok_upload_expires_at === null && a.v.post_url === "https://www.tiktok.com/player/v1/" + POST_ID && m.tiktok.statusCalls().length === 1, a.ok ? J(a.v) : a.msg);
  check("U6. the file is kept (still ready) for the other platform: TikTok having it is not enough", vr.status === "ready" && vr.path === video.path && !!m.storage.objects[video.path]);
  check("U7. nothing logged names a token, the upload URL or a path", LOGS.every(function (l) { return noSecretIn(l) && l.indexOf(UPLOAD_BASE) === -1 && l.indexOf("open-upload") === -1 && l.indexOf(video.path) === -1; }) &&
    (stripComments(FILES.api).match(/console\.\w+\([^\n]*/g) || []).every(function (l) { return !/token|url|Url|path|upload/i.test(l.replace("[tiktok] the reconnect notice", "")); }) &&
    noSecretIn(J(a.v)), J(LOGS));
  // processing words
  for (const word of ["PROCESSING_DOWNLOAD", "SEND_TO_USER_INBOX"]) {
    m = mountRoutes({ env: CONFIGURED, tiktok: { status: word } });
    seedConnection(m.db);
    video = seedVideo(m.db, mp4(20000, 22));
    a = await approve(m, proposalOf(video));
    vr = rowOf(m, video.id);
    check("U8. " + word + " after the PUT: processing, never posted; the upload cleared (every byte is there)",
      a.ok && a.v.processing === true && vr.tiktok_status === "processing" && vr.tiktok_posted_at === null && vr.tiktok_upload_ciphertext === null && vr.tiktok_publish_id === PUBLISH_BASE + ".1", a.ok ? J(a.v) : a.msg);
  }
  // crash in the middle, then again
  m = mountRoutes({ env: CONFIGURED, tiktok: { cut: 1 } });
  seedConnection(m.db);
  buf = mp4(200000, 23);
  video = seedVideo(m.db, buf);
  prop = proposalOf(video);
  a = await approve(m, prop);
  vr = rowOf(m, video.id);
  check("U9. the connection breaks mid-file: refused as unfinished; the publish and the sealed URL stay stored, initiated",
    !a.ok && /didn't finish/.test(a.msg || "") && vr.tiktok_status === "initiated" && vr.tiktok_publish_id === PUBLISH_BASE + ".1" && uploadOf(vr) === UPLOAD_BASE + "1" && noSecretIn(a.msg), a.msg);
  const view = MV.publicView(vr);
  check("U10. ...the video's public view says tiktok_upload_unfinished, never the URL", !!view && view.tiktok_upload_unfinished === true && J(view).indexOf("upload_id") === -1 &&
    J(view).indexOf("ciphertext") === -1);
  a = await approve(m, prop);
  vr = rowOf(m, video.id);
  const sf = m.tiktok.statusFetches || [];
  check("U11. approved again: the status is fetched FIRST, then the whole file PUT once more to the same URL; never a second init",
    a.ok && m.tiktok.inits.length === 1 && sf[0] === PUBLISH_BASE + ".1" && m.tiktok.puts().length === 2 && m.tiktok.puts()[1].url === UPLOAD_BASE + "1" &&
    sha(m.tiktok.puts()[1].body) === sha(buf) && vr.tiktok_upload_ciphertext === null, a.ok ? J(a.v) : a.msg);
  // expired stored upload
  m = mountRoutes({ env: CONFIGURED, tiktok: { cut: 1 } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(100000, 24));
  prop = proposalOf(video);
  await approve(m, prop);
  rowOf(m, video.id).tiktok_upload_expires_at = iso(Date.now() - 1000);
  const putsBefore = m.tiktok.puts().length;
  a = await approve(m, prop);
  vr = rowOf(m, video.id);
  check("U12. the stored upload URL has expired: let go (cleared, failed, publish_id cleared), nothing PUT, no init",
    !a.ok && /expired/.test(a.msg || "") && vr.tiktok_status === "failed" && vr.tiktok_publish_id === null && vr.tiktok_upload_ciphertext === null &&
    m.tiktok.puts().length === putsBefore && m.tiktok.inits.length === 1, a.msg);
  m.tiktok.opts.cut = 0;
  r = await file(m, video);
  a = await approve(m, m.db.t.agent_proposals[0] || prop);
  check("U13. ...the next filing starts over: one new init", r.status === 201 && a.ok && m.tiktok.inits.length === 2, J([r.status, r.body.code, a.msg]));
  // stored, then TikTok says complete / failed
  m = mountRoutes({ env: CONFIGURED, tiktok: { cut: 1 } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(100000, 25));
  prop = proposalOf(video);
  await approve(m, prop);
  m.tiktok.opts.status = "PUBLISH_COMPLETE";
  const puts1 = m.tiktok.puts().length;
  a = await approve(m, prop);
  check("U14. a stored publish TikTok reports complete: recorded posted, nothing PUT, no init", a.ok && rowOf(m, video.id).tiktok_status === "posted" &&
    m.tiktok.puts().length === puts1 && m.tiktok.inits.length === 1, a.ok ? J(a.v) : a.msg);
  m = mountRoutes({ env: CONFIGURED, tiktok: { cut: 1 } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(100000, 26));
  prop = proposalOf(video);
  await approve(m, prop);
  m.tiktok.opts.status = "FAILED";
  a = await approve(m, prop);
  vr = rowOf(m, video.id);
  check("U15. a stored publish TikTok reports FAILED: failed, publish and upload cleared, its reason shown", !a.ok && /file_format_check_failed/.test(a.msg || "") &&
    vr.tiktok_status === "failed" && vr.tiktok_publish_id === null && vr.tiktok_upload_ciphertext === null, a.msg);
  // execution-time refusals
  m = mountRoutes({ env: CONFIGURED, tiktok: { creator: { duet_disabled: true } } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 27));
  a = await approve(m, proposalOf(video, { allow_duet: true }));
  check("U16. at execution a FRESH creator_info is checked: duets turned off since filing, refused, no init", !a.ok && /Allow duet: Turned off in your TikTok settings\./.test(a.msg || "") &&
    m.tiktok.creatorCalls().length === 1 && m.tiktok.inits.length === 0, a.msg);
  m = mountRoutes({ env: CONFIGURED, tiktok: { creator: { privacy_level_options: ["SELF_ONLY"] } } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 28));
  a = await approve(m, proposalOf(video));
  check("U17. ...and the privacy filed is no longer offered: refused, no init", !a.ok && m.tiktok.inits.length === 0);
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  buf = mp4(10000, 29);
  video = seedVideo(m.db, buf);
  m.storage.objects[video.path].buf = mp4(10000, 30);
  a = await approve(m, proposalOf(video));
  check("U18. the stored file no longer matches the filed fingerprint (checked by streaming): refused, no init, nothing PUT",
    !a.ok && /no longer matches/.test(a.msg || "") && m.tiktok.inits.length === 0 && m.tiktok.puts().length === 0, a.msg);
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 31));
  a = await approve(m, proposalOf(video, { sha256: "0".repeat(64) }));
  check("U19. the filed fingerprint isn't the video's: refused, nothing asked", !a.ok && m.tiktok.inits.length === 0 && m.tiktok.creatorCalls().length === 0);
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db, { open_id: OPEN_ID2 });
  video = seedVideo(m.db, mp4(10000, 32));
  a = await approve(m, proposalOf(video));
  check("U20. the connected account isn't the one filed for: refused, nothing asked", !a.ok && /isn't the one this was filed for/.test(a.msg || "") && m.tiktok.requests.length === 0);
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  for (let i = 0; i < 5; i++) seedVideo(m.db, mp4(1000, 300 + i), { status: "uploaded", path: null, tiktok_status: "posted", tiktok_posted_at: iso(Date.now() - 3600000), tiktok_post_id: POST_ID });
  video = seedVideo(m.db, mp4(10000, 33));
  a = await approve(m, proposalOf(video));
  check("U21. five TikTok posts in 24 hours: refused at execution too, no init", !a.ok && /5 videos to TikTok in 24 hours/.test(a.msg || "") && m.tiktok.inits.length === 0);
  m = mountRoutes({ env: CONFIGURED, tiktok: { initError: "You have posted too many videos today." } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 34));
  a = await approve(m, proposalOf(video));
  vr = rowOf(m, video.id);
  check("U22. TikTok refuses the init: its own words shown (no duration is parsed here), nothing stored", !a.ok && /TikTok refused the post: You have posted too many videos today\./.test(a.msg || "") &&
    vr.tiktok_publish_id === null && vr.tiktok_status === null && m.tiktok.puts().length === 0, a.msg);
  m = mountRoutes({ env: CONFIGURED, tiktok: { uploadUrl: "https://evil.example.com/upload/?upload_id=x" } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 35));
  a = await approve(m, proposalOf(video));
  check("U23. an upload URL not on open-upload.tiktokapis.com/upload/: refused, nothing stored, nothing PUT", !a.ok && rowOf(m, video.id).tiktok_publish_id === null && m.tiktok.puts().length === 0);
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 36));
  a = await approve(m, proposalOf(video, { caption: "Guaranteed results." }));
  check("U24. the claims screen runs again at execution", !a.ok && /guaranteed/i.test(a.msg || "") && m.tiktok.requests.length === 0);
  a = await approve(m, { id: uuid(), user_id: USER, action_type: "publish_tiktok_post", payload: { video_id: video.id } });
  check("U25. an incomplete payload: refused, nothing asked", !a.ok && /not complete/.test(a.msg || "") && m.tiktok.requests.length === 0);
  m = mountRoutes({ env: CONFIGURED, tiktok: { putStatus: 206 } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 37));
  a = await approve(m, proposalOf(video));
  check("U26. a 206 (part of the file) is not done: unfinished, the upload kept to send again", !a.ok && rowOf(m, video.id).tiktok_status === "initiated" && !!rowOf(m, video.id).tiktok_upload_ciphertext);
  // status route
  m = mountRoutes({ env: CONFIGURED, tiktok: { status: "PUBLISH_COMPLETE" } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 38), { tiktok_status: "processing", tiktok_publish_id: PUBLISH_BASE + ".7" });
  r = await hit(m, "get /api/tiktok/videos/:id/status", { params: { id: video.id } });
  check("U27. a post's status, fetched on demand: PUBLISH_COMPLETE recorded as posted, the link, and the line on removing a post",
    r.status === 200 && r.body.tiktok_status === "posted" && rowOf(m, video.id).tiktok_post_id === POST_ID && r.body.post_url === "https://www.tiktok.com/player/v1/" + POST_ID &&
    r.body.note === "To remove a TikTok post, delete it in the TikTok app.", J(r.body));
  const other = seedVideo(m.db, mp4(1000, 39), { user_id: OTHER, tiktok_status: "processing", tiktok_publish_id: PUBLISH_BASE + ".8" });
  r = await hit(m, "get /api/tiktok/videos/:id/status", { params: { id: other.id } });
  const plain = seedVideo(m.db, mp4(1000, 40));
  const rPlain = await hit(m, "get /api/tiktok/videos/:id/status", { params: { id: plain.id } });
  check("U28. another member's video is not found; a video never sent has no status (409)", r.status === 404 && rPlain.status === 409 && rPlain.body.code === "not_on_tiktok");
  check("U29. no delete: no TikTok route or code removes a post", !/delete_tiktok|tiktok\/videos\/:id\/propose-delete|\/post\/delete/.test(TT_SECTION + FILES.api) &&
    TK.MESSAGES.noDelete === "To remove a TikTok post, delete it in the TikTok app.");

  /* ── S ── */
  OUT("\n══ S. the stream profiles ══");
  let g = makeTiktok({});
  const sNoProf = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/upload/e201", { method: "PUT", body: null, contentLength: 0 }));
  const sGoogle = await attempt(g.streamUpload("https://www.googleapis.com/upload/x", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  const sPath = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/v2/x", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  const sYtAtTt = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/upload/e201", { profile: "youtube", method: "PUT", body: null, contentLength: 0 }));
  check("S1. the caller must name a profile; tiktok reaches only open-upload.tiktokapis.com under /upload/, and youtube never reaches it; no request",
    !sNoProf.ok && !sGoogle.ok && sGoogle.code === "invalid_url" && !sPath.ok && sPath.code === "invalid_url" && !sYtAtTt.ok && sYtAtTt.code === "invalid_url" && g.requests.length === 0,
    J([sNoProf.msg, sGoogle.code, sPath.code, sYtAtTt.code]));
  const s201 = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/upload/e201", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  check("S2. tiktok: an empty 201 is done (json null)", s201.ok && s201.v.status === 201 && s201.v.json === null, s201.ok ? J(s201.v) : s201.code);
  const s308 = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/upload/redirect", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  check("S3. tiktok: a 308 is not allowed (redirected)", !s308.ok && s308.code === "redirected", s308.ok ? J(s308.v) : s308.code);
  const sHtml = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/upload/html", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  const s200 = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/upload/empty200", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  check("S4. tiktok: a 201 with a body that is not JSON, or an empty 200, is refused", !sHtml.ok && sHtml.code === "unaccepted_type" && !s200.ok, J([sHtml.code, s200.code]));
  const sYt201 = await attempt(g.streamUpload("https://www.googleapis.com/upload/e201", { profile: "youtube", method: "PUT", body: null, contentLength: 0 }));
  check("S5. youtube is not loosened: an empty 201 is still refused there", !sYt201.ok, sYt201.ok ? J(sYt201.v) : sYt201.code);
  check("S6. the two profiles, as named", J(GF.STREAM_PROFILES) === J({ youtube: { host: "www.googleapis.com", pathPrefix: "/upload/", allow308: true, emptyOkStatuses: [] },
    tiktok: { host: "open-upload.tiktokapis.com", pathPrefix: "/upload/", allow308: false, emptyOkStatuses: [201, 206] } }) && Object.isFrozen(GF.STREAM_PROFILES));

  /* ── J ── */
  OUT("\n══ J. retention and deleting a video ══");
  db = makeDb();
  const bothV = seedVideo(db, mp4(100, 41), { youtube_video_id: "Ab3_x-9Kq2Z", uploaded_at: iso(now - 3600000), tiktok_status: "posted", tiktok_posted_at: iso(now - 600000), tiktok_post_id: POST_ID });
  const ytOnly = seedVideo(db, mp4(100, 42), { youtube_video_id: "Ab3_x-9Kq2Y", uploaded_at: iso(now - 3600000) });
  const ttOnly = seedVideo(db, mp4(100, 43), { tiktok_status: "posted", tiktok_posted_at: iso(now - 600000), tiktok_post_id: POST_ID });
  const heldV = seedVideo(db, mp4(100, 44), { youtube_video_id: "Ab3_x-9Kq2X", uploaded_at: iso(now - 3600000), tiktok_status: "posted", tiktok_posted_at: iso(now - 600000), tiktok_post_id: POST_ID });
  const oldTt = seedVideo(db, mp4(100, 45), { created_at: iso(now - 15 * 86400000), tiktok_status: "posted", tiktok_posted_at: iso(now - 15 * 86400000), tiktok_post_id: POST_ID });
  const oldNone = seedVideo(db, mp4(100, 46), { created_at: iso(now - 15 * 86400000) });
  const oldStuck = seedVideo(db, mp4(100, 47), { created_at: iso(now - 15 * 86400000), tiktok_status: "initiated", tiktok_publish_id: PUBLISH_BASE + ".3",
    tiktok_upload_ciphertext: seal(UPLOAD_BASE + "3").ciphertext, tiktok_upload_iv: "0".repeat(24), tiktok_upload_auth_tag: "0".repeat(32), tiktok_upload_expires_at: iso(now + 600000) });
  db.t.agent_proposals.push({ id: uuid(), user_id: USER, action_type: "publish_tiktok_post", status: "pending", payload: { video_id: heldV.id } });
  // NAMED, item 8 part 3a: the early delete now also needs a published Instagram reel; bothV, ytOnly and heldV have one, so only the platform under test differs.
  [bothV, ytOnly, heldV].forEach(function (v) { db.t.instagram_posts.push({ id: uuid(), user_id: USER, kind: "reel", status: "published", video_id: v.id, created_at: iso(now - 600000) }); });
  const tick =await MV.retentionTick({ supabase: db, storage: db.storage, now: function () { return now; } }, now);
  const rowIn = function (id) { return db.t.member_videos.filter(function (x) { return x.id === id; })[0]; };
  check("J1. YouTube, TikTok AND Instagram have it (NAMED, item 8 part 3a: Instagram added): the file deleted at once, status uploaded (a platform got it)", !db.storage.objects[bothV.path] && rowIn(bothV.id).status === "uploaded" && rowIn(bothV.id).path === null, J(tick));
  check("J2. only one platform has it, under 14 days: the file kept", !!db.storage.objects[ytOnly.path] && rowIn(ytOnly.id).status === "ready" && !!db.storage.objects[ttOnly.path] && rowIn(ttOnly.id).status === "ready");
  check("J3. a pending proposal names it: kept, even with both platforms done", !!db.storage.objects[heldV.path] && rowIn(heldV.id).status === "ready");
  check("J4. 14 days after it was added: deleted whatever the platforms have (uploaded when one got it, removed when none did)",
    !db.storage.objects[oldTt.path] && rowIn(oldTt.id).status === "uploaded" && !db.storage.objects[oldNone.path] && rowIn(oldNone.id).status === "removed" && tick.expired >= 3 && tick.both === 1, J(tick));
  check("J5. ...an unfinished TikTok upload on a deleted file is let go: failed, the publish and the upload URL cleared",
    rowIn(oldStuck.id).status === "removed" && rowIn(oldStuck.id).tiktok_status === "failed" && rowIn(oldStuck.id).tiktok_publish_id === null && rowIn(oldStuck.id).tiktok_upload_ciphertext === null);
  db = makeDb();
  const named = seedVideo(db, mp4(100, 48));
  db.t.agent_proposals.push({ id: uuid(), user_id: USER, action_type: "publish_tiktok_post", status: "pending", payload: { video_id: named.id } });
  const del = await MV.deleteVideo({ supabase: db, storage: db.storage }, USER, named.id);
  check("J6. DELETE /api/videos/:id refuses while a pending TikTok proposal names the video", del.status === 409 && del.body.code === "in_proposal" && !!db.storage.objects[named.path]);
  check("J7. the kept line is the server's own, word for word", MV.MESSAGES.kept === "BizForce deletes the file once every platform you sent it to has it, or 14 days after you added it.");

  /* ── P ── */
  OUT("\n══ P. the pages ══");
  check("P1. the Social page: the TikTok panel with its three lines word for word, the not-set-up line, and tiktok.js right after youtube.js (NAMED, item 8 part 3a: oauth-return.js now before, instagram.js after)",
    FILES.page.indexOf("<p class=\"bsky-quiet\">Until TikTok reviews BizForce, TikTok keeps posts from BizForce visible only to you.</p>") !== -1 &&
    FILES.page.indexOf("<p class=\"bsky-quiet\">To remove a TikTok post, delete it in the TikTok app.</p>") !== -1 &&
    FILES.page.indexOf("<p class=\"bsky-quiet\">BizForce deletes the file once every platform you sent it to has it, or 14 days after you added it.</p>") !== -1 &&
    FILES.page.indexOf("<p class=\"bsky-warn\" id=\"ttUnavailable\" hidden>TikTok connection isn't set up yet.</p>") !== -1 && FILES.page.indexOf("id=\"ttConnect\"") !== -1 &&
    FILES.page.indexOf("<script src=\"/scripts/oauth-return.js\"></script>\n<script src=\"/scripts/youtube.js\"></script>\n<script src=\"/scripts/tiktok.js\"></script>\n<script src=\"/scripts/instagram.js\"></script>") !== -1);
  let dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers(), "tiktok");
  await flush();
  const fin = dom.fetches.filter(function (x) { return x.path === "/api/tiktok/finish"; })[0];
  const finIdx = dom.events.indexOf("fetch:POST /api/tiktok/finish"), rsIdx = dom.events.indexOf("replaceState:" + PAGE_PATH);
  check("P2. back from TikTok (marker tiktok): code and state POSTed to finish, then stripped with replaceState; the marker cleared; YouTube's finish never called",
    !!fin && J(fin.body) === J({ code: CODE, state: "S".repeat(43) }) && finIdx !== -1 && rsIdx > finIdx && dom.session.bf_oauth_return === undefined &&
    !dom.fetches.some(function (x) { return x.path === "/api/youtube/finish"; }) && dom.get("ttConnectMsg").textContent === "Connected.", dom.events.join(","));
  dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers({ "POST /api/tiktok/finish": { status: 400, body: { error: "That sign-in link has expired or was already used. Start again." } } }), "tiktok");
  await flush();
  check("P3. ...a refused finish is stripped too, with the server's words", dom.events.indexOf("replaceState:" + PAGE_PATH) !== -1 &&
    dom.get("ttConnectMsg").textContent === "That sign-in link has expired or was already used. Start again.");
  dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers(), null);
  await flush();
  check("P4. a return with NO marker: neither script finishes; it is stripped and the page says \"Start the connection again.\"",
    !dom.fetches.some(function (x) { return /\/finish$/.test(x.path); }) && dom.events.indexOf("replaceState:" + PAGE_PATH) !== -1 &&
    dom.get("ytConnectMsg").textContent === "Start the connection again.");
  dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers({ "GET /api/youtube/status": { status: 200, body: { youtube_available: true, connected: false, status: "not_connected" } },
    "POST /api/youtube/finish": { status: 200, body: { youtube_available: true, connected: true, status: "connected", channel_title: "x" } } }), "youtube");
  await flush();
  check("P5. Google's return (marker youtube): only YouTube's finish runs", dom.fetches.some(function (x) { return x.path === "/api/youtube/finish"; }) &&
    !dom.fetches.some(function (x) { return x.path === "/api/tiktok/finish"; }));
  dom = runPage("?error=access_denied&state=" + "S".repeat(43), pageAnswers(), "tiktok");
  await flush();
  check("P6. ?error=access_denied with the marker tiktok: stripped, \"You cancelled the TikTok sign-in.\", no finish", dom.events.indexOf("replaceState:" + PAGE_PATH) !== -1 &&
    dom.get("ttConnectMsg").textContent === "You cancelled the TikTok sign-in." && !dom.fetches.some(function (x) { return /\/finish$/.test(x.path); }));
  dom = runPage("", pageAnswers({ "GET /api/tiktok/status": { status: 200, body: { tiktok_available: true, connected: false, status: "not_connected" } } }));
  await flush();
  dom.get("ttConnectBtn").click();
  await flush();
  check("P7. Connect TikTok sets the marker to tiktok and goes to TikTok's authorize page", dom.assigned.length === 1 && dom.assigned[0].indexOf("https://www.tiktok.com/v2/auth/authorize/") === 0 &&
    dom.session.bf_oauth_return === "tiktok");
  dom = runPage("", pageAnswers({ "GET /api/tiktok/status": { status: 200, body: { tiktok_available: true, connected: false, status: "not_connected" } },
    "POST /api/tiktok/start": { status: 200, body: { authorize_url: "https://www.tiktok.com.evil.example/v2/auth/authorize/" } } }));
  await flush();
  dom.get("ttConnectBtn").click();
  await flush();
  check("P8. ...and never anywhere else", dom.assigned.length === 0 && dom.session.bf_oauth_return === undefined);
  dom = runPage("", pageAnswers({ "GET /api/tiktok/status": { status: 200, body: { tiktok_available: false, connected: false, status: "not_connected" } } }));
  await flush();
  check("P9. TikTok not set up (and YouTube not either): the not-set-up line shows, Connect and the file input are off", dom.get("ttUnavailable").hidden === false &&
    dom.get("ttConnectBtn").disabled === true && dom.get("ytFile").disabled === true);
  dom = runPage("", pageAnswers());
  await flush();
  check("P10. TikTok set up, YouTube not: the file input is on (a video can go to either)", dom.get("ytFile").disabled === false);
  const list = dom.get("ytVideoList");
  const prepBtn = findAll(list, function (n) { return n.tagName === "BUTTON" && n.textContent === "Prepare TikTok post"; });
  check("P11. a ready video not on TikTok gets \"Prepare TikTok post\"; a posted one gets its tiktok.com link, the remove line and no remove button",
    prepBtn.length === 1 && findAll(list, function (n) { return n.tagName === "A" && n.href === "https://www.tiktok.com/player/v1/" + POST_ID && n.rel === "noopener"; }).length === 1 &&
    findAll(list, function (n) { return n.textContent === "To remove a TikTok post, delete it in the TikTok app." && n.tagName === "P"; }).length === 1 &&
    findAll(list, function (n) { return n.tagName === "BUTTON" && /Remove from TikTok|Delete from TikTok/.test(n.textContent); }).length === 0);
  prepBtn[0].click();
  await flush();
  const selects = findAll(list, function (n) { return n.tagName === "SELECT" && n.children.length > 0 && n.children[0].textContent === "Choose who can see it"; });
  const sel = selects[0];
  const boxes = findAll(list, function (n) { return n.tagName === "INPUT" && n.type === "checkbox"; });
  const labelFor = function (box) { return box.parentNode ? box.parentNode.textContent : ""; };
  const boxNamed = function (name) { return boxes.filter(function (bx) { return labelFor(bx).indexOf(name) !== -1; })[0]; };
  check("P12. the form names the account (\"Posting as Maple Street Bakery\") and carries the review line",
    findAll(list, function (n) { return n.textContent === "Posting as " + NICK; }).length === 1 &&
    findAll(list, function (n) { return n.tagName === "P" && n.textContent === "Until TikTok reviews BizForce, TikTok keeps posts from BizForce visible only to you."; }).length === 1);
  check("P13. who can see it: TikTok's options only, in words, and NOTHING chosen (no default)", !!sel && sel.value === "" &&
    J(sel.children.slice(1).map(function (o) { return o.value; })) === J(OPTIONS) && sel.children.slice(1).every(function (o) { return o.selected === false; }) &&
    J(sel.children.slice(1).map(function (o) { return o.textContent; })) === J(["Everyone", "Friends", "Only you"]), sel ? J(sel.children.map(function (o) { return [o.value, o.selected]; })) : "no select");
  const cb = boxNamed("Allow comments"), du = boxNamed("Allow duet"), stc = boxNamed("Allow stitch"), dis = boxNamed("Disclose video content"), yb = boxNamed("Your brand"), bc = boxNamed("Branded content");
  check("P14. Allow comments, duet and stitch start unchecked; duet (turned off for this account) is disabled, \"Turned off in your TikTok settings\"",
    !!cb && !!du && !!stc && !cb.checked && !du.checked && !stc.checked && du.disabled === true && cb.disabled === false && labelFor(du).indexOf("Turned off in your TikTok settings") !== -1);
  const consentP = function () { return findAll(list, function (n) { return n.tagName === "P" && /^By posting, you agree to TikTok's/.test(n.textContent); })[0]; };
  const labelP = function () { return findAll(list, function (n) { return n.tagName === "P" && /^Your video will be labeled/.test(n.textContent) && !n.hidden; })[0]; };
  check("P15. \"Disclose video content\" starts off, its two options hidden; the consent line is the music one",
    !!dis && !dis.checked && yb.parentNode.parentNode.hidden === true && !!consentP() && consentP().textContent === "By posting, you agree to TikTok's Music Usage Confirmation." && !labelP());
  dis.checked = true; dis.fire("change");
  yb.checked = true; yb.fire("change");
  check("P16. Your brand: \"Your video will be labeled 'Promotional content'.\"", !!labelP() && labelP().textContent === "Your video will be labeled 'Promotional content'." &&
    consentP().textContent === "By posting, you agree to TikTok's Music Usage Confirmation.");
  bc.checked = true; bc.fire("change");
  const selfOpt = sel.children.filter(function (o) { return o.value === "SELF_ONLY"; })[0];
  check("P17. Branded content: \"Your video will be labeled 'Paid partnership'.\", the consent line names the Branded Content Policy, \"Only you\" can't be chosen",
    !!labelP() && labelP().textContent === "Your video will be labeled 'Paid partnership'." &&
    consentP().textContent === "By posting, you agree to TikTok's Branded Content Policy and Music Usage Confirmation." && selfOpt.disabled === true);
  // YouTube's form has its own "File for approval": TikTok's is the one in the same box as the privacy select.
  const ttForm = sel ? sel.parentNode.parentNode.parentNode : list;
  const fileBtn = findAll(ttForm, function (n) { return n.tagName === "BUTTON" && n.textContent === "File for approval"; })[0];
  const n0 = dom.fetches.length;
  fileBtn.click();
  await flush();
  const msgs = function () { return findAll(list, function () { return true; }).map(function (n) { return n._t; }); };
  check("P18. filing with nothing chosen for who can see it is stopped on the page", dom.fetches.length === n0 && msgs().indexOf("Choose who can see this post.") !== -1, J(msgs()));
  sel.value = "SELF_ONLY";
  fileBtn.click();
  await flush();
  check("P19. branded content as Only you is stopped on the page: \"Branded content can't be private.\"", dom.fetches.length === n0 && msgs().indexOf("Branded content can't be private.") !== -1);
  yb.checked = false; bc.checked = false; yb.fire("change");
  fileBtn.click();
  await flush();
  check("P20. disclosure on with neither option is stopped on the page", dom.fetches.length === n0 && msgs().indexOf("Choose Your brand, Branded content, or both.") !== -1);
  dis.checked = false; dis.fire("change");
  sel.value = "PUBLIC_TO_EVERYONE";
  cb.checked = true;
  findAll(ttForm, function (n) { return n.tagName === "TEXTAREA"; })[0].value = "Spring cakes.";
  fileBtn.click();
  await flush();
  const pp = dom.fetches.filter(function (x) { return x.path === "/api/tiktok/propose-post"; })[0];
  check("P21. filed: propose-post with exactly what was chosen", !!pp && J(pp.body) === J({ video_id: PAGE_VIDEO.id, caption: "Spring cakes.", privacy_level: "PUBLIC_TO_EVERYONE",
    allow_comment: true, allow_duet: false, allow_stitch: false, disclose: false, brand_organic: false, brand_content: false }), pp ? J(pp.body) : "none");
  dom = runPage("", pageAnswers({ "GET /api/videos": { status: 200, body: { videos: [Object.assign({}, PAGE_POSTED, { tiktok_post_url: "https://evil.example/player/v1/1", label: "<img src=x onerror=alert(1)>" })] } } }));
  await flush();
  check("P22. a post link not on www.tiktok.com/player/v1/ is not drawn; a label is text", findAll(dom.get("ytVideoList"), function (n) { return n.tagName === "A"; }).length === 0 &&
    dom.get("ytVideoList").textContent.indexOf("<img src=x onerror=alert(1)>") !== -1);
  check("P23. no innerHTML anywhere: nothing set with it in these runs, and tiktok.js never names it", dom.innerHTML.length === 0 && !/innerHTML/.test(stripComments(FILES.ui)));
  check("P24. the proposal card: publish_tiktok_post drawn from escaped fields, the privacy in words, the label line, only a tiktok.com player address as a link",
    /function tiktokPostPayloadFields\(payload\)/.test(FILES.proposals) && /function tiktokResultHtml\(result\)/.test(FILES.proposals) &&
    FILES.proposals.indexOf("fieldsHtml = tiktokPostPayloadFields(p.payload || {});") !== -1 && FILES.proposals.indexOf("execHtml = tiktokResultHtml(p.execution_result);") !== -1 &&
    FILES.proposals.indexOf("<pre class=\"exec-block tt-caption\">' + escapeHtml(String(payload.caption == null ? \"\" : payload.caption))") !== -1 &&
    FILES.proposals.indexOf("/^https:\\/\\/www\\.tiktok\\.com\\/player\\/v1\\/[0-9]{1,64}$/.test(result.post_url)") !== -1 &&
    FILES.proposals.indexOf("To remove a TikTok post, delete it in the TikTok app.") !== -1);
  const card = function (name) { return (new RegExp("<p class=\"int-card-name\">" + name.replace("/", "\\/") + "</p>\\s*<p class=\"int-card-desc\">([^<]*)</p>\\s*<span class=\"int-status\">([^<]*)</span>").exec(FILES.integrations) || []); };
  check("P25. Integrations: TikTok and YouTube say they connect on the Social page (not Removed), and say what is true until review",
    card("TikTok")[2] === "On the Social page" && /Social Agent page/.test(card("TikTok")[1] || "") && /visible only to you/.test(card("TikTok")[1] || "") &&
    card("YouTube")[2] === "On the Social page" && /keeps uploads from BizForce private/.test(card("YouTube")[1] || "") && card("Facebook")[2] === "Removed");
  check("P26. the guide tips: Social names TikTok as connecting, Integrations names the new state; still 4 Integrations tips",
    // NAMED (Nov 7 2026, Instagram posting, migration 179): BEFORE "Bluesky, Mastodon, YouTube and TikTok connect so far"; AFTER Instagram is named too.
    FILES.guide.indexOf("Bluesky, Mastodon, YouTube, TikTok and Instagram connect so far, and posts cannot be scheduled") !== -1 &&
    ((/"integrations\.html": \[([\s\S]*?)\n    \]/.exec(FILES.guide) || ["", ""])[1].match(/\n      "/g) || []).length === 4 &&
    FILES.guide.indexOf("\\\"On the Social page\\\"") !== -1);

  /* ── G ── */
  OUT("\n══ G. legal, yourData, README, registries, the migration ══");
  const PRIVACY = "If you connect your TikTok account, BizForce stores your TikTok name and account id and the access TikTok grants BizForce, encrypted, and uses that access only to post a video when you approve it and to check its status when you ask. Videos you send to TikTok go only to TikTok with the caption and settings you approve; BizForce cannot delete a TikTok post, so you delete it in TikTok. You can disconnect at any time, which also asks TikTok to cancel BizForce's access, and everything is deleted with your account.";
  const TERMS = "If you post to TikTok through BizForce, you confirm you have the rights to the video and its music and that it follows TikTok's rules.";
  const esc = function (t) { return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); };
  let built = null;
  try { built = LP.buildLegalPages(); } catch (e) { built = null; }
  const bp = built ? built["privacy.html"] : "", bt = built ? built["terms.html"] : "";
  check("G1. the privacy sentence word for word, once, right after YouTube's", LP.TIKTOK_PRIVACY_SENTENCE === PRIVACY && bp.split(esc(PRIVACY)).length === 2 &&
    bp.indexOf(esc(LP.YOUTUBE_PRIVACY_SENTENCE)) !== -1 && bp.indexOf(esc(LP.YOUTUBE_PRIVACY_SENTENCE)) < bp.indexOf(esc(PRIVACY)));
  check("G2. the terms sentence word for word, once, right after YouTube's", LP.TIKTOK_TERMS_SENTENCE === TERMS && bt.split(esc(TERMS)).length === 2 &&
    bt.indexOf(esc(LP.YOUTUBE_TERMS_SENTENCE)) < bt.indexOf(esc(TERMS)));
  check("G3. YouTube's sentence now says the files go once every platform has them", LP.YOUTUBE_PRIVACY_SENTENCE.indexOf("and deleted once every platform you sent them to has them, or 14 days after you added them") !== -1 &&
    LP.YOUTUBE_PRIVACY_SENTENCE.indexOf("as soon as YouTube has them") === -1);
  check("G4. privacy.html and terms.html carry both, as built", FILES.privacy.split(esc(PRIVACY)).length === 2 && FILES.terms.split(esc(TERMS)).length === 2 &&
    FILES.privacy.indexOf(esc("TikTok (posting the videos you approve to your own TikTok account, when you connect it)")) !== -1);
  const LEGAL = realRequire("./lib/legal");
  check("G5. TERMS_VERSION is Nov 7 2026", LEGAL.TERMS_VERSION === "2026-11-07", LEGAL.TERMS_VERSION);
  const YD = realRequire("./lib/yourData");
  const ttEntry = (YD.DATA || []).filter(function (e) { return e.table === "member_tiktok_connections"; })[0] ||
    (FILES.yourData.indexOf("{ table: \"member_tiktok_connections\", group: \"account\"") !== -1 ? { select: (/table: "member_tiktok_connections"[\s\S]*?select: "([^"]*)"/.exec(FILES.yourData) || [])[1], onDelete: "delete" } : null);
  check("G6. yourData: the TikTok connection exported as its name and date only, deleted with the account; never its tokens",
    !!ttEntry && ttEntry.select === "display_name, created_at" && ttEntry.onDelete === "delete" &&
    FILES.yourData.indexOf("\"Your TikTok access: stored encrypted; the export shows only your TikTok name and the date you connected.\"") !== -1 &&
    // NAMED (Nov 7 2026, Instagram posting, migration 179): BEFORE "member_tiktok_connections", "oauth_states" side by side. AFTER
    // member_instagram_connections sits between them; the TikTok connection is still deleted before the sign-in states.
    FILES.yourData.indexOf("\"member_youtube_connections\", \"member_tiktok_connections\", \"member_instagram_connections\", \"oauth_states\"") !== -1);
  check("G7. ...the videos export TikTok's status, time and post id, never the publish id or the upload address; TikTok a third party; the sign-in states line",
    FILES.yourData.indexOf("select: \"id, label, bytes, status, youtube_video_id, uploaded_at, tiktok_status, tiktok_posted_at, tiktok_post_id, created_at\"") !== -1 &&
    FILES.yourData.indexOf("{ name: \"TikTok\", for: \"posting the videos you approve to your own TikTok account, when you connect it\" }") !== -1 &&
    // NAMED (Nov 7 2026, Instagram posting): BEFORE "..., Connect YouTube and Connect TikTok". AFTER Connect Instagram is named last.
    FILES.yourData.indexOf("Sign in with Microsoft, Connect Shopify, Connect YouTube, Connect TikTok and Connect Instagram") !== -1);
  check("G8. schemaCheck knows member_tiktok_connections at 178; the backup leaves it out", FILES.schema.indexOf("[\"member_tiktok_connections\", \"178_tiktok_posting.sql\"],") !== -1 &&
    FILES.backup.indexOf("member_tiktok_connections: \"members' TikTok access, sealed; members connect again\",") !== -1);
  const tts = (FILES.readme.split("## TikTok app setup")[1] || "").split("\n## ")[0];
  check("G9. README: the two env var rows and the TikTok app setup (Login Kit for Web, Direct Post, both scopes, the exact redirect URI, SELF_ONLY until the audit, the secret only on Railway)",
    /\n\| `TIKTOK_CLIENT_KEY` \| none \| /.test(FILES.readme) && /\n\| `TIKTOK_CLIENT_SECRET` \| none \| [^\n]*only on Railway/.test(FILES.readme) &&
    /Login Kit for Web/.test(tts) && /Content Posting API with Direct Post/.test(tts) && /`user\.info\.basic` and `video\.publish`/.test(tts) &&
    tts.indexOf("exactly `https://bizforceai.net/agents/social.html`") !== -1 && /only if TikTok asks/.test(tts) && /SELF_ONLY/.test(tts) && /only on Railway/.test(tts));
  check("G10. migration 178: the connections table with RLS on and nothing granted; the eight video columns; tiktok_login in the purpose check and the verifier rule",
    FILES.migration.indexOf("ALTER TABLE public.member_tiktok_connections ENABLE ROW LEVEL SECURITY;") !== -1 &&
    FILES.migration.indexOf("REVOKE ALL ON public.member_tiktok_connections FROM anon, authenticated;") !== -1 &&
    (FILES.migration.match(/ADD COLUMN IF NOT EXISTS tiktok_/g) || []).length === 8 &&
    FILES.migration.indexOf("CHECK (purpose IN ('mailbox_microsoft', 'store_shopify', 'youtube_google', 'tiktok_login'))") !== -1 &&
    FILES.migration.indexOf("purpose IN ('store_shopify', 'tiktok_login')") !== -1);
  check("G11. the server's limits: SOCIAL_SEARCH_LIMITS.tiktok.caption_max 2200, and SOCIAL_PLATFORMS.tiktok max 2200",
    /tiktok: \{\n    label: "TikTok",\n    \/\/ [^\n]*\n    caption_max: 2200,/.test(FILES.server) && /tiktok: \{\n    label: "TikTok",\n    max: 2200, kind: "hard",/.test(FILES.server));
  check("G12. no emoji in any TikTok file", [FILES.auth, FILES.api, FILES.ui, TT_SECTION, FILES.migration].every(function (s) { return !EMOJI.test(s); }));
  const migFiles = fs.readdirSync(path.join(REPO, "supabase", "migrations")).filter(function (x) { return /^\d{3}_.*\.sql$/.test(x); });
  const highest = migFiles.map(function (x) { return Number(x.slice(0, 3)); }).reduce(function (acc, x) { return Math.max(acc, x); }, 0);
  // NAMED (Nov 7 2026, Instagram posting, migration 179): BEFORE 178 was the highest. AFTER it is the only 178, and only
  // 179_instagram_posting.sql is above it; "the highest" is checkInstagramPosting R1's.
  check("G13. R1. 178_tiktok_posting.sql is the only 178, and only 179_instagram_posting.sql is above it (checkInstagramPosting R1)", highest === 179 &&
    migFiles.filter(function (x) { return /^178_/.test(x); }).join() === "178_tiktok_posting.sql" &&
    migFiles.filter(function (x) { return Number(x.slice(0, 3)) > 178; }).join() === "179_instagram_posting.sql", highest);
  check("G14. the network tripwire never fired, and no promise was left rejected", TRIPPED.length === 0 && UNHANDLED.length === 0, J(TRIPPED.concat(UNHANDLED.map(function (e) { return String(e && e.message); }))));

  OUT("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (failures + passes) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
})().catch(function (e) { OUT("    FAIL  the harness stopped: " + ((e && e.stack) || e)); process.exit(1); });
