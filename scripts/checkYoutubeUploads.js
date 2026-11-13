/* checkYoutubeUploads: YouTube uploads (migration 177). Connect YouTube through Google OAuth with PKCE, private 50 MB video
   storage verified by streaming, resumable approved uploads with crash-safe sessions, and removal through approval.

   WHAT IT PROVES (lib/googleAuth.js, lib/youtubeApi.js, lib/memberVideos.js, the stream mode of lib/guardedFetch.js, the
   YouTube section of server.js, its executors and the 04:45 chain, migration 177, the Social page's YouTube panel and the
   proposal cards). Google is a stub behind the REAL guarded fetcher (lib/guardedFetch.js createGuardedFetch, with only its
   DNS answer and its https.request stood in): the token and revoke endpoints, channels.list, videos.list, videos.delete,
   the resumable start and the session it names. Storage is in memory and hands objects back as web ReadableStreams, as
   storage-js's download(path).asStream() does. The database is in memory and enforces migration 177's CHECKs. A network
   tripwire fails the run if anything opens a socket, asks real DNS or fetches. Nothing here calls Google.

     O. CONNECT. 503 unconfigured; the authorize URL exactly (both scopes, offline, consent, S256); the state stored only as
        its sha256, purpose youtube_google, the verifier sealed, no flow_context; the state consumed once; both scopes
        required (422); the refresh token required; both tokens sealed before YouTube is asked anything; no channel 422.
     T. TOKENS. Within 5 minutes of expiry a refresh; the compare-and-set on token_version; the loser uses the winner's
        token; one refresh at a time; a refresh with no new refresh token keeps the stored one, a rotated one is stored;
        invalid_grant is needs_reconnect with one notice.
     D. DISCONNECT. Revoke as a best effort (Google down still disconnects); only youtube_google states deleted; the note.
     V. VIDEOS. upload-url (types, 50 MB, 2 waiting, the path); finalize streamed (asStream, never a whole download),
        sniffed (every MP4 brand, qt, WebM with DocType webm; HEIC and HEIF refused), counted, hashed; a mismatch deletes
        the object and answers 422; the list never shows a path, a fingerprint or a session; another member's video is
        404 everywhere; delete; the caps and limiters.
     F. FILING. The metadata rules; privacy private by default; made_for_kids required; the claims screen; one pending
        upload per video; filing never sends; the generic proposals route refuses both types.
     U. THE UPLOAD on approval. The fingerprint before anything; the 5-in-24-hours cap; 100 units reserved first and
        failing closed; the session sealed before the first byte; one resume per run; a stored session gets a status
        query first and never a second insert; the frozen metadata reused; an expired session cleared; the guard that
        holds the last chunk; the record, the link, the object deleted; nothing logged.
     R. REMOVAL and STATUS. 50 units, DELETE, removed; videos.list part=status,processingDetails, 1 unit.
     S. THE STREAM MODE. PUT only; www.googleapis.com under /upload/ only; 308 answered, no other 3xx followed; the idle
        timeout; the JSON answer cap; Range and Location exposed.
     J. RETENTION. Its own job_runs row; 14-day ready videos, leftovers and 1-day orphans removed, the rest kept; the
        04:45 chain runs it after the Shopify purge.
     P. THE PAGES. The three lines word for word; the query stripped with replaceState whatever the answer; only an
        accounts.google.com address followed; the upload flow; Private first; "Made for kids?" required; textContent only.
     G. LEGAL AND REGISTRIES. The privacy and terms sentences word for word and in place; gateRules, yourData, backup,
        schemaCheck, accountFiles, README; migration 177; R1, the highest migration.

   MUTATIONS: MUTATE=<name> applies one in memory; MUTATE=all runs each in its own process. The 32 the brief named, then the
   ones the code earned (disconnect-deletes-all-states, guard-releases-changed-file, location-unchecked,
   readonly-scope-dropped, second-pending-upload, refile-metadata-changed, claims-unscreened, ready-cap-missing,
   refresh-margin-ignored, retention-ready-kept, refresh-not-single-flight, refresh-rotation-ignored). */
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
const readFe = (f) => fs.readFileSync(path.join(FE, f), "utf8");

const MUTATIONS = {
  "pkce-plain": ["server",
    "var url = ga.authorizeUrl(config.clientId, youtubeRedirectUri(), state, ga.challengeFor(verifier));",
    "var url = ga.authorizeUrl(config.clientId, youtubeRedirectUri(), state, verifier);"],
  // NAMED (Nov 7 2026, TikTok posting): TikTok's finish consumes its state with the same first line, so the anchor
  // goes on to YouTube's own second line (ga.stateHash) to stay one match.
  "state-reusable": ["server",
    "var consumed = await supabase.from(\"oauth_states\").update({ consumed_at: consumedAt })\n        .eq(\"state_hash\", ga.stateHash(",
    "var consumed = await supabase.from(\"oauth_states\").update({ consumed_at: null })\n        .eq(\"state_hash\", ga.stateHash("],
  "scopes-unchecked": ["auth",
    "  if (needScopes && !grantsYoutube(j.scope)) throw new GoogleError(\"no_scopes\", \"scope_missing\");\n", ""],
  "unsealed-before-api": ["server",
    "      // Sealed first: both tokens are encrypted before YouTube is asked anything.\n",
    "      await ya.readChannel(youtubeDeps(), grant.accessToken);\n      // Sealed first: both tokens are encrypted before YouTube is asked anything.\n"],
  "refresh-token-dropped": ["api",
    "  if (grant.refreshToken) {\n    var refresh = sealed(deps.crypt, grant.refreshToken);\n",
    "  if (true) {\n    var refresh = sealed(deps.crypt, grant.refreshToken || \"\");\n"],
  "refresh-cas-missing": ["api",
    ".eq(\"id\", row.id).eq(\"user_id\", row.user_id).eq(\"token_version\", version).select(\"id\");",
    ".eq(\"id\", row.id).eq(\"user_id\", row.user_id).select(\"id\");"],
  "invalid-grant-ignored": ["api",
    "      await markNeedsReconnect(deps, row, \"invalid_grant\");\n", ""],
  "revoke-blocks-disconnect": ["server",
    "        revoked = await ga.revoke(refreshToken);\n",
    "        revoked = await ga.revoke(refreshToken);\n        if (!revoked) return res.status(502).json({ error: ga.MESSAGES.unreachable, code: \"unreachable\" });\n"],
  "whole-file-buffered": ["videos",
    "  var got = await storage.from(BUCKET).download(path).asStream();\n",
    "  var got = await storage.from(BUCKET).download(path);\n"],
  "sniff-trusts-declared": ["videos",
    "    else if (sniffed !== extOf(path)) refusal = { status: 422, code: \"mismatch\", error: MESSAGES.mismatch };\n", ""],
  "heic-accepted": ["videos",
    "    if (REFUSED_BRANDS.indexOf(brand) !== -1) return null;\n",
    "    if (REFUSED_BRANDS.indexOf(brand) !== -1) return \"mp4\";\n"],
  "size-mismatch-accepted": ["videos",
    "    else if (m.bytes !== declared) refusal = { status: 422, code: \"size_mismatch\", error: MESSAGES.sizeMismatch };\n", ""],
  "sha-unchecked-at-send": ["api",
    "  if ((counted.count || 0) >= MV.UPLOADS_PER_DAY) throw fail(MESSAGES.dailyCap);\n  if (!(await verifyFile(deps, video))) throw fail(MESSAGES.fingerprint);\n",
    "  if ((counted.count || 0) >= MV.UPLOADS_PER_DAY) throw fail(MESSAGES.dailyCap);\n"],
  "quota-unreserved": ["api",
    "    await YQ.reserveYoutubeUnits(deps.supabase, { method: method, caller: YQ.YOUTUBE_MEMBER_CALLER, user_id: userId }, deps.now());\n", ""],
  "daily-cap-missing": ["api",
    "  if ((counted.count || 0) >= MV.UPLOADS_PER_DAY) throw fail(MESSAGES.dailyCap);\n", ""],
  "session-unsealed": ["api",
    "  var stored = await deps.supabase.from(\"member_videos\").update({ session_ciphertext: s.ciphertext, session_iv: s.iv, session_auth_tag: s.authTag })\n" +
    "    .eq(\"id\", video.id).eq(\"user_id\", ownerId).eq(\"status\", \"ready\").is(\"session_ciphertext\", null).select(\"id\");\n",
    "  var stored = { error: null, data: [{ id: video.id }] };\n"],
  "second-insert-with-session": ["api",
    "  if (video.session_ciphertext) {\n    // A stored session: ask YouTube first. Never a second insert while one is stored.\n",
    "  if (false) {\n    // A stored session: ask YouTube first. Never a second insert while one is stored.\n"],
  "resume-twice": ["api",
    "    if (!interrupted || resumed) return null;\n", "    if (!interrupted) return null;\n"],
  "status-query-skipped": ["api",
    "      q = await queryUpload(deps, session, token, Number(video.bytes));\n", "      q = { status: 308, headers: {} };\n"],
  "upload-auto-executed": ["api",
    "  if (reused) note += \" \" + MESSAGES.reused;\n",
    "  if (reused) note += \" \" + MESSAGES.reused;\n  await executePublish(deps, ins.data);\n"],
  "privacy-default-public": ["videos",
    "b.privacy === \"\" ? \"private\" : b.privacy;", "b.privacy === \"\" ? \"public\" : b.privacy;"],
  "made-for-kids-optional": ["videos",
    "  if (typeof b.made_for_kids !== \"boolean\") return { ok: false, error: MESSAGES.kids, field: \"made_for_kids\" };\n", ""],
  // NAMED (Nov 7 2026, TikTok posting, migration 178): BEFORE the executor deleted the file once YouTube had it. AFTER the file
  // is deleted by the retention pass once YouTube AND TikTok have it (J8), so the mutation keeps every such file instead.
  // NAMED, item 8 part 3a (Instagram posting): the filter now also needs Instagram and maps each row; the mutation still keeps every file.
  "file-kept-after-upload": ["videos",
    // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): the filter now also needs Facebook and maps each row through withFacebook; the mutation still keeps every file.
    "    var bothRows = (both.data || []).filter(function (r) { return r.path && !named[r.id] && bothIg.published[r.id] && !bothIg.holding[r.id]; })\n      .filter(function (r) { return bothFb.published[r.id] && !bothFb.holding[r.id]; })\n      .map(function (r) { return withFacebook(withInstagram(r, bothIg), bothFb); });\n", "    var bothRows = [];\n"],
  "retention-missing": ["server",
    "    return await require(\"./lib/memberVideos\").retentionTick(youtubeDeps());\n", "    return null;\n"],
  "foreign-video-visible": ["videos",
    "  var r = await supabase.from(\"member_videos\").select(ROW_COLUMNS).eq(\"id\", id).eq(\"user_id\", userId).maybeSingle();\n  if (r.error) throw r.error;\n  return r.data && r.data.user_id === userId ? r.data : null;\n",
    "  var r = await supabase.from(\"member_videos\").select(ROW_COLUMNS).eq(\"id\", id).maybeSingle();\n  if (r.error) throw r.error;\n  return r.data || null;\n"],
  // NAMED (Nov 7 2026, TikTok posting): the host check is now the named profile's (youtube: www.googleapis.com).
  "stream-host-unrestricted": ["fetch",
    "target.hostname !== profile.host || ", ""],
  "other-3xx-followed": ["fetch",
    "        if (status >= 300 && status < 400) {\n          res.destroy();\n          return fail(new GuardedFetchError(\"redirected\", \"answered \" + status + \"; the stream mode never follows a redirect\"));\n        }\n", ""],
  "session-uri-logged": ["api",
    "  // Sealed BEFORE the first byte: a crash from here on leaves a session to continue, never a second insert.\n",
    "  console.log(\"[youtube] upload session \" + location);\n  // Sealed BEFORE the first byte: a crash from here on leaves a session to continue, never a second insert.\n"],
  "unconfigured-not-503": ["server",
    "  return res.status(503).json({ error: require(\"./lib/googleAuth\").MESSAGES.notConfigured, code: \"not_configured\", saved: false });",
    "  return res.status(200).json({ error: require(\"./lib/googleAuth\").MESSAGES.notConfigured, code: \"not_configured\", saved: false });"],
  "replacestate-skipped": ["ui",
    "    }).then(function (res) {\n      stripQuery();\n", "    }).then(function (res) {\n"],
  "privacy-sentence-removed": ["legal",
    "      YOUTUBE_PRIVACY_SENTENCE,\n", ""],
  "innerHTML-on-page": ["ui",
    "    if (text !== undefined && text !== null) node.textContent = text;\n", "    if (text !== undefined && text !== null) node.innerHTML = text;\n"],
  // the others the code earns
  "disconnect-deletes-all-states": ["server",
    "var statesDropped = await supabase.from(\"oauth_states\").delete().eq(\"user_id\", req.user.id).eq(\"purpose\", ga.PURPOSE);",
    "var statesDropped = await supabase.from(\"oauth_states\").delete().eq(\"user_id\", req.user.id);"],
  "guard-releases-changed-file": ["api",
    "      if (seen !== total || hash.digest(\"hex\") !== sha256) return cb(new Error(\"fingerprint\"));\n",
    "      if (seen !== total) return cb(new Error(\"fingerprint\"));\n"],
  "location-unchecked": ["api",
    " || location.indexOf(SESSION_PREFIX) !== 0) {", ") {"],
  "readonly-scope-dropped": ["auth",
    "const SCOPE = UPLOAD_SCOPE + \" \" + READONLY_SCOPE;", "const SCOPE = UPLOAD_SCOPE;"],
  "second-pending-upload": ["api",
    "  if ((await MV.proposalsNaming(deps.supabase, userId, video.id, [ACTION_UPLOAD])).length) {\n", "  if (false) {\n"],
  "refile-metadata-changed": ["api",
    "      if (again.ok) { meta = again.value; reused = true; }\n", ""],
  "claims-unscreened": ["api",
    "    if (refused) return { status: 422, body: { error: refused.error + \" Nothing was filed.\", code: \"claims\", field: fields[i], violations: refused.violations } };\n", ""],
  "ready-cap-missing": ["videos",
    "  if (await readyCount(deps.supabase, userId) >= READY_MAX) return { status: 409, body: { error: MESSAGES.readyCap, code: \"ready_cap\" } };\n  var path = newPath(userId, ext, deps.randomBytes);\n",
    "  var path = newPath(userId, ext, deps.randomBytes);\n"],
  "refresh-margin-ignored": ["api",
    "const REFRESH_MARGIN_MS = 5 * 60 * 1000;", "const REFRESH_MARGIN_MS = 0;"],
  // NAMED (Nov 7 2026, TikTok posting): the stale select now reads youtube_video_id and tiktok_status too (for fileGonePatch).
  "retention-ready-kept": ["videos",
    "    var stale = await supabase.from(\"member_videos\").select(\"id, user_id, path, youtube_video_id, tiktok_status\").eq(\"status\", \"ready\").lt(\"created_at\", cutoff).limit(PAGE_SIZE);\n",
    "    var stale = { data: [], error: null };\n"],
  "refresh-not-single-flight": ["api",
    "  var running = refreshesInFlight.get(key);\n", "  var running = null;\n"],
  "refresh-rotation-ignored": ["api",
    "  if (grant.refreshToken) {\n    var refresh = sealed(deps.crypt, grant.refreshToken);\n",
    "  if (false) {\n    var refresh = sealed(deps.crypt, grant.refreshToken);\n"]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + NAMES.join(", ")); process.exit(2); }

/* Every console line anything prints in this run is captured, so "nothing logged" can be proved; the check's own lines
   go straight to stdout. */
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
  auth: read("lib/googleAuth.js"),
  api: read("lib/youtubeApi.js"),
  videos: read("lib/memberVideos.js"),
  quota: read("lib/youtubeQuota.js"),
  fetch: read("lib/guardedFetch.js"),
  legal: read("lib/legalPages.js"),
  migration: read("supabase/migrations/177_youtube_uploads.sql"),
  yourData: read("lib/yourData.js"),
  backup: read("lib/backup.js"),
  schema: read("lib/schemaCheck.js"),
  accountFiles: read("lib/accountFiles.js"),
  gateRules: read("lib/gateRules.js"),
  readme: read("README.md"),
  privacy: readFe("privacy.html"),
  terms: readFe("terms.html"),
  page: readFe("agents/social.html"),
  ui: readFe("scripts/youtube.js"),
  // NAMED, item 8 part 3a (Instagram posting): the shared sign-in return reads ?code and ?state; youtube.js registers with it.
  oauth: readFe("scripts/oauth-return.js"),
  proposals: readFe("proposals.html")
};
if (MUTATE) {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  OUT("\n!! MUTATION: " + MUTATE);
}
["log", "warn", "error", "info"].forEach(function (k) { console[k] = function () { LOGS.push([].slice.call(arguments).map(String).join(" ")); }; });

const J = JSON.stringify;
const SECRET_HEX = crypto.createHash("sha256").update("checkYoutubeUploads").digest("hex");
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
/* The Google stub of the moment: every request the libraries make goes to it. */
let CURRENT = null;
const GF_PROXY = {
  guardedJsonRequest: function (u, o) { return CURRENT.jsonRequest(u, o); },
  guardedStreamUpload: function (u, o) { return CURRENT.streamUpload(u, o); }
};
const GF = compile(FILES.fetch, "lib/guardedFetch.js", {});
const GA = compile(FILES.auth, "lib/googleAuth.js", { "./guardedFetch": GF_PROXY });
const MV = compile(FILES.videos, "lib/memberVideos.js", {});
const YQ = compile(FILES.quota, "lib/youtubeQuota.js", {});
const YA = compile(FILES.api, "lib/youtubeApi.js", { "./googleAuth": GA, "./memberVideos": MV, "./youtubeQuota": YQ });
const LP = compile(FILES.legal, "lib/legalPages.js", {});

const CLIENT = { id: "check-client-id.apps.googleusercontent.com", secret: "check-google-secret-" + "9".repeat(16) };
const CONFIGURED = { GOOGLE_OAUTH_CLIENT_ID: CLIENT.id, GOOGLE_OAUTH_CLIENT_SECRET: CLIENT.secret };
const USER = "00000000-0000-4000-8000-000000000001";
const OTHER = "00000000-0000-4000-8000-000000000002";
const ACCESS = "ya29.check-access-" + "a1".repeat(10);
const ACCESS2 = "ya29.check-access2-" + "b2".repeat(10);
const WINNER = "ya29.check-winner-" + "c3".repeat(10);
const REFRESH = "1//check-refresh-" + "d4".repeat(10);
const REFRESH2 = "1//check-refresh2-" + "e5".repeat(10);
const CODE = "4/0Acheck-code-" + "f6".repeat(10);
const CHANNEL = "UCabcdefghijklmnopqrstuv";
const CHANNEL_TITLE = "Maple Street Bakery";
const YT_ID = "Ab3_x-9Kq2Z";
const UPLOAD_SCOPE = "https://www.googleapis.com/auth/youtube.upload";
const READONLY_SCOPE = "https://www.googleapis.com/auth/youtube.readonly";
const BOTH_SCOPES = UPLOAD_SCOPE + " " + READONLY_SCOPE;
const SESSION_BASE = "https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status&upload_id=check-session-";
const SIGNED_TOKEN = "signed-upload-token-" + "7a".repeat(8);
const PAGE_PATH = "/agents/social.html";
const SECRETS = [ACCESS, ACCESS2, WINNER, REFRESH, REFRESH2, CODE, CLIENT.secret, "check-session-", SIGNED_TOKEN];
function noSecretIn(text) { return SECRETS.every(function (s) { return String(text).indexOf(s) === -1; }); }
const EMOJI = /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{1F000}-\u{1F2FF}\u{FE0F}]/u;
const NOT_SET_UP = "YouTube connection isn't set up yet.";
const LIMITS = { title_max: 100, description_max_bytes: 5000, tags_max_total: 500 };
const sha = function (b) { return crypto.createHash("sha256").update(b).digest("hex"); };
const b64url = function (b) { return Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };

/* ── test files ─────────────────────────────────────────────────────────── */
function filler(n, seed) {
  const out = Buffer.alloc(n);
  let x = seed || 7;
  for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) >>> 0; out[i] = x >>> 24; }
  return out;
}
function mp4(brand, n, seed) {
  const head = Buffer.concat([Buffer.from([0, 0, 0, 0x18]), Buffer.from("ftyp", "latin1"), Buffer.from(brand, "latin1"), Buffer.from([0, 0, 2, 0]), Buffer.from("isomiso2", "latin1")]);
  return Buffer.concat([head, filler(Math.max(0, (n || 4096) - head.length), seed)]);
}
function webm(docType, n) {
  const dt = Buffer.from(docType, "latin1");
  const head = Buffer.concat([Buffer.from([0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x86, 0x81, 0x01, 0x42, 0x82, 0x80 | dt.length]), dt]);
  return Buffer.concat([head, filler(Math.max(0, (n || 4096) - head.length), 3)]);
}

/* ── an in-memory database, with migration 177's CHECKs, and the bf-video bucket ── */
function uuid() { return crypto.randomUUID(); }
const HEX = /^[0-9a-f]+$/;
const EV = [];   // one timeline: database writes, encryptions and Google requests, in order
function makeStorage() {
  const objects = {};   // path -> { buf, created_at, queue }
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
  function lazyStream(size, head) {
    let at = 0;
    const block = filler(1024 * 1024, 5);
    return new ReadableStream({
      pull: function (controller) {
        if (at >= size) { controller.close(); return; }
        const n = Math.min(block.length, size - at);
        const chunk = Buffer.from(block.subarray(0, n));
        if (at === 0) head.copy(chunk, 0);
        controller.enqueue(new Uint8Array(chunk));
        at += n;
      }
    });
  }
  function bytesOf(o) { return o.queue && o.queue.length ? o.queue.shift() : o.buf; }
  const bucket = {
    createSignedUploadUrl: async function (p) {
      calls.push({ op: "sign", path: p });
      return { data: { signedUrl: "https://check.supabase.co/storage/v1/object/upload/sign/bf-video/" + p + "?token=" + SIGNED_TOKEN, path: p, token: SIGNED_TOKEN }, error: null };
    },
    download: function (p) {
      const builder = {
        asStream: async function () {
          calls.push({ op: "stream", path: p });
          const o = objects[p];
          if (!o) return { data: null, error: { message: "Object not found", statusCode: "404" } };
          if (o.lazySize) return { data: lazyStream(o.lazySize, o.head), error: null };
          return { data: webStream(bytesOf(o)), error: null };
        },
        then: function (ok, bad) {
          calls.push({ op: "whole", path: p });
          const o = objects[p];
          const r = o ? { data: new Blob([o.lazySize ? Buffer.alloc(1) : bytesOf(o)]), error: null } : { data: null, error: { message: "Object not found" } };
          return Promise.resolve(r).then(ok, bad);
        }
      };
      return builder;
    },
    remove: async function (paths) {
      calls.push({ op: "remove", paths: paths.slice() });
      if (storage.failRemove) return { data: null, error: { message: "remove failed" } };
      paths.forEach(function (p) { delete objects[p]; });
      return { data: paths.map(function (p) { return { name: p }; }), error: null };
    },
    list: async function (prefix, opts) {
      calls.push({ op: "list", prefix: prefix });
      const keys = Object.keys(objects);
      let items = [];
      if (prefix === "video") {
        const owners = {};
        keys.forEach(function (k) { const m = /^video\/([^/]+)\//.exec(k); if (m) owners[m[1]] = true; });
        items = Object.keys(owners).map(function (n) { return { name: n, id: null }; });
      } else {
        keys.forEach(function (k) { if (k.indexOf(prefix + "/") === 0 && k.slice(prefix.length + 1).indexOf("/") === -1) items.push({ name: k.slice(prefix.length + 1), id: "obj-" + sha(k).slice(0, 8), created_at: objects[k].created_at }); });
      }
      const off = (opts && opts.offset) || 0, lim = (opts && opts.limit) || 100;
      return { data: items.slice(off, off + lim), error: null };
    }
  };
  const storage = { from: function (b) { if (b !== "bf-video") throw new Error("unexpected bucket " + b); return bucket; }, objects: objects, calls: calls, failRemove: false };
  return storage;
}
function makeDb() {
  // NAMED, item 8 part 3a (Instagram posting): instagram_posts added; retention and deleting a video now read it.
  const t = { member_youtube_connections: [], member_videos: [], oauth_states: [], agent_proposals: [], notifications: [], job_runs: [], youtube_api_calls: [], business_profiles: [], instagram_posts: [],
    // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): lib/memberVideos.js reads facebook_posts too.
    facebook_posts: [] };
  const log = [];
  const fail = {};   // table -> error for the next read
  function rows(name) { if (!t[name]) t[name] = []; return t[name]; }
  function uniqueViolation(name, row, except) {
    const others = rows(name).filter(function (r) { return r !== except; });
    if (name === "member_youtube_connections" && others.some(function (r) { return r.user_id === row.user_id; })) return "member_youtube_connections_user_id_key";
    if (name === "member_videos" && row.path != null && others.some(function (r) { return r.path === row.path; })) return "member_videos_path_key";
    if (name === "job_runs" && others.some(function (r) { return r.job_name === row.job_name; })) return "job_runs_pkey";
    return null;
  }
  function checkViolation(name, row) {
    if (name === "member_youtube_connections") {
      if (!/^UC[A-Za-z0-9_-]{22}$/.test(row.channel_id || "")) return "member_youtube_connections_channel_id_check";
      if (!(String(row.channel_title || "").length >= 1 && String(row.channel_title).length <= 200)) return "member_youtube_connections_channel_title_check";
      if (!HEX.test(row.refresh_ciphertext || "") || !/^[0-9a-f]{24}$/.test(row.refresh_iv || "") || !/^[0-9a-f]{32}$/.test(row.refresh_auth_tag || "")) return "member_youtube_connections_refresh_check";
      if (!HEX.test(row.access_ciphertext || "") || !/^[0-9a-f]{24}$/.test(row.access_iv || "") || !/^[0-9a-f]{32}$/.test(row.access_auth_tag || "")) return "member_youtube_connections_access_check";
      if (!row.access_expires_at) return "member_youtube_connections_access_expires_at_not_null";
      if (!(Number.isInteger(row.token_version) && row.token_version >= 0)) return "member_youtube_connections_token_version_check";
      if (row.granted_scopes != null && !(String(row.granted_scopes).length <= 500 && /^[A-Za-z0-9:/._ -]*$/.test(row.granted_scopes))) return "member_youtube_connections_scopes_check";
      if (["connected", "needs_reconnect"].indexOf(row.status) === -1) return "member_youtube_connections_status_check";
      if (row.last_error_code != null && String(row.last_error_code).length > 60) return "member_youtube_connections_error_code_check";
    }
    if (name === "member_videos") {
      if (["video/mp4", "video/webm", "video/quicktime"].indexOf(row.mime) === -1) return "member_videos_mime_check";
      if (!(Number(row.bytes) > 0 && Number(row.bytes) <= 52428800)) return "member_videos_bytes_check";
      if (!/^[0-9a-f]{64}$/.test(row.sha256 || "")) return "member_videos_sha_check";
      if (String(row.label == null ? "" : row.label).length > 120) return "member_videos_label_check";
      if (["ready", "uploaded", "removed"].indexOf(row.status) === -1) return "member_videos_status_check";
      if (row.path != null && !(/^video\/[0-9a-f-]{36}\/[0-9a-f]{32}\.(mp4|webm|mov)$/.test(row.path) && row.path.indexOf("video/" + row.user_id + "/") === 0)) return "member_videos_path_check";
      if (row.status === "ready" && row.path == null) return "member_videos_ready_path_check";
      if (row.youtube_video_id != null && !/^[A-Za-z0-9_-]{11}$/.test(row.youtube_video_id)) return "member_videos_youtube_id_check";
      const none = row.session_ciphertext == null && row.session_iv == null && row.session_auth_tag == null;
      const all = HEX.test(row.session_ciphertext || "") && /^[0-9a-f]{24}$/.test(row.session_iv || "") && /^[0-9a-f]{32}$/.test(row.session_auth_tag || "");
      if (!none && !all) return "member_videos_session_check";
    }
    if (name === "oauth_states") {
      if (["mailbox_microsoft", "store_shopify", "youtube_google"].indexOf(row.purpose) === -1) return "oauth_states_purpose_check";
      if (row.purpose !== "store_shopify" && (row.verifier_ciphertext == null || row.verifier_iv == null || row.verifier_auth_tag == null)) return "oauth_states_verifier_shape_check";
      if ((row.purpose === "store_shopify") !== (row.flow_context != null)) return "oauth_states_context_check";
    }
    if (name === "youtube_api_calls" && ["radar", "social_search"].indexOf(row.caller) === -1) return "youtube_api_calls_caller_check";
    return null;
  }
  function defaults(name, row) {
    const now = new Date().toISOString();
    const r = Object.assign({ id: uuid(), created_at: now }, row);
    if (name === "member_youtube_connections") { if (r.status === undefined) r.status = "connected"; if (r.token_version === undefined) r.token_version = 0; }
    if (name === "member_videos") {
      if (r.status === undefined) r.status = "ready"; if (r.label === undefined) r.label = "";
      ["youtube_video_id", "session_ciphertext", "session_iv", "session_auth_tag", "uploaded_at"].forEach(function (k) { if (r[k] === undefined) r[k] = null; });
    }
    if (name === "oauth_states") { if (r.consumed_at === undefined) r.consumed_at = null; if (r.flow_context === undefined) r.flow_context = null; }
    if (name === "youtube_api_calls") r.id = t.youtube_api_calls.length + 1;
    return r;
  }
  function project(r, cols) {
    if (!cols || cols.trim() === "*") return Object.assign({}, r);
    const o = {};
    cols.split(",").map(function (c) { return c.trim(); }).forEach(function (c) { o[c] = r[c] === undefined ? null : r[c]; });
    return o;
  }
  function from(name) {
    const q = { op: null, cols: null, count: false, head: false, filters: [], or: null, payload: null, onConflict: null, single: null, range: null, returning: false };
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
      order: function () { return api; }, limit: function () { return api; },
      range: function (a, b) { q.range = [a, b]; return api; },
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
      log.push({ table: name, op: q.op, payload: q.payload });
      if (q.op !== "select") EV.push("db:" + name + ":" + q.op);
      const all = rows(name);
      if (q.op === "select") {
        if (fail[name]) { const e = fail[name]; delete fail[name]; return { data: null, error: e }; }
        let hit = all.filter(match);
        const total = hit.length;
        if (q.range) hit = hit.slice(q.range[0], q.range[1] + 1);
        const out = q.head ? { data: null, error: null } : shape(hit);
        if (q.count) out.count = total;
        return out;
      }
      if (q.op === "insert") {
        if (fail[name + ":insert"]) { const e = fail[name + ":insert"]; delete fail[name + ":insert"]; return { data: null, error: e }; }
        const list = Array.isArray(q.payload) ? q.payload : [q.payload];
        const made = [];
        for (const p of list) {
          const r = defaults(name, p);
          const u = uniqueViolation(name, r, null); if (u) return { data: null, error: { code: "23505", message: "duplicate key value violates unique constraint \"" + u + "\"" } };
          const c = checkViolation(name, r); if (c) return { data: null, error: { code: "23514", message: "violates check constraint \"" + c + "\"" } };
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
  const db = { from: from, t: t, log: log, fail: fail, storage: makeStorage() };
  return db;
}

/* ── Google, stubbed behind the real guarded fetcher ────────────────────── */
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
const PUBLIC_V4 = "142.250.80.10";
function makeGoogle(opts) {
  const o = Object.assign({}, opts || {});
  const g = { opts: o, requests: [], sessions: {}, n: 0, bodyPuts: 0, tokenCalls: [], sealedAtFirstPut: null, db: o.db || null };
  function sessionFor(u) { return g.sessions[u.pathname + u.search]; }
  function record(method, u, headers, body) {
    const auth = headerOf(headers, "Authorization");
    const entry = { method: method, host: u.hostname, path: u.pathname, search: u.search, url: u.href, contentRange: headerOf(headers, "Content-Range"),
      contentLength: headerOf(headers, "Content-Length"), bearer: auth ? auth.replace(/^Bearer /, "") : null, bytes: body ? body.length : 0,
      xType: headerOf(headers, "X-Upload-Content-Type"), xLength: headerOf(headers, "X-Upload-Content-Length") };
    g.requests.push(entry);
    return entry;
  }
  function answer(method, u, headers, body) {
    const entry = record(method, u, headers, body);
    if (u.hostname === "oauth2.googleapis.com" && u.pathname === "/token") {
      const form = new URLSearchParams(body.toString("utf8"));
      const call = { grant_type: form.get("grant_type"), code: form.get("code"), code_verifier: form.get("code_verifier"), refresh_token: form.get("refresh_token"),
        client_id: form.get("client_id"), client_secret_ok: form.get("client_secret") === CLIENT.secret, redirect_uri: form.get("redirect_uri") };
      g.tokenCalls.push(call);
      EV.push("yt:token:" + call.grant_type);
      if (call.grant_type === "refresh_token") {
        if (typeof o.onRefresh === "function") o.onRefresh(call);
        if (o.refresh === "invalid_grant") return reply(400, { error: "invalid_grant", error_description: "Token has been expired or revoked." });
        if (o.refresh === "down") return reply(503, { error: "backend_error" });
        const grant = { access_token: ACCESS2, expires_in: 3599, scope: BOTH_SCOPES, token_type: "Bearer" };
        if (o.rotate) grant.refresh_token = REFRESH2;
        return reply(200, grant);
      }
      if (o.exchange === "invalid_grant") return reply(400, { error: "invalid_grant" });
      const grant = { access_token: ACCESS, refresh_token: REFRESH, expires_in: 3599, scope: o.scope === undefined ? BOTH_SCOPES : o.scope, token_type: "Bearer" };
      (o.grantOmit || []).forEach(function (k) { delete grant[k]; });
      return reply(200, grant);
    }
    if (u.hostname === "oauth2.googleapis.com" && u.pathname === "/revoke") {
      EV.push("yt:revoke");
      g.revoked = new URLSearchParams(body.toString("utf8")).get("token");
      if (o.revoke === "down") return { error: Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }) };
      if (o.revoke === "400") return reply(400, { error: "invalid_token" });
      return reply(200, null);
    }
    if (u.hostname !== "www.googleapis.com") return reply(404, { error: "no such host" });
    if (o.reject && o.reject.indexOf(entry.bearer) !== -1) return reply(401, { error: { code: 401, message: "Request had invalid authentication credentials." } });
    if (u.pathname === "/youtube/v3/channels" && method === "GET") {
      EV.push("yt:channels");
      if (o.noChannel) return reply(200, { kind: "youtube#channelListResponse", items: [] });
      return reply(200, { kind: "youtube#channelListResponse", items: [{ id: CHANNEL, snippet: { title: CHANNEL_TITLE } }] });
    }
    if (u.pathname === "/youtube/v3/videos" && method === "DELETE") {
      EV.push("yt:videos.delete");
      if (o.deleteStatus) return reply(o.deleteStatus, o.deleteStatus === 204 ? null : { error: { code: o.deleteStatus } });
      return reply(204, null);
    }
    if (u.pathname === "/youtube/v3/videos" && method === "GET") {
      EV.push("yt:videos.list");
      if (o.listGone) return reply(200, { items: [] });
      return reply(200, { items: [{ id: u.searchParams.get("id"), status: { uploadStatus: "processed", privacyStatus: "private" }, processingDetails: { processingStatus: "succeeded" } }] });
    }
    if (u.pathname === "/upload/youtube/v3/videos" && method === "POST" && u.searchParams.get("uploadType") === "resumable" && !u.searchParams.get("upload_id")) {
      EV.push("yt:start");
      let meta = null;
      try { meta = JSON.parse(body.toString("utf8")); } catch (e) { meta = null; }
      g.startBodies = (g.startBodies || []).concat([meta]);
      if (o.startStatus) return reply(o.startStatus, { error: { code: o.startStatus } });
      g.n++;
      const loc = o.startLocation || (SESSION_BASE + g.n);
      const lu = new URL(loc);
      g.sessions[lu.pathname + lu.search] = { total: Number(entry.xLength), received: Buffer.alloc(0), done: false, mime: entry.xType };
      return reply(200, null, { location: loc });
    }
    if (u.pathname === "/upload/youtube/v3/videos" && method === "PUT" && u.searchParams.get("upload_id")) {
      const s = sessionFor(u);
      if (!s || o.expired) { EV.push("yt:session-gone"); return reply(404, { error: { code: 404, message: "Not Found" } }); }
      const range = entry.contentRange || "";
      if (/^bytes \*\//.test(range) && entry.bytes === 0) {
        EV.push("yt:query");
        if (s.done) return reply(200, done(s));
        return s.received.length ? { status: 308, headers: { range: "bytes=0-" + (s.received.length - 1) }, raw: Buffer.alloc(0) } : { status: 308, headers: {}, raw: Buffer.alloc(0) };
      }
      const m = /^bytes (\d+)-(\d+)\/(\d+)$/.exec(range);
      const offset = m ? Number(m[1]) : 0;
      s.received = Buffer.concat([s.received.subarray(0, offset), body]);
      if (s.received.length >= s.total) {
        s.done = true;
        if (o.crashAfterComplete && !g.crashed) { g.crashed = true; return { error: Object.assign(new Error("socket hang up"), { code: "ECONNRESET" }) }; }
        return reply(200, done(s));
      }
      return { status: 308, headers: { range: "bytes=0-" + (s.received.length - 1) }, raw: Buffer.alloc(0) };
    }
    if (u.pathname.indexOf("/upload/redirect") === 0) return reply(302, null, { location: "https://www.googleapis.com/upload/elsewhere" });
    if (u.pathname.indexOf("/upload/silent") === 0) return { silent: true };
    if (u.pathname.indexOf("/upload/huge") === 0) return { status: 200, headers: { "content-type": "application/json" }, raw: Buffer.from("[" + "1,".repeat(600000) + "1]") };
    return reply(404, { error: "no stub for " + u.pathname });
  }
  function done(s) {
    return { kind: "youtube#video", id: YT_ID, snippet: { title: "t" }, status: { uploadStatus: "uploaded", privacyStatus: "private" }, sha256: sha(s.received) };
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
        const row = g.db.t.member_videos.filter(function (r) { return r.session_ciphertext; })[0];
        let opened = null;
        try { opened = row ? CRYPT.decrypt({ ciphertext: row.session_ciphertext, iv: row.session_iv, authTag: row.session_auth_tag }) : null; } catch (e) { opened = null; }
        g.sealedAtFirstPut = opened;
      }
      EV.push("yt:put");
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
        // YouTube keeps what arrived before the connection broke.
        const s = sessionFor(u);
        const range = headerOf(options.headers, "Content-Range") || "";
        const m = /^bytes (\d+)-/.exec(range);
        const offset = m ? Number(m[1]) : 0;
        if (s) s.received = Buffer.concat([s.received.subarray(0, offset), Buffer.concat(chunks)]);
        record(options.method, u, options.headers, Buffer.concat(chunks)).cut = true;
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
          if (r.silent) return;
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
  g.starts = function () { return g.of(function (r) { return r.method === "POST" && r.path === "/upload/youtube/v3/videos"; }); };
  g.puts = function () { return g.of(function (r) { return r.method === "PUT" && r.bytes > 0; }); };
  g.queries = function () { return g.of(function (r) { return r.method === "PUT" && r.bytes === 0 && /^bytes \*\//.test(r.contentRange || ""); }); };
  return g;
}

/* THE NETWORK TRIPWIRE: no socket, no real DNS question, no fetch, in this whole run. */
const TRIPPED = [];
(function tripwire() {
  const http = require("http"), https = require("https"), net = require("net"), tls = require("tls"), dns = require("dns");
  function wire(obj, name, label) {
    obj[name] = function () { TRIPPED.push(label); throw new Error("checkYoutubeUploads: " + label + " is not allowed in this check"); };
  }
  wire(http, "request", "http.request"); wire(http, "get", "http.get");
  wire(https, "request", "https.request"); wire(https, "get", "https.get");
  wire(net, "connect", "net.connect"); wire(net, "createConnection", "net.createConnection");
  wire(tls, "connect", "tls.connect");
  wire(dns, "lookup", "dns.lookup"); wire(dns, "resolve", "dns.resolve"); wire(dns.promises, "lookup", "dns.promises.lookup");
  globalThis.fetch = function () { TRIPPED.push("fetch"); return Promise.reject(new Error("checkYoutubeUploads: fetch is not allowed in this check")); };
})();

/* ── the routes, run from server.js's own source ─────────────────────────── */
function sliceOf(src, start, end) {
  const a = src.indexOf(start), b = src.indexOf(end, a);
  return a === -1 || b === -1 ? "" : src.slice(a, b);
}
const YT_SECTION = sliceOf(FILES.server, "/* ── YouTube uploads (migration 177; lib/googleAuth.js, lib/youtubeApi.js, lib/memberVideos.js) ──",
  "// ── Mailbox: a member's own inbox, read only (migration 169)");
const CRON_START = "  if (require.main === module) {\n    cron.schedule(\"45 4 * * *\", function () {\n      cardLeads.cardLeadsPurgeTick(supabase)";
const CRON_SECTION = sliceOf(FILES.server, CRON_START, "    console.log(\"[startup] card leads purge scheduled");
function requireAuth() {} function requireActiveSubscription() {} function aiLimiter() {}
function claimsStub(text) {
  return /guaranteed/i.test(String(text)) ? { error: "That makes a promise BizForce can't check (\"guaranteed\").", violations: [{ phrase: "guaranteed" }] } : null;
}
function mountRoutes(env) {
  env = env || {};
  const db = env.db || makeDb();
  const google = makeGoogle(Object.assign({ db: db }, env.google || {}));
  CURRENT = google;
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
    SOCIAL_SEARCH_LIMITS: { youtube: Object.assign({ label: "YouTube" }, LIMITS) },
    blueskyClaimsRefusal: claimsStub,
    callAnthropicText: async function (prompt) {
      prompts.push(prompt);
      return { text: env.draft !== undefined ? env.draft : "TITLE: Spring cakes at Maple Street\nDESCRIPTION: How we make our spring cakes.\nTAGS: cakes, bakery, spring" };
    },
    Promise: Promise, Buffer: Buffer, URL: URL, Date: Date, JSON: JSON, Object: Object, Array: Array, String: String, Number: Number, Math: Math,
    require: function (r) {
      if (r === "./lib/apiKeyCrypto") return crypt;
      if (r === "./lib/guardedFetch") return Object.assign({}, GF, GF_PROXY);
      if (r === "./lib/googleAuth") return GA;
      if (r === "./lib/youtubeApi") return YA;
      if (r === "./lib/memberVideos") return MV;
      return realRequire(r);
    },
    app: {}
  };
  ["get", "post", "put", "delete"].forEach(function (m) {
    ctx.app[m] = function (p) { const args = [].slice.call(arguments, 1); routes[m + " " + p] = { middleware: args.slice(0, -1), handler: args[args.length - 1] }; };
  });
  vm.createContext(ctx);
  vm.runInContext(YT_SECTION, ctx, { filename: "server.js (YouTube section)" });
  return { db: db, google: google, routes: routes, ctx: ctx, prompts: prompts, storage: db.storage };
}
async function hit(m, key, req) {
  CURRENT = m.google;
  const r = m.routes[key];
  const res = { statusCode: 200, body: undefined, headers: {}, set: function (k, v) { this.headers[k] = v; return this; },
    status: function (c) { this.statusCode = c; return this; }, json: function (b) { this.body = JSON.parse(JSON.stringify(b)); return this; } };
  let err = null;
  try { await r.handler(Object.assign({ user: { id: USER }, body: {}, params: {} }, req), res, function (e) { err = e || new Error("next"); }); }
  catch (e) { err = e; res.statusCode = 599; }
  return { status: res.statusCode, body: res.body || {}, headers: res.headers, err: err };
}
async function attempt(p) { try { return { ok: true, v: await p }; } catch (e) { return { ok: false, msg: e && e.message, code: e && e.code, kind: e && e.kind }; } }
async function begin(m) {
  const r = await hit(m, "post /api/youtube/start", {});
  const url = r.body && r.body.authorize_url ? new URL(r.body.authorize_url) : null;
  return { r: r, url: url, state: url ? url.searchParams.get("state") : null };
}
async function connect(m, extra) {
  const b = await begin(m);
  const f = await hit(m, "post /api/youtube/finish", { body: Object.assign({ code: CODE, state: b.state }, extra || {}) });
  return { b: b, f: f };
}
function seal(p) { const s = CRYPT.encrypt(p); return { ciphertext: s.ciphertext, iv: s.iv, authTag: s.authTag }; }
function seedConnection(db, over) {
  const a = seal(ACCESS), r = seal(REFRESH);
  const row = Object.assign({ id: uuid(), user_id: USER, channel_id: CHANNEL, channel_title: CHANNEL_TITLE,
    refresh_ciphertext: r.ciphertext, refresh_iv: r.iv, refresh_auth_tag: r.authTag,
    access_ciphertext: a.ciphertext, access_iv: a.iv, access_auth_tag: a.authTag,
    access_expires_at: new Date(Date.now() + 50 * 60 * 1000).toISOString(), token_version: 0, granted_scopes: BOTH_SCOPES,
    status: "connected", last_ok_at: null, last_error_at: null, last_error_code: null, created_at: "2026-11-07T10:00:00.000Z", updated_at: "2026-11-07T10:00:00.000Z" }, over || {});
  db.t.member_youtube_connections.push(row);
  return row;
}
function videoPath(userId, ext) { return "video/" + userId + "/" + crypto.randomBytes(16).toString("hex") + "." + (ext || "mp4"); }
function seedVideo(db, buf, over) {
  const userId = (over && over.user_id) || USER;
  const p = (over && over.path) || videoPath(userId, "mp4");
  const row = Object.assign({ id: uuid(), user_id: userId, path: p, mime: "video/mp4", bytes: buf.length, sha256: sha(buf), label: "Spring cakes",
    status: "ready", youtube_video_id: null, session_ciphertext: null, session_iv: null, session_auth_tag: null, uploaded_at: null,
    created_at: new Date().toISOString() }, over || {});
  db.t.member_videos.push(row);
  if (row.path) db.storage.objects[row.path] = { buf: buf, created_at: new Date(Date.now() - 3 * 86400000).toISOString() };
  return row;
}
const META = { title: "Spring cakes at Maple Street", description: "How we bake our spring cakes, start to finish.", tags: ["cakes", "bakery"], made_for_kids: false };
async function file(m, video, body) {
  return hit(m, "post /api/youtube/propose-upload", { body: Object.assign({ video_id: video.id }, META, body || {}) });
}
async function approve(m, proposal) { CURRENT = m.google; return attempt(m.ctx.executePublishYoutubeVideo(proposal)); }
function rowOf(m, id) { return m.db.t.member_videos.filter(function (r) { return r.id === id; })[0]; }
function sessionOf(row) {
  try { return row && row.session_ciphertext ? CRYPT.decrypt({ ciphertext: row.session_ciphertext, iv: row.session_iv, authTag: row.session_auth_tag }) : null; } catch (e) { return "unreadable"; }
}
function accessOf(row) { try { return CRYPT.decrypt({ ciphertext: row.access_ciphertext, iv: row.access_iv, authTag: row.access_auth_tag }); } catch (e) { return null; } }
function refreshOf(row) { try { return CRYPT.decrypt({ ciphertext: row.refresh_ciphertext, iv: row.refresh_iv, authTag: row.refresh_auth_tag }); } catch (e) { return null; } }
function units(m, method) { return m.db.t.youtube_api_calls.reduce(function (n, r) { return n + Number(r.units); }, 0); }
function libDeps(db, google, extra) {
  CURRENT = google;
  return Object.assign({ supabase: db, storage: db.storage, crypt: CRYPT, jsonRequest: google.jsonRequest, streamUpload: google.streamUpload,
    now: function () { return Date.now(); }, config: function () { return GA.configured(CONFIGURED); }, limits: LIMITS, claims: claimsStub, env: {} }, extra || {});
}
async function flush() { for (let i = 0; i < 60; i++) await new Promise(function (r) { setImmediate(r); }); }
function stripComments(src) { return String(src).replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, ""); }

/* ── the Social page's YouTube panel in a fake DOM ───────────────────────── */
const API = "https://dynamic-prosperity-production-5382.up.railway.app";
/* NAMED (Nov 7 2026, TikTok posting): sessionStorage "bf_oauth_return" marks whose sign-in comes back. A return
   (a query) starts with the marker "youtube" unless marker says otherwise (null: none). */
function runPage(search, answers, marker) {
  const dom = { els: {}, fetches: [], events: [], innerHTML: [], assigned: [], xhr: [], session: {} };
  const mk = marker === undefined ? (search ? "youtube" : null) : marker;
  if (mk !== null) dom.session.bf_oauth_return = mk;
  function node(tag) {
    const n = { tagName: String(tag).toUpperCase(), children: [], _t: "", className: "", hidden: false, disabled: false, value: "", checked: false, type: "", id: "", name: "",
      required: false, selected: false, attrs: {}, listeners: {}, files: null,
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
      Object.defineProperty(n, "value", { get: function () { const s = this.children.filter(function (c) { return c.selected; })[0] || this.children[0]; return s ? s.value : ""; },
        set: function (v) { this.children.forEach(function (c) { c.selected = c.value === v; }); } });
    }
    return n;
  }
  const document = { readyState: "complete", addEventListener: function () {},
    getElementById: function (id) { if (!dom.els[id]) { dom.els[id] = node("div"); dom.els[id].id = id; } return dom.els[id]; },
    createElement: node };
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
  function XMLHttpRequest() {
    const x = { upload: {}, headers: {}, status: 0 };
    x.open = function (m, u) { x.method = m; x.url = u; };
    x.setRequestHeader = function (k, v) { x.headers[k] = v; };
    x.send = function (f) {
      dom.xhr.push({ method: x.method, url: x.url, headers: x.headers, file: f });
      dom.events.push("xhr:" + x.method);
      Promise.resolve().then(function () {
        if (x.upload.onprogress) x.upload.onprogress({ lengthComputable: true, loaded: f.size, total: f.size });
        x.status = 200;
        x.onload();
      });
    };
    return x;
  }
  const sessionStorage = { getItem: function (k) { return Object.prototype.hasOwnProperty.call(dom.session, k) ? dom.session[k] : null; },
    setItem: function (k, v) { dom.session[k] = String(v); }, removeItem: function (k) { delete dom.session[k]; } };
  const ctx = { window: window, document: document, localStorage: { getItem: function () { return "tok"; } }, sessionStorage: sessionStorage, fetch: fetch, URLSearchParams: URLSearchParams,
    XMLHttpRequest: XMLHttpRequest, encodeURIComponent: encodeURIComponent,
    console: { log: function () {}, error: function () {}, warn: function () {} }, Promise: Promise, JSON: JSON, String: String, Array: Array, Date: Date, Math: Math, Number: Number, Error: Error };
  vm.createContext(ctx);
  vm.runInContext(FILES.oauth, ctx, { filename: "scripts/oauth-return.js" }); // NAMED, item 8 part 3a (Instagram posting): loaded first, as on the page
  vm.runInContext(FILES.ui, ctx, { filename: "scripts/youtube.js" });
  return dom;
}
function findAll(root, pred, out) {
  out = out || [];
  (root.children || []).forEach(function (c) { if (pred(c)) out.push(c); findAll(c, pred, out); });
  return out;
}
const PAGE_VIDEO = { id: "22222222-2222-4222-8222-222222222222", label: "Spring cakes", bytes: 3 * 1048576, mime: "video/mp4", status: "ready",
  youtube_video_id: null, youtube_url: null, uploaded_at: null, created_at: "2026-11-07T10:00:00Z", upload_unfinished: false };
const PAGE_UPLOADED = { id: "33333333-3333-4333-8333-333333333333", label: "Autumn menu", bytes: 2 * 1048576, mime: "video/mp4", status: "uploaded",
  youtube_video_id: YT_ID, youtube_url: "https://www.youtube.com/watch?v=" + YT_ID, uploaded_at: "2026-11-07T11:00:00Z", created_at: "2026-11-07T10:00:00Z", upload_unfinished: false };
function pageAnswers(over) {
  return function (p, method) {
    if (over && over[method + " " + p] !== undefined) return over[method + " " + p];
    if (p === "/api/youtube/status") return { status: 200, body: { youtube_available: true, connected: true, status: "connected", channel_title: CHANNEL_TITLE, channel_id: CHANNEL, since: "2026-11-07T10:00:00Z", reconnect_message: null } };
    if (p === "/api/videos" && method === "GET") return { status: 200, body: { videos: [PAGE_VIDEO, PAGE_UPLOADED], max_bytes: 52428800, ready_max: 2 } };
    if (p === "/api/youtube/start") return { status: 200, body: { authorize_url: "https://accounts.google.com/o/oauth2/v2/auth?client_id=x" } };
    if (p === "/api/youtube/finish") return { status: 200, body: { youtube_available: true, connected: true, status: "connected", channel_title: CHANNEL_TITLE, since: "2026-11-07T10:00:00Z" } };
    if (p === "/api/videos/upload-url") return { status: 200, body: { upload_url: "https://check.supabase.co/storage/v1/object/upload/sign/bf-video/x?token=t", path: "video/" + USER + "/" + "a".repeat(32) + ".mp4", mime: "video/mp4", max_bytes: 52428800 } };
    if (p === "/api/videos/finalize") return { status: 201, body: { video: PAGE_VIDEO } };
    if (p === "/api/youtube/propose-upload") return { status: 201, body: { note: "Filed for approval. Nothing has been sent to YouTube." } };
    return { status: 404, body: { error: "Not found" } };
  };
}

(async function main() {
  check("the YouTube section and the 04:45 chain of server.js were found", YT_SECTION.length > 5000 && CRON_SECTION.length > 500, J([YT_SECTION.length, CRON_SECTION.length]));

  /* ── O ── */
  OUT("\n══ O. Connect YouTube ══");
  let m = mountRoutes({});
  const start = m.routes["post /api/youtube/start"], fin = m.routes["post /api/youtube/finish"];
  const cLim = start.middleware[2] && start.middleware[2].limiter;
  check("O1. start and finish are requireAuth, requireActiveSubscription and one limiter, 10 an hour, keyed youtube-connect:<id>",
    start.middleware[0] === requireAuth && start.middleware[1] === requireActiveSubscription && fin.middleware[0] === requireAuth &&
    fin.middleware[1] === requireActiveSubscription && fin.middleware[2] === start.middleware[2] && cLim.max === 10 && cLim.windowMs === 3600000 &&
    cLim.keyGenerator({ user: { id: USER } }) === "youtube-connect:" + USER);
  const gated = ["post /api/youtube/start", "post /api/youtube/finish", "post /api/videos/upload-url", "post /api/videos/finalize", "post /api/youtube/propose-upload",
    "post /api/youtube/draft-metadata", "post /api/youtube/videos/:id/propose-delete"];
  const loginOnly = ["get /api/youtube/status", "post /api/youtube/disconnect", "get /api/videos", "delete /api/videos/:id", "get /api/youtube/videos/:id/status"];
  check("O2. the twelve routes: seven behind a subscription, five login-only (status, disconnect, the list, delete, a video's status)",
    Object.keys(m.routes).length === 12 &&
    gated.every(function (k) { return m.routes[k] && m.routes[k].middleware[0] === requireAuth && m.routes[k].middleware[1] === requireActiveSubscription; }) &&
    loginOnly.every(function (k) { return m.routes[k] && m.routes[k].middleware.length === 1 && m.routes[k].middleware[0] === requireAuth; }), Object.keys(m.routes).join(", "));
  // unconfigured
  const unconfigured = [];
  for (const k of ["post /api/youtube/start", "post /api/youtube/finish", "post /api/videos/upload-url", "post /api/videos/finalize", "post /api/youtube/propose-upload",
    "post /api/youtube/draft-metadata", "post /api/youtube/videos/:id/propose-delete", "get /api/youtube/videos/:id/status"]) {
    const r = await hit(m, k, { body: { code: CODE, state: "A".repeat(43), mime: "video/mp4", bytes: 10 }, params: { id: uuid() } });
    unconfigured.push([k, r.status, r.body.error]);
  }
  check("O3. without GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET every YouTube and video route but four answers 503 \"YouTube connection isn't set up yet.\"",
    unconfigured.every(function (u) { return u[1] === 503 && u[2] === NOT_SET_UP; }) && m.google.requests.length === 0 && m.db.t.oauth_states.length === 0,
    J(unconfigured.map(function (u) { return u[1]; })));
  let r = await hit(m, "get /api/youtube/status", {});
  const rList = await hit(m, "get /api/videos", {});
  const rDis = await hit(m, "post /api/youtube/disconnect", {});
  check("O4. ...status says youtube_available false and not connected; the list and disconnect still answer",
    r.status === 200 && r.body.youtube_available === false && r.body.connected === false && r.body.status === "not_connected" &&
    rList.status === 200 && Array.isArray(rList.body.videos) && rDis.status === 200 && rDis.body.youtube_available === false, J([r.status, r.body.youtube_available, rList.status, rDis.status]));
  m = mountRoutes({ env: { GOOGLE_OAUTH_CLIENT_ID: CLIENT.id } });
  r = await hit(m, "post /api/youtube/start", {});
  check("O5. one of the two set is not configured: 503", r.status === 503 && m.db.t.oauth_states.length === 0, r.status);

  m = mountRoutes({ env: CONFIGURED });
  m.db.t.oauth_states.push({ id: uuid(), user_id: USER, purpose: "mailbox_microsoft", state_hash: "b".repeat(64), verifier_ciphertext: "00", verifier_iv: "0".repeat(24), verifier_auth_tag: "0".repeat(32),
    flow_context: null, created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 600000).toISOString(), consumed_at: null });
  let b = await begin(m);
  const st = m.db.t.oauth_states.filter(function (s) { return s.purpose === "youtube_google"; })[0];
  let verifier = null;
  try { verifier = CRYPT.decrypt({ ciphertext: st.verifier_ciphertext, iv: st.verifier_iv, authTag: st.verifier_auth_tag }); } catch (e) { verifier = null; }
  const q = b.url ? b.url.searchParams : new URLSearchParams();
  check("O6. the authorize URL is Google's page: client_id, the Social page as redirect_uri, response_type code, both scopes, offline, consent, the state",
    b.r.status === 200 && b.url && b.url.origin + b.url.pathname === "https://accounts.google.com/o/oauth2/v2/auth" && q.get("client_id") === CLIENT.id &&
    q.get("redirect_uri") === "https://bizforceai.net" + PAGE_PATH && q.get("response_type") === "code" && q.get("scope") === BOTH_SCOPES &&
    q.get("access_type") === "offline" && q.get("prompt") === "consent" && /^[A-Za-z0-9_-]{43}$/.test(b.state || ""), b.url && b.url.search.length);
  check("O7. PKCE S256: code_challenge is base64url(sha256(the verifier)), never the verifier itself; code_challenge_method S256",
    !!verifier && /^[A-Za-z0-9_-]{43}$/.test(verifier) && q.get("code_challenge_method") === "S256" &&
    q.get("code_challenge") === b64url(crypto.createHash("sha256").update(verifier, "ascii").digest()) && q.get("code_challenge") !== verifier);
  check("O8. the state is stored only as its sha256: purpose youtube_google, this member, the verifier sealed, no flow_context, 10 minutes, unconsumed",
    !!st && st.user_id === USER && st.state_hash === sha(b.state || "") && st.flow_context === null && st.consumed_at === null &&
    Date.parse(st.expires_at) - Date.parse(st.created_at) === 600000 && J(m.db.t.oauth_states).indexOf(b.state) === -1 && J(m.db.t.oauth_states).indexOf(verifier) === -1);
  check("O9. ...answered no-store, with nothing asked of Google", b.r.headers["Cache-Control"] === "no-store" && m.google.requests.length === 0);
  EV.length = 0;
  let f = await hit(m, "post /api/youtube/finish", { body: { code: CODE, state: b.state } });
  const conn = m.db.t.member_youtube_connections[0];
  const ex = m.google.tokenCalls[0] || {};
  check("O10. finish exchanges the code once, with the verifier whose S256 is the challenge, the client secret and the same redirect_uri",
    m.google.tokenCalls.length === 1 && ex.grant_type === "authorization_code" && ex.code === CODE && ex.code_verifier === verifier && ex.client_secret_ok &&
    ex.client_id === CLIENT.id && ex.redirect_uri === "https://bizforceai.net" + PAGE_PATH);
  check("O11. connected: the channel stored with both tokens sealed, token_version 0, both scopes granted; the answer carries no token",
    f.status === 200 && f.body.connected === true && f.body.channel_title === CHANNEL_TITLE && f.body.youtube_available === true && !!conn &&
    conn.channel_id === CHANNEL && accessOf(conn) === ACCESS && refreshOf(conn) === REFRESH && conn.token_version === 0 && conn.granted_scopes === BOTH_SCOPES &&
    noSecretIn(J(f.body)) && J(conn).indexOf(ACCESS) === -1 && J(conn).indexOf(REFRESH) === -1, J([f.status, f.body.code]));
  const firstChannel = EV.indexOf("yt:channels");
  check("O12. both tokens are sealed before YouTube is asked anything (the channel read comes after both encryptions)",
    firstChannel !== -1 && EV.indexOf("encrypt:refresh") !== -1 && EV.indexOf("encrypt:access") !== -1 &&
    EV.indexOf("encrypt:refresh") < firstChannel && EV.indexOf("encrypt:access") < firstChannel && EV.filter(function (e) { return e === "yt:channels"; }).length === 1, EV.join(","));
  check("O13. the channel read reserved 1 unit (channels.list) as social_search for this member", m.db.t.youtube_api_calls.length === 1 &&
    m.db.t.youtube_api_calls[0].units === 1 && m.db.t.youtube_api_calls[0].caller === "social_search" && m.db.t.youtube_api_calls[0].user_id === USER);
  const again = await hit(m, "post /api/youtube/finish", { body: { code: CODE, state: b.state } });
  check("O14. the state is consumed once: the same state again is 400 state_invalid, with no second exchange",
    again.status === 400 && again.body.code === "state_invalid" && m.google.tokenCalls.length === 1, J([again.status, again.body.code]));
  // another member's, an expired one
  b = await begin(m);
  const theirs = await hit(m, "post /api/youtube/finish", { user: { id: OTHER }, body: { code: CODE, state: b.state } });
  const stOwn = m.db.t.oauth_states.filter(function (s) { return s.state_hash === sha(b.state); })[0];
  stOwn.expires_at = new Date(Date.now() - 1000).toISOString();
  const expired = await hit(m, "post /api/youtube/finish", { body: { code: CODE, state: b.state } });
  check("O15. another member's state and an expired one are refused with the same answer and no reason, with no exchange",
    theirs.status === 400 && expired.status === 400 && J(theirs.body) === J(expired.body) && m.google.tokenCalls.length === 1);
  const bad = await hit(m, "post /api/youtube/finish", { body: { code: "a b", state: b.state } });
  check("O16. a code with a space or a malformed state is 400 bad_request before anything", bad.status === 400 && bad.body.code === "bad_request");
  // scopes
  m = mountRoutes({ env: CONFIGURED, google: { scope: UPLOAD_SCOPE } });
  let c = await connect(m);
  check("O17. only youtube.upload granted: 422 \"Google didn't grant both YouTube permissions...\", nothing stored, the channel never read",
    c.f.status === 422 && c.f.body.code === "no_scopes" && c.f.body.error === GA.MESSAGES.noScopes && m.db.t.member_youtube_connections.length === 0 &&
    m.google.of(function (x) { return x.path === "/youtube/v3/channels"; }).length === 0, J([c.f.status, c.f.body.code]));
  m = mountRoutes({ env: CONFIGURED, google: { scope: READONLY_SCOPE } });
  c = await connect(m);
  check("O18. only youtube.readonly granted: 422 the same", c.f.status === 422 && c.f.body.code === "no_scopes" && m.db.t.member_youtube_connections.length === 0);
  m = mountRoutes({ env: CONFIGURED, google: { grantOmit: ["refresh_token"] } });
  c = await connect(m);
  check("O19. no refresh token in the exchange: refused (502), nothing stored", c.f.status === 502 && m.db.t.member_youtube_connections.length === 0, c.f.status);
  m = mountRoutes({ env: CONFIGURED, google: { noChannel: true } });
  c = await connect(m);
  check("O20. a Google account with no channel: 422 no_channel, nothing stored", c.f.status === 422 && c.f.body.code === "no_channel" && m.db.t.member_youtube_connections.length === 0);
  m = mountRoutes({ env: CONFIGURED, google: { exchange: "invalid_grant" } });
  c = await connect(m);
  check("O21. a code Google refuses (invalid_grant) is 400 state_invalid, nothing stored", c.f.status === 400 && c.f.body.code === "state_invalid" && m.db.t.member_youtube_connections.length === 0);
  check("O22. GA.grantsYoutube needs both full scope URLs", GA.grantsYoutube(BOTH_SCOPES) && GA.grantsYoutube(READONLY_SCOPE + " openid " + UPLOAD_SCOPE) &&
    !GA.grantsYoutube(UPLOAD_SCOPE) && !GA.grantsYoutube("youtube.upload youtube.readonly") && !GA.grantsYoutube(null));

  /* ── T ── */
  OUT("\n══ T. tokens ══");
  let db = makeDb();
  let g = makeGoogle({ db: db });
  let row = seedConnection(db, { access_expires_at: new Date(Date.now() + 6 * 60 * 1000).toISOString() });
  let got = await attempt(YA.accessToken(libDeps(db, g), row, false));
  check("T1. six minutes from expiry: the stored access token, no refresh", got.ok && got.v.token === ACCESS && g.tokenCalls.length === 0);
  row.access_expires_at = new Date(Date.now() + 4 * 60 * 1000).toISOString();
  got = await attempt(YA.accessToken(libDeps(db, g), row, false));
  check("T2. four minutes from expiry: refreshed first; the new token stored with token_version 1, the stored refresh token kept (Google sent none)",
    got.ok && got.v.token === ACCESS2 && g.tokenCalls.length === 1 && g.tokenCalls[0].grant_type === "refresh_token" && g.tokenCalls[0].refresh_token === REFRESH &&
    accessOf(db.t.member_youtube_connections[0]) === ACCESS2 && refreshOf(db.t.member_youtube_connections[0]) === REFRESH &&
    db.t.member_youtube_connections[0].token_version === 1, got.ok ? "" : got.msg);
  db = makeDb(); g = makeGoogle({ db: db, rotate: true });
  row = seedConnection(db, { access_expires_at: new Date(Date.now() - 1000).toISOString() });
  got = await attempt(YA.accessToken(libDeps(db, g), row, false));
  check("T3. Google sends a new refresh token: it is stored, sealed, in the same update", got.ok && refreshOf(db.t.member_youtube_connections[0]) === REFRESH2 &&
    accessOf(db.t.member_youtube_connections[0]) === ACCESS2);
  // the race
  db = makeDb();
  row = seedConnection(db, { access_expires_at: new Date(Date.now() - 1000).toISOString() });
  g = makeGoogle({ db: db, onRefresh: function () {
    const live = db.t.member_youtube_connections[0];
    const w = seal(WINNER);
    Object.assign(live, { access_ciphertext: w.ciphertext, access_iv: w.iv, access_auth_tag: w.authTag, token_version: 1, access_expires_at: new Date(Date.now() + 3600000).toISOString() });
  } });
  got = await attempt(YA.accessToken(libDeps(db, g), Object.assign({}, row), false));
  check("T4. the compare-and-set: another process refreshed first (token_version moved), so this one writes nothing and uses the winner's token",
    got.ok && got.v.token === WINNER && accessOf(db.t.member_youtube_connections[0]) === WINNER && db.t.member_youtube_connections[0].token_version === 1,
    got.ok ? J([got.v.token === WINNER, got.v.token === ACCESS2, accessOf(db.t.member_youtube_connections[0]) === WINNER, db.t.member_youtube_connections[0].token_version]) : got.msg);
  db = makeDb(); g = makeGoogle({ db: db });
  row = seedConnection(db, { access_expires_at: new Date(Date.now() - 1000).toISOString() });
  const two = await Promise.all([attempt(YA.accessToken(libDeps(db, g), row, false)), attempt(YA.accessToken(libDeps(db, g), row, false))]);
  check("T5. single-flight: two at once make ONE refresh request and both get its token", g.tokenCalls.length === 1 && two.every(function (x) { return x.ok && x.v.token === ACCESS2; }), g.tokenCalls.length);
  db = makeDb(); g = makeGoogle({ db: db, refresh: "invalid_grant" });
  row = seedConnection(db, { access_expires_at: new Date(Date.now() - 1000).toISOString() });
  got = await attempt(YA.accessToken(libDeps(db, g), row, false));
  const got2 = await attempt(YA.accessToken(libDeps(db, g), db.t.member_youtube_connections[0], false));
  check("T6. invalid_grant: the connection is needs_reconnect, with ONE in-app notice; the next call asks Google nothing",
    !got.ok && got.kind === "auth" && db.t.member_youtube_connections[0].status === "needs_reconnect" &&
    db.t.notifications.filter(function (n) { return n.type === "youtube_reconnect" && n.user_id === USER; }).length === 1 && !got2.ok && g.tokenCalls.length === 1, J([got.kind, db.t.notifications.length]));
  check("T7. the notice names the channel and no token", db.t.notifications.length === 1 && db.t.notifications[0].message.indexOf(CHANNEL_TITLE) !== -1 && noSecretIn(J(db.t.notifications)));
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db, { status: "needs_reconnect" });
  r = await hit(m, "get /api/youtube/status", {});
  check("T8. status for needs_reconnect: not connected, the reconnect message, never a token", r.status === 200 && r.body.connected === false && r.body.status === "needs_reconnect" &&
    r.body.reconnect_message === YA.MESSAGES.needsReconnect && noSecretIn(J(r.body)) && Object.keys(r.body).every(function (k) { return !/cipher|token|iv|tag/.test(k); }), J(Object.keys(r.body)));

  /* ── D ── */
  OUT("\n══ D. disconnect ══");
  m = mountRoutes({ env: CONFIGURED, google: { revoke: "down" } });
  seedConnection(m.db);
  m.db.t.oauth_states.push({ id: uuid(), user_id: USER, purpose: "youtube_google", state_hash: "c".repeat(64), verifier_ciphertext: "00", verifier_iv: "0".repeat(24), verifier_auth_tag: "0".repeat(32), flow_context: null, consumed_at: null });
  m.db.t.oauth_states.push({ id: uuid(), user_id: USER, purpose: "store_shopify", state_hash: "d".repeat(64), flow_context: { shop: "x.myshopify.com", permission: "read" }, consumed_at: null });
  m.db.t.oauth_states.push({ id: uuid(), user_id: USER, purpose: "mailbox_microsoft", state_hash: "e".repeat(64), verifier_ciphertext: "00", verifier_iv: "0".repeat(24), verifier_auth_tag: "0".repeat(32), flow_context: null, consumed_at: null });
  r = await hit(m, "post /api/youtube/disconnect", {});
  check("D1. Google unreachable for the revoke: the disconnect still happens (200), the row deleted, revoked false",
    r.status === 200 && r.body.removed === true && r.body.revoked === false && m.db.t.member_youtube_connections.length === 0 && m.google.of(function (x) { return x.path === "/revoke"; }).length === 1, J([r.status, r.body.removed]));
  check("D2. the note is \"Disconnected. BizForce asked Google to cancel its access to your channel.\"", r.body.note === "Disconnected. BizForce asked Google to cancel its access to your channel.");
  check("D3. only this sign-in's states are deleted: Connect Shopify's and Microsoft's stay",
    m.db.t.oauth_states.filter(function (s) { return s.purpose === "youtube_google"; }).length === 0 && m.db.t.oauth_states.length === 2);
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  r = await hit(m, "post /api/youtube/disconnect", {});
  check("D4. Google reachable: the refresh token is what is revoked (a form POST), revoked true", r.status === 200 && r.body.revoked === true && m.google.revoked === REFRESH);
  check("D5. disconnect is login-only and always open (no subscription, configured or not)", m.routes["post /api/youtube/disconnect"].middleware.length === 1);

  /* ── V ── */
  OUT("\n══ V. videos ══");
  m = mountRoutes({ env: CONFIGURED });
  const upLim = m.routes["post /api/videos/upload-url"].middleware[2] && m.routes["post /api/videos/upload-url"].middleware[2].limiter;
  check("V1. upload-url and finalize share one limiter, 10 an hour, keyed video-upload:<id>",
    !!upLim && m.routes["post /api/videos/finalize"].middleware[2] === m.routes["post /api/videos/upload-url"].middleware[2] && upLim.max === 10 && upLim.windowMs === 3600000 &&
    upLim.keyGenerator({ user: { id: USER } }) === "video-upload:" + USER);
  r = await hit(m, "post /api/videos/upload-url", { body: { mime: "video/mp4", bytes: 1048576, label: "Spring cakes" } });
  check("V2. upload-url: a signed upload URL for video/<uid>/<32 hex>.mp4 in bf-video, and the 50 MB limit",
    r.status === 200 && /^video\/00000000-0000-4000-8000-000000000001\/[0-9a-f]{32}\.mp4$/.test(r.body.path || "") && r.body.max_bytes === 52428800 &&
    r.body.mime === "video/mp4" && typeof r.body.upload_url === "string" && m.storage.calls.filter(function (x) { return x.op === "sign"; }).length === 1, J([r.status, r.body.path]));
  const rMov = await hit(m, "post /api/videos/upload-url", { body: { mime: "video/quicktime", bytes: 10 } });
  const rWebm = await hit(m, "post /api/videos/upload-url", { body: { mime: "video/webm", bytes: 10 } });
  const rGif = await hit(m, "post /api/videos/upload-url", { body: { mime: "image/heic", bytes: 10 } });
  const rBig = await hit(m, "post /api/videos/upload-url", { body: { mime: "video/mp4", bytes: 52428801 } });
  const rZero = await hit(m, "post /api/videos/upload-url", { body: { mime: "video/mp4", bytes: 0 } });
  check("V3. MOV and WebM take .mov and .webm; another type is 400, over 50 MB is 413, zero bytes is 400",
    /\.mov$/.test(rMov.body.path || "") && /\.webm$/.test(rWebm.body.path || "") && rGif.status === 400 && rGif.body.code === "unsupported" && rBig.status === 413 && rZero.status === 400,
    J([rMov.status, rWebm.status, rGif.status, rBig.status, rZero.status]));
  // finalize
  m = mountRoutes({ env: CONFIGURED });
  let buf = mp4("isom", 200000);
  let p = videoPath(USER, "mp4");
  m.storage.objects[p] = { buf: buf, created_at: new Date().toISOString() };
  r = await hit(m, "post /api/videos/finalize", { body: { path: p, label: "Spring cakes", bytes: buf.length } });
  const vrow = m.db.t.member_videos[0];
  check("V4. finalize: the object read as a stream (asStream), never as a whole download; the row stores its size and sha256, status ready",
    r.status === 201 && !!vrow && vrow.sha256 === sha(buf) && Number(vrow.bytes) === buf.length && vrow.status === "ready" && vrow.mime === "video/mp4" &&
    m.storage.calls.some(function (x) { return x.op === "stream" && x.path === p; }) && !m.storage.calls.some(function (x) { return x.op === "whole"; }), J([r.status, r.body.code]));
  check("V5. what the member sees has no path, fingerprint or session", r.status === 201 && ["path", "sha256", "session_ciphertext", "session_iv", "session_auth_tag", "user_id"].every(function (k) { return !(k in r.body.video); }) &&
    r.body.video.upload_unfinished === false, J(Object.keys(r.body.video || {})));
  r = await hit(m, "post /api/videos/finalize", { body: { path: p, label: "", bytes: buf.length } });
  check("V6. finalizing the same path twice is 409", r.status === 409 && m.db.t.member_videos.length === 1);
  async function finalizeOne(content, ext, declared) {
    const mm = mountRoutes({ env: CONFIGURED });
    const pp = videoPath(USER, ext);
    mm.storage.objects[pp] = content && content.lazySize ? { lazySize: content.lazySize, head: content.head, created_at: new Date().toISOString() } : { buf: content, created_at: new Date().toISOString() };
    const rr = await hit(mm, "post /api/videos/finalize", { body: { path: pp, label: "x", bytes: declared === undefined ? (content.lazySize || content.length) : declared } });
    return { r: rr, m: mm, p: pp, kept: !!mm.storage.objects[pp], rows: mm.db.t.member_videos.length };
  }
  const brands = [];
  for (const br of ["isom", "iso2", "iso4", "iso5", "iso6", "mp41", "mp42", "avc1", "dash", "M4V "]) brands.push((await finalizeOne(mp4(br, 5000), "mp4")).r.status);
  check("V7. every MP4 brand the brief names is accepted at .mp4", brands.every(function (s) { return s === 201; }), J(brands));
  const mov = await finalizeOne(mp4("qt  ", 5000), "mov");
  const wm = await finalizeOne(webm("webm", 5000), "webm");
  check("V8. \"qt  \" is a .mov; EBML with DocType webm is a .webm", mov.r.status === 201 && wm.r.status === 201, J([mov.r.status, wm.r.status]));
  const mkv = await finalizeOne(webm("matroska", 5000), "webm");
  check("V9. EBML with DocType matroska is refused (422) and deleted", mkv.r.status === 422 && mkv.r.body.deleted === true && !mkv.kept && mkv.rows === 0);
  const heics = [];
  for (const br of ["heic", "heix", "hevc", "hevx", "heim", "heis", "mif1", "msf1", "avif"]) { const x = await finalizeOne(mp4(br, 5000), "mp4"); heics.push([x.r.status, x.kept]); }
  check("V10. HEIC and HEIF brands are refused at .mp4 (422), and each is deleted", heics.every(function (h) { return h[0] === 422 && h[1] === false; }), J(heics));
  check("V11. MV.sniffVideo refuses the HEIC brands, an unknown brand and a short file", ["heic", "mif1", "avif", "abcd"].every(function (br) { return MV.sniffVideo(mp4(br, 100)) === null; }) &&
    MV.sniffVideo(Buffer.from("ftyp")) === null && MV.sniffVideo(mp4("mp42", 100)) === "mp4");
  const lie = await finalizeOne(mp4("isom", 5000), "webm");
  check("V12. an MP4 at a .webm path (the declared type is not what the bytes are): 422 mismatch, deleted, no row",
    lie.r.status === 422 && lie.r.body.code === "mismatch" && !lie.kept && lie.rows === 0, J([lie.r.status, lie.r.body.code]));
  const short = await finalizeOne(mp4("isom", 5000), "mp4", 5001);
  check("V13. a size that is not the one the browser declared: 422 size_mismatch, deleted, no row",
    short.r.status === 422 && short.r.body.code === "size_mismatch" && !short.kept && short.rows === 0, J([short.r.status, short.r.body.code]));
  const huge = await finalizeOne({ lazySize: 52428801, head: mp4("isom", 64) }, "mp4", 52428800);
  check("V14. more than 50 MB arriving (counted while streaming): 422 too_big, deleted, no row", huge.r.status === 422 && huge.r.body.code === "too_big" && !huge.kept && huge.rows === 0, J([huge.r.status, huge.r.body.code]));
  const notThere = await (async function () { const mm = mountRoutes({ env: CONFIGURED }); return hit(mm, "post /api/videos/finalize", { body: { path: videoPath(USER), bytes: 10 } }); })();
  const foreignPath = await (async function () { const mm = mountRoutes({ env: CONFIGURED }); return hit(mm, "post /api/videos/finalize", { body: { path: videoPath(OTHER), bytes: 10 } }); })();
  check("V15. an object not uploaded is 404; another member's path is 400 bad_path", notThere.status === 404 && foreignPath.status === 400 && foreignPath.body.code === "bad_path");
  // the ready cap
  m = mountRoutes({ env: CONFIGURED });
  seedVideo(m.db, mp4("isom", 1000)); seedVideo(m.db, mp4("isom", 1000, 9));
  r = await hit(m, "post /api/videos/upload-url", { body: { mime: "video/mp4", bytes: 1000 } });
  p = videoPath(USER); m.storage.objects[p] = { buf: mp4("isom", 1000, 11), created_at: new Date().toISOString() };
  const rCap = await hit(m, "post /api/videos/finalize", { body: { path: p, bytes: 1000 } });
  check("V16. two videos waiting: upload-url and finalize are 409 \"You have 2 videos waiting. Upload or delete one first.\"",
    r.status === 409 && r.body.error === "You have 2 videos waiting. Upload or delete one first." && rCap.status === 409 && rCap.body.code === "ready_cap" &&
    m.storage.calls.filter(function (x) { return x.op === "sign"; }).length === 0, J([r.status, rCap.status]));
  // foreign videos
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  const mine = seedVideo(m.db, mp4("isom", 1000));
  const theirsV = seedVideo(m.db, mp4("isom", 1000, 4), { user_id: OTHER });
  const theirsUp = seedVideo(m.db, mp4("isom", 1000, 5), { user_id: OTHER, status: "uploaded", youtube_video_id: YT_ID, path: null, uploaded_at: new Date().toISOString() });
  r = await hit(m, "get /api/videos", {});
  const fDel = await hit(m, "delete /api/videos/:id", { params: { id: theirsV.id } });
  const fProp = await file(m, theirsV);
  const fDraft = await hit(m, "post /api/youtube/draft-metadata", { body: { video_id: theirsV.id, idea: "cakes" } });
  const fStat = await hit(m, "get /api/youtube/videos/:id/status", { params: { id: theirsUp.id } });
  const fPropDel = await hit(m, "post /api/youtube/videos/:id/propose-delete", { params: { id: theirsUp.id } });
  check("V17. another member's video is in no list, and delete, filing, a draft, a status and a removal of it are 404, with nothing changed",
    r.status === 200 && r.body.videos.length === 1 && r.body.videos[0].id === mine.id && fDel.status === 404 && fProp.status === 404 && fDraft.status === 404 &&
    fStat.status === 404 && fPropDel.status === 404 && rowOf(m, theirsV.id).status === "ready" && !!m.storage.objects[theirsV.path] &&
    m.db.t.agent_proposals.length === 0 && m.prompts.length === 0, J([r.body.videos && r.body.videos.length, fDel.status, fProp.status, fDraft.status, fStat.status, fPropDel.status]));
  r = await hit(m, "delete /api/videos/:id", { params: { id: mine.id } });
  check("V18. deleting a waiting video removes its file and marks it removed (path null)", r.status === 200 && rowOf(m, mine.id).status === "removed" && rowOf(m, mine.id).path === null &&
    !m.storage.objects[mine.path]);
  const mine2 = seedVideo(m.db, mp4("isom", 1000, 21));
  await file(m, mine2);
  r = await hit(m, "delete /api/videos/:id", { params: { id: mine2.id } });
  check("V19. a video a pending proposal names cannot be deleted (409), its file kept", r.status === 409 && r.body.code === "in_proposal" && !!m.storage.objects[mine2.path]);

  /* ── F ── */
  OUT("\n══ F. filing ══");
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  let video = seedVideo(m.db, mp4("isom", 300000));
  EV.length = 0;
  r = await file(m, video, { privacy: undefined });
  let prop = m.db.t.agent_proposals[0];
  check("F1. filed: one pending publish_youtube_video proposal with the payload the brief names, category 22, this channel",
    r.status === 201 && !!prop && prop.status === "pending" && prop.action_type === "publish_youtube_video" && prop.user_id === USER &&
    J(Object.keys(prop.payload).sort()) === J(["bytes", "category_id", "channel_id", "description", "made_for_kids", "mime", "privacy", "sha256", "tags", "title", "video_id"]) &&
    prop.payload.sha256 === video.sha256 && prop.payload.bytes === video.bytes && prop.payload.category_id === "22" && prop.payload.channel_id === CHANNEL, J([r.status, r.body.code]));
  check("F2. privacy defaults to private", !!prop && prop.payload.privacy === "private");
  check("F3. filing never sends: nothing asked of Google, no units, no session", m.google.requests.length === 0 && m.db.t.youtube_api_calls.length === 0 &&
    !rowOf(m, video.id).session_ciphertext && prop && prop.status === "pending" && r.body.note.indexOf("Nothing has been sent to YouTube.") !== -1);
  r = await file(m, video);
  check("F4. one pending upload per video: filing again is 409 pending", r.status === 409 && r.body.code === "pending" && m.db.t.agent_proposals.length === 1);
  m.db.t.agent_proposals = [];
  r = await file(m, video, { made_for_kids: undefined });
  const rKidsText = await file(m, video, { made_for_kids: "yes" });
  check("F5. made_for_kids is required and must be true or false", r.status === 400 && r.body.field === "made_for_kids" && rKidsText.status === 400 && m.db.t.agent_proposals.length === 0);
  const fieldsBad = [];
  for (const over of [{ title: "" }, { title: "x".repeat(101) }, { title: "a <b>" }, { description: "é".repeat(2501) }, { tags: ["a,b"] }, { tags: ["x".repeat(501)] }, { privacy: "friends" }]) {
    fieldsBad.push((await file(m, video, over)).status);
  }
  check("F6. the metadata rules: a title of 1 to 100 code points without < or >, a description of at most 5000 bytes, tags without commas, 500 in all, privacy of three",
    fieldsBad.every(function (s) { return s === 400; }) && m.db.t.agent_proposals.length === 0, J(fieldsBad));
  const okEdge = MV.validateMetadata({ title: "x".repeat(100), description: "é".repeat(2500), tags: ["x".repeat(250), "y".repeat(249)], made_for_kids: true }, LIMITS);
  check("F7. ...and the edges pass: 100 characters, 5000 bytes, 500 with separators", okEdge.ok === true && okEdge.value.privacy === "private" && okEdge.value.category_id === "22");
  r = await file(m, video, { title: "Guaranteed results every time" });
  check("F8. the claims screen on the title: 422 claims, nothing filed", r.status === 422 && r.body.code === "claims" && r.body.field === "title" && m.db.t.agent_proposals.length === 0);
  r = await file(m, video, { description: "Guaranteed to sell out." });
  check("F9. ...and on the description", r.status === 422 && r.body.field === "description" && m.db.t.agent_proposals.length === 0);
  const pl = m.routes["post /api/youtube/propose-upload"].middleware[2].limiter;
  check("F10. propose-upload and propose-delete share a limiter of 30 an hour", pl.max === 30 && pl.windowMs === 3600000 &&
    m.routes["post /api/youtube/videos/:id/propose-delete"].middleware[2] === m.routes["post /api/youtube/propose-upload"].middleware[2]);
  check("F11. the generic proposals route refuses both types, and both are subscription-gated and have an executor",
    FILES.server.indexOf("if (actionType === \"publish_youtube_video\") {\n      return res.status(400).json({\n        error: \"A YouTube upload cannot be filed here.") !== -1 &&
    FILES.server.indexOf("if (actionType === \"delete_youtube_video\") {\n      return res.status(400).json({\n        error: \"A YouTube removal cannot be filed here.") !== -1 &&
    // NAMED (Nov 7 2026, TikTok posting): the gated list goes on with publish_tiktok_post; both YouTube types still in it.
    // NAMED, item 8 part 3a (Instagram posting): publish_instagram_post now ends the list.
    // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): publish_facebook_post now ends the list.
    FILES.server.indexOf("\"update_store_item\", \"publish_youtube_video\", \"delete_youtube_video\", \"publish_tiktok_post\", \"publish_instagram_post\", \"publish_facebook_post\"];") !== -1 &&
    FILES.server.indexOf("  publish_youtube_video: executePublishYoutubeVideo,\n") !== -1 && FILES.server.indexOf("  delete_youtube_video: executeDeleteYoutubeVideo,\n") !== -1);
  // draft
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4("isom", 3000), { label: "secret-label-zz" });
  r = await hit(m, "post /api/youtube/draft-metadata", { body: { video_id: video.id, idea: "Our spring cakes" } });
  check("F12. a draft: the model sees the idea and nothing of the file, label or channel; measured in code; nothing filed",
    r.status === 200 && r.body.draft.title === "Spring cakes at Maple Street" && r.body.within_limits === true && J(r.body.draft.tags) === J(["cakes", "bakery", "spring"]) &&
    m.prompts.length === 1 && m.prompts[0].indexOf("Our spring cakes") !== -1 && m.prompts[0].indexOf("secret-label-zz") === -1 && m.prompts[0].indexOf(video.path) === -1 &&
    m.prompts[0].indexOf(CHANNEL) === -1 && m.db.t.agent_proposals.length === 0, J([r.status, r.body.code]));

  /* ── U ── */
  OUT("\n══ U. the upload on approval ══");
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  buf = mp4("isom", 300000);
  video = seedVideo(m.db, buf);
  await file(m, video);
  prop = m.db.t.agent_proposals[0];
  EV.length = 0; LOGS.length = 0;
  let a = await approve(m, prop);
  let v = rowOf(m, video.id);
  const sess = m.google.sessions[Object.keys(m.google.sessions)[0]];
  check("U1. approved: the file reaches YouTube whole and once, through one resumable session", a.ok && m.google.starts().length === 1 && m.google.puts().length === 1 &&
    !!sess && sess.done && sha(sess.received) === sha(buf), a.ok ? "" : a.msg);
  /* NAMED (Nov 7 2026, TikTok posting, migration 178): BEFORE the upload set status uploaded and deleted the file at once.
     AFTER status describes the FILE, so it stays ready with the file kept for TikTok; the retention pass deletes it once
     YouTube and TikTok both have it, or 14 days after it was added (J8, J1). */
  check("U2. recorded: the id, uploaded_at, the session cleared, the file still ready; the link https://www.youtube.com/watch?v=<id>",
    a.ok && v.status === "ready" && v.youtube_video_id === YT_ID && !!v.uploaded_at && v.session_ciphertext === null && a.v.url === "https://www.youtube.com/watch?v=" + YT_ID &&
    a.v.privacy === "private" && a.v.channel === CHANNEL_TITLE);
  check("U3. the file is kept after YouTube has it (path kept, the object there), for the other platform or the retention pass", v.path === video.path && !!m.storage.objects[video.path]);
  const sb = (m.google.startBodies || [])[0] || {};
  const start0 = m.google.starts()[0] || {};
  check("U4. the start sends the filed title, description, tags, category 22, privacy and made-for-kids, and the file's type and size",
    sb.snippet && sb.snippet.title === META.title && sb.snippet.description === META.description && J(sb.snippet.tags) === J(META.tags) && sb.snippet.categoryId === "22" &&
    sb.status.privacyStatus === "private" && sb.status.selfDeclaredMadeForKids === false && start0.xType === "video/mp4" && start0.xLength === String(buf.length) &&
    start0.search === "?uploadType=resumable&part=snippet,status");
  check("U5. the session was sealed BEFORE the first byte: at the first PUT the row already held it, encrypted", m.google.sealedAtFirstPut === SESSION_BASE + "1");
  const ledger = m.db.t.youtube_api_calls;
  const reservedAt = EV.indexOf("db:youtube_api_calls:insert");
  check("U6. 100 units reserved (videos.insert) as social_search for this member, before the start", ledger.length === 1 && ledger[0].units === 100 && ledger[0].caller === "social_search" &&
    ledger[0].user_id === USER && reservedAt !== -1 && reservedAt < EV.indexOf("yt:start"), J(ledger.map(function (x) { return x.units; })));
  check("U7. the order: reserve, start, seal, PUT", EV.indexOf("yt:start") < EV.indexOf("db:member_videos:update") && EV.indexOf("db:member_videos:update") < EV.indexOf("yt:put"), EV.join(","));
  check("U8. every YouTube request carried the access token; nothing logged holds a token, a code or a session URI",
    m.google.requests.every(function (x) { return x.bearer === ACCESS; }) && LOGS.every(noSecretIn), LOGS.filter(function (l) { return !noSecretIn(l); }).length);
  // approving again
  a = await approve(m, prop);
  check("U9. approving it again records nothing new and sends nothing: already uploaded", a.ok && a.v.already_uploaded === true && m.google.starts().length === 1);
  // fingerprint
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  buf = mp4("isom", 300000);
  video = seedVideo(m.db, buf);
  await file(m, video);
  prop = m.db.t.agent_proposals[0];
  const changed = Buffer.from(buf); changed[1000] ^= 0xff;
  m.storage.objects[video.path].buf = changed;
  a = await approve(m, prop);
  check("U10. the file changed after filing (same size): refused with the fingerprint message before anything; no start, no units, no session",
    !a.ok && a.msg === "publish_youtube_video: " + YA.MESSAGES.fingerprint && m.google.requests.length === 0 && m.db.t.youtube_api_calls.length === 0 &&
    !rowOf(m, video.id).session_ciphertext, a.msg);
  // the guard
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  buf = mp4("isom", 300000);
  video = seedVideo(m.db, buf);
  await file(m, video);
  prop = m.db.t.agent_proposals[0];
  const changed2 = Buffer.from(buf); changed2[buf.length - 10] ^= 0xff;
  m.storage.objects[video.path].queue = [buf, changed2];   // the check reads the filed file; the send reads a changed one
  a = await approve(m, prop);
  const s2 = m.google.sessions[Object.keys(m.google.sessions)[0]];
  check("U11. the file changes between the check and the send: the guard holds the last chunk back, so YouTube never gets the whole file and nothing is recorded",
    !a.ok && a.msg === "publish_youtube_video: " + YA.MESSAGES.fingerprint && !!s2 && !s2.done && s2.received.length < buf.length && rowOf(m, video.id).status === "ready" &&
    !rowOf(m, video.id).youtube_video_id, a.ok ? "uploaded" : a.msg);
  const guardRun = await (async function () {
    const data = filler(200000, 2);
    const gd = YA.fingerprintGuard(sha(data), data.length, 50000);
    const out = [];
    gd.on("data", function (c) { out.push(c); });
    const ended = new Promise(function (res) { gd.on("end", function () { res(true); }); gd.on("error", function () { res(false); }); });
    for (let i = 0; i < data.length; i += 65536) gd.write(data.subarray(i, i + 65536));
    gd.end();
    return { ok: await ended, out: Buffer.concat(out), data: data };
  })();
  check("U12. YA.fingerprintGuard hashes from byte 0 and passes on only the bytes from the offset", guardRun.ok && guardRun.out.equals(guardRun.data.subarray(50000)));
  // the daily cap
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  for (let i = 0; i < 5; i++) seedVideo(m.db, mp4("isom", 1000, 30 + i), { status: "uploaded", path: null, youtube_video_id: YT_ID, uploaded_at: new Date(Date.now() - (i + 1) * 3600000).toISOString() });
  video = seedVideo(m.db, mp4("isom", 3000, 40));
  await file(m, video);
  a = await approve(m, m.db.t.agent_proposals[0]);
  check("U13. five uploads in the last 24 hours (counted from uploaded_at): a sixth is refused with the cap message, nothing sent",
    !a.ok && a.msg === "publish_youtube_video: " + YA.MESSAGES.dailyCap && m.google.requests.length === 0, a.msg);
  m.db.t.member_videos[0].uploaded_at = new Date(Date.now() - 25 * 3600000).toISOString();
  a = await approve(m, m.db.t.agent_proposals[0]);
  check("U14. ...one of them 25 hours old: the upload goes", a.ok, a.msg);
  // quota fails closed
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4("isom", 3000));
  await file(m, video);
  m.db.fail.youtube_api_calls = { message: "relation does not exist" };
  a = await approve(m, m.db.t.agent_proposals[0]);
  check("U15. the quota ledger unreadable: refused (\"today's YouTube allowance\"), nothing sent (fails closed)", !a.ok && a.msg === "publish_youtube_video: " + YA.MESSAGES.quota &&
    m.google.requests.length === 0, a.msg);
  m.db.t.youtube_api_calls.push({ id: 1, created_on: new Date().toISOString().slice(0, 10), caller: "radar", user_id: null, units: 4950 });
  a = await approve(m, m.db.t.agent_proposals[0]);
  check("U16. 4950 of the 5000 units spent today: an upload (100) is refused, nothing sent", !a.ok && a.msg === "publish_youtube_video: " + YA.MESSAGES.quota && m.google.requests.length === 0, a.msg);
  // one resume per run, then crash safety
  m = mountRoutes({ env: CONFIGURED, google: { cut: 2 } });
  seedConnection(m.db);
  buf = mp4("isom", 400000);
  video = seedVideo(m.db, buf);
  await file(m, video, { title: "First title" });
  prop = m.db.t.agent_proposals[0];
  a = await approve(m, prop);
  v = rowOf(m, video.id);
  check("U17. interrupted twice: one status query and one resume in the run, never a second; the upload fails with the exact message",
    !a.ok && a.msg === "publish_youtube_video: YouTube upload didn't finish. File the upload again and BizForce will continue the same upload." &&
    m.google.puts().length === 2 && m.google.queries().length === 1 && m.google.starts().length === 1, J([a.msg, m.google.puts().length, m.google.queries().length]));
  check("U18. the session stays stored, sealed (never plain), and the video is still waiting, shown as an unfinished upload",
    sessionOf(v) === SESSION_BASE + "1" && J(v).indexOf("check-session-") === -1 && v.status === "ready" && MV.publicView(v).upload_unfinished === true);
  const resumedOffset = m.google.puts()[1] ? Number(/^bytes (\d+)-/.exec(m.google.puts()[1].contentRange || "bytes 0-")[1]) : -1;
  check("U19. the resume started at the offset YouTube's Range named, with Content-Range bytes A-(N-1)/N", resumedOffset > 0 &&
    m.google.puts()[1].contentRange === "bytes " + resumedOffset + "-" + (buf.length - 1) + "/" + buf.length, m.google.puts()[1] && m.google.puts()[1].contentRange);
  // filing again
  m.google.opts.cut = 0;
  prop.status = "failed";
  r = await file(m, video, { title: "A different title", privacy: "public" });
  const prop2 = m.db.t.agent_proposals[1];
  check("U20. filing again reuses the frozen metadata of the earlier filing (title and privacy unchanged), and says so",
    r.status === 201 && !!prop2 && prop2.payload.title === "First title" && prop2.payload.privacy === "private" && r.body.reused_earlier_details === true &&
    r.body.note.indexOf(YA.MESSAGES.reused) !== -1, J([r.status, prop2 && prop2.payload.title]));
  const putsBefore = m.google.puts().length, queriesBefore = m.google.queries().length;
  const reqBefore = m.google.requests.length;
  a = await approve(m, prop2);
  const after = m.google.requests.slice(reqBefore);
  const s1 = m.google.sessions[Object.keys(m.google.sessions)[0]];
  check("U21. approved again: a status query FIRST, then the rest from YouTube's offset; never a second insert",
    a.ok && m.google.starts().length === 1 && after.length >= 2 && after[0].method === "PUT" && after[0].bytes === 0 && after[0].contentRange === "bytes */" + buf.length &&
    m.google.queries().length === queriesBefore + 1 && m.google.puts().length === putsBefore + 1 && /^bytes [1-9]\d*-/.test(after[1].contentRange || "") &&
    s1.done && sha(s1.received) === sha(buf), a.ok ? J(after.map(function (x) { return x.method + " " + x.contentRange; })) : a.msg);
  check("U22. ...the status query reserved 1 unit (uploads.status), and the run made no second 100-unit reservation",
    m.db.t.youtube_api_calls.filter(function (x) { return x.units === 100; }).length === 1 && m.db.t.youtube_api_calls.filter(function (x) { return x.units === 1; }).length === 1);
  // NAMED (Nov 7 2026, TikTok posting): BEFORE "uploaded ... the file deleted"; AFTER the YouTube id recorded once, the file kept (U3).
  check("U23. ...recorded once: the YouTube id, the session cleared, the file kept", rowOf(m, video.id).youtube_video_id === YT_ID && rowOf(m, video.id).status === "ready" &&
    rowOf(m, video.id).session_ciphertext === null && rowOf(m, video.id).path === video.path && !!m.storage.objects[video.path]);
  // crash after the last byte, before the record
  m = mountRoutes({ env: CONFIGURED, google: { cut: 1 } });
  seedConnection(m.db);
  buf = mp4("isom", 200000);
  video = seedVideo(m.db, buf);
  await file(m, video);
  m.google.opts.cut = 99;
  a = await approve(m, m.db.t.agent_proposals[0]);
  check("U24. (setup) the first run did not finish", !a.ok && !!rowOf(m, video.id).session_ciphertext);
  const s3 = m.google.sessions[Object.keys(m.google.sessions)[0]];
  s3.received = Buffer.from(buf); s3.done = true;   // YouTube got every byte; BizForce crashed before it heard
  m.google.opts.cut = 0;
  m.db.t.agent_proposals[0].status = "failed";
  await file(m, video);
  const pBefore = m.google.puts().length;
  a = await approve(m, m.db.t.agent_proposals[1]);
  check("U25. YouTube already had the whole file: the status query finds it complete and BizForce records it, with no byte sent again and no insert",
    a.ok && m.google.puts().length === pBefore && m.google.starts().length === 1 && rowOf(m, video.id).youtube_video_id === YT_ID, a.ok ? "" : a.msg);
  // an expired session
  m = mountRoutes({ env: CONFIGURED, google: { cut: 9 } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4("isom", 200000));
  await file(m, video);
  await approve(m, m.db.t.agent_proposals[0]);
  m.google.opts.expired = true; m.google.opts.cut = 0;
  m.db.t.agent_proposals[0].status = "failed";
  await file(m, video);
  a = await approve(m, m.db.t.agent_proposals[1]);
  check("U26. a session YouTube no longer knows (404): cleared, the expired message, and no new insert in that run",
    !a.ok && a.msg === "publish_youtube_video: " + YA.MESSAGES.expired && rowOf(m, video.id).session_ciphertext === null && m.google.starts().length === 1, a.msg);
  // a start that names another host
  m = mountRoutes({ env: CONFIGURED, google: { startLocation: "https://evil.example.com/upload/youtube/v3/videos?upload_id=x" } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4("isom", 3000));
  await file(m, video);
  a = await approve(m, m.db.t.agent_proposals[0]);
  check("U27. a Location that is not www.googleapis.com/upload/: refused, nothing stored, nothing PUT", !a.ok && /didn't start the upload/.test(a.msg || "") &&
    !rowOf(m, video.id).session_ciphertext && m.google.puts().length === 0, a.msg);
  // the channel changed
  m = mountRoutes({ env: CONFIGURED });
  const cRow = seedConnection(m.db);
  video = seedVideo(m.db, mp4("isom", 3000));
  await file(m, video);
  cRow.channel_id = "UCzzzzzzzzzzzzzzzzzzzzzz";
  a = await approve(m, m.db.t.agent_proposals[0]);
  check("U28. the channel connected now is not the one filed for: refused, nothing sent", !a.ok && a.msg === "publish_youtube_video: " + YA.MESSAGES.channelChanged && m.google.requests.length === 0);
  // made_for_kids missing in a payload
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4("isom", 3000));
  a = await approve(m, { id: uuid(), user_id: USER, payload: { video_id: video.id, sha256: video.sha256, bytes: video.bytes, mime: video.mime, title: "x", description: "", tags: [], privacy: "private", category_id: "22", channel_id: CHANNEL } });
  check("U29. a payload without made_for_kids is refused at approval too, nothing sent", !a.ok && a.msg.indexOf(MV.MESSAGES.kids) !== -1 && m.google.requests.length === 0, a.msg);
  check("U30. lib/youtubeApi.js and lib/memberVideos.js log nothing but counts (no console call names a token, a session or a path)",
    !/console\.(log|warn|error)\([^;]*(token|session|location|path|signed)/i.test(stripComments(FILES.api).replace(/the reconnect notice could not be saved/, "")) &&
    !/console\.(log|warn|error)\([^;]*(token|session|location|signedUrl)/i.test(stripComments(FILES.videos)));

  /* ── R ── */
  OUT("\n══ R. removal and status ══");
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  const up = seedVideo(m.db, mp4("isom", 3000), { status: "uploaded", youtube_video_id: YT_ID, path: null, uploaded_at: new Date().toISOString() });
  r = await hit(m, "post /api/youtube/videos/:id/propose-delete", { params: { id: up.id } });
  const dp = m.db.t.agent_proposals[0];
  check("R1. removal is filed as a pending delete_youtube_video proposal with { video_id, youtube_video_id, channel_id }; nothing sent",
    r.status === 201 && !!dp && dp.status === "pending" && dp.action_type === "delete_youtube_video" && J(dp.payload) === J({ video_id: up.id, youtube_video_id: YT_ID, channel_id: CHANNEL }) &&
    m.google.requests.length === 0, J([r.status, r.body.code]));
  r = await hit(m, "post /api/youtube/videos/:id/propose-delete", { params: { id: up.id } });
  check("R2. one pending removal per video", r.status === 409 && r.body.code === "pending");
  a = await attempt(m.ctx.executeDeleteYoutubeVideo(dp));
  const del = m.google.of(function (x) { return x.method === "DELETE"; })[0];
  // NAMED (Nov 7 2026, TikTok posting): BEFORE "then status removed"; AFTER status describes the file, so removing from YouTube clears youtube_video_id.
  check("R3. approved: videos.delete on that id (50 units reserved first), then youtube_video_id cleared", a.ok && a.v.removed === true && !!del && del.search === "?id=" + YT_ID &&
    rowOf(m, up.id).youtube_video_id === null && rowOf(m, up.id).status === "uploaded" && m.db.t.youtube_api_calls.some(function (x) { return x.units === 50; }), a.ok ? "" : a.msg);
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  const up2 = seedVideo(m.db, mp4("isom", 3000), { status: "uploaded", youtube_video_id: YT_ID, path: null, uploaded_at: new Date().toISOString() });
  r = await hit(m, "get /api/youtube/videos/:id/status", { params: { id: up2.id } });
  const lst = m.google.of(function (x) { return x.method === "GET" && x.path === "/youtube/v3/videos"; })[0];
  check("R4. Check status: videos.list part=status,processingDetails for that id, 1 unit; the words YouTube answers; the link",
    r.status === 200 && r.body.found === true && r.body.upload_status === "processed" && r.body.privacy_status === "private" && r.body.processing_status === "succeeded" &&
    r.body.url === "https://www.youtube.com/watch?v=" + YT_ID && !!lst && lst.search === "?part=status,processingDetails&id=" + YT_ID &&
    m.db.t.youtube_api_calls.length === 1 && m.db.t.youtube_api_calls[0].units === 1, J([r.status, lst && lst.search]));
  const ready = seedVideo(m.db, mp4("isom", 3000, 77));
  r = await hit(m, "get /api/youtube/videos/:id/status", { params: { id: ready.id } });
  check("R5. a video not on YouTube has no status to check (409), nothing asked", r.status === 409 && r.body.code === "not_uploaded" && m.google.requests.length === 1);
  check("R6. YQ units: videos.insert 100, videos.delete 50, videos.list 1, channels.list 1, uploads.status 1; member calls are social_search",
    YQ.YOUTUBE_API_UNITS["videos.insert"] === 100 && YQ.YOUTUBE_API_UNITS["videos.delete"] === 50 && YQ.YOUTUBE_API_UNITS["videos.list"] === 1 &&
    YQ.YOUTUBE_API_UNITS["channels.list"] === 1 && YQ.YOUTUBE_API_UNITS["uploads.status"] === 1 && YQ.YOUTUBE_MEMBER_CALLER === "social_search");

  /* ── S ── */
  OUT("\n══ S. the stream mode ══");
  g = makeGoogle({});
  const sNone = await attempt(g.streamUpload("https://evil.example.com/upload/x", { profile: "youtube", method: "PUT", body: null, contentLength: 0 }));
  const sPath = await attempt(g.streamUpload("https://www.googleapis.com/youtube/v3/videos", { profile: "youtube", method: "PUT", body: null, contentLength: 0 }));
  const sHttp = await attempt(g.streamUpload("http://www.googleapis.com/upload/x", { profile: "youtube", method: "PUT", body: null, contentLength: 0 }));
  const sPort = await attempt(g.streamUpload("https://www.googleapis.com:8443/upload/x", { profile: "youtube", method: "PUT", body: null, contentLength: 0 }));
  check("S1. only https://www.googleapis.com on 443 with a path under /upload/: another host, path, scheme or port is invalid_url, with no request",
    [sNone, sPath, sHttp, sPort].every(function (x) { return !x.ok && x.code === "invalid_url" && noSecretIn(x.msg) && String(x.msg).indexOf("evil") === -1; }) && g.requests.length === 0,
    J([sNone.code, sPath.code, sHttp.code, sPort.code]));
  const sPost = await attempt(g.streamUpload("https://www.googleapis.com/upload/x", { profile: "youtube", method: "POST", body: null, contentLength: 0 }));
  check("S2. PUT only", !sPost.ok && /method must be PUT/.test(sPost.msg || ""));
  const sRedir = await attempt(g.streamUpload("https://www.googleapis.com/upload/redirect", { profile: "youtube", method: "PUT", body: null, contentLength: 0 }));
  check("S3. a 302 is not followed: rejected as redirected, one request", !sRedir.ok && sRedir.code === "redirected" && g.requests.length === 1, sRedir.ok ? J(sRedir.v) : sRedir.code);
  g = makeGoogle({});
  const sHuge = await attempt(g.streamUpload("https://www.googleapis.com/upload/huge", { profile: "youtube", method: "PUT", body: null, contentLength: 0 }));
  check("S4. a JSON answer over 1 MB is too_large", !sHuge.ok && sHuge.code === "too_large", sHuge.code);
  const t0 = Date.now();
  const sIdle = await attempt(g.streamUpload("https://www.googleapis.com/upload/silent", { profile: "youtube", method: "PUT", body: null, contentLength: 0, idleTimeoutMs: 1000 }));
  check("S5. nothing answered for the idle time: timeout", !sIdle.ok && sIdle.code === "timeout" && Date.now() - t0 < 5000, sIdle.code);
  check("S6. the limits: 60 s idle, 20 minutes total, 50 MB up, 1 MB of answer; Range and Location exposed",
    GF.STREAM_IDLE_TIMEOUT_MS === 60000 && GF.STREAM_TOTAL_TIMEOUT_MS === 1200000 && GF.STREAM_MAX_UPLOAD_BYTES === 52428800 && GF.STREAM_HOST === "www.googleapis.com" &&
    GF.STREAM_PATH_PREFIX === "/upload/" && FILES.fetch.indexOf("const STREAM_ANSWER_HEADERS = [\"range\", \"location\"];") !== -1 && FILES.fetch.indexOf("const STREAM_MAX_BODY_BYTES = 1024 * 1024;") !== -1);
  const sLong = await attempt(g.streamUpload("https://www.googleapis.com/upload/x", { profile: "youtube", method: "PUT", body: null, contentLength: 0, idleTimeoutMs: 61000 }));
  const sMax = await attempt(g.streamUpload("https://www.googleapis.com/upload/x", { profile: "youtube", method: "PUT", body: null, contentLength: 52428801 }));
  check("S7. an idle time over 60 s, or more than 50 MB, is refused before any request", !sLong.ok && !sMax.ok && g.requests.length === 2);
  // NAMED (Nov 7 2026, TikTok posting): the stream mode serves named provider profiles, and the caller must name one.
  // Every call above names "youtube"; with none, or an unknown one, nothing is sent.
  const sNoProfile = await attempt(g.streamUpload("https://www.googleapis.com/upload/x", { method: "PUT", body: null, contentLength: 0 }));
  const sBadProfile = await attempt(g.streamUpload("https://www.googleapis.com/upload/x", { profile: "vimeo", method: "PUT", body: null, contentLength: 0 }));
  check("S8. no profile, or one not named, is refused before any request", !sNoProfile.ok && !sBadProfile.ok && /profile must be one of/.test(sNoProfile.msg || "") && g.requests.length === 2);
  check("S9. the youtube profile is www.googleapis.com under /upload/, 308 allowed, no empty-body statuses",
    J(GF.STREAM_PROFILES.youtube) === J({ host: "www.googleapis.com", pathPrefix: "/upload/", allow308: true, emptyOkStatuses: [] }));

  /* ── J ── */
  OUT("\n══ J. retention ══");
  db = makeDb();
  const now = Date.now();
  const iso = function (ms) { return new Date(ms).toISOString(); };
  const staleV = seedVideo(db, mp4("isom", 100, 1), { created_at: iso(now - 15 * 86400000) });
  const freshV = seedVideo(db, mp4("isom", 100, 2), { created_at: iso(now - 13 * 86400000) });
  const leftV = seedVideo(db, mp4("isom", 100, 3), { status: "uploaded", youtube_video_id: YT_ID, uploaded_at: iso(now - 3600000) });
  const orphanOld = videoPath(USER), orphanNew = videoPath(USER), orphanOther = videoPath(OTHER);
  db.storage.objects[orphanOld] = { buf: Buffer.from("x"), created_at: iso(now - 2 * 86400000) };
  db.storage.objects[orphanNew] = { buf: Buffer.from("x"), created_at: iso(now - 3600000) };
  db.storage.objects[orphanOther] = { buf: Buffer.from("x"), created_at: iso(now - 3 * 86400000) };
  CURRENT = makeGoogle({});
  let tick = await MV.retentionTick({ supabase: db, storage: db.storage, now: function () { return now; } }, now);
  check("J1. a ready video 15 days old: its file deleted and the row removed (path null); one 13 days old kept",
    !db.storage.objects[staleV.path] && db.t.member_videos.filter(function (x) { return x.id === staleV.id; })[0].status === "removed" &&
    db.t.member_videos.filter(function (x) { return x.id === staleV.id; })[0].path === null && !!db.storage.objects[freshV.path] && tick.expired === 1, J(tick));
  check("J2. an uploaded video's leftover file: deleted, path null", !db.storage.objects[leftV.path] && db.t.member_videos.filter(function (x) { return x.id === leftV.id; })[0].path === null && tick.leftovers === 1);
  // NAMED (Nov 7 2026, TikTok posting, migration 178): a ready video YouTube has AND TikTok posted goes at once, unless a pending proposal names it.
  const dbB = makeDb();
  const bothV = seedVideo(dbB, mp4("isom", 100, 4), { youtube_video_id: YT_ID, uploaded_at: iso(now - 3600000), tiktok_status: "posted", tiktok_posted_at: iso(now - 600000) });
  const ytOnly = seedVideo(dbB, mp4("isom", 100, 5), { youtube_video_id: YT_ID, uploaded_at: iso(now - 3600000) });
  const heldV = seedVideo(dbB, mp4("isom", 100, 6), { youtube_video_id: YT_ID, uploaded_at: iso(now - 3600000), tiktok_status: "posted", tiktok_posted_at: iso(now - 600000) });
  dbB.t.agent_proposals.push({ id: uuid(), user_id: USER, action_type: "delete_youtube_video", status: "pending", payload: { video_id: heldV.id, youtube_video_id: YT_ID, channel_id: CHANNEL } });
  // NAMED, item 8 part 3a (Instagram posting): the early delete now also needs a published Instagram reel; all three have one, so YouTube and TikTok are what differ.
  [bothV, ytOnly, heldV].forEach(function (v) { dbB.t.instagram_posts.push({ id: uuid(), user_id: USER, kind: "reel", status: "published", video_id: v.id, created_at: iso(now - 600000) }); });
  // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): and a published Facebook video post; YouTube and TikTok are still what differ.
  [bothV, ytOnly, heldV].forEach(function (v) { dbB.t.facebook_posts.push({ id: uuid(), user_id: USER, kind: "video", status: "published", post_id: "1200000000000008", video_id: v.id, created_at: iso(now - 600000) }); });
  const tickBoth = await MV.retentionTick({ supabase: dbB, storage: dbB.storage, now: function () { return now; } }, now);
  const rowIn = function (id) { return dbB.t.member_videos.filter(function (x) { return x.id === id; })[0]; };
  check("J8. YouTube AND TikTok (and Instagram and Facebook, NAMED item 8 parts 3a and 3b) have it: the file deleted at once, status uploaded; YouTube alone, or named by a pending proposal: kept",
    !dbB.storage.objects[bothV.path] && rowIn(bothV.id).status === "uploaded" && rowIn(bothV.id).path === null &&
    !!dbB.storage.objects[ytOnly.path] && rowIn(ytOnly.id).status === "ready" && !!dbB.storage.objects[heldV.path] && rowIn(heldV.id).status === "ready" && tickBoth.both === 1, J(tickBoth));
  check("J3. a file with no row: deleted after a day (both members' folders); one an hour old kept",
    !db.storage.objects[orphanOld] && !db.storage.objects[orphanOther] && !!db.storage.objects[orphanNew] && tick.orphans === 2, J(tick));
  const jr = db.t.job_runs.filter(function (x) { return x.job_name === "member_videos_retention"; });
  tick = await MV.retentionTick({ supabase: db, storage: db.storage, now: function () { return now; } }, now);
  check("J4. claimed through its own job_runs row, member_videos_retention, once a day; finished_at recorded", jr.length === 1 && !!jr[0].finished_at && tick.claimed === false);
  // the 04:45 chain
  const order = [];
  const scheduled = [];
  const cronMod = { main: null };
  cronMod.main = cronMod;
  const cctx = {
    require: Object.assign(function (r) {
      if (r === "./lib/microsoftAuth") return { oauthStatesPurgeTick: async function () { order.push("states"); } };
      if (r === "./lib/shopifyAuth") return { webhookEventsPurgeTick: async function () { order.push("shopify"); } };
      throw new Error("unexpected require " + r);
    }, { main: cronMod }),
    module: cronMod,
    cron: { schedule: function (spec, fn, o) { scheduled.push({ spec: spec, fn: fn, tz: o && o.timezone }); } },
    cardLeads: { cardLeadsPurgeTick: async function () { order.push("leads"); }, PURGE_JOB_NAME: "card_leads_purge" },
    // NAMED, item 8 part 3a (Instagram posting): instagramRefreshTick now follows videoRetentionTick in the chain.
    supabase: {}, videoRetentionTick: async function () { order.push("videos"); }, instagramRefreshTick: async function () { order.push("instagram"); },
    // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): facebookChoosingPurgeTick follows instagramRefreshTick.
    facebookChoosingPurgeTick: async function () { order.push("facebook"); }, console: console
  };
  vm.createContext(cctx);
  let cronOk = true;
  try { vm.runInContext(CRON_SECTION + "\n  }\n", cctx, { filename: "server.js (04:45 chain)" }); } catch (e) { cronOk = false; }
  if (scheduled[0]) { scheduled[0].fn(); await flush(); }
  check("J5. the 04:45 UTC chain runs videoRetentionTick after the Shopify purge, then instagramRefreshTick, then facebookChoosingPurgeTick (NAMED, item 8 parts 3a and 3b)", cronOk && scheduled.length === 1 && scheduled[0].spec === "45 4 * * *" &&
    scheduled[0].tz === "UTC" && J(order) === J(["leads", "states", "shopify", "videos", "instagram", "facebook"]), J(order));
  m = mountRoutes({ env: CONFIGURED });
  const vr = await attempt(m.ctx.videoRetentionTick());
  check("J6. videoRetentionTick runs lib/memberVideos.js retentionTick on youtubeDeps() (its job_runs row claimed)", vr.ok && vr.v && vr.v.claimed === true &&
    m.db.t.job_runs.filter(function (x) { return x.job_name === "member_videos_retention"; }).length === 1, vr.ok ? J(vr.v) : vr.msg);
  m = mountRoutes({ env: CONFIGURED });
  m.ctx.require = function (x) { if (x === "./lib/memberVideos") return { retentionTick: function () { return Promise.reject(Object.assign(new Error("boom"), { code: "boom" })); } }; return realRequire(x); };
  const vr2 = await attempt(m.ctx.videoRetentionTick());
  check("J7. ...and never rejects: a failing pass is logged by its code and answered null", vr2.ok && vr2.v === null && LOGS.some(function (l) { return l === "[VideoRetention] Scheduled run error: boom"; }));

  /* ── P ── */
  OUT("\n══ P. the pages ══");
  check("P1. the Social page: the three lines word for word, the panel, and the script after mastodon-connect.js",
    FILES.page.indexOf("<p class=\"bsky-quiet\">Videos up to 50 MB (MP4, WebM or MOV).</p>") !== -1 &&
    // NAMED (Nov 7 2026, TikTok posting): BEFORE "as soon as YouTube has it, or after 14 days if it's never uploaded"; AFTER every platform.
    FILES.page.indexOf("<p class=\"bsky-quiet\">BizForce deletes the file once every platform you sent it to has it, or 14 days after you added it.</p>") !== -1 &&
    FILES.page.indexOf("<p class=\"bsky-quiet\">Until Google approves BizForce, YouTube keeps uploads from BizForce private.</p>") !== -1 &&
    FILES.page.indexOf("id=\"ytConnect\"") !== -1 && FILES.page.indexOf("<script src=\"/scripts/youtube.js\"></script>") > FILES.page.indexOf("mastodon-connect.js"));
  check("P2. the same three lines are the server's own (lib/memberVideos.js MESSAGES)", MV.MESSAGES.limits === "Videos up to 50 MB (MP4, WebM or MOV)." &&
    MV.MESSAGES.kept === "BizForce deletes the file once every platform you sent it to has it, or 14 days after you added it." &&
    MV.MESSAGES.privateUntilVerified === "Until Google approves BizForce, YouTube keeps uploads from BizForce private.");
  let dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers());
  await flush();
  const finCall = dom.fetches.filter(function (x) { return x.path === "/api/youtube/finish"; })[0];
  const finIdx = dom.events.indexOf("fetch:POST /api/youtube/finish"), rsIdx = dom.events.indexOf("replaceState:" + PAGE_PATH);
  check("P3. back from Google: the code and state POSTed to finish, then the query stripped with replaceState", !!finCall && J(finCall.body) === J({ code: CODE, state: "S".repeat(43) }) &&
    finIdx !== -1 && rsIdx > finIdx, dom.events.join(","));
  check("P3b. ...and the marker is cleared once handled", dom.session.bf_oauth_return === undefined);
  dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers(), null);
  await flush();
  check("P3c. a return with no marker: stripped with replaceState, \"Start the connection again.\", no finish",
    dom.events.indexOf("replaceState:" + PAGE_PATH) !== -1 && dom.get("ytConnectMsg").textContent === "Start the connection again." &&
    !dom.fetches.some(function (x) { return /\/finish$/.test(x.path); }));
  dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers(), "tiktok");
  await flush();
  // NAMED, item 8 part 3a: the shared sign-in return (oauth-return.js) now reads and clears the marker once and holds the answer for TikTok;
  // BEFORE "... and leaves the marker" (each script read the marker itself).
  check("P3d. TikTok's return (marker tiktok): this script neither finishes nor strips it, and does not say start again (the answer is held for TikTok)",
    !dom.fetches.some(function (x) { return x.path === "/api/youtube/finish"; }) && dom.events.indexOf("replaceState:" + PAGE_PATH) === -1 &&
    dom.get("ytConnectMsg").textContent !== "Start the connection again.");
  dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers({ "POST /api/youtube/finish": { status: 400, body: { error: "That sign-in link has expired or was already used. Start again." } } }));
  await flush();
  check("P4. ...stripped whatever the answer: a refused finish strips it too, and shows the server's words",
    dom.events.indexOf("replaceState:" + PAGE_PATH) !== -1 && dom.get("ytConnectMsg").textContent === "That sign-in link has expired or was already used. Start again.");
  dom = runPage("?code=" + encodeURIComponent(CODE) + "&state=" + "S".repeat(43), pageAnswers({ "POST /api/youtube/finish": "reject" }));
  await flush();
  check("P5. ...and a finish that never answers strips it too", dom.events.indexOf("replaceState:" + PAGE_PATH) !== -1);
  dom = runPage("?error=access_denied&state=" + "S".repeat(43), pageAnswers());
  await flush();
  check("P6. ?error=access_denied: stripped, \"You cancelled the Google sign-in.\", no finish", dom.events.indexOf("replaceState:" + PAGE_PATH) !== -1 &&
    dom.get("ytConnectMsg").textContent === "You cancelled the Google sign-in." && !dom.fetches.some(function (x) { return x.path === "/api/youtube/finish"; }));
  dom = runPage("", pageAnswers({ "GET /api/youtube/status": { status: 200, body: { youtube_available: true, connected: false, status: "not_connected" } } }));
  await flush();
  dom.get("ytConnectBtn").click();
  await flush();
  check("P7. Connect YouTube goes to the address start answers, on accounts.google.com", dom.assigned.length === 1 && dom.assigned[0].indexOf("https://accounts.google.com/") === 0);
  check("P7b. ...having set the return marker to youtube first", dom.session.bf_oauth_return === "youtube");
  dom = runPage("", pageAnswers({ "GET /api/youtube/status": { status: 200, body: { youtube_available: true, connected: false, status: "not_connected" } },
    "POST /api/youtube/start": { status: 200, body: { authorize_url: "https://accounts.google.com.evil.example/x" } } }));
  await flush();
  dom.get("ytConnectBtn").click();
  await flush();
  check("P8. ...and never to any other host", dom.assigned.length === 0);
  dom = runPage("", pageAnswers({ "GET /api/youtube/status": { status: 200, body: { youtube_available: false, connected: false, status: "not_connected" } } }));
  await flush();
  check("P9. unconfigured: the not-set-up line shows and Connect is disabled", dom.get("ytUnavailable").hidden === false && dom.get("ytConnectBtn").disabled === true);
  // the upload flow
  dom = runPage("", pageAnswers());
  await flush();
  dom.get("ytLabel").value = "Spring cakes";
  dom.get("ytFile").files = [{ name: "cakes.mp4", type: "video/mp4", size: 3 * 1048576 }];
  dom.get("ytFile").fire("change");
  await flush();
  const upCall = dom.fetches.filter(function (x) { return x.path === "/api/videos/upload-url"; })[0];
  const finz = dom.fetches.filter(function (x) { return x.path === "/api/videos/finalize"; })[0];
  check("P10. adding a video: upload-url { mime, bytes, label }, a PUT straight to the signed URL, then finalize { path, label, bytes }",
    !!upCall && J(upCall.body) === J({ mime: "video/mp4", bytes: 3 * 1048576, label: "Spring cakes" }) && dom.xhr.length === 1 && dom.xhr[0].method === "PUT" &&
    dom.xhr[0].url.indexOf("https://check.supabase.co/") === 0 && dom.xhr[0].headers["Content-Type"] === "video/mp4" && !!finz &&
    J(finz.body) === J({ path: "video/" + USER + "/" + "a".repeat(32) + ".mp4", label: "Spring cakes", bytes: 3 * 1048576 }), J(dom.fetches.map(function (x) { return x.path; })));
  const before = dom.fetches.length;
  dom.get("ytFile").files = [{ name: "big.mp4", type: "video/mp4", size: 52428801 }];
  dom.get("ytFile").fire("change");
  dom.get("ytFile").files = [{ name: "photo.heic", type: "image/heic", size: 1000 }];
  dom.get("ytFile").fire("change");
  await flush();
  check("P11. over 50 MB, or not MP4, WebM or MOV: refused on the page, nothing sent", dom.fetches.length === before && dom.xhr.length === 1);
  const list = dom.get("ytVideoList");
  /* NAMED (Nov 12 2026, Social page clean-up): BEFORE the form was built hidden under every ready row ("Prepare upload"), and
     "Made for kids?" was a fieldset LEGEND. AFTER it opens under the row on "Prepare for YouTube" (YouTube connected), and
     "Made for kids?" labels a role="radiogroup" of the same two required radios (checkSocialVideoPanel holds its keys). */
  const ytPrep = findAll(list, function (n) { return n.tagName === "BUTTON" && n.textContent === "Prepare for YouTube"; });
  if (ytPrep[0]) ytPrep[0].click();
  const selects = findAll(list, function (n) { return n.tagName === "SELECT"; });
  const radios = findAll(list, function (n) { return n.tagName === "INPUT" && n.type === "radio"; });
  const kidsGroup = findAll(list, function (n) { return n.attrs && n.attrs.role === "radiogroup"; });
  const kidsLabel = kidsGroup[0] ? findAll(list, function (n) { return n.id === kidsGroup[0].attrs["aria-labelledby"]; })[0] : null;
  check("P12. the prepare form: privacy Private first and selected; \"Made for kids?\" two required radios, neither checked",
    ytPrep.length === 1 && selects.length === 1 && selects[0].children[0].value === "private" && selects[0].children[0].selected === true && selects[0].value === "private" &&
    radios.length === 2 && radios.every(function (x) { return x.required === true && x.checked === false; }) && kidsGroup.length === 1 &&
    findAll(kidsGroup[0], function (n) { return n.tagName === "INPUT" && n.type === "radio"; }).length === 2 && !!kidsLabel && kidsLabel.textContent === "Made for kids?");
  const fileBtn = findAll(list, function (n) { return n.tagName === "BUTTON" && n.textContent === "File for approval"; })[0];
  const n0 = dom.fetches.length;
  fileBtn.click();
  await flush();
  check("P13. filing without answering \"Made for kids?\" is stopped on the page", dom.fetches.length === n0);
  radios[1].checked = true;
  findAll(list, function (n) { return n.tagName === "INPUT" && n.type === "text"; })[0].value = "Spring cakes";
  fileBtn.click();
  await flush();
  const pu = dom.fetches.filter(function (x) { return x.path === "/api/youtube/propose-upload"; })[0];
  check("P14. ...answered No: propose-upload with made_for_kids false and privacy private", !!pu && pu.body.made_for_kids === false && pu.body.privacy === "private" && pu.body.video_id === PAGE_VIDEO.id);
  const links = findAll(list, function (n) { return n.tagName === "A"; });
  check("P15. an uploaded video shows its youtube.com link, Check status and Remove from YouTube",
    links.length === 1 && links[0].href === "https://www.youtube.com/watch?v=" + YT_ID && links[0].rel === "noopener" &&
    findAll(list, function (n) { return n.tagName === "BUTTON" && (n.textContent === "Check status" || n.textContent === "Remove from YouTube"); }).length === 2);
  dom = runPage("", pageAnswers({ "GET /api/videos": { status: 200, body: { videos: [Object.assign({}, PAGE_UPLOADED, { youtube_url: "https://evil.example/watch?v=" + YT_ID, label: "<img src=x onerror=alert(1)>" })] } } }));
  await flush();
  check("P16. a link that is not a youtube.com watch address is not drawn; a label is text", findAll(dom.get("ytVideoList"), function (n) { return n.tagName === "A"; }).length === 0 &&
    dom.get("ytVideoList").textContent.indexOf("<img src=x onerror=alert(1)>") !== -1);
  check("P17. no innerHTML anywhere: nothing set with it in any of these runs, and the script never names it", dom.innerHTML.length === 0 && !/innerHTML/.test(stripComments(FILES.ui)));
  check("P18. the proposal cards: both types drawn from escaped fields, only a youtube.com watch address as a link",
    /function youtubeUploadPayloadFields\(payload\)/.test(FILES.proposals) && /function youtubeDeletePayloadFields\(payload\)/.test(FILES.proposals) &&
    /function youtubeResultHtml\(result\)/.test(FILES.proposals) && FILES.proposals.indexOf("fieldsHtml = youtubeUploadPayloadFields(p.payload || {});") !== -1 &&
    FILES.proposals.indexOf("fieldsHtml = youtubeDeletePayloadFields(p.payload || {});") !== -1 &&
    FILES.proposals.indexOf("<span class=\"pf-value yt-title\">' + escapeHtml(String(payload.title == null ? \"\" : payload.title))") !== -1);

  /* ── G ── */
  OUT("\n══ G. legal and registries ══");
  const PRIVACY = "If you connect your YouTube channel, BizForce stores your channel's name and id and the access Google grants BizForce, encrypted, and uses " +
    "that access only to upload or remove a video when you approve it and to check a video's status when you ask. Videos you add for YouTube " +
    // NAMED (Nov 7 2026, TikTok posting): BEFORE "deleted as soon as YouTube has them or after 14 days if they are never uploaded";
    // AFTER, word for word as the owner decided, "deleted once every platform you sent them to has them, or 14 days after you added them".
    "are kept privately, sent only to YouTube with the title, description and tags you approve, and deleted once every platform you sent " +
    "them to has them, or 14 days after you added them. You can disconnect at any time, which also asks Google to cancel BizForce's access, and " +
    "everything is deleted with your account.";
  const TERMS = "If you upload videos through BizForce, you confirm you have the rights to them and that they follow YouTube's rules.";
  const esc = function (t) { return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); };
  let built = null;
  try { built = LP.buildLegalPages(); } catch (e) { built = null; }
  const bp = built ? built["privacy.html"] : "", bt = built ? built["terms.html"] : "";
  check("G1. the privacy sentence word for word, once, right after the social images sentence and before the mailbox one",
    LP.YOUTUBE_PRIVACY_SENTENCE === PRIVACY && bp.split(esc(PRIVACY)).length === 2 && bp.indexOf(esc(LP.SOCIAL_MEDIA_PRIVACY_SENTENCE)) < bp.indexOf(esc(PRIVACY)) &&
    bp.indexOf(esc(PRIVACY)) < bp.indexOf(esc(LP.MAILBOX_PRIVACY_SENTENCE)));
  check("G2. the terms sentence word for word, once, right after the mailbox reply one", LP.YOUTUBE_TERMS_SENTENCE === TERMS && bt.split(esc(TERMS)).length === 2 &&
    bt.indexOf(esc(LP.MAILBOX_REPLY_TERMS_SENTENCE)) < bt.indexOf(esc(TERMS)));
  check("G3. privacy.html and terms.html carry them, as built", FILES.privacy.split(esc(PRIVACY)).length === 2 && FILES.terms.split(esc(TERMS)).length === 2);
  const LEGAL = realRequire("./lib/legal");
  // NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE Nov 7 2026, this change's date. AFTER Nov 8 2026, the version
  // the Etsy privacy sentence set (this change still set Nov 7).
  check("G4. TERMS_VERSION is the latest change's, Nov 8 2026 (Etsy; this change set Nov 7)", LEGAL.TERMS_VERSION === "2026-11-08", LEGAL.TERMS_VERSION);
  const GR = realRequire("./lib/gateRules");
  check("G5. gateRules: both actions known, channel youtube", GR.ACTION_TYPES.indexOf("publish_youtube_video") !== -1 && GR.ACTION_TYPES.indexOf("delete_youtube_video") !== -1 &&
    GR.CHANNELS.indexOf("youtube") !== -1 && GR.channelFor("publish_youtube_video") === "youtube" && GR.channelFor("delete_youtube_video") === "youtube");
  check("G6. yourData: the connection and the videos exported without tokens, paths, fingerprints or sessions; deleted with the account; YouTube a third party",
    // NAMED (Nov 7 2026, TikTok posting, migration 178): the videos' export adds TikTok's status, time and post id (never the
    // upload address); the sign-in states line names Connect TikTok last; the TikTok connection is deleted between the two.
    FILES.yourData.indexOf("select: \"id, label, bytes, status, youtube_video_id, uploaded_at, tiktok_status, tiktok_posted_at, tiktok_post_id, created_at\"") !== -1 &&
    // NAMED (Nov 7 2026, Instagram posting, migration 179): the sign-in states line names Connect Instagram last, and the
    // Instagram connection is deleted between the TikTok one and the sign-in states.
    // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): Connect Facebook is named last, and member_facebook_pages is deleted after the Instagram connection.
    // NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE "..., Connect Instagram and Connect Facebook". AFTER Connect Etsy is named last.
    // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE "..., Connect Facebook and Connect Etsy". AFTER Connect Amazon is named last.
    FILES.yourData.indexOf("Temporary sign-in states for Sign in with Microsoft, Connect Shopify, Connect YouTube, Connect TikTok, Connect Instagram, Connect Facebook, Connect Etsy and Connect Amazon") !== -1 &&
    FILES.yourData.indexOf("{ name: \"YouTube (Google)\", for: \"uploading the videos you approve to your own channel, when you connect it\" }") !== -1 &&
    FILES.yourData.indexOf("\"member_media\", \"member_videos\",") !== -1 && FILES.yourData.indexOf("\"member_youtube_connections\", \"member_tiktok_connections\", \"member_instagram_connections\", \"member_facebook_pages\", \"oauth_states\"") !== -1);
  check("G7. schemaCheck knows both tables at migration 177; backup leaves both out; accountFiles lists bf-video",
    FILES.schema.split("177_youtube_uploads.sql").length - 1 >= 2 && /member_videos/.test(FILES.backup) && /member_youtube_connections/.test(FILES.backup) &&
    FILES.accountFiles.indexOf("const BUCKETS = [PUBLIC, BOOKS, GOODS, MUSIC, VIDEO];") !== -1 && FILES.accountFiles.indexOf("const VIDEO = \"bf-video\";") !== -1);
  check("G8. README: the two env vars and the YouTube app setup", FILES.readme.indexOf("GOOGLE_OAUTH_CLIENT_ID") !== -1 && FILES.readme.indexOf("GOOGLE_OAUTH_CLIENT_SECRET") !== -1 &&
    FILES.readme.indexOf("## YouTube app setup") !== -1);
  check("G9. no other new env var: the YouTube files read only GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET (and the existing YouTube caps)",
    (stripComments(FILES.auth + FILES.api + FILES.videos).match(/env\.[A-Z_]+/g) || []).every(function (e) { return ["env.GOOGLE_OAUTH_CLIENT_ID", "env.GOOGLE_OAUTH_CLIENT_SECRET"].indexOf(e) !== -1; }) &&
    (stripComments(YT_SECTION).match(/process\.env\.[A-Z_]+/g) || []).length === 0);
  check("G10. migration 177: bf-video private at 52428800 with MP4, WebM and MOV; both tables with RLS on and nothing granted; youtube_google in the purpose check",
    FILES.migration.indexOf("VALUES ('bf-video', 'bf-video', false, 52428800, ARRAY['video/mp4', 'video/webm', 'video/quicktime'])") !== -1 &&
    FILES.migration.indexOf("ALTER TABLE public.member_youtube_connections ENABLE ROW LEVEL SECURITY;") !== -1 &&
    FILES.migration.indexOf("ALTER TABLE public.member_videos ENABLE ROW LEVEL SECURITY;") !== -1 &&
    FILES.migration.indexOf("REVOKE ALL ON public.member_videos FROM anon, authenticated;") !== -1 &&
    FILES.migration.indexOf("REVOKE ALL ON public.member_youtube_connections FROM anon, authenticated;") !== -1 &&
    FILES.migration.indexOf("CHECK (purpose IN ('mailbox_microsoft', 'store_shopify', 'youtube_google'))") !== -1 &&
    FILES.migration.indexOf("CHECK (status IN ('ready', 'uploaded', 'removed'))") !== -1);
  check("G11. MV.PATH_RE is migration 177's path pattern, and every path it makes matches", MV.PATH_RE.source === "^video\\/[0-9a-f-]{36}\\/[0-9a-f]{32}\\.(mp4|webm|mov)$" &&
    MV.PATH_RE.test(MV.newPath(USER, "webm")) && !MV.PATH_RE.test("video/" + USER + "/x.mp4"));
  const migFiles = fs.readdirSync(path.join(REPO, "supabase", "migrations")).filter(function (x) { return /^\d{3}_.*\.sql$/.test(x); });
  const highest = migFiles.map(function (x) { return Number(x.slice(0, 3)); }).reduce(function (acc, x) { return Math.max(acc, x); }, 0);
  // NAMED (Nov 7 2026, TikTok posting, migration 178): BEFORE 177 was the highest. AFTER it is the only 177, and only
  // 178_tiktok_posting.sql is above it; "the highest" is checkTiktokPosting R1's.
  // NAMED (Nov 7 2026, Instagram posting, migration 179): BEFORE only 178 was above 177. AFTER 178_tiktok_posting.sql and
  // 179_instagram_posting.sql are, by name; "the highest" is checkInstagramPosting R1's.
  // NAMED (Nov 7 2026, Facebook Pages posting, migration 180): AFTER 180_facebook_pages.sql is above it too, by name;
  // "the highest" is checkFacebookPages R1's.
  // NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE 180 was the highest. AFTER 181_etsy_store.sql is above it too,
  // by name; "the highest" is checkEtsyConnect R1's.
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE 181 the highest. AFTER 182_amazon_store.sql is above it
  // too, by name; "the highest" is checkAmazonConnect R1's.
  // NAMED (Nov 11 2026, orbit stage 2), migration 183): it adds 183_weekly_goal_and_order_status.sql above, by name; "the highest" is checkOrbitStage2 R1's.
  check("G12. R1. 177_youtube_uploads.sql is the only 177, and only 178_tiktok_posting.sql, 179_instagram_posting.sql, 180_facebook_pages.sql, 181_etsy_store.sql, 182_amazon_store.sql and 183_weekly_goal_and_order_status.sql are above it (checkOrbitStage2 R1)", highest === 183 &&
    migFiles.filter(function (x) { return /^177_/.test(x); }).join() === "177_youtube_uploads.sql" &&
    migFiles.filter(function (x) { return Number(x.slice(0, 3)) > 177; }).join() === "178_tiktok_posting.sql,179_instagram_posting.sql,180_facebook_pages.sql,181_etsy_store.sql,182_amazon_store.sql,183_weekly_goal_and_order_status.sql", highest);
  const fresh = { "lib/googleAuth.js": FILES.auth, "lib/youtubeApi.js": FILES.api, "lib/memberVideos.js": FILES.videos, "177_youtube_uploads.sql": FILES.migration,
    "scripts/youtube.js": FILES.ui, "agents/social.html": FILES.page, "scripts/checkYoutubeUploads.js": fs.readFileSync(__filename, "utf8") };
  check("G13. no emoji in any new or edited YouTube file", Object.keys(fresh).every(function (k) { return !EMOJI.test(fresh[k]); }),
    Object.keys(fresh).filter(function (k) { return EMOJI.test(fresh[k]); }).join(", "));

  check("nothing logged in this whole run holds a token, a code, a client secret, a signed URL token or a session URI", LOGS.every(noSecretIn), LOGS.filter(function (l) { return !noSecretIn(l); }).length);
  check("nothing reached the network: no socket, no real DNS question and no fetch in this whole run (the tripwire)", TRIPPED.length === 0, TRIPPED.join(", "));
  check("no unhandled rejection", UNHANDLED.length === 0, UNHANDLED.map(String).join("; "));
  OUT("");
  if (failures) { OUT("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  OUT("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { OUT("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
