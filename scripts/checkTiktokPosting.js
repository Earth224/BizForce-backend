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
     K. TK1 (Nov 17 2026), TikTok's content-sharing guidelines before app review: the video's length (migration 186) read
        from the file and checked at filing and at approval, the preview, the declaration with TikTok's links directly
        above the publish button, the processing notice and the bounded status polling, the disclosure button, the wording
     X. TK2 (Nov 18 2026): video/init per TikTok's Direct Post reference (the Content-Type, the body, the documented
        upload_url), every documented init error code, one "[tiktok] <step> refused" log line per TikTok refusal with
        nothing secret in it, TikTok's code on the card, fragmented and OBS Hybrid MP4
     G. legal, yourData, README, registries, the migration; R1, the highest migration (186, verify/186_verify.sql).

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
  // NAMED (Nov 18 2026, BV1): chunked FILE_UPLOAD over 64 MB, a parted video's chunks, the transport's TikTok cap.
  "bv-tt-one-chunk-always": ["api",
    "  if (size <= ONE_CHUNK_MAX) return { chunk_size: size, total_chunk_count: 1, ranges: [[0, size]] };",
    "  return { chunk_size: size, total_chunk_count: 1, ranges: [[0, size]] };"],
  "bv-tt-count-ceil": ["api",
    "  var count = Math.floor(size / chunk), ranges = [];",
    "  var count = Math.ceil(size / chunk), ranges = [];"],
  "bv-tt-chunk-too-big": ["api",
    "  var chunk = Math.min(MV.PART_BYTES, Math.floor(size / 2));",
    "  var chunk = Math.floor(size / 2);"],
  "bv-tt-206-not-required": ["api",
    "    if (last ? putComplete(answer) : answer.status === 206) continue;",
    "    continue;"],
  "bv-tt-no-chunk-tail": ["api",
    "\" content_type=\" + typeWord(answer.contentType) + \" chunk=\" + (i + 1) + \"/\" + plan.ranges.length));",
    "\" content_type=\" + typeWord(answer.contentType)));"],
  "bv-tt-parts-as-whole": ["api",
    "  return MV.partCount(video) > 1 ? sendParts(deps, uploadUrl, video) : sendWhole(deps, uploadUrl, video);",
    "  return sendWhole(deps, uploadUrl, video);"],
  "bv-tt-source-one-chunk": ["api",
    "chunk_size: plan.chunk_size, total_chunk_count: plan.total_chunk_count };",
    "chunk_size: Number(video.bytes), total_chunk_count: 1 };"],
  // NAMED (Nov 18 2026, BV2): bv-tt-parts-unverified (verifyFile passing a parted video unread) is gone with verifyFile.
  // The parts are checked while they are sent: mismatch-sends-last-chunk below.
  // NAMED (Nov 18 2026, BV2): ONE storage read per send.
  "double-read-again": ["api",
    "    put = await sendVideo(deps, uploadUrl, video);\n",
    "    await MV.measureStream(MV.partCount(video) > 1 ? MV.openRange(deps.storage, await MV.fileParts(deps.supabase, video), 0, Number(video.bytes)) : await MV.openStream(deps.storage, video.path), MV.MAX_BYTES);\n    put = await sendVideo(deps, uploadUrl, video);\n"],
  "cursor-reopens-every-chunk": ["videos",
    "      if (!cur || !cur.whole || cur.pos !== a) {\n",
    "      if (true) {\n"],
  "mismatch-sends-last-chunk": ["api",
    "      if (err && err.code === \"body_failed\") throw new TiktokApiError(\"fingerprint\", \"body_failed\");\n",
    "      if (err && err.code === \"body_failed\" && i < plan.ranges.length - 1) continue;\n      if (err && err.code === \"body_failed\") throw new TiktokApiError(\"fingerprint\", \"body_failed\");\n"],
  "mismatch-not-failed": ["api",
    "    throw fail(err && err.kind === \"fingerprint\" ? MESSAGES.stopped : MESSAGES.unfinished);\n  }\n  uploadUrl = null;\n",
    "    if (err && err.kind === \"fingerprint\") put = { status: 201 }; else throw fail(MESSAGES.unfinished);\n  }\n  uploadUrl = null;\n"],
  "bv-tt-cap-default": ["fetch",
    "    const lengthCap = profile.maxUploadBytes || STREAM_MAX_UPLOAD_BYTES;",
    "    const lengthCap = STREAM_MAX_UPLOAD_BYTES;"],
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
  // NAMED (Nov 17 2026, TK1): BEFORE consent.textContent = paid ? CONSENT_BRANDED : CONSENT. AFTER the line is built with its links (declaration).
  "consent-line-missing": ["ui",
    "      declaration(consent, paid);", "      declaration(consent, false);"],
  "creator-info-not-rechecked": ["api",
    "  var checked = validatePost(postFields(p), creator, deps.limits);", "  var checked = { ok: true, value: postFields(p) };"],
  // NAMED (Nov 18 2026, BV2): BEFORE it dropped verifyFile, the read before the send. AFTER verifyFile is gone (the send is
  // the one read), so it drops the check the send makes: sendWhole's guard becomes a plain pass-through.
  "sha-unchecked-at-send": ["api",
    "  var guard = YA.fingerprintGuard(video.sha256, total, 0);\n",
    "  var guard = new (require(\"stream\").PassThrough)();\n"],
  "upload-unsealed": ["api",
    "  var s = sealed(deps.crypt, uploadUrl);", "  var s = { ciphertext: Buffer.from(uploadUrl).toString(\"hex\"), iv: \"0\".repeat(24), authTag: \"0\".repeat(32) };"],
  // NAMED (Nov 13 2026, S3): the stored-publish branch now also steps aside for a filed repost of a posted video; the
  // mutation still turns the whole branch off.
  "second-init-while-valid": ["api",
    "  if (video.tiktok_publish_id && !reposting) {\n    // A stored publish: ask TikTok first.", "  if (false) {\n    // A stored publish: ask TikTok first."],
  // NAMED (Nov 21 2026, P3-1): BEFORE the anchor was the old one-chunk source_info, gone since BV1's chunkPlan (MUTATE=all said
  // ERROR). AFTER the same fault in chunkPlan: a video small enough for one chunk is sent as two.
  "multi-chunk-sent": ["api",
    "  if (size <= ONE_CHUNK_MAX) return { chunk_size: size, total_chunk_count: 1, ranges: [[0, size]] };",
    "  if (size <= ONE_CHUNK_MAX) return { chunk_size: Math.ceil(size / 2), total_chunk_count: 2, ranges: [[0, Math.ceil(size / 2)], [Math.ceil(size / 2), size]] };"],
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
  // NAMED (Nov 18 2026, TK2): BEFORE the anchor was tiktok's one exact host. AFTER its host pattern, opened to any host.
  // NAMED (Nov 18 2026, TK3): BEFORE the anchor was the TK2 host regex literal. AFTER the shared TIKTOK_UPLOAD_HOST_RE.
  "tiktok-host-unrestricted": ["fetch",
    "  tiktok: Object.freeze({ hostPattern: TIKTOK_UPLOAD_HOST_RE,", "  tiktok: Object.freeze({ hostPattern: /^/,"],
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
  // NAMED (Nov 18 2026, TK2): BEFORE anchored on "pathPrefix: \"/upload/\", allow308: false,". AFTER on the tiktok profile's own line.
  "tiktok-308-allowed": ["fetch",
    // NAMED (Nov 18 2026, TK5): re-anchored on the statusOnly line.
    // NAMED (Nov 18 2026, BV1): the line now ends with maxUploadBytes too.
    "    allow308: false, statusOnly: true, answerMaxBytes: 64 * 1024, maxUploadBytes: 128 * 1000 * 1000 })", "    allow308: true, statusOnly: true, answerMaxBytes: 64 * 1024, maxUploadBytes: 128 * 1000 * 1000 })"],
  "delete-ignores-tiktok": ["videos",
    // NAMED, item 8 part 3a: FILE_ACTIONS now also names publish_instagram_post.
    // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): and publish_facebook_post after it; the mutation still drops publish_tiktok_post alone.
    "const FILE_ACTIONS = Object.freeze([\"publish_youtube_video\", \"delete_youtube_video\", \"publish_tiktok_post\", \"publish_instagram_post\", \"publish_facebook_post\"]);",
    "const FILE_ACTIONS = Object.freeze([\"publish_youtube_video\", \"delete_youtube_video\", \"publish_instagram_post\", \"publish_facebook_post\"]);"],
  "privacy-defaulted-on-page": ["ui",
    "      opt.value = o;\n      privacy.appendChild(opt);", "      opt.value = o;\n      if (privacy.children.length === 1) { none.selected = false; opt.selected = true; }\n      privacy.appendChild(opt);"],
  "upload-not-whole": ["api",
    "function putComplete(answer) { return !!answer && answer.status === 201; }", "function putComplete(answer) { return !!answer && (answer.status === 201 || answer.status === 206); }"],
  // NAMED, item 8 part 3a: the marker is read once in scripts/oauth-return.js; the mutation now lets the first registered script (YouTube) take TikTok's answer.
  "youtube-marker-ignored": ["oauth",
    "    if (!pending || pending.name !== name) return false;\n", "    if (!pending) return false;\n"],
  // NAMED (Nov 13 2026, S3, "Post again"): the repost flag (section RP).
  // a video already on TikTok is filed again without the flag
  "unflagged-duplicate-allowed": ["api",
    "  var repost = b.repost === true && video.tiktok_status === \"posted\";\n", "  var repost = video.tiktok_status === \"posted\";\n"],
  // the flag is ignored: a confirmed Post again is still refused
  "repost-flag-ignored": ["api",
    "  var repost = b.repost === true && video.tiktok_status === \"posted\";\n", "  var repost = false;\n"],
  // a repost inside 24 hours of the last post: the daily cap could miss a post
  "repost-gap-ignored": ["api",
    "    if (isFinite(lastAt) && deps.now() - lastAt < REPOST_GAP_MS) {", "    if (false) {"],
  // the new publish may overwrite any slot, not only the posted publish the repost was filed against
  // NAMED (Nov 17 2026, TK1): section K.
  // the length is not checked when the post is filed
  "duration-unchecked-at-filing": ["api",
    "  if (tooLong) return { status: 422, body: { error: tooLong + \" Nothing was filed.\", code: video.duration_ms == null ? \"duration_unknown\" : \"too_long\", field: \"video_id\" } };\n", ""],
  // ...nor again at approval, against TikTok's answer then
  "duration-unchecked-at-send": ["api",
    "  if (overLength) throw fail(overLength + \" Nothing was sent.\");\n", ""],
  // an unknown length is let through
  "duration-null-allowed": ["api",
    "  if (ms === null) return MESSAGES.durationUnknown;", "  if (ms === null) return null;"],
  // the limit (seconds) compared as minutes
  "duration-units-wrong": ["api",
    "  if (ms > max * 1000) return", "  if (ms > max * 60000) return"],
  // mvhd version 0 read with timescale and duration swapped
  "mvhd-fields-swapped": ["videos",
    "        return d32 === 0xFFFFFFFF ? null : msOf(d32, body.readUInt32BE(p + 8));", "        return d32 === 0xFFFFFFFF ? null : msOf(body.readUInt32BE(p + 8), d32);"],
  // a box header split across two chunks is lost
  "mvhd-split-header-lost": ["videos",
    "        if (buf.length - i < 8) { pending = Buffer.from(buf.subarray(i)); return; }", "        if (buf.length - i < 8) { return; }"],
  // the file's own length never read
  // NAMED (Nov 21 2026, P3-1): BEFORE the anchor matched twice once BV1 added the parts path (MUTATE=all said ERROR). AFTER it names
  // the one-file path (ONE_FILE_MAX_BYTES), the path TK1's tests upload through.
  "duration-not-read": ["videos",
    "ONE_FILE_MAX_BYTES, extOf(path) === \"webm\" ? null : durationReader()", "ONE_FILE_MAX_BYTES, null"],
  // the browser's length believed as sent
  "browser-duration-trusted": ["videos",
    "  return perSec >= BROWSER_MIN_BYTES_PER_SEC && perSec <= BROWSER_MAX_BYTES_PER_SEC ? v : null;", "  return v;"],
  // the browser's length preferred over the file's
  // NAMED (Nov 21 2026, P3-1): BEFORE the anchor matched twice once BV1 added the parts path. AFTER it carries TK1's comment line,
  // so it names the one-file insert only.
  "browser-over-file": ["videos",
    "    // NAMED (Nov 17 2026, TK1): the file's own length first; the browser's only when the file gave none.\n    duration_ms: m.durationMs !== null ? m.durationMs : browserDuration(b.duration_ms, m.bytes),",
    "    // NAMED (Nov 17 2026, TK1): the file's own length first; the browser's only when the file gave none.\n    duration_ms: browserDuration(b.duration_ms, m.bytes) || m.durationMs,"],
  // a deleted file still gets a preview address
  "preview-gone-signed": ["videos",
    "  if (video.status !== \"ready\" || !video.path) return { status: 410, body: { error: MESSAGES.previewGone, code: \"file_gone\" } };\n", ""],
  // the preview plays on its own, or with sound
  "preview-autoplay": ["ui", "player.autoplay = false;", "player.autoplay = true;"],
  "preview-unmuted": ["ui", "player.controls = true; player.muted = true;", "player.controls = true; player.muted = false;"],
  // a deleted file is not said
  "preview-gone-unsaid": ["ui",
    "      if (res.status === 410 || res.status === 404) { note.textContent = \"This video's file was deleted, so it can't be previewed or posted.\"; return; }\n", ""],
  // no preview in the form
  "preview-missing": ["ui", "    box.appendChild(preview(v));\n", ""],
  // the declaration's names not linked, or linked elsewhere
  "declaration-unlinked": ["ui",
    "    node.appendChild(link(\"Music Usage Confirmation\", MUSIC_URL));", "    node.appendChild(document.createTextNode(\"Music Usage Confirmation\"));"],
  "declaration-bc-url-wrong": ["ui",
    "  var BC_URL = \"https://www.tiktok.com/legal/page/global/bc-policy/en\";", "  var BC_URL = \"https://www.tiktok.com/legal/page/global/music-usage-confirmation/en\";"],
  // File for approval stays on while Disclose is on with nothing chosen
  "disclosure-button-enabled": ["ui", "      file.disabled = unchosen || busy;", "      file.disabled = busy;"],
  // "Only you" disabled without saying why
  "private-hover-missing": ["ui", "        privacy.options[i].title = paid ? PRIVATE_HOVER : \"\";", "        privacy.options[i].title = \"\";"],
  // the Social page's polling: unbounded, without backoff, or started again on every redraw
  "poll-unbounded": ["ui", "      if (p.tries >= POLL_DELAYS.length) {", "      if (false) {"],
  "poll-no-backoff": ["ui", "      setTimeout(ask, POLL_DELAYS[p.tries]);", "      setTimeout(ask, POLL_DELAYS[0]);"],
  "poll-restarted": ["ui", "    if (p) { p.show = show; if (p.text) show(p.text); return; }", "    if (false) { p.show = show; if (p.text) show(p.text); return; }"],
  "poll-missing": ["ui", "    if (v.tiktok_status === \"processing\") poll(v, function (text) { msg.textContent = text; });\n", ""],
  // the server's status fetch not single-flight
  "status-not-single-flight": ["api", "  var running = statusInFlight.get(video.id);", "  var running = null;"],
  // the processing notice dropped from a sent post
  "processing-notice-missing": ["api",
    "  return { processing: true, status: \"processing\", note: \"TikTok has the video and is processing it. Check its status on the Social page.\", notice: MESSAGES.processingNotice };\n}",
    "  return { processing: true, status: \"processing\", note: \"TikTok has the video and is processing it. Check its status on the Social page.\" };\n}"],
  // creator_info's "can't post more now" treated as any other failure
  "cannot-post-unmapped": ["api",
    "    if (err && CANNOT_POST_CODES.indexOf(err.code) !== -1) return { status: 409, body: { error: MESSAGES.cannotPostNow + \" Nothing was filed.\", code: \"cannot_post_now\" } };\n    return { status: 502, body: { error: err && err.said ? \"TikTok said: \" + err.said + \" Nothing was filed.\"",
    "    return { status: 502, body: { error: err && err.said ? \"TikTok said: \" + err.said + \" Nothing was filed.\""],
  // the old daily-cap words (not named as BizForce's own limit)
  "daily-cap-unnamed": ["api",
    "  dailyCap: \"BizForce's own limit is 5 TikTok posts in 24 hours. Nothing was sent. Try again later.\",", "  dailyCap: \"You can post 5 videos to TikTok in 24 hours. Nothing was sent. Try again later.\","],
  // the nickname not filed, or not shown on the card
  "nickname-not-filed": ["api", "    creator_nickname: creator.creator_nickname\n", "    creator_nickname: null\n"],
  "card-nickname-dropped": ["proposals", "escapeHtml(tiktokNickname(payload))", "escapeHtml(\"your connected TikTok account\")"],
  // the card: no declaration above Approve, no preview, unbounded polling
  "card-declaration-missing": ["proposals", "      ? (p.action_type === \"publish_tiktok_post\" ? tiktokDeclarationHtml(p.payload || {}) : '') +\n", "      ? '' +\n"],
  "card-preview-autoplay": ["proposals", "v.controls = true; v.muted = true; v.autoplay = false;", "v.controls = true; v.muted = true; v.autoplay = true;"],
  "card-poll-unbounded": ["proposals", "    if (p.done || p.tries >= TIKTOK_POLL_DELAYS.length) {", "    if (p.done) {"],
  "card-notice-missing": ["proposals", "      (sent ? '<div><span class=\"pf-label\">processing</span>", "      (false ? '<div><span class=\"pf-label\">processing</span>"],
  // the private-account line gone from the TikTok card
  "private-account-line-missing": ["page", "your TikTok account must be set to private, and ", ""],
  // the stale token lifetimes back in the comment
  "token-comment-stale": ["auth", "an access token (expires_in; TikTok documents 2 hours)", "an access token (about 24 hours)"],
  // NAMED (Nov 18 2026, TK2): section X.
  // the JSON calls go out without the documented "application/json; charset=UTF-8"
  "init-content-type-default": ["api",
    "function jsonHeaders(token) { return { Authorization: \"Bearer \" + token, \"Content-Type\": JSON_TYPE }; }", "function jsonHeaders(token) { return { Authorization: \"Bearer \" + token }; }"],
  // the old prefix rule, which refused TikTok's documented /video/ upload_url (the live failure)
  // NAMED (Nov 18 2026, TK3): the four below re-anchored on the shared rule (lib/guardedFetch.js tiktokUploadUrlOk).
  "upload-url-old-prefix": ["api",
    "function uploadUrlOk(s) { return GF.tiktokUploadUrlOk(s); }", "function uploadUrlOk(s) { return String(s).indexOf(\"https://open-upload.tiktokapis.com/upload/\") === 0; }"],
  // the guarded transport still only reaches /upload/
  "upload-profile-old-path": ["fetch",
    "tiktok: Object.freeze({ hostPattern: TIKTOK_UPLOAD_HOST_RE, pathPattern: TIKTOK_UPLOAD_PATH_RE,", "tiktok: Object.freeze({ hostPattern: TIKTOK_UPLOAD_HOST_RE, pathPattern: /^\\/upload\\//,"],
  // the transport's host pattern loosened to any host ending in tiktokapis.com (look-alikes included)
  "upload-host-loose": ["fetch",
    "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.(?:com|us)$/;","const TIKTOK_UPLOAD_HOST_RE = /tiktokapis\\.com$/;"],
  /* ── Y ── NAMED (Nov 18 2026, TK3) */
  // the TK2 rule: "/upload/" and "/video/" with the trailing slash (the live refusal)
  "y-path-slash-required": ["fetch",
    "const TIKTOK_UPLOAD_PATH_RE = /^\\/(?:upload|video)(?:\\/|$)/;", "const TIKTOK_UPLOAD_PATH_RE = /^\\/(?:upload|video)\\//;"],
  // the TK2 host rule: an "upload" label required (the API host and other subdomains refused)
  "y-host-tk2-rule": ["fetch",
    "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.(?:com|us)$/;","const TIKTOK_UPLOAD_HOST_RE = /^[a-z0-9-]*upload[a-z0-9-]*(?:\\.[a-z0-9-]+)?\\.tiktokapis\\.com$/;"],
  // only open-upload.tiktokapis.com (open-upload-i18n, open-upload-va and upload.us refused)
  "y-host-one-only": ["fetch",
    "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.(?:com|us)$/;","const TIKTOK_UPLOAD_HOST_RE = /^open-upload\\.tiktokapis\\.com$/;"],
  // the end not anchored: tiktokapis.com.evil.com accepted
  "y-host-end-open": ["fetch",
    "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.(?:com|us)$/;","const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.com/;"],
  // NAMED (Nov 18 2026, TK4): BEFORE "y-host-us-domain" (tiktokapis.us accepted, then a fault). AFTER "y-host-com-only": the
  // TK3 rule, tiktokapis.com only, which refused the live US answer.
  "y-host-com-only": ["fetch",
    "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.(?:com|us)$/;", "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.com$/;"],
  // a label may start with a hyphen or run past 63 characters
  "y-host-label-loose": ["fetch",
    "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.(?:com|us)$/;", "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9-]+\\.)+tiktokapis\\.(?:com|us)$/;"],
  /* NAMED (Nov 18 2026, TK4): the .us domain's own faults */
  // the apex accepted (tiktokapis.us, tiktokapis.com)
  "us-apex-accepted": ["fetch",
    "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.(?:com|us)$/;", "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*tiktokapis\\.(?:com|us)$/;"],
  // the end not anchored: tiktokapis.us.evil.com and tiktokapis.usa accepted
  "us-end-open": ["fetch",
    "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.(?:com|us)$/;", "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.(?:com|us)/;"],
  // a suffix match: evil-tiktokapis.us accepted
  "us-suffix-only": ["fetch",
    "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.(?:com|us)$/;", "const TIKTOK_UPLOAD_HOST_RE = /tiktokapis\\.(?:com|us)$/;"],
  // any top-level domain: tiktokapis.usa, tiktokapis.uk accepted
  "us-any-tld": ["fetch",
    "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.(?:com|us)$/;", "const TIKTOK_UPLOAD_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.[a-z]+$/;"],
  // the .us host let through on http or another port (the scheme and port rules dropped for .us only)
  "us-http-allowed": ["fetch", "  return u.protocol === \"https:\" && (u.port === \"\" || u.port === \"443\") && !u.username", "  return (u.protocol === \"https:\" || /\\.us$/.test(u.hostname)) && (u.port === \"\" || u.port === \"443\") && !u.username"],
  "us-port-any": ["fetch", "  return u.protocol === \"https:\" && (u.port === \"\" || u.port === \"443\") && !u.username", "  return u.protocol === \"https:\" && (u.port === \"\" || u.port === \"443\" || /\\.us$/.test(u.hostname)) && !u.username"],
  // the path not anchored after the word: /uploadx accepted
  "y-path-open": ["fetch",
    "const TIKTOK_UPLOAD_PATH_RE = /^\\/(?:upload|video)(?:\\/|$)/;", "const TIKTOK_UPLOAD_PATH_RE = /^\\/(?:upload|video)/;"],
  // http accepted by uploadUrlOk
  "y-http-allowed": ["fetch", "  return u.protocol === \"https:\" && (u.port === \"\" || u.port === \"443\") && !u.username", "  return /^https?:$/.test(u.protocol) && (u.port === \"\" || u.port === \"443\") && !u.username"],
  // any port accepted by uploadUrlOk
  "y-port-any": ["fetch", "  return u.protocol === \"https:\" && (u.port === \"\" || u.port === \"443\") && !u.username", "  return u.protocol === \"https:\" && !u.username"],
  // credentials accepted by uploadUrlOk
  "y-credentials-allowed": ["fetch", " && !u.username && !u.password &&\n    u.hostname.length <= 253", " &&\n    u.hostname.length <= 253"],
  // the guarded PUT ignores the host or the path pattern
  "y-stream-host-any": ["fetch", "  const hostOk = profile.hostPattern ? target.hostname.length <= 253 && profile.hostPattern.test(target.hostname) :", "  const hostOk = profile.hostPattern ? true :"],
  "y-stream-path-any": ["fetch", "  const pathOk = profile.pathPattern ? profile.pathPattern.test(target.url.pathname) :", "  const pathOk = profile.pathPattern ? true :"],
  // the DNS guard skipped for the PUT
  "y-dns-guard-off": ["fetch", "method: \"PUT\", agent: false, lookup: guardedLookup, headers: headers", "method: \"PUT\", agent: false, lookup: function (h, o, cb) { return resolve(h, o, cb); }, headers: headers"],
  // lib/tiktokApi.js keeps its own copy of the rule
  "y-tk-own-copy": ["api", "const UPLOAD_HOST_RE = GF.TIKTOK_UPLOAD_HOST_RE;", "const UPLOAD_HOST_RE = /^open-upload\\.tiktokapis\\.com$/;"],
  // the host redacted again by the scrubber
  "y-host-redacted": ["api", "(shape ? \" \" + shape : \"\")", "(shape ? \" \" + scrubbed(shape, secrets) : \"\")"],
  // the shape not passed (no host in the line)
  "y-host-not-logged": ["api", "answerLine(\"video/init\", a, [], \"unusable upload_url\", urlShape(uploadUrl))", "answerLine(\"video/init\", a, [], \"unusable upload_url\")"],
  // the query, or the whole path, in the log
  "y-query-logged": ["api", " + (u.username || u.password ? \" credentials\" : \"\") + \" \" + path;", " + (u.username || u.password ? \" credentials\" : \"\") + \" \" + path + u.search;"],
  "y-path-logged": ["api", " + (u.username || u.password ? \" credentials\" : \"\") + \" \" + path;", " + (u.username || u.password ? \" credentials\" : \"\") + \" \" + u.pathname;"],
  // the credentials or the port left out of the line, or the credentials printed
  "y-port-not-logged": ["api", "    (/^[0-9]{1,5}$/.test(u.port) ? \" port \" + u.port : \"\")", "    \"\""],
  "y-credentials-logged": ["api", "(u.username || u.password ? \" credentials\" : \"\")", "(u.username || u.password ? \" \" + u.username + \":\" + u.password : \"\")"],
  // any host printed, whatever its characters or length
  "y-host-unchecked": ["api", "  var host = /^[a-z0-9.-]{1,253}$/.test(u.hostname) ? u.hostname : \"(odd host)\";", "  var host = u.hostname;"],
  // a 200 counted as a success whatever error.code says
  "ok-means-2xx": ["api",
    "answer.json && answer.json.error && answer.json.error.code === \"ok\");", "answer.json);"],
  // TikTok's refusals not logged, or logged raw, or without the log_id, or unbounded
  "refusal-not-logged": ["api", "  if (!tiktokOk(answer)) logRefusal(answerLine(step, answer, [tokenOf(options)]));\n", ""],
  "transport-failure-not-logged": ["api", "    logRefusal(refusalLine(step, \"none\", (err && err.code) || \"request\", \"\", \"\", [tokenOf(options)]));\n", ""],
  "refusal-log-unscrubbed": ["api", "  var s = String(text == null ? \"\" : text);\n", "  var s = String(text == null ? \"\" : text);\n  return s;\n"],
  // NAMED (Nov 18 2026, TK5): the two below re-anchored on TK5's refusalLine (head, then the content_type tail).
  "refusal-log-id-dropped": ["api", "\" log_id=\" + l);", "\" log_id=-\");"],
  "refusal-log-unbounded": ["api", "  return (head.slice(0, 300 - tail.length) + tail).slice(0, 300);", "  return head + tail;"],
  // NAMED (Nov 18 2026, TK5): put-refusal-not-logged and put-card-code-missing re-anchored on TK5's sendWhole and putSaid.
  "put-refusal-not-logged": ["api", "  if (!putComplete(answer)) {\n    var e = answer", "  if (false) {\n    var e = answer"],
  "put-transport-not-logged": ["api", "    logRefusal(refusalLine(\"upload\", \"none\", (err && err.code) || \"request\", \"\", \"\", []));\n", ""],
  // NAMED (Nov 18 2026, TK3): the two below re-anchored on TK3's log call and urlShape.
  "unusable-answer-not-logged": ["api", "    logRefusal(PUBLISH_ID_RE.test(publishId) ? answerLine(", "    (function () {})(PUBLISH_ID_RE.test(publishId) ? answerLine("],
  // the unusable upload_url logged whole (its token in the query)
  "unusable-url-logged-whole": ["api", "  try { u = new URL(String(s)); } catch (e) { return \"(not an address)\"; }\n", "  try { u = new URL(String(s)); } catch (e) { return \"(not an address)\"; }\n  return String(s);\n"],
  // the card without TikTok's code
  "card-code-missing": ["api",
    "  return \"TikTok didn't start the post. TikTok said: \" + c + (w ? \" (\" + w + \")\" : \"\") + \". Nothing was sent.\";",
    "  return \"TikTok didn't start the post\" + (w ? \" (\" + w + \")\" : \"\") + \". Nothing was sent.\";"],
  "put-card-code-missing": ["api", "  return \" TikTok said: http \" + (/^[0-9]{3}$/.test(String(answer.status)) ? answer.status : \"-\") + c + \".\";", "  return \" TikTok said: http \" + (/^[0-9]{3}$/.test(String(answer.status)) ? answer.status : \"-\") + \".\";"],
  /* ── Z ── NAMED (Nov 18 2026, TK5): the upload PUT judged by status, not body */
  // the TK2-TK4 transport: a body that is there must be JSON
  "json-required-again": ["fetch", "            succeed({ status: status, json: obj, headers: picked, contentType: answerType, bodyBytes: seen });",
    "            if (!obj && seen > 0) return fail(new GuardedFetchError(\"not_json\", \"a \" + status + \" answer whose body is not JSON\"));\n            succeed({ status: status, json: obj, headers: picked, contentType: answerType, bodyBytes: seen });"],
  // any answer counted as done, whatever its status
  "status-ignored": ["api", "function putComplete(answer) { return !!answer && answer.status === 201; }", "function putComplete(answer) { return !!answer; }"],
  // the answer body read whole, however long
  "body-unbounded": ["fetch", "            const room = profile.answerMaxBytes - seen;", "            const room = Infinity;"],
  // YouTube's profile given TikTok's status-only reading
  "youtube-profile-changed": ["fetch", "allow308: true, emptyOkStatuses: Object.freeze([]) }),", "allow308: true, emptyOkStatuses: Object.freeze([]), statusOnly: true, answerMaxBytes: 64 * 1024 }),"],
  // the content type left out of the upload line
  "put-content-type-not-logged": ["api", "      \" content_type=\" + typeWord(answer.contentType)));", "      \"\"));"],
  // the card without the status
  "put-status-not-on-card": ["api", "  return \" TikTok said: http \" + (/^[0-9]{3}$/.test(String(answer.status)) ? answer.status : \"-\") + c + \".\";", "  return \" TikTok said:\" + c + \".\";"],
  // the body put in the log line
  "put-body-logged": ["api", "      \" content_type=\" + typeWord(answer.contentType)));", "      \" content_type=\" + typeWord(answer.contentType) + \" body=\" + JSON.stringify(answer)));"],
  "creator-card-code-missing": ["api", "    if (err && err.kind === \"refused\") throw fail(saidLine(err.code, err.said));\n", ""],
  "reconnect-card-code-missing": ["api", "(err.tiktokCode ? \" TikTok said: \" + err.tiktokCode + \".\" : \"\")", "\"\""],
  "repost-slot-unchecked": ["api",
    "  if (reposting && p.repost_of) storing = storing.eq(\"tiktok_publish_id\", p.repost_of).eq(\"tiktok_status\", \"posted\");\n",
    "  if (reposting && p.repost_of) storing = storing;\n"]
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
// NAMED (Nov 18 2026, TK3): lib/tiktokApi.js takes its upload_url rule from lib/guardedFetch.js, the compiled (mutable) one.
const TK = compile(FILES.api, "lib/tiktokApi.js", { "./tiktokAuth": TA, "./memberVideos": MV, "./youtubeApi": YA, "./guardedFetch": GF });
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
// NAMED (Nov 18 2026, TK2): BEFORE ".../upload/?upload_id=", a shape TikTok's init never answers. AFTER the documented
// init answer, "https://open-upload.tiktokapis.com/video/?upload_id=67890&upload_token=Xza123" (content-posting-api-reference-direct-post).
const UPLOAD_BASE = "https://open-upload.tiktokapis.com/video/?upload_token=check-token&upload_id=check-upload-";
const PUBLISH_BASE = "v_pub_file~v2-1.check";
const POST_ID = "7350000000000000001";
const PAGE_PATH = "/agents/social.html";
const REDIRECT = "https://bizforceai.net/agents/social.html";
const SECRETS = [ACCESS, ACCESS2, WINNER, REFRESH, REFRESH2, CODE, CLIENT.secret, "check-upload-", "check-token"];
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
    },
    // NAMED (Nov 17 2026, TK1): the preview's signed address.
    createSignedUrl: async function (p, secs) {
      calls.push({ op: "sign", path: p, secs: secs });
      if (!objects[p]) return { data: null, error: { message: "Object not found" } };
      return { data: { signedUrl: "https://check.supabase.co/storage/v1/object/sign/bf-video/" + p + "?token=sig" }, error: null };
    }
  };
  return { from: function (b) { if (b !== "bf-video") throw new Error("unexpected bucket " + b); return bucket; }, objects: objects, calls: calls };
}
function makeDb() {
  // NAMED, item 8 part 3a: instagram_posts added; retention and deleting a video now read it.
  const t = { member_tiktok_connections: [], member_videos: [], oauth_states: [], agent_proposals: [], notifications: [], job_runs: [], business_profiles: [], instagram_posts: [],
    // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): lib/memberVideos.js reads facebook_posts too.
    facebook_posts: [],
    // NAMED (Nov 18 2026, BV1, migration 187): the parts of a video over 50 MB.
    member_video_parts: [] };
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
      // NAMED (Nov 18 2026, BV1, migration 187): BEFORE 52428800. AFTER 524288000, and part_count 1..12.
      if (!(Number(row.bytes) > 0 && Number(row.bytes) <= 524288000)) return "member_videos_bytes_check";
      if (row.part_count != null && !(Number.isInteger(row.part_count) && row.part_count >= 1 && row.part_count <= 12)) return "member_videos_part_count_check";
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
// NAMED (Nov 18 2026, TK2): the documented log_id example.
const INIT_LOG_ID = "202210112248442CB9319E1FB30C1073F3";
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
      // NAMED (Nov 17 2026, TK1): creatorError answers creator_info with that error code (TikTok's "can't post more now" codes).
      if (o.creatorError) return reply(o.creatorStatus || 403, { error: { code: o.creatorError, message: "Posting is limited for this account right now.", log_id: "x" } });
      const d = Object.assign({ creator_avatar_url: "https://p16.example/a.jpg", creator_username: "maplestreet", creator_nickname: NICK,
        privacy_level_options: OPTIONS.slice(), comment_disabled: false, duet_disabled: false, stitch_disabled: false, max_video_post_duration_sec: 300 }, o.creator || {});
      return reply(200, { data: d, error: OK });
    }
    if (u.hostname === "open.tiktokapis.com" && u.pathname === "/v2/post/publish/video/init/" && method === "POST") {
      EV.push("tt:init");
      let b = null;
      try { b = JSON.parse(body.toString("utf8")); } catch (e) { b = null; }
      g.inits.push(b);
      // NAMED (Nov 13 2026, S3): a test may change the stored row while TikTok answers the init (RP11).
      if (typeof g.onInit === "function") g.onInit();
      if (o.initError) return reply(o.initStatus || 403, { error: { code: "spam_risk_too_many_posts", message: o.initError, log_id: "x" } });
      // NAMED (Nov 18 2026, TK2): initCode answers init with that documented error code, HTTP initStatus, message initMessage.
      if (o.initCode) return reply(o.initStatus || 400, { error: { code: o.initCode, message: o.initMessage === undefined ? "Check error message for details." : o.initMessage, log_id: INIT_LOG_ID } });
      if (o.initRaw) return o.initRaw;
      if (o.initDown) return { error: Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }) };
      g.n++;
      const publishId = PUBLISH_BASE + "." + g.n;
      const url = o.uploadUrl || (UPLOAD_BASE + g.n);
      // NAMED (Nov 18 2026, BV1): the chunk plan the init named; chunks counts the PUTs taken.
      g.uploads[new URL(url).search] = { publishId: publishId, total: b && b.source_info ? b.source_info.video_size : 0, received: Buffer.alloc(0), done: false,
        chunkSize: b && b.source_info ? b.source_info.chunk_size : 0, chunkCount: b && b.source_info ? b.source_info.total_chunk_count : 1, chunks: 0 };
      return reply(200, { data: { publish_id: publishId, upload_url: url }, error: OK });
    }
    if (u.hostname === "open.tiktokapis.com" && u.pathname === "/v2/post/publish/status/fetch/" && method === "POST") {
      EV.push("tt:status");
      let b = null;
      try { b = JSON.parse(body.toString("utf8")); } catch (e) { b = null; }
      g.statusFetches = (g.statusFetches || []).concat([b && b.publish_id]);
      // NAMED (Nov 18 2026, TK2): statusCode answers status/fetch with that documented error code.
      if (o.statusCode) return reply(o.statusHttp || 400, { error: { code: o.statusCode, message: "The publish_id is invalid.", log_id: INIT_LOG_ID } });
      return statusAnswer(b && b.publish_id);
    }
    // NAMED (Nov 18 2026, TK2): BEFORE only open-upload.tiktokapis.com under "/upload/". AFTER the documented upload hosts and paths.
    // NAMED (Nov 18 2026, TK3): AFTER also open-upload-i18n and open-upload-va, and the paths "/upload" and "/video" with
    // no trailing slash (the live answer was "https://<host>/upload?upload_id=...").
    // NAMED (Nov 18 2026, TK4): AFTER also open-upload.tiktokapis.us (the live US account's upload host).
    if ((/^(?:open-upload(?:-i18n|-va)?|upload\.us)\.tiktokapis\.com$/.test(u.hostname) || u.hostname === "open-upload.tiktokapis.us") &&["/upload/", "/video/", "/upload", "/video"].indexOf(u.pathname) !== -1 && method === "PUT") {
      EV.push("tt:put");
      const up = g.uploads[u.search];
      if (!up) return reply(404, { error: { code: "not_found" } });
      // NAMED (Nov 18 2026, BV1): putCodeAt refuses only that chunk (1-based); without it every PUT is refused, as before.
      if (o.putCode && (o.putCodeAt === undefined || o.putCodeAt === up.chunks + 1)) return reply(o.putHttp || 403, { error: { code: o.putCode, message: "The upload_url has expired.", log_id: INIT_LOG_ID } });
      // NAMED (Nov 18 2026, BV1): BEFORE only "bytes 0-(N-1)/N". AFTER with total_chunk_count over 1, each chunk in order:
      // chunk_size bytes from where the last ended, the final one to the end; 206 until the last, then 201.
      const many = up.chunkCount > 1;
      const at = many ? up.received.length : 0;
      const end = !many || up.chunks === up.chunkCount - 1 ? up.total : at + up.chunkSize;
      const want = "bytes " + at + "-" + (end - 1) + "/" + up.total;
      if (entry.contentRange !== want || Number(entry.contentLength) !== end - at) return reply(416, { error: { code: "range_not_satisfiable" } });
      up.received = many ? Buffer.concat([up.received, body]) : Buffer.from(body);
      up.chunks++;
      up.done = up.received.length === up.total;
      if (o.putStatus) return reply(o.putStatus, null);
      // NAMED (Nov 18 2026, TK5): putAnswer { status, type, body } answers the PUT with any status, content type and raw body.
      if (o.putAnswer) return { status: o.putAnswer.status, headers: o.putAnswer.type ? { "content-type": o.putAnswer.type } : {}, raw: Buffer.from(o.putAnswer.body || "", "utf8") };
      return o.putJson ? reply(201, { ok: true }) : reply(up.done ? 201 : 206, null);
    }
    if (u.hostname === "open-upload.tiktokapis.com" && u.pathname.indexOf("/upload/redirect") === 0) return reply(308, null, { location: "https://open-upload.tiktokapis.com/upload/x" });
    if (u.hostname === "open-upload.tiktokapis.com" && u.pathname.indexOf("/upload/html") === 0) return { status: 201, headers: { "content-type": "text/html" }, raw: Buffer.from("<p>ok</p>") };
    if (u.hostname === "open-upload.tiktokapis.com" && u.pathname.indexOf("/upload/empty200") === 0) return reply(200, null);
    if (u.hostname === "open-upload.tiktokapis.com" && u.pathname.indexOf("/upload/e201") === 0) return reply(201, null);
    if (u.hostname === "www.googleapis.com" && u.pathname.indexOf("/upload/e201") === 0) return reply(201, null);
    // NAMED (Nov 18 2026, TK5): a 201 in plain text or broken JSON (YouTube must still refuse both); a 201 with a 200 KB body (TikTok reads 64 KB).
    if (u.hostname === "www.googleapis.com" && u.pathname.indexOf("/upload/plain201") === 0) return { status: 201, headers: { "content-type": "text/plain" }, raw: Buffer.from("OK") };
    if (u.hostname === "www.googleapis.com" && u.pathname.indexOf("/upload/badjson201") === 0) return { status: 201, headers: { "content-type": "application/json" }, raw: Buffer.from("{") };
    if (u.hostname === "open-upload.tiktokapis.com" && u.pathname.indexOf("/upload/big201") === 0) return { status: 201, headers: { "content-type": "text/plain" }, raw: Buffer.alloc(200 * 1024, 120) };
    if (u.hostname === "open-upload.tiktokapis.com" && u.pathname.indexOf("/upload/plain201") === 0) return { status: 201, headers: { "content-type": "text/plain" }, raw: Buffer.from("OK") };
    if (u.hostname === "open-upload.tiktokapis.com" && u.pathname.indexOf("/upload/badjson201") === 0) return { status: 201, headers: { "content-type": "application/json" }, raw: Buffer.from("{") };
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
    // NAMED (Nov 18 2026, BV1): cutAt cuts only that body PUT (a later chunk).
    const cutThis = isBodyPut && ((o.cut || 0) >= g.bodyPuts || o.cutAt === g.bodyPuts);
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
  g.puts = function () { return g.of(function (r) { return r.method === "PUT" && r.host !== "open.tiktokapis.com" && /\.tiktokapis\.(?:com|us)$/.test(r.host) && r.bytes > 0; }); }; // TK4: .us too
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
    // NAMED (Nov 17 2026, TK1): migration 186's length, 45 s unless a test says otherwise.
    duration_ms: 45000,
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
  const dom = { els: {}, fetches: [], events: [], innerHTML: [], assigned: [], session: {}, timers: [] };
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
    Number: Number, Error: Error, Object: Object,
    // NAMED (Nov 17 2026, TK1): timers are kept, not run; a test runs them (dom.timers) to step the status polling.
    setTimeout: function (fn, ms) { dom.timers.push({ fn: fn, ms: ms }); return dom.timers.length; }, clearTimeout: function () {} };
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
const PREVIEW_URL = "https://check.supabase.co/storage/v1/object/sign/bf-video/video/x.mp4?token=sig";
const PAGE_VIDEO = { id: "22222222-2222-4222-8222-222222222222", label: "Spring cakes", bytes: 3 * 1048576, mime: "video/mp4", status: "ready",
  youtube_video_id: null, youtube_url: null, uploaded_at: null, created_at: "2026-11-07T10:00:00Z", upload_unfinished: false,
  tiktok_status: null, tiktok_posted_at: null, tiktok_post_url: null, tiktok_upload_unfinished: false, duration_ms: 45000 };
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
    // NAMED (Nov 17 2026, TK1): the preview's signed address, and a processing post's status.
    if (/^\/api\/videos\/[0-9a-f-]{36}\/preview$/.test(p)) return { status: 200, body: { url: PREVIEW_URL, mime: "video/mp4", expires_in: 600 } };
    if (/^\/api\/tiktok\/videos\/[0-9a-f-]{36}\/status$/.test(p)) return { status: 200, body: { tiktok_status: "processing", tiktok_says: "PROCESSING_UPLOAD", post_url: null } };
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
      // NAMED (Nov 17 2026, TK1): the payload also names the account's nickname, for the proposal card.
      allow_comment: true, allow_duet: false, allow_stitch: false, brand_organic: false, brand_content: false, open_id: OPEN_ID, creator_nickname: NICK }) &&
    m.tiktok.creatorCalls().length === 1 && m.tiktok.initCalls().length === 0 && m.tiktok.puts().length === 0, J([r.status, r.body.error, prop && prop.payload]));
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

  /* ── RP ── NAMED (Nov 13 2026, S3, "Post again"): a video already on TikTok is filed again only with repost: true. */
  OUT("\n══ RP. posting a video again ══");
  const OLD_PUB = "v_pub_old.1";
  const postedOver = function (hoursAgo) {
    return { tiktok_status: "posted", tiktok_publish_id: OLD_PUB, tiktok_post_id: POST_ID, tiktok_posted_at: iso(Date.now() - hoursAgo * 3600000) };
  };
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  buf = mp4(300000, 31);
  video = seedVideo(m.db, buf, postedOver(48));
  r = await file(m, video);
  check("RP1. without the flag a video already on TikTok is refused as before: 409 already_posted, nothing filed",
    r.status === 409 && r.body.code === "already_posted" && m.db.t.agent_proposals.length === 0, J([r.status, r.body.code]));
  const loose = [];
  for (const flag of ["true", 1, "yes", {}]) loose.push((await file(m, video, { repost: flag })).body.code);
  check("RP2. only exactly true is the flag: \"true\", 1, \"yes\" and {} are refused the same way",
    J(loose) === J(["already_posted", "already_posted", "already_posted", "already_posted"]) && m.db.t.agent_proposals.length === 0, J(loose));
  r = await file(m, video, { repost: true });
  prop = m.db.t.agent_proposals[0];
  check("RP3. with repost: true it is filed: one pending post naming the publish it was filed against, titled \"again\", nothing sent but creator_info",
    r.status === 201 && !!prop && prop.status === "pending" && prop.payload.repost === true && prop.payload.repost_of === OLD_PUB &&
    /^Post to TikTok again as Maple Street Bakery \(Friends\)/.test(prop.title) && m.tiktok.initCalls().length === 0 && m.tiktok.puts().length === 0, J([r.status, r.body.code]));
  r = await file(m, video, { repost: true });
  check("RP4. the one-pending guard stands: a second flagged filing while the first waits is 409 pending", r.status === 409 && r.body.code === "pending" && m.db.t.agent_proposals.length === 1);
  a = await approve(m, prop);
  const rpRow = rowOf(m, video.id);
  check("RP5. approved: ONE new init and ONE PUT; the new publish replaces the old one and is recorded posted",
    a.ok && m.tiktok.inits.length === 1 && m.tiktok.puts().length === 1 && rpRow.tiktok_publish_id === PUBLISH_BASE + ".1" && rpRow.tiktok_status === "posted" &&
    Date.parse(rpRow.tiktok_posted_at) > Date.now() - 60000, a.ok ? J(a.v) : a.msg);
  a = await approve(m, prop);
  check("RP6. approving the same repost again sends nothing: already posted", a.ok && a.v.already_posted === true && m.tiktok.inits.length === 1 && m.tiktok.puts().length === 1, a.ok ? J(a.v) : a.msg);
  // the 24-hour gap
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(4000, 32), postedOver(3));
  r = await file(m, video, { repost: true });
  check("RP7. a repost within 24 hours of its last post: 409 repost_too_soon with the time, nothing filed",
    r.status === 409 && r.body.code === "repost_too_soon" && /less than 24 hours ago\. You can post it again after \d{4}-\d\d-\d\d \d\d:\d\d UTC\.$/.test(r.body.error || "") &&
    m.db.t.agent_proposals.length === 0, J([r.status, r.body.error]));
  // the daily cap stands
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  for (let i = 0; i < 5; i++) seedVideo(m.db, mp4(1000, 300 + i), { status: "uploaded", path: null, tiktok_status: "posted", tiktok_posted_at: iso(Date.now() - 3600000), tiktok_post_id: POST_ID });
  video = seedVideo(m.db, mp4(4000, 33), postedOver(48));
  r = await file(m, video, { repost: true });
  check("RP8. the daily cap stands for a repost: five posts in 24 hours, 409 daily_cap", r.status === 409 && r.body.code === "daily_cap" && m.db.t.agent_proposals.length === 0, J([r.status, r.body.code]));
  // a forged payload against another publish
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(4000, 34), postedOver(48));
  a = await approve(m, Object.assign(proposalOf(video), { payload: Object.assign(payloadOf(video), { repost: true, repost_of: "v_pub_other.2" }) }));
  check("RP9. a repost filed against another publish is already posted, nothing sent", a.ok && a.v.already_posted === true && m.tiktok.inits.length === 0, a.ok ? J(a.v) : a.msg);
  // the posted publish changes while TikTok starts the repost (another run got there first)
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(4000, 36), postedOver(48));
  r = await file(m, video, { repost: true });
  prop = m.db.t.agent_proposals[0];
  m.tiktok.onInit = function () { const row = rowOf(m, video.id); row.tiktok_publish_id = "v_pub_raced.9"; };
  a = await approve(m, prop);
  m.tiktok.onInit = null;
  check("RP11. the store replaces only the publish the repost was filed against: changed meanwhile, nothing is recorded and nothing uploaded",
    r.status === 201 && !a.ok && /couldn't be recorded before sending/.test(a.msg || "") && m.tiktok.puts().length === 0 && rowOf(m, video.id).tiktok_publish_id === "v_pub_raced.9" &&
    rowOf(m, video.id).tiktok_status === "posted", a.ok ? J(a.v) : a.msg);
  // the flag on a video TikTok doesn't have
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(4000, 35));
  r = await file(m, video, { repost: true });
  prop = m.db.t.agent_proposals[0];
  check("RP10. the flag on a video TikTok doesn't have files a plain post: no repost key, the plain title",
    r.status === 201 && !!prop && !("repost" in prop.payload) && !("repost_of" in prop.payload) && /^Post to TikTok as /.test(prop.title));

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
  m.storage.calls.length = 0;
  a = await approve(m, proposalOf(video));
  const up18 = m.tiktok.uploads[Object.keys(m.tiktok.uploads)[0]] || {};
  // NAMED (Nov 18 2026, BV2): BEFORE refused with no init (the file was read once to check it, then again to send it).
  // AFTER the send is the one read and the check: the PUT starts and the guard stops it before its last bytes.
  check("U18. the stored file no longer matches the filed fingerprint: read ONCE, by the PUT; the guard stops it, TikTok never has it all, the plain words, not posted",
    !a.ok && a.msg === "publish_tiktok_post: " + TK.MESSAGES.stopped && m.tiktok.inits.length === 1 && up18.done !== true &&
    m.storage.calls.filter(function (x) { return x.op === "stream"; }).length === 1 && ["posted", "processing"].indexOf(rowOf(m, video.id).tiktok_status) === -1, a.msg);
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
  // NAMED (Nov 17 2026, TK1): BEFORE "You can post 5 videos to TikTok in 24 hours." AFTER named as BizForce's own limit.
  check("U21. five TikTok posts in 24 hours: refused at execution too, no init", !a.ok && /BizForce's own limit is 5 TikTok posts in 24 hours/.test(a.msg || "") && m.tiktok.inits.length === 0);
  m = mountRoutes({ env: CONFIGURED, tiktok: { initError: "You have posted too many videos today." } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 34));
  a = await approve(m, proposalOf(video));
  vr = rowOf(m, video.id);
  // NAMED (Nov 18 2026, TK2): BEFORE "TikTok refused the post: <words>". AFTER the code always, the words after it.
  check("U22. TikTok refuses the init: its code and its own words shown (no duration is parsed here), nothing stored",
    !a.ok && /TikTok didn't start the post\. TikTok said: spam_risk_too_many_posts \(You have posted too many videos today\)\. Nothing was sent\.$/.test(a.msg || "") &&
    vr.tiktok_publish_id === null && vr.tiktok_status === null && m.tiktok.puts().length === 0, a.msg);
  m = mountRoutes({ env: CONFIGURED, tiktok: { uploadUrl: "https://evil.example.com/upload/?upload_id=x" } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 35));
  a = await approve(m, proposalOf(video));
  // NAMED (Nov 18 2026, TK2): BEFORE "not on open-upload.tiktokapis.com/upload/". AFTER not an upload host under tiktokapis.com, /video/ or /upload/.
  check("U23. an upload URL not on a TikTok upload host: refused, nothing stored, nothing PUT", !a.ok && rowOf(m, video.id).tiktok_publish_id === null && m.tiktok.puts().length === 0);
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
  // NAMED (Nov 18 2026, TK2): BEFORE only open-upload.tiktokapis.com under /upload/. AFTER an upload host under tiktokapis.com,
  // under /video/ or /upload/; the API host, a look-alike host, http and another port are still refused.
  // NAMED (Nov 18 2026, TK3): BEFORE the API host open.tiktokapis.com (refused then; every subdomain of tiktokapis.com is
  // TikTok's own, so it is accepted now). AFTER a look-alike, evil-tiktokapis.com.
  const sApiHost = await attempt(g.streamUpload("https://evil-tiktokapis.com/video/e201", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  const sLook = await attempt(g.streamUpload("https://open-upload.tiktokapis.com.evil.example/video/e201", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  const sHttp = await attempt(g.streamUpload("http://open-upload.tiktokapis.com/video/e201", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  const sPort = await attempt(g.streamUpload("https://open-upload.tiktokapis.com:8443/video/e201", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  check("S1. the caller must name a profile; tiktok reaches only a subdomain of tiktokapis.com, under /video or /upload, and youtube never reaches it; no request",
    !sNoProf.ok && !sGoogle.ok && sGoogle.code === "invalid_url" && !sPath.ok && sPath.code === "invalid_url" && !sYtAtTt.ok && sYtAtTt.code === "invalid_url" &&
    [sApiHost, sLook, sHttp, sPort].every(function (x) { return !x.ok && x.code === "invalid_url"; }) && g.requests.length === 0,
    J([sNoProf.msg, sGoogle.code, sPath.code, sYtAtTt.code, sApiHost.code, sLook.code, sHttp.code, sPort.code]));
  const s201 = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/upload/e201", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  check("S2. tiktok: an empty 201 is done (json null)", s201.ok && s201.v.status === 201 && s201.v.json === null, s201.ok ? J(s201.v) : s201.code);
  const s308 = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/upload/redirect", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  check("S3. tiktok: a 308 is not allowed (redirected)", !s308.ok && s308.code === "redirected", s308.ok ? J(s308.v) : s308.code);
  const sHtml = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/upload/html", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  const s200 = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/upload/empty200", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  // NAMED (Nov 18 2026, TK5): BEFORE a 201 with an HTML body was unaccepted_type and an empty 200 refused. AFTER the tiktok
  // profile is judged by status only: both come back with their status (lib/tiktokApi.js decides; only 201 is done).
  check("S4. tiktok: a 201 with an HTML body, and an empty 200, come back with their status, content type and body size (status only)",
    sHtml.ok && sHtml.v.status === 201 && sHtml.v.contentType === "text/html" && sHtml.v.bodyBytes === 9 && sHtml.v.json === null &&
    s200.ok && s200.v.status === 200 && s200.v.bodyBytes === 0, J([sHtml.ok ? sHtml.v : sHtml.code, s200.ok ? s200.v : s200.code]));
  const sYt201 = await attempt(g.streamUpload("https://www.googleapis.com/upload/e201", { profile: "youtube", method: "PUT", body: null, contentLength: 0 }));
  check("S5. youtube is not loosened: an empty 201 is still refused there", !sYt201.ok, sYt201.ok ? J(sYt201.v) : sYt201.code);
  // NAMED (Nov 18 2026, TK5): YouTube's profile is unchanged: a 201 in plain text, or broken JSON, is still refused there.
  const sYtPlain = await attempt(g.streamUpload("https://www.googleapis.com/upload/plain201", { profile: "youtube", method: "PUT", body: null, contentLength: 0 }));
  const sYtBad = await attempt(g.streamUpload("https://www.googleapis.com/upload/badjson201", { profile: "youtube", method: "PUT", body: null, contentLength: 0 }));
  check("S7. TK5: youtube still requires JSON: a 201 in text/plain is unaccepted_type, a 201 of broken JSON is not_json",
    !sYtPlain.ok && sYtPlain.code === "unaccepted_type" && !sYtBad.ok && sYtBad.code === "not_json", J([sYtPlain.ok ? sYtPlain.v : sYtPlain.code, sYtBad.ok ? sYtBad.v : sYtBad.code]));
  const sTtPlain = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/upload/plain201", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  const sTtBad = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/upload/badjson201", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  const sTtBig = await attempt(g.streamUpload("https://open-upload.tiktokapis.com/upload/big201", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  check("S8. TK5: tiktok never throws not_json: a 201 \"OK\" in text/plain and a 201 of broken JSON come back as 201 (json null); a 200 KB body is read to 64 KB only",
    sTtPlain.ok && sTtPlain.v.status === 201 && sTtPlain.v.bodyBytes === 2 && sTtPlain.v.json === null && sTtPlain.v.contentType === "text/plain" &&
    sTtBad.ok && sTtBad.v.status === 201 && sTtBad.v.json === null && sTtBig.ok && sTtBig.v.status === 201 && sTtBig.v.bodyBytes === 65536,
    J([sTtPlain.ok ? sTtPlain.v : sTtPlain.code, sTtBad.ok ? sTtBad.v : sTtBad.code, sTtBig.ok ? sTtBig.v.bodyBytes : sTtBig.code]));
  // NAMED (Nov 18 2026, TK2): BEFORE tiktok { host: "open-upload.tiktokapis.com", pathPrefix: "/upload/" }. AFTER a host pattern and two prefixes.
  const ttProf = GF.STREAM_PROFILES.tiktok;
  check("S6. the two profiles, as named", J(GF.STREAM_PROFILES.youtube) === J({ host: "www.googleapis.com", pathPrefix: "/upload/", allow308: true, emptyOkStatuses: [] }) &&
    // NAMED (Nov 18 2026, TK3): BEFORE hostPattern (upload hosts only) and pathPrefixes ["/video/", "/upload/"]. AFTER the shared
    // TIKTOK_UPLOAD_HOST_RE (any subdomain of tiktokapis.com) and TIKTOK_UPLOAD_PATH_RE ("/upload" or "/video", slash optional).
    // NAMED (Nov 18 2026, TK5): BEFORE emptyOkStatuses [201, 206]. AFTER statusOnly true and answerMaxBytes 64 KB.
    // NAMED (Nov 18 2026, BV1): AFTER maxUploadBytes 128 MB too (a final chunk; BV12).
    Object.keys(ttProf).join() === "hostPattern,pathPattern,allow308,statusOnly,answerMaxBytes,maxUploadBytes" && ttProf.statusOnly === true && ttProf.answerMaxBytes === 65536 &&
    ttProf.maxUploadBytes === 128000000 &&
    // NAMED (Nov 18 2026, TK4): BEFORE tiktokapis\\.com$ only. AFTER tiktokapis\\.(?:com|us)$.
    String(ttProf.hostPattern) === "/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+tiktokapis\\.(?:com|us)$/" && String(ttProf.pathPattern) === "/^\\/(?:upload|video)(?:\\/|$)/" &&
    ttProf.hostPattern === GF.TIKTOK_UPLOAD_HOST_RE && ttProf.pathPattern === GF.TIKTOK_UPLOAD_PATH_RE &&
    ttProf.allow308 === false && Object.isFrozen(GF.STREAM_PROFILES) && Object.isFrozen(ttProf),
    J([String(ttProf.hostPattern), String(ttProf.pathPattern)]));

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
  // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): and a published Facebook video post; again only the platform under test differs.
  [bothV, ytOnly, heldV].forEach(function (v) { db.t.facebook_posts.push({ id: uuid(), user_id: USER, kind: "video", status: "published", post_id: "1200000000000009", video_id: v.id, created_at: iso(now - 600000) }); });
  const tick =await MV.retentionTick({ supabase: db, storage: db.storage, now: function () { return now; } }, now);
  const rowIn = function (id) { return db.t.member_videos.filter(function (x) { return x.id === id; })[0]; };
  check("J1. YouTube, TikTok, Instagram AND Facebook have it (NAMED, item 8 parts 3a and 3b: Instagram, then Facebook added): the file deleted at once, status uploaded (a platform got it)", !db.storage.objects[bothV.path] && rowIn(bothV.id).status === "uploaded" && rowIn(bothV.id).path === null, J(tick));
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
    // NAMED (Nov 17 2026, TK1): BEFORE "...TikTok keeps posts from BizForce visible only to you." AFTER the account must be private too.
    FILES.page.indexOf("<p class=\"bsky-quiet\">Until TikTok reviews BizForce, your TikTok account must be set to private, and TikTok keeps posts from BizForce visible only to you.</p>") !== -1 &&
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
  // NAMED (Nov 12 2026, Social page clean-up): BEFORE "Prepare TikTok post"; AFTER "Prepare for TikTok" (shown while TikTok is connected).
  const prepBtn = findAll(list, function (n) { return n.tagName === "BUTTON" && n.textContent === "Prepare for TikTok"; });
  check("P11. a ready video not on TikTok gets \"Prepare for TikTok\"; a posted one gets its tiktok.com link, the remove line and no remove button",
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
    // NAMED (Nov 17 2026, TK1): the review line now says the account must be private.
    findAll(list, function (n) { return n.tagName === "P" && n.textContent === "Until TikTok reviews BizForce, your TikTok account must be set to private, and TikTok keeps posts from BizForce visible only to you."; }).length === 1);
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
  // NAMED (Nov 12 2026, Social page clean-up): BEFORE sel.parentNode.parentNode.parentNode (label, fields, box). AFTER the
  // open form's panel, data-form "<video id>:tiktok", which holds the privacy select.
  const ttForm = findAll(list, function (n) { return n.attrs && n.attrs["data-form"] === PAGE_VIDEO.id + ":tiktok"; })[0] || list;
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
  // NAMED (Nov 12 2026, Social page clean-up): BEFORE the first textarea was the caption. AFTER the AI helper comes first,
  // so the caption is the textarea its "Caption" label names.
  const capLabel = findAll(ttForm, function (n) { return n.tagName === "LABEL" && n.textContent === "Caption"; })[0];
  findAll(ttForm, function (n) { return n.tagName === "TEXTAREA" && !!capLabel && n.id === capLabel.attrs.for; })[0].value = "Spring cakes.";
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
    // NAMED (Nov 17 2026, TK1): BEFORE tiktokResultHtml(result). AFTER it also takes the video id, for the status polling.
    /function tiktokPostPayloadFields\(payload\)/.test(FILES.proposals) && /function tiktokResultHtml\(result, videoId\)/.test(FILES.proposals) &&
    FILES.proposals.indexOf("fieldsHtml = tiktokPostPayloadFields(p.payload || {});") !== -1 && FILES.proposals.indexOf("execHtml = tiktokResultHtml(p.execution_result, p.payload && p.payload.video_id);") !== -1 &&
    FILES.proposals.indexOf("<pre class=\"exec-block tt-caption\">' + escapeHtml(String(payload.caption == null ? \"\" : payload.caption))") !== -1 &&
    FILES.proposals.indexOf("/^https:\\/\\/www\\.tiktok\\.com\\/player\\/v1\\/[0-9]{1,64}$/.test(result.post_url)") !== -1 &&
    FILES.proposals.indexOf("To remove a TikTok post, delete it in the TikTok app.") !== -1);
  const card = function (name) { return (new RegExp("<p class=\"int-card-name\">" + name.replace("/", "\\/") + "</p>\\s*<p class=\"int-card-desc\">([^<]*)</p>\\s*<span class=\"int-status\">([^<]*)</span>").exec(FILES.integrations) || []); };
  check("P25. Integrations: TikTok and YouTube say they connect on the Social page (not Removed), and say what is true until review",
    card("TikTok")[2] === "On the Social page" && /Social Agent page/.test(card("TikTok")[1] || "") && /visible only to you/.test(card("TikTok")[1] || "") &&
    // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): BEFORE Facebook was Removed; AFTER it connects on the Social page too.
    card("YouTube")[2] === "On the Social page" && /keeps uploads from BizForce private/.test(card("YouTube")[1] || "") && card("Facebook")[2] === "On the Social page");
  check("P26. the guide tips: Social names TikTok as connecting, Integrations names the new state; still 4 Integrations tips",
    // NAMED (Nov 7 2026, Instagram posting, migration 179): BEFORE "Bluesky, Mastodon, YouTube and TikTok connect so far"; AFTER Instagram is named too.
    // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): AFTER Facebook Pages are named after Instagram.
    FILES.guide.indexOf("Bluesky, Mastodon, YouTube, TikTok, Instagram and Facebook Pages connect so far, and posts cannot be scheduled") !== -1 &&
    ((/"integrations\.html": \[([\s\S]*?)\n    \]/.exec(FILES.guide) || ["", ""])[1].match(/\n      "/g) || []).length === 4 &&
    FILES.guide.indexOf("\\\"On the Social page\\\"") !== -1);

  /* ── K ── NAMED (Nov 17 2026, TK1): TikTok's content-sharing guidelines (developers.tiktok.com/docs/en/content-sharing-guidelines). */
  OUT("\n══ K. TK1: length, preview, declaration, processing, disclosure, wording ══");
  // K1-K4: the length, read from the file (moov > mvhd) as it streams past
  const box = function (type, body) { const h = Buffer.alloc(8); h.writeUInt32BE(8 + body.length); h.write(type, 4, "latin1"); return Buffer.concat([h, body]); };
  const mvhd0 = function (timescale, duration) { const b = Buffer.alloc(100); b[0] = 0; b.writeUInt32BE(timescale, 12); b.writeUInt32BE(duration, 16); return box("mvhd", b); };
  const mvhd1 = function (timescale, duration) { const b = Buffer.alloc(112); b[0] = 1; b.writeUInt32BE(timescale, 20); b.writeBigUInt64BE(BigInt(duration), 24); return box("mvhd", b); };
  const ftyp = box("ftyp", Buffer.from("isom\0\0\x02\0isomiso2", "latin1"));
  const movie = function (mv, moovFirst) {
    const moov = box("moov", Buffer.concat([mv, box("trak", filler(300, 5))]));
    const mdat = box("mdat", filler(20000, 6));
    return Buffer.concat(moovFirst ? [ftyp, moov, mdat] : [ftyp, mdat, moov]);
  };
  const readIn = function (buf, step) { const rd = MV.durationReader(); for (let i = 0; i < buf.length; i += step) rd.push(buf.subarray(i, i + step)); return rd.result(); };
  const v0 = movie(mvhd0(600, 75300), false);
  check("K1. mvhd version 0 (timescale 600, duration 75300 = 125.5 s) read as 125500 ms, whatever the chunk sizes (1, 7, 64 bytes, all at once)",
    [1, 7, 64, v0.length].every(function (n) { return readIn(v0, n) === 125500; }), J([1, 7, 64].map(function (n) { return readIn(v0, n); })));
  check("K2. version 1 (64-bit) with moov before mdat: 90 s; a file with no moov, or a broken box: null (never a guess)",
    readIn(movie(mvhd1(90000, 8100000), true), 4096) === 90000 && readIn(Buffer.concat([ftyp, box("mdat", filler(5000, 7))]), 512) === null &&
    readIn(Buffer.concat([ftyp, Buffer.from([0, 0, 0, 4, 0x6d, 0x6f, 0x6f, 0x76])]), 512) === null);
  check("K3. the browser's length is believed only when the bitrate it implies is plausible (1 kB/s to 25 MB/s) and it is 1 ms to 4 hours",
    MV.browserDuration(60000, 3000000) === 60000 && MV.browserDuration(1, 3000000) === null && MV.browserDuration(60000, 10) === null &&
    MV.browserDuration(14400001, 52428800) === null && MV.browserDuration("60000", 3000000) === null && MV.browserDuration(60000.5, 3000000) === null);
  // K4-K5: finalize stores it
  let kdb = makeDb(); kdb.storage = makeStorage();
  const kDeps = { supabase: kdb, storage: kdb.storage, now: function () { return Date.now(); } };
  const kFile = movie(mvhd0(1000, 61000), false);
  const kPath = videoPath(USER);
  kdb.storage.objects[kPath] = { buf: kFile, created_at: new Date().toISOString() };
  let fin1 = await MV.finalize(kDeps, USER, { path: kPath, label: "Clip", bytes: kFile.length, duration_ms: 5000 });
  const kRow = kdb.t.member_videos.filter(function (x) { return x.path === kPath; })[0];
  check("K4. adding an MP4: duration_ms is the file's own (61 s), not the browser's (5 s); the list shows it",
    fin1.status === 201 && !!kRow && kRow.duration_ms === 61000 && fin1.body.video.duration_ms === 61000, J([fin1.status, fin1.body, kRow && kRow.duration_ms]));
  const kNoMoov = mp4(40000, 51);
  const kPath2 = videoPath(USER);
  kdb.storage.objects[kPath2] = { buf: kNoMoov, created_at: new Date().toISOString() };
  fin1 = await MV.finalize(kDeps, USER, { path: kPath2, label: "Clip 2", bytes: kNoMoov.length, duration_ms: 12000 });
  const kRow2 = kdb.t.member_videos.filter(function (x) { return x.path === kPath2; })[0];
  check("K5. an MP4 with no readable mvhd: the browser's plausible length (12 s) is kept", fin1.status === 201 && !!kRow2 && kRow2.duration_ms === 12000, J([fin1.status, kRow2 && kRow2.duration_ms]));
  kdb.t.member_videos = kdb.t.member_videos.filter(function (x) { return x.path !== kPath && x.path !== kPath2; });
  const kPath3 = videoPath(USER);
  kdb.storage.objects[kPath3] = { buf: kNoMoov, created_at: new Date().toISOString() };
  fin1 = await MV.finalize(kDeps, USER, { path: kPath3, label: "Clip 3", bytes: kNoMoov.length, duration_ms: 3600000 });
  const kRow3 = kdb.t.member_videos.filter(function (x) { return x.path === kPath3; })[0];
  check("K6. ...an implausible browser length (an hour for 40 kB) is not: duration_ms stays NULL (unknown)", fin1.status === 201 && !!kRow3 && kRow3.duration_ms === null, J([fin1.status, kRow3 && kRow3.duration_ms]));
  // K7-K10: filing
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(4000, 52), { duration_ms: null });
  r = await file(m, video);
  check("K7. filing a video whose length is unknown (added before TK1): 422 duration_unknown, the member told to add it again, nothing filed",
    r.status === 422 && r.body.code === "duration_unknown" && r.body.error === "BizForce doesn't know how long this video is, and TikTok needs that checked. Delete it from Your videos and add it again. Nothing was filed." &&
    m.db.t.agent_proposals.length === 0 && m.tiktok.initCalls().length === 0, J(r.body));
  video = seedVideo(m.db, mp4(4000, 53), { duration_ms: 301000 });
  r = await file(m, video);
  check("K8. a video longer than creator_info's max_video_post_duration_sec (301 s against 300): refused naming kBoth lengths, nothing filed",
    r.status === 422 && r.body.code === "too_long" && r.body.error === "This video is 5 min 1 s long, and TikTok lets this account post videos up to 5 min. Nothing was filed." &&
    m.db.t.agent_proposals.length === 0, J(r.body));
  video = seedVideo(m.db, mp4(4000, 54), { duration_ms: 300000 });
  r = await file(m, video);
  check("K9. exactly the limit (300 s) is filed", r.status === 201 && m.db.t.agent_proposals.length === 1, J(r.body));
  m = mountRoutes({ env: CONFIGURED, tiktok: { creator: { max_video_post_duration_sec: null } } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(4000, 55));
  r = await file(m, video);
  check("K10. creator_info naming no limit: refused (the length can't be checked), nothing filed", r.status === 422 && r.body.code === "too_long" &&
    /TikTok didn't say how long a video this account may post/.test(r.body.error || "") && m.db.t.agent_proposals.length === 0, J(r.body));
  // K11: approval, against TikTok's answer then
  m = mountRoutes({ env: CONFIGURED, tiktok: { creator: { max_video_post_duration_sec: 30 } } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(4000, 56), { duration_ms: 45000 });
  a = await approve(m, proposalOf(video));
  check("K11. at approval the length is checked again against a fresh creator_info (now 30 s): refused naming both, no init, nothing sent",
    !a.ok && /This video is 45 s long, and TikTok lets this account post videos up to 30 s\. Nothing was sent\./.test(a.msg || "") && m.tiktok.initCalls().length === 0 && m.tiktok.puts().length === 0, a.msg);
  video = seedVideo(m.db, mp4(4000, 57), { duration_ms: null });
  a = await approve(m, proposalOf(video));
  check("K12. ...and an unknown length is refused at approval too", !a.ok && /BizForce doesn't know how long this video is/.test(a.msg || "") && m.tiktok.initCalls().length === 0, a.msg);
  // K13-K14: creator_info saying the account can't post more now
  m = mountRoutes({ env: CONFIGURED, tiktok: { creatorError: "spam_risk_too_many_posts" } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(4000, 58));
  r = await file(m, video);
  const civ = await hit(m, "get /api/tiktok/creator-info", {});
  check("K13. creator_info answering spam_risk_too_many_posts: \"TikTok says this account can't post more right now. Try again later. Nothing was filed.\" (filing and the form)",
    r.status === 409 && r.body.code === "cannot_post_now" && r.body.error === "TikTok says this account can't post more right now. Try again later. Nothing was filed." &&
    civ.status === 409 && civ.body.error === r.body.error && m.db.t.agent_proposals.length === 0, J([r.body, civ.body]));
  a = await approve(m, proposalOf(video));
  check("K14. ...and at approval: stopped, nothing sent", !a.ok && /TikTok says this account can't post more right now\. Try again later\. Nothing was sent\./.test(a.msg || "") && m.tiktok.initCalls().length === 0, a.msg);
  check("K15. the 5-a-day message names it as BizForce's own limit; the review line says the account must be private",
    TK.MESSAGES.dailyCap === "BizForce's own limit is 5 TikTok posts in 24 hours. Nothing was sent. Try again later." &&
    TK.MESSAGES.reviewed === "Until TikTok reviews BizForce, your TikTok account must be set to private, and TikTok keeps posts from BizForce visible only to you.", TK.MESSAGES.dailyCap);
  // K16-K18: the processing notice, and the status fetch single-flight
  m = mountRoutes({ env: CONFIGURED, tiktok: { status: "PROCESSING_UPLOAD" } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(6000, 59));
  a = await approve(m, proposalOf(video));
  check("K16. a sent post TikTok is still processing carries the notice \"TikTok may take a few minutes to process this video before it appears on your profile.\"",
    a.ok && a.v.processing === true && a.v.notice === "TikTok may take a few minutes to process this video before it appears on your profile.", a.ok ? J(a.v) : a.msg);
  const sBefore = m.tiktok.statusCalls().length;
  const kBoth = await Promise.all([hit(m, "get /api/tiktok/videos/:id/status", { params: { id: video.id } }), hit(m, "get /api/tiktok/videos/:id/status", { params: { id: video.id } })]);
  check("K17. two status asks at once for one video: ONE fetch to TikTok, both answered, with the notice while processing",
    m.tiktok.statusCalls().length - sBefore === 1 && kBoth.every(function (x) { return x.status === 200 && x.body.tiktok_status === "processing" && x.body.notice === TK.MESSAGES.processingNotice; }),
    J([m.tiktok.statusCalls().length - sBefore, kBoth.map(function (x) { return x.body; })]));
  r = await hit(m, "get /api/tiktok/videos/:id/status", { params: { id: video.id } });
  check("K18. ...and a later ask fetches again (the single flight is only while one runs)", m.tiktok.statusCalls().length - sBefore === 2 && r.status === 200, m.tiktok.statusCalls().length - sBefore);
  // K19-K20: the preview address
  m = mountRoutes({ env: CONFIGURED });
  video = seedVideo(m.db, mp4(3000, 60));
  const pv = await MV.previewUrl({ supabase: m.db, storage: m.db.storage }, USER, video.id);
  const pvOther = await MV.previewUrl({ supabase: m.db, storage: m.db.storage }, OTHER, video.id);
  rowOf(m, video.id).status = "uploaded"; rowOf(m, video.id).path = null;
  const pvGone = await MV.previewUrl({ supabase: m.db, storage: m.db.storage }, USER, video.id);
  check("K19. the preview: a signed address to the member's own file for 10 minutes; another member's video is not found; a deleted file is 410 file_gone",
    pv.status === 200 && pv.body.url.indexOf("https://check.supabase.co/") === 0 && pv.body.expires_in === 600 && pvOther.status === 404 &&
    pvGone.status === 410 && pvGone.body.code === "file_gone" && pvGone.body.error === "This video's file was deleted, so there is nothing to preview.", J([pv, pvOther, pvGone]));
  check("K20. server.js: GET /api/videos/:id/preview, login only, never cached, answering previewUrl",
    /app\.get\("\/api\/videos\/:id\/preview", requireAuth, async function \(req, res, next\) \{\n  try \{\n    res\.set\("Cache-Control", "no-store"\);\n    var out = await require\("\.\/lib\/memberVideos"\)\.previewUrl\(youtubeDeps\(\), req\.user\.id, req\.params\.id\);/.test(FILES.server));
  // K21-K27: the Social page's TikTok form
  dom = runPage("", pageAnswers());
  await flush();
  let klist = dom.get("ytVideoList");
  findAll(klist, function (n) { return n.tagName === "BUTTON" && n.textContent === "Prepare for TikTok"; })[0].click();
  await flush();
  const kvid = findAll(klist, function (n) { return n.tagName === "VIDEO"; })[0];
  check("K21. the form shows a preview of the file: a video from the signed address, muted, with controls, not autoplaying",
    !!kvid && kvid.src === PREVIEW_URL && kvid.muted === true && kvid.controls === true && kvid.autoplay === false && kvid.attrs.muted === "" &&
    dom.fetches.some(function (x) { return x.path === "/api/videos/" + PAGE_VIDEO.id + "/preview" && x.method === "GET"; }), kvid ? J([kvid.src, kvid.muted, kvid.controls, kvid.autoplay]) : "no video");
  check("K22. ...and the length against TikTok's limit: \"Length 45 s; TikTok allows this account up to 5 min.\"",
    findAll(klist, function (n) { return n.tagName === "P" && n.textContent === "Length 45 s; TikTok allows this account up to 5 min."; }).length === 1);
  const kForm = findAll(klist, function (n) { return n.attrs && n.attrs["data-form"] === PAGE_VIDEO.id + ":tiktok"; })[0] || klist;
  const kDecl = findAll(kForm, function (n) { return n.tagName === "P" && /^By posting, you agree to TikTok's/.test(n.textContent); })[0];
  const kRowBtn = findAll(kForm, function (n) { return n.tagName === "BUTTON" && n.textContent === "File for approval"; })[0];
  const links = kDecl ? findAll(kDecl, function (n) { return n.tagName === "A"; }) : [];
  check("K23. the declaration links \"Music Usage Confirmation\" to TikTok's page (new tab, noopener), directly above the File for approval row",
    !!kDecl && links.length === 1 && links[0].textContent === "Music Usage Confirmation" && links[0].href === "https://www.tiktok.com/legal/page/global/music-usage-confirmation/en" &&
    links[0].target === "_blank" && links[0].rel === "noopener" && !!kRowBtn &&
    kDecl.parentNode.children.indexOf(kDecl) + 1 === kDecl.parentNode.children.indexOf(kRowBtn.parentNode), kDecl ? J(links.map(function (l) { return [l.textContent, l.href]; })) : "none");
  const kBoxes = findAll(kForm, function (n) { return n.tagName === "INPUT" && n.type === "checkbox"; });
  const kNamed = function (name) { return kBoxes.filter(function (bx) { return bx.parentNode && bx.parentNode.textContent.indexOf(name) !== -1; })[0]; };
  const kDis = kNamed("Disclose video content"), kYb = kNamed("Your brand"), kBc = kNamed("Branded content");
  check("K24. File for approval is on while Disclose is off", kRowBtn.disabled === false);
  kDis.checked = true; kDis.fire("change");
  check("K25. Disclose on with no option chosen: File for approval is disabled, its title saying what to choose",
    kRowBtn.disabled === true && kRowBtn.title === "Choose Your brand, Branded content, or both.", J([kRowBtn.disabled, kRowBtn.title, kDis.checked]));
  kBc.checked = true; kBc.fire("change");
  const kSel = findAll(kForm, function (n) { return n.tagName === "SELECT"; })[0];
  const kSelf = kSel.children.filter(function (o) { return o.value === "SELF_ONLY"; })[0];
  const links2 = findAll(kDecl, function (n) { return n.tagName === "A"; });
  check("K26. Branded content chosen: the button is on again; \"Only you\" disabled with the title \"Branded content visibility cannot be set to private.\"; the declaration links kBoth policies",
    kRowBtn.disabled === false && kSelf.disabled === true && kSelf.title === "Branded content visibility cannot be set to private." &&
    J(links2.map(function (l) { return [l.textContent, l.href]; })) === J([["Branded Content Policy", "https://www.tiktok.com/legal/page/global/bc-policy/en"], ["Music Usage Confirmation", "https://www.tiktok.com/legal/page/global/music-usage-confirmation/en"]]) &&
    kDecl.textContent === "By posting, you agree to TikTok's Branded Content Policy and Music Usage Confirmation.");
  kBc.checked = false; kDis.checked = false; kDis.fire("change");
  check("K27. ...Branded content off: \"Only you\" can be chosen again, its title cleared", kSelf.disabled === false && kSelf.title === "");
  dom = runPage("", pageAnswers({ "GET /api/videos": { status: 200, body: { videos: [Object.assign({}, PAGE_VIDEO, { duration_ms: null })] } },
    ["GET /api/videos/" + PAGE_VIDEO.id + "/preview"]: { status: 410, body: { error: "This video's file was deleted, so there is nothing to preview.", code: "file_gone" } } }));
  await flush();
  klist = dom.get("ytVideoList");
  findAll(klist, function (n) { return n.tagName === "BUTTON" && n.textContent === "Prepare for TikTok"; })[0].click();
  await flush();
  check("K28. a deleted file: no player, \"This video's file was deleted, so it can't be previewed or posted.\"; an unknown length says to add it again",
    findAll(klist, function (n) { return n.tagName === "VIDEO"; }).length === 0 &&
    findAll(klist, function (n) { return n.tagName === "P" && n.textContent === "This video's file was deleted, so it can't be previewed or posted."; }).length === 1 &&
    findAll(klist, function (n) { return n.tagName === "P" && /^BizForce doesn't know this video's length/.test(n.textContent) && /add it again\.$/.test(n.textContent); }).length === 1);
  // K29-K31: a processing video is asked about on its own
  const PROC = Object.assign({}, PAGE_VIDEO, { tiktok_status: "processing" });
  let kAnswer = { status: 200, body: { tiktok_status: "processing", tiktok_says: "PROCESSING_UPLOAD", post_url: null } };
  dom = runPage("", pageAnswers({ "GET /api/videos": { status: 200, body: { videos: [PROC] } }, ["GET /api/tiktok/videos/" + PROC.id + "/status"]: kAnswer }));
  await flush();
  const statusAsks = function () { return dom.fetches.filter(function (x) { return x.path === "/api/tiktok/videos/" + PROC.id + "/status"; }).length; };
  const shown = function () { return findAll(dom.get("ytVideoList"), function () { return true; }).map(function (n) { return n._t; }); };
  check("K29. a video TikTok is processing: the notice shown at once and ONE ask scheduled after 10 s (none yet)",
    dom.timers.length === 1 && dom.timers[0].ms === 10000 && statusAsks() === 0 &&
    shown().indexOf("TikTok may take a few minutes to process this video before it appears on your profile.") !== -1, J([dom.timers.map(function (t) { return t.ms; }), statusAsks()]));
  for (let i = 0; i < 8; i++) { const t = dom.timers[i]; if (!t) break; t.fn(); await flush(); }
  check("K30. still processing: asked 5 times, waiting 10, 20, 40, 80 and 160 s, then it stops and points to Check TikTok status (still there)",
    statusAsks() === 5 && J(dom.timers.map(function (t) { return t.ms; })) === J([10000, 20000, 40000, 80000, 160000]) &&
    shown().indexOf("TikTok is still processing it. Use Check TikTok status later.") !== -1 &&
    findAll(dom.get("ytVideoList"), function (n) { return n.tagName === "BUTTON" && n.textContent === "Check TikTok status"; }).length === 1,
    J([statusAsks(), dom.timers.map(function (t) { return t.ms; })]));
  dom = runPage("", pageAnswers({ "GET /api/videos": { status: 200, body: { videos: [PROC] } },
    ["GET /api/tiktok/videos/" + PROC.id + "/status"]: { status: 200, body: { tiktok_status: "posted", post_url: "https://www.tiktok.com/player/v1/" + POST_ID } } }));
  await flush();
  const vids0 = dom.fetches.filter(function (x) { return x.path === "/api/videos"; }).length;
  dom.timers[0].fn(); await flush();
  const vids1 = dom.fetches.filter(function (x) { return x.path === "/api/videos"; }).length;
  check("K31. a final answer (posted) stops the asking and redraws the list; the redraw does not start a second poll (single flight per video)",
    statusAsks() === 1 && vids1 === vids0 + 1 && dom.timers.length === 1, J([statusAsks(), vids0, vids1, dom.timers.length]));
  // K32-K36: the proposal card (proposals.html's TikTok functions, run on their own)
  const propSrc = (function () { const a0 = FILES.proposals.indexOf("var TIKTOK_PRIVACY_WORDS"); const b0 = FILES.proposals.indexOf("// A publish_instagram_post proposal"); return a0 !== -1 && b0 > a0 ? FILES.proposals.slice(a0, b0) : ""; })();
  const pctx = { timers: [], fetched: [], answers: {}, nodes: {} };
  const pc = { API_URL: API, token: "tok", Promise: Promise, JSON: JSON, String: String, Object: Object, Array: Array, Math: Math,
    escapeHtml: function (t) { return String(t == null ? "" : t).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); },
    youtubeSize: function (b) { return String(b) + " bytes"; },
    setTimeout: function (fn, ms) { pctx.timers.push({ fn: fn, ms: ms }); },
    fetch: function (u) { const p0 = String(u).replace(API, ""); pctx.fetched.push(p0); const ans = pctx.answers[p0] || { status: 404, body: {} };
      return Promise.resolve({ ok: ans.status < 300, status: ans.status, json: function () { return Promise.resolve(ans.body); } }); },
    document: { createElement: function (t) { return { tagName: t.toUpperCase(), attrs: {}, setAttribute: function (k, v) { this.attrs[k] = v; } }; },
      querySelectorAll: function (sel) { return pctx.nodes[sel] || []; } } };
  vm.createContext(pc);
  let propOk = true;
  // NAMED (Nov 19 2026, LOGO2): LOGO1 lifted approvalMark and postedMark here; LOGO2 took them off proposals.html (8d29b93 again), so this is as before LOGO1.
  try { vm.runInContext(propSrc + "\n;this.F = { fields: tiktokPostPayloadFields, decl: tiktokDeclarationHtml, result: tiktokResultHtml, previews: fillTiktokPreviews, poll: pollTiktokStatus };", pc); } catch (e) { propOk = false; }
  const PF = propOk ? pc.F : null;
  const cardHtml = PF ? PF.fields(payloadOf({ id: PAGE_VIDEO.id, sha256: "a".repeat(64), bytes: 100, mime: "video/mp4" }, { creator_nickname: "Maple <Street>" })) : "";
  check("K32. the card's account field is the nickname filed with the post (escaped); a post filed before TK1 keeps \"your connected TikTok account\"; the private-account line",
    cardHtml.indexOf('<span class="pf-value tt-account">Maple &lt;Street&gt;</span>') !== -1 &&
    PF.fields({}).indexOf('<span class="pf-value tt-account">your connected TikTok account</span>') !== -1 &&
    cardHtml.indexOf("Until TikTok reviews BizForce, your TikTok account must be set to private, and TikTok keeps posts from BizForce visible only to you.") !== -1, cardHtml.slice(0, 300));
  check("K33. TikTok's declaration on the card, with both links, and the card puts it directly before the Approve row of a pending TikTok post only",
    !!PF && PF.decl({}) === '<p class="tt-declaration">By posting, you agree to TikTok\'s <a href="https://www.tiktok.com/legal/page/global/music-usage-confirmation/en" target="_blank" rel="noopener">Music Usage Confirmation</a>.</p>' &&
    PF.decl({ brand_content: true }).indexOf('<a href="https://www.tiktok.com/legal/page/global/bc-policy/en" target="_blank" rel="noopener">Branded Content Policy</a> and <a href="https://www.tiktok.com/legal/page/global/music-usage-confirmation/en"') !== -1 &&
    FILES.proposals.indexOf("    var actions = p.status === \"pending\"\n      ? (p.action_type === \"publish_tiktok_post\" ? tiktokDeclarationHtml(p.payload || {}) : '') +\n        '<div class=\"proposal-actions\">' +\n          '<button type=\"button\" class=\"btn-approve\"") !== -1);
  // the card's preview
  const msgNode = { textContent: "" };
  const spot = { kids: [], getAttribute: function () { return PAGE_VIDEO.id; }, querySelector: function () { return msgNode; }, appendChild: function (c) { this.kids.push(c); } };
  pctx.answers["/api/videos/" + PAGE_VIDEO.id + "/preview"] = { status: 200, body: { url: PREVIEW_URL } };
  if (PF) PF.previews({ querySelectorAll: function () { return [spot]; } });
  await flush();
  const cv = spot.kids[0];
  const msgGone = { textContent: "" };
  const spotGone = { kids: [], getAttribute: function () { return "44444444-4444-4444-8444-444444444444"; }, querySelector: function () { return msgGone; }, appendChild: function (c) { this.kids.push(c); } };
  pctx.answers["/api/videos/44444444-4444-4444-8444-444444444444/preview"] = { status: 410, body: { code: "file_gone" } };
  if (PF) PF.previews({ querySelectorAll: function () { return [spotGone]; } });
  await flush();
  check("K34. the card's preview: muted, controls, no autoplay, from the signed address; a deleted file says so",
    !!cv && cv.tagName === "VIDEO" && cv.src === PREVIEW_URL && cv.muted === true && cv.controls === true && cv.autoplay === false &&
    spotGone.kids.length === 0 && msgGone.textContent === "The video file was deleted, so it can't be previewed or posted.", J([cv, msgGone.textContent]));
  const resHtml = PF ? PF.result({ processing: true, status: "processing" }, PAGE_VIDEO.id) : "";
  check("K35. an approved post still processing: the card says it may take a few minutes, and names a spot for the live status",
    resHtml.indexOf("TikTok may take a few minutes to process this video before it appears on your profile.") !== -1 &&
    resHtml.indexOf('data-tt-poll-id="' + PAGE_VIDEO.id + '"') !== -1 && PF.result({ posted: true, post_url: "https://www.tiktok.com/player/v1/1" }).indexOf("may take a few minutes") !== -1);
  const live = { textContent: "", getAttribute: function () { return PAGE_VIDEO.id; } };
  pctx.nodes['[data-tt-poll-id="' + PAGE_VIDEO.id + '"]'] = [live];
  pctx.answers["/api/tiktok/videos/" + PAGE_VIDEO.id + "/status"] = { status: 200, body: { tiktok_status: "processing" } };
  if (PF) { PF.poll({ querySelectorAll: function () { return [live]; } }); PF.poll({ querySelectorAll: function () { return [live]; } }); }
  for (let i = 0; i < 8; i++) { const t = pctx.timers[i]; if (!t) break; t.fn(); await flush(); }
  const cardAsks = pctx.fetched.filter(function (x) { return x === "/api/tiktok/videos/" + PAGE_VIDEO.id + "/status"; }).length;
  check("K36. the card asks on its own, once per video however often it is drawn: 5 asks at 10, 20, 40, 80, 160 s, then it stops",
    cardAsks === 5 && J(pctx.timers.map(function (t) { return t.ms; })) === J([10000, 20000, 40000, 80000, 160000]) && /^still processing; use Check TikTok status/.test(live.textContent), J([cardAsks, pctx.timers.length, live.textContent]));
  check("K37. the wording: the Social page's TikTok card says the account must be private and that processing takes a few minutes; the token comment gives TikTok's 2 hours and 180 days",
    FILES.page.indexOf("<p class=\"bsky-quiet\">After you approve a post, TikTok may take a few minutes to process it before it appears on your profile.</p>") !== -1 &&
    FILES.auth.indexOf("an access token (expires_in; TikTok documents 2 hours), a refresh token\n   (refresh_expires_in; TikTok documents 180 days)") !== -1 &&
    !/an access token \(about 24 hours\)/.test(FILES.auth));

  /* ── BV ── NAMED (Nov 18 2026, BV1, migration 187): a video over 50 MB is stored as parts; TikTok's FILE_UPLOAD takes
     it in chunks when it is over 64 MB ("Videos with a total size greater than 64 MB must be uploaded in multiple chunks."),
     each 5 to 64 MB, the final one up to 128 MB, total_chunk_count = floor(video_size / chunk_size), sent in order, every
     chunk but the last answered 206 and the last 201 (developers.tiktok.com/doc/content-posting-api-media-transfer-guide). */
  OUT("\n══ BV. videos over 50 MB: parts and chunks ══");
  {
    const PB = MV.PART_BYTES;
    const seedParted = function (db, buf) {
      const row = seedVideo(db, buf, { part_count: MV.partSizes(buf.length).length });
      delete db.storage.objects[row.path];
      let at = 0;
      MV.partSizes(buf.length).forEach(function (n, i) {
        const b = buf.subarray(at, at + n); at += n;
        db.storage.objects[MV.partPath(row.path, i)] = { buf: b, created_at: new Date(Date.now() - 86400000).toISOString() };
        db.t.member_video_parts.push({ id: uuid(), user_id: row.user_id, video_id: row.id, upload_path: row.path, idx: i, path: MV.partPath(row.path, i), bytes: n, sha256: sha(b),
          created_at: new Date(Date.now() - 86400000).toISOString() });
      });
      return row;
    };
    const ttLines = function () { return LOGS.filter(function (x) { return x.indexOf("[tiktok] ") === 0; }); };
    const rulesHold = function (size) {
      const p = TK.chunkPlan(size);
      const r = p.ranges;
      return p.total_chunk_count === Math.floor(size / p.chunk_size) && r.length === p.total_chunk_count && p.total_chunk_count <= 1000 && r[0][0] === 0 && r[r.length - 1][1] === size &&
        r.every(function (x, i) { return (i === 0 || x[0] === r[i - 1][1]) && x[1] - x[0] >= 5 * 1000 * 1000 && (i === r.length - 1 ? x[1] - x[0] <= 128 * 1000 * 1000 && x[1] - x[0] >= p.chunk_size : x[1] - x[0] === p.chunk_size && p.chunk_size <= 64 * 1000 * 1000); });
    };
    const p64 = TK.chunkPlan(64000000), p64b = TK.chunkPlan(64000001), p500 = TK.chunkPlan(524288000);
    check("BV1. the chunk plan: at most 64 MB is ONE chunk (as before); above it chunks of a part (45 MiB) or half the video, floor(size / chunk) of them, the last taking the rest",
      TK.ONE_CHUNK_MAX === 64000000 && p64.total_chunk_count === 1 && p64.chunk_size === 64000000 && p64b.total_chunk_count === 2 && p64b.chunk_size === 32000000 &&
      J(p64b.ranges) === J([[0, 32000000], [32000000, 64000001]]) && p500.chunk_size === PB && p500.total_chunk_count === 11 && p500.ranges[10][1] - p500.ranges[10][0] === 524288000 - 10 * PB,
      J([p64b, p500.total_chunk_count, p500.chunk_size]));
    check("BV2. ...and TikTok's rules hold at every size from 64 MB to 500 MB: 5 to 64 MB each, the last at most 128 MB, in order, at most 1000",
      [64000001, 70000000, 94371840, 94371841, 100000000, 200000000, 333333333, 450000000, 524288000].every(rulesHold));
    check("BV3. sourceInfo: FILE_UPLOAD, video_size, chunk_size and total_chunk_count from the plan",
      J(TK.sourceInfo({ bytes: 70000000 })) === J({ source: "FILE_UPLOAD", video_size: 70000000, chunk_size: 35000000, total_chunk_count: 2 }) &&
      J(TK.sourceInfo({ bytes: 3000 })) === J({ source: "FILE_UPLOAD", video_size: 3000, chunk_size: 3000, total_chunk_count: 1 }));

    // a parted video of at most 64 MB: one chunk, as before
    const T1 = PB + 6 * 1024 * 1024;
    const buf1 = mp4(T1, 71);
    m = mountRoutes({ env: CONFIGURED });
    seedConnection(m.db);
    video = seedParted(m.db, buf1);
    LOGS.length = 0;
    a = await approve(m, proposalOf(video));
    let up = m.tiktok.uploads[Object.keys(m.tiktok.uploads)[0]] || {};
    let puts = m.tiktok.puts();
    check("BV4. a parted video of 64 MB or less: ONE chunk, ONE PUT \"bytes 0-(N-1)/N\" over both parts, chunk_size the whole size; TikTok has every byte",
      a.ok && J((m.tiktok.inits[0] || {}).source_info) === J({ source: "FILE_UPLOAD", video_size: T1, chunk_size: T1, total_chunk_count: 1 }) && puts.length === 1 &&
      puts[0].contentRange === "bytes 0-" + (T1 - 1) + "/" + T1 && puts[0].contentLength === String(T1) && up.done === true && sha(up.received) === sha(buf1),
      a.ok ? J(puts.map(function (x) { return x.contentRange; })) : a.msg);

    // over 64 MB: chunks
    const T2 = 70000000;
    const buf2 = mp4(T2, 72);
    m = mountRoutes({ env: CONFIGURED });
    seedConnection(m.db);
    video = seedParted(m.db, buf2);
    m.db.storage.calls.length = 0;
    LOGS.length = 0;
    a = await approve(m, proposalOf(video));
    up = m.tiktok.uploads[Object.keys(m.tiktok.uploads)[0]] || {};
    puts = m.tiktok.puts();
    check("BV5. over 64 MB: init says chunk_size 35000000 and total_chunk_count 2; two PUTs in order, \"bytes 0-34999999/70000000\" then \"bytes 35000000-69999999/70000000\"",
      a.ok && J((m.tiktok.inits[0] || {}).source_info) === J({ source: "FILE_UPLOAD", video_size: T2, chunk_size: 35000000, total_chunk_count: 2 }) && puts.length === 2 &&
      puts[0].contentRange === "bytes 0-34999999/70000000" && puts[0].contentLength === "35000000" && puts[1].contentRange === "bytes 35000000-69999999/70000000" &&
      puts[1].contentLength === "35000000" && puts.every(function (x) { return x.contentType === "video/mp4" && x.host === "open-upload.tiktokapis.com"; }),
      a.ok ? J(puts.map(function (x) { return x.contentRange; })) : a.msg);
    check("BV6. ...TikTok has every byte, in order (the fake answers 206 then 201), and the post goes on: processing, then posted",
      a.ok && up.done === true && up.chunks === 2 && sha(up.received) === sha(buf2) && ["processing", "posted"].indexOf(rowOf(m, video.id).tiktok_status) !== -1, J([up.chunks, rowOf(m, video.id).tiktok_status]));
    // NAMED (Nov 18 2026, BV2): BEFORE [p0, p1] for the check, then p0 for chunk 1 and p0, p1 for chunk 2 (the 35 MB edge
    // cuts through part 0, so it was read three times). AFTER one cursor for the send: each part once.
    check("BV7. the parts are streamed from Storage, each ONCE for the whole send although the chunk edge (35 MB) cuts through part 0, never downloaded whole",
      J(m.db.storage.calls.filter(function (x) { return x.op === "stream"; }).map(function (x) { return x.path; })) ===
        J([video.path, MV.partPath(video.path, 1)]) && !m.db.storage.calls.some(function (x) { return x.op === "whole"; }),
      J(m.db.storage.calls.map(function (x) { return x.op + " " + String(x.path).slice(-8); })));

    // a chunk refused
    m = mountRoutes({ env: CONFIGURED, tiktok: { putCode: "access_denied", putHttp: 403, putCodeAt: 1 } });
    seedConnection(m.db);
    video = seedParted(m.db, buf2);
    LOGS.length = 0;
    a = await approve(m, proposalOf(video));
    const r1 = [a.msg, ttLines(), m.tiktok.puts().length];
    m = mountRoutes({ env: CONFIGURED, tiktok: { putCode: "access_denied", putHttp: 403, putCodeAt: 2 } });
    seedConnection(m.db);
    video = seedParted(m.db, buf2);
    LOGS.length = 0;
    a = await approve(m, proposalOf(video));
    const r2 = [a.msg, ttLines(), m.tiktok.puts().length];
    check("BV8. the first chunk refused: no second PUT; logged with chunk=1/2; the card says what TikTok said",
      !!r1[0] && r1[2] === 1 && J(r1[1]) === J(["[tiktok] upload refused: http 403 access_denied The upload_url has expired. log_id=" + INIT_LOG_ID + " content_type=application/json chunk=1/2"]) &&
      /didn't finish\..* TikTok said: http 403 access_denied\.$/.test(r1[0] || ""), J(r1));
    check("BV9. the last chunk refused: logged with chunk=2/2, the same card", r2[2] === 2 &&
      J(r2[1]) === J(["[tiktok] upload refused: http 403 access_denied The upload_url has expired. log_id=" + INIT_LOG_ID + " content_type=application/json chunk=2/2"]) &&
      /TikTok said: http 403 access_denied\.$/.test(r2[0] || ""), J(r2));
    m = mountRoutes({ env: CONFIGURED, tiktok: { cutAt: 2 } });
    seedConnection(m.db);
    video = seedParted(m.db, buf2);
    LOGS.length = 0;
    a = await approve(m, proposalOf(video));
    const rc = ttLines();
    check("BV10. the second chunk cut off: logged as \"http none\" with chunk=2/2, and the card says it didn't finish",
      !a.ok && rc.length === 1 && /^\[tiktok\] upload refused: http none [a-z0-9_-]+ - log_id=- chunk=2\/2$/.test(rc[0]) && /didn't finish/.test(a.msg || ""), J([a.msg, rc]));
    m = mountRoutes({ env: CONFIGURED });
    seedConnection(m.db);
    video = seedParted(m.db, buf2);
    const swapped = Buffer.from(m.db.storage.objects[MV.partPath(video.path, 1)].buf); swapped[9] ^= 0xff;
    m.db.storage.objects[MV.partPath(video.path, 1)] = { buf: swapped, created_at: new Date().toISOString() };
    a = await approve(m, proposalOf(video));
    up = m.tiktok.uploads[Object.keys(m.tiktok.uploads)[0]] || {};
    // NAMED (Nov 18 2026, BV2): BEFORE refused before init (the separate check read). AFTER the send finds it: the first
    // chunk goes (206), the last one, carrying the changed part, never completes.
    check("BV11. a part changed after filing: the first chunk goes, the last (the changed part) never completes; the plain words; not posted",
      !a.ok && a.msg === "publish_tiktok_post: " + TK.MESSAGES.stopped && m.tiktok.inits.length === 1 && m.tiktok.puts().length === 1 && up.done !== true &&
      ["posted", "processing"].indexOf(rowOf(m, video.id).tiktok_status) === -1, a.msg);
    // the transport's caps
    const big = await attempt(m.tiktok.streamUpload(UPLOAD_BASE + "9", { profile: "tiktok", method: "PUT", headers: {}, body: require("stream").Readable.from([]), contentLength: 128000001, contentRange: "bytes 0-128000000/128000001" }));
    const ytBig = await attempt(m.tiktok.streamUpload("https://www.googleapis.com/upload/youtube/v3/videos?upload_id=x", { profile: "youtube", method: "PUT", headers: {}, body: require("stream").Readable.from([]), contentLength: 52428801 }));
    check("BV12. the transport: TikTok's profile takes a PUT of up to 128 MB (its final chunk), more is refused; YouTube's stays at 50 MiB",
      GF.STREAM_PROFILES.tiktok.maxUploadBytes === 128000000 && !("maxUploadBytes" in GF.STREAM_PROFILES.youtube) &&
      !big.ok && /from 0 to 128000000$/.test(big.msg || "") && !ytBig.ok && /from 0 to 52428800$/.test(ytBig.msg || ""), J([big.msg, ytBig.msg]));

    /* NAMED (Nov 18 2026, BV2): ONE storage read per send. The fake storage counts every stream it opens, per path. */
    const readsOf = function (mx) {
      const n = {};
      mx.db.storage.calls.forEach(function (x) { if (x.op === "stream") n[x.path] = (n[x.path] || 0) + 1; });
      return n;
    };
    m = mountRoutes({ env: CONFIGURED });
    seedConnection(m.db);
    const one1 = mp4(300000, 81);
    video = seedVideo(m.db, one1);
    m.db.storage.calls.length = 0;
    a = await approve(m, proposalOf(video));
    up = m.tiktok.uploads[Object.keys(m.tiktok.uploads)[0]] || {};
    check("ONE1. a video of one object: read from Storage exactly ONCE for the post (the PUT's guard is the check), and TikTok has every byte",
      a.ok && J(readsOf(m)) === J({ [video.path]: 1 }) && up.done === true && sha(up.received) === sha(one1), J([a.ok || a.msg, readsOf(m)]));
    // four parts, three chunks; the second part corrupted
    const T4 = 3 * PB + 6 * 1024 * 1024;
    const buf4 = mp4(T4, 82);
    m = mountRoutes({ env: CONFIGURED });
    seedConnection(m.db);
    video = seedParted(m.db, buf4);
    m.db.storage.calls.length = 0;
    a = await approve(m, proposalOf(video));
    up = m.tiktok.uploads[Object.keys(m.tiktok.uploads)[0]] || {};
    check("ONE2. a video of four parts (three chunks): each part read exactly ONCE, and TikTok has every byte",
      a.ok && J(readsOf(m)) === J({ [MV.partPath(video.path, 0)]: 1, [MV.partPath(video.path, 1)]: 1, [MV.partPath(video.path, 2)]: 1, [MV.partPath(video.path, 3)]: 1 }) &&
      m.tiktok.puts().length === 3 && up.done === true && sha(up.received) === sha(buf4), J([a.ok || a.msg, readsOf(m)]));
    m = mountRoutes({ env: CONFIGURED });
    seedConnection(m.db);
    video = seedParted(m.db, buf4);
    const vid4 = video.id;
    const mid4 = MV.partPath(video.path, 1);
    const bad4 = Buffer.from(m.db.storage.objects[mid4].buf); bad4[4096] ^= 0xff;
    m.db.storage.objects[mid4] = { buf: bad4, created_at: new Date().toISOString() };
    m.db.storage.calls.length = 0;
    LOGS.length = 0;
    a = await approve(m, proposalOf(video));
    up = m.tiktok.uploads[Object.keys(m.tiktok.uploads)[0]] || {};
    puts = m.tiktok.puts();
    check("ONE3. a MIDDLE part corrupted: the first chunk goes (206), the send stops inside the middle part's chunk, and the LAST chunk is never sent",
      !a.ok && puts.length === 1 && puts[0].contentRange === "bytes 0-" + (PB - 1) + "/" + T4 &&
      !puts.some(function (x) { return String(x.contentRange).indexOf("bytes " + (2 * PB) + "-") === 0; }) && up.done !== true && up.received.length === PB,
      J([a.msg, puts.map(function (x) { return x.contentRange; })]));
    check("ONE4. ...the executor throws the plain words (so the proposal is marked failed with them); nothing is reported as posted",
      !a.ok && a.msg === "publish_tiktok_post: " + TK.MESSAGES.stopped && TK.MESSAGES.stopped === "The video file no longer matches the one you filed, so the upload was stopped before it finished. Nothing was posted." &&
      ["posted", "processing"].indexOf(rowOf(m, vid4).tiktok_status) === -1 && !rowOf(m, vid4).tiktok_post_id && !rowOf(m, vid4).tiktok_posted_at, J([a.msg, rowOf(m, vid4).tiktok_status]));
    check("ONE5. ...and the read stops there too: parts 1 and 2 read once each, parts 3 and 4 never read",
      J(readsOf(m)) === J({ [MV.partPath(video.path, 0)]: 1, [mid4]: 1 }), J(readsOf(m)));
  }

  /* ── G ── */
  /* ── X ── NAMED (Nov 18 2026, TK2): video/init per TikTok's Direct Post reference (developers.tiktok.com,
     content-posting-api-reference-direct-post, -media-transfer-guide, -get-started), every TikTok refusal logged as one
     line, TikTok's error code on the card. The live failure (Nov 17 2026): init answered error.code "ok" with an
     upload_url under /video/, which the old prefix rule refused ("TikTok didn't start the post. Nothing was sent."). */
  OUT("\n══ X. TK2: video/init per the docs, refusal logging, the code on the card ══");
  const XLINES = [];
  const tkLines = function () { const l = LOGS.filter(function (x) { return x.indexOf("[tiktok] ") === 0; }); l.forEach(function (x) { XLINES.push(x); }); return l; };
  const cleanLog = function (l) { return noSecretIn(l) && l.indexOf(OPEN_ID) === -1 && !/https?:|upload_id|upload_token|Bearer act|Bearer rft/.test(l) && l.length <= 300; };
  const cleanCard = function (s) { return noSecretIn(s) && String(s).indexOf(OPEN_ID) === -1 && !/https?:|upload_id|upload_token/.test(String(s)); };
  // X1-X2: a 2.1 MB file (the live clip's size), privacy Only you, comments, duet and stitch off
  m = mountRoutes({ env: CONFIGURED });
  seedConnection(m.db);
  buf = mp4(2100000, 51);
  video = seedVideo(m.db, buf, { duration_ms: 10000 });
  LOGS.length = 0;
  a = await approve(m, proposalOf(video, { privacy_level: "SELF_ONLY", allow_comment: false }));
  const xInit = m.tiktok.initCalls()[0] || {};
  const xTypes = [m.tiktok.creatorCalls()[0], xInit, m.tiktok.statusCalls()[0]].map(function (r) { return r ? r.contentType : null; });
  check("X1. creator_info, video/init and status/fetch carry Content-Type \"application/json; charset=UTF-8\" and the Bearer token, as TikTok's reference requires",
    xTypes.every(function (t) { return t === "application/json; charset=UTF-8"; }) && xInit.bearer === ACCESS, J(xTypes));
  const xb = m.tiktok.inits[0] || {};
  check("X2. the init body for a 2.1 MB file: post_info (title, privacy_level SELF_ONLY, disable_* true, brand toggles false) and source_info FILE_UPLOAD, video_size = chunk_size = 2100000, total_chunk_count 1; posted; nothing logged",
    a.ok && a.v.posted === true && Object.keys(xb).join() === "post_info,source_info" &&
    J(xb.post_info) === J({ title: POST.caption, privacy_level: "SELF_ONLY", disable_comment: true, disable_duet: true, disable_stitch: true, brand_content_toggle: false, brand_organic_toggle: false }) &&
    J(xb.source_info) === J({ source: "FILE_UPLOAD", video_size: 2100000, chunk_size: 2100000, total_chunk_count: 1 }) && tkLines().length === 0, a.ok ? J(xb) : a.msg);
  // X3: every documented upload_url, used whole
  const xUrls = ["https://open-upload.tiktokapis.com/video/?upload_id=67890&upload_token=check-token-x",
    "https://upload.us.tiktokapis.com/video/?upload_id=67891&upload_token=check-token-y",
    "https://open-upload.tiktokapis.com/upload/?upload_id=67892&upload_token=check-token-z"];
  const xUp = [];
  for (const u of xUrls) {
    m = mountRoutes({ env: CONFIGURED, tiktok: { uploadUrl: u } });
    seedConnection(m.db);
    video = seedVideo(m.db, mp4(30000, 52));
    a = await approve(m, proposalOf(video));
    const p0 = m.tiktok.puts()[0] || {};
    xUp.push(a.ok && a.v.posted === true && m.tiktok.puts().length === 1 && p0.url === u ? "ok" : (a.ok ? J(a.v) : a.msg));
  }
  check("X3. every upload_url TikTok documents is used whole (open-upload /video/, upload.us /video/, open-upload /upload/): one PUT to it, posted",
    xUp.every(function (x) { return x === "ok"; }), J(xUp));
  // X4: every documented video/init error code, at its documented HTTP status, and a 200 carrying invalid_params
  const DOC_CODES = [[400, "invalid_param"], [403, "spam_risk_too_many_posts"], [403, "spam_risk_user_banned_from_posting"], [403, "reached_active_user_cap"],
    [403, "unaudited_client_can_only_post_to_private_accounts"], [403, "url_ownership_unverified"], [403, "privacy_level_option_mismatch"],
    [401, "access_token_invalid"], [401, "scope_not_authorized"], [429, "rate_limit_exceeded"], [500, "internal_error"], [200, "invalid_params"]];
  const xBad = [];
  for (const pair of DOC_CODES) {
    m = mountRoutes({ env: CONFIGURED, tiktok: { initCode: pair[1], initStatus: pair[0] } });
    seedConnection(m.db);
    video = seedVideo(m.db, mp4(10000, 53));
    LOGS.length = 0;
    a = await approve(m, proposalOf(video));
    const want = "[tiktok] video/init refused: http " + pair[0] + " " + pair[1] + " Check error message for details. log_id=" + INIT_LOG_ID;
    const lines = tkLines();
    const msg = a.msg || "";
    const cardOk = pair[0] === 401 ? msg.indexOf(TK.MESSAGES.needsReconnect + " TikTok said: " + pair[1] + ".") !== -1
      : msg.indexOf("TikTok didn't start the post. TikTok said: " + pair[1] + " (Check error message for details). Nothing was sent.") !== -1;
    const ok = !a.ok && cardOk && lines.length === (pair[0] === 401 ? 2 : 1) && lines.every(function (l) { return l === want; }) && lines.every(cleanLog) &&
      rowOf(m, video.id).tiktok_publish_id === null && m.tiktok.puts().length === 0;
    if (!ok) xBad.push(pair[1] + ": " + J([msg, lines]));
  }
  check("X4. each documented init error code (and a 200 with error.code invalid_params): logged as \"[tiktok] video/init refused: http <status> <code> <message> log_id=<log_id>\", the card says \"TikTok said: <code>\", nothing stored, nothing PUT",
    xBad.length === 0, J(xBad));
  // X5: not JSON at all
  m = mountRoutes({ env: CONFIGURED, tiktok: { initRaw: { status: 502, headers: { "content-type": "text/html" }, raw: Buffer.from("<html>Bad gateway</html>") } } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 54));
  LOGS.length = 0;
  a = await approve(m, proposalOf(video));
  check("X5. a 502 that is not JSON: logged with no code or log_id, the card says TikTok said: status_502",
    !a.ok && /TikTok said: status_502\. Nothing was sent\.$/.test(a.msg || "") && J(tkLines()) === J(["[tiktok] video/init refused: http 502 - - log_id=-"]), J([a.msg, LOGS]));
  // X6: TikTok never answers
  m = mountRoutes({ env: CONFIGURED, tiktok: { initDown: true } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 55));
  LOGS.length = 0;
  a = await approve(m, proposalOf(video));
  let xl = tkLines();
  check("X6. init never answered: logged as \"http none <transport code>\", the card says TikTok couldn't be reached",
    !a.ok && /couldn't be reached to start the post/.test(a.msg || "") && xl.length === 1 && /^\[tiktok\] video\/init refused: http none [a-z0-9_-]+ - log_id=-$/.test(xl[0]), J([a.msg, xl]));
  // X7: TikTok's message carrying a token, the open_id and an upload address: none of it logged or shown
  m = mountRoutes({ env: CONFIGURED, tiktok: { initCode: "invalid_param", initStatus: 400,
    initMessage: "Bad token " + ACCESS + " for " + OPEN_ID + " at " + UPLOAD_BASE + "9 with Bearer " + ACCESS2 + " here." } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 56));
  LOGS.length = 0;
  a = await approve(m, proposalOf(video));
  xl = tkLines();
  check("X7. a TikTok message holding a token, the open_id and an upload URL: the log line and the card keep the code and log_id, and none of those",
    !a.ok && xl.length === 1 && xl[0].indexOf("[tiktok] video/init refused: http 400 invalid_param Bad token [redacted] for [redacted] at [redacted]") === 0 &&
    / log_id=202210112248442CB9319E1FB30C1073F3$/.test(xl[0]) && xl.every(cleanLog) && cleanCard(a.msg) && /TikTok said: invalid_param \(Bad token/.test(a.msg || ""), J([a.msg, xl]));
  // X8: a very long message: the line is cut at 300 characters
  m = mountRoutes({ env: CONFIGURED, tiktok: { initCode: "invalid_param", initStatus: 400, initMessage: "too long ".repeat(90) } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 57));
  LOGS.length = 0;
  a = await approve(m, proposalOf(video));
  xl = tkLines();
  check("X8. a 810-character message: the log line is exactly 300 characters", !a.ok && xl.length === 1 && xl[0].length === 300 &&
    xl[0].indexOf("[tiktok] video/init refused: http 400 invalid_param too long") === 0, J(xl.map(function (l) { return l.length; })));
  // X9: init succeeds, but the answer can't be used
  m = mountRoutes({ env: CONFIGURED, tiktok: { uploadUrl: "https://evil.example.com/upload/?upload_id=check-upload-77&upload_token=check-token" } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 58));
  LOGS.length = 0;
  a = await approve(m, proposalOf(video));
  xl = tkLines();
  check("X9. init answered ok with an upload_url TikTok doesn't document: logged with the host and first path segment only, the card says so, nothing stored or PUT",
    !a.ok && J(xl) === J(["[tiktok] video/init refused: http 200 ok unusable upload_url https evil.example.com /upload/ log_id=check"]) &&
    /no usable upload address, so nothing was sent\. TikTok said: ok\.$/.test(a.msg || "") && cleanCard(a.msg) && rowOf(m, video.id).tiktok_publish_id === null &&
    m.tiktok.puts().length === 0, J([a.msg, xl]));
  // X10: creator_info refused at approval
  m = mountRoutes({ env: CONFIGURED, tiktok: { creatorError: "rate_limit_exceeded", creatorStatus: 429 } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 59));
  LOGS.length = 0;
  a = await approve(m, proposalOf(video));
  xl = tkLines();
  check("X10. creator_info refused at approval: logged, the card says TikTok said: rate_limit_exceeded, no init",
    !a.ok && J(xl) === J(["[tiktok] creator_info refused: http 429 rate_limit_exceeded Posting is limited for this account right now. log_id=x"]) &&
    /TikTok didn't start the post\. TikTok said: rate_limit_exceeded \(Posting is limited for this account right now\)\. Nothing was sent\.$/.test(a.msg || "") &&
    m.tiktok.inits.length === 0, J([a.msg, xl]));
  // X11: the upload PUT refused, partial, or cut off
  m = mountRoutes({ env: CONFIGURED, tiktok: { putCode: "access_denied", putHttp: 403 } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 60));
  LOGS.length = 0;
  a = await approve(m, proposalOf(video));
  const xPut403 = [a.msg, tkLines()];
  m = mountRoutes({ env: CONFIGURED, tiktok: { putStatus: 206 } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 61));
  LOGS.length = 0;
  a = await approve(m, proposalOf(video));
  const xPut206 = [a.msg, tkLines()];
  m = mountRoutes({ env: CONFIGURED, tiktok: { cut: 1 } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(100000, 62));
  LOGS.length = 0;
  a = await approve(m, proposalOf(video));
  const xPutCut = [a.msg, tkLines()];
  check("X11. the upload PUT: a 403 with a code, a 206, and a cut connection are each logged as \"[tiktok] upload refused\", and the card adds TikTok's code",
    // NAMED (Nov 18 2026, TK5): BEFORE "... log_id=<id>" and the card "TikTok said: access_denied." / "status_206.". AFTER the
    // line ends with content_type=<type> and the card names the status: "TikTok said: http 403 access_denied." / "http 206.".
    J(xPut403[1]) === J(["[tiktok] upload refused: http 403 access_denied The upload_url has expired. log_id=" + INIT_LOG_ID + " content_type=application/json"]) &&
    /didn't finish\..* TikTok said: http 403 access_denied\.$/.test(xPut403[0] || "") &&
    J(xPut206[1]) === J(["[tiktok] upload refused: http 206 - - log_id=- content_type=-"]) && /TikTok said: http 206\.$/.test(xPut206[0] || "") &&
    xPutCut[1].length === 1 && /^\[tiktok\] upload refused: http none [a-z0-9_-]+ - log_id=-$/.test(xPutCut[1][0]) && /didn't finish/.test(xPutCut[0] || "") &&
    !/TikTok said/.test(xPutCut[0] || ""), J([xPut403, xPut206, xPutCut]));
  // X12: status/fetch refused after the bytes are all there
  m = mountRoutes({ env: CONFIGURED, tiktok: { statusCode: "invalid_publish_id", statusHttp: 400 } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(10000, 63));
  LOGS.length = 0;
  a = await approve(m, proposalOf(video));
  xl = tkLines();
  check("X12. status/fetch refused: logged, and the post stays processing (TikTok has every byte)",
    a.ok && a.v.processing === true && J(xl) === J(["[tiktok] status/fetch refused: http 400 invalid_publish_id The publish_id is invalid. log_id=" + INIT_LOG_ID]), J([a.ok ? a.v : a.msg, xl]));
  check("X13. every [tiktok] line in this section is at most 300 characters and holds no token, open_id, upload address or upload id; the library logs from two places only",
    XLINES.length >= 20 && XLINES.every(cleanLog) && (stripComments(FILES.api).match(/console\.\w+\(/g) || []).length === 2, J(XLINES.filter(function (l) { return !cleanLog(l); })));
  // X14: one rule, in the library and the guarded transport
  // NAMED (Nov 18 2026, TK3): BEFORE UPLOAD_PATHS compared with pathPrefixes, and the API host refused. AFTER the very same
  // regex objects in both files (lib/tiktokApi.js takes them from lib/guardedFetch.js); the API host is a tiktokapis.com subdomain.
  check("X14. lib/tiktokApi.js and lib/guardedFetch.js hold the same upload_url rule; the docs' examples pass, http and look-alikes do not",
    TK.UPLOAD_HOST_RE === GF.STREAM_PROFILES.tiktok.hostPattern && TK.UPLOAD_PATH_RE === GF.STREAM_PROFILES.tiktok.pathPattern &&
    TK.JSON_TYPE === "application/json; charset=UTF-8" &&
    ["https://open-upload.tiktokapis.com/video/?upload_id=67890&upload_token=Xza123", "https://upload.us.tiktokapis.com/video/?upload_id=67890&upload_token=chunkexample",
      "https://open-upload.tiktokapis.com/upload/?upload_id=67890&upload_token=Xza123"].every(TK.uploadUrlOk) &&
    !["http://open-upload.tiktokapis.com/video/?a=1", "https://open-upload.tiktokapis.com.evil.example/video/",
      "https://open-upload.tiktokapis.com:8443/video/", "https://open-upload.tiktokapis.com/v2/x", "https://user:pw@open-upload.tiktokapis.com/video/", "not a url"].some(TK.uploadUrlOk));
  // X15: OBS "Hybrid MP4" and fragmented MP4 (moof boxes): sniffed as MP4, the length read when moov holds it
  const xFtyp = box("ftyp", Buffer.concat([Buffer.from("isom", "latin1"), Buffer.from([0, 0, 2, 0]), Buffer.from("isomiso6mp41", "latin1")]));
  const xFrag = function (seed) { return Buffer.concat([box("moof", Buffer.concat([box("mfhd", Buffer.alloc(8)), box("traf", filler(200, seed))])), box("mdat", filler(4000, seed + 1))]); };
  const xMoov = function (mv) { return box("moov", Buffer.concat([mv, box("trak", filler(300, 5)), box("mvex", box("mehd", Buffer.alloc(8)))])); };
  const fragOnly = Buffer.concat([xFtyp, xMoov(mvhd0(1000, 0)), xFrag(70), xFrag(72)]);
  const hybridEnd = Buffer.concat([xFtyp, xFrag(74), xFrag(76), xMoov(mvhd0(1000, 10000))]);
  const hybridFront = Buffer.concat([xFtyp, xMoov(mvhd0(1000, 10000)), xFrag(78), xFrag(80)]);
  check("X15. fragmented MP4 (moov first, mvhd duration 0, then moof/mdat): MP4, length unknown from the file (the browser's is used); OBS Hybrid MP4 (moof/mdat, then a finished moov), or moov first: MP4, 10 s",
    [fragOnly, hybridEnd, hybridFront].every(function (b) { return MV.sniffVideo(b) === "mp4"; }) && readIn(fragOnly, 512) === null &&
    [1, 7, 4096, hybridEnd.length].every(function (n) { return readIn(hybridEnd, n) === 10000 && readIn(hybridFront, n) === 10000; }),
    J([readIn(fragOnly, 512), readIn(hybridEnd, 4096), readIn(hybridFront, 4096)]));

  /* ── Y ── NAMED (Nov 18 2026, TK3): the live init answer (Nov 18 2026 06:58:35 PST, log_id
     2026111814583279603BC770A1970AF2C0) was ok with an upload_url whose path was "/upload" and the query straight after
     it; TK2's prefix "/upload/" refused it, and the scrubber hid the host. One rule now (lib/guardedFetch.js
     tiktokUploadUrlOk), the host logged verbatim, the query never. */
  OUT("\n══ Y. TK3: TikTok's upload hosts, the /upload path, the host in the log ══");
  const YHOSTS = ["open-upload.tiktokapis.com", "open-upload-i18n.tiktokapis.com", "open-upload-va.tiktokapis.com", "upload.us.tiktokapis.com"];
  const yUp = [];
  let yi = 0;
  for (const h of YHOSTS) {
    yi++;
    const u = "https://" + h + "/upload?upload_id=check-upload-y" + yi + "&upload_token=check-token-y" + yi;
    m = mountRoutes({ env: CONFIGURED, tiktok: { uploadUrl: u } });
    seedConnection(m.db);
    video = seedVideo(m.db, mp4(20000, 90 + yi));
    LOGS.length = 0;
    a = await approve(m, proposalOf(video));
    const p0 = m.tiktok.puts()[0] || {};
    yUp.push(a.ok && a.v.posted === true && m.tiktok.puts().length === 1 && p0.url === u && tkLines().length === 0 ? "ok" : h + ": " + (a.ok ? J(a.v) : a.msg));
  }
  check("Y1. each TikTok upload host (open-upload, open-upload-i18n, open-upload-va, upload.us), with the live path \"/upload?upload_id=...\" (no trailing slash): one PUT to the whole URL, posted, nothing logged",
    yUp.every(function (x) { return x === "ok"; }), J(yUp));
  const Y_REFUSED = ["https://tiktokapis.com.evil.com/upload?upload_id=1", "https://evil-tiktokapis.com/upload?upload_id=1", "http://open-upload.tiktokapis.com/upload?upload_id=1",
    "https://open-upload.tiktokapis.com:8443/upload?upload_id=1", "https://user:pw@open-upload.tiktokapis.com/upload?upload_id=1", "https://user@open-upload.tiktokapis.com/upload?upload_id=1",
    // NAMED (Nov 18 2026, TK4): BEFORE "https://open-upload.tiktokapis.us/upload?upload_id=1" was refused here (not in TikTok's
    // docs). AFTER it is accepted (Y8: TikTok's live init answer for a US account); the .us look-alikes are refused in Y9.
    "https://tiktokapis.com/upload?upload_id=1", "https://open-upload.tiktokapis.com/uploadx?upload_id=1",
    "https://open-upload.tiktokapis.com/v2/upload/?upload_id=1", "https://-bad.tiktokapis.com/upload?upload_id=1", "https://" + "a".repeat(64) + ".tiktokapis.com/upload?x"];
  const yRefusedOk = Y_REFUSED.filter(TK.uploadUrlOk);
  const yg = makeTiktok({});
  const yStream = [];
  for (const u of Y_REFUSED) { const r = await attempt(yg.streamUpload(u, { profile: "tiktok", method: "PUT", body: null, contentLength: 0 })); if (r.ok || r.code !== "invalid_url") yStream.push(u + " " + (r.ok ? "ok" : r.code)); }
  check("Y2. refused by uploadUrlOk and by the guarded PUT: tiktokapis.com.evil.com, evil-tiktokapis.com, http, port 8443, credentials, the bare domain, /uploadx, /v2/upload/, a bad label; no request",
    yRefusedOk.length === 0 && yStream.length === 0 && yg.requests.length === 0, J([yRefusedOk, yStream, yg.requests.length]));
  const yPaths = ["https://open-upload.tiktokapis.com/upload?x", "https://open-upload.tiktokapis.com/video?x", "https://open-upload.tiktokapis.com/upload", "https://open-upload.tiktokapis.com/upload/?x",
    "https://open-upload.tiktokapis.com:443/upload?x", "https://open.tiktokapis.com/upload?x"];
  const yg2 = makeTiktok({});
  const yReach = [];
  for (const u of yPaths) { const r = await attempt(yg2.streamUpload(u, { profile: "tiktok", method: "PUT", body: null, contentLength: 0 })); yReach.push(!r.ok && r.code === "invalid_url" ? "refused" : "reached"); }
  check("Y3. path \"/upload?x\", \"/video?x\", \"/upload\" alone, \"/upload/?x\", port 443 written out, and any tiktokapis.com subdomain: accepted by uploadUrlOk and reached by the guarded PUT",
    yPaths.every(TK.uploadUrlOk) && yReach.every(function (x) { return x === "reached"; }) && yg2.requests.length === yPaths.length, J([yPaths.map(TK.uploadUrlOk), yReach]));
  // Y4: the public-address guard still runs for an accepted host
  let yLookup = null;
  const yBlocked = GF.createGuardedFetch({ resolve: function (h, o, cb) { return cb(null, [{ address: "10.0.0.7", family: 4 }]); },
    request: function (options) {
      const req = new EventEmitter();
      req.destroy = function () {};
      req.write = function () { return true; };
      req.end = function () {
        process.nextTick(function () {
          options.lookup(options.hostname, { all: true }, function (err) { yLookup = err ? "blocked" : "resolved"; req.emit("error", err || Object.assign(new Error("stop"), { code: "ECONNRESET" })); });
        });
      };
      return req;
    } });
  const yPriv = await attempt(yBlocked.streamUpload("https://open-upload.tiktokapis.com/upload?upload_id=1", { profile: "tiktok", method: "PUT", body: null, contentLength: 0 }));
  check("Y4. an accepted TikTok host that resolves to a private address is still refused by the DNS guard before any connection",
    !yPriv.ok && yPriv.code !== "invalid_url" && yLookup === "blocked", J([yPriv, yLookup]));
  // Y5: the unusable upload_url line names the host, never the query
  const yLogCases = [
    ["https://open-upload-va.tiktokapis.com:8443/upload?upload_id=check-upload-y9&upload_token=check-token-y9", "https open-upload-va.tiktokapis.com port 8443 /upload"],
    ["https://tiktokapis.com.evil.com/upload?upload_id=check-upload-y9&upload_token=check-token-y9", "https tiktokapis.com.evil.com /upload"],
    ["http://open-upload.tiktokapis.com/upload/?upload_id=check-upload-y9&upload_token=check-token-y9", "http open-upload.tiktokapis.com /upload/"],
    ["https://check:pw@open-upload.tiktokapis.com/upload?upload_id=check-upload-y9&upload_token=check-token-y9", "https open-upload.tiktokapis.com credentials /upload"],
    // NAMED (Nov 18 2026, TK4): BEFORE open-upload.tiktokapis.us (accepted now). AFTER the look-alike tiktokapis.usa.
    ["https://open-upload.tiktokapis.usa/upload/12345678901234567890?upload_id=check-upload-y9&upload_token=check-token-y9", "https open-upload.tiktokapis.usa /upload/"],
    ["https://open-upload.tiktokapis.com/v2/check-upload-y9?upload_id=check-upload-y9", "https open-upload.tiktokapis.com (other path)"]];
  const yLines = [];
  const yBad = [];
  for (const pair of yLogCases) {
    m = mountRoutes({ env: CONFIGURED, tiktok: { uploadUrl: pair[0] } });
    seedConnection(m.db);
    video = seedVideo(m.db, mp4(10000, 99));
    LOGS.length = 0;
    a = await approve(m, proposalOf(video));
    const l = LOGS.filter(function (x) { return x.indexOf("[tiktok] ") === 0; });
    l.forEach(function (x) { yLines.push(x); });
    if (!(!a.ok && J(l) === J(["[tiktok] video/init refused: http 200 ok unusable upload_url " + pair[1] + " log_id=check"]) && m.tiktok.puts().length === 0)) yBad.push([pair[1], l, a.ok ? a.v : a.msg]);
  }
  check("Y5. init ok with an unusable upload_url: the line names the scheme, the host verbatim, the port, credentials (as a word) and the path kind",
    yBad.length === 0, J(yBad));
  check("Y6. none of those lines holds the query, upload_id, upload_token, a path segment after /upload/, the credentials, a token or the open_id; each at most 300 characters",
    yLines.length === yLogCases.length && yLines.every(function (l) {
      return cleanLog(l) && !/[?&]|=(?!check$)|upload_id|upload_token|check-upload|check-token|check:pw|12345678901234567890/.test(l);
    }), J(yLines));
  check("Y7. urlShape: a host that is not a plain DNS name, or longer than 253 characters, is not printed",
    TK.urlShape("https://xn--bcher-kva.example/upload") === "https xn--bcher-kva.example /upload" && TK.urlShape("https://" + "a.".repeat(130) + "com/upload").indexOf("(odd host)") !== -1 &&
    TK.urlShape("not a url") === "(not an address)", J([TK.urlShape("https://" + "a.".repeat(130) + "com/upload")]));
  /* NAMED (Nov 18 2026, TK4): the live init answer for a US account (Nov 18 2026 08:53:31 PST, TK3 deployed) was
     "[tiktok] video/init refused: http 200 ok unusable upload_url https open-upload.tiktokapis.us /upload log_id=...".
     Subdomains of tiktokapis.us are now accepted; its apex and look-alikes are not. */
  const yUsUrl = "https://open-upload.tiktokapis.us/upload?upload_id=check-upload-us1&upload_token=check-token-us1";
  m = mountRoutes({ env: CONFIGURED, tiktok: { uploadUrl: yUsUrl } });
  seedConnection(m.db);
  video = seedVideo(m.db, mp4(20000, 101));
  LOGS.length = 0;
  a = await approve(m, proposalOf(video));
  const yUsPut = m.tiktok.puts()[0] || {};
  check("Y8. TK4: open-upload.tiktokapis.us with \"/upload?upload_id=...\" (the live US answer): accepted by uploadUrlOk, one PUT to the whole URL, posted, nothing logged",
    TK.uploadUrlOk(yUsUrl) && a.ok && a.v.posted === true && m.tiktok.puts().length === 1 && yUsPut.url === yUsUrl && tkLines().length === 0, a.ok ? J(a.v) : a.msg);
  const Y_US_REFUSED = ["https://tiktokapis.us/upload?upload_id=1", "https://tiktokapis.us.evil.com/upload?upload_id=1", "https://evil-tiktokapis.us/upload?upload_id=1",
    "https://open-upload.tiktokapis.usa/upload?upload_id=1", "http://open-upload.tiktokapis.us/upload?upload_id=1", "https://open-upload.tiktokapis.us:8443/upload?upload_id=1",
    "https://user:pw@open-upload.tiktokapis.us/upload?upload_id=1", "https://open-upload.tiktokapis.uk/upload?upload_id=1"];
  const yUsOk = Y_US_REFUSED.filter(TK.uploadUrlOk);
  const yg3 = makeTiktok({});
  const yUsStream = [];
  for (const u of Y_US_REFUSED) { const r = await attempt(yg3.streamUpload(u, { profile: "tiktok", method: "PUT", body: null, contentLength: 0 })); if (r.ok || r.code !== "invalid_url") yUsStream.push(u + " " + (r.ok ? "ok" : r.code)); }
  check("Y9. TK4: refused by uploadUrlOk and by the guarded PUT: tiktokapis.us (apex), tiktokapis.us.evil.com, evil-tiktokapis.us, tiktokapis.usa, http and port 8443 on the .us host, credentials, another TLD; no request",
    yUsOk.length === 0 && yUsStream.length === 0 && yg3.requests.length === 0, J([yUsOk, yUsStream, yg3.requests.length]));

  /* ── Z ── NAMED (Nov 18 2026, TK5): the live PUT to open-upload.tiktokapis.us (Nov 18 2026 09:59:01 PST) was answered,
     and the transport threw the answer away as not_json ("[tiktok] upload refused: http none not_json - log_id=-").
     TikTok's Media Transfer Guide documents the PUT answer by status only (201 "All parts are uploaded.", 206, 400,
     403, 404, 416, 5xx) and shows no body or content type. Each answer below is judged by its status alone. */
  OUT("\n══ Z. TK5: the upload PUT judged by status, not body ══");
  const ZLONG = "<html><body>Forbidden upload_token=check-token " + ACCESS + " " + OPEN_ID + "</body></html>";
  const Z_CASES = [
    ["201 empty", { status: 201, type: "", body: "" }, true, null, null],
    ["201 text/plain OK", { status: 201, type: "text/plain", body: "OK" }, true, null, null],
    ["201 text/html", { status: 201, type: "text/html; charset=utf-8", body: "<html><body>ok</body></html>" }, true, null, null],
    ["201 JSON", { status: 201, type: "application/json", body: "{\"ok\":true}" }, true, null, null],
    ["206 with a body", { status: 206, type: "text/plain", body: "partial" }, false, " TikTok said: http 206.", "[tiktok] upload refused: http 206 - - log_id=- content_type=text/plain"],
    ["403 JSON error", { status: 403, type: "application/json", body: JSON.stringify({ error: { code: "access_denied", message: "The upload_url has expired.", log_id: "ZLOG403" } }) }, false,
      " TikTok said: http 403 access_denied.", "[tiktok] upload refused: http 403 access_denied The upload_url has expired. log_id=ZLOG403 content_type=application/json"],
    ["403 HTML", { status: 403, type: "text/html", body: ZLONG }, false, " TikTok said: http 403.", "[tiktok] upload refused: http 403 - - log_id=- content_type=text/html"],
    ["500 text", { status: 500, type: "text/plain", body: "Internal error upload_id=check-upload-z" }, false, " TikTok said: http 500.", "[tiktok] upload refused: http 500 - - log_id=- content_type=text/plain"]];
  const zBad = [];
  const zLines = [];
  let zi = 0;
  for (const c of Z_CASES) {
    zi++;
    m = mountRoutes({ env: CONFIGURED, tiktok: { putAnswer: c[1] } });
    seedConnection(m.db);
    video = seedVideo(m.db, mp4(15000, 110 + zi));
    LOGS.length = 0;
    a = await approve(m, proposalOf(video));
    const l = LOGS.filter(function (x) { return x.indexOf("[tiktok] ") === 0; });
    l.forEach(function (x) { zLines.push(x); });
    const row = rowOf(m, video.id);
    const good = c[2] ?
      (a.ok && a.v.posted === true && m.tiktok.puts().length === 1 && m.tiktok.statusCalls().length >= 1 && l.length === 0) :
      (!a.ok && typeof a.msg === "string" && a.msg.slice(-(TK.MESSAGES.unfinished + c[3]).length) === TK.MESSAGES.unfinished + c[3] && J(l) === J([c[4]]) && row.tiktok_status === "initiated" && !!row.tiktok_upload_ciphertext &&
        cleanCard(a.msg) && a.msg.indexOf("check-token") === -1 && a.msg.indexOf("Forbidden") === -1);
    if (!good) zBad.push([c[0], a.ok ? a.v : a.msg, l]);
  }
  check("Z1. a 201 is done whatever its body (empty, text/plain \"OK\", text/html, JSON): posted, then status/fetch, nothing logged",
    zBad.filter(function (b) { return /^201/.test(b[0]); }).length === 0, J(zBad.filter(function (b) { return /^201/.test(b[0]); })));
  check("Z2. a 206 with a body, a 403 with a JSON error, a 403 in HTML and a 500 in text: not done, the upload kept, the card says \"TikTok said: http <status>\" (and TikTok's code when it sent one), one log line with the status and content type",
    zBad.filter(function (b) { return !/^201/.test(b[0]); }).length === 0, J(zBad.filter(function (b) { return !/^201/.test(b[0]); })));
  check("Z3. no upload log line carries the body, the URL or query, a token or the open_id; each at most 300 characters",
    zLines.length === 4 && zLines.every(function (x) { return cleanLog(x) && !/Forbidden|Internal error|check-token|check-upload|<html|[?&]/.test(x); }), J(zLines));
  check("Z4. refusalLine keeps the content_type tail within 300 characters",
    TK.refusalLine("upload", 403, "x", "a b ".repeat(200), "-", [], null, " content_type=text/html").length === 300 &&
    /content_type=text\/html$/.test(TK.refusalLine("upload", 403, "x", "word ".repeat(80), "-", [], null, " content_type=text/html")));

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
  // NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE Nov 7 2026, this change's date. AFTER Nov 8 2026, the version
  // the Etsy privacy sentence set (this change still set Nov 7).
  // NAMED (Nov 14 2026, L1): BEFORE "2026-11-08". AFTER "2026-11-14", the version L1's Google and YouTube, renewal-email and Do Not Track text set.
  // NAMED (Nov 20 2026, P2-2): BEFORE "2026-11-14". AFTER "2026-11-20", the version P2-2's community rules, reporting, blocking, moderation and copyright text set.
  // NAMED (Nov 20 2026, P3-1): BEFORE "2026-11-20" and "Last updated November 20, 2026" (P2-2). AFTER "2026-11-21", the version P3-1's free accounts, email confirmation, storage per account, members-only BizCash sending and the adult content rule set.
  // NAMED (Nov 21 2026, P3-2): BEFORE "2026-11-21" (P3-1). AFTER "2026-11-21b", the Verified badge's version (made the same day, so it carries a letter); TERMS_UPDATED stays "Last updated November 21, 2026".
  // NAMED (Nov 21 2026, P3-1B): BEFORE "2026-11-21b" (P3-2). AFTER "2026-11-21c", the owner's final free-account rules and members' Google optimisation (the same day again, so the next letter).
  // NAMED (Nov 21 2026, P3-1C): BEFORE "2026-11-21c" (P3-1B). AFTER "2026-11-21d": members start with 1,000 BizCash and free accounts hold none (the same day again, so the next letter).
  check("G5. TERMS_VERSION is the latest change's, Nov 21 2026 (P3-1C; this change set Nov 7)", LEGAL.TERMS_VERSION === "2026-11-21d", LEGAL.TERMS_VERSION);
  const YD = realRequire("./lib/yourData");
  const ttEntry = (YD.DATA || []).filter(function (e) { return e.table === "member_tiktok_connections"; })[0] ||
    (FILES.yourData.indexOf("{ table: \"member_tiktok_connections\", group: \"account\"") !== -1 ? { select: (/table: "member_tiktok_connections"[\s\S]*?select: "([^"]*)"/.exec(FILES.yourData) || [])[1], onDelete: "delete" } : null);
  check("G6. yourData: the TikTok connection exported as its name and date only, deleted with the account; never its tokens",
    !!ttEntry && ttEntry.select === "display_name, created_at" && ttEntry.onDelete === "delete" &&
    FILES.yourData.indexOf("\"Your TikTok access: stored encrypted; the export shows only your TikTok name and the date you connected.\"") !== -1 &&
    // NAMED (Nov 7 2026, Instagram posting, migration 179): BEFORE "member_tiktok_connections", "oauth_states" side by side. AFTER
    // member_instagram_connections sits between them; the TikTok connection is still deleted before the sign-in states.
    // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): member_facebook_pages sits after the Instagram connection, before the sign-in states.
    FILES.yourData.indexOf("\"member_youtube_connections\", \"member_tiktok_connections\", \"member_instagram_connections\", \"member_facebook_pages\", \"oauth_states\"") !== -1);
  check("G7. ...the videos export TikTok's status, time and post id, never the publish id or the upload address; TikTok a third party; the sign-in states line",
    FILES.yourData.indexOf("select: \"id, label, bytes, status, youtube_video_id, uploaded_at, tiktok_status, tiktok_posted_at, tiktok_post_id, created_at\"") !== -1 &&
    FILES.yourData.indexOf("{ name: \"TikTok\", for: \"posting the videos you approve to your own TikTok account, when you connect it\" }") !== -1 &&
    // NAMED (Nov 7 2026, Instagram posting): BEFORE "..., Connect YouTube and Connect TikTok". AFTER Connect Instagram is named last.
    // NAMED (Nov 7 2026, item 8 part 3b, Facebook Pages): Connect Facebook is named last.
    // NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE "..., Connect Instagram and Connect Facebook". AFTER Connect Etsy is named last.
    // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE "..., Connect Facebook and Connect Etsy". AFTER Connect Amazon is named last.
    FILES.yourData.indexOf("Sign in with Microsoft, Connect Shopify, Connect YouTube, Connect TikTok, Connect Instagram, Connect Facebook, Connect Etsy and Connect Amazon") !== -1);
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
  // NAMED (Nov 7 2026, Facebook Pages posting, migration 180): AFTER 179_instagram_posting.sql and 180_facebook_pages.sql
  // are above it, by name; "the highest" is checkFacebookPages R1's.
  // NAMED (Nov 8 2026, Etsy store connection, migration 181): BEFORE 180 was the highest. AFTER 181_etsy_store.sql is above it too,
  // by name; "the highest" is checkEtsyConnect R1's.
  // NAMED (Nov 8 2026, Amazon store connection, migration 182): BEFORE 181 the highest. AFTER 182_amazon_store.sql is above it
  // too, by name; "the highest" is checkAmazonConnect R1's.
  // NAMED (Nov 11 2026, orbit stage 2), migration 183): it adds 183_weekly_goal_and_order_status.sql above, by name; "the highest" is checkOrbitStage2 R1's.
  // NAMED (Nov 15 2026, Shopify webhooks, migration 184): BEFORE 183 was the highest. AFTER 184_shopify_webhook_requests.sql is above it too, by name; "the highest" is checkShopifyWebhooks R1's.
  // NAMED (Nov 15 2026, W-T4, migration 185): BEFORE 184 was the highest. AFTER 185_shopify_uninstall_hook.sql is above it too, by name; "the highest" is checkShopifyUninstallHook R1's.
  // NAMED (Nov 17 2026, TK1, migration 186): BEFORE 185 was the highest (checkShopifyUninstallHook R1's). AFTER
  // 186_member_videos_duration.sql is above it too, by name, and "the highest" is this check's (G15).
  // NAMED (Nov 18 2026, BV1, migration 187): BEFORE 186 was the highest. AFTER 187_member_video_parts.sql is above it too, by name; "the highest" is checkYoutubeUploads G14's.
  // NAMED (Nov 19 2026, HQ1, migration 188): 188_user_preferences_hq_view.sql (the phone dashboard's hq_card_view and hq_orbit) is allowed above the earlier highest too, by name; "the highest" is checkHqViews R1's.
  // NAMED (Nov 19 2026, P2-1, migrations 189 and 190): 189_handles_and_place.sql (the handle format, the reserved handles, the place for Local) and 190_notifications_links.sql (a notification's actor, object and link) are allowed above the earlier highest too, by name; "the highest" is checkHandles R1's.
  // NAMED (Nov 20 2026, P2-2, migrations 191 and 192): 191_safety.sql (blocks, mutes, reports, the moderation queue, copyright notices) and 192_buy_listing_digital.sql (bfc_buy_listing keeps digital listings on sale and copies their file) are allowed above the earlier highest too, by name; "the highest" is checkBuyListingDigital R1's.
  // NAMED (Nov 20 2026, P2-3, migrations 193 and 194): 193_posts.sql (posts, post_media) and 194_social_graph.sql (follows, likes, saves, comments, share days, the count triggers) are allowed above the earlier highest too, by name; "the highest" is checkBuyListingDigital R1's.
  // NAMED (Nov 20 2026, P3-1, migrations 195 to 198): 195_users_email_canonical.sql (users.email_canonical, one account per inbox), 196_storage_account_tables.sql, 197_storage_account_functions.sql and 198_storage_account_backfill.sql (per-account storage totals; written in P3-1A as 196a/196b/196c and renamed) are allowed above the earlier highest too, by name; "the highest" (198) is checkBuyListingDigital R1's.
  // NAMED (Nov 21 2026, P3-2, migration 199): 199_verified_badge.sql (bf_profiles.verified_reason and verified_at, the Verified badge) is allowed above too, by name; "the highest" (199) is checkBuyListingDigital R1's.
  // NAMED (Nov 21 2026, FX2, migration 200): 200_categories_and_intent.sql (the shared categories table, post category, intent, need_place and need_when, marketplace_listings.category_slug, and 200e's agents_card_view, search_visible and the SEO fields; applied by hand Nov 21 2026) is allowed above too, by name; "the highest" (200) is checkBuyListingDigital R1's.
  // NAMED (Nov 21 2026, P3-1C, migration 201): 201_member_welcome.sql (the member welcome and the free-account clawback, once per account: two unique partial indexes on wallet_transactions) is allowed above too, by name; "the highest" (201) is checkBuyListingDigital R1's.
  check("G13. R1. 178_tiktok_posting.sql is the only 178, and only 179 to 187, by name, are above it", highest === 201 &&
    migFiles.filter(function (x) { return /^178_/.test(x); }).join() === "178_tiktok_posting.sql" &&
    // NAMED (Nov 21 2026, P3-1C, migration 201): 201_member_welcome.sql (the member welcome and the free-account clawback, once per account: two unique partial indexes on wallet_transactions) is allowed above too, by name; "the highest" (201) is checkBuyListingDigital R1's.
    migFiles.filter(function (x) { return Number(x.slice(0, 3)) > 178; }).join() === "179_instagram_posting.sql,180_facebook_pages.sql,181_etsy_store.sql,182_amazon_store.sql,183_weekly_goal_and_order_status.sql,184_shopify_webhook_requests.sql,185_shopify_uninstall_hook.sql,186_member_videos_duration.sql,187_member_video_parts.sql,188_user_preferences_hq_view.sql,189_handles_and_place.sql,190_notifications_links.sql,191_safety.sql,192_buy_listing_digital.sql,193_posts.sql,194_social_graph.sql,195_users_email_canonical.sql,196_storage_account_tables.sql,197_storage_account_functions.sql,198_storage_account_backfill.sql,199_verified_badge.sql,200_categories_and_intent.sql,201_member_welcome.sql", highest);
  /* NAMED (Nov 17 2026, TK1): R1, the highest migration. 186_member_videos_duration.sql is the only 186 and the highest; it adds
     member_videos.duration_ms (integer, NULL) with the CHECK 1 ms to 4 hours, and its VERIFY is verify/186_verify.sql.
     NAMED (Nov 18 2026, BV1, migration 187): BEFORE 186 was the highest. AFTER it is the only 186, and only
     187_member_video_parts.sql is above it; "the highest" is checkYoutubeUploads G14's. */
  const m186 = migFiles.filter(function (x) { return /^186_/.test(x); });
  const sql186 = m186.length === 1 ? read("supabase/migrations/" + m186[0]) : "";
  const verify186 = fs.existsSync(path.join(REPO, "supabase", "migrations", "verify", "186_verify.sql")) ? read("supabase/migrations/verify/186_verify.sql") : "";
  check("G15. R1. 186_member_videos_duration.sql is the only 186, and only 187_member_video_parts.sql is above it; duration_ms integer NULL, CHECK NULL or 1..14400000; VERIFY is verify/186_verify.sql",
    // NAMED (Nov 21 2026, P3-1C, migration 201): 201_member_welcome.sql (the member welcome and the free-account clawback, once per account: two unique partial indexes on wallet_transactions) is allowed above too, by name; "the highest" (201) is checkBuyListingDigital R1's.
    highest === 201 && m186.join() === "186_member_videos_duration.sql" &&
    // NAMED (Nov 21 2026, P3-1C, migration 201): 201_member_welcome.sql (the member welcome and the free-account clawback, once per account: two unique partial indexes on wallet_transactions) is allowed above too, by name; "the highest" (201) is checkBuyListingDigital R1's.
    migFiles.filter(function (x) { return Number(x.slice(0, 3)) > 186; }).join() === "187_member_video_parts.sql,188_user_preferences_hq_view.sql,189_handles_and_place.sql,190_notifications_links.sql,191_safety.sql,192_buy_listing_digital.sql,193_posts.sql,194_social_graph.sql,195_users_email_canonical.sql,196_storage_account_tables.sql,197_storage_account_functions.sql,198_storage_account_backfill.sql,199_verified_badge.sql,200_categories_and_intent.sql,201_member_welcome.sql" &&
    sql186.indexOf("ADD COLUMN IF NOT EXISTS duration_ms integer NULL;") !== -1 &&
    sql186.indexOf("CHECK (duration_ms IS NULL OR (duration_ms > 0 AND duration_ms <= 14400000))") !== -1 &&
    /member_videos_duration_check/.test(verify186) && /duration_ms/.test(verify186) && !/\b(INSERT|UPDATE|DELETE|ALTER|DROP)\b/i.test(verify186.replace(/--[^\n]*/g, "")), J([highest, m186]));
  check("G14. the network tripwire never fired, and no promise was left rejected", TRIPPED.length === 0 && UNHANDLED.length === 0, J(TRIPPED.concat(UNHANDLED.map(function (e) { return String(e && e.message); }))));

  OUT("\n" + (failures ? "CHECKS FAILED: " + failures + " of " + (failures + passes) : "ALL " + passes + " CHECKS PASSED") + (MUTATE ? "  (MUTATE=" + MUTATE + ")" : ""));
  process.exit(failures ? 1 : 0);
})().catch(function (e) { OUT("    FAIL  the harness stopped: " + ((e && e.stack) || e)); process.exit(1); });
