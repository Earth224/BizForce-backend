"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkSocialVideoPanel — the Social page clean-up (Nov 12 2026, from the
   owner's photos of agents/social.html, Accounts tab).

   BEFORE "Your videos" sat inside the YouTube card and listed every
   platform's status there ("TikTok: not sent" inside YouTube), and the
   prepare forms used browser defaults: a tiny monospace textarea beside its
   label, a white select, a white-bordered "Made for kids?" fieldset.
   AFTER "Your videos" is its own card above the platform cards; each row
   shows one chip and one "Prepare for ..." button per CONNECTED platform; a
   Prepare button opens that platform's form under the row, one at a time;
   every form control carries the shared .sf-control style.

   THE PAGE RUNS IN JSDOM: agents/social.html's markup (its script tags left
   out) with scripts/oauth-return.js, youtube.js, tiktok.js, instagram.js and
   facebook.js, over fixture answers. No network, no database.

     V1  the Your videos card: its own section, outside every platform card,
         directly above the YouTube card, in the Accounts tab before it;
     V2  the notes word for word: the two intro lines in the card, the Google
         line moved into the YouTube card, TikTok's line still in TikTok's;
     V3  chips only for connected platforms, in the platforms' own words,
         coloured from the theme tokens;
     V4  Prepare buttons only for connected platforms; with none connected,
         "Connect a platform below to send this video." and no button;
     V5  one form open at a time, with its header; the same button closes it;
         the Instagram and Facebook forms go back to their cards;
     V6  status messages show inside the open form;
     V7  every input, textarea and select in Your videos and the four forms
         carries .sf-control, and the stylesheet styles it (dark select, the
         site font, never monospace, a focus glow, labels above, 640px);
     V8  the AI helper: "Describe the video for the AI writer", 3 rows, its
         placeholder, "Draft with AI" directly under it, "File for approval"
         the primary button at the end;
     V9  "Made for kids?": a role="radiogroup" labelled above, two required
         radios, no fieldset, and the arrow keys move the choice;
     V10 TikTok's UX rules intact: no default privacy, disabled options with
         their reason, the disclosure, the label and consent lines;
     V11 behaviour unchanged, proved against frontend BASELINE: the same
         routes in each script, the same requests on load, and the same
         payloads filed from each form;
     V12 NAMED (Nov 17 2026, TK1), TikTok's content-sharing guidelines: the
         TikTok form's preview (muted, controls, no autoplay), the declaration
         with TikTok's links directly above File for approval, the button off
         while Disclose is on with nothing chosen, "Only you"'s hover text,
         and the TikTok card's private-account and processing lines.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check.
   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
// The frontend commit before the clean-up (orbit stage 2).
const BASELINE = "0238268";

const PAGE = "agents/social.html", OAUTH = "scripts/oauth-return.js", YT = "scripts/youtube.js", TT = "scripts/tiktok.js",
  IG = "scripts/instagram.js", FB = "scripts/facebook.js";
const ALL = [PAGE, OAUTH, YT, TT, IG, FB];

const MUTATIONS = {
  // NAMED (Nov 18 2026, BV1): part uploads, progress, retry, cancel, the 50 MB reasons, the partial preview (V13).
  "bv-ui-one-url-only": [[YT, "      if (file.size > ONE_FILE_MAX_BYTES) {", "      if (false) {"]],
  "bv-ui-max-50": [[YT, "  var MAX_BYTES = 500 * 1024 * 1024;", "  var MAX_BYTES = 50 * 1024 * 1024;"]],
  "bv-ui-no-sha": [[YT, "{ path: plan.path, idx: idx, bytes: file.size, sha256: hex }", "{ path: plan.path, idx: idx, bytes: file.size, sha256: \"\" }"]],
  "bv-ui-no-retry": [[YT, "          if ((err && err.final) || n >= PART_TRIES) throw err;", "          throw err;"]],
  "bv-ui-retry-forever": [[YT, "          if ((err && err.final) || n >= PART_TRIES) throw err;", "          if (err && err.final) throw err;"]],
  "bv-ui-retry-final": [[YT, "{ final: res.status >= 400 && res.status < 500 && res.status !== 429 }", "{ final: false }"]],
  "bv-ui-no-progress": [[YT, "        var pct = Math.floor((done + sent) * 100 / file.size);\n        showProgress(true, pct);\n", "        var pct = Math.floor((done + sent) * 100 / file.size);\n"]],
  "bv-ui-progress-per-part": [[YT, "        var pct = Math.floor((done + sent) * 100 / file.size);", "        var pct = Math.floor(sent * 100 / file.size);"]],
  "bv-ui-cancel-unwired": [[YT, "    if (cancel) cancel.addEventListener(\"click\", cancelUpload);\n", ""]],
  "bv-ui-cancel-no-abort": [[YT, "    if (upload.xhr) { try { upload.xhr.abort(); } catch (e) { /* already finished */ } }\n", ""]],
  "bv-ui-reason-hover-only": [[YT, "          actions.appendChild(reason);\n", ""]],
  "bv-ui-ig-size-ignored": [[IG, "  function reelSize(v) { return v.fits_meta === false || (Number(v.bytes) || 0) > META_MAX_BYTES ? REEL_SIZE : \"\"; }", "  function reelSize(v) { return \"\"; }"]],
  "bv-ui-fb-size-ignored": [[FB, "  function videoSize(v) { return v.fits_meta === false || (Number(v.bytes) || 0) > META_MAX_BYTES ? VIDEO_SIZE : \"\"; }", "  function videoSize(v) { return \"\"; }"]],
  "bv-ui-tt-preview-unlabelled": [[TT, "      if (res.data.partial === true) wrap.appendChild(make(\"p\", PREVIEW_START, \"bsky-quiet tt-preview-part\"));\n", ""]],
  "bv-ui-limits-text": [[PAGE, "<p class=\"bsky-quiet\">Videos up to 500 MB for YouTube and TikTok (MP4, WebM or MOV). Instagram and Facebook take videos up to 50 MB.</p>", "<p class=\"bsky-quiet\">Videos up to 50 MB (MP4, WebM or MOV).</p>"]],
  // Your videos goes back inside the YouTube card (V1)
  "videos-inside-youtube": [
    [PAGE, "    <section class=\"context-card bsky-card\" id=\"videosCard\" aria-label=\"Your videos\">",
      "    <section class=\"context-card bsky-card\" id=\"ytConnect\" aria-label=\"YouTube\">\n    <div class=\"bsky-sub\" id=\"videosCard\">"],
    [PAGE, "      <ul class=\"bsky-mentions-list sf-videos\" id=\"ytVideoList\"></ul>\n    </section>\n    <section class=\"context-card bsky-card\" id=\"ytConnect\" aria-label=\"YouTube\">\n",
      "      <ul class=\"bsky-mentions-list sf-videos\" id=\"ytVideoList\"></ul>\n    </div>\n"]],
  // a platform that is not connected gets a chip (V3)
  "chip-for-unconnected": [[YT, "      if (!connected[name] || !hook) return;\n", "      if (!hook) return;\n"]],
  // a platform that is not connected gets its Prepare button (V4)
  "prepare-for-unconnected": [[YT, "      if (!connected[name] || !hook) return;\n",
    "      if (!hook) return;\n      if (!connected[name]) { hook.actions(v, row); return; }\n"]],
  // opening a second form leaves the first open (V5)
  "two-forms-open": [[YT, "    closeOpenForm();\n    if (same) return;\n", "    if (same) { closeOpenForm(); return; }\n"]],
  // the YouTube privacy select loses the shared style: a browser-default white box (V7)
  "unstyled-select": [[YT, "    var privacy = control(document.createElement(\"select\"));", "    var privacy = document.createElement(\"select\");"]],
  // the AI helper is a bare textarea again: the browser's monospace, 2 rows (V7, V8)
  "monospace-helper": [[YT, "    var idea = control(document.createElement(\"textarea\"));\n    idea.rows = 3;", "    var idea = document.createElement(\"textarea\");\n    idea.rows = 2;"]],
  // "Made for kids?" is a bordered fieldset again (V9)
  "kids-fieldset-border-back": [[YT, "    var wrap = make(\"div\", null, \"sf-field\");\n    var label = make(\"span\", \"Made for kids?\", \"sf-label\");",
    "    var wrap = make(\"fieldset\", null, \"sf-field\");\n    var label = make(\"span\", \"Made for kids?\", \"sf-label\");"]],
  // TikTok's privacy gets a default (V10)
  "tiktok-privacy-default-added": [[TT, "      var opt = make(\"option\", typeof words[o] === \"string\" ? words[o] : o);\n      opt.value = o;\n",
    "      var opt = make(\"option\", typeof words[o] === \"string\" ? words[o] : o);\n      opt.value = o;\n      if (o === \"PUBLIC_TO_EVERYONE\") opt.selected = true;\n"]],
  // NAMED (Nov 15 2026, S4): the posted links run together again (V4f)
  "links-no-gap": [[PAGE, "flex-wrap: wrap; align-items: baseline; gap: 6px 14px; margin-top: 8px;", "flex-wrap: wrap; align-items: baseline; margin-top: 8px;"]],
  "links-not-flex": [[PAGE, "    .sf-links { display: flex; flex-wrap: wrap;", "    .sf-links { display: block; flex-wrap: wrap;"]],
  "links-old-margin": [[PAGE, "    .sf-videos .masto-post-link { display: inline-block; min-width: 0; overflow-wrap: anywhere; }", "    .sf-videos .masto-post-link { display: inline-block; margin-top: 8px; overflow-wrap: anywhere; }"]],
  // NAMED (Nov 17 2026, TK1): V12.
  // the TikTok preview autoplays, or plays sound
  "tt-preview-autoplay": [[TT, "player.autoplay = false;", "player.autoplay = true;"]],
  "tt-preview-sound": [[TT, "player.setAttribute(\"playsinline\", \"\"); player.setAttribute(\"muted\", \"\");", "player.setAttribute(\"playsinline\", \"\");"]],
  // the declaration moves above the interactions, away from the button
  "tt-declaration-away": [[TT, "    box.appendChild(labelLine);\n    box.appendChild(consent);\n", "    box.insertBefore(consent, box.firstChild);\n    box.appendChild(labelLine);\n"]],
  // the declaration's music link goes to a page that is not TikTok's
  "tt-music-link-wrong": [[TT, "  var MUSIC_URL = \"https://www.tiktok.com/legal/page/global/music-usage-confirmation/en\";", "  var MUSIC_URL = \"https://bizforceai.net/terms.html\";"]],
  // File for approval stays on while Disclose is on with nothing chosen
  "tt-file-on-unchosen": [[TT, "      var unchosen = disclose.input.checked && !yours.input.checked && !branded.input.checked;", "      var unchosen = false;"]],
  // "Only you" disabled without its hover text
  "tt-only-you-silent": [[TT, "        privacy.options[i].title = paid ? PRIVATE_HOVER : \"\";", "        privacy.options[i].title = \"\";"]],
  // the TikTok card loses the private-account or the processing line
  "tt-card-private-lost": [[PAGE, "your TikTok account must be set to private, and TikTok keeps", "TikTok keeps"]],
  // the hidden disclosure options drawn anyway (display: grid beats [hidden])
  "tt-brands-drawn-hidden": [[PAGE, "    .sf-check-group[hidden] { display: none; }\n", ""]],
  "tt-card-processing-lost": [[PAGE, "      <p class=\"bsky-quiet\">After you approve a post, TikTok may take a few minutes to process it before it appears on your profile.</p>\n", ""]],
  // the moved Google line is lost (V2)
  "note-lost": [[PAGE, "      <p class=\"bsky-quiet\">Until Google approves BizForce, YouTube keeps uploads from BizForce private.</p>\n", ""]]
};

// One rule for every mutation runner (scripts/_shared.js): an unmatched search text is an ERROR, never a catch.
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {}, BASE = {};
ALL.forEach(f => {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(2); }
  FILES[f] = lf(fs.readFileSync(p, "utf8"));
  BASE[f] = lf(execFileSync("git", ["show", BASELINE + ":" + f], { cwd: FRONTEND, maxBuffer: 1 << 27 }).toString("utf8"));
});
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 500) + "]" : "")); }
}
process.on("unhandledRejection", e => check("no page request is left unhandled", false, (e && e.message) || e));
const J = JSON.stringify;

/* ── fixtures ── */
const API = "https://dynamic-prosperity-production-5382.up.railway.app";
const V_NEW = { id: "22222222-2222-4222-8222-222222222222", label: "Spring cakes", bytes: 3 * 1048576, mime: "video/mp4", status: "ready",
  youtube_video_id: null, youtube_url: null, uploaded_at: null, created_at: "2026-11-07T10:00:00Z", upload_unfinished: false,
  tiktok_status: null, tiktok_posted_at: null, tiktok_post_url: null, tiktok_upload_unfinished: false,
  // NAMED (Nov 17 2026, TK1): the length (migration 186).
  duration_ms: 45000 };
const V_SENT = Object.assign({}, V_NEW, { id: "33333333-3333-4333-8333-333333333333", label: "Autumn menu", mime: "video/webm",
  youtube_video_id: "dQw4w9WgXcQ", youtube_url: "https://www.youtube.com/watch?v=dQw4w9WgXcQ", uploaded_at: "2026-11-07T11:00:00Z",
  tiktok_status: "posted", tiktok_posted_at: "2026-11-07T11:00:00Z", tiktok_post_url: "https://www.tiktok.com/player/v1/7300000000000000001" });
const CREATOR = { creator_nickname: "Maple Street Bakery", privacy_level_options: ["PUBLIC_TO_EVERYONE", "MUTUAL_FOLLOW_FRIENDS", "SELF_ONLY"],
  comment_disabled: false, duet_disabled: true, stitch_disabled: false,
  privacy_words: { PUBLIC_TO_EVERYONE: "Everyone", MUTUAL_FOLLOW_FRIENDS: "Friends", SELF_ONLY: "Only you" } };
const SINCE = "2026-11-07T10:00:00Z";
const PREVIEW_URL = "https://check.supabase.co/storage/v1/object/sign/bf-video/video/x.mp4?token=sig";
function answersFor(on) {
  const st = c => (c ? "connected" : "not_connected");
  return function (p, method) {
    if (p === "/api/youtube/status") return { status: 200, body: { youtube_available: true, connected: !!on.youtube, status: st(on.youtube), channel_title: "Maple Street", since: SINCE } };
    if (p === "/api/tiktok/status") return { status: 200, body: { tiktok_available: true, connected: !!on.tiktok, status: st(on.tiktok), display_name: "Maple Street", since: SINCE } };
    if (p === "/api/instagram/status") return { status: 200, body: { instagram_available: true, connected: !!on.instagram, status: st(on.instagram), username: "maplestreet", since: SINCE } };
    if (p === "/api/facebook/status") return { status: 200, body: { facebook_available: true, connected: !!on.facebook, status: st(on.facebook), page_name: "Maple Street", since: SINCE } };
    if (p === "/api/videos" && method === "GET") return { status: 200, body: { videos: [V_NEW, V_SENT], max_bytes: 52428800, ready_max: 2 } };
    if (p === "/api/instagram/posts" || p === "/api/facebook/posts") return { status: 200, body: { posts: [] } };
    if (p === "/api/tiktok/creator-info") return { status: 200, body: CREATOR };
    // NAMED (Nov 17 2026, TK1): the TikTok form's preview.
    if (/^\/api\/videos\/[0-9a-f-]{36}\/preview$/.test(p)) return { status: 200, body: { url: PREVIEW_URL, mime: "video/mp4", expires_in: 600 } };
    if (/propose/.test(p)) return { status: 201, body: { note: "Filed for approval." } };
    return { status: 404, body: { error: "not in this fixture: " + method + " " + p } };
  };
}

let pIn2 = null; // NAMED (Nov 17 2026, TK1): V2's paragraph finder, reused in V12.
const flush = async (n) => { for (let i = 0; i < (n || 12); i++) await new Promise(r => setTimeout(r, 0)); };
const windows = [];
function stripScripts(html) { return html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, ""); }

// The page in jsdom: its markup, then the five scripts in page order. `files` is FILES or BASE.
async function runPage(files, on) {
  const reqs = [];
  const answers = answersFor(on);
  const dom = new JSDOM(stripScripts(files[PAGE]), { url: "https://bizforceai.net/agents/social.html", runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  windows.push(w);
  w.localStorage.setItem("bf_token", "tok");
  w.fetch = function (url, init) {
    const p = String(url).replace(API, "");
    const method = (init && init.method) || "GET";
    reqs.push({ method: method, path: p, body: init && init.body ? JSON.parse(init.body) : undefined });
    const a = answers(p, method);
    const pr = Promise.resolve({ ok: a.status < 300, status: a.status, json: function () { return Promise.resolve(a.body); } });
    pr.catch(function () {});
    return pr;
  };
  [OAUTH, YT, TT, IG, FB].forEach(f => w.eval(files[f] + "\n//# sourceURL=" + f));
  await flush(20);
  return { w: w, doc: w.document, reqs: reqs };
}
const $ = (root, sel) => Array.from(root.querySelectorAll(sel));
const text = n => (n ? n.textContent.replace(/\s+/g, " ").trim() : "");
function rowOf(doc, id) { return doc.querySelector("#ytVideoList li[data-video-id=\"" + id + "\"]"); }
function buttonIn(root, label) { return $(root, "button").filter(b => b.textContent === label)[0] || null; }
function panels(doc) { return $(doc, "#ytVideoList .sf-panel"); }
function controlsIn(root) { return $(root, "input, textarea, select"); }
function key(w, target, k) { target.dispatchEvent(new w.KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true })); }
const ON_ALL = { youtube: true, tiktok: true, instagram: true, facebook: true };

(async function main() {
  const page = FILES[PAGE];
  const styleText = (/<style>([\s\S]*?)<\/style>/.exec(page) || ["", ""])[1];
  const rule = sel => { const i = styleText.indexOf(sel + " {"); return i === -1 ? "" : styleText.slice(i, styleText.indexOf("}", i) + 1); };

  /* ── V1 ── */
  console.log("\n══ V1. the Your videos card ══");
  let r = await runPage(FILES, { youtube: true });
  let doc = r.doc;
  const card = doc.getElementById("videosCard");
  const platformCards = ["ytConnect", "ttConnect", "igConnect", "fbConnect"].map(id => doc.getElementById(id));
  check("V1a. #videosCard is a context-card section titled \"Your videos\", holding the label, the file input and the list",
    !!card && card.tagName === "SECTION" && /context-card/.test(card.className) && text(card.querySelector("h2")) === "Your videos" &&
    !!card.querySelector("#ytLabel") && !!card.querySelector("#ytFile") && !!card.querySelector("#ytVideoList") && !!card.querySelector("#ytUploadMsg"));
  check("V1b. ...outside every platform card, and no platform card holds a video list",
    !!card && platformCards.every(c => !!c && !c.contains(card) && !card.contains(c) && !c.querySelector("#ytVideoList, .sf-videos")));
  check("V1c. ...directly above the platform cards: after the Mastodon card, and the YouTube card is the next section",
    !!card && !!card.previousElementSibling && card.previousElementSibling.id === "mastoConnect" && !!card.nextElementSibling && card.nextElementSibling.id === "ytConnect");
  const tabIds = (/specificTab: \{ name: "Accounts", sectionIds: (\[[^\]]*\]) \}/.exec(page) || ["", "[]"])[1];
  // NAMED (Nov 23 2026, LR-2): BEFORE the list ended at fbConnect. AFTER the Threads tile (thConnect) follows it; the videos card is where it was.
  check("V1d. the Accounts tab carries it, right before ytConnect", tabIds === "[\"bskyConnect\", \"bskyMentions\", \"mastoConnect\", \"videosCard\", \"ytConnect\", \"ttConnect\", \"igConnect\", \"fbConnect\", \"thConnect\"]", tabIds);

  /* ── V2 ── */
  console.log("\n══ V2. the notes, word for word ══");
  // NAMED (Nov 18 2026, BV1): BEFORE "Videos up to 50 MB (MP4, WebM or MOV)." AFTER the per-platform limits.
  const LIMITS = "Videos up to 500 MB for YouTube and TikTok (MP4, WebM or MOV). Instagram and Facebook take videos up to 50 MB.";
  const KEPT = "BizForce deletes the file once every platform you sent it to has it, or 14 days after you added it.";
  const GOOGLE = "Until Google approves BizForce, YouTube keeps uploads from BizForce private.";
  // NAMED (Nov 17 2026, TK1): BEFORE "...TikTok keeps posts from BizForce visible only to you." AFTER the account must be private too.
  const TIKTOK = "Until TikTok reviews BizForce, your TikTok account must be set to private, and TikTok keeps posts from BizForce visible only to you.";
  const pIn = (root, t) => !!root && $(root, "p").filter(p => p.textContent === t).length === 1;
  pIn2 = pIn;
  const once = t => page.split("<p class=\"bsky-quiet\">" + t + "</p>").length === 2;
  check("V2a. the two intro lines, word for word, in the Your videos card and nowhere else", pIn(card, LIMITS) && pIn(card, KEPT) && once(LIMITS) && once(KEPT));
  check("V2b. the Google line moved into the YouTube card, word for word, once, and not in Your videos",
    pIn(doc.getElementById("ytConnect"), GOOGLE) && !pIn(card, GOOGLE) && once(GOOGLE));
  check("V2c. TikTok's line stays in the TikTok card, word for word, once", pIn(doc.getElementById("ttConnect"), TIKTOK) && once(TIKTOK));
  check("V2d. the old place is gone: no #ytVideos block, no Your videos heading inside the YouTube card",
    !doc.getElementById("ytVideos") && !$(doc.getElementById("ytConnect"), "h3").some(h => h.textContent === "Your videos"));

  /* ── V3 / V4 ── */
  console.log("\n══ V3–V4. chips and Prepare buttons, connected platforms only ══");
  const chipsOf = row => $(row, ".sf-chip").map(c => [c.getAttribute("data-platform"), c.textContent]);
  const preparesOf = row => $(row, "button[data-prepare]").map(b => b.textContent);
  // YouTube connected, TikTok not (it is set up), Instagram and Facebook not
  check("V3a. YouTube connected, TikTok not: each row has the YouTube chip only, in its words",
    J(chipsOf(rowOf(doc, V_NEW.id))) === J([["youtube", "YouTube: not sent"]]) && J(chipsOf(rowOf(doc, V_SENT.id))) === J([["youtube", "YouTube: uploaded"]]),
    J([chipsOf(rowOf(doc, V_NEW.id)), chipsOf(rowOf(doc, V_SENT.id))]));
  check("V3b. ...and nothing about TikTok, Instagram or Facebook anywhere in Your videos (the photo's \"TikTok: not sent\")",
    !/TikTok|Instagram|Facebook/.test(doc.getElementById("ytVideoList").textContent), text(doc.getElementById("ytVideoList")));
  /* NAMED (Nov 13 2026, S3, "Post again"): BEFORE the video YouTube has showed no YouTube button. AFTER it shows
     "Post again on YouTube" (asked first, scripts/checkRepostAndDates.js holds the dialog and the flag); the video
     YouTube doesn't have keeps "Prepare for YouTube". Still YouTube's button alone while only YouTube is connected. */
  check("V4a. ...only YouTube's button: \"Prepare for YouTube\" on the video YouTube doesn't have, \"Post again on YouTube\" on the one it has; Delete on both",
    J(preparesOf(rowOf(doc, V_NEW.id))) === J(["Prepare for YouTube"]) && J(preparesOf(rowOf(doc, V_SENT.id))) === J(["Post again on YouTube"]) &&
    !!buttonIn(rowOf(doc, V_NEW.id), "Delete") && !!buttonIn(rowOf(doc, V_SENT.id), "Delete"));
  check("V4b. ...and the uploaded one keeps its youtube.com link, Check status and Remove from YouTube",
    $(rowOf(doc, V_SENT.id), "a").map(a => a.href).join() === V_SENT.youtube_url && !!buttonIn(rowOf(doc, V_SENT.id), "Check status") &&
    !!buttonIn(rowOf(doc, V_SENT.id), "Remove from YouTube"));
  const ytReqs = r.reqs.length;
  // all four connected
  r = await runPage(FILES, ON_ALL);
  doc = r.doc;
  // NAMED (Nov 13 2026, S2): Instagram's and Facebook's chips now say what the platform has of the video (these fixtures
  // carry no instagram_status or facebook_status: not sent), not what the file allows; the file rule is the disabled
  // button's reason (V4c). Every status is held by scripts/checkSocialFinishes.js.
  check("V3c. all four connected: one chip per platform, in order, in each platform's words",
    J(chipsOf(rowOf(doc, V_NEW.id))) === J([["youtube", "YouTube: not sent"], ["tiktok", "TikTok: not sent"], ["instagram", "Instagram: not sent"], ["facebook", "Facebook: not sent"]]) &&
    J(chipsOf(rowOf(doc, V_SENT.id))) === J([["youtube", "YouTube: uploaded"], ["tiktok", "TikTok: posted"], ["instagram", "Instagram: not sent"], ["facebook", "Facebook: not sent"]]),
    J([chipsOf(rowOf(doc, V_NEW.id)), chipsOf(rowOf(doc, V_SENT.id))]));
  check("V3d. chip colours come from classes whose rules use the theme tokens", /var\(--bf-accent-a, #22d3ee\)/.test(rule(".sf-chip")) &&
    /var\(--bf-success, #34d399\)/.test(rule(".sf-chip--ok")) && /var\(--bf-warning, #fbbf24\)/.test(rule(".sf-chip--wait")) &&
    /var\(--bf-text-muted, #8892b8\)/.test(rule(".sf-chip--off")) &&
    $(doc, "#ytVideoList .sf-chip").every(c => /^sf-chip sf-chip--(ok|wait|bad|off|ready)$/.test(c.className)));
  // NAMED (Nov 13 2026, S3): the sent one now has "Post again" for YouTube and TikTok (both have it), enabled; Instagram's
  // and Facebook's buttons stay disabled with the file reason (WebM): the file rule still wins.
  const sentBtns = $(rowOf(doc, V_SENT.id), "button[data-prepare]");
  check("V4c. ...all four Prepare buttons on the new video; the sent one: Post again on YouTube and TikTok, Instagram and Facebook disabled with the reason (WebM)",
    J(preparesOf(rowOf(doc, V_NEW.id))) === J(["Prepare for YouTube", "Prepare for TikTok", "Prepare for Instagram", "Prepare for Facebook"]) &&
    J(preparesOf(rowOf(doc, V_SENT.id))) === J(["Post again on YouTube", "Post again on TikTok", "Prepare for Instagram", "Prepare for Facebook"]) &&
    sentBtns.slice(0, 2).every(b => b.disabled === false) &&
    sentBtns.slice(2).every(b => b.disabled === true && /MP4 or MOV/.test(b.title)),
    J([preparesOf(rowOf(doc, V_NEW.id)), preparesOf(rowOf(doc, V_SENT.id))]));
  check("V4d. ...and the posted TikTok video keeps its player link, the remove line and Check TikTok status",
    $(rowOf(doc, V_SENT.id), "a").some(a => a.href === V_SENT.tiktok_post_url && a.rel === "noopener") &&
    pIn(rowOf(doc, V_SENT.id), "To remove a TikTok post, delete it in the TikTok app.") && !!buttonIn(rowOf(doc, V_SENT.id), "Check TikTok status"));
  // NAMED (Nov 15 2026, S4): BEFORE each posted link was inline-block with only margin-top: 8px, so two sat on one line
  // with no space between them. AFTER they sit in the row's .sf-links, a wrapping flex row with a 6px line gap (as
  // .sf-chips) and 14px between links (the .sf-form rhythm); the site has no spacing tokens, so the values are those.
  const sentLinks = $(rowOf(doc, V_SENT.id), "a.masto-post-link");
  check("V4f. the posted links (youtube.com and TikTok's player) sit in one .sf-links row: flex, wrapping, 6px between lines and 14px between links, no margin of their own",
    sentLinks.length === 2 && sentLinks.every(a => a.parentNode.className === "sf-links" && a.parentNode === sentLinks[0].parentNode) &&
    /display: flex;/.test(rule(".sf-links")) && /flex-wrap: wrap;/.test(rule(".sf-links")) && /gap: 6px 14px;/.test(rule(".sf-links")) &&
    !/margin/.test(rule(".sf-videos .masto-post-link")) && /:empty { display: none; }/.test(styleText),
    J([sentLinks.map(a => a.parentNode.className), rule(".sf-links"), rule(".sf-videos .masto-post-link")]));
  const r0 = await runPage(FILES, {});
  const none = r0.doc;
  check("V4e. nothing connected: no chip, no Prepare button, \"Connect a platform below to send this video.\" on each row, Delete kept",
    $(none, "#ytVideoList .sf-chip").length === 0 && $(none, "#ytVideoList button[data-prepare]").length === 0 &&
    [V_NEW.id, V_SENT.id].every(id => pIn(rowOf(none, id), "Connect a platform below to send this video.") && !!buttonIn(rowOf(none, id), "Delete")));

  /* ── V5 / V6 ── */
  console.log("\n══ V5–V6. one form at a time, messages inside it ══");
  const rowN = rowOf(doc, V_NEW.id);
  buttonIn(rowN, "Prepare for YouTube").click();
  await flush();
  let ps = panels(doc);
  check("V5a. \"Prepare for YouTube\" opens one form under its row, headed \"YouTube upload\"",
    ps.length === 1 && rowN.contains(ps[0]) && text(ps[0].querySelector(".sf-panel-head")) === "YouTube upload");
  buttonIn(ps[0], "File for approval").click();
  await flush();
  check("V6a. filing unanswered says \"Answer \\\"Made for kids?\\\" with Yes or No.\" INSIDE the form, and nothing is sent",
    !!ps[0].querySelector(".bsky-msg") && $(ps[0], ".bsky-msg").some(m => m.textContent === "Answer \"Made for kids?\" with Yes or No.") &&
    !r.reqs.some(x => x.path === "/api/youtube/propose-upload"));
  buttonIn(rowN, "Prepare for TikTok").click();
  await flush();
  ps = panels(doc);
  check("V5b. \"Prepare for TikTok\" closes it and opens TikTok's, headed \"TikTok post\": still one form", ps.length === 1 &&
    text(ps[0].querySelector(".sf-panel-head")) === "TikTok post" && !!ps[0].querySelector("select"));
  const ttPanel = ps[0];
  buttonIn(rowN, "Prepare for Instagram").click();
  await flush();
  ps = panels(doc);
  const igForm = doc.getElementById("igPrepare");
  check("V5c. \"Prepare for Instagram\" moves the Instagram form under the row as a Reel of that video, headed \"Instagram Reel\"",
    ps.length === 1 && text(ps[0].querySelector(".sf-panel-head")) === "Instagram Reel" && ps[0].contains(igForm) && igForm.hidden === false &&
    doc.getElementById("igKindReel").checked === true && doc.getElementById("igVideo").value === V_NEW.id && !doc.contains(ttPanel));
  buttonIn(rowN, "Prepare for Facebook").click();
  await flush();
  ps = panels(doc);
  const fbForm = doc.getElementById("fbPrepare");
  check("V5d. \"Prepare for Facebook\" puts Instagram's form back in its card and moves Facebook's under the row as a video post",
    ps.length === 1 && text(ps[0].querySelector(".sf-panel-head")) === "Facebook video post" && ps[0].contains(fbForm) &&
    doc.getElementById("igPrepareHome").contains(igForm) && doc.getElementById("igKindPhotos").checked === true &&
    doc.getElementById("fbKindVideo").checked === true && doc.getElementById("fbVideo").value === V_NEW.id);
  buttonIn(rowN, "Prepare for Facebook").click();
  await flush();
  check("V5e. the same button again closes it: no form open, Facebook's back in its card as a text post",
    panels(doc).length === 0 && doc.getElementById("fbPrepareHome").contains(fbForm) && doc.getElementById("fbKindText").checked === true);
  buttonIn(rowN, "Prepare for Instagram").click();
  await flush();
  const openBefore = panels(doc).length;
  r.w.BFVideos.reload();
  await flush();
  check("V5f. drawing the list again closes the open form, and the Instagram form goes back to its card",
    openBefore === 1 && panels(doc).length === 0 && doc.getElementById("igPrepareHome").contains(igForm), J([openBefore, panels(doc).length]));

  /* ── V7 ── */
  console.log("\n══ V7. one shared form style ══");
  r = await runPage(FILES, ON_ALL);
  doc = r.doc;
  buttonIn(rowOf(doc, V_NEW.id), "Prepare for YouTube").click();
  await flush();
  const ytCtl = controlsIn(panels(doc)[0]);
  buttonIn(rowOf(doc, V_NEW.id), "Prepare for TikTok").click();
  await flush();
  const ttCtl = controlsIn(panels(doc)[0]);
  const shared = n => (" " + n.className + " ").indexOf(" sf-control ") !== -1;
  const regions = { "Your videos": controlsIn(doc.getElementById("videosCard")).filter(n => !doc.getElementById("ytVideoList").contains(n)),
    YouTube: ytCtl, TikTok: ttCtl, Instagram: controlsIn(doc.getElementById("igPrepare")), Facebook: controlsIn(doc.getElementById("fbPrepare")),
    "Facebook Page choice": controlsIn(doc.getElementById("fbChoosing")) };
  const bare = Object.keys(regions).map(k => [k, regions[k].filter(n => !shared(n)).map(n => n.tagName + "#" + (n.id || n.name || n.type))]).filter(x => x[1].length);
  check("V7a. every input, textarea and select in Your videos and the four forms carries .sf-control",
    ytCtl.length >= 7 && ttCtl.length >= 9 && regions.Instagram.length >= 5 && regions.Facebook.length >= 6 && bare.length === 0, J(bare));
  check("V7b. every select there is a styled one: .sf-control, no browser-default white box",
    Object.keys(regions).every(k => regions[k].filter(n => n.tagName === "SELECT").every(shared)) &&
    /-webkit-appearance: none; appearance: none/.test(rule("select.sf-control")) && /background-color: #0d1328/.test(rule("select.sf-control option")));
  const ctlRule = rule(".sf-control");
  check("V7c. the shared rule: the page's field glass, border and radius, the site font, full width; a focus glow; a placeholder colour",
    /border-radius: 10px/.test(ctlRule) && /border: 1px solid rgba\(244,114,182,\.3\)/.test(ctlRule) && /background-color: rgba\(10,14,30,\.6\)/.test(ctlRule) &&
    /font-family: inherit/.test(ctlRule) && /width: 100%/.test(ctlRule) && /max-width: 100%/.test(ctlRule) && /min-width: 0/.test(ctlRule) &&
    /box-shadow: 0 0 0 3px/.test(rule(".sf-control:focus")) && /color: #6f7aa3/.test(rule(".sf-control::placeholder")));
  check("V7d. no monospace anywhere: no textarea outside .sf-control, and no stylesheet or script names monospace",
    Object.keys(regions).every(k => regions[k].filter(n => n.tagName === "TEXTAREA").every(shared)) &&
    [PAGE, YT, TT, IG, FB].every(f => !/monospace/i.test(FILES[f])));
  check("V7e. labels sit above their fields in one column at most 640px wide; one 14px rhythm",
    /display: grid; gap: 14px; width: 100%; max-width: 640px/.test(rule(".sf-form")) && /display: grid; gap: 6px/.test(rule(".sf-field")) &&
    /display: block; text-align: left/.test(rule(".sf-label")) &&
    $(panels(doc)[0], ".sf-field").every(f => f.firstElementChild && f.firstElementChild.classList.contains("sf-label")));
  check("V7f. no fieldset in Your videos or any of the four forms", $(doc.getElementById("videosCard"), "fieldset").length === 0 &&
    $(doc.getElementById("igPrepare"), "fieldset").length === 0 && $(doc.getElementById("fbPrepare"), "fieldset").length === 0);

  /* ── V8 ── */
  console.log("\n══ V8. the AI helper ══");
  const HELPER = "Describe the video for the AI writer";
  const PH = "For example: a 30-second clip showing our herbal oil and how to use it";
  function helperOk(root) {
    const label = $(root, "label").filter(l => l.textContent === HELPER)[0];
    const ta = label ? root.querySelector("#" + label.getAttribute("for").replace(/[^A-Za-z0-9_-]/g, "\\$&")) : null;
    const under = ta ? ta.nextElementSibling : null;
    return !!ta && ta.tagName === "TEXTAREA" && ta.rows === 3 && ta.placeholder === PH && shared(ta) && label.parentNode === ta.parentNode &&
      label.nextElementSibling === ta && !!under && under.classList.contains("sf-under") && !!buttonIn(under, "Draft with AI");
  }
  function primaryLast(root) {
    const btns = $(root, "button");
    const last = btns[btns.length - 1];
    return !!last && last.textContent === "File for approval" && last.className === "action-btn";
  }
  buttonIn(rowOf(doc, V_NEW.id), "Prepare for YouTube").click();
  await flush();
  const ytPanel = panels(doc)[0];
  check("V8a. YouTube: \"Describe the video for the AI writer\" above a full-width 3-row textarea with its placeholder, \"Draft with AI\" right under it",
    helperOk(ytPanel));
  check("V8b. YouTube: \"File for approval\" is the primary button, last in the form", primaryLast(ytPanel));
  buttonIn(rowOf(doc, V_NEW.id), "Prepare for TikTok").click();
  await flush();
  check("V8c. TikTok: the same helper, and \"File for approval\" last and primary", helperOk(panels(doc)[0]) && primaryLast(panels(doc)[0]));
  buttonIn(rowOf(doc, V_NEW.id), "Prepare for Instagram").click();
  await flush();
  check("V8d. Instagram as a Reel: the helper names the video, with its placeholder; \"File for approval\" last and primary",
    text(doc.getElementById("igIdeaLabel")) === HELPER && doc.getElementById("igIdea").placeholder === PH && doc.getElementById("igIdea").rows === 3 &&
    doc.getElementById("igIdea").nextElementSibling.classList.contains("sf-under") && primaryLast(doc.getElementById("igPrepare")));
  buttonIn(rowOf(doc, V_NEW.id), "Prepare for Facebook").click();
  await flush();
  check("V8e. Facebook as a video: the same helper words; \"Draft with AI\" under it; \"File for approval\" last and primary",
    text(doc.getElementById("fbIdeaLabel")) === HELPER && doc.getElementById("fbIdea").placeholder === PH && doc.getElementById("fbIdea").rows === 3 &&
    !!buttonIn(doc.getElementById("fbIdea").nextElementSibling, "Draft with AI") && primaryLast(doc.getElementById("fbPrepare")));
  buttonIn(rowOf(doc, V_NEW.id), "Prepare for Facebook").click();
  await flush();
  check("V8f. back in the cards, for a text or photo post, the helper names the post",
    text(doc.getElementById("fbIdeaLabel")) === "Describe the post for the AI writer" && text(doc.getElementById("igIdeaLabel")) === "Describe the post for the AI writer");

  /* ── V9 ── */
  console.log("\n══ V9. \"Made for kids?\" ══");
  buttonIn(rowOf(doc, V_NEW.id), "Prepare for YouTube").click();
  await flush();
  const kp = panels(doc)[0];
  const group = kp.querySelector("[role=radiogroup]");
  const kidsLabel = group ? doc.getElementById(group.getAttribute("aria-labelledby")) : null;
  const radios = group ? $(group, "input[type=radio]") : [];
  check("V9a. a role=\"radiogroup\" labelled \"Made for kids?\" above it, aria-required, in the segmented style",
    !!group && !!kidsLabel && kidsLabel.textContent === "Made for kids?" && kidsLabel.nextElementSibling === group && kidsLabel.classList.contains("sf-label") &&
    group.getAttribute("aria-required") === "true" && group.classList.contains("sf-seg") && !kp.querySelector("fieldset, legend"));
  check("V9b. two radios, Yes then No, required, neither chosen, each in a segment drawn like the site's tabs",
    radios.length === 2 && radios[0].value === "yes" && radios[1].value === "no" && radios.every(x => x.required && !x.checked && shared(x) && x.classList.contains("sf-seg-input")) &&
    J(radios.map(x => x.nextElementSibling && x.nextElementSibling.textContent)) === J(["Yes", "No"]) &&
    /var\(--bf-btn-a, #00e5ff\)/.test(rule(".sf-seg-input:checked + span")) && /outline: 2px solid #67e8f9/.test(rule(".sf-seg-input:focus-visible + span")));
  if (radios.length === 2) {
    radios[0].focus();
    key(r.w, radios[0], "ArrowRight");
    const a1 = [radios[0].checked, radios[1].checked, doc.activeElement === radios[0]];
    key(r.w, radios[0], "ArrowRight");
    const a2 = [radios[0].checked, radios[1].checked, doc.activeElement === radios[1]];
    key(r.w, radios[1], "ArrowLeft");
    const a3 = [radios[0].checked, radios[1].checked, doc.activeElement === radios[0]];
    key(r.w, radios[0], "ArrowUp");
    const a4 = [radios[0].checked, radios[1].checked, doc.activeElement === radios[1]];
    check("V9c. the arrow keys move the choice and the focus: Right chooses Yes, Right No, Left Yes, Up wraps to No",
      J([a1, a2, a3, a4]) === J([[true, false, true], [false, true, true], [true, false, true], [false, true, true]]), J([a1, a2, a3, a4]));
  } else check("V9c. the arrow keys move the choice and the focus", false, "no radios");

  /* ── V10 ── */
  console.log("\n══ V10. TikTok's rules ══");
  buttonIn(rowOf(doc, V_NEW.id), "Prepare for TikTok").click();
  await flush();
  const tp = panels(doc)[0];
  const sel = tp.querySelector("select");
  const boxes = $(tp, "input[type=checkbox]");
  const boxNamed = n => boxes.filter(b => b.parentNode.textContent.indexOf(n) !== -1)[0];
  check("V10a. who can see it: TikTok's options in words, and NOTHING chosen", !!sel && sel.value === "" && sel.options[0].textContent === "Choose who can see it" &&
    J(Array.from(sel.options).slice(1).map(o => [o.value, o.textContent, o.selected])) === J([["PUBLIC_TO_EVERYONE", "Everyone", false], ["MUTUAL_FOLLOW_FRIENDS", "Friends", false], ["SELF_ONLY", "Only you", false]]),
    sel ? J(Array.from(sel.options).map(o => [o.value, o.selected])) : "no select");
  check("V10b. comments, duet and stitch unchecked; duet disabled \"(Turned off in your TikTok settings)\"; each in the shared style",
    ["Allow comments", "Allow duet", "Allow stitch"].every(n => !!boxNamed(n) && !boxNamed(n).checked && shared(boxNamed(n))) &&
    boxNamed("Allow duet").disabled === true && boxNamed("Allow comments").disabled === false && boxNamed("Allow duet").parentNode.textContent.indexOf("Turned off in your TikTok settings") !== -1);
  const consentP = () => $(tp, "p").filter(p => /^By posting, you agree to TikTok's/.test(p.textContent))[0];
  check("V10c. disclosure off, its options hidden, the music consent line", !!boxNamed("Disclose video content") && !boxNamed("Disclose video content").checked &&
    boxNamed("Your brand").parentNode.parentNode.hidden === true && !!consentP() && consentP().textContent === "By posting, you agree to TikTok's Music Usage Confirmation.");
  const fire = (n, t) => n.dispatchEvent(new r.w.Event(t, { bubbles: true }));
  boxNamed("Disclose video content").checked = true; fire(boxNamed("Disclose video content"), "change");
  boxNamed("Branded content").checked = true; fire(boxNamed("Branded content"), "change");
  check("V10d. branded content: the Paid partnership line, the Branded Content consent, \"Only you\" disabled",
    $(tp, "p").some(p => !p.hidden && p.textContent === "Your video will be labeled 'Paid partnership'.") &&
    consentP().textContent === "By posting, you agree to TikTok's Branded Content Policy and Music Usage Confirmation." &&
    Array.from(sel.options).filter(o => o.value === "SELF_ONLY")[0].disabled === true);
  boxNamed("Branded content").checked = false; boxNamed("Disclose video content").checked = false; fire(boxNamed("Disclose video content"), "change");
  const n0 = r.reqs.length;
  buttonIn(tp, "File for approval").click();
  await flush();
  check("V10e. filing with nothing chosen is stopped, with \"Choose who can see this post.\" inside the form",
    r.reqs.length === n0 && $(tp, ".bsky-msg").some(m => m.textContent === "Choose who can see this post."));

  /* ── V11 ── */
  console.log("\n══ V11. behaviour unchanged against frontend " + BASELINE + " ══");
  const routes = src => Array.from(new Set((src.match(/"\/api\/[A-Za-z0-9_/-]*"/g) || []))).sort();
  // NAMED (Nov 17 2026, TK1): BEFORE every script's routes equal BASELINE's. AFTER tiktok.js adds exactly one, "/api/videos/" (the
  // preview, GET /api/videos/:id/preview); every other route is unchanged.
  // NAMED (Nov 18 2026, BV1): youtube.js adds the two part routes, part-url and part-done (V13).
  const added = { [TT]: ["\"/api/videos/\""], [YT]: ["\"/api/videos/part-done\"", "\"/api/videos/part-url\""] };
  const expectRoutes = f => Array.from(new Set(routes(BASE[f]).concat(added[f] || []))).sort();
  check("V11a. each script calls the same routes as at " + BASELINE + " (tiktok.js adds only the preview, youtube.js only the two part routes)", [YT, TT, IG, FB].every(f => J(routes(FILES[f])) === J(expectRoutes(f))),
    [YT, TT, IG, FB].filter(f => J(routes(FILES[f])) !== J(expectRoutes(f))).map(f => f + " " + J(routes(FILES[f]))).join(" ;; "));
  const loadReqs = rr => rr.reqs.map(x => x.method + " " + x.path).sort();
  const nowAll = await runPage(FILES, ON_ALL), baseAll = await runPage(BASE, ON_ALL);
  const nowYt = await runPage(FILES, { youtube: true }), baseYt = await runPage(BASE, { youtube: true });
  check("V11b. the same requests on load, all connected and YouTube only", J(loadReqs(nowAll)) === J(loadReqs(baseAll)) && J(loadReqs(nowYt)) === J(loadReqs(baseYt)),
    J([loadReqs(nowAll), loadReqs(baseAll)]));
  check("V11c. (YouTube-only load requests counted: " + ytReqs + ")", ytReqs === loadReqs(baseYt).length);

  // The same filing, done the old way and the new way: the bodies must be equal.
  async function fileYoutube(files, isNew) {
    const p = await runPage(files, ON_ALL);
    const row = isNew ? rowOf(p.doc, V_NEW.id) : $(p.doc, "#ytVideoList > li")[0];
    if (isNew) { buttonIn(row, "Prepare for YouTube").click(); await flush(); }
    const scope = isNew ? panels(p.doc)[0] : row;
    const texts = $(scope, "input[type=text]");
    texts[0].value = "Spring cakes"; texts[1].value = "cakes, spring";
    $(scope, "textarea").filter(t => t.rows === 5)[0].value = "Our spring range.";
    const sel2 = scope.querySelector("select"); sel2.value = "unlisted";
    $(scope, "input[type=radio]").filter(x => x.value === "no")[0].checked = true;
    buttonIn(scope, "File for approval").click();
    await flush();
    return (p.reqs.filter(x => x.path === "/api/youtube/propose-upload")[0] || {}).body;
  }
  const ytNew = await fileYoutube(FILES, true), ytOld = await fileYoutube(BASE, false);
  check("V11d. YouTube: the propose-upload body is the old one", !!ytNew && J(ytNew) === J(ytOld), J([ytNew, ytOld]));
  async function fileTiktok(files, isNew) {
    const p = await runPage(files, ON_ALL);
    const row = isNew ? rowOf(p.doc, V_NEW.id) : $(p.doc, "#ytVideoList > li")[0];
    buttonIn(row, isNew ? "Prepare for TikTok" : "Prepare TikTok post").click();
    await flush();
    // TikTok's privacy select is the one that starts "Choose who can see it"; at BASELINE its form is the .bsky-sub box holding it.
    const sel3 = $(row, "select").filter(x => x.options[0] && x.options[0].textContent === "Choose who can see it")[0];
    const scope = isNew ? panels(p.doc)[0] : sel3.closest(".bsky-sub");
    sel3.value = "MUTUAL_FOLLOW_FRIENDS";
    const cbs = $(scope, "input[type=checkbox]");
    cbs.filter(b => b.parentNode.textContent.indexOf("Allow comments") !== -1)[0].checked = true;
    const cap = isNew ? scope.querySelector("#" + $(scope, "label").filter(l => l.textContent === "Caption")[0].getAttribute("for")) : $(scope, "textarea")[0];
    cap.value = "Spring cakes.";
    buttonIn(scope, "File for approval").click();
    await flush();
    return (p.reqs.filter(x => x.path === "/api/tiktok/propose-post")[0] || {}).body;
  }
  const ttNew = await fileTiktok(FILES, true), ttOld = await fileTiktok(BASE, false);
  check("V11e. TikTok: the propose-post body is the old one", !!ttNew && J(ttNew) === J(ttOld), J([ttNew, ttOld]));
  async function fileVideoPost(files, isNew, which) {
    const p = await runPage(files, ON_ALL);
    const d = p.doc;
    const ig = which === "instagram";
    if (isNew) { buttonIn(rowOf(d, V_NEW.id), ig ? "Prepare for Instagram" : "Prepare for Facebook").click(); await flush(); }
    else {
      const radio = d.getElementById(ig ? "igKindReel" : "fbKindVideo");
      radio.checked = true; radio.dispatchEvent(new p.w.Event("change")); await flush();
      d.getElementById(ig ? "igVideo" : "fbVideo").value = V_NEW.id;
    }
    d.getElementById(ig ? "igCaption" : "fbMessage").value = "Spring cakes.";
    d.getElementById(ig ? "igFileBtn" : "fbFileBtn").click();
    await flush();
    return (p.reqs.filter(x => x.path === (ig ? "/api/instagram/propose-post" : "/api/facebook/propose-post"))[0] || {}).body;
  }
  const igNew = await fileVideoPost(FILES, true, "instagram"), igOld = await fileVideoPost(BASE, false, "instagram");
  check("V11f. Instagram: a Reel filed from \"Prepare for Instagram\" sends the old body", !!igNew && J(igNew) === J(igOld) && igNew.kind === "reel" && igNew.video_id === V_NEW.id, J([igNew, igOld]));
  const fbNew = await fileVideoPost(FILES, true, "facebook"), fbOld = await fileVideoPost(BASE, false, "facebook");
  check("V11g. Facebook: a video post filed from \"Prepare for Facebook\" sends the old body", !!fbNew && J(fbNew) === J(fbOld) && fbNew.kind === "video" && fbNew.video_id === V_NEW.id, J([fbNew, fbOld]));
  const pDel = await runPage(FILES, ON_ALL);
  buttonIn(rowOf(pDel.doc, V_NEW.id), "Delete").click();
  await flush();
  check("V11h. Delete still calls DELETE /api/videos/:id", pDel.reqs.some(x => x.method === "DELETE" && x.path === "/api/videos/" + V_NEW.id));
  check("V11i. no innerHTML in the four scripts' code", [YT, TT, IG, FB].every(f => !/innerHTML/.test(FILES[f].replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, ""))));

  /* ── V12 ── NAMED (Nov 17 2026, TK1) */
  console.log("\n══ V12. TikTok's content-sharing guidelines ══");
  const pT = await runPage(FILES, ON_ALL);
  const tcard = pT.doc.getElementById("ttConnect");
  check("V12a. the TikTok card: the private-account line and the processing line, word for word",
    pIn2(tcard, "Until TikTok reviews BizForce, your TikTok account must be set to private, and TikTok keeps posts from BizForce visible only to you.") &&
    pIn2(tcard, "After you approve a post, TikTok may take a few minutes to process it before it appears on your profile."));
  buttonIn(rowOf(pT.doc, V_NEW.id), "Prepare for TikTok").click();
  await flush();
  const tp2 = panels(pT.doc)[0];
  const vid = tp2 ? tp2.querySelector("video") : null;
  check("V12b. the form's preview: a <video> from the signed address with controls, muted, never autoplay",
    !!vid && vid.getAttribute("src") === PREVIEW_URL && vid.hasAttribute("controls") && vid.hasAttribute("muted") && vid.muted === true && !vid.hasAttribute("autoplay") &&
    pT.reqs.some(x => x.method === "GET" && x.path === "/api/videos/" + V_NEW.id + "/preview"), vid ? vid.outerHTML : "no video");
  const fileBtn2 = tp2 ? buttonIn(tp2, "File for approval") : null;
  const decl = tp2 ? $(tp2, "p").filter(p => /^By posting, you agree to TikTok's/.test(p.textContent))[0] : null;
  const dlinks = decl ? $(decl, "a").map(a => [a.textContent, a.getAttribute("href"), a.getAttribute("target"), a.getAttribute("rel")]) : [];
  check("V12c. the declaration sits directly above File for approval, and links Music Usage Confirmation to TikTok's page",
    !!decl && !!fileBtn2 && decl.nextElementSibling === fileBtn2.parentNode &&
    J(dlinks) === J([["Music Usage Confirmation", "https://www.tiktok.com/legal/page/global/music-usage-confirmation/en", "_blank", "noopener"]]), J(dlinks));
  const boxes2 = tp2 ? $(tp2, "input[type=checkbox]") : [];
  const named2 = n => boxes2.filter(b => b.parentNode.textContent.indexOf(n) !== -1)[0];
  const fire2 = (n, t) => n.dispatchEvent(new pT.w.Event(t, { bubbles: true }));
  const on0 = !!fileBtn2 && fileBtn2.disabled === false;
  named2("Disclose video content").checked = true; fire2(named2("Disclose video content"), "change");
  const off1 = fileBtn2.disabled === true;
  named2("Your brand").checked = true; fire2(named2("Your brand"), "change");
  const on2 = fileBtn2.disabled === false;
  check("V12d. File for approval: on with Disclose off, OFF with Disclose on and nothing chosen, on again once an option is chosen", on0 && off1 && on2, J([on0, off1, on2]));
  named2("Branded content").checked = true; fire2(named2("Branded content"), "change");
  const selfOpt2 = Array.from(tp2.querySelector("select").options).filter(o => o.value === "SELF_ONLY")[0];
  const blinks = $(decl, "a").map(a => [a.textContent, a.getAttribute("href")]);
  check("V12e. Branded content: \"Only you\" disabled with the hover text \"Branded content visibility cannot be set to private.\", and both policies linked",
    selfOpt2.disabled === true && selfOpt2.getAttribute("title") === "Branded content visibility cannot be set to private." &&
    J(blinks) === J([["Branded Content Policy", "https://www.tiktok.com/legal/page/global/bc-policy/en"], ["Music Usage Confirmation", "https://www.tiktok.com/legal/page/global/music-usage-confirmation/en"]]), J([selfOpt2.title, blinks]));
  // NAMED (Nov 17 2026, TK1): jsdom applies no stylesheet, so the rule itself is checked here (browserCheckSocial checks what Chrome draws).
  check("V12f. the stylesheet keeps a hidden check group undrawn: .sf-check-group[hidden] { display: none; } after .sf-check-group's display: grid",
    FILES[PAGE].indexOf("    .sf-check-group { display: grid; gap: 10px; }\n") !== -1 &&
    FILES[PAGE].indexOf("    .sf-check-group[hidden] { display: none; }\n") > FILES[PAGE].indexOf("    .sf-check-group { display: grid; gap: 10px; }\n"));

  /* ── V13 ── NAMED (Nov 18 2026, BV1): a video over 50 MB goes up in parts, each with its own signed URL, with a
     progress bar, a Cancel button and up to three tries a part; Instagram and Facebook say why they can't take it; the
     TikTok preview of a parted video says it shows the start. */
  console.log("\n══ V13. videos up to 500 MB, in parts ══");
  const MIB = 1024 * 1024, PART = 45 * MIB, BIG = 60 * MIB;
  const PATH = "video/00000000-0000-4000-8000-000000000001/" + "b".repeat(32) + ".mp4";
  const V_BIG = Object.assign({}, V_NEW, { id: "44444444-4444-4444-8444-444444444444", label: "Long cut", bytes: BIG, parts: 2, fits_meta: false });
  const nodeCrypto = require("crypto");
  const fakeFile = function (size) {
    const blob = function (a, b) {
      return { size: b - a, arrayBuffer: function () { const u = Buffer.from("bytes " + a + "-" + b); return Promise.resolve(u.buffer.slice(u.byteOffset, u.byteOffset + u.length)); }, from: a, to: b };
    };
    return Object.assign(blob(0, size), { name: "long.mp4", type: "video/mp4", slice: function (a, b) { return blob(a, Math.min(b, size)); } });
  };
  const hexOf = (a, b) => nodeCrypto.createHash("sha256").update("bytes " + a + "-" + b).digest("hex");
  const waitFor = async (pred, tries) => { for (let i = 0; i < (tries || 400); i++) { if (pred()) return true; await new Promise(r => setTimeout(r, 2)); } return false; };
  // The page with its PUTs answered by putPlan (an array of statuses in order, "hold" to never answer) and its own answers.
  async function runUpload(files, over, putPlan) {
    const reqs = [], puts = [], seen = [];
    const base = answersFor(ON_ALL);
    const dom = new JSDOM(stripScripts(files[PAGE]), { url: "https://bizforceai.net/agents/social.html", runScripts: "outside-only", pretendToBeVisual: true });
    const w = dom.window;
    windows.push(w);
    w.localStorage.setItem("bf_token", "tok");
    Object.defineProperty(w, "crypto", { value: { subtle: nodeCrypto.webcrypto.subtle, getRandomValues: function (a) { return nodeCrypto.webcrypto.getRandomValues(a); } }, configurable: true });
    w.fetch = function (url, init) {
      const p = String(url).replace(API, "");
      const method = (init && init.method) || "GET";
      const body = init && init.body ? JSON.parse(init.body) : undefined;
      reqs.push({ method: method, path: p, body: body });
      const a = (over && over(p, method, body, reqs)) || (function () {
        if (p === "/api/videos/upload-url") return body.bytes > 50 * MIB ? { status: 200, body: { path: PATH, mime: "video/mp4", max_bytes: 500 * MIB, parts: Math.ceil(body.bytes / PART), part_bytes: PART } }
          : { status: 200, body: { upload_url: "https://check.supabase.co/storage/v1/object/upload/sign/bf-video/" + PATH + "?token=one", path: PATH, mime: "video/mp4", max_bytes: 500 * MIB } };
        if (p === "/api/videos/part-url") return { status: 200, body: { upload_url: "https://check.supabase.co/storage/v1/object/upload/sign/bf-video/part-" + body.idx + "?token=t", idx: body.idx, bytes: body.idx === 0 ? PART : body.bytes - PART } };
        if (p === "/api/videos/part-done") return { status: 200, body: { recorded: true, idx: body.idx } };
        if (p === "/api/videos/finalize") return { status: 201, body: { video: V_NEW } };
        return base(p, method);
      })();
      const pr = Promise.resolve({ ok: a.status < 300, status: a.status, json: function () { return Promise.resolve(a.body); } });
      pr.catch(function () {});
      return pr;
    };
    w.XMLHttpRequest = function () {
      const x = { upload: {}, headers: {}, status: 0, aborted: false };
      x.open = function (m, u) { x.method = m; x.url = u; };
      x.setRequestHeader = function (k, v) { x.headers[k] = v; };
      x.abort = function () { x.aborted = true; setTimeout(function () { if (x.onabort) x.onabort(); }, 0); };
      x.send = function (blob) {
        const plan = putPlan && putPlan.length > puts.length ? putPlan[puts.length] : 200;
        puts.push({ method: x.method, url: x.url, type: x.headers["Content-Type"], from: blob.from, to: blob.to, size: blob.size, xhr: x, msg: w.document.getElementById("ytUploadMsg").textContent });
        if (plan === "hold") return;
        setTimeout(function () {
          if (x.aborted) return;
          if (x.upload.onprogress) x.upload.onprogress({ lengthComputable: true, loaded: blob.size, total: blob.size });
          const doc = w.document;
          seen.push([doc.getElementById("ytUploadBar").value, doc.getElementById("ytUploadProgress").hidden, doc.getElementById("ytUploadMsg").textContent]);
          x.status = plan;
          x.onload();
        }, 0);
      };
      return x;
    };
    [OAUTH, YT, TT, IG, FB].forEach(f => w.eval(files[f] + "\n//# sourceURL=" + f));
    await flush(20);
    return { w: w, doc: w.document, reqs: reqs, puts: puts, seen: seen };
  }
  const pick = async function (u, size) {
    const input = u.doc.getElementById("ytFile");
    Object.defineProperty(input, "files", { value: [fakeFile(size)], configurable: true });
    input.dispatchEvent(new u.w.Event("change"));
  };
  const msgOf = u => u.doc.getElementById("ytUploadMsg").textContent;
  const of = (u, p) => u.reqs.filter(x => x.path === p);
  // the whole flow
  let u = await runUpload(FILES);
  await pick(u, BIG);
  await waitFor(() => msgOf(u) === "Added.");
  check("V13a. a 60 MB video: upload-url, then per part in order part-url, its PUT (that slice, to that part's URL) and part-done with its sha256; then finalize",
    J(of(u, "/api/videos/upload-url").map(x => x.body)) === J([{ mime: "video/mp4", bytes: BIG, label: "" }]) &&
    J(u.reqs.filter(x => /part-|finalize/.test(x.path)).map(x => x.path)) === J(["/api/videos/part-url", "/api/videos/part-done", "/api/videos/part-url", "/api/videos/part-done", "/api/videos/finalize"]) &&
    J(of(u, "/api/videos/part-url").map(x => x.body)) === J([{ path: PATH, idx: 0, bytes: BIG }, { path: PATH, idx: 1, bytes: BIG }]) &&
    J(of(u, "/api/videos/part-done").map(x => x.body)) === J([{ path: PATH, idx: 0, bytes: BIG, sha256: hexOf(0, PART) }, { path: PATH, idx: 1, bytes: BIG, sha256: hexOf(PART, BIG) }]) &&
    J(u.puts.map(x => [x.method, x.url.split("/").pop(), x.type, x.from, x.to])) === J([["PUT", "part-0?token=t", "video/mp4", 0, PART], ["PUT", "part-1?token=t", "video/mp4", PART, BIG]]) &&
    J(of(u, "/api/videos/finalize").map(x => x.body)) === J([{ path: PATH, label: "", bytes: BIG }]) && msgOf(u) === "Added.",
    J([u.reqs.map(x => x.path).filter(p => /videos\//.test(p)), u.puts.map(x => [x.from, x.to]), msgOf(u)]));
  check("V13b. the progress bar counts the whole video (75% after part 1, 100% after part 2), shown while it runs, with \"Uploading part 1 of 2… 75%\"; hidden once added",
    J(u.seen) === J([[75, false, "Uploading part 1 of 2… 75%"], [100, false, "Uploading part 2 of 2… 100%"]]) && u.doc.getElementById("ytUploadProgress").hidden === true,
    J([u.seen, u.doc.getElementById("ytUploadProgress").hidden]));
  // a part that fails once is tried again
  u = await runUpload(FILES, null, [200, 500, 200]);
  await pick(u, BIG);
  await waitFor(() => msgOf(u) === "Added.");
  check("V13c. part 2's PUT fails once: \"Part 2 of 2 didn't finish. Trying again…\", a fresh part-url for it, then it goes and the video is added",
    u.puts.length === 3 && u.puts[2].msg === "Part 2 of 2 didn't finish. Trying again…" && J(of(u, "/api/videos/part-url").map(x => x.body.idx)) === J([0, 1, 1]) && u.puts.length === 3 &&
    of(u, "/api/videos/part-done").length === 2 && of(u, "/api/videos/finalize").length === 1 && msgOf(u) === "Added.", J([of(u, "/api/videos/part-url").map(x => x.body.idx), msgOf(u)]));
  u = await runUpload(FILES, null, [200, 500, 500, 500]);
  await pick(u, BIG);
  await waitFor(() => u.puts.length === 4 && u.doc.getElementById("ytUploadProgress").hidden);
  await flush(10);
  check("V13d. ...three tries at most: after the third the upload stops with \"Part 2 of 2 didn't finish.\", nothing finalized",
    u.puts.length === 4 && of(u, "/api/videos/finalize").length === 0 && msgOf(u) === "Part 2 of 2 didn't finish.", J([u.puts.length, msgOf(u)]));
  u = await runUpload(FILES, (p) => p === "/api/videos/part-url" ? { status: 409, body: { error: "This video was already added.", code: "already" } } : null);
  await pick(u, BIG);
  await waitFor(() => msgOf(u) === "This video was already added.");
  check("V13e. a refusal the server means (a 4xx from part-url) is not tried again: one ask, its words, nothing sent",
    of(u, "/api/videos/part-url").length === 1 && u.puts.length === 0 && msgOf(u) === "This video was already added.", J([of(u, "/api/videos/part-url").length, msgOf(u)]));
  // cancel
  u = await runUpload(FILES, null, ["hold"]);
  await pick(u, BIG);
  await waitFor(() => u.puts.length === 1);
  const shownWhileHeld = u.doc.getElementById("ytUploadProgress").hidden === false;
  u.doc.getElementById("ytUploadCancel").click();
  await waitFor(() => msgOf(u) === "Upload cancelled. Nothing was added.");
  await flush(10);
  check("V13f. Cancel upload during a part: the PUT is aborted, \"Upload cancelled. Nothing was added.\", no part-done, no finalize, the bar hidden",
    shownWhileHeld && u.puts[0].xhr.aborted === true && msgOf(u) === "Upload cancelled. Nothing was added." && of(u, "/api/videos/part-done").length === 0 &&
    of(u, "/api/videos/finalize").length === 0 && u.doc.getElementById("ytUploadProgress").hidden === true, J([shownWhileHeld, msgOf(u)]));
  // the old flow and the limit
  u = await runUpload(FILES);
  await pick(u, 3 * MIB);
  await waitFor(() => msgOf(u) === "Added.");
  check("V13g. a video of at most 50 MB: one PUT to the one signed URL, no part-url, as before",
    u.puts.length === 1 && /token=one$/.test(u.puts[0].url) && of(u, "/api/videos/part-url").length === 0 && of(u, "/api/videos/finalize").length === 1, J(u.puts.map(x => x.url)));
  u = await runUpload(FILES);
  const before13 = u.reqs.length;
  await pick(u, 500 * MIB + 1);
  await flush(10);
  check("V13h. over 500 MB: \"A video is at most 500 MB.\" on the page, nothing sent", msgOf(u) === "A video is at most 500 MB." && u.reqs.length === before13 && u.puts.length === 0, msgOf(u));
  // Instagram and Facebook say why
  u = await runUpload(FILES, (p, method) => p === "/api/videos" && method === "GET" ? { status: 200, body: { videos: [V_NEW, V_BIG], max_bytes: 500 * MIB, ready_max: 2 } } : null);
  const bigRow = rowOf(u.doc, V_BIG.id), smallRow = rowOf(u.doc, V_NEW.id);
  const btnOf = (row, pf) => row ? row.querySelector("button[data-prepare=\"" + pf + "\"]") : null;
  const whyOf = b => b && b.getAttribute("aria-describedby") ? u.doc.getElementById(b.getAttribute("aria-describedby")) : null;
  const IG_WHY = "Instagram takes videos up to 50 MB from BizForce.", FB_WHY = "Facebook takes videos up to 50 MB from BizForce.";
  check("V13i. a video over 50 MB: Prepare for Instagram and Prepare for Facebook disabled, each with its reason as the hover text AND shown beside it (aria-describedby)",
    !!bigRow && btnOf(bigRow, "instagram").disabled === true && btnOf(bigRow, "instagram").title === IG_WHY && text(whyOf(btnOf(bigRow, "instagram"))) === IG_WHY &&
    btnOf(bigRow, "facebook").disabled === true && btnOf(bigRow, "facebook").title === FB_WHY && text(whyOf(btnOf(bigRow, "facebook"))) === FB_WHY &&
    bigRow.contains(whyOf(btnOf(bigRow, "instagram"))) && /sf-why/.test(whyOf(btnOf(bigRow, "facebook")).className),
    bigRow ? J($(bigRow, "button[data-prepare]").map(b => [b.textContent, b.disabled, b.title])) : "no row");
  check("V13j. ...while YouTube and TikTok take it (enabled), and a video of at most 50 MB has no such reason",
    btnOf(bigRow, "youtube").disabled === false && btnOf(bigRow, "tiktok").disabled === false && btnOf(smallRow, "instagram").disabled === false &&
    btnOf(smallRow, "facebook").disabled === false && $(smallRow, ".sf-why").length === 0);
  // TikTok's preview of a parted video
  u = await runUpload(FILES, (p, method) => {
    if (p === "/api/videos" && method === "GET") return { status: 200, body: { videos: [V_NEW, V_BIG], max_bytes: 500 * MIB, ready_max: 2 } };
    if (p === "/api/videos/" + V_BIG.id + "/preview") return { status: 200, body: { url: PREVIEW_URL, mime: "video/mp4", expires_in: 600, partial: true, note: "Preview shows the start of the video." } };
    return null;
  });
  buttonIn(rowOf(u.doc, V_BIG.id), "Prepare for TikTok").click();
  await waitFor(() => !!u.doc.querySelector("#ytVideoList .sf-panel video"));
  await flush(5);
  const partNote = $(u.doc, "#ytVideoList .sf-panel p").filter(p => p.textContent === "Preview shows the start of the video.");
  buttonIn(rowOf(u.doc, V_NEW.id), "Prepare for TikTok").click();
  await waitFor(() => !!rowOf(u.doc, V_NEW.id).querySelector(".sf-panel video"));
  await flush(5);
  check("V13k. TikTok's preview of a video over 50 MB says \"Preview shows the start of the video.\" under the player; a whole video's does not",
    partNote.length === 1 && partNote[0].previousElementSibling && partNote[0].previousElementSibling.tagName === "VIDEO" &&
    $(rowOf(u.doc, V_NEW.id), ".sf-panel p").every(p => p.textContent !== "Preview shows the start of the video."), J(partNote.length));
  const proposalsSrc = fs.readFileSync(path.join(FRONTEND, "proposals.html"), "utf8");
  check("V13l. the Proposals card's preview says the same when the answer is partial",
    proposalsSrc.indexOf("msg.textContent = r.d.partial === true ? \"Preview shows the start of the video.\" : \"\";") !== -1);
  check("V13m. the bar and Cancel sit in Your videos: <progress id=\"ytUploadBar\" max=\"100\"> labelled, Cancel upload beside it, hidden until an upload runs",
    FILES[PAGE].indexOf("<div class=\"bsky-row\" id=\"ytUploadProgress\" hidden><progress id=\"ytUploadBar\" max=\"100\" value=\"0\" aria-label=\"Upload progress\"></progress> <button type=\"button\" class=\"action-btn action-btn--ghost\" id=\"ytUploadCancel\">Cancel upload</button></div>") !== -1 &&
    !!u.doc.getElementById("videosCard") && u.doc.getElementById("videosCard").contains(u.doc.getElementById("ytUploadProgress")));

  windows.forEach(w => { try { w.close(); } catch (e) { /* closed */ } });
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
