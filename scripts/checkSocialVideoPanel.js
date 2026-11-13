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
         payloads filed from each form.

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
  tiktok_status: null, tiktok_posted_at: null, tiktok_post_url: null, tiktok_upload_unfinished: false };
const V_SENT = Object.assign({}, V_NEW, { id: "33333333-3333-4333-8333-333333333333", label: "Autumn menu", mime: "video/webm",
  youtube_video_id: "dQw4w9WgXcQ", youtube_url: "https://www.youtube.com/watch?v=dQw4w9WgXcQ", uploaded_at: "2026-11-07T11:00:00Z",
  tiktok_status: "posted", tiktok_posted_at: "2026-11-07T11:00:00Z", tiktok_post_url: "https://www.tiktok.com/player/v1/7300000000000000001" });
const CREATOR = { creator_nickname: "Maple Street Bakery", privacy_level_options: ["PUBLIC_TO_EVERYONE", "MUTUAL_FOLLOW_FRIENDS", "SELF_ONLY"],
  comment_disabled: false, duet_disabled: true, stitch_disabled: false,
  privacy_words: { PUBLIC_TO_EVERYONE: "Everyone", MUTUAL_FOLLOW_FRIENDS: "Friends", SELF_ONLY: "Only you" } };
const SINCE = "2026-11-07T10:00:00Z";
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
    if (/propose/.test(p)) return { status: 201, body: { note: "Filed for approval." } };
    return { status: 404, body: { error: "not in this fixture: " + method + " " + p } };
  };
}

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
  check("V1d. the Accounts tab carries it, right before ytConnect", tabIds === "[\"bskyConnect\", \"bskyMentions\", \"mastoConnect\", \"videosCard\", \"ytConnect\", \"ttConnect\", \"igConnect\", \"fbConnect\"]", tabIds);

  /* ── V2 ── */
  console.log("\n══ V2. the notes, word for word ══");
  const LIMITS = "Videos up to 50 MB (MP4, WebM or MOV).";
  const KEPT = "BizForce deletes the file once every platform you sent it to has it, or 14 days after you added it.";
  const GOOGLE = "Until Google approves BizForce, YouTube keeps uploads from BizForce private.";
  const TIKTOK = "Until TikTok reviews BizForce, TikTok keeps posts from BizForce visible only to you.";
  const pIn = (root, t) => !!root && $(root, "p").filter(p => p.textContent === t).length === 1;
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
  check("V4a. ...only \"Prepare for YouTube\", on the video YouTube doesn't have; Delete on both",
    J(preparesOf(rowOf(doc, V_NEW.id))) === J(["Prepare for YouTube"]) && J(preparesOf(rowOf(doc, V_SENT.id))) === J([]) &&
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
  check("V4c. ...all four Prepare buttons on the new video; the sent one only Instagram and Facebook, disabled with the reason (WebM)",
    J(preparesOf(rowOf(doc, V_NEW.id))) === J(["Prepare for YouTube", "Prepare for TikTok", "Prepare for Instagram", "Prepare for Facebook"]) &&
    J(preparesOf(rowOf(doc, V_SENT.id))) === J(["Prepare for Instagram", "Prepare for Facebook"]) &&
    $(rowOf(doc, V_SENT.id), "button[data-prepare]").every(b => b.disabled === true && /MP4 or MOV/.test(b.title)),
    J([preparesOf(rowOf(doc, V_NEW.id)), preparesOf(rowOf(doc, V_SENT.id))]));
  check("V4d. ...and the posted TikTok video keeps its player link, the remove line and Check TikTok status",
    $(rowOf(doc, V_SENT.id), "a").some(a => a.href === V_SENT.tiktok_post_url && a.rel === "noopener") &&
    pIn(rowOf(doc, V_SENT.id), "To remove a TikTok post, delete it in the TikTok app.") && !!buttonIn(rowOf(doc, V_SENT.id), "Check TikTok status"));
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
  check("V11a. each script calls the same routes as at " + BASELINE, [YT, TT, IG, FB].every(f => J(routes(FILES[f])) === J(routes(BASE[f]))),
    [YT, TT, IG, FB].filter(f => J(routes(FILES[f])) !== J(routes(BASE[f]))).join());
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

  windows.forEach(w => { try { w.close(); } catch (e) { /* closed */ } });
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
