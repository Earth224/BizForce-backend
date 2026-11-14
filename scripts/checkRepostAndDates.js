#!/usr/bin/env node
/* checkRepostAndDates.js — NAMED (Nov 13 2026, S3 polish): "Post again" on the Social page's Your videos, and
   readable dates on proposal cards. (The card picker is held by scripts/checkCardEditorTabs.js, PK-n; the
   server's repost flag for YouTube and TikTok by checkYoutubeUploads.js and checkTiktokPosting.js, RP-n.)

   B. THE BUTTONS. agents/social.html in jsdom with scripts/oauth-return.js, youtube.js, tiktok.js,
      instagram.js and facebook.js, all four platforms connected, one video in each status:
        not sent           "Prepare for <Platform>", enabled;
        waiting / publishing the same button disabled, its reason beside it ("Waiting for your approval"
                           with a link to Proposals; "Publishing"), named by aria-describedby;
        posted             "Post again on <Platform>", enabled;
        failed             "Try again on <Platform>", enabled (YouTube has no failed state);
        a file the platform can't take keeps its disabled reason (MP4 or MOV), whatever the status;
        an unfinished upload keeps "Prepare for ..." (its resume is the server's).
   D. THE DIALOG. "Post again" asks first: role dialog, aria-modal, labelled "This video is already on
      <Platform>. Post it again?", Post again and Cancel, focus on Cancel, Tab kept inside, Escape and
      Cancel and a click outside cancel with no form and no request, focus back on the button.
   F. THE FLAG. repost: true is in the filing only after "Post again" was confirmed, on all four
      platforms; never from Prepare or Try again.
   S. THE SERVER'S SIDE. GET /api/videos <platform>_proposal ("pending", "publishing" or null) from the
      same one bounded read of agent_proposals (lib/memberVideos.js); Instagram and Facebook take a
      flagged repost of a posted video, as they took an unflagged one before (they never refused a
      second post), and keep one pending proposal per video.
   C. THE DATES. proposals.html .proposal-date: the theme's accent mixed into the muted text colour, at
      least 4.5:1 against the card on all 11 theme presets (the card over the page's black and over
      each glow), from the theme tokens (scripts/bf-theme.js tokensFor); size and placement unchanged.

   No network, no database, no model call. BIZFORCE_FRONTEND_DIR overrides the frontend location.
   MUTATE=<name> applies one mutation in memory; MUTATE=all runs every mutation (each must be caught). */
"use strict";
const fs = require("fs");
const path = require("path");
const Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const PAGE = "agents/social.html", OAUTH = "scripts/oauth-return.js", YT = "scripts/youtube.js", TT = "scripts/tiktok.js",
  IG = "scripts/instagram.js", FB = "scripts/facebook.js", PROPOSALS = "proposals.html", THEME = "scripts/bf-theme.js";
const MV = "lib/memberVideos.js", IGAPI = "lib/instagramApi.js", FBAPI = "lib/facebookApi.js";
const FRONT_FILES = [PAGE, OAUTH, YT, TT, IG, FB, PROPOSALS, THEME];
const BACK_FILES = [MV, IGAPI, FBAPI];

const MUTATIONS = {
  // a posted video shows "Prepare for ..." again (B4)
  "posted-shows-prepare": [[YT, "    if (state === \"posted\") return \"Post again on \" + word;\n", ""]],
  // a waiting or publishing video's button can be pressed (B2, B3)
  "pending-button-enabled": [[YT, "        if (state === \"pending\" || state === \"publishing\") {\n          b.disabled = true;\n",
    "        if (state === \"pending\" || state === \"publishing\") {\n          b.disabled = false;\n"]],
  // "Post again" opens the form at once, flagged, with no question (D1, F1)
  "repost-without-confirm": [[YT, "          if (state !== \"posted\" || (openForm && openForm.key === key)) {\n            toggleForm(key, slot, title, function (shell) { build(shell, false); });\n",
    "          if (true) {\n            toggleForm(key, slot, title, function (shell) { build(shell, state === \"posted\"); });\n"]],
  // the date line back to its old dim colour (C1)
  "date-low-contrast": [[PROPOSALS, "color:#8892b8;color:color-mix(in srgb,var(--bf-accent-a, #22d3ee) 40%,#8892b8);", "color:#4a5280;"]],
  // (extra) every YouTube filing says repost (F2)
  "repost-flag-always": [[YT, "      if (repost === true) body.repost = true;\n", "      body.repost = true;\n"]],
  // (extra) Tab leaves the dialog (D2)
  "dialog-no-focus-trap": [[YT, "        if (e.key !== \"Tab\") return;\n        e.preventDefault();\n        var at = trap.indexOf(document.activeElement);\n",
    "        if (e.key !== \"Tab\") return;\n        return;\n        var at = trap.indexOf(document.activeElement);\n"]],
  // (extra) Escape doesn't cancel (D3)
  "dialog-escape-ignored": [[YT, "        if (e.key === \"Escape\") { e.preventDefault(); done(false); return; }\n", ""]],
  // (extra) the dialog loses its role (D1)
  "dialog-not-aria": [[YT, "      box.setAttribute(\"role\", \"dialog\");\n      box.setAttribute(\"aria-modal\", \"true\");\n", ""]],
  // (extra) Instagram's confirmed repost files without the flag (F1)
  "ig-flag-lost": [[IG, "      if (repostFor && body.video_id === repostFor) body.repost = true;\n", ""]],
  // (extra) the server never says a proposal is waiting (S1)
  "proposal-state-ignored": [[MV, "  var filed = function (k) { return pp[k] === \"pending\" || pp[k] === \"publishing\" ? pp[k] : null; };",
    "  var filed = function (k) { return null; };"]],
  // (extra) the waiting reason is not beside the button (B2)
  "reason-not-shown": [[YT, "          actions.appendChild(why);\n", ""]],
  // (extra) the date line moves (C3)
  "date-moved": [[PROPOSALS, "40%,#8892b8);margin-left:auto}", "40%,#8892b8)}"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
FRONT_FILES.forEach(f => {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(2); }
  FILES[f] = lf(fs.readFileSync(p, "utf8"));
});
BACK_FILES.forEach(f => { FILES[f] = lf(fs.readFileSync(path.join(REPO, f), "utf8")); });
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 600) + "]" : "")); }
}
process.on("unhandledRejection", e => check("no page request is left unhandled", false, (e && e.message) || e));
const J = JSON.stringify;
const API = "https://dynamic-prosperity-production-5382.up.railway.app";
const flush = async (n) => { for (let i = 0; i < (n || 12); i++) await new Promise(r => setTimeout(r, 0)); };
function stripScripts(html) { return html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, ""); }
const $ = (root, sel) => Array.from(root.querySelectorAll(sel));
const windows = [];

// A lib file compiled from FILES (so a mutation in memory is what runs), resolving its requires from lib/.
function loadLib(rel, overrides) {
  const file = path.join(REPO, rel);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  const realReq = Module.createRequire(file);
  m.require = function (r) { return overrides && Object.prototype.hasOwnProperty.call(overrides, r) ? overrides[r] : realReq(r); };
  m._compile(FILES[rel], file);
  return m.exports;
}

/* ── fixtures: one video per status ── */
const SINCE = "2026-11-07T10:00:00Z";
const V0 = { label: "Clip", bytes: 3 * 1048576, mime: "video/mp4", status: "ready", youtube_video_id: null, youtube_url: null, uploaded_at: null,
  created_at: "2026-11-07T10:00:00Z", upload_unfinished: false, tiktok_status: null, tiktok_posted_at: null, tiktok_post_url: null, tiktok_upload_unfinished: false,
  instagram_status: "not_sent", instagram_post_url: null, instagram_error: null, facebook_status: "not_sent", facebook_post_url: null, facebook_error: null,
  youtube_proposal: null, tiktok_proposal: null, instagram_proposal: null, facebook_proposal: null };
const vid = (n, label, extra) => Object.assign({}, V0, { id: "5555555" + n + "-5555-4555-8555-555555555555", label: label }, extra);
const IG_URL = "https://www.instagram.com/reel/AbCdEf123/", FB_URL = "https://www.facebook.com/100000000000001/videos/300000000000003/";
const VN = vid("1", "Not sent");
const VP = vid("2", "Posted", { youtube_video_id: "dQw4w9WgXcQ", youtube_url: "https://www.youtube.com/watch?v=dQw4w9WgXcQ", uploaded_at: SINCE,
  tiktok_status: "posted", tiktok_posted_at: SINCE, tiktok_post_url: "https://www.tiktok.com/player/v1/7300000000000000001",
  instagram_status: "posted", instagram_post_url: IG_URL, facebook_status: "posted", facebook_post_url: FB_URL });
const VW = vid("3", "Waiting", { youtube_proposal: "pending", tiktok_proposal: "pending", instagram_status: "pending", instagram_proposal: "pending",
  facebook_status: "pending", facebook_proposal: "pending" });
const VB = vid("4", "Publishing", { youtube_proposal: "publishing", tiktok_status: "processing", instagram_status: "publishing", instagram_proposal: "publishing",
  facebook_status: "publishing" });
const VF = vid("5", "Failed", { tiktok_status: "failed", instagram_status: "failed", instagram_error: "The video is too short for a Reel.",
  facebook_status: "failed", facebook_error: "The Page token expired." });
const VX = vid("6", "WebM", { mime: "video/webm", instagram_status: "pending", instagram_proposal: "pending", facebook_status: "posted", facebook_post_url: FB_URL });
const VU = vid("7", "Unfinished", { upload_unfinished: true, tiktok_status: "initiated", tiktok_upload_unfinished: true });
const VR = vid("8", "Posted, repost waiting", { youtube_video_id: "dQw4w9WgXcQ", youtube_url: "https://www.youtube.com/watch?v=dQw4w9WgXcQ", uploaded_at: SINCE,
  youtube_proposal: "pending", instagram_status: "posted", instagram_post_url: IG_URL, instagram_proposal: "pending" });
const VIDEOS = [VN, VP, VW, VB, VF, VX, VU, VR];
const CREATOR = { creator_nickname: "Maple Street Bakery", privacy_level_options: ["PUBLIC_TO_EVERYONE", "MUTUAL_FOLLOW_FRIENDS", "SELF_ONLY"],
  comment_disabled: false, duet_disabled: false, stitch_disabled: false, privacy_words: { PUBLIC_TO_EVERYONE: "Everyone", MUTUAL_FOLLOW_FRIENDS: "Friends", SELF_ONLY: "Only you" } };

async function runSocial() {
  const reqs = [];
  const dom = new JSDOM(stripScripts(FILES[PAGE]), { url: "https://bizforceai.net/agents/social.html", runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  windows.push(w);
  w.localStorage.setItem("bf_token", "tok");
  w.fetch = function (url, init) {
    const p = String(url).replace(API, "");
    const method = (init && init.method) || "GET";
    reqs.push({ method: method, path: p, body: init && init.body ? JSON.parse(init.body) : undefined });
    let a = { status: 404, body: { error: "not in this fixture: " + method + " " + p } };
    const st = { status: "connected", connected: true, since: SINCE };
    if (p === "/api/youtube/status") a = { status: 200, body: Object.assign({ youtube_available: true, channel_title: "Maple Street" }, st) };
    if (p === "/api/tiktok/status") a = { status: 200, body: Object.assign({ tiktok_available: true, display_name: "Maple Street" }, st) };
    if (p === "/api/instagram/status") a = { status: 200, body: Object.assign({ instagram_available: true, username: "maplestreet" }, st) };
    if (p === "/api/facebook/status") a = { status: 200, body: Object.assign({ facebook_available: true, page_name: "Maple Street" }, st) };
    if (p === "/api/videos" && method === "GET") a = { status: 200, body: { videos: VIDEOS, max_bytes: 52428800, ready_max: 2 } };
    if (p === "/api/instagram/posts" || p === "/api/facebook/posts") a = { status: 200, body: { posts: [] } };
    if (p === "/api/tiktok/creator-info") a = { status: 200, body: CREATOR };
    if (/propose/.test(p)) a = { status: 201, body: { note: "Filed for approval." } };
    const pr = Promise.resolve({ ok: a.status < 300, status: a.status, json: function () { return Promise.resolve(a.body); } });
    pr.catch(function () {});
    return pr;
  };
  [OAUTH, YT, TT, IG, FB].forEach(f => w.eval(FILES[f] + "\n//# sourceURL=" + f));
  await flush(20);
  const doc = w.document;
  const row = v => doc.querySelector("#ytVideoList li[data-video-id=\"" + v.id + "\"]");
  const btn = (v, p) => row(v) && row(v).querySelector("button[data-prepare=\"" + p + "\"]");
  const dialog = () => doc.querySelector(".sf-dialog-back [role='dialog']") || doc.querySelector(".sf-dialog-back .sf-dialog");
  const panels = () => $(doc, "#ytVideoList .sf-panel");
  const key = async (k, shift) => { doc.dispatchEvent(new w.KeyboardEvent("keydown", { key: k, shiftKey: !!shift, bubbles: true, cancelable: true })); await flush(4); };
  const dialogButton = label => { const d = dialog(); return d ? $(d, "button").filter(b => b.textContent === label)[0] || null : null; };
  return { w, doc, reqs, row, btn, dialog, panels, key, dialogButton };
}

const PLATFORMS = [["youtube", "YouTube"], ["tiktok", "TikTok"], ["instagram", "Instagram"], ["facebook", "Facebook"]];

/* A small in-memory Supabase for lib/instagramApi.js and lib/facebookApi.js filings, and memberVideos reads. */
function fakeDb(tables) {
  const log = [];
  function from(table) {
    const q = { table, calls: [], insertRow: null, head: false, single: null };
    log.push(q);
    const api = {};
    ["eq", "neq", "in", "gte", "lte", "is", "order", "limit", "not", "lt", "gt"].forEach(m => { api[m] = function () { q.calls.push([m].concat(Array.from(arguments))); return api; }; });
    api.select = function (cols, opts) { q.calls.push(["select", cols]); if (opts && opts.head) q.head = true; return api; };
    api.insert = function (row) { q.insertRow = Object.assign({ id: "p" + Math.random().toString(16).slice(2) }, row); q.calls.push(["insert"]); return api; };
    api.maybeSingle = function () { q.single = "maybe"; return api; };
    api.single = function () { q.single = "one"; return api; };
    api.then = function (res, rej) {
      if (q.insertRow) { (tables[table] = tables[table] || []).push(q.insertRow); return Promise.resolve({ data: q.insertRow, error: null }).then(res, rej); }
      let rows = (tables[table] || []).slice();
      for (const c of q.calls) {
        if (c[0] === "eq") rows = rows.filter(r => r[c[1]] === c[2]);
        if (c[0] === "neq") rows = rows.filter(r => r[c[1]] !== c[2]);
        if (c[0] === "in") rows = rows.filter(r => c[2].indexOf(r[c[1]]) !== -1);
        if (c[0] === "gte") rows = rows.filter(r => String(r[c[1]]) >= String(c[2]));
        if (c[0] === "limit") rows = rows.slice(0, c[1]);
      }
      if (q.head) return Promise.resolve({ data: null, count: rows.length, error: null }).then(res, rej);
      if (q.single) return Promise.resolve({ data: rows[0] || null, error: null }).then(res, rej);
      return Promise.resolve({ data: rows, error: null }).then(res, rej);
    };
    return api;
  }
  return { from, log };
}

(async function main() {
  /* ── B ── */
  console.log("\n══ B. one button per connected platform, by what that platform has of the video ══");
  const S = await runSocial();
  const state = (v, p) => { const b = S.btn(v, p); return b ? [b.textContent, b.disabled, b.getAttribute("data-state")] : null; };
  const all = v => PLATFORMS.map(([p]) => state(v, p));
  check("B1. not sent: \"Prepare for YouTube\", \"Prepare for TikTok\", \"Prepare for Instagram\", \"Prepare for Facebook\", each enabled",
    J(all(VN)) === J(PLATFORMS.map(([, w]) => ["Prepare for " + w, false, "new"])), J(all(VN)));
  const whyOf = b => { const id = b && b.getAttribute("aria-describedby"); const n = id ? S.doc.getElementById(id) : null; return n ? n : null; };
  const waitOk = (v, p) => {
    const b = S.btn(v, p), why = whyOf(b);
    const link = why && why.nextElementSibling;
    return !!b && b.disabled === true && !!why && why.textContent === "Waiting for your approval" && b.nextElementSibling === why && why.className === "sf-why" &&
      !!link && link.tagName === "A" && link.textContent === "Open Proposals" && link.getAttribute("href") === "/proposals.html";
  };
  check("B2. waiting for approval: each button disabled, \"Waiting for your approval\" beside it (aria-describedby), and a link to Proposals",
    PLATFORMS.every(([p]) => waitOk(VW, p)) && J(all(VW).map(x => x && x[0])) === J(["Prepare for YouTube", "Prepare for TikTok", "Prepare for Instagram", "Prepare for Facebook"]),
    J(all(VW)) + " " + PLATFORMS.map(([p]) => { const y = whyOf(S.btn(VW, p)); return y ? y.textContent : "no reason"; }).join("|"));
  const pubOk = (v, p) => { const b = S.btn(v, p), why = whyOf(b); return !!b && b.disabled === true && !!why && why.textContent === "Publishing" && b.nextElementSibling === why &&
    !(why.nextElementSibling && why.nextElementSibling.tagName === "A" && why.nextElementSibling.textContent === "Open Proposals"); };
  check("B3. publishing (an executing proposal; TikTok processing): each button disabled, \"Publishing\" beside it, no Proposals link",
    PLATFORMS.every(([p]) => pubOk(VB, p)), J(all(VB)));
  check("B4. posted: \"Post again on YouTube\", \"Post again on TikTok\", \"Post again on Instagram\", \"Post again on Facebook\", each enabled",
    J(all(VP)) === J(PLATFORMS.map(([, w]) => ["Post again on " + w, false, "posted"])), J(all(VP)));
  check("B5. failed: \"Try again on TikTok\", \"Try again on Instagram\", \"Try again on Facebook\" enabled; YouTube (no failed state) \"Prepare for YouTube\"",
    J(all(VF)) === J([["Prepare for YouTube", false, "new"], ["Try again on TikTok", false, "failed"], ["Try again on Instagram", false, "failed"], ["Try again on Facebook", false, "failed"]]), J(all(VF)));
  const igX = S.btn(VX, "instagram"), fbX = S.btn(VX, "facebook");
  check("B6. the file rule wins: a WebM's Instagram (waiting) and Facebook (posted) buttons are disabled with the MP4 or MOV reason and no other",
    !!igX && igX.disabled && igX.title === "Instagram Reels need an MP4 or MOV video." && !whyOf(igX) && !!fbX && fbX.disabled && fbX.title === "Facebook videos must be MP4 or MOV." && !whyOf(fbX) &&
    state(VX, "youtube")[1] === false && state(VX, "tiktok")[1] === false, J([state(VX, "instagram"), state(VX, "facebook"), igX && igX.title]));
  check("B7. an unfinished upload keeps \"Prepare for YouTube\" and \"Prepare for TikTok\", enabled (the server resumes it)",
    J([state(VU, "youtube"), state(VU, "tiktok")]) === J([["Prepare for YouTube", false, "new"], ["Prepare for TikTok", false, "new"]]), J([state(VU, "youtube"), state(VU, "tiktok")]));
  check("B8. a posted video with a repost waiting: its button waits too (disabled, the reason), the post's link kept",
    waitOk(VR, "youtube") && waitOk(VR, "instagram") && $(S.row(VR), "a").some(a => a.href === IG_URL) && state(VR, "tiktok")[0] === "Prepare for TikTok", J(all(VR)));
  const chips = v => $(S.row(v), ".sf-chip").map(c => c.textContent);
  check("B9. YouTube's and TikTok's chips say a filed post waits or publishes", chips(VW).indexOf("YouTube: waiting for your approval") !== -1 &&
    chips(VW).indexOf("TikTok: waiting for your approval") !== -1 && chips(VB).indexOf("YouTube: publishing") !== -1 && chips(VB).indexOf("TikTok: processing") !== -1, J([chips(VW), chips(VB)]));
  const rule = (src, sel) => { const i = src.indexOf(sel + " {"); return i === -1 ? "" : src.slice(i, src.indexOf("}", i) + 1); };
  check("B10. the reason and the dialog are styled from the theme tokens", /var\(--bf-warning, #fbbf24\)/.test(rule(FILES[PAGE], ".sf-why")) &&
    /var\(--bf-accent-a, #22d3ee\)/.test(rule(FILES[PAGE], ".sf-why-link")) && /position: fixed; inset: 0; z-index: 1000/.test(rule(FILES[PAGE], ".sf-dialog-back")) &&
    /rgba\(var\(--bf-accent-a3-rgb, 0, 229, 255\), \.3\)/.test(rule(FILES[PAGE], ".sf-dialog")));

  /* ── D ── */
  console.log("\n══ D. \"Post again\" asks first ══");
  const before = S.reqs.length;
  const ytP = S.btn(VP, "youtube");
  ytP.focus();
  ytP.click();
  await flush();
  const dlg = S.dialog();
  const lab = dlg ? S.doc.getElementById(dlg.getAttribute("aria-labelledby")) : null;
  check("D1. \"Post again on YouTube\" opens no form; it opens a dialog: role dialog, aria-modal, labelled \"This video is already on YouTube. Post it again?\", Post again and Cancel, focus on Cancel",
    !!dlg && dlg.getAttribute("role") === "dialog" && dlg.getAttribute("aria-modal") === "true" && !!lab && lab.textContent === "This video is already on YouTube. Post it again?" &&
    J($(dlg, "button").map(b => b.textContent)) === J(["Post again", "Cancel"]) && S.doc.activeElement === S.dialogButton("Cancel") && S.panels().length === 0 && S.reqs.length === before,
    J([!!dlg, lab && lab.textContent, dlg && $(dlg, "button").map(b => b.textContent), S.panels().length]));
  const trail = [];
  await S.key("Tab"); trail.push(S.doc.activeElement.textContent);
  await S.key("Tab"); trail.push(S.doc.activeElement.textContent);
  await S.key("Tab", true); trail.push(S.doc.activeElement.textContent);
  await S.key("Tab", true); trail.push(S.doc.activeElement.textContent);
  check("D2. Tab and Shift+Tab stay on the dialog's two buttons", J(trail) === J(["Post again", "Cancel", "Post again", "Cancel"]), J(trail));
  await S.key("Escape");
  check("D3. Escape cancels: the dialog closes, no form, no request, focus back on \"Post again on YouTube\"",
    !S.dialog() && S.panels().length === 0 && S.reqs.length === before && S.doc.activeElement === ytP, J([!!S.dialog(), S.panels().length]));
  ytP.click(); await flush();
  S.dialogButton("Cancel").click(); await flush();
  const afterCancel = [!S.dialog(), S.panels().length, S.reqs.length === before];
  ytP.click(); await flush();
  const back = S.doc.querySelector(".sf-dialog-back");
  back.dispatchEvent(new S.w.MouseEvent("click", { bubbles: true }));
  await flush();
  check("D4. Cancel, and a click outside the dialog, cancel the same way", J(afterCancel) === J([true, 0, true]) && !S.dialog() && S.panels().length === 0 && S.reqs.length === before, J(afterCancel));
  const ttP = S.btn(VP, "tiktok");
  ttP.click(); await flush();
  const ttLab = S.dialog() ? S.doc.getElementById(S.dialog().getAttribute("aria-labelledby")) : null;
  const ttWords = ttLab ? ttLab.textContent : "";
  S.dialogButton("Cancel").click(); await flush();
  check("D5. each platform names itself: \"This video is already on TikTok. Post it again?\"", ttWords === "This video is already on TikTok. Post it again?", ttWords);
  S.btn(VF, "tiktok").click(); await flush();
  const tryOpens = !S.dialog() && S.panels().length === 1;
  S.btn(VF, "tiktok").click(); await flush();
  S.btn(VN, "youtube").click(); await flush();
  const prepOpens = !S.dialog() && S.panels().length === 1;
  check("D6. \"Try again\" and \"Prepare\" open the form at once, with no question", tryOpens && prepOpens, J([tryOpens, prepOpens]));
  S.btn(VN, "youtube").click(); await flush();

  /* ── F ── */
  console.log("\n══ F. repost: true only after the question was answered \"Post again\" ══");
  const lastBody = p => { const x = S.reqs.filter(r => r.path === p); return x.length ? x[x.length - 1].body : null; };
  async function fileYoutube(v) {
    const panel = S.panels()[0];
    const texts = $(panel, "input[type=text]");
    texts[0].value = "Spring cakes"; texts[1].value = "cakes";
    $(panel, "input[type=radio]").filter(x => x.value === "no")[0].checked = true;
    $(panel, "button").filter(b => b.textContent === "File for approval")[0].click();
    await flush();
    return lastBody("/api/youtube/propose-upload");
  }
  async function fileTiktok() {
    const panel = S.panels()[0];
    const sel = $(panel, "select").filter(x => x.options[0] && x.options[0].textContent === "Choose who can see it")[0];
    sel.value = "SELF_ONLY";
    const cap = panel.querySelector("#" + $(panel, "label").filter(l => l.textContent === "Caption")[0].getAttribute("for"));
    cap.value = "Spring cakes.";
    $(panel, "button").filter(b => b.textContent === "File for approval")[0].click();
    await flush();
    return lastBody("/api/tiktok/propose-post");
  }
  async function fileIg() { S.doc.getElementById("igCaption").value = "Spring cakes."; S.doc.getElementById("igFileBtn").click(); await flush(); return lastBody("/api/instagram/propose-post"); }
  async function fileFb() { S.doc.getElementById("fbMessage").value = "Spring cakes."; S.doc.getElementById("fbFileBtn").click(); await flush(); return lastBody("/api/facebook/propose-post"); }
  const FILERS = { youtube: fileYoutube, tiktok: fileTiktok, instagram: fileIg, facebook: fileFb };
  const confirmed = {}, plain = {}, retried = {};
  for (const [p] of PLATFORMS) {
    S.btn(VP, p).click(); await flush();
    const asked = !!S.dialog();
    if (S.dialogButton("Post again")) S.dialogButton("Post again").click();
    await flush(20);
    const open = S.panels().length === 1;
    const body = open ? await FILERS[p](VP) : null;
    confirmed[p] = { asked, open, repost: body ? body.repost : "no filing", video: body ? body.video_id : null };
    S.btn(VP, p).click(); await flush();   // the same button closes the form
    S.btn(VN, p).click(); await flush(20);
    const b2 = S.panels().length === 1 ? await FILERS[p](VN) : null;
    plain[p] = b2 ? ("repost" in b2) : "no filing";
    S.btn(VN, p).click(); await flush();
  }
  check("F1. after \"Post again\" is confirmed, each platform's filing says repost: true for that video (YouTube, TikTok, Instagram, Facebook)",
    PLATFORMS.every(([p]) => confirmed[p].asked && confirmed[p].open && confirmed[p].repost === true && confirmed[p].video === VP.id), J(confirmed));
  check("F2. a filing from \"Prepare for ...\" never carries the flag (no repost key at all)", PLATFORMS.every(([p]) => plain[p] === false), J(plain));
  for (const p of ["tiktok", "instagram", "facebook"]) {
    S.btn(VF, p).click(); await flush(20);
    const b3 = S.panels().length === 1 ? await FILERS[p](VF) : null;
    retried[p] = b3 ? ("repost" in b3) : "no filing";
    S.btn(VF, p).click(); await flush();
  }
  check("F3. nor from \"Try again on ...\"", ["tiktok", "instagram", "facebook"].every(p => retried[p] === false), J(retried));
  S.btn(VP, "instagram").click(); await flush();
  S.dialogButton("Post again").click(); await flush(20);
  S.btn(VP, "instagram").click(); await flush();
  S.doc.getElementById("igKindReel").checked = true; S.doc.getElementById("igKindReel").dispatchEvent(new S.w.Event("change")); await flush();
  S.doc.getElementById("igVideo").value = VP.id;
  const igCard = await fileIg();
  check("F4. once the form is closed the flag is gone: the same video filed from the Instagram card says no repost", !!igCard && !("repost" in igCard), J(igCard));

  /* ── S ── */
  console.log("\n══ S. the server's side ══");
  let mv = null;
  try { mv = loadLib(MV); } catch (e) { check("S0. lib/memberVideos.js loads", false, e.message); }
  if (mv) {
    const U = "11111111-1111-4111-8111-111111111111";
    const A = "a1111111-1111-4111-8111-111111111111", B = "a2222222-2222-4222-8222-222222222222", C = "a3333333-3333-4333-8333-333333333333";
    const vrow = (id, at, extra) => Object.assign({ id: id, user_id: U, path: "video/" + U + "/x.mp4", mime: "video/mp4", bytes: 1000, sha256: "x", label: "L", status: "ready", created_at: at }, extra || {});
    const tables = {
      member_videos: [vrow(A, "2026-11-10", { youtube_video_id: "dQw4w9WgXcQ" }), vrow(B, "2026-11-11"), vrow(C, "2026-11-12")],
      instagram_posts: [{ user_id: U, video_id: A, status: "published", permalink: IG_URL, error: null, created_at: "2026-11-10" }],
      facebook_posts: [],
      agent_proposals: [
        { user_id: U, action_type: "publish_youtube_video", status: "pending", payload: { video_id: A, repost: true }, created_at: "2026-11-12" },
        { user_id: U, action_type: "publish_tiktok_post", status: "executing", payload: { video_id: B }, created_at: "2026-11-12" },
        { user_id: U, action_type: "publish_instagram_post", status: "pending", payload: { video: { id: A } }, created_at: "2026-11-12" },
        { user_id: U, action_type: "publish_facebook_post", status: "pending", payload: { video: { id: C } }, created_at: "2026-11-12" },
        { user_id: U, action_type: "publish_youtube_video", status: "executed", payload: { video_id: C }, created_at: "2026-11-09" },
        { user_id: "99999999-9999-4999-8999-999999999999", action_type: "publish_tiktok_post", status: "pending", payload: { video_id: C }, created_at: "2026-11-12" }]
    };
    const db = fakeDb(tables);
    let list = null, err = null;
    try { list = await mv.listVideos({ supabase: db, now: () => 0 }, U); } catch (e) { err = e; }
    const by = id => (list || []).filter(v => v.id === id)[0] || {};
    const pick = v => [v.youtube_proposal, v.tiktok_proposal, v.instagram_proposal, v.facebook_proposal];
    check("S1. GET /api/videos says each platform's filed proposal: a waiting YouTube repost and Instagram post on a posted video, TikTok executing (publishing), Facebook waiting",
      J(pick(by(A))) === J(["pending", null, "pending", null]) && J(pick(by(B))) === J([null, "publishing", null, null]) && J(pick(by(C))) === J([null, null, null, "pending"]) &&
      by(A).instagram_status === "posted", err ? err.message : J([pick(by(A)), pick(by(B)), pick(by(C)), by(A).instagram_status]));
    const props = db.log.filter(q => q.table === "agent_proposals");
    check("S2. ...from the same one read of agent_proposals, bounded by the member and SOCIAL_ROWS_MAX, pending and executing only; no write",
      props.length === 1 && props[0].calls.some(c => c[0] === "eq" && c[1] === "user_id" && c[2] === U) && props[0].calls.some(c => c[0] === "limit" && c[1] === mv.SOCIAL_ROWS_MAX) &&
      props[0].calls.some(c => c[0] === "in" && c[1] === "status" && J(c[2]) === J(["pending", "executing"])) &&
      props[0].calls.some(c => c[0] === "in" && c[1] === "action_type" && J(c[2].slice().sort()) === J(["publish_facebook_post", "publish_instagram_post", "publish_tiktok_post", "publish_youtube_video"])) &&
      !db.log.some(q => q.insertRow), J(props.map(q => q.calls)));
    const failing = { from: function (t) { if (t === "agent_proposals") { const f = fakeDb({}).from(t); f.then = (res, rej) => Promise.resolve({ data: null, error: { message: "down" } }).then(res, rej); return f; } return fakeDb(tables).from(t); } };
    let l2 = null;
    try { l2 = await mv.listVideos({ supabase: failing, now: () => 0 }, U); } catch (e) { l2 = null; }
    check("S3. proposals unreadable: every <platform>_proposal null and the list still answers (the server's one-pending guard still refuses a second filing)",
      Array.isArray(l2) && l2.length === 3 && l2.every(v => J(pick(v)) === J([null, null, null, null])));
    check("S4. a video just added (no read yet): all four null", J(pick(mv.publicView({ id: A, status: "ready" }))) === J([null, null, null, null]));
  }
  // Instagram and Facebook: never refused a second post; a flagged repost is filed the same, and one pending stays
  const U2 = "22222222-2222-4222-8222-222222222222", VID = "b1111111-1111-4111-8111-111111111111";
  const SHA = "a".repeat(64);
  const base = () => ({
    member_instagram_connections: [{ user_id: U2, status: "connected", ig_user_id: "17841400000000000", username: "maplestreet" }],
    member_facebook_pages: [{ user_id: U2, status: "connected", page_id: "100000000000001", page_name: "Maple Street" }],
    member_videos: [{ id: VID, user_id: U2, path: "video/" + U2 + "/x.mp4", mime: "video/mp4", bytes: 1000, sha256: SHA, label: "L", status: "ready", created_at: "2026-11-10" }],
    instagram_posts: [{ user_id: U2, video_id: VID, status: "published", permalink: IG_URL, created_at: "2026-11-01T00:00:00Z" }],
    facebook_posts: [{ user_id: U2, video_id: VID, status: "published", permalink: FB_URL, created_at: "2026-11-01T00:00:00Z" }],
    agent_proposals: []
  });
  const deps = db => ({ supabase: db, now: () => Date.parse("2026-11-13T12:00:00Z"), limits: { max: 2200 }, claims: () => null });
  let ig = null, fb = null;
  try { ig = loadLib(IGAPI); fb = loadLib(FBAPI); } catch (e) { check("S5. lib/instagramApi.js and lib/facebookApi.js load", false, e.message); }
  if (ig && fb) {
    const out = {};
    for (const [name, lib, bodyOf] of [["instagram", ig, r => ({ kind: "reel", caption: "Spring cakes.", video_id: VID, repost: r })],
      ["facebook", fb, r => ({ kind: "video", message: "Spring cakes.", video_id: VID, repost: r })]]) {
      const t1 = base(), d1 = fakeDb(t1);
      const plainR = await lib.proposePost(deps(d1), U2, Object.assign(bodyOf(undefined)));
      delete (plainR.body || {}).proposal;
      const t2 = base(), d2 = fakeDb(t2);
      const flagged = await lib.proposePost(deps(d2), U2, bodyOf(true));
      const again = await lib.proposePost(deps(d2), U2, bodyOf(true));
      out[name] = { plain: plainR.status, flagged: flagged.status, again: [again.status, again.body && again.body.code], filed: t2.agent_proposals.length,
        payloadKeys: t2.agent_proposals[0] ? Object.keys(t2.agent_proposals[0].payload).sort() : [] };
    }
    check("S5. Instagram and Facebook, a video they already have: filed with or without the flag, as before (201); one pending per video stays (409 pending); the payload is the same shape",
      ["instagram", "facebook"].every(n => out[n].plain === 201 && out[n].flagged === 201 && out[n].again[0] === 409 && out[n].again[1] === "pending" && out[n].filed === 1 &&
        out[n].payloadKeys.indexOf("repost") === -1), J(out));
  }

  /* ── C ── */
  console.log("\n══ C. the proposal date line on every theme ══");
  const page = FILES[PROPOSALS];
  const dateRule = (/\.proposal-date\{([^}]*)\}/.exec(page) || ["", ""])[1];
  const cardRule = (/\.proposal-card\{([^}]*)\}/.exec(page) || ["", ""])[1];
  const colours = (dateRule.match(/(?:^|;)color:([^;]+)/g) || []).map(x => x.replace(/^;?color:/, "").trim());
  const last = colours[colours.length - 1] || "";
  const mixM = /^color-mix\(in srgb,\s*var\((--[a-z0-9-]+),\s*(#[0-9a-f]{6})\)\s*(\d+)%,\s*(#[0-9a-f]{6})\)$/.exec(last);
  const cardBg = /background:rgba\((\d+),(\d+),(\d+),(\.\d+|0?\.\d+|1)\)/.exec(cardRule);
  const dom = new JSDOM("<!doctype html><html><head></head><body></body></html>", { url: "https://bizforceai.net/proposals.html", runScripts: "outside-only" });
  windows.push(dom.window);
  dom.window.fetch = () => new Promise(() => {});
  let T = null;
  try { dom.window.eval(FILES[THEME]); T = dom.window.BFTheme; } catch (e) { check("C0. scripts/bf-theme.js loads", false, e.message); }
  const hex = h => { h = String(h).replace("#", ""); return [0, 2, 4].map(i => parseInt(h.slice(i, i + 2), 16)); };
  const over = (top, a, under) => under.map((u, i) => u + a * (top[i] - u));
  const ratios = [];
  if (T && cardBg) {
    const card = [Number(cardBg[1]), Number(cardBg[2]), Number(cardBg[3])], alpha = Number(cardBg[4]);
    for (const p of T.PRESETS) {
      const tok = T.tokensFor(p.theme);
      const black = hex(tok["--bf-bg"] || "#070b18");
      const backs = [black, over(hex(p.theme.glow_a), p.theme.glow_a_alpha, black), over(hex(p.theme.glow_b), p.theme.glow_b_alpha, black)];
      let col;
      if (mixM) { const a = hex(tok[mixM[1]] || mixM[2]), b = hex(mixM[4]), k = Number(mixM[3]) / 100; col = a.map((x, i) => x * k + b[i] * (1 - k)); }
      else if (/^#[0-9a-f]{6}$/i.test(last)) col = hex(last);
      else col = null;
      const worst = col ? Math.min.apply(null, backs.map(bk => T.contrast(col, over(card, alpha, bk)))) : 0;
      ratios.push([p.id, Math.round(worst * 100) / 100]);
    }
  }
  console.log("      contrast on the card, worst of black and each glow: " + ratios.map(r => r[0] + " " + r[1].toFixed(2)).join(", "));
  check("C1. the date line is at least 4.5:1 against the card on all 11 presets", ratios.length === 11 && ratios.every(r => r[1] >= 4.5), J(ratios));
  check("C2. its colour comes from the theme tokens (the accent mixed into the muted text colour), with the muted colour as the plain fallback",
    !!mixM && mixM[1] === "--bf-accent-a" && mixM[4] === "#8892b8" && colours.length === 2 && colours[0] === "#8892b8", J(colours));
  check("C3. size and placement unchanged: .72rem, pushed right (margin-left:auto); the card still draws it from created_at",
    /font-size:\.72rem/.test(dateRule) && /margin-left:auto/.test(dateRule) && page.indexOf("'<span class=\"proposal-date\">' + escapeHtml(formatTime(p.created_at)) + '</span>'") !== -1, dateRule);

  windows.forEach(w => { try { w.close(); } catch (e) { /* closed */ } });
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
