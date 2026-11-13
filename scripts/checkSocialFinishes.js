#!/usr/bin/env node
/* checkSocialFinishes.js — NAMED (Nov 13 2026, S2): three owner finishes, held together.

   F. proposals.html: every human-readable value on a proposal card is in the page's own font.
      Monospace only inside the "View payload" raw JSON block (pre.exec-block.payload-raw).
      The page runs in jsdom (its inline script, a stubbed API with one card of every kind);
      jsdom applies the page's own stylesheet, so getComputedStyle is the cascade's answer.
   S. lib/memberVideos.js: GET /api/videos carries Instagram's and Facebook's status per video
      (posted with its permalink, publishing, pending approval, failed with the reason, removed,
      not sent, unknown), derived from instagram_posts, facebook_posts and agent_proposals.
      Pure derivation from fixtures; socialStatus and listVideos against a recording fake
      Supabase: reads only, every read bounded by user, ids and SOCIAL_ROWS_MAX.
   C. agents/social.html Your videos: Instagram's and Facebook's chips say that status, a posted
      one links to the post, a failed one says why; chips for connected platforms only; the
      file-type rule stays as the disabled Prepare button's reason.
   G. scripts/termaximus-guide.js: below 640 px the Guide button is a 48 px round icon button,
      named "Guide", bottom-right inside the safe-area insets, z-index 40 (over the page, under
      every dialog), and a spacer pads the page's end (kept last, after a footer appended later)
      so the button never covers the last content. At rest it is raised (or moved to the other
      corner) off any header, nav, tab, heading, field, button or link: the rules here, the
      geometry in scripts/browserCheckSocial.js. Desktop is unchanged.

   No network, no database, no model call. BIZFORCE_FRONTEND_DIR overrides the frontend location.
   MUTATE=<name> applies one mutation in memory; MUTATE=all runs every mutation (each must be caught). */
const fs = require("fs");
const path = require("path");
const Module = require("module");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const PROPOSALS = "proposals.html", PAGE = "agents/social.html", OAUTH = "scripts/oauth-return.js", YT = "scripts/youtube.js",
  TT = "scripts/tiktok.js", IG = "scripts/instagram.js", FB = "scripts/facebook.js", GUIDE = "scripts/termaximus-guide.js";
const MV = "lib/memberVideos.js", SERVER = "server.js";
const FRONT_FILES = [PROPOSALS, PAGE, OAUTH, YT, TT, IG, FB, GUIDE];
const BACK_FILES = [MV, SERVER];

const MUTATIONS = {
  // F: a detail value is in the typewriter font again
  "proposal-mono-back": [[PROPOSALS, ".pf-value{color:#e6edf3;font-family:inherit;",
    ".pf-value{color:#e6edf3;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;"]],
  // F: the raw payload block loses its monospace
  "payload-not-mono": [[PROPOSALS, "'<pre class=\"exec-block payload-raw\">' + escapeHtml(collapsibleText)",
    "'<pre class=\"exec-block\">' + escapeHtml(collapsibleText)"]],
  // C: Instagram's chip ignores the status
  "ig-status-ignored": [[IG, "function statusOf(v) { return Object.prototype.hasOwnProperty.call(STATUS_CHIP, v.instagram_status) ? v.instagram_status : \"not_sent\"; }",
    "function statusOf(v) { return \"not_sent\"; }"]],
  // C: Facebook's chip ignores the status
  "fb-status-ignored": [[FB, "function statusOf(v) { return Object.prototype.hasOwnProperty.call(STATUS_CHIP, v.facebook_status) ? v.facebook_status : \"not_sent\"; }",
    "function statusOf(v) { return \"not_sent\"; }"]],
  // S: a proposal waiting for approval reads as posted
  "pending-shown-as-posted": [[MV, "if (props.some(function (p) { return p.status === \"pending\"; })) return { status: \"pending\", url: null, error: null };",
    "if (props.some(function (p) { return p.status === \"pending\"; })) return { status: \"posted\", url: null, error: null };"]],
  // C: a platform that is not connected gets a chip
  "chip-for-unconnected": [[YT, "      if (!connected[name] || !hook) return;\n", "      if (!hook) return;\n"]],
  // S: listing the videos writes a row
  "videos-route-writes": [[MV, "  return rows.map(function (row) { return publicView(row, social[row.id]); });\n}",
    "  await deps.supabase.from(\"member_videos\").update({ listed_at: new Date(deps.now()).toISOString() }).eq(\"user_id\", userId);\n  return rows.map(function (row) { return publicView(row, social[row.id]); });\n}"]],
  // G: no padding at the page's end on phones: the button covers the last content
  "guide-overlaps-content": [[GUIDE, "    \"  #tmx-guide-fab-spacer { display: block; height: calc(80px + env(safe-area-inset-bottom, 0px)); }\",\n", ""]],
  // G: the phone button shrinks below a 44 px tap target
  "guide-tap-target-small": [[GUIDE, "width: 48px; height: 48px; padding: 0; gap: 0; border-radius: 50%; }", "width: 32px; height: 32px; padding: 0; gap: 0; border-radius: 50%; }"]],
  // S (extra): an unbounded read of a platform table
  "social-read-unbounded": [[MV, "var r = await supabase.from(P.table).select(P.columns).eq(\"user_id\", userId).in(\"video_id\", videoIds)\n        .order(\"created_at\", { ascending: false }).limit(SOCIAL_ROWS_MAX);",
    "var r = await supabase.from(P.table).select(P.columns).eq(\"user_id\", userId)\n        .order(\"created_at\", { ascending: false });"]],
  // S (extra): a failed post's reason is dropped
  "failed-reason-lost": [[MV, "list[0].error.trim().slice(0, 200) : \"not posted\" };", "\"not posted\" : \"not posted\" };"]],
  // C (extra): a posted chip without the link
  "posted-link-lost": [[IG, "      if (s === \"posted\" && typeof v.instagram_post_url === \"string\" && PERMALINK_RE.test(v.instagram_post_url)) row.link(v.instagram_post_url);\n", ""]],
  // G (extra): a footer appended after the Guide ends the page under the button again
  "spacer-not-kept-last": [[GUIDE, "      if (!/^tmx-guide-/.test(n.id || \"\")) { document.body.appendChild(fabSpacer); return; }\n", ""]],
  // G (extra): links are no longer avoided at rest
  "guide-rests-on-links": [[GUIDE, "select,button,a[href],.btn,#videosCard\";", "select,button,.btn,#videosCard\";"]],
  // G (extra): the phone button loses its name
  "guide-name-lost": [[GUIDE, "fab.setAttribute(\"aria-label\", \"Guide\");", "fab.setAttribute(\"aria-label\", \"\");"]]
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
const text = n => (n ? n.textContent.replace(/\s+/g, " ").trim() : "");
const MONO = /monospace|consolas|menlo|courier|sfmono|ui-monospace/i;
const windows = [];

// lib/memberVideos.js compiled from FILES (so a mutation in memory is what runs), resolving its requires from lib/.
function loadMemberVideos() {
  const file = path.join(REPO, MV);
  const m = new Module(file, module);
  m.filename = file;
  m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(FILES[MV], file);
  return m.exports;
}

/* ── fixtures ── */
const VID = "22222222-2222-4222-8222-222222222222";
const P_BASE = { agent_type: "social", status: "pending", reasoning: "Because the owner asked for it.", created_at: "2026-11-13T09:00:00Z", execution_result: null, execution_error: null };
let n = 0;
const prop = (action_type, payload, extra) => Object.assign({}, P_BASE, { id: "p" + (++n), title: "A " + action_type + " card", action_type: action_type, payload: payload }, extra || {});
const PROPOSAL_FIXTURES = [
  prop("publish_blog_post", { slug: "spring-cakes", meta_description: "Spring cakes at Maple Street.", body: "<p>Hello <a href=\"/menu\">menu</a></p>", internal_links: ["/menu", "/about"] }),
  prop("create_calendar_event", { title: "Tasting", event_type: "meeting", notes: "Bring samples", jdn: 2461358, local_year: 2026, local_month: 11, local_day: 20, days_from_now: 7 }),
  prop("send_email_sequence", { name: "Welcome", steps: [{ subject: "Hi", body: "Welcome aboard", delay_days: 0 }, { subject: "Day two", body: "A tip", delay_days: 2 }] }),
  prop("publish_social_post", { platform: "bluesky", posts_as: "maplestreet.bsky.social", text: "Fresh spring cakes today https://maplestreet.example/cakes" }),
  prop("reply_bluesky_mention", { posts_as: "maplestreet.bsky.social", reply: { text: "Thank you!" }, text: "Thank you!" }),
  prop("update_bluesky_profile", { posts_as: "maplestreet.bsky.social", display_name: "Maple Street Bakery", description: "Cakes and bread since 1998." }),
  prop("publish_mastodon_post", { posts_as: "@maple@mastodon.social", text: "Spring cakes are here." }),
  prop("send_mailbox_reply", { to: "pat@example.com", from: "hello@maplestreet.example", subject: "Re: order", text: "Your order is ready." }),
  prop("update_store_item", { platform: "shopify", item_name: "Spring cake", field: "price", currency: "USD", measured: { from: 20, to: 22 } }),
  prop("publish_youtube_video", { channel_id: "UC123", title: "Spring cakes", description: "How we bake them.", privacy: "private", made_for_kids: false, tags: ["cake"], video: { id: VID, bytes: 3145728 } }),
  prop("delete_youtube_video", { channel_id: "UC123", youtube_video_id: "dQw4w9WgXcQ", title: "Old video" }),
  prop("publish_tiktok_post", { title: "Spring cakes", privacy_level: "SELF_ONLY", allow_comment: true, allow_duet: false, allow_stitch: false, video: { id: VID, bytes: 3145728 } }),
  prop("publish_instagram_post", { ig_user_id: "17841400000000000", kind: "reel", caption: "Spring cakes, fresh today.", video: { id: VID, bytes: 3145728 } }),
  prop("publish_facebook_post", { page_id: "100000000000001", kind: "video", message: "Spring cakes, fresh today.", video: { id: VID, bytes: 3145728 } }),
  prop("delete_facebook_post", { page_id: "100000000000001", post_id: "100000000000001_200000000000002" }),
  prop("some_future_action", { anything: "goes", nested: { a: 1 } }),
  prop("publish_instagram_post", { ig_user_id: "17841400000000000", kind: "image", caption: "Done.", items: [{ id: "m1", alt: "A cake" }] },
    { status: "executed", execution_result: { published: true, permalink: "https://www.instagram.com/reel/AbCdEf123/" } }),
  prop("publish_facebook_post", { page_id: "100000000000001", kind: "video", message: "Done.", video: { id: VID, bytes: 3145728 } },
    { status: "executed", execution_result: { published: true, permalink: "https://www.facebook.com/100000000000001/videos/300000000000003/" } }),
  prop("some_future_action", { anything: "goes" }, { status: "executed", execution_result: { done: true, note: "a raw result" } }),
  prop("publish_mastodon_post", { posts_as: "@maple@mastodon.social", text: "x" }, { status: "failed", execution_error: "The server refused the post." })
];

async function runProposals() {
  const html = FILES[PROPOSALS];
  const inline = /<script>\n([\s\S]*?)<\/script>/.exec(html);
  if (!inline) return null;
  const dom = new JSDOM(stripScripts(html), { url: "https://bizforceai.net/proposals.html", runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  windows.push(w);
  w.localStorage.setItem("bf_token", "tok");
  w.fetch = function (url) {
    const p = String(url).replace(API, "");
    let body = { error: "not in this fixture" }, status = 404;
    if (/^\/api\/proposals(\?|$)/.test(p)) { status = 200; body = { proposals: PROPOSAL_FIXTURES }; }
    else if (/^\/api\/media/.test(p)) { status = 200; body = { media: [] }; }
    else if (p === "/api/videos") { status = 200; body = { videos: [{ id: VID, label: "Spring cakes", bytes: 3145728, mime: "video/mp4", status: "ready" }] }; }
    const pr = Promise.resolve({ ok: status < 300, status: status, json: function () { return Promise.resolve(body); } });
    pr.catch(function () {});
    return pr;
  };
  let err = null;
  try { w.eval(inline[1] + "\n//# sourceURL=" + PROPOSALS); } catch (e) { err = e; }
  await flush(30);
  return { w: w, doc: w.document, err: err };
}

/* A recording fake Supabase: every chain is logged; a write method is a write whatever table it names. */
const WRITE_METHODS = ["insert", "update", "upsert", "delete", "rpc"];
function fakeSupabase(tables, opts) {
  const log = [];
  const o = opts || {};
  function chain(table) {
    const q = { table: table, calls: [] };
    log.push(q);
    const api = {};
    ["select", "eq", "in", "order", "limit", "maybeSingle", "single", "neq", "is", "gte", "lte", "not", "filter", "match", "range"].concat(WRITE_METHODS).forEach(mth => {
      api[mth] = function () { q.calls.push([mth].concat(Array.from(arguments))); return api; };
    });
    api.then = function (res, rej) {
      if (o.fail && o.fail.indexOf(table) !== -1) return Promise.resolve({ data: null, error: { message: "relation unavailable" } }).then(res, rej);
      let rows = (tables[table] || []).slice();
      for (const c of q.calls) {
        if (c[0] === "eq") rows = rows.filter(r => r[c[1]] === c[2]);
        if (c[0] === "in") rows = rows.filter(r => c[2].indexOf(r[c[1]]) !== -1);
        if (c[0] === "limit") rows = rows.slice(0, c[1]);
      }
      return Promise.resolve({ data: rows, error: null }).then(res, rej);
    };
    return api;
  }
  return { from: chain, rpc: function () { log.push({ table: "(rpc)", calls: [["rpc"]] }); return Promise.resolve({ data: null, error: null }); }, log: log };
}
const writesIn = log => log.filter(q => q.table === "(rpc)" || q.calls.some(c => WRITE_METHODS.indexOf(c[0]) !== -1));

/* The Social page in jsdom, as in checkSocialVideoPanel.js. */
const SINCE = "2026-11-07T10:00:00Z";
function answersFor(on, videos) {
  const st = c => (c ? "connected" : "not_connected");
  return function (p, method) {
    if (p === "/api/youtube/status") return { status: 200, body: { youtube_available: true, connected: !!on.youtube, status: st(on.youtube), channel_title: "Maple Street", since: SINCE } };
    if (p === "/api/tiktok/status") return { status: 200, body: { tiktok_available: true, connected: !!on.tiktok, status: st(on.tiktok), display_name: "Maple Street", since: SINCE } };
    if (p === "/api/instagram/status") return { status: 200, body: { instagram_available: true, connected: !!on.instagram, status: st(on.instagram), username: "maplestreet", since: SINCE } };
    if (p === "/api/facebook/status") return { status: 200, body: { facebook_available: true, connected: !!on.facebook, status: st(on.facebook), page_name: "Maple Street", since: SINCE } };
    if (p === "/api/videos" && method === "GET") return { status: 200, body: { videos: videos, max_bytes: 52428800, ready_max: 2 } };
    if (p === "/api/instagram/posts" || p === "/api/facebook/posts") return { status: 200, body: { posts: [] } };
    return { status: 404, body: { error: "not in this fixture: " + method + " " + p } };
  };
}
async function runSocial(on, videos) {
  const answers = answersFor(on, videos);
  const dom = new JSDOM(stripScripts(FILES[PAGE]), { url: "https://bizforceai.net/agents/social.html", runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  windows.push(w);
  w.localStorage.setItem("bf_token", "tok");
  w.fetch = function (url, init) {
    const a = answers(String(url).replace(API, ""), (init && init.method) || "GET");
    const pr = Promise.resolve({ ok: a.status < 300, status: a.status, json: function () { return Promise.resolve(a.body); } });
    pr.catch(function () {});
    return pr;
  };
  [OAUTH, YT, TT, IG, FB].forEach(f => w.eval(FILES[f] + "\n//# sourceURL=" + f));
  await flush(20);
  return w.document;
}
const V0 = { label: "Clip", bytes: 3 * 1048576, mime: "video/mp4", status: "ready", youtube_video_id: null, youtube_url: null, uploaded_at: null,
  created_at: "2026-11-07T10:00:00Z", upload_unfinished: false, tiktok_status: null, tiktok_posted_at: null, tiktok_post_url: null, tiktok_upload_unfinished: false };
const vid = (id, extra) => Object.assign({}, V0, { id: "4444444" + id + "-4444-4444-8444-444444444444" }, extra);
const IG_URL = "https://www.instagram.com/reel/AbCdEf123/", FB_URL = "https://www.facebook.com/100000000000001/videos/300000000000003/";
const CHIP_VIDEOS = [
  vid("1", { instagram_status: "posted", instagram_post_url: IG_URL, instagram_error: null, facebook_status: "posted", facebook_post_url: FB_URL, facebook_error: null }),
  vid("2", { instagram_status: "pending", instagram_post_url: null, instagram_error: null, facebook_status: "pending", facebook_post_url: null, facebook_error: null }),
  vid("3", { instagram_status: "failed", instagram_post_url: null, instagram_error: "The video is too short for a Reel.", facebook_status: "failed", facebook_post_url: null, facebook_error: "The Page token expired." }),
  vid("4", { instagram_status: "not_sent", instagram_post_url: null, instagram_error: null, facebook_status: "not_sent", facebook_post_url: null, facebook_error: null }),
  vid("5", { mime: "video/webm", instagram_status: "publishing", instagram_post_url: null, instagram_error: null, facebook_status: "removed", facebook_post_url: null, facebook_error: null }),
  vid("6", { instagram_status: "unknown", instagram_post_url: null, instagram_error: null, facebook_status: "unknown", facebook_post_url: null, facebook_error: null })
];

/* The Guide in jsdom: a small page, the script, then its stylesheet read through the CSSOM. */
async function runGuide(file) {
  const dom = new JSDOM("<!doctype html><html><head></head><body><header><h1>Social Agent</h1></header><main><p>Content</p><button>Save</button></main></body></html>",
    { url: "https://bizforceai.net/agents/" + file, runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  windows.push(w);
  w.localStorage.setItem("bf_token", "tok");
  let err = null;
  try { w.eval(FILES[GUIDE] + "\n//# sourceURL=" + GUIDE); } catch (e) { err = e; }
  if (w.document.readyState !== "complete") w.document.dispatchEvent(new w.Event("DOMContentLoaded"));
  await flush(10);
  return { w: w, doc: w.document, err: err };
}
function cssRules(doc) {
  const out = [];
  for (const sh of Array.from(doc.styleSheets)) {
    let rules;
    try { rules = Array.from(sh.cssRules); } catch (e) { continue; }
    for (const r of rules) {
      if (r.media) for (const ir of Array.from(r.cssRules)) out.push({ media: r.media.mediaText, sel: ir.selectorText, style: ir.style });
      else if (r.selectorText) out.push({ media: "", sel: r.selectorText, style: r.style });
    }
  }
  return out;
}
const px = v => { const m = /^(\d+(?:\.\d+)?)px$/.exec(String(v || "").trim()); return m ? Number(m[1]) : NaN; };
const leadPx = v => { const m = /calc\((\d+(?:\.\d+)?)px \+ env\(safe-area-inset-[a-z]+, 0px\)\)/.exec(String(v || "")); return m ? Number(m[1]) : NaN; };

(async function main() {
  /* ── F ── */
  console.log("\n══ F. proposal cards: the site font, monospace only in the raw payload ══");
  const pr = await runProposals();
  check("F0. the page's inline script runs against the stubbed API without an error", !!pr && !pr.err, pr && pr.err && pr.err.message);
  const doc = pr ? pr.doc : null;
  const cards = doc ? $(doc, ".proposal-card") : [];
  check("F1. one card per fixture, every kind drawn (" + PROPOSAL_FIXTURES.length + ")", cards.length === PROPOSAL_FIXTURES.length, cards.length);
  const mono = [], raws = [], missingRaw = [];
  cards.forEach((card, i) => {
    const raw = $(card, "details.payload-toggle > pre");
    if (raw.length !== 1) missingRaw.push(PROPOSAL_FIXTURES[i].action_type);
    $(card, "*").forEach(el => {
      const own = Array.from(el.childNodes).some(c => c.nodeType === 3 && c.textContent.trim());
      if (!own) return;
      const ff = pr.w.getComputedStyle(el).fontFamily;
      const inRaw = !!el.closest("details.payload-toggle > pre");
      if (inRaw) raws.push(ff);
      else if (MONO.test(ff)) mono.push(PROPOSAL_FIXTURES[i].action_type + " ." + el.className + " " + ff);
    });
  });
  check("F2. no human-readable value on any card is in a monospace font (detail rows, caption blocks, links, results, errors)", cards.length > 0 && mono.length === 0, mono.slice(0, 6).join(" | "));
  check("F3. every card has exactly one View payload block", missingRaw.length === 0, missingRaw.join());
  check("F4. ...and that raw JSON block is monospace (pre.exec-block.payload-raw)", raws.length === cards.length && raws.every(f => MONO.test(f)), J(raws.slice(0, 3)));
  const vals = doc ? $(doc, ".proposal-card .pf-value") : [];
  const fams = Array.from(new Set(vals.map(v => pr.w.getComputedStyle(v).fontFamily)));
  check("F5. detail values inherit the page's font (no family of their own)", vals.length > 20 && fams.every(f => !f || f === "inherit" || !MONO.test(f)), J(fams));
  const links = doc ? $(doc, ".proposal-card a.pf-value") : [];
  check("F6. a posted address stays a link (Instagram, Facebook) and wraps (overflow-wrap:anywhere)",
    links.some(a => a.href === "https://www.instagram.com/reel/AbCdEf123/") && links.some(a => a.href === "https://www.facebook.com/100000000000001/videos/300000000000003/") &&
    links.every(a => /anywhere/.test(pr.w.getComputedStyle(a).overflowWrap || "")), J(links.map(a => a.href)));
  const page = FILES[PROPOSALS];
  check("F7. the stylesheet names a monospace family once: the payload-raw rule", (page.match(/font-family:[^;}]*monospace/g) || []).length === 1 &&
    /\.exec-block\.payload-raw\{[^}]*font-family:ui-monospace[^}]*\}/.test(page), (page.match(/[^\n]*monospace[^\n]*/g) || []).join(" | "));

  /* ── S ── */
  console.log("\n══ S. Instagram and Facebook status per video (lib/memberVideos.js) ══");
  let mv = null;
  try { mv = loadMemberVideos(); } catch (e) { check("S0. lib/memberVideos.js loads", false, e.message); }
  if (mv) {
    const ps = mv.platformStatus;
    const row = (st, at, extra) => Object.assign({ video_id: VID, status: st, permalink: null, error: null, created_at: at }, extra || {});
    const cases = [
      ["S1. a published Instagram row: posted, with its permalink", ps("instagram", [row("published", "2026-11-10", { permalink: IG_URL })], []), { status: "posted", url: IG_URL, error: null }],
      ["S2. a published row whose permalink is not instagram.com: posted, no link", ps("instagram", [row("published", "2026-11-10", { permalink: "https://evil.example/x" })], []), { status: "posted", url: null, error: null }],
      ["S3. a pending proposal and no row: pending (waiting for approval), never posted", ps("instagram", [], [{ status: "pending" }]), { status: "pending", url: null, error: null }],
      ["S4. Facebook pending likewise", ps("facebook", [], [{ status: "pending" }]), { status: "pending", url: null, error: null }],
      ["S5. a row still processing, or an executing proposal: publishing", ps("instagram", [row("processing", "2026-11-10")], []), { status: "publishing", url: null, error: null }],
      ["S6. ...executing proposal", ps("facebook", [], [{ status: "executing" }]), { status: "publishing", url: null, error: null }],
      ["S7. the newest row failed: failed, with that row's reason", ps("instagram", [row("failed", "2026-11-09", { error: "old" }), row("failed", "2026-11-10", { error: "  The video is too short.  " })], []), { status: "failed", url: null, error: "The video is too short." }],
      ["S8. a failed row without a reason: failed, \"not posted\"", ps("facebook", [row("failed", "2026-11-10")], []), { status: "failed", url: null, error: "not posted" }],
      ["S9. a reason is cut at 200 characters", ps("facebook", [row("failed", "2026-11-10", { error: "x".repeat(300) })], []), { status: "failed", url: null, error: "x".repeat(200) }],
      ["S10. a failed attempt then a published one: posted", ps("facebook", [row("failed", "2026-11-09", { error: "e" }), row("published", "2026-11-10", { permalink: FB_URL })], []), { status: "posted", url: FB_URL, error: null }],
      ["S11. a Facebook post the member removed: removed", ps("facebook", [row("published", "2026-11-10", { permalink: FB_URL, removed_at: "2026-11-11" })], []), { status: "removed", url: null, error: null }],
      ["S12. nothing at all: not sent", ps("instagram", [], []), { status: "not_sent", url: null, error: null }],
      ["S13. a failed row and a pending re-try: pending", ps("instagram", [row("failed", "2026-11-10", { error: "e" })], [{ status: "pending" }]), { status: "pending", url: null, error: null }]
    ];
    cases.forEach(([label, got, want]) => check(label, J(got) === J(want), J(got)));
    check("S14. the statuses the chips know are exactly the derivation's", J(mv.SOCIAL_STATUSES) === J(["posted", "publishing", "pending", "failed", "removed", "not_sent", "unknown"]));

    // socialStatus and listVideos against the fake
    const U = "11111111-1111-4111-8111-111111111111", OTHER = "99999999-9999-4999-8999-999999999999";
    const V1 = "a1111111-1111-4111-8111-111111111111", V2 = "a2222222-2222-4222-8222-222222222222", V3 = "a3333333-3333-4333-8333-333333333333";
    const mvRow = (id, at) => ({ id: id, user_id: U, path: U + "/" + id + ".mp4", mime: "video/mp4", bytes: 1000, sha256: "x", label: "L", status: "ready", created_at: at });
    const tables = {
      member_videos: [mvRow(V1, "2026-11-10"), mvRow(V2, "2026-11-11"), mvRow(V3, "2026-11-12")],
      instagram_posts: [{ user_id: U, video_id: V1, status: "published", permalink: IG_URL, error: null, created_at: "2026-11-10" },
        { user_id: OTHER, video_id: V2, status: "published", permalink: IG_URL, error: null, created_at: "2026-11-10" }],
      facebook_posts: [{ user_id: U, video_id: V3, status: "failed", permalink: null, error: "The Page token expired.", removed_at: null, created_at: "2026-11-12" }],
      agent_proposals: [{ user_id: U, action_type: "publish_facebook_post", status: "pending", payload: { video: { id: V2 } }, created_at: "2026-11-12" },
        { user_id: U, action_type: "publish_instagram_post", status: "pending", payload: { video: { id: V3 } }, created_at: "2026-11-12" }]
    };
    const sb = fakeSupabase(tables);
    let list = null, lerr = null;
    try { list = await mv.listVideos({ supabase: sb, now: () => Date.parse("2026-11-13T00:00:00Z") }, U); } catch (e) { lerr = e; }
    check("S15. listVideos answers", Array.isArray(list) && list.length === 3, lerr && lerr.message);
    const by = id => (list || []).filter(v => v.id === id)[0] || {};
    const pick = v => [v.instagram_status, v.instagram_post_url, v.instagram_error, v.facebook_status, v.facebook_post_url, v.facebook_error];
    check("S16. V1: Instagram posted with its link, Facebook not sent", J(pick(by(V1))) === J(["posted", IG_URL, null, "not_sent", null, null]), J(pick(by(V1))));
    check("S17. V2: Instagram not sent (another member's row is not read), Facebook pending", J(pick(by(V2))) === J(["not_sent", null, null, "pending", null, null]), J(pick(by(V2))));
    check("S18. V3: Instagram pending, Facebook failed with the reason", J(pick(by(V3))) === J(["pending", null, null, "failed", null, "The Page token expired."]), J(pick(by(V3))));
    check("S19. no write of any kind while listing (no insert, update, upsert, delete or rpc)", writesIn(sb.log).length === 0, J(writesIn(sb.log).map(q => q.table + ":" + q.calls.map(c => c[0]).join("."))));
    const reads = sb.log.filter(q => q.table !== "member_videos");
    const bounded = q => q.calls.some(c => c[0] === "eq" && c[1] === "user_id" && c[2] === U) && q.calls.some(c => c[0] === "limit" && c[1] === mv.SOCIAL_ROWS_MAX);
    check("S20. three status reads (agent_proposals, instagram_posts, facebook_posts), each by user and limited to SOCIAL_ROWS_MAX (" + mv.SOCIAL_ROWS_MAX + ")",
      J(reads.map(q => q.table).sort()) === J(["agent_proposals", "facebook_posts", "instagram_posts"]) && reads.every(bounded) && mv.SOCIAL_ROWS_MAX <= 500,
      J(reads.map(q => [q.table, q.calls.map(c => c[0])])));
    check("S21. the platform tables are read for the listed ids only, never select *",
      reads.filter(q => /_posts$/.test(q.table)).every(q => q.calls.some(c => c[0] === "in" && c[1] === "video_id" && J(c[2].slice().sort()) === J([V1, V2, V3].sort())) &&
        q.calls.some(c => c[0] === "select" && c[1] !== "*")));
    const sb2 = fakeSupabase(tables, { fail: ["facebook_posts"] });
    let l2 = null;
    try { l2 = await mv.listVideos({ supabase: sb2, now: () => 0 }, U); } catch (e) { l2 = null; }
    check("S22. a table that cannot be read leaves that platform unknown and the list still answers",
      Array.isArray(l2) && l2.length === 3 && l2.every(v => v.facebook_status === "unknown") && l2.filter(v => v.id === V1)[0].instagram_status === "posted");
    check("S23. a video just added (no status read) is not sent on both", J(pick(mv.publicView({ id: V1, status: "ready" }))) === J(["not_sent", null, null, "not_sent", null, null]));
    const server = FILES[SERVER];
    check("S24. the route is unchanged: GET /api/videos, requireAuth, mv.listVideos(youtubeDeps(), req.user.id)",
      /app\.get\("\/api\/videos", requireAuth, async function \(req, res, next\) \{[^}]{0,160}mv\.listVideos\(youtubeDeps\(\), req\.user\.id\)/.test(server));
    const src = FILES[MV];
    const body = name => { const i = src.indexOf(name); const j = src.indexOf("\n}\n", i); return i === -1 ? "" : src.slice(i, j); };
    check("S25. socialStatus and listVideos name no write and no model call",
      ["async function socialStatus(", "async function listVideos("].every(f => body(f) && !/\.(insert|update|upsert|delete|rpc)\(|anthropic|openai|messages\.create/i.test(body(f))));
  }

  /* ── C ── */
  console.log("\n══ C. Instagram and Facebook chips in Your videos ══");
  const ON_ALL = { youtube: true, tiktok: true, instagram: true, facebook: true };
  let sd = await runSocial(ON_ALL, CHIP_VIDEOS);
  const rowOf = v => sd.querySelector("#ytVideoList li[data-video-id=\"" + v.id + "\"]");
  const chip = (v, p) => { const c = rowOf(v) && rowOf(v).querySelector(".sf-chip[data-platform=\"" + p + "\"]"); return c ? [c.textContent, c.className.replace("sf-chip sf-chip--", "")] : null; };
  const want = [
    ["posted", ["Instagram: posted", "ok"], ["Facebook: posted", "ok"]],
    ["pending", ["Instagram: waiting for your approval", "wait"], ["Facebook: waiting for your approval", "wait"]],
    ["failed", ["Instagram: failed", "bad"], ["Facebook: failed", "bad"]],
    ["not sent", ["Instagram: not sent", "off"], ["Facebook: not sent", "off"]],
    ["publishing / removed", ["Instagram: publishing", "wait"], ["Facebook: removed", "off"]],
    ["unknown", ["Instagram: status unavailable", "off"], ["Facebook: status unavailable", "off"]]
  ];
  want.forEach(([label, ig, fb], i) => {
    const got = [chip(CHIP_VIDEOS[i], "instagram"), chip(CHIP_VIDEOS[i], "facebook")];
    check("C" + (i + 1) + ". " + label + ": the chips say so, in the shared chip style", J(got) === J([ig, fb]), J(got));
  });
  const linksOf = v => $(rowOf(v), "a").map(a => a.href);
  check("C7. a posted video links to the Instagram post and the Facebook post", linksOf(CHIP_VIDEOS[0]).indexOf(IG_URL) !== -1 && linksOf(CHIP_VIDEOS[0]).indexOf(FB_URL) !== -1, J(linksOf(CHIP_VIDEOS[0])));
  check("C8. only a posted one links (pending, failed, not sent have no instagram.com or facebook.com link)",
    CHIP_VIDEOS.slice(1).every(v => !linksOf(v).some(h => /instagram\.com|facebook\.com/.test(h))));
  const notes = v => $(rowOf(v), ".sf-note").map(p => p.textContent);
  check("C9. a failed one says why", notes(CHIP_VIDEOS[2]).indexOf("Instagram didn't post it: The video is too short for a Reel.") !== -1 &&
    notes(CHIP_VIDEOS[2]).indexOf("Facebook didn't post it: The Page token expired.") !== -1, J(notes(CHIP_VIDEOS[2])));
  const prep = (v, label) => $(rowOf(v), "button[data-prepare]").filter(b => b.textContent === label)[0] || null;
  const igB = prep(CHIP_VIDEOS[4], "Prepare for Instagram"), fbB = prep(CHIP_VIDEOS[4], "Prepare for Facebook");
  check("C10. the file rule stays the disabled Prepare button's reason (a WebM file), not a chip",
    !!igB && igB.disabled && /MP4|MOV/.test(igB.title) && !!fbB && fbB.disabled && /MP4|MOV/.test(fbB.title) &&
    !$(sd, "#ytVideoList .sf-chip").some(c => /can post|needs MP4/.test(c.textContent)), J([igB && igB.title, fbB && fbB.title]));
  sd = await runSocial({ youtube: true }, CHIP_VIDEOS);
  check("C11. only YouTube connected: no Instagram, Facebook or TikTok chip on any row",
    $(sd, "#ytVideoList .sf-chip").length === CHIP_VIDEOS.length && $(sd, "#ytVideoList .sf-chip").every(c => c.getAttribute("data-platform") === "youtube"),
    J($(sd, "#ytVideoList .sf-chip").map(c => c.textContent)));
  sd = await runSocial({ instagram: true }, CHIP_VIDEOS);
  check("C12. only Instagram connected: its chip alone on each row", $(sd, "#ytVideoList .sf-chip").length === CHIP_VIDEOS.length &&
    $(sd, "#ytVideoList .sf-chip").every(c => c.getAttribute("data-platform") === "instagram"), J($(sd, "#ytVideoList .sf-chip").map(c => c.textContent)));

  /* ── G ── */
  console.log("\n══ G. the Guide button on phones ══");
  const g = await runGuide("social.html");
  check("G0. the Guide script runs in jsdom", !g.err, g.err && g.err.message);
  const fab = g.doc.getElementById("tmx-guide-fab"), spacer = g.doc.getElementById("tmx-guide-fab-spacer");
  check("G1. the button's accessible name is \"Guide\", and its visible word is kept for screen readers", !!fab && fab.getAttribute("aria-label") === "Guide" &&
    !!fab.querySelector(".tmx-guide-fab-text") && fab.querySelector(".tmx-guide-fab-text").textContent === "Guide" &&
    !!fab.querySelector("svg.tmx-guide-fab-icon[aria-hidden=\"true\"]"));
  const rules = cssRules(g.doc);
  const phone = rules.filter(r => /max-width:\s*639px/.test(r.media));
  const pr1 = sel => phone.filter(r => r.sel === sel)[0];
  const base = sel => rules.filter(r => !r.media && r.sel === sel)[0];
  const fp = pr1("#tmx-guide-fab");
  check("G2. below 640 px it is a round button of at least 44 x 44 px", !!fp && px(fp.style.width) >= 44 && px(fp.style.height) >= 44 && fp.style.borderRadius === "50%",
    fp && J([fp.style.width, fp.style.height, fp.style.borderRadius]));
  check("G3. ...bottom-right inside the safe-area insets", !!fp && fp.style.left === "auto" && leadPx(fp.style.right) >= 8 && leadPx(fp.style.bottom) >= 8 &&
    /safe-area-inset-right/.test(fp.style.right) && /safe-area-inset-bottom/.test(fp.style.bottom), fp && J([fp.style.left, fp.style.right, fp.style.bottom]));
  const fb0 = base("#tmx-guide-fab");
  const dialogs = rules.filter(r => !r.media && /#tmx-guide-(sheet|panel|tab|mist)|tmx-guide-sheet/.test(r.sel) && r.style.zIndex).map(r => Number(r.style.zIndex));
  check("G4. above the page (z-index 40, not changed on phones), below every dialog", !!fb0 && fb0.style.zIndex === "40" && !(fp && fp.style.zIndex) &&
    dialogs.length > 0 && dialogs.every(z => z > 40), J(dialogs));
  const spRule = pr1("#tmx-guide-fab-spacer");
  const spH = spRule ? leadPx(spRule.style.height) : NaN;
  check("G5. the page gets bottom padding on phones: a spacer at least the button plus its gap (" + spH + " px)",
    !!spacer && spacer.getAttribute("aria-hidden") === "true" && spacer.parentNode === g.doc.body && !!spRule && spRule.style.display === "block" &&
    !!fp && spH >= px(fp.style.height) + leadPx(fp.style.bottom) + 8 && /safe-area-inset-bottom/.test(spRule.style.height), spRule && J([spRule.style.display, spRule.style.height]));
  // a later script appends the legal footer; once the page has loaded the spacer is after it again
  const foot = g.doc.createElement("footer");
  foot.id = "bf-legal-footer";
  foot.innerHTML = "<nav><a href=\"/terms.html\">Terms</a></nav>";
  g.doc.body.appendChild(foot);
  g.w.dispatchEvent(new g.w.Event("load"));
  await flush(5);
  const after = $(g.doc.body, ":scope > *").filter(e => e !== spacer && (e.compareDocumentPosition(spacer) & 2));
  check("G6. ...after every page element, a footer appended later included (only the Guide's own fixed layers may follow it)", !!spacer &&
    !!(foot.compareDocumentPosition(spacer) & 4) && after.every(e => /^tmx-guide-/.test(e.id)), J(after.map(e => e.tagName + "#" + e.id)));
  const hid = rules.filter(r => !r.media && /#tmx-guide-fab-spacer/.test(r.sel || ""))[0];
  check("G7. desktop unchanged: the spacer and the icon are hidden outside the phone rule, the label button keeps its word",
    !!hid && hid.style.display === "none" && !!pr1("#tmx-guide-fab .tmx-guide-fab-text") && !rules.some(r => !r.media && r.sel === "#tmx-guide-fab .tmx-guide-fab-text"));
  const moved = pr1("#tmx-guide-fab.tmx-guide-fab--moved");
  check("G8. a moved button on a phone stays inside the safe area on the left", !!moved && moved.style.right === "auto" && /safe-area-inset-left/.test(moved.style.left));
  // G9: the rest position (jsdom draws no layout; scripts/browserCheckSocial.js measures it at 390 px on six pages)
  const gsrc = FILES[GUIDE];
  const avoid = (/var AVOID = "([^"]*)";/.exec(gsrc) || ["", ""])[1].split(",");
  check("G9. at rest on a phone the button avoids headers, navs, tabs, headings, form fields, buttons, links and the Your videos card",
    ["header", "nav", "[role=tablist]", "[role=tab]", "h1", "h2", "h3", "input:not([type=hidden])", "textarea", "select", "button", "a[href]", "#videosCard"].every(x => avoid.indexOf(x) !== -1), J(avoid));
  check("G10. ...phones only (desktop untouched), raised at most 45% of the screen, re-placed on load, resize, tap and when scrolling stops",
    /if \(!PHONE \|\| !PHONE\.matches\) return;/.test(gsrc) && /window\.matchMedia\("\(max-width: 639px\)"\)/.test(gsrc) && /Math\.round\(window\.innerHeight \* 0\.45\)/.test(gsrc) &&
    /addEventListener\("scroll", function \(\) \{ restSoon\(150\); \}/.test(gsrc) && /addEventListener\("load", function \(\) \{ keepSpacerLast\(\);/.test(gsrc) &&
    /addEventListener\("pointerup", function \(\) \{ restSoon\(50\); \}\)/.test(gsrc));

  windows.forEach(w => { try { w.close(); } catch (e) {} });
  console.log("\n" + passes + " passed, " + failures + " failed");
  process.exit(failures ? 1 : 0);
})().catch(e => { console.log("    FAIL  the check crashed: " + (e && e.stack || e)); process.exit(1); });
