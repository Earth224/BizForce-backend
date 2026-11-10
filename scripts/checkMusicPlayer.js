/* scripts/checkMusicPlayer.js — the BizForce music player: a member's own
   music library on the server (lib/music.js, migration 155, the routes in
   server.js) and the player in the pages (frontend scripts/bf-music.js, the
   dashboard's console, music-popout.html, and the corners that move with the
   music through scripts/bf-theme.js).

   ══ What it proves ══════════════════════════════════════════════════════════
     A  THE LIBRARY, against the real routes lifted from server.js over a fake
        database and storage: a file is taken for what its BYTES are (never its
        name or declared type), at most 25 MB, and only while the member's
        library stays within 250 MB; it is stored in the private bucket, in the
        member's own folder; playback is a signed URL that expires, never a
        public one; rename, delete (the file too, and out of every playlist),
        and playlists with their order; every route signed-in and rate-limited;
        the migration's tables, RLS and private bucket.
     B  EXPORT AND DELETION: the export carries the tracks and playlists
        (metadata only, never the storage path), and deleting the account
        deletes the rows and removes the files from bf-music.
     C  THE TERMS AND PRIVACY: the music section, built from lib/music.js's
        figures, on the live pages; the Terms version moved on.
     D  THE PLAYER in jsdom, with a fake Web Audio, a fake BroadcastChannel and
        fake audio elements: play, pause, seek, next, previous, shuffle, the
        three repeat modes, volume and mute; the crossfade's equal-power curves
        over exactly the set time and nothing playing after it; the visualiser
        drawing only while visible and never under reduced motion; "Play when I
        open BizForce" waiting for the first interaction; the pop-out handoff
        and two tabs never sounding together; the relay; signed URLs refreshed.
     E  MOVE WITH THE MUSIC: the energy clamped to 0 … 1 whatever comes in,
        easing to 0 within a second of the music stopping, off under reduced
        motion and with the setting off, and reaching the page only through
        setLiveEnergy (--bf-live-energy); the theme keys validated.
     F  MEMORY AND WORDING: bf_music is cleared at sign-out and never applied
        to another member; no emoji in anything the player shows.
     G  THE BOOMBOX: on every signed-in page (with the mist) and never on a
        public page or a card; where it sits, how it moves, what it keeps;
        and G13, NOW PLAYING: the VFD scrolls "Title — Artist", the LED ticker
        "NN / TT · Title · Artist · Playlist name", the "Now playing" sweep
        once per new track (never on a pause, a resume or a page change), the
        tag's marquee only when its title overflows, all of it still under
        reduced motion and paused while hidden, one announcement per track,
        and "No track loaded" with nothing scrolling when nothing is loaded.
     H  THE BOOMBOX-MIXER: it starts as the bar on every page, beside the logo
        or in the top-left corner (never bottom left), and remembers the bar or
        the boombox and its place; no Pop out on the face, the body's keys
        (Library, Minimise, Reset position) drawn and named; the library slides
        out by transform and closes on its key or Escape, never opening a
        window, while "Keep playing between pages" opens one only when chosen;
        the finish (Chrome / Black) on the boombox AND the bar, kept on the
        device and the account (GET/PUT /api/music/player, validated, 503
        before migration 157), chosen in the panel or Settings; the EQ's three
        filters (low shelf 120 Hz, peaking 1 kHz, high shelf 6 kHz) clamped to
        ±12 dB, with keys, a centre detent and a double-click reset, and kept;
        the crossfader setting the Mix and showing it; the fader setting the
        master gain; the meters L/R where the sound splits, else level and
        peak; and the bar on the member's own profile only.
     I  THREE STAGES, PIN OR FOLLOW, THE MIXER'S SPACING (Oct 31 2026): no page
        header or logo moved (every page's header markup as at 9750ee2); the
        volume fader, its handle and its VOL label never overlap the L/R
        meters at min, mid or max, in Chrome and Black, at desktop and phone
        size (computed boxes); the dashboard's first stage is the drawn ICON
        beside the logo, with no bar, no boombox and no audio; icon -> bar ->
        boombox and back, Escape one stage at a time; other pages show
        nothing without music and the bar or the boombox while it is on;
        "Close to icon" keeps the music (the icon's equaliser) and "Stop
        music" takes the player off other pages; the stage remembered on the
        device and the account; Pinned not fixed, scrolling with the page,
        never dragged, Reset hidden; Follow me fixed; the position and stage
        validated, saved and restored; the accessible names; no emoji.
        NAMED BEFORE → AFTER (Oct 31 2026, three stages): G, H and the live
        order checks that expected the bar first now expect the icon on the
        dashboard, and a page other than the dashboard is given music
        (liveOn) where it must show the bar.

   MUTATE=<name> edits the files IN MEMORY; MUTATE=all runs each in its own
   process. BIZFORCE_FRONTEND_DIR overrides the frontend location. No network,
   no database. */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const SERVER = "server.js", LIBM = "lib/music.js", YOURDATA = "lib/yourData.js", MIGRATION = "supabase/migrations/155_member_music.sql";
const MUSIC = "F:scripts/bf-music.js", THEME = "F:scripts/bf-theme.js", SESSION = "F:scripts/bf-session.js", STUDIO = "F:scripts/bf-theme-studio.js";
const DASH = "F:dashboard.html", POPOUT = "F:music-popout.html", SETTINGS = "F:settings.html", TERMS = "F:terms.html", PRIVACY = "F:privacy.html";
const GUIDE = "F:scripts/termaximus-guide.js", BOOMBOX = "F:scripts/bf-boombox.js", PRESENCE = "F:scripts/termaximus-presence.js";
/* A signed-in page whose mist tag a mutation can take away (G1 reads the pages through FILES). */
const CRM = "F:crm.html";
const MIGRATION_157 = "supabase/migrations/157_user_preferences_music_player.sql", PROFILE = "F:profile.html";
const UID = "aaaaaaaa-0000-4000-8000-000000000001";
const OTHER = "bbbbbbbb-0000-4000-8000-000000000002";
const API = "https://dynamic-prosperity-production-5382.up.railway.app";

/* Each mutation: [file, from, to]. Every one must make a check fail. */
const MUTATIONS = {
  // sound before the member has interacted with the page
  "plays-before-interaction": [[MUSIC, "    if (!R.activated) { arm(); return Promise.resolve(false); }\n", ""]],
  // a second source left playing when another claims
  "two-sources": [[MUSIC, "      if (R.playing || R.awaitRelease) { pauseLocal(); R.yielded = true; say(YIELDED, \"info\"); post({ type: \"released\", from: ID, to: m.from }); }\n", ""]],
  // playback through a public URL
  "public-url": [[SERVER, "      .createSignedUrl(track.storage_path, memberMusic.SIGNED_URL_SECONDS);", "      .getPublicUrl(track.storage_path); signed.signedUrl = signed.publicUrl;"]],
  // a file over the size limit accepted
  "oversize-accepted": [[LIBM, "  if (size > FILE_MAX_BYTES) return { status: 413,", "  if (false) return { status: 413,"],
    [SERVER, "  limits: { fileSize: memberMusic.FILE_MAX_BYTES, files: 1 }", "  limits: { files: 1 }"]],
  // the live energy left unclamped
  "energy-unclamped": [[MUSIC, "    return { e: clamp01(e), avg:", "    return { e: e, avg:"]],
  // the visualiser drawing while the page is hidden
  "viz-when-hidden": [[MUSIC, "    if (doc.hidden || reducedMotion()) return;", "    if (reducedMotion()) return;"]],
  // the music library missing from the data export
  "export-missing-music": [[YOURDATA, "{ table: \"member_tracks\", group: \"profile\",", "{ table: \"member_tracks\", group: \"profile\", export: false, exportWhy: \"left out\","]],
  // the boombox on a public page (a card, reset-password, verify-email)
  "boombox-on-public-page": [[MUSIC, "    if (!T || T.publicView(T.pageKey())) return null;\n", ""]],
  // the tag scrolling away with the page
  "tag-not-fixed": [[BOOMBOX, "\".bfm-float{position:fixed;", "\".bfm-float{position:absolute;"]],
  // the speakers pulsing while paused
  "speakers-move-while-paused": [[BOOMBOX, "var bass = playing ? clamp01(lv && lv.bass) : 0;", "var bass = clamp01(lv && lv.bass);"]],
  // the speakers and reels moving under prefers-reduced-motion
  "motion-under-reduced-motion": [[MUSIC, "    if (reducedMotion()) { c.setAttribute(\"data-viz\", \"static\"); drawStatic(c); if (BOX) BOX.still(); return; }\n", ""]],
  // a capability of the old Music panel lost from the expanded view (Mix)
  "capability-lost": [[MUSIC, "      '<div class=\"bfm-row\">' +\n        '<label for=\"bfmMix\">Mix</label>", "      '<div class=\"bfm-row\" hidden>' +\n        '<label for=\"bfmMixGone\">Mix</label>"]],
  // a signed-in page without the mist, so without the boombox (crm.html)
  "signed-in-page-missing-boombox": [[CRM, "<script src=\"/scripts/termaximus-presence.js\"></script>\n", ""]],
  // the "Now playing" sweep firing when playback resumes, not only when a new track starts
  "sweep-on-resume": [[BOOMBOX, "    var lastKey = null, seenStarts,", "    var lastKey = null, wasPlaying = false, seenStarts,"],
    [BOOMBOX, "        if (seenStarts !== undefined && v.starts !== seenStarts && loaded) sweep();\n", "        if (seenStarts !== undefined && (v.starts !== seenStarts || (v.playing && !wasPlaying)) && loaded) sweep();\n        wasPlaying = !!v.playing;\n"]],
  // the LED ticker scrolling under prefers-reduced-motion
  "ticker-scrolls-under-reduced-motion": [[BOOMBOX, "        if (loaded && !still) tr.appendChild(span(\"bbx-ticker-text\", text, true));\n        tk.setAttribute(\"data-scroll\", loaded && !still ? \"true\" : \"false\");",
    "        if (loaded) tr.appendChild(span(\"bbx-ticker-text\", text, true));\n        tk.setAttribute(\"data-scroll\", loaded ? \"true\" : \"false\");"]],
  // the missing tables shown as "Internal server error"
  // the live dashboard's bug: the player decides its mode while the page is still parsed (G1/G2 live order)
  "music-mode-at-parse-time": [[MUSIC, "  if (document.readyState === \"loading\") document.addEventListener(\"DOMContentLoaded\", run);\n  else run();\n})();", "  run();\n})();"]],
  // a start that fails leaves nothing on the page (G2 live order)
  "start-failure-silent": [[MUSIC, "    doc.body.appendChild(b);\n  }\n  window.__bfMusicStartFailed = startFailed;", "  }\n  window.__bfMusicStartFailed = startFailed;"]],
  // H: the boombox opens expanded on a first visit
  /* NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: the anchor was mount's "prefs.state === \"box\" ? \"box\" : \"tag\"". AFTER: the first
     stage is decided in stageOf (the icon on the dashboard, the bar elsewhere); the mutation makes it the boombox there. */
  "auto-expanded-on-first-load": [[BOOMBOX, "return STAGES.indexOf(s) !== -1 ? s : (home ? \"icon\" : \"tag\"); }", "return STAGES.indexOf(s) !== -1 ? s : \"box\"; }"]],
  // I: the bar shown on the dashboard's first visit, not the icon
  "bar-on-first-dashboard-load": [[BOOMBOX, "return STAGES.indexOf(s) !== -1 ? s : (home ? \"icon\" : \"tag\"); }", "return STAGES.indexOf(s) !== -1 ? s : \"tag\"; }"]],
  // I: the player shown on another page with no music playing
  /* NAMED re-anchor (Part 0). BEFORE: anchored on away() as "!home && (state === icon || !live)". AFTER: the same
     mutant (shown whatever the music) on today's away(), which is "!home && !live". */
  "player-shown-without-music": [[BOOMBOX, "function away() { return !popout && !home && !live; }", "function away() { return !popout && !home && false; }"]],
  /* Part 0: the old gap back. Closing to the icon off the dashboard hides the player again, so nothing there can stop the music. */
  "no-stop-off-dashboard": [[BOOMBOX, "function away() { return !popout && !home && !live; }", "function away() { return !popout && !home && (state === \"icon\" || !live); }"]],
  // I: the volume fader's lane moved back over the R meter
  "fader-overlaps-meter": [[BOOMBOX, "\".bbx-vol{left:268px;top:2px;width:30px;height:40px}\"", "\".bbx-vol{left:246px;top:2px;width:30px;height:40px}\""]],
  // I: Pinned still fixed on screen
  "pinned-still-fixed": [[BOOMBOX, "    \".bfm-float[data-pinned=true]:not([data-dock=phone]){position:absolute}\",\n", ""]],
  // I: Escape skipping a stage (the boombox straight to the icon)
  "escape-skips-a-stage": [[BOOMBOX, "      if (state === \"box\") setState(\"tag\", focus);", "      if (state === \"box\") setState(\"icon\", focus);"]],
  // I: an unvalidated position value accepted by the server
  "position-unvalidated": [[LIBM, "    if (POSITIONS.indexOf(input.position) === -1) return { error: \"The position is follow or pinned.\", field: \"position\" };\n", ""]],
  // I: a page header changed (the dashboard's logo block)
  "header-changed": [[DASH, "  <div class=\"topbar-brand\" data-bf-boombox-anchor>", "  <div class=\"topbar-brand topbar-brand-moved\" data-bf-boombox-anchor>"]],
  // H: the default without a logo moved back to the bottom left
  "default-bottom-left": [[BOOMBOX, "      return { left: EDGE, top: EDGE };", "      return { left: EDGE, top: window.innerHeight - EDGE - BAR_H };"]],
  // H: a Pop out key back on the boombox's face
  "pop-out-on-the-face": [[BOOMBOX, "        '<button type=\"button\" data-act=\"bbx-reset\"", "        '<button type=\"button\" data-act=\"popout\" aria-label=\"Pop out\">' + svg(\"expand\", 12) + \"</button>\" +\n        '<button type=\"button\" data-act=\"bbx-reset\""]],
  // H: the library key opening a window instead of sliding the panel out
  "panel-opens-a-window": [[BOOMBOX, "      else if (act === \"bbx-library\") setLibrary(!library);", "      else if (act === \"bbx-library\") { setLibrary(!library); window.open(\"/music-popout.html\", \"bf-music-popout\"); }"]],
  // H: an EQ gain past ±12 dB reaching the filter
  "eq-gain-unclamped": [[MUSIC, "    S.eq[band] = clampDb(db);", "    S.eq[band] = Number(db);"],
    [MUSIC, "if (filters[b]) filters[b].gain.value = clampDb(S.eq[b]); }); }", "if (filters[b]) filters[b].gain.value = Number(S.eq[b]); }); }"]],
  // H: the bar painted in fixed colours, so the finish never reaches it
  "finish-not-on-the-bar": [[BOOMBOX, "color:var(--bbx-ink);background:\" + BRUSH + \",\" + METAL + \";border:1px solid rgba(0,0,0,.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.85)",
    "color:#1b2030;background:linear-gradient(180deg,#ffffff,#a7adb9);border:1px solid rgba(0,0,0,.5);box-shadow:inset 0 1px 0 rgba(255,255,255,.85)"]],
  // H: the boombox shown to a visitor of someone else's profile
  "profile-boombox-to-visitor": [[THEME, "    if (key === \"profile.html\") {\n      var id = null, preview = false;", "    if (key === \"profile-never.html\") {\n      var id = null, preview = false;"]],
  // H: an EQ band past ±12 dB accepted by the server
  "server-eq-unvalidated": [[LIBM, "|| Math.abs(n) > EQ_MAX_DB) {", ") {"]],
  // H: the Escape key leaving the library open
  /* NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: "if (library) setLibrary(false, true); else setState(\"tag\", true);". AFTER: Escape
     steps back one stage (stepBack), the library first. */
  "escape-keeps-library": [[BOOMBOX, "        if (state === \"box\" && library) setLibrary(false, true); else stepBack(true);", "        stepBack(true);"]],
  "503-as-internal-error": [[SERVER, "  if (memberMusic.missingTable(error)) return res.status(503).json({ error: memberMusic.NOT_SET_UP, reason: \"music_not_set_up\" });\n", ""]]
};
if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
function readInto(key) {
  const p = key.indexOf("F:") === 0 ? path.join(FRONTEND, key.slice(2)) : path.join(REPO, key);
  FILES[key] = fs.existsSync(p) ? lf(fs.readFileSync(p, "utf8")) : null;
}
[SERVER, LIBM, YOURDATA, MIGRATION, "lib/accountFiles.js", "lib/legal.js", "lib/legalPages.js", "lib/themes.js",
  MUSIC, THEME, SESSION, STUDIO, DASH, POPOUT, SETTINGS, TERMS, PRIVACY, GUIDE, BOOMBOX, PRESENCE, CRM, MIGRATION_157, PROFILE].forEach(readInto);
if (FILES[MUSIC] === null) { console.log("    FAIL  frontend not found at " + FRONTEND + " (set BIZFORCE_FRONTEND_DIR)"); process.exit(1); }

if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
function compile(rel) {
  const Module = require("module"), file = path.join(REPO, rel), m = new Module(file, module);
  m.filename = file; m.paths = Module._nodeModulePaths(path.dirname(file));
  m._compile(FILES[rel], file);
  return m.exports;
}
const M = compile(LIBM);
const accountFiles = require("../lib/accountFiles");
const yourData = compile(YOURDATA);

/* ── fakes: a database, its storage ─────────────────────────────────────── */
let uuidN = 0;
const uuid = () => { uuidN++; const h = uuidN.toString(16).padStart(12, "0"); return "cccccccc-0000-4000-8000-" + h; };
function memDb(seed) {
  const T = seed || {};
  const db = { T, uploads: [], removed: [], signed: [], publicCalls: [], objects: {}, rpc: [] };
  const rowsOf = n => T[n] || (T[n] = []);
  function from(table) {
    const st = { op: "select", filters: [], single: null, range: null, limit: null, head: false, payload: null, cols: null };
    const b = {
      // Like PostgREST, a plain column list returns only those columns.
      select(cols, o) {
        if (o && o.head) st.head = true;
        const list = String(cols || "*").split(",").map(c => c.trim());
        if (list.every(c => /^\w+$/.test(c))) st.cols = list;
        return b;
      },
      eq(c, v) { st.filters.push(r => r[c] === v); return b; },
      neq(c, v) { st.filters.push(r => r[c] !== v); return b; },
      in(c, vs) { st.filters.push(r => vs.indexOf(r[c]) !== -1); return b; },
      is(c, v) { st.filters.push(r => (r[c] === undefined ? null : r[c]) === v); return b; },
      gt() { return b; }, gte() { return b; }, lt() { return b; }, lte() { return b; }, or() { return b; }, not() { return b; }, like() { return b; }, ilike() { return b; },
      order() { return b; }, limit(n) { st.limit = n; return b; }, range(a, z) { st.range = [a, z]; return b; },
      maybeSingle() { st.single = "maybe"; return b; }, single() { st.single = "one"; return b; },
      insert(p) { st.op = "insert"; st.payload = p; return b; }, upsert(p) { st.op = "insert"; st.payload = p; return b; },
      update(p) { st.op = "update"; st.payload = p; return b; }, delete() { st.op = "delete"; return b; },
      then(res, rej) { return Promise.resolve().then(run).then(res, rej); }
    };
    function finish(list) {
      const pick = r => { if (!st.cols) return r; const o = {}; st.cols.forEach(c => { if (c in r) o[c] = r[c]; }); return o; };
      const out = list.map(r => JSON.parse(JSON.stringify(pick(r))));
      if (st.single === "maybe") return { data: out[0] || null, error: null };
      if (st.single === "one") return out.length === 1 ? { data: out[0], error: null } : { data: null, error: { message: "expected one row" } };
      return { data: out, error: null, count: out.length };
    }
    function run() {
      const match = r => st.filters.every(f => f(r));
      if (st.op === "insert") {
        const list = (Array.isArray(st.payload) ? st.payload : [st.payload]).map(p => Object.assign({ id: uuid(), created_at: new Date(Date.now() + uuidN).toISOString(), updated_at: new Date().toISOString() }, JSON.parse(JSON.stringify(p))));
        list.forEach(r => rowsOf(table).push(r));
        return finish(list);
      }
      if (st.op === "update") { const hit = rowsOf(table).filter(match); hit.forEach(r => Object.assign(r, JSON.parse(JSON.stringify(st.payload)))); return finish(hit); }
      if (st.op === "delete") { const hit = rowsOf(table).filter(match); T[table] = rowsOf(table).filter(r => !match(r)); return finish(hit); }
      let hit = rowsOf(table).filter(match);
      if (st.head) return { data: null, count: hit.length, error: null };
      if (st.range) hit = hit.slice(st.range[0], st.range[1] + 1);
      if (st.limit) hit = hit.slice(0, st.limit);
      return finish(hit);
    }
    return b;
  }
  const storage = {
    from(bucket) {
      return {
        upload: async (p, buf, o) => { db.uploads.push({ bucket, path: p, size: buf.length, contentType: o && o.contentType }); db.objects[bucket + "/" + p] = buf.length; return { error: null }; },
        remove: async paths => { paths.forEach(p => { db.removed.push({ bucket, path: p }); delete db.objects[bucket + "/" + p]; }); return { error: null }; },
        createSignedUrl: async (p, ttl) => { db.signed.push({ bucket, path: p, ttl }); return { data: { signedUrl: "https://x.supabase.co/storage/v1/object/sign/" + bucket + "/" + p + "?token=t" + db.signed.length }, error: null }; },
        getPublicUrl: p => { db.publicCalls.push({ bucket, path: p }); return { data: { publicUrl: "https://x.supabase.co/storage/v1/object/public/" + bucket + "/" + p } }; },
        list: async (prefix, o) => {
          const pre = prefix ? prefix + "/" : "", names = {};
          Object.keys(db.objects).forEach(k => {
            if (k.indexOf(bucket + "/" + pre) !== 0) return;
            const rest = k.slice((bucket + "/" + pre).length), first = rest.split("/")[0];
            names[first] = rest.indexOf("/") === -1 ? "file" : "folder";
          });
          const items = Object.keys(names).map(n => ({ name: n, id: names[n] === "file" ? "obj-" + n : null }));
          const off = (o && o.offset) || 0;
          return { data: items.slice(off, off + ((o && o.limit) || 1000)), error: null };
        }
      };
    }
  };
  db.client = { from, storage, rpc: async (fn, args) => { db.rpc.push({ fn, args }); return { data: null, error: null }; } };
  return db;
}

/* ── the routes, lifted from server.js ──────────────────────────────────── */
function liftRoutes(fake) {
  const src = FILES[SERVER];
  const a = src.indexOf("/* ── Members' music (lib/music.js, migration 155)");
  const b = src.indexOf("/* ── end of members' music");
  if (a === -1 || b === -1 || b < a) throw new Error("the music routes were not found in server.js");
  const routes = [], limiters = [];
  function requireAuth(req, res, next) { next(); }
  const ctx = {
    console: { log() {}, error() {}, warn() {} },
    require: name => { if (name === "./lib/music") return M; throw new Error("unexpected require " + name); },
    rateLimit: o => { const fn = function (req, res, next) { next(); }; fn.__limiter = o; limiters.push(fn); return fn; },
    multer: Object.assign(o => ({
      single: field => (req, res, cb) => {
        const f = req.__file;
        if (f && f.field !== field) { const e = new Error("Unexpected field"); e.code = "LIMIT_UNEXPECTED_FILE"; return cb(e); }
        if (f && o.limits && o.limits.fileSize !== undefined && f.buffer.length > o.limits.fileSize) { const e = new Error("File too large"); e.code = "LIMIT_FILE_SIZE"; return cb(e); }
        req.file = f; cb();
      }
    }), { memoryStorage: () => ({}) }),
    supabase: fake.client, accountFiles, requireAuth, Buffer, app: {}
  };
  ["get", "post", "put", "delete"].forEach(m => { ctx.app[m] = function (p) { const args = [].slice.call(arguments, 1); routes.push({ method: m, path: p, mw: args.slice(0, -1), handler: args[args.length - 1] }); }; });
  vm.createContext(ctx);
  vm.runInContext(src.slice(a, b), ctx);
  return { routes, limiters, requireAuth };
}
function match(routes, method, url) {
  for (const r of routes) {
    if (r.method !== method) continue;
    const names = [];
    const re = new RegExp("^" + r.path.replace(/:([a-z_]+)/g, (m, nm) => { names.push(nm); return "([^/]+)"; }) + "$");
    const m = re.exec(url);
    if (m) { const params = {}; names.forEach((nm, i) => { params[nm] = decodeURIComponent(m[i + 1]); }); return { r, params }; }
  }
  return null;
}
function callRoute(lifted, method, url, body, file, uid) {
  return new Promise((resolve, reject) => {
    const hit = match(lifted.routes, method, url);
    if (!hit) return resolve({ status: 404, body: { error: "no route" } });
    const req = { user: { id: uid || UID }, params: hit.params, body: body || {}, __file: file || null };
    const res = { statusCode: 200, status(c) { this.statusCode = c; return this; }, json(x) { resolve({ status: this.statusCode, body: JSON.parse(JSON.stringify(x)) }); return this; } };
    const p = hit.r.handler(req, res, err => reject(err || new Error("next() with no error")));
    if (p && p.catch) p.catch(reject);
  });
}

/* ── audio files, by their bytes ────────────────────────────────────────── */
const be32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const le32 = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
const le16 = n => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const MPEG_FRAME = Buffer.concat([Buffer.from([0xff, 0xfb, 0x90, 0x64]), Buffer.alloc(400)]);
function id3Frame(id, text) { const body = Buffer.concat([Buffer.from([3]), Buffer.from(text, "utf8")]); return Buffer.concat([Buffer.from(id, "latin1"), be32(body.length), Buffer.from([0, 0]), body]); }
function mp3(title, artist) {
  const frames = Buffer.concat([title ? id3Frame("TIT2", title) : Buffer.alloc(0), artist ? id3Frame("TPE1", artist) : Buffer.alloc(0)]);
  const n = frames.length, size = Buffer.from([(n >> 21) & 0x7f, (n >> 14) & 0x7f, (n >> 7) & 0x7f, n & 0x7f]);
  return Buffer.concat([Buffer.from("ID3", "latin1"), Buffer.from([3, 0, 0]), size, frames, MPEG_FRAME]);
}
function wav(seconds) {
  const fmt = Buffer.concat([le16(1), le16(2), le32(44100), le32(176400), le16(4), le16(16)]);
  return Buffer.concat([Buffer.from("RIFF", "latin1"), le32(36 + 400), Buffer.from("WAVEfmt ", "latin1"), le32(16), fmt, Buffer.from("data", "latin1"), le32(176400 * seconds), Buffer.alloc(400)]);
}
function flac(seconds, title) {
  const info = Buffer.alloc(34);
  info[10] = 0x0a; info[11] = 0xc4; info[12] = 0x42; info[13] = 0xf0; info.writeUInt32BE(44100 * seconds, 14);
  const vendor = Buffer.from("x"), c = Buffer.from("TITLE=" + title, "utf8");
  const vc = Buffer.concat([le32(vendor.length), vendor, le32(1), le32(c.length), c]);
  return Buffer.concat([Buffer.from("fLaC", "latin1"), Buffer.from([0x00, 0, 0, 34]), info, Buffer.from([0x84, (vc.length >> 16) & 255, (vc.length >> 8) & 255, vc.length & 255]), vc, Buffer.alloc(100)]);
}
function m4a(title) {
  const data = Buffer.concat([be32(16 + Buffer.byteLength(title)), Buffer.from("data", "latin1"), be32(1), be32(0), Buffer.from(title, "utf8")]);
  const nam = Buffer.concat([be32(8 + data.length), Buffer.from(String.fromCharCode(0xa9) + "nam", "latin1"), data]);
  return Buffer.concat([be32(24), Buffer.from("ftypM4A ", "latin1"), be32(0), Buffer.from("M4A isom", "latin1"), nam, Buffer.alloc(200)]);
}
const ogg = Buffer.concat([Buffer.from("OggS", "latin1"), Buffer.alloc(24), Buffer.from("\u0001vorbis", "latin1"), Buffer.alloc(200)]);
const opus = Buffer.concat([Buffer.from("OggS", "latin1"), Buffer.alloc(24), Buffer.from("OpusHead", "latin1"), Buffer.alloc(200)]);
const aac = Buffer.concat([Buffer.from([0xff, 0xf1, 0x50, 0x80]), Buffer.alloc(300)]);
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(300)]);
const TEXT = Buffer.from("ID3 is not here; this is a text file pretending to be music.\n".repeat(8));
const upload = (buffer, name, mimetype) => ({ field: "track", buffer, originalname: name, mimetype: mimetype || "audio/mpeg" });

(async function main() {
  /* ── A. the library ───────────────────────────────────────────────────── */
  console.log("\n══ A. the library: bytes decide, caps hold, own folder, signed playback ══");
  const sniffs = { mp3: mp3("T"), "mp3 (no tag)": MPEG_FRAME, aac, m4a: m4a("T"), ogg, opus, flac: flac(3, "T"), wav: wav(2) };
  const want = { mp3: "mp3", "mp3 (no tag)": "mp3", aac: "aac", m4a: "m4a", ogg: "ogg", opus: "opus", flac: "flac", wav: "wav" };
  const sniffed = Object.keys(sniffs).map(k => [k, M.sniffAudio(sniffs[k])]);
  check("A1. each format is recognised by its first bytes: " + Object.keys(want).join(", "), sniffed.every(([k, v]) => v === want[k]), JSON.stringify(sniffed));
  check("A1. a PNG, a text file, an empty file and noise are not music", [PNG, TEXT, Buffer.alloc(0), Buffer.alloc(64, 7)].every(b => M.sniffAudio(b) === null));

  let fake = memDb(), lifted;
  try { lifted = liftRoutes(fake); } catch (e) { check("A0. the music routes lift from server.js", false, e.message); return finish(); }
  const call = (method, url, body, file, uid) => callRoute(lifted, method, url, body, file, uid);
  let r = await call("post", "/api/music/tracks", {}, upload(PNG, "song.mp3", "audio/mpeg"));
  check("A2. a PNG named song.mp3 and sent as audio/mpeg is refused (415), and nothing is stored", r.status === 415 && fake.uploads.length === 0 && !(fake.T.member_tracks || []).length, r.status);
  r = await call("post", "/api/music/tracks", { duration: "201.5" }, upload(mp3("Night Drive", "Neon Owl"), "notes.txt", "text/plain"));
  const firstId = r.body.track && r.body.track.id;
  check("A2. real MP3 bytes named notes.txt and sent as text/plain are taken (201), as audio/mpeg", r.status === 201 && fake.uploads[0] && fake.uploads[0].contentType === "audio/mpeg", r.status + " " + JSON.stringify(r.body).slice(0, 160));
  const row0 = (fake.T.member_tracks || [])[0] || {};
  check("A3. stored in the private bucket bf-music, in the member's own folder: <id>/<time>-<random>.mp3",
    fake.uploads[0] && fake.uploads[0].bucket === "bf-music" && /^aaaaaaaa-0000-4000-8000-000000000001\/\d{10,16}-[0-9a-f]{8}\.mp3$/.test(fake.uploads[0].path) && row0.storage_path === fake.uploads[0].path,
    fake.uploads[0] && fake.uploads[0].bucket + "/" + fake.uploads[0].path);
  check("A3. ownTrackPath accepts only the member's own folder", M.ownTrackPath(row0.storage_path, UID) && !M.ownTrackPath(row0.storage_path, OTHER) &&
    !M.ownTrackPath("theme-photos/" + UID + "/1234567890123-0a1b2c3d.mp3", UID) && !M.ownTrackPath(UID + "/../x/1234567890123-0a1b2c3d.mp3", UID));
  const sameMs = [M.trackPathFor(UID, 1730000000000, "mp3"), M.trackPathFor(UID, 1730000000000, "mp3")];
  check("A3. two uploads in the same millisecond get different paths (the column is UNIQUE)", sameMs[0] !== sameMs[1] && sameMs.every(p => M.ownTrackPath(p, UID)), sameMs.join(" "));
  check("A4. the title and artist come from the file's own tags; the duration from the browser's measure", row0.title === "Night Drive" && row0.artist === "Neon Owl" && Number(row0.duration_secs) === 201.5, JSON.stringify(row0));
  check("A4. the reply never carries the storage path", JSON.stringify(r.body).indexOf("storage_path") === -1 && JSON.stringify(r.body).indexOf(row0.storage_path || "@@") === -1);
  r = await call("post", "/api/music/tracks", {}, upload(wav(5), "Morning_Pages.wav", "audio/wav"));
  const wavRow = (fake.T.member_tracks || [])[1] || {};
  check("A4. with no tags the title is the file name; a WAV's length is read from its header", r.status === 201 && wavRow.title === "Morning Pages" && Number(wavRow.duration_secs) === 5 && wavRow.mime === "audio/wav", JSON.stringify(wavRow));
  r = await call("post", "/api/music/tracks", {}, upload(flac(10, "Tide"), "a.flac", "audio/flac"));
  const flacRow = (fake.T.member_tracks || [])[2] || {};
  check("A4. a FLAC's title from its Vorbis comment and its length from STREAMINFO", r.status === 201 && flacRow.title === "Tide" && Number(flacRow.duration_secs) === 10, JSON.stringify(flacRow));
  const m4aTags = M.readTags(m4a("Harbour Lights"), "m4a");
  check("A4. an M4A's title from its 0xA9 + \"nam\" atom", m4aTags.title === "Harbour Lights", JSON.stringify(m4aTags));

  const over = Buffer.alloc(M.FILE_MAX_BYTES + 1); MPEG_FRAME.copy(over);
  const exact = Buffer.alloc(M.FILE_MAX_BYTES); MPEG_FRAME.copy(exact);
  check("A5. the file limit is 25 MB: one byte over is refused (413), exactly 25 MB passes the check",
    M.FILE_MAX_BYTES === 25 * 1024 * 1024 && M.checkUpload({ buffer: over }, 0).status === 413 && !M.checkUpload({ buffer: exact }, 0).error);
  const before = fake.uploads.length;
  r = await call("post", "/api/music/tracks", {}, upload(over, "big.mp3"));
  check("A5. ... and the route refuses a file over 25 MB with 413, storing nothing", r.status === 413 && fake.uploads.length === before, r.status);
  const big = memDb({ member_tracks: [{ id: uuid(), user_id: UID, title: "old", size_bytes: 240 * 1024 * 1024, storage_path: UID + "/1000000000000.mp3", mime: "audio/mpeg", created_at: "2026-01-01T00:00:00Z" },
    { id: uuid(), user_id: OTHER, title: "theirs", size_bytes: 200 * 1024 * 1024, storage_path: OTHER + "/1000000000000.mp3", mime: "audio/mpeg", created_at: "2026-01-01T00:00:00Z" }] });
  const liftedBig = liftRoutes(big);
  const fifteen = Buffer.alloc(15 * 1024 * 1024); MPEG_FRAME.copy(fifteen);
  const nine = Buffer.alloc(9 * 1024 * 1024); MPEG_FRAME.copy(nine);
  const rOver = await callRoute(liftedBig, "post", "/api/music/tracks", {}, upload(fifteen, "x.mp3"));
  const rFits = await callRoute(liftedBig, "post", "/api/music/tracks", {}, upload(nine, "y.mp3"));
  check("A6. the member's total is 250 MB: with 240 MB stored, 15 MB more is refused (413) and 9 MB fits; another member's files do not count",
    M.MEMBER_TOTAL_BYTES === 250 * 1024 * 1024 && rOver.status === 413 && /250 MB/.test(rOver.body.error || "") && rFits.status === 201 && rFits.body.used_bytes === 249 * 1024 * 1024,
    rOver.status + " " + rFits.status + " " + rFits.body.used_bytes);

  r = await call("get", "/api/music/tracks/" + firstId + "/url");
  check("A7. playback is a signed URL from bf-music for the member's own file, valid " + M.SIGNED_URL_SECONDS + " s (at most 15 minutes)",
    r.status === 200 && /\/object\/sign\/bf-music\//.test(r.body.url || "") && fake.signed.length === 1 && fake.signed[0].path === row0.storage_path &&
    fake.signed[0].ttl === M.SIGNED_URL_SECONDS && M.SIGNED_URL_SECONDS <= 900 && Date.parse(r.body.expires_at) > Date.now(), JSON.stringify(r.body).slice(0, 200));
  check("A7. ... and never a public URL: no music route asked storage for one", fake.publicCalls.length === 0 && !/getPublicUrl/.test(FILES[SERVER].slice(FILES[SERVER].indexOf("/* ── Members' music"), FILES[SERVER].indexOf("/* ── end of members' music"))),
    JSON.stringify(fake.publicCalls));
  r = await call("get", "/api/music/tracks/" + firstId + "/url", {}, null, OTHER);
  check("A7. another member asking for the track's URL gets 404, and nothing is signed", r.status === 404 && fake.signed.length === 1);
  r = await call("get", "/api/music");
  check("A8. GET /api/music lists the member's tracks, the bytes used and the caps, never a storage path",
    r.status === 200 && r.body.tracks.length === 3 && r.body.cap_bytes === M.MEMBER_TOTAL_BYTES && r.body.file_max_bytes === M.FILE_MAX_BYTES && JSON.stringify(r.body).indexOf("storage_path") === -1);
  r = await call("put", "/api/music/tracks/" + firstId, { title: "  Night   Drive (edit) " });
  check("A9. rename: the title is cleaned and saved", r.status === 200 && r.body.track.title === "Night Drive (edit)" && fake.T.member_tracks[0].title === "Night Drive (edit)");
  r = await call("put", "/api/music/tracks/" + firstId, { title: "   " });
  const rOtherRename = await call("put", "/api/music/tracks/" + firstId, { title: "Mine now" }, null, OTHER);
  check("A9. an empty title is refused (400); another member's rename finds nothing (404)", r.status === 400 && rOtherRename.status === 404 && fake.T.member_tracks[0].title === "Night Drive (edit)");

  const ids = fake.T.member_tracks.map(t => t.id);
  r = await call("post", "/api/music/playlists", { name: "Focus", track_ids: [ids[2], ids[0]] });
  const plId = r.body.created_id;
  check("A10. a playlist is created with the member's own tracks, in the order given", r.status === 201 && r.body.playlists[0].name === "Focus" && JSON.stringify(r.body.playlists[0].track_ids) === JSON.stringify([ids[2], ids[0]]));
  r = await call("post", "/api/music/playlists", { name: "Bad", track_ids: [ids[0], "dddddddd-0000-4000-8000-000000000009"] });
  check("A10. a playlist with a track that is not the member's is refused (400)", r.status === 400 && fake.T.member_playlists.length === 1);
  r = await call("put", "/api/music/playlists/" + plId, { track_ids: [ids[0], ids[1], ids[2]] });
  const rRen = await call("put", "/api/music/playlists/" + plId, { name: "Deep focus" });
  check("A10. reorder (the tracks in their new order) and rename are saved", r.status === 200 && JSON.stringify(fake.T.member_playlists[0].track_ids) === JSON.stringify([ids[0], ids[1], ids[2]]) &&
    rRen.status === 200 && fake.T.member_playlists[0].name === "Deep focus");
  const rOtherPl = await call("put", "/api/music/playlists/" + plId, { name: "x" }, null, OTHER);
  check("A10. another member cannot change it (404)", rOtherPl.status === 404 && fake.T.member_playlists[0].name === "Deep focus");

  const delPath = fake.T.member_tracks[1].storage_path;
  r = await call("delete", "/api/music/tracks/" + ids[1]);
  check("A11. deleting a track deletes its row, removes its file from bf-music, and takes it out of every playlist",
    r.status === 200 && fake.T.member_tracks.length === 2 && fake.removed.some(x => x.bucket === "bf-music" && x.path === delPath) &&
    JSON.stringify(fake.T.member_playlists[0].track_ids) === JSON.stringify([ids[0], ids[2]]), JSON.stringify(fake.removed));
  const rOtherDel = await call("delete", "/api/music/tracks/" + ids[0], {}, null, OTHER);
  check("A11. another member's delete finds nothing (404) and removes no file", rOtherDel.status === 404 && fake.T.member_tracks.length === 2 && fake.removed.length === 1);
  r = await call("delete", "/api/music/playlists/" + plId);
  check("A11. deleting a playlist leaves its tracks", r.status === 200 && fake.T.member_playlists.length === 0 && fake.T.member_tracks.length === 2);

  const musicRoutes = lifted.routes.filter(x => /^\/api\/music/.test(x.path));
  /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: 8 music routes. AFTER: 10, with GET and PUT /api/music/player (the finish and the EQ). */
  check("A12. all " + musicRoutes.length + " music routes (list, upload, rename, delete, URL, playlists create, change, delete, the player's settings read and saved) require sign-in first and are rate-limited",
    musicRoutes.length === 10 && musicRoutes.filter(x => x.path === "/api/music/player").map(x => x.method).sort().join() === "get,put" && musicRoutes.every(x => x.mw[0] === lifted.requireAuth && x.mw.slice(1).some(f => f.__limiter)));

  const sql = FILES[MIGRATION] || "";
  const migNames = fs.readdirSync(path.join(REPO, "supabase", "migrations"));
  const nums = migNames.map(n => Number((/^(\d+)_/.exec(n) || [])[1])).filter(n => n);
  /* NAMED BEFORE → AFTER (Oct 31 2026, profile designs). BEFORE: "the next free number": 155 was the highest
     migration. AFTER: 156_profile_design.sql follows it, so 155 is checked as the only 155, right after 154. */
  check("A13. migration 155_member_music.sql is the only 155, the number after 154", !!FILES[MIGRATION] && migNames.filter(n => /^155_/.test(n)).length === 1 &&
    nums.filter(n => n === 154).length >= 1 && nums.filter(n => n > 155).every(n => n >= 156));
  check("A13. it creates member_tracks and member_playlists with RLS on, and the bucket PRIVATE at 25 MB",
    /CREATE TABLE IF NOT EXISTS public\.member_tracks/.test(sql) && /CREATE TABLE IF NOT EXISTS public\.member_playlists/.test(sql) &&
    /ALTER TABLE public\.member_tracks ENABLE ROW LEVEL SECURITY;/.test(sql) && /ALTER TABLE public\.member_playlists ENABLE ROW LEVEL SECURITY;/.test(sql) &&
    /VALUES \('bf-music', 'bf-music', false, 26214400,/.test(sql) && /SET public = false/.test(sql) && 26214400 === M.FILE_MAX_BYTES &&
    /CHECK \(storage_path LIKE user_id::text \|\| '\/%'\)/.test(sql) && !/CREATE POLICY/i.test(sql));

  /* ── B. export and deletion ───────────────────────────────────────────── */
  console.log("\n══ B. the data export and the account delete include the music ══");
  const entry = t => yourData.DATA.find(d => d.table === t);
  const et = entry("member_tracks"), ep = entry("member_playlists");
  check("B1. Your data describes the library and the playlists, both exported and deleted", !!et && !!ep && et.export !== false && ep.export !== false && et.onDelete === "delete" && ep.onDelete === "delete" &&
    yourData.DELETE_ORDER.indexOf("member_tracks") !== -1 && yourData.DELETE_ORDER.indexOf("member_playlists") !== -1);
  check("B1. ... metadata only: the export's columns leave out the storage path", !!et && /title/.test(et.select) && !/storage_path/.test(et.select || "*") && (et.select || "*") !== "*");
  const exDb = memDb({
    users: [{ id: UID, email: "m@x.test", role: "user", password_hash: "h" }],
    member_tracks: [{ id: "t-1", user_id: UID, title: "Night Drive", artist: "Neon Owl", duration_secs: 201.5, storage_path: UID + "/1730000000000.mp3", mime: "audio/mpeg", size_bytes: 9000, created_at: "2026-10-01T00:00:00Z" },
      { id: "t-9", user_id: OTHER, title: "Theirs", storage_path: OTHER + "/1730000000000.mp3", mime: "audio/mpeg", size_bytes: 1, created_at: "2026-10-01T00:00:00Z" }],
    member_playlists: [{ id: "p-1", user_id: UID, name: "Focus", track_ids: ["t-1"], created_at: "2026-10-02T00:00:00Z" }]
  });
  exDb.objects["bf-music/" + UID + "/1730000000000.mp3"] = 9000;
  exDb.objects["bf-music/" + OTHER + "/1730000000000.mp3"] = 1;
  let out = "";
  const manifest = await yourData.exportAccountData({ supabase: exDb.client, userId: UID, write: t => { out += t; } });
  let doc = null;
  try { doc = JSON.parse(out); } catch (e) { doc = null; }
  const exTracks = doc && doc.tables && doc.tables.member_tracks, exPl = doc && doc.tables && doc.tables.member_playlists;
  check("B2. the export carries the member's track (title, artist, length) and playlist, and no one else's",
    !!exTracks && exTracks.length === 1 && exTracks[0].title === "Night Drive" && exTracks[0].artist === "Neon Owl" && !!exPl && exPl.length === 1 && exPl[0].name === "Focus" &&
    manifest.tables.some(t => t.table === "member_tracks" && t.rows === 1 && t.status === "complete"), JSON.stringify(exTracks));
  const leak = Math.max(out.indexOf("storage_path"), out.indexOf("1730000000000.mp3"));
  check("B2. ... and never the storage path", leak === -1, out.slice(Math.max(0, leak - 200), leak + 60));
  check("B3. the account's files include bf-music: the bucket and member_tracks' bare paths are known to lib/accountFiles.js",
    accountFiles.BUCKETS.indexOf("bf-music") !== -1 && accountFiles.FILE_TABLES.some(t => t.table === "member_tracks" && t.bare === "bf-music"));
  const del = await yourData.deleteAccount({ supabase: exDb.client, storage: exDb.client.storage, userId: UID, body: { username: "m@x.test", password: "pw" },
    comparePassword: async () => true, activeSubscriptions: async () => [], publicUrlBase: "https://x.supabase.co" });
  check("B4. deleting the account deletes the member's tracks and playlists, and only theirs",
    del.status === 200 && exDb.T.member_tracks.length === 1 && exDb.T.member_tracks[0].user_id === OTHER && (exDb.T.member_playlists || []).length === 0, del.status + " " + JSON.stringify(del.body).slice(0, 240));
  check("B4. ... and removes the member's audio file from bf-music, leaving another member's",
    exDb.removed.some(x => x.bucket === "bf-music" && x.path === UID + "/1730000000000.mp3") && !exDb.removed.some(x => x.path.indexOf(OTHER) === 0), JSON.stringify(exDb.removed));

  /* ── C. the Terms and Privacy ─────────────────────────────────────────── */
  console.log("\n══ C. the Terms and Privacy say it, from lib/music.js's figures ══");
  const legalPages = require("../lib/legalPages"), legal = require("../lib/legal");
  const esc = t => legal.escapeHtml(t);
  const terms = FILES[TERMS] || "", privacy = FILES[PRIVACY] || "";
  const mt = legalPages.musicTerms();
  check("C1. the Terms have \"Your music\" in section 7: only music you have the right to use; private to you; reported infringing files may be removed",
    /<h3 id="music">Your music<\/h3>/.test(terms) && mt.every(x => terms.indexOf(esc(x)) !== -1) &&
    /only music you have the right to use/.test(mt[0]) && /private to you/.test(mt[1]) && /may remove it/.test(mt[3]) && terms.indexOf('id="content"') < terms.indexOf('id="music"') && terms.indexOf('id="music"') < terms.indexOf('id="bizcash"'));
  check("C1. ... with the limits from lib/music.js (25 MB a file, 250 MB in all, links that expire after 10 minutes)",
    /at most 25 MB, and your library at most 250 MB/.test(mt[2]) && /expires after 10 minutes/.test(mt[1]));
  const built = legalPages.buildLegalPages(legalPages.codeFacts());
  check("C1. the live terms.html and privacy.html are exactly what lib/legalPages.js builds", built["terms.html"] === terms && built["privacy.html"] === privacy);
  check("C2. TERMS_VERSION moved past 2026-10-28 (the Terms before the music section), so members are asked to accept again",
    legal.TERMS_VERSION > "2026-10-28" && terms.indexOf("Version " + legal.TERMS_VERSION) !== -1, legal.TERMS_VERSION);
  check("C3. Privacy says what is stored: the files privately, their details, the playlists; not in the download as audio; deleted with the account; the player's memory cleared at sign-out",
    privacy.indexOf(esc(legalPages.musicPrivacySentence())) !== -1 && privacy.indexOf(esc(et ? et.what : "@@")) !== -1 && privacy.indexOf(esc(ep ? ep.what : "@@")) !== -1);

  /* ── D. the player ────────────────────────────────────────────────────── */
  console.log("\n══ D. the player, in jsdom with fake Web Audio and a fake BroadcastChannel ══");
  /* NAMED BEFORE → AFTER (Oct 30 2026, the BizForce boombox). BEFORE: the dashboard had a Music panel
     (#bfMusicPanel in #musicSection). AFTER: no panel; the logo is the boombox's anchor and the page loads
     bf-boombox.js before bf-music.js; every capability of the panel is in the boombox's expanded view (G2). */
  const boomboxTag = '<script src="/scripts/bf-boombox.js"></script>', musicTag = '<script src="/scripts/bf-music.js"></script>';
  check("D0. the dashboard: the old Music panel is gone, the logo is the boombox's anchor, and it loads bf-boombox.js then bf-music.js",
    !/musicSection|bfMusicPanel/.test(FILES[DASH]) && /class="topbar-brand"[^>]*data-bf-boombox-anchor/.test(FILES[DASH]) &&
    FILES[DASH].indexOf(boomboxTag) !== -1 && FILES[DASH].indexOf(boomboxTag) < FILES[DASH].indexOf(musicTag));
  check("D0. music-popout.html is the pop-out: #bfMusicPopout, the theme, the session guard, the boombox and the player",
    !!FILES[POPOUT] && /<div id="bfMusicPopout"><\/div>/.test(FILES[POPOUT]) && FILES[POPOUT].indexOf('<script src="/scripts/bf-theme.js"></script>') !== -1 &&
    FILES[POPOUT].indexOf('<script src="/scripts/bf-session.js"></script>') !== -1 && FILES[POPOUT].indexOf(boomboxTag) !== -1 && FILES[POPOUT].indexOf(boomboxTag) < FILES[POPOUT].indexOf(musicTag));
  const appMap = JSON.parse(fs.readFileSync(path.join(REPO, "lib", "appMap.json"), "utf8"));
  check("D0. the app map knows the pop-out page", JSON.stringify(appMap).indexOf("music-popout.html") !== -1);
  await playerChecks();
  finish();
})().catch(e => { check("the check ran to the end", false, e && e.stack); finish(); });

/* ════ the player harness ═══════════════════════════════════════════════════ */
let JSDOM;
try { JSDOM = require("jsdom").JSDOM; } catch (e) { JSDOM = null; }
const CLOCK = { t: 0 };
const BUS = { chans: [], pending: 0, after: [] };
class FakeBC {
  constructor(name) { this.name = name; this.onmessage = null; this.closed = false; BUS.chans.push(this); }
  postMessage(m) {
    const data = JSON.stringify(m);
    // A closed window neither sends nor hears (its page is gone).
    if (this.win && this.win.__closed) return;
    BUS.chans.filter(c => c !== this && c.name === this.name && !c.closed && !(c.win && c.win.__closed)).forEach(c => {
      BUS.pending++;
      setTimeout(() => {
        BUS.pending--;
        if (!c.closed && c.onmessage) { try { c.onmessage({ data: JSON.parse(data) }); } catch (e) { /* the page's own error */ } }
        BUS.after.forEach(f => f(JSON.parse(data)));
      }, 0);
    });
  }
  close() { this.closed = true; }
}
class FakeParam {
  constructor(v) { this.base = v; this.ev = []; this.curves = []; }
  get value() { return this.at(CLOCK.t); }
  set value(v) { this.base = v; this.ev = []; }
  push(e) { this.ev.push(e); this.ev.sort((a, b) => a.t - b.t); return this; }
  setValueAtTime(v, t) { return this.push({ k: "set", v, t }); }
  linearRampToValueAtTime(v, t) { return this.push({ k: "lin", v, t }); }
  setValueCurveAtTime(c, t, d) { this.curves.push({ c: Array.from(c), t, d }); return this.push({ k: "curve", c: Array.from(c), t, d }); }
  cancelScheduledValues(t) { this.ev = this.ev.filter(e => e.t < t && !(e.k === "curve" && e.t + e.d > t)); return this; }
  at(t) {
    let v = this.base, vt = -Infinity;
    for (const e of this.ev) {
      if (e.k === "set") { if (t >= e.t) { v = e.v; vt = e.t; } else break; }
      else if (e.k === "lin") { if (t >= e.t) { v = e.v; vt = e.t; } else { const f = (t - vt) / (e.t - vt); if (isFinite(f) && f >= 0) v = v + (e.v - v) * f; break; } }
      else { if (t < e.t) break; const f = Math.min(1, (t - e.t) / e.d), x = f * (e.c.length - 1), i0 = Math.floor(x), i1 = Math.min(e.c.length - 1, i0 + 1); v = e.c[i0] + (e.c[i1] - e.c[i0]) * (x - i0); vt = e.t + e.d; if (f < 1) break; }
    }
    return v;
  }
}
/* SPECTRUM.level drives the frequency bins; SPECTRUM.left / .right (0 … 1) the two channels' waveforms, a
   square wave of that amplitude, whose RMS is the amplitude itself. FAKE_AUDIO.split false takes the
   channel splitter away (a browser without one), FAKE_AUDIO.biquad false the filters.
   NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: gains, analysers and sources only, and a flat waveform. AFTER: the EQ's three BiquadFilters
   (type, frequency, Q, gain), a ChannelSplitter feeding a meter analyser per channel, and every connection
   recorded (node.out) so the chain can be read. */
const SPECTRUM = { level: 0, left: 0, right: 0 };
const FAKE_AUDIO = { split: true, biquad: true };
const node = extra => Object.assign({ out: [], connect(dst, outIdx) { this.out.push(dst); if (dst && dst.__meter && outIdx !== undefined) dst.channel = outIdx; return dst; } }, extra);
class FakeAudioContext {
  constructor() { this.sampleRate = 48000; this.state = "running"; this.destination = node({ __destination: true }); this.filters = []; this.splitters = []; }
  get currentTime() { return CLOCK.t; }
  createGain() { return node({ gain: new FakeParam(1) }); }
  createAnalyser() {
    return node({ fftSize: 2048, get frequencyBinCount() { return this.fftSize / 2; }, smoothingTimeConstant: 0, __meter: true, channel: null,
      getByteFrequencyData(a) { for (let i = 0; i < a.length; i++) a[i] = i < 8 ? SPECTRUM.level : Math.round(SPECTRUM.level / 3); },
      getByteTimeDomainData(a) {
        const amp = this.channel === 0 ? SPECTRUM.left : this.channel === 1 ? SPECTRUM.right : 0;
        const d = Math.round(Math.max(0, Math.min(1, amp)) * 127);
        for (let i = 0; i < a.length; i++) a[i] = 128 + (i % 2 ? d : -d);
      } });
  }
  get createBiquadFilter() {
    if (!FAKE_AUDIO.biquad) return undefined;
    return () => { const f = node({ type: "lowpass", frequency: new FakeParam(350), Q: new FakeParam(1), gain: new FakeParam(0), detune: new FakeParam(0) }); this.filters.push(f); return f; };
  }
  get createChannelSplitter() {
    if (!FAKE_AUDIO.split) return undefined;
    return n => { const sp = node({ channels: n }); this.splitters.push(sp); return sp; };
  }
  createMediaElementSource(el) { return node({ el }); }
  resume() { return Promise.resolve(); }
}
const AUDIOS = [];
const DURATIONS = {};
function makeFakeAudio(w) {
  return class FakeAudio {
    constructor() { this.paused = true; this.currentTime = 0; this.duration = NaN; this.src = ""; this.volume = 1; this.listeners = {}; this.plays = 0; this.blocked = false; this.win = w; AUDIOS.push(this); }
    addEventListener(n, f) { (this.listeners[n] = this.listeners[n] || []).push(f); }
    removeEventListener() {}
    fire(n) { (this.listeners[n] || []).forEach(f => f({ type: n, target: this })); }
    play() {
      this.plays++;
      if (this.blocked || w.__blockPlay) return Promise.reject(new Error("NotAllowedError"));
      this.paused = false;
      const m = /\/object\/sign\/bf-music\/([^?]+)/.exec(this.src || "");
      if (m && DURATIONS[m[1]]) this.duration = DURATIONS[m[1]];
      return Promise.resolve();
    }
    pause() { this.paused = true; }
    load() {}
    removeAttribute(k) { if (k === "src") this.src = ""; }
  };
}
const WINS = [];
const violations = [];
function audibleCount() { return WINS.filter(w => !w.__closed && w.BFMusic && w.BFMusic.audible && w.BFMusic.audible()).length; }
BUS.after.push(() => { const n = audibleCount(); if (n > 1) violations.push(n + " sources audible after a message"); });
const settle = async (ms) => { for (let i = 0; i < 40; i++) { await new Promise(r => setTimeout(r, ms || 5)); if (!BUS.pending) { await new Promise(r => setTimeout(r, 2)); if (!BUS.pending) return; } } };
const b64 = o => Buffer.from(JSON.stringify(o)).toString("base64").replace(/=+$/, "");
const TOKEN = "x." + b64({ id: UID }) + ".y";
const MUSIC_THEME = { v: 1, glow_mid: "#6eabff", alive: true, music_move: true, music_intensity: 1 };
function themeCache(theme) {
  return JSON.stringify({ v: 1, uid: UID, fetched_at: Date.now() + 3600 * 1000, state: { themes: [{ id: "th-1", name: "Mine", theme: theme }], default_theme_id: "th-1", page_themes: {} } });
}

/* The page under test. A boombox page ("float") is any app page that loads the
   mist; the dashboard also has the logo the boombox sits beside. jsdom lays
   nothing out, so sizes come from data-size (the mist, the chat box) or the
   boombox's own state (the bar 300 x 40, the boombox 440 x 250; the library
   slides out beside it and does not change its size), and places from the
   inline left and top.
   NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: the tag 290 x 40, the boombox 320 x 176, with the library
   320 x 484. AFTER: the bar 300 x 40 and the boombox 440 x 250 (bf-boombox.js's BAR_W/BAR_H, BOX_W/BOX_H).
   NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: the bar or the boombox. AFTER: the icon too, 40 x 36 (ICON_W/ICON_H).
   NAMED BEFORE → AFTER (Nov 8 2026, the music button). BEFORE: the icon 40 x 36. AFTER: 40 x 40. */
const MIST_TAG = '<script src="/scripts/termaximus-presence.js"></script>';
function layoutStub(win) {
  const HE = win.HTMLElement.prototype;
  const size = el => {
    const ds = el.getAttribute && el.getAttribute("data-size");
    if (ds) { const [sw, sh] = ds.split("x").map(Number); return { w: sw, h: sh }; }
    if (el.classList && el.classList.contains("bfm-float")) {
      const st = el.getAttribute("data-state");
      return st === "box" ? { w: 440, h: 250 } : st === "icon" ? { w: 40, h: 40 } : { w: 300, h: 40 };
    }
    return { w: 0, h: 0 };
  };
  Object.defineProperty(HE, "offsetWidth", { configurable: true, get() { return size(this).w; } });
  Object.defineProperty(HE, "offsetHeight", { configurable: true, get() { return size(this).h; } });
  HE.getBoundingClientRect = function () {
    if (this.hasAttribute("data-bf-boombox-anchor")) return { left: 16, top: 10, right: 200, bottom: 50, width: 184, height: 40, x: 16, y: 10 };
    const z = size(this), l = parseFloat(this.style.left), t = parseFloat(this.style.top);
    const left = isNaN(l) ? 16 : l, top = isNaN(t) ? (this.classList.contains("bfm-float") ? win.innerHeight - 16 - z.h : 0) : t;
    return { left, top, right: left + z.w, bottom: top + z.h, width: z.w, height: z.h, x: left, y: top };
  };
  win.__w = win.__w || 1280; win.__h = 800;
  Object.defineProperty(win, "innerWidth", { configurable: true, get: () => win.__w });
  Object.defineProperty(win, "innerHeight", { configurable: true, get: () => win.__h });
}
async function openPage(o) {
  const calls = [];
  const page = o.popout ? "music-popout.html" : o.mini ? "crm.html" : o.page || "dashboard.html";
  const anchor = page === "dashboard.html" ? '<header class="topbar"><a class="topbar-brand" data-bf-boombox-anchor href="/dashboard">BizForceAI</a></header>' : "";
  const html = "<!DOCTYPE html><html><head><script>" + FILES[THEME] + "</script></head><body>" +
    (o.popout ? '<div id="bfMusicPopout"></div>' : o.mini ? "<main>page</main>" : anchor + "<main>page</main>" + (o.extra || "") + MIST_TAG) +
    (o.mini ? "" : "<script>" + FILES[BOOMBOX] + "</script>") + "<script>" + FILES[MUSIC] + "</script></body></html>";
  const raf = [];
  let w;
  const dom = new JSDOM(html, {
    url: "https://bizforceai.net/" + page, runScripts: "dangerously", pretendToBeVisual: true,
    beforeParse(win) {
      w = win;
      if (o.width) win.__w = o.width;
      layoutStub(win);
      win.document.addEventListener("DOMContentLoaded", () => { win.__loadedAt = Date.now(); });
      if (o.blockPlay) win.__blockPlay = true;
      win.localStorage.setItem("bf_token", TOKEN);
      if (o.store) win.localStorage.setItem("bf_music", JSON.stringify(o.store));
      if (o.boombox) win.localStorage.setItem("bf_boombox", JSON.stringify(o.boombox));
      /* music already on in this tab's session (bf-music.js LIVE_KEY): with a track paused mid-way, another page shows the player */
      if (o.live) win.sessionStorage.setItem("bf_music_live", UID);
      win.localStorage.setItem("bf_theme", themeCache(o.theme || MUSIC_THEME));
      win.matchMedia = q => ({ matches: !!o.reduce && /prefers-reduced-motion: reduce/.test(q), addEventListener() {}, addListener() {} });
      win.Audio = makeFakeAudio(win);
      win.AudioContext = FakeAudioContext;
      win.BroadcastChannel = class extends FakeBC { constructor(n) { super(n); this.win = win; } };
      win.requestAnimationFrame = f => { raf.push(f); win.__rafRequests = (win.__rafRequests || 0) + 1; return raf.length; };
      win.cancelAnimationFrame = () => {};
      win.HTMLCanvasElement.prototype.getContext = () => null;
      win.open = (u, n) => { calls.push("open " + u); return o.blockPopup ? null : { closed: false }; };
      win.fetch = (u, opts) => {
        const method = ((opts && opts.method) || "GET").toLowerCase();
        const url = new URL(String(u));
        calls.push(method + " " + url.pathname);
        if (url.origin !== API) return Promise.resolve({ ok: false, status: 404, json: async () => ({}) });
        const body = opts && typeof opts.body === "string" ? JSON.parse(opts.body) : undefined;
        // A route that calls next(error) meets server.js's global handler: 500, "Internal server error".
        return callRoute(o.lifted, method, url.pathname, body).then(r => r, () => ({ status: 500, body: { error: "Internal server error" } }))
          .then(r => ({ ok: r.status < 400, status: r.status, json: async () => r.body }));
      };
      win.XMLHttpRequest = class {
        constructor() { this.upload = {}; this.headers = {}; }
        open(m, u) { this.method = m; this.url = u; }
        setRequestHeader(k, v) { this.headers[k] = v; }
        send(form) {
          const file = form.get("track"), dur = form.get("duration");
          const fr = new win.FileReader();
          fr.onload = () => {
            const buf = Buffer.from(fr.result);
            if (this.upload.onprogress) { this.upload.onprogress({ lengthComputable: true, loaded: buf.length / 2, total: buf.length }); this.upload.onprogress({ lengthComputable: true, loaded: buf.length, total: buf.length }); }
            callRoute(o.lifted, "post", "/api/music/tracks", { duration: dur || undefined }, { field: "track", buffer: buf, originalname: file.name, mimetype: file.type })
              .then(r => { this.status = r.status; this.responseText = JSON.stringify(r.body); if (this.onload) this.onload(); });
          };
          fr.readAsArrayBuffer(file);
        }
      };
    }
  });
  w.__raf = raf;
  w.__calls = calls;
  w.__dom = dom;
  WINS.push(w);
  await settle(10);
  return w;
}
function flushRaf(w) { const list = w.__raf.splice(0); list.forEach(f => f(0)); return list.length; }
function setHidden(w, hidden) {
  Object.defineProperty(w.document, "hidden", { configurable: true, get: () => hidden });
  w.document.dispatchEvent(new w.Event("visibilitychange"));
}
function gesture(w, kind) { w.document.dispatchEvent(new w.Event(kind || "pointerdown", { bubbles: true })); }
// A press on the control itself (it bubbles to the document, the page's first interaction), then the click.
function click(w, sel) {
  const b = w.document.querySelector(sel); if (!b) return false;
  b.dispatchEvent(new w.MouseEvent("pointerdown", { bubbles: true })); b.dispatchEvent(new w.MouseEvent("pointerup", { bubbles: true }));
  b.dispatchEvent(new w.MouseEvent("click", { bubbles: true })); return true;
}
function closeAll() { WINS.forEach(w => { w.__closed = true; try { w.close(); } catch (e) { /* closed */ } }); BUS.chans.forEach(c => c.close()); }
const near = (a, b, eps) => Math.abs(a - b) <= (eps || 0.02);

async function playerChecks() {
  if (!JSDOM) { check("D. jsdom is installed (npm i in the backend)", false); return; }
  const db = memDb();
  const lifted = liftRoutes(db);
  const add = async (title, dur) => {
    const r = await callRoute(lifted, "post", "/api/music/tracks", { duration: String(dur) }, upload(mp3(title, "Artist"), title + ".mp3"));
    const row = db.T.member_tracks.find(t => t.id === r.body.track.id);
    DURATIONS[row.storage_path] = dur;
    return r.body.track.id;
  };
  const T1 = await add("One", 200), T2 = await add("Two", 180), T3 = await add("Three", 240);
  const base = { lifted };

  /* D1. the controls */
  const A = await openPage(base);
  const BM = A.BFMusic;
  /* NAMED BEFORE → AFTER (Oct 30 2026, the BizForce boombox). BEFORE: mode "panel", the keys in .bfm-console and a
     .bfm-volume slider. AFTER: mode "float", the keys are the boombox's piano keys (.bbx-keys) and the volume is
     its rotary dial (.bbx-dial, a slider).
     NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: a Pop out key ([data-act=popout]) and the rotary dial. AFTER: no Pop out; the panel's
     "Keep playing between pages" chip ([data-act=keep-playing]) and a vertical fader (.bbx-fader, a slider). */
  check("D1. the dashboard's boombox is built, with every control as a drawn icon button (no emoji) and the exact autoplay words",
    BM && BM.mode === "float" && !!A.document.querySelector(".bbx-keys [data-act=toggle] svg") && !!A.document.querySelector("[data-act=shuffle] svg") &&
    !!A.document.querySelector("[data-act=repeat] svg") && !!A.document.querySelector("[data-act=mute] svg") && !!A.document.querySelector(".bfm-panel [data-act=keep-playing] svg") &&
    !A.document.querySelector("[data-act=popout]") && !!A.document.querySelector(".bfm-seek") && !!A.document.querySelector(".bbx-fader[role=slider]") && !!A.document.querySelector(".bfm-mix") && !!A.document.querySelector(".bfm-playlist") &&
    !!A.document.querySelector(".bfm-queue") && !!A.document.querySelector(".bfm-drop") && A.document.getElementById("bfmAutoplayNote").textContent === "Starts on your first click — browsers don't allow sound before that." &&
    A.document.querySelector("label[for=bfmAutoplay]").textContent === "Play when I open BizForce");
  check("D1. it reads the library: three tracks in the queue, in library order", BM.state().queue.join() === [T1, T2, T3].join() && A.document.querySelectorAll(".bfm-queue .bfm-item").length === 3);
  click(A, "[data-act=toggle]");
  await settle();
  const decks = () => BM._decks();
  const act = () => decks().find(d => d.track === BM.state().track_id && !d.el.paused) || decks()[0];
  check("D1. Play starts the first track, through a signed URL, and it is heard", BM.playing() && BM.state().track_id === T1 && /\/object\/sign\/bf-music\//.test(act().el.src) && BM.audible());
  check("D1. ... and the button turns to Pause", A.document.querySelector("[data-act=toggle]").getAttribute("aria-label") === "Pause");
  BM.seek(42);
  check("D1. seek moves the playhead", act().el.currentTime === 42 && BM.position() === 42);
  click(A, "[data-act=next]"); await settle();
  check("D1. Next plays the second track", BM.state().track_id === T2 && BM.playing());
  act().el.currentTime = 30;
  BM.prev(); await settle();
  check("D1. Previous more than 3 s in restarts the track", BM.state().track_id === T2 && act().el.currentTime === 0);
  BM.prev(); await settle();
  check("D1. Previous at the start goes back a track", BM.state().track_id === T1);
  BM.cycleRepeat(); const r1 = BM.state().repeat; BM.cycleRepeat(); const r2 = BM.state().repeat; BM.cycleRepeat(); const r3 = BM.state().repeat;
  check("D1. Repeat cycles off, all, one, off, and says which", r1 === "all" && r2 === "one" && r3 === "off" && A.document.querySelector("[data-act=repeat]").getAttribute("aria-label") === "Repeat: off");
  BM.setRepeat("one"); act().el.fire("ended"); await settle();
  check("D1. repeat one: a track that ends plays again", BM.state().track_id === T1 && BM.playing() && act().el.currentTime === 0);
  BM.setRepeat("all"); BM.playTrack(T3); await settle(); act().el.fire("ended"); await settle();
  check("D1. repeat all: the last track's end goes to the first", BM.state().track_id === T1 && BM.playing());
  BM.setRepeat("off"); BM.playTrack(T3); await settle(); act().el.fire("ended"); await settle();
  check("D1. repeat off: the last track's end stops", !BM.playing() && !BM.audible());
  BM.setShuffle(true); BM.playTrack(T1); await settle();
  const seen = new Set();
  for (let i = 0; i < 6; i++) { BM.next(); await settle(); seen.add(BM.state().track_id); }
  check("D1. shuffle: Next always picks another track from the queue", BM.state().shuffle === true && [...seen].every(id => [T1, T2, T3].indexOf(id) !== -1) && seen.size >= 2,
    [...seen].join());
  BM.setShuffle(false);
  BM.setVolume(0.5);
  const ctx = BM._context();
  check("D1. volume sets the master gain", !!ctx && near(masterGain(A), 0.5));
  BM.toggleMute();
  check("D1. mute silences it (gain 0) and says Unmute; unmute brings back the volume", masterGain(A) === 0 && !BM.audible() && A.document.querySelector("[data-act=mute]").getAttribute("aria-label") === "Unmute" &&
    (BM.toggleMute(), near(masterGain(A), 0.5)));
  click(A, "[data-act=toggle]"); await settle();
  check("D1. Pause stops it", !BM.playing() && !BM.audible());

  /* D2. the mix */
  BM.setCrossfade(6);
  BM.setRepeat("off");
  BM.playTrack(T1); await settle();
  const from = act();
  from.el.currentTime = 195;
  CLOCK.t = 100;
  BM._tick(); await settle();
  const f = BM._fade();
  const to = decks().find(d => d !== from);
  check("D2. with Mix at 6 s the next track starts on the other deck 6 s before the end, both decks playing",
    !!f && !f.pending && f.end - f.start === 5 && !to.el.paused && !from.el.paused && BM.state().track_id === T2,
    JSON.stringify({ f: f && { s: f.start, e: f.end, p: f.pending }, dur: from.el.duration, ct: from.el.currentTime, xf: BM.state().crossfade, pl: BM.playing(), src: from.el.src, keys: Object.keys(DURATIONS) }));
  const gIn = to.gain.gain, gOut = from.gain.gain;
  const at = t => { CLOCK.t = t; return [gOut.value, gIn.value]; };
  const [o0, i0] = at(100), [oh, ih] = at(102.5), [oe, ie] = at(105);
  check("D2. the curves are equal-power over exactly the mix time: out 1 → 0 as cos, in 0 → 1 as sin, loudness constant",
    near(o0, 1) && near(i0, 0) && near(oh, Math.cos(Math.PI / 4)) && near(ih, Math.sin(Math.PI / 4)) && near(oh * oh + ih * ih, 1) && near(oe, 0) && near(ie, 1),
    [o0, i0, oh, ih, oe, ie].map(x => x.toFixed(3)).join(" "));
  check("D2. ... matching the documented fadeGains(t, d)", near(BM.fadeGains(2.5, 5).out, Math.cos(Math.PI / 4), 1e-9) && BM.fadeGains(5, 5).out === 0 && BM.fadeGains(0, 5).in === 0);
  CLOCK.t = 105.01; BM._tick();
  check("D2. after the mix the outgoing deck is paused at gain 0: no overlap", from.el.paused && from.gain.gain.value === 0 && !to.el.paused && BM._fade() === null &&
    decks().filter(d => !d.el.paused).length === 1);
  CLOCK.t = 107; BM._tick();
  check("D2. ... and stays so", from.el.paused && decks().filter(d => !d.el.paused).length === 1 && BM.audible());
  BM.setCrossfade(0); BM.pause();
  check("D2. Mix runs 0 to 12 seconds", (BM.setCrossfade(20), BM.state().crossfade === 12) && (BM.setCrossfade(-3), BM.state().crossfade === 0));

  /* D3. the visualiser */
  BM.playTrack(T1); await settle();
  flushRaf(A);
  const reqVisible = A.__rafRequests;
  flushRaf(A);
  check("D3. while visible and playing the visualiser asks for every frame", A.__rafRequests > reqVisible && A.document.querySelector(".bfm-viz").getAttribute("data-viz") === "spectrum");
  setHidden(A, true);
  flushRaf(A);
  const reqHidden = A.__rafRequests;
  flushRaf(A); flushRaf(A);
  check("D3. hidden, it stops: no frame is asked for", A.__rafRequests === reqHidden && A.__raf.length === 0, A.__rafRequests - reqHidden);
  setHidden(A, false);
  check("D3. visible again, it starts again", A.__raf.length === 1);
  BM.setView("wave");
  check("D3. Spectrum and Waveform switch", A.document.querySelector(".bfm-viz").getAttribute("data-viz") === "wave" && A.document.querySelector("[data-view=wave]").getAttribute("aria-pressed") === "true");
  BM.setView("spectrum");
  BM.pause();

  /* D4. play when I open BizForce */
  const autoStore = { v: 1, uid: UID, autoplay: true, track_id: T2, position: 12, queue: [T1, T2, T3] };
  /* NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: the dashboard opened as the bar and armed. AFTER: its first stage is
     the icon, where no audio starts, so autoplay never arms there (checked just below); P is a dashboard left as the bar. */
  const PI = await openPage(Object.assign({}, base, { store: autoStore }));
  await settle(20);
  const armedAtIcon = PI.BFMusic.armed();
  gesture(PI, "keydown"); await settle();
  check("D4. in the icon stage (the dashboard's first visit) \"Play when I open BizForce\" arms nothing and plays nothing, even after a press",
    PI.document.querySelector(".bfm-float").getAttribute("data-state") === "icon" && !armedAtIcon && !PI.BFMusic.playing() &&
    AUDIOS.filter(x => x.win === PI).reduce((n, x) => n + x.plays, 0) === 0, PI.BFMusic.armed() + " " + PI.document.querySelector(".bfm-float").getAttribute("data-state"));
  closeOne(PI);
  const P = await openPage(Object.assign({}, base, { store: autoStore, boombox: { state: "tag" } }));
  await settle(20);
  const playsBefore = AUDIOS.filter(x => x.win === P).reduce((n, x) => n + x.plays, 0);
  check("D4. with \"Play when I open BizForce\" on, the page arms and plays nothing before an interaction",
    P.BFMusic.armed() && !P.BFMusic.playing() && playsBefore === 0 && P.document.querySelector(".bfm").getAttribute("data-armed") === "true" &&
    P.document.querySelector(".bfm-armed").textContent === "Starts on your first click — browsers don't allow sound before that.", P.BFMusic.armed() + " " + playsBefore);
  P.BFMusic.play();
  check("D4. ... play() itself refuses before the first interaction", !P.BFMusic.playing() && AUDIOS.filter(x => x.win === P).reduce((n, x) => n + x.plays, 0) === 0);
  BM.pause();
  gesture(P, "keydown");
  await settle();
  check("D4. the first key press starts it, from the remembered track and position", P.BFMusic.playing() && P.BFMusic.state().track_id === T2 && near(P.BFMusic.position(), 12, 0.01));
  check("D4. ... and the other tab that was playing, if any, is silent", audibleCount() === 1);
  P.BFMusic.pause();
  const Q = await openPage(Object.assign({}, base, { store: Object.assign({}, autoStore, { autoplay: false }) }));
  check("D4. with it off, nothing is armed", !Q.BFMusic.armed() && !Q.BFMusic.playing());

  /* D5. two tabs: one source */
  violations.length = 0;
  gesture(Q); gesture(P);
  P.BFMusic.playTrack(T1); await settle(); CLOCK.t += 1; P.BFMusic._tick(); await settle();
  Q.BFMusic.playTrack(T3); await settle(30); CLOCK.t += 1;
  check("D5. a second tab starting music silences the first: never two at once", !P.BFMusic.playing() && Q.BFMusic.playing() && Q.BFMusic.audible() && audibleCount() === 1 && violations.length === 0,
    "P " + P.BFMusic.playing() + " Q " + Q.BFMusic.playing() + " " + violations.join("; "));
  check("D5. ... and the first says why", /music started elsewhere/.test(P.document.querySelector(".bfm-msg").textContent));
  Q.BFMusic.pause(); await settle();

  /* D6. the pop-out */
  violations.length = 0;
  const watch = setInterval(() => { const n = audibleCount(); if (n > 1) violations.push(n + " audible"); }, 1);
  A.BFMusic.playTrack(T2); await settle(); A.BFMusic.seek(33); CLOCK.t += 1; A.BFMusic._tick(); await settle();
  /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: the Pop out key opened the window. AFTER: only the panel's "Keep playing between pages" does. */
  click(A, ".bfm-panel [data-act=keep-playing]");
  check("D6. \"Keep playing between pages\" opens music-popout.html", A.__calls.indexOf("open /music-popout.html") !== -1);
  const B = await openPage(Object.assign({}, base, { popout: true }));
  await settle(30);
  /* Where the pop-out had already heard the page playing, it claims, waits for the page's "released", and ramps its
     gain up on the AUDIO clock; the fake clock (CLOCK) moves only when a check moves it, so that ramp would sit at 0.
     Let audio time pass as it would (10 ms a step, at most 2 s), with the one-source watch still running. */
  for (let i = 0; i < 200 && !B.BFMusic.audible(); i++) { await wait(10); CLOCK.t += 0.01; }
  clearInterval(watch);
  check("D6. the handoff: the page goes silent first and the pop-out plays on from the same track and place; never two at once",
    !A.BFMusic.playing() && B.BFMusic.playing() && B.BFMusic.audible() && B.BFMusic.state().track_id === T2 && near(B.BFMusic.position(), 33, 0.01) && violations.length === 0,
    "A " + A.BFMusic.playing() + " B " + B.BFMusic.playing() + " audible " + B.BFMusic.audible() + " track " + (B.BFMusic.state().track_id === T2) + " at " + B.BFMusic.position() + " " + violations.slice(0, 3).join("; "));
  B.BFMusic._tick(); await settle();
  check("D6. the page shows \"Playing in the pop-out player\"", A.BFMusic.popoutAlive() && A.document.querySelector(".bfm-remote").textContent === "Playing in the pop-out player" &&
    A.document.querySelector(".bfm").getAttribute("data-remote") === "true");
  A.BFMusic.play(); await settle();
  /* NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: counted at once. AFTER: the relayed Play reaches the pop-out, which (the page heard
     playing within 1.5 s) starts at gain 0 and rises after RELEASE_WAIT_MS on the audio clock; a race, so let that audio time pass first. */
  for (let i = 0; i < 150 && !B.BFMusic.audible(); i++) { await wait(10); CLOCK.t += 0.01; }
  check("D6. while the pop-out is open the page plays nothing itself", !A.BFMusic.playing() && audibleCount() === 1);

  /* D7. the relay */
  click(A, "[data-act=next]"); await settle();
  check("D7. the page's Next is relayed to the pop-out over the channel", B.BFMusic.state().track_id === T3 && !A.BFMusic.playing());
  B.BFMusic._tick(); await settle();
  check("D7. ... and the page shows what the pop-out now plays", A.document.querySelector(".bfm-np-title").textContent === "Three");
  click(A, "[data-act=toggle]"); await settle();
  check("D7. the page's Pause pauses the pop-out", !B.BFMusic.playing());
  click(A, "[data-act=toggle]"); await settle();
  check("D7. ... and Play plays it again", B.BFMusic.playing() && !A.BFMusic.playing());
  B.dispatchEvent(new B.Event("pagehide")); B.__closed = true; await settle();
  check("D7. closing the pop-out stops the music cleanly, and the page knows", !B.BFMusic.playing() && !B.BFMusic.audible() && !A.BFMusic.popoutAlive() && !A.BFMusic.playing() && audibleCount() === 0);
  const Z = await openPage(Object.assign({}, base, { blockPopup: true }));
  click(Z, ".bfm-panel [data-act=keep-playing]");
  /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: "... blocked the pop-out window ...". AFTER: the window is "the small window", as the option says. */
  check("D7. a blocked pop-up is said plainly", Z.document.querySelector(".bfm-msg").textContent === "Your browser blocked the small window. Allow pop-ups for BizForce, then choose Keep playing between pages again.",
    Z.document.querySelector(".bfm-msg").textContent);

  /* D8. signed URLs refreshed */
  gesture(A);
  A.BFMusic.playTrack(T1); await settle();
  const urlCalls = () => A.__calls.filter(c => /\/url$/.test(c)).length;
  const t1Calls = () => A.__calls.filter(c => c === "get /api/music/tracks/" + T1 + "/url").length;
  const n0 = t1Calls();
  A.BFMusic._urls[T1].expires = Date.now() + 30 * 1000;
  A.BFMusic.pause(); A.BFMusic.playTrack(T2); await settle(); A.BFMusic.playTrack(T1); await settle();
  check("D8. a link within a minute of expiring is replaced before playing", t1Calls() === n0 + 1 && A.BFMusic._urls[T1].expires - Date.now() > 60 * 1000 && A.BFMusic.playing(),
    t1Calls() - n0);
  const deck = A.BFMusic._decks().find(d => d.track === T1);
  deck.el.currentTime = 77;
  const n1 = urlCalls(), oldSrc = deck.el.src;
  deck.el.fire("error"); await settle();
  check("D8. a failed load (an expired link) fetches a fresh one and picks up where it was", urlCalls() === n1 + 1 && deck.el.src !== oldSrc && deck.el.currentTime === 77 && !deck.el.paused);
  A.BFMusic.pause();

  /* D9. reduced motion: a still meter */
  const RM = await openPage(Object.assign({}, base, { reduce: true }));
  gesture(RM); RM.BFMusic.playTrack(T1); await settle(); flushRaf(RM);
  check("D9. under reduced motion the visualiser is a still meter: no frame is ever asked for", (RM.__rafRequests || 0) === 0 && RM.document.querySelector(".bfm-viz").getAttribute("data-viz") === "static" &&
    /stays still/.test(RM.document.querySelector(".bfm-viz-note").textContent));
  RM.BFMusic.pause();

  /* D10. queue order by keyboard, saved to the playlist */
  A.BFMusic.choosePlaylist("");
  const pl = await callRoute(lifted, "post", "/api/music/playlists", { name: "Run", track_ids: [T1, T2, T3] });
  await A.BFMusic.loadLibrary(true);
  A.BFMusic.choosePlaylist(pl.body.created_id);
  const li = A.document.querySelector('.bfm-item[data-id="' + T1 + '"]');
  li.focus();
  li.dispatchEvent(new A.KeyboardEvent("keydown", { key: "ArrowDown", altKey: true, bubbles: true }));
  await settle();
  check("D10. Alt+Down on a focused queue item moves it, keeps focus, says so, and saves the playlist's order",
    A.BFMusic.state().queue.join() === [T2, T1, T3].join() && JSON.stringify(db.T.member_playlists[0].track_ids) === JSON.stringify([T2, T1, T3]) &&
    A.document.activeElement && A.document.activeElement.getAttribute("data-id") === T1 && /moved to position 2 of 3/.test(A.document.getElementById("bfmAnnounce").textContent));

  /* D11. upload with progress */
  const file = new A.File([new Uint8Array(mp3("Sunrise", "Me"))], "sunrise.mp3", { type: "audio/mpeg" });
  const fake = new A.File([new Uint8Array(PNG)], "fake.mp3", { type: "audio/mpeg" });
  const res = await A.BFMusic.uploadFiles([file, fake]);
  const rows = A.document.querySelectorAll(".bfm-uploads li");
  check("D11. the drop zone uploads each file with a progress bar; music is added, a fake is refused with the server's reason",
    res.join() === "true,false" && rows.length === 2 && /Sunrise.*added/.test(rows[0].textContent) && rows[0].querySelector("progress").value === 100 &&
    /not MP3, M4A/.test(rows[1].textContent) && A.BFMusic.library().tracks.some(t => t.title === "Sunrise"), res.join() + " " + (rows[1] && rows[1].textContent));

  /* ── E. move with the music ───────────────────────────────────────────── */
  console.log("\n══ E. the corners move with the music ══");
  const ES = A.BFMusic.energyStep;
  const loud = new Uint8Array(1024).fill(255);
  let st = { e: 0, avg: 0 }, maxE = 0;
  for (let i = 0; i < 20; i++) { st = ES(st, loud, 48000, 2048); maxE = Math.max(maxE, st.e); }
  const hostile = [ES({ e: 7, avg: -3 }, loud, 48000, 2048), ES({ e: -2, avg: 9 }, new Uint8Array(1024), 48000, 2048), ES({ e: NaN, avg: NaN }, [NaN, NaN, NaN], 48000, 2048),
    ES({ e: 0.5, avg: 0 }, new Array(1024).fill(99999), 48000, 2048)];
  check("E1. the energy is always within 0 … 1: loud music, a beat, nonsense in, a bad previous value", maxE <= 1 && maxE > 0.9 && hostile.every(h => typeof h.e === "number" && h.e >= 0 && h.e <= 1),
    maxE + " " + hostile.map(h => h.e).join(","));
  const quiet = ES({ e: 0, avg: 0 }, new Uint8Array(1024), 48000, 2048), bassy = ES({ e: 0, avg: 0 }, (() => { const a = new Uint8Array(1024); for (let i = 0; i < 8; i++) a[i] = 200; return a; })(), 48000, 2048);
  check("E1. silence gives 0 and a bass hit gives a flash (bass weighted, the onset added)", quiet.e === 0 && bassy.e > 0.3 && bassy.onset > 0 && bassy.highs === 0, bassy.e);
  const heard = [];
  const ear = new FakeBC("bf-music");
  ear.onmessage = e => { if (e.data.type === "energy") heard.push(e.data.value); };
  SPECTRUM.level = 230;
  gesture(A); A.BFMusic.playTrack(T1); await settle();
  for (let i = 0; i < 10; i++) A.BFMusic._energyTick();
  await settle();
  const live = A.document.documentElement.style.getPropertyValue("--bf-live-energy");
  check("E2. while it plays, the energy goes out on the channel, each value within 0 … 1", heard.length >= 10 && heard.every(v => v >= 0 && v <= 1) && Math.max.apply(null, heard) > 0.3, heard.slice(0, 6).join(","));
  check("E2. ... and reaches the page's corners as --bf-live-energy (BFTheme.setLiveEnergy), scaled by the intensity", Number(live) > 0.3 && Number(live) <= 1 && near(Number(live), A.BFTheme.liveEnergy(), 0.001), live);
  const B2 = await openPage(Object.assign({}, base, { mini: true }));
  for (let i = 0; i < 3; i++) A.BFMusic._energyTick();
  await settle();
  check("E2. ... on every open BizForce page, through the channel", Number(B2.document.documentElement.style.getPropertyValue("--bf-live-energy")) > 0.3);
  heard.length = 0;
  A.BFMusic.pause();
  let ticks = 0;
  while (A.BFMusic.energy() > 0 && ticks < 60) { A.BFMusic._energyTick(); ticks++; }
  await settle();
  check("E3. when the music stops the energy eases to 0 within a second (" + A.BFMusic.ENERGY_HZ + " steps), falling every step",
    ticks <= A.BFMusic.ENERGY_HZ && heard.length >= ticks && heard[heard.length - 1] === 0 && heard.every((v, i) => i === 0 || v <= heard[i - 1]), ticks + " " + heard.slice(-3).join(","));
  await settle();
  check("E3. ... and the corners are back to their own motion", A.document.documentElement.style.getPropertyValue("--bf-live-energy") === "");
  const styleBefore = A.document.documentElement.getAttribute("style") || "";
  ear.postMessage({ type: "energy", value: 0.8 }); await settle();
  const styleAfter = A.document.documentElement.getAttribute("style") || "";
  check("E4. the energy changes nothing on the page but --bf-live-energy", styleAfter.replace(/\s*--bf-live-energy:\s*[\d.]+;?/, "").trim() === styleBefore.trim() && /--bf-live-energy:\s*0\.8/.test(styleAfter),
    styleBefore + " || " + styleAfter);
  const samples = [];
  for (let i = 0; i < 13; i++) { await new Promise(r => setTimeout(r, 100)); samples.push(A.BFTheme.liveEnergy()); }
  check("E4. a source that goes quiet (a closed pop-out) is eased to 0 by the page itself within about a second", A.BFTheme.liveEnergy() === 0, samples.join(","));
  const musicCode = FILES[MUSIC].replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  check("E4. bf-music.js never touches the corners itself: no setLiveEnergy, no --bf-live-energy in its code", !/setLiveEnergy|--bf-live-energy/.test(musicCode));
  const OFF = await openPage(Object.assign({}, base, { theme: Object.assign({}, MUSIC_THEME, { music_move: false }) }));
  ear.postMessage({ type: "energy", value: 0.9 }); await settle();
  heard.length = 0;
  gesture(OFF); OFF.BFMusic.playTrack(T1); await settle(); OFF.BFMusic._tick(); await new Promise(r => setTimeout(r, 120)); await settle();
  check("E5. with \"Move with the music\" off the corners do not follow, and the player measures nothing", OFF.document.documentElement.style.getPropertyValue("--bf-live-energy") === "" &&
    !OFF.BFTheme.musicWanted() && heard.length === 0, heard.length);
  OFF.BFMusic.pause();
  const RM2 = await openPage(Object.assign({}, base, { reduce: true }));
  heard.length = 0;
  gesture(RM2); RM2.BFMusic.playTrack(T1); await settle(); RM2.BFMusic._tick(); RM2.BFMusic._energyTick(); await settle();
  ear.postMessage({ type: "energy", value: 0.9 }); await settle();
  check("E6. under reduced motion nothing is measured or posted, and the corners stay still", heard.length === 0 && RM2.document.documentElement.style.getPropertyValue("--bf-live-energy") === "" && RM2.BFTheme.musicScale() === 0);
  RM2.BFMusic.pause();
  SPECTRUM.level = 0;

  const TH = compile("lib/themes.js");
  const okT = TH.validateTheme(Object.assign({}, TH.DEFAULT_THEME, { music_move: true, music_intensity: 4 }), UID);
  const badT = TH.validateTheme(Object.assign({}, TH.DEFAULT_THEME, { music_move: "yes" }), UID);
  const legacyIn = { v: 1, glow_a: "#00e5ff", glow_b: "#a855f7" };
  const legacy = TH.validateTheme(legacyIn, UID);
  check("E7. the theme keys: music_move true or false (off by default), music_intensity clamped to 0 … 1; a legacy theme stays as it came",
    TH.DEFAULT_THEME.music_move === false && okT.theme && okT.theme.music_move === true && okT.theme.music_intensity === 1 && badT.error && badT.key === "music_move" &&
    legacy.theme && !("music_move" in legacy.theme) && !("music_intensity" in legacy.theme) && JSON.stringify(Object.keys(A.BFTheme.DEFAULT_THEME)) === JSON.stringify(Object.keys(TH.DEFAULT_THEME)));
  check("E7. a full theme with them still fits the database's 2048-byte limit", Buffer.byteLength(JSON.stringify(okT.theme)) <= 2048, Buffer.byteLength(JSON.stringify(okT.theme)));
  const settings = FILES[SETTINGS];
  check("E8. Settings, Theme, Motion: \"Move with the music\" (a switch) with its intensity, and help text saying it reacts only to BizForce's own player",
    /id="tsMusicMoveLabel">Move with the music</.test(settings) && /<input type="checkbox" id="tsMusicMove"/.test(settings) && /<input type="range" id="tsMusicIntensity" min="0" max="100"/.test(settings) &&
    /It can only react to music in BizForce's player, never to other tabs or apps\./.test(settings) && /It can only react to music in BizForce's player, never to other tabs or apps\./.test(FILES[STUDIO]) &&
    /set\("music_move", this\.checked\)/.test(FILES[STUDIO]) && /wireRange\("tsMusicIntensity", "music_intensity", 100\)/.test(FILES[STUDIO]));

  /* ── F. memory and wording ────────────────────────────────────────────── */
  console.log("\n══ F. the player's memory is the member's; no emoji ══");
  const sess = FILES[SESSION];
  // bf-session.js quotes a "</script>" in its comments, so it is run with eval, not inlined.
  const SD = new JSDOM("<!DOCTYPE html><html><head></head><body></body></html>", { url: "https://bizforceai.net/crm.html", runScripts: "outside-only",
    beforeParse(w) { w.localStorage.setItem("bf_token", TOKEN); w.localStorage.setItem("bf_music", "{\"uid\":\"x\"}"); w.localStorage.setItem("bf_editor_theme", "dark"); } });
  const sw = SD.window;
  sw.fetch = () => new Promise(() => {});
  sw.eval(sess);
  await new Promise(r => setTimeout(r, 20));
  const loaderTag = sw.document.querySelector("script[src='/scripts/bf-music.js']");
  check("F1. the session guard puts the player on the signed-in page it guards", !!loaderTag);
  sw.BFSession.clearDevice();
  check("F1. bf_music is PER_USER: signing out clears it (and leaves a display choice)", sw.BFSession.PER_USER_LOCAL.indexOf("bf_music") !== -1 && sw.localStorage.getItem("bf_music") === null && sw.localStorage.getItem("bf_editor_theme") === "dark");
  sw.close();
  const STRANGER = await openPage(Object.assign({}, base, { store: { v: 1, uid: OTHER, track_id: T3, position: 99, volume: 0.1, autoplay: true } }));
  check("F2. a remembered state belonging to another member is never applied", STRANGER.BFMusic.state().track_id !== T3 && STRANGER.BFMusic.state().volume === 0.8 && !STRANGER.BFMusic.armed());
  gesture(A); A.BFMusic.playTrack(T2); await settle(); A.BFMusic.seek(61); A.BFMusic.pause();
  const saved = JSON.parse(A.localStorage.getItem("bf_music") || "{}");
  check("F2. it remembers the track, the position, the volume and the queue for the member signed in", saved.uid === UID && saved.track_id === T2 && near(saved.position, 61, 0.01) && near(saved.volume, 0.5) && Array.isArray(saved.queue) && saved.queue.length >= 3,
    JSON.stringify(saved));
  const EMOJI = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}\u{200D}\u{20E3}]/u;
  const shown = [FILES[MUSIC], FILES[BOOMBOX], FILES[POPOUT], FILES[LIBM], legalPages_musicText(), A.document.body.textContent];
  check("F3. no emoji in the player, the boombox, the pop-out, the library rules, the music Terms, or anything the boombox shows", shown.every(t => !EMOJI.test(t || "")), shown.map(t => EMOJI.test(t || "")).join());
  const tip = (FILES[GUIDE].match(/"dashboard\.html": \[[\s\S]*?\]/) || [""])[0];
  /* NAMED BEFORE → AFTER (Oct 30 2026, the BizForce boombox). BEFORE: the tip named the panel ("Under \"Music\" ...
     press \"Play\""). AFTER: it names the boombox beside the logo and its own keys, "Library" and "Pop out".
     NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: "Library" and "Pop out". AFTER: the bar beside the logo, "Library" sliding out the tracks, and
     "Keep playing between pages" (no Pop out key any more).
     NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: "The bar beside the logo is your music: press it for the boombox, then \"Library\" ...;
     \"Keep playing between pages\" carries it on." AFTER: the icon beside the logo, then the bar, then the boombox; "Library" and "Close to icon".
     NAMED BEFORE → AFTER (Nov 8 2026, the music button). BEFORE: "The small boombox icon beside the logo is your music: ..." and the icon
     named "Open music". AFTER: "The music button in the top bar is your music: ..." and the icon named "Music player". */
  check("F4. the dashboard's guide names the icon, the bar, the boombox and its own labels, \"Library\" and \"Close to icon\"",
    /The music button in the top bar is your music: press it for the bar, then the boombox; \\"Library\\" slides out your tracks, \\"Close to icon\\" tucks it away\./.test(tip) &&
    !/Pop out/.test(tip) && !!A.document.querySelector("[data-act=bbx-library][aria-label=Library]") && !!A.document.querySelector(".bfm-icon[aria-label='Music player']") &&
    A.document.querySelectorAll("[data-act=bbx-close][aria-label='Close to icon']").length === 2 &&
    /^Keep playing between pages \(opens a small window\)$/.test(A.document.querySelector(".bfm-panel [data-act=keep-playing]").textContent.trim()));
  ear.close();
  await boomboxChecks({ db, lifted, base, add, T1, T2, T3 });
  closeAll();
}
/* ── G. the boombox ─────────────────────────────────────────────────────── */
const wait = ms => new Promise(r => setTimeout(r, ms));
const ptr = (w, el, type, x, y) => el.dispatchEvent(new w.MouseEvent(type, { bubbles: true, cancelable: true, clientX: x, clientY: y }));
const key = (w, el, k, more) => el.dispatchEvent(new w.KeyboardEvent("keydown", Object.assign({ key: k, bubbles: true, cancelable: true }, more || {})));
const boxOf = w => w.document.querySelector(".bfm-float");
const prefsOf = w => JSON.parse(w.localStorage.getItem("bf_boombox") || "{}");
/* The stage is remembered on the account too, and a new device (a jsdom window has its own storage) adopts it.
   Before a check of a FIRST visit: let any pending save land (PLAYER_SAVE_MS), then forget the account's stage. */
async function freshStage(db) {
  await wait(800); await settle();
  const row = (db.T.user_preferences || []).find(r => r.user_id === UID);
  if (row && row.music_player) delete row.music_player.stage;
}
/* A page where music is on: this session has played, and a track sits paused mid-way (bf-music.js musicOn). */
const liveOn = (T1, o) => Object.assign({ live: true, store: { v: 1, uid: UID, track_id: T1, position: 5 } }, o || {});
const shown = w => { const r = boxOf(w); return !!r && r.getAttribute("data-away") !== "true" && w.getComputedStyle(r).display !== "none"; };
const spot = w => { const r = boxOf(w); return r ? [parseFloat(r.style.left), parseFloat(r.style.top)] : null; };
const scaleOf = el => el ? parseFloat((/scale\((-?[\d.]+)\)/.exec(el.style.transform) || [0, "NaN"])[1]) : NaN;
const angleOf = el => el ? parseFloat((/rotate\((-?[\d.]+)deg\)/.exec(el.style.transform) || [0, "NaN"])[1]) : NaN;
const overlaps = (a, b) => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
function closeOne(w) { w.__closed = true; try { w.close(); } catch (e) { /* closed */ } }
/* One frame of bf-music.js's loop, n times, 1/60 s apart. */
function frames(w, n) { for (let i = 0; i < n; i++) { const list = w.__raf.splice(0); list.forEach(f => f((w.__ft = (w.__ft || 1000) + 1000 / 60))); } }
/* A real page's script tags for the mist, with the player inlined; whether the boombox appears. */
async function presenceOn(file, html) {
  const mist = (html.match(/<script[^>]*termaximus-presence\.js[^>]*><\/script>/g) || []).join("");
  const page = "<!DOCTYPE html><html><head><script>" + FILES[THEME] + "</script></head><body><main>page</main>" + mist +
    "<script>" + FILES[BOOMBOX] + "</script><script>" + FILES[MUSIC] + "</script></body></html>";
  const dom = new JSDOM(page, { url: "https://bizforceai.net/" + file, runScripts: "dangerously", pretendToBeVisual: true,
    beforeParse(win) {
      win.localStorage.setItem("bf_token", TOKEN);
      win.matchMedia = () => ({ matches: false, addEventListener() {}, addListener() {} });
      win.AudioContext = FakeAudioContext; win.Audio = makeFakeAudio(win); win.BroadcastChannel = undefined;
      win.requestAnimationFrame = () => 0; win.cancelAnimationFrame = () => {};
      win.HTMLCanvasElement.prototype.getContext = () => null;
      win.fetch = () => new Promise(() => {});
    } });
  await wait(5);   // the player builds on DOMContentLoaded
  const on = !!dom.window.document.querySelector(".bfm-float");
  dom.window.close();
  return on;
}
function missingClient(fallback) {
  const from = table => {
    const err = { code: "PGRST205", message: "Could not find the table 'public." + table + "' in the schema cache", hint: "Perhaps you meant the table 'public.member_playlists'", details: null };
    const b = new Proxy({}, { get(t, k) { return k === "then" ? (res, rej) => Promise.resolve({ data: null, error: err }).then(res, rej) : () => b; } });
    return b;
  };
  return { client: { from, storage: fallback.client.storage, rpc: fallback.client.rpc } };
}

async function boomboxChecks(c) {
  console.log("\n══ G. the boombox: where it sits, how it moves, what it keeps ══");
  const { db, base, add, T1, T2 } = c;
  const BX = FILES[BOOMBOX] || "";

  /* G1. on every signed-in page that has the mist; never on a public page or a card */
  const pages = fs.readdirSync(FRONTEND).filter(f => /\.html$/.test(f)).sort();
  const UNTHEMED = (/var UNTHEMED = \[([\s\S]*?)\]/.exec(FILES[THEME]) || ["", ""])[1].match(/"[^"]+"/g).map(x => JSON.parse(x));
  /* A mist page with the session guard gets the player (bf-session.js loads it); a public page
     without the guard never loads it. A card or other public view (bf-theme's UNTHEMED) is tried
     with the player loaded all the same, and must still show no boombox.
     NAMED BEFORE → AFTER (Oct 31 2026, the mist and the boombox on every signed-in page). BEFORE: 33 pages,
     and a signed-in page without the mist (settings, crm, calendar and 12 more) simply had neither.
     AFTER: every signed-in page carries both. A signed-in page is one with the session guard, or
     settings.html, whose guard-free bf-session.js tag asks for the player with data-music. Its
     pages are counted exactly (SIGNED_IN_PAGES), and one without the mist fails here. */
  // NAMED (Nov 4 2026, the Media Library): BEFORE 47 signed-in pages; AFTER 48, with media.html, which carries both.
  // NAMED (Nov 5 2026, mailbox connection): BEFORE 48 signed-in pages; AFTER 49, with mailbox.html, which carries both.
  const SIGNED_IN_PAGES = 49;
  const signedInTag = html => /<script src="\/scripts\/bf-session\.js"><\/script>/.test(html) ||
    /<script src="\/scripts\/bf-session\.js" data-clear-only data-music><\/script>/.test(html);
  const want = [], refuse = [], wrong = [], noMist = [], signedIn = [];
  for (const f of pages) {
    const html = lf(FILES["F:" + f] !== undefined && FILES["F:" + f] !== null ? FILES["F:" + f] : fs.readFileSync(path.join(FRONTEND, f), "utf8"));
    if (signedInTag(html) && UNTHEMED.indexOf(f) === -1 && f !== "music-popout.html") {
      signedIn.push(f);
      if (!/<script src="\/scripts\/termaximus-presence\.js"><\/script>/.test(html)) noMist.push(f);
    }
    if (!/termaximus-presence\.js/.test(html) || f === "music-popout.html") continue;
    const guarded = signedInTag(html);
    const card = UNTHEMED.indexOf(f) !== -1;
    const expected = guarded && !card;
    (expected ? want : refuse).push(f);
    if (!guarded && !card) { if (/bf-music\.js|bf-boombox\.js/.test(html)) wrong.push(f + " has it"); continue; }
    const on = await presenceOn(f, html);
    if (on !== expected) wrong.push(f + (on ? " has it" : " lacks it"));
  }
  check("G1. every signed-in page carries the mist (" + signedIn.length + " signed-in pages, settings.html among them)",
    noMist.length === 0 && signedIn.length === SIGNED_IN_PAGES && signedIn.indexOf("settings.html") !== -1 && signedIn.indexOf("crm.html") !== -1 && signedIn.indexOf("calendar.html") !== -1,
    "without the mist: " + noMist.join(", ") + "; " + signedIn.length + " pages");
  check("G1. the boombox is on every signed-in page (" + want.length + " pages)", want.length === SIGNED_IN_PAGES && wrong.filter(x => / lacks it$/.test(x)).length === 0, wrong.join(", ") + " " + want.length);
  check("G1. ... and never on a public page or a card, even with the player loaded (" + refuse.join(", ") + ")",
    refuse.indexOf("card-view.html") !== -1 && wrong.filter(x => / has it$/.test(x)).length === 0, wrong.join(", "));
  const loaders = pages.filter(f => /\/scripts\/bf-music\.js/.test(fs.readFileSync(path.join(FRONTEND, f), "utf8")));
  const sessionLoads = /bf-music\.js/.test(FILES[SESSION]);
  check("G1. the player loads only where a member is signed in: through the session guard, or on the dashboard and the pop-out",
    sessionLoads && loaders.every(f => f === "dashboard.html" || f === "music-popout.html"), loaders.join());
  /* settings.html: bf-session.js loaded data-clear-only data-music runs no guard, and loads the
     player only while a member is signed in. */
  const sessionWith = (token, attrs) => {
    const added = [];
    const doc = { readyState: "complete", currentScript: { hasAttribute: n => attrs.indexOf(n) !== -1 }, addEventListener() {},
      querySelector: () => null, createElement: () => ({}), body: { appendChild: tag => added.push(tag.src) } };
    const store = { getItem: k => (k === "bf_token" ? token : null), setItem() {}, removeItem() {} };
    const replaced = [];
    vm.runInNewContext(FILES[SESSION], { window: { location: { replace: u => replaced.push(u) } }, document: doc, localStorage: store, sessionStorage: { length: 0, key: () => null },
      console, indexedDB: { deleteDatabase() {} } });
    return { added, replaced };
  };
  const setIn = sessionWith(TOKEN, ["data-clear-only", "data-music"]), setOut = sessionWith(null, ["data-clear-only", "data-music"]);
  const appIn = sessionWith(TOKEN, ["data-clear-only"]);
  check("G1. settings.html's bf-session.js (data-clear-only data-music) loads the player when a member is signed in, never when signed out, and runs no guard; app.html's (no data-music) never",
    setIn.added.join() === "/scripts/bf-music.js" && setOut.added.length === 0 && setIn.replaced.length === 0 && setOut.replaced.length === 0 && appIn.added.length === 0,
    JSON.stringify([setIn, setOut, appIn]));

  /* G2. the dashboard: beside the logo, and every capability of the old panel in the expanded view */
  await freshStage(db);
  const D = await openPage(base);
  const DR = boxOf(D);
  /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: the dashboard opened as the boombox. AFTER: every page starts as the bar; on the dashboard it
     sits 12 px right of the logo, centred on the header's height (the stub's logo is 16…200 x 10…50).
     NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: the bar at (212, 10). AFTER: the dashboard starts as the 40 x 36 icon, centred the same way
     (212, 12); "Open music" opens the bar at (212, 10).
     NAMED BEFORE → AFTER (Nov 8 2026, the music button). BEFORE: the 40 x 36 icon 12 px right of the logo (212, 12). AFTER: the 40 x 40
     music button, named "Music player", centred between the logo's right edge (200) and the header's centre (the stub's header has no
     width, so the window's, 640): (400, 10), level with the logo. The bar it opens is still at (212, 10). */
  check("G2. on the dashboard it starts as the icon in the top bar, between the BizForce AI logo and the header's centre, level with it",
    !!DR && DR.getAttribute("data-state") === "icon" && DR.style.left === "400px" && DR.style.top === "10px", DR && DR.getAttribute("style"));
  click(D, "[data-act=bbx-open]");
  check("G2. ... and \"Open music\" opens the bar in its place, level with the logo", DR.getAttribute("data-state") === "tag" && DR.style.left === "212px" && DR.style.top === "10px",
    DR.getAttribute("style"));
  click(D, "[data-act=bbx-expand]");
  click(D, "[data-act=bbx-library]");
  const CAPS = [["play and pause", ".bbx-keys [data-act=toggle]"], ["previous", ".bbx-keys [data-act=prev]"], ["next", ".bbx-keys [data-act=next]"],
    ["shuffle", ".bbx-keys [data-act=shuffle]"], ["repeat", ".bbx-keys [data-act=repeat]"], ["mute", ".bbx-fkeys [data-act=mute]"], ["volume", ".bbx-fader[role=slider]"],
    ["seek", ".bbx-display .bfm-seek"], ["the time", ".bbx-display .bfm-cur"], ["the live strip", ".bbx-display .bfm-viz"],
    ["Spectrum", ".bfm-panel [data-view=spectrum]"], ["Waveform", ".bfm-panel [data-view=wave]"], ["Mix", ".bfm-panel .bfm-mix"],
    ["the playlists", ".bfm-panel .bfm-playlist"], ["new playlist", ".bfm-panel [data-act=pl-new]"], ["rename playlist", ".bfm-panel [data-act=pl-rename]"],
    ["delete playlist", ".bfm-panel [data-act=pl-delete]"], ["the queue", ".bfm-panel .bfm-queue"], ["a draggable queue item", ".bfm-panel .bfm-item[draggable=true]"],
    ["upload (the drop zone)", ".bfm-panel .bfm-drop"], ["the file picker", ".bfm-panel [data-act=choose]"], ["choose files", ".bfm-panel [data-act=choose]"], ["Play when I open BizForce", ".bfm-panel #bfmAutoplay"],
    /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: "Pop out" on the face, mute under the dial and the volume a dial. AFTER: mute and the volume
       fader on the deck, "Keep playing between pages" in the panel, and the mixer's own controls. */
    ["Keep playing between pages", ".bfm-panel [data-act=keep-playing]"], ["bass", ".bbx-knob[data-band=bass][role=slider]"],
    ["mid", ".bbx-knob[data-band=mid][role=slider]"], ["treble", ".bbx-knob[data-band=treble][role=slider]"], ["the crossfader", ".bbx-xf[role=slider]"],
    ["the finish", ".bfm-panel .bfm-finish-pick[value=black]"]];
  const lost = CAPS.filter(([name, sel]) => { const el = DR.querySelector(sel); return !el || !!el.closest("[hidden]"); }).map(x => x[0]);
  const labelled = D.document.querySelector("label[for=bfmMix]") && D.document.querySelector("label[for=bfmPlaylist]") && D.document.querySelector("label[for=bfmAutoplay]");
  check("G2. every capability of the old Music panel is reachable in the expanded view, with its label (" + CAPS.length + ")",
    lost.length === 0 && !!labelled && DR.getAttribute("data-library") === "true", lost.join(", "));
  const unlabelled = Array.prototype.filter.call(DR.querySelectorAll("button, input, select, [role=slider], [tabindex='0']"), el => {
    if (el.closest("[hidden]") || el.getAttribute("aria-label") || el.getAttribute("aria-labelledby")) return false;
    if (el.id && D.document.querySelector("label[for=" + el.id + "]")) return false;
    return !(el.textContent || "").trim();
  }).map(el => el.outerHTML.slice(0, 60));
  check("G2. every control is labelled (an aria-label, a label, or its own words)", unlabelled.length === 0, unlabelled.join(" | "));

  /* G3. fixed on screen, under the mist and the chat */
  const cs = D.getComputedStyle(DR);
  check("G3. it is fixed on screen (computed position: fixed), and its CSS says so", cs.position === "fixed" && /"\.bfm-float\{position:fixed;/.test(BX), cs.position);
  const zOf = re => Number((re.exec(FILES[PRESENCE]) || [0, "NaN"])[1]);
  const glowZ = zOf(/tmx-chat-glow-wrap[\s\S]{0,400}?z-?[iI]ndex["']?\s*[:=]\s*["']?(\d+)/), Zb = D.BFBoombox.Z;
  check("G3. the z-order: the boombox (" + Zb + ") sits under the chat box's glow and the mist (2147483646, 2147483647), as its header documents",
    Number(cs.zIndex) === Zb && Zb < 2147483646 && /Z-ORDER, low to high: the page; the boombox \(2147483000\); the chat box's\s+glow \(2147483646\); the chat box and the mist \(2147483647\)/.test(BX), cs.zIndex + " " + glowZ);

  /* G4. dragged like the mist, clamped, moved by the keys, remembered, reset */
  /* NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: tasks.html showed the bar with no music. AFTER: a page other than the dashboard shows the
     player only while music is on, so F is tasks.html with a track paused mid-way in this session (liveOn); the bar's mechanics are the same. */
  await freshStage(db);
  const F = await openPage(Object.assign({}, base, liveOn(T1, { page: "tasks.html" })));
  const FR = boxOf(F), tag = F.document.querySelector(".bfm-tag"), grabAt = F.document.querySelector(".bfm-tag-title");
  /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: a page without the logo started bottom left (16, 744). AFTER: top left, 16 px in (16, 16);
     the bottom-left default is gone. Drags and clamps use the bar's 300 x 40 and the boombox's 440 x 250. */
  check("G4. on a page without the logo header, with music on, it shows as the bar, top left with a 16 px margin", FR.getAttribute("data-state") === "tag" && spot(F).join() === "16,16" &&
    F.BFBoombox.EDGE === 16 && shown(F), spot(F));
  ptr(F, grabAt, "pointerdown", 100, 100); ptr(F, grabAt, "pointermove", 103, 102);
  const under = spot(F).join();
  ptr(F, grabAt, "pointermove", 300, 300); ptr(F, grabAt, "pointerup", 300, 300);
  check("G4. a press becomes a drag only past the mist's 6 px; then it follows the pointer and is saved on release",
    F.BFBoombox.DRAG_THRESHOLD === 6 && under === "16,16" && spot(F).join() === "216,216" && prefsOf(F).left === 216 && prefsOf(F).top === 216, under + " " + spot(F));
  ptr(F, grabAt, "pointerdown", 300, 500); ptr(F, grabAt, "pointermove", 9000, 9000); ptr(F, grabAt, "pointerup", 9000, 9000);
  const far = spot(F).join();
  ptr(F, grabAt, "pointerdown", 300, 500); ptr(F, grabAt, "pointermove", -9000, -9000); ptr(F, grabAt, "pointerup", -9000, -9000);
  check("G4. it is clamped fully on screen, at every edge", far === (1280 - 300) + "," + (800 - 40) && spot(F).join() === "0,0", far + " " + spot(F));
  const mistSrc = (/function _tmxClampPosition\(left, top, el\) \{[\s\S]*?\n  \}\n/.exec(FILES[PRESENCE]) || [""])[0];
  let same = !!mistSrc;
  if (same) {
    const fakeWin = { innerWidth: 1280, innerHeight: 800 };
    const mistClamp = new Function("window", "root", mistSrc + "\nreturn _tmxClampPosition;")(fakeWin, null);
    [[-50, -50, 300, 40], [5000, 5000, 300, 40], [400, 300, 440, 250], [1100, 790, 440, 250], [10, 10, 2000, 2000]].forEach(([l, t, ew, eh]) => {
      const el = { offsetWidth: ew, offsetHeight: eh };
      if (JSON.stringify(mistClamp(l, t, el)) !== JSON.stringify(F.BFBoombox.clampPosition(l, t, el))) same = false;
    });
  }
  check("G4. the clamp is the mist's own rule (_tmxClampPosition), giving the same place for the same inputs", same);
  tag.focus();
  key(F, tag, "ArrowRight"); key(F, tag, "ArrowDown", { shiftKey: true });
  check("G4. the arrow keys move the focused tag 10 px, 40 with Shift, and it is saved", spot(F).join() === "10,40" && prefsOf(F).left === 10 && prefsOf(F).top === 40, spot(F));
  key(F, tag, "Home");
  check("G4. Home resets it to its default place and forgets the saved one", spot(F).join() === "16,16" && !("left" in prefsOf(F)));
  ptr(F, grabAt, "pointerdown", 100, 100); ptr(F, grabAt, "pointermove", 2000, 400); ptr(F, grabAt, "pointerup", 2000, 400);
  F.__w = 900; F.dispatchEvent(new F.Event("resize"));
  check("G4. a smaller window re-clamps it, so it stays fully on screen", spot(F)[0] === 900 - 300, spot(F));
  F.__w = 1280; F.dispatchEvent(new F.Event("resize"));
  click(F, "[data-act=bbx-expand]");
  ptr(F, F.document.querySelector(".bbx-body-grip"), "pointerdown", 100, 100); ptr(F, F.document.querySelector(".bbx-body-grip"), "pointermove", 140, 60);
  ptr(F, F.document.querySelector(".bbx-body-grip"), "pointerup", 140, 60);
  const moved = spot(F).join();
  click(F, "[data-act=bbx-reset]");
  check("G4. the boombox's handle drags it too, and the reset key puts it back and keeps the focus on the handle",
    moved === (1280 - 440) + "," + (316 - 40) && spot(F).join() === "16,16" && !("left" in prefsOf(F)) &&
    F.document.activeElement === F.document.querySelector(".bbx-body-grip"), moved + " " + spot(F));
  const K = await openPage(Object.assign({}, base, { page: "tasks.html", boombox: { state: "tag", left: 400, top: 300 } }));
  const K2 = await openPage(Object.assign({}, base, { boombox: { state: "tag" } }));
  check("G4. its place and whether it is minimised are remembered on this device (bf_boombox), even on the dashboard",
    spot(K).join() === "400,300" && boxOf(K).getAttribute("data-state") === "tag" && boxOf(K2).getAttribute("data-state") === "tag" && K.BFBoombox.STORE_KEY === "bf_boombox");

  /* G5. the tag and the boombox */
  const expand = F.document.querySelector("[data-act=bbx-expand]");
  click(F, "[data-act=bbx-minimise]");
  check("G5. Minimise turns it into the tag, moves the focus to Expand, and remembers it",
    FR.getAttribute("data-state") === "tag" && F.document.activeElement === expand && expand.getAttribute("aria-expanded") === "false" && prefsOf(F).state === "tag");
  click(F, "[data-act=bbx-expand]");
  /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: Expand opened the boombox with the library. AFTER: it opens the boombox in place; the library
     slides out only from its own key, and is remembered on its own. */
  check("G5. Expand opens the boombox in place (the library stays shut), focuses its Play key, and remembers it",
    FR.getAttribute("data-state") === "box" && FR.getAttribute("data-library") === "false" && expand.getAttribute("aria-expanded") === "true" &&
    F.document.activeElement === F.document.querySelector(".bbx-keys [data-act=toggle]") && prefsOf(F).state === "box");
  key(F, F.document.activeElement, "Escape");
  check("G5. Escape returns it to the tag, with the focus on Expand", FR.getAttribute("data-state") === "tag" && F.document.activeElement === expand);
  const tagKeys = ["toggle", "next", "bbx-expand"].every(a => !!tag.querySelector("[data-act=" + a + "]"));
  check("G5. the tag holds the title, a tiny wave, play/pause, next and expand", tagKeys && tag.querySelectorAll(".bfm-tag-wave span").length === 5 && !!tag.querySelector(".bfm-tag-title"));

  /* G6. never over the mist or the open chat box */
  const MIST = '<div id="tmx-presence-root" data-size="120x120" style="position:fixed;left:400px;top:60px"></div>';
  /* NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: the dashboard's first visit, the bar. AFTER: that is the icon, always in place (never
     nudged); N is a dashboard left as the bar (Follow me), the one that moves. */
  const N = await openPage(Object.assign({}, base, { extra: MIST, boombox: { state: "tag" } }));
  const mistR = N.document.getElementById("tmx-presence-root").getBoundingClientRect();
  const nr = () => boxOf(N).getBoundingClientRect();
  check("G6. where the mist would cover it, it is nudged aside, and stays on screen",
    !overlaps(nr(), mistR) && nr().left >= 0 && nr().right <= 1280 && nr().top >= 0 && nr().bottom <= 800, JSON.stringify(nr()));
  const chat = N.document.createElement("div");
  chat.id = "tmx-chat"; chat.setAttribute("data-size", "360x480");
  const at = nr();
  chat.style.left = at.left + "px"; chat.style.top = at.top + "px"; chat.style.pointerEvents = "auto";
  N.document.body.appendChild(chat);
  N.BFMusic._box().nudge();
  const chatR = chat.getBoundingClientRect();
  check("G6. ... and so is the open chat box", !overlaps(nr(), chatR) && !overlaps(nr(), mistR), JSON.stringify(nr()) + " " + JSON.stringify(chatR));
  check("G6. the nudge runs when it is placed, when a drag ends, and every 1.5 s (the chat box opens and moves on its own)",
    /function place\(\)[\s\S]*?nudge\(\);[\s\S]*?\n    \}/.test(BX) && /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: "nudge(); saveSpot(); }". AFTER: the library's side is chosen again too. */ /if \(drag\.moved\) \{ nudge\(\); saveSpot\(\); side\(\); \}/.test(BX) &&
    /* NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: "if (state && !drag.on) nudge();". AFTER: not while it is away (nothing shown). */
    /setInterval\(function \(\) \{ if \(state && !drag\.on && !away\(\)\) nudge\(\); \}, 1500\)/.test(BX));

  /* G7. the motion */
  const MO = await openPage(Object.assign({}, base, { page: "tasks.html" }));
  const bx = MO.BFMusic._box(), q1 = s => MO.document.querySelector(s);
  bx.rest();
  for (let i = 0; i < 30; i++) bx.animate({ bass: 1, highs: 1, level: 1 }, false, 1 / 60);
  check("G7. paused, nothing moves: loud levels leave the cones, caps and tweeters at rest, the LEDs dark and the reels still",
    scaleOf(q1(".bbx-cone")) === 1 && scaleOf(q1(".bbx-cap")) === 1 && angleOf(q1(".bbx-reel")) === 0 && q1(".bbx-leds span").style.opacity === "0.18" && bx.motion().speed === 0,
    q1(".bbx-cone").style.transform + " " + q1(".bbx-reel").style.transform);
  for (let i = 0; i < 30; i++) bx.animate({ bass: 1, highs: 1, level: 1 }, true, 1 / 60);
  const full = scaleOf(q1(".bbx-cone")), fullCap = scaleOf(q1(".bbx-cap")), dome = Number(q1(".bbx-tweeter-dome").style.opacity);
  const litFull = Array.prototype.filter.call(MO.document.querySelectorAll(".bbx-leds span"), l => l.style.opacity === "1").length;
  bx.rest();
  for (let i = 0; i < 30; i++) bx.animate({ bass: 0.3, highs: 0, level: 0.5 }, true, 1 / 60);
  const third = scaleOf(q1(".bbx-cone"));
  const litHalf = Array.prototype.filter.call(MO.document.querySelectorAll(".bbx-leds[data-side=left] span"), l => l.style.opacity === "1").length;
  check("G7. the woofer cones and caps scale with the bass: full bass 1 + " + MO.BFBoombox.CONE_PULSE + " (caps 1 + " + MO.BFBoombox.CAP_PULSE + "), 0.3 of it 0.3 as far",
    near(full, 1 + MO.BFBoombox.CONE_PULSE, 0.002) && near(fullCap, 1 + MO.BFBoombox.CAP_PULSE, 0.002) && near(third - 1, 0.3 * MO.BFBoombox.CONE_PULSE, 0.002), full + " " + fullCap + " " + third);
  /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: 12 LEDs, 6 a side. AFTER: two meters of 8 (bf-boombox.js's LEDS). */
  check("G7. the tweeters shimmer with the highs, and the LEDs light with the level (all 16 at full, 4 of 8 a side at half)",
    dome > 0.95 && Number(q1(".bbx-tweeter-dome").style.opacity) === 0.55 && litFull === 16 && litHalf === 4 && MO.BFBoombox.LEDS === 8, dome + " " + litFull + " " + litHalf);
  bx.rest();
  const angles = [];
  for (let i = 0; i < 120; i++) { bx.animate({ bass: 0, highs: 0, level: 0 }, true, 1 / 60); angles.push(angleOf(q1(".bbx-reel"))); }
  const steady = (angles[119] - angles[118] + 360) % 360;
  const slowing = [];
  for (let i = 0; i < 120; i++) { bx.animate({ bass: 0, highs: 0, level: 0 }, false, 1 / 60); slowing.push(angleOf(q1(".bbx-reel"))); }
  const steps = slowing.map((a, i) => (a - (i ? slowing[i - 1] : angles[119]) + 360) % 360);
  const stopAt = steps.findIndex(s => s === 0);
  check("G7. the reels turn steadily while playing (even in silence), then slow to a stop within 2 s of a pause, every step slower",
    steady > 3 && stopAt > 10 && stopAt <= 120 && steps.slice(0, stopAt).every((s, i) => i === 0 || s <= steps[i - 1] + 0.02) && steps.slice(stopAt).every(s => s === 0), steady + " " + stopAt);
  /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: no inline style but transform and opacity. AFTER: the same, except an SVG part's stop-color or
     fill set to one of the finish's tokens (var(--bbx-...)): static paint, never animated. */
  const styled = Array.prototype.filter.call(MO.document.querySelectorAll(".bbx *, .bfm-tag *"), el => {
    for (let i = 0; i < el.style.length; i++) {
      const p = el.style.item(i);
      if ((p === "stop-color" || p === "fill") && el.namespaceURI === "http://www.w3.org/2000/svg" && /^var\(--bbx-[\w-]+\)$/.test(el.style.getPropertyValue(p).trim())) continue;
      if (["transform", "opacity", "--bbx-scroll-s"].indexOf(p) === -1) return true;
    }
    return false;
  }).map(el => el.getAttribute("class") + ": " + el.getAttribute("style"));
  const styleProps = new Set((BX.match(/\.style\.(\w+)\s*=(?!=)/g) || []).map(x => /\.style\.(\w+)/.exec(x)[1]));
  const placeOnly = (BX.match(/\w+\.style\.(left|top|right|bottom)\s*=/g) || []).every(x => /^root\./.test(x));
  const frames_ = (BX.match(/@keyframes [\w-]+\{[\s\S]*?\}\}/g) || []);
  const kfOk = frames_.length >= 2 && frames_.every(k => (k.match(/[\w-]+(?=:)/g) || []).every(p => p === "transform" || p === "opacity"));
  /* NAMED BEFORE → AFTER (Nov 9 2026, golden note icon). BEFORE: a transition could name transform only, narrower than
     this check's own label ("transform or opacity"). AFTER: transform or opacity, as the label and the keyframe rule say,
     so the music button's hover can fade (transition:opacity 200ms). Every other property is still refused. */
  const transOk = (BX.match(/transition:[^;}"]+/g) || []).every(t => t.split(",").every(p => /^(transition:)?\s*(transform|opacity)\b/.test(p.trim()) || /none/.test(p)));
  check("G7. all motion is transform or opacity: the moving parts' styles, every keyframe and transition; only the root's place is left/top",
    styled.length === 0 && [...styleProps].every(p => ["transform", "opacity", "left", "top", "right", "bottom"].indexOf(p) !== -1) && placeOnly && kfOk && transOk,
    styled.slice(0, 3).join(" | ") + " " + [...styleProps].join());
  const T4 = await add("A Very Long Title For The Marquee", 210);
  await MO.BFMusic.loadLibrary(true);
  SPECTRUM.level = 230;
  gesture(MO); MO.BFMusic.playTrack(T4); await settle();
  frames(MO, 20);
  const live = scaleOf(q1(".bbx-cone"));
  check("G7. playing, bf-music.js's frame loop drives it from the analyser: the cones out, the reels turning",
    live > 1.05 && angleOf(q1(".bbx-reel")) > 0 && MO.BFMusic._levels().bass > 0.5, live);
  /* NAMED BEFORE → AFTER (Oct 31 2026, now playing). BEFORE: only a title over 16 characters scrolled
     (data-long, two bare spans). AFTER: the VFD scrolls "Title — Artist" whenever a track is loaded
     (data-scroll, two .bbx-vfd-copy, the second hidden from screen readers); G13 covers the rest. */
  check("G7. a loaded track scrolls on the display (two copies, the second hidden from screen readers), and the title is announced",
    q1(".bbx-marquee").getAttribute("data-scroll") === "true" && MO.document.querySelectorAll(".bbx-scroll .bbx-vfd-copy").length === 2 &&
    MO.document.querySelectorAll(".bbx-scroll .bbx-vfd-copy")[1].getAttribute("aria-hidden") === "true" && q1(".bfm-live").getAttribute("aria-live") === "polite" &&
    q1(".bfm-live").textContent === "Now playing: A Very Long Title For The Marquee by Artist");
  setHidden(MO, true);
  const hidAt = bx.motion().angle;
  frames(MO, 5);
  check("G7. hidden, it stops: no frame runs, nothing turns, and the marquee is paused", bx.motion().angle === hidAt && MO.__raf.length === 0 &&
    /* NAMED BEFORE → AFTER (Oct 31 2026, now playing): BEFORE the one marquee rule; AFTER the VFD, the ticker, the tag and the sweep in one rule.
       NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: those four. AFTER: the chrome's light sweep, the rim's shine and the bar's sheen pause in the same rule. */
    boxOf(MO).getAttribute("data-hidden") === "true" && /\.bfm\[data-hidden=true\] \.bbx-scroll,\.bfm\[data-hidden=true\] \.bbx-ticker-track,\.bfm\[data-hidden=true\] \.bfm-tag-scroll,\.bfm\[data-hidden=true\] \.bbx-sweep,\.bfm\[data-hidden=true\] \.bbx-sheen,\.bfm\[data-hidden=true\] \.bbx-rim-shine,\.bfm\[data-hidden=true\] \.bfm-tag-sheen\{animation-play-state:paused\}/.test(BX));
  setHidden(MO, false);
  MO.BFMusic.pause(); await settle();
  frames(MO, 150);
  check("G7. after a pause the speakers come to rest and the reels stop, and the loop ends", scaleOf(q1(".bbx-cone")) === 1 && bx.motion().speed === 0 && MO.__raf.length === 0,
    q1(".bbx-cone").style.transform + " " + bx.motion().speed);
  const RM = await openPage(Object.assign({}, base, { page: "tasks.html", reduce: true }));
  gesture(RM); RM.BFMusic.playTrack(T4); await settle(); frames(RM, 10);
  const rm = RM.BFMusic._box().motion();
  check("G7. under reduced motion it is still while playing: no frame, the speakers and reels at rest, a still level on the display, no scrolling title",
    (RM.__rafRequests || 0) === 0 && rm.speed === 0 && rm.cone === 0 && rm.angle === 0 && boxOf(RM).getAttribute("data-still") === "true" &&
    /* NAMED BEFORE → AFTER (Oct 31 2026, now playing): BEFORE data-long and the one marquee in the media query; AFTER data-scroll, and every moving part. */
    RM.document.querySelector(".bfm-viz").getAttribute("data-viz") === "static" && RM.document.querySelector(".bbx-marquee").getAttribute("data-scroll") === "false" &&
    /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: the four scrolling parts and the sweep. AFTER: the sheen, the rim's shine and the bar's sheen are
       stopped and the sheens hidden, and the keys and the panel do not slide. */
    /@media \(prefers-reduced-motion: reduce\)\{\.bbx-scroll,\.bbx-ticker-track,\.bfm-tag-scroll,\.bbx-sweep,\.bbx-ticker,\.bbx-sheen,\.bbx-rim-shine,\.bfm-tag-sheen\{animation:none!important\}\.bbx-sweep,\.bbx-sheen,\.bfm-tag \.bfm-tag-sheen\{display:none\}\.bbx-keys button,\.bbx-fkeys button,\.bfm-panel\{transition:none\}/.test(BX), JSON.stringify(rm));
  await nowPlayingReducedChecks(RM, T4);
  RM.BFMusic.pause();
  SPECTRUM.level = 0;

  /* G8. continuity across pages */
  const P1 = await openPage(Object.assign({}, base, { page: "tasks.html" }));
  gesture(P1); P1.BFMusic.playTrack(T2); await settle(); P1.BFMusic.seek(50); P1.BFMusic.setVolume(0.4);
  P1.dispatchEvent(new P1.Event("pagehide"));
  const left = JSON.parse(P1.localStorage.getItem("bf_music") || "{}");
  check("G8. leaving a page while it plays saves the track, the place, the queue, the volume, and that it was playing",
    left.was_playing === true && left.track_id === T2 && near(left.position, 50, 0.01) && near(left.volume, 0.4) && left.queue.length >= 3, JSON.stringify(left));
  P1.BFMusic.pause(); closeOne(P1);
  /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: timed from before jsdom built the page, which counts jsdom compiling the scripts (140 to 740 ms
     on this machine, more with the mixer). AFTER: timed from the page's DOMContentLoaded, when a browser's page
     has its scripts ready, to the first moment it plays; still within a second, and RESUME_WAIT_MS at most 500. */
  const P2 = await openPage(Object.assign({}, base, { page: "tasks.html", store: left }));
  const t0 = P2.__loadedAt;
  while (!P2.BFMusic.playing() && Date.now() - t0 < 2000) await wait(5);
  const took = Date.now() - t0;
  check("G8. the next page carries on by itself, from the same track and place, with the same queue and volume, within a second (" + took + " ms)",
    P2.BFMusic.playing() && P2.BFMusic.state().track_id === T2 && near(P2.BFMusic.position(), 50, 0.01) && near(P2.BFMusic.state().volume, 0.4) &&
    P2.BFMusic.state().queue.join() === left.queue.join() && took < 1000 && P2.BFMusic.RESUME_WAIT_MS <= 500, took);
  P2.BFMusic.pause(); await settle(); closeOne(P2);
  const P3 = await openPage(Object.assign({}, base, { page: "tasks.html", store: left, blockPlay: true }));
  await wait(P3.BFMusic.RESUME_WAIT_MS + 150); await settle();
  const ttag = P3.document.querySelector(".bfm-tag-title");
  check("G8. where the browser will not play before a tap, the tag says \"Tap to resume\" and nothing is heard",
    !P3.BFMusic.playing() && !P3.BFMusic.audible() && P3.BFMusic.armed() && ttag.textContent === "Tap to resume: Two" &&
    P3.document.querySelector(".bfm-tag").getAttribute("data-resume") === "true", ttag.textContent + " " + P3.BFMusic.playing());
  P3.__blockPlay = false;
  gesture(P3); await settle();
  check("G8. ... and the tap resumes it at the saved place", P3.BFMusic.playing() && P3.BFMusic.state().track_id === T2 && near(P3.BFMusic.position(), 50, 0.01));
  P3.BFMusic.pause(); await settle(); closeOne(P3);
  /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: "... For unbroken music, use Pop out." AFTER: it names the panel's option. */
  check("G8. the help text says so, word for word", F.document.querySelector(".bfm-continuity").textContent === "Moving between pages pauses for a moment. For unbroken music, choose Keep playing between pages." &&
    F.BFMusic.CONTINUITY_NOTE === "Moving between pages pauses for a moment. For unbroken music, choose Keep playing between pages.");

  /* G9. with the pop-out playing, each page's boombox is its remote and moves with it.
     The levels come every 33 ms and count for 400 ms; with two dozen jsdom windows each
     hearing every message the harness's own clock falls behind that, so the windows the
     rest of the check does not use are closed first. */
  WINS.filter(w => w !== D && w !== F).forEach(closeOne);
  const R1 =await openPage(Object.assign({}, base, { page: "tasks.html" }));
  const POP = await openPage(Object.assign({}, base, { popout: true }));
  SPECTRUM.level = 230;
  gesture(POP); POP.BFMusic.playTrack(T1); await settle(); POP.BFMusic._tick();
  // The page follows levels no older than 400 ms, so its frames run as soon as they arrive.
  /* wait for fresh levels AND the pop-out's "playing" status (it comes every tick, so on a loaded machine the
     levels can arrive first, while the page still reads "The pop-out player is open") AND the page's frame loop,
     then run its frames at once */
  const heardPlaying = () => /^Playing in the pop-out player/.test(R1.document.querySelector(".bfm-tag-title").textContent);
  for (let i = 0; i < 300 && !(R1.BFMusic._levels().bass > 0.5 && heardPlaying() && R1.__raf.length > 0); i++) await wait(10);
  frames(R1, 20);
  const rCone = scaleOf(R1.document.querySelector(".bbx-cone"));
  check("G9. while the pop-out plays, a page's speakers move with the pop-out's levels, and the page plays nothing itself",
    R1.BFMusic.popoutAlive() && !R1.BFMusic.playing() && rCone > 1.05 && R1.BFMusic._levels().bass > 0.5 && audibleCount() === 1, rCone + " " + JSON.stringify(R1.BFMusic._levels()) + " pop " + POP.BFMusic.playing() + " " + JSON.stringify(POP.BFMusic._levels()) + " alive " + R1.BFMusic.popoutAlive() + " audible " + audibleCount());
  check("G9. ... and its tag says where the music is", /^Playing in the pop-out player: One$/.test(R1.document.querySelector(".bfm-tag-title").textContent), R1.document.querySelector(".bfm-tag-title").textContent);
  click(R1, ".bfm-tag [data-act=toggle]"); await settle();
  check("G9. the tag's play/pause is the pop-out's remote", !POP.BFMusic.playing() && !R1.BFMusic.playing());
  POP.BFMusic._tick(); await wait(120); await settle();
  const rafLeft = R1.__raf.length;
  frames(R1, 120);
  check("G9. ... and when the pop-out pauses, the page's speakers come to rest", scaleOf(R1.document.querySelector(".bbx-cone")) === 1 && R1.BFMusic._box().motion().speed === 0,
    rafLeft + " " + JSON.stringify(R1.BFMusic._box().motion()) + " " + JSON.stringify(R1.BFMusic._levels()) + " " + POP.BFMusic.playing());
  click(R1, ".bfm-tag [data-act=next]"); await settle();
  check("G9. the tag's Next goes to the pop-out too", POP.BFMusic.state().track_id !== T1 && !R1.BFMusic.playing());
  POP.BFMusic.pause();
  POP.dispatchEvent(new POP.Event("pagehide")); closeOne(POP); await settle();
  SPECTRUM.level = 0;

  /* G10. phones: docked at the bottom, a bottom sheet */
  const PH = await openPage(Object.assign({}, base, { page: "tasks.html", width: 600 }));
  const PR = boxOf(PH), ptag = PH.document.querySelector(".bfm-tag-title");
  ptr(PH, ptag, "pointerdown", 50, 780); ptr(PH, ptag, "pointermove", 250, 500); ptr(PH, ptag, "pointerup", 250, 500);
  key(PH, PH.document.querySelector(".bfm-tag"), "ArrowUp");
  check("G10. at 860 px and narrower the tag docks to the bottom edge: no dragging, no arrow-key moves",
    PR.getAttribute("data-dock") === "phone" && PR.style.left === "" && PR.style.top === "" && !("left" in prefsOf(PH)) && PH.BFBoombox.PHONE_MAX === 860 &&
    /\.bfm-float\[data-dock=phone\]\{left:0!important;right:0;top:auto!important;bottom:0!important;/.test(BX));
  click(PH, "[data-act=bbx-expand]");
  check("G10. expanding opens a bottom sheet", PR.getAttribute("data-state") === "box" && PR.getAttribute("data-dock") === "phone" &&
    /\.bfm-float\[data-dock=phone\]\[data-state=box\]\{max-height:88vh;overflow:auto;/.test(BX));
  PH.__w = 1280; PH.dispatchEvent(new PH.Event("resize"));
  check("G10. widened, it leaves the dock and is placed on screen again", PR.getAttribute("data-dock") === "desktop" && PR.getAttribute("data-placed") === "true");

  /* G11. before migration 155: 503 and a plain sentence */
  const NOT_SET_UP = "Music isn't set up yet on the server (migration 155). Nothing is lost.";
  const liftedMissing = liftRoutes(missingClient(db));
  // next(error) is server.js's global handler: 500, "Internal server error".
  const served = (...a) => callRoute(...a).catch(() => ({ status: 500, body: { error: "Internal server error" } }));
  const r503 = await served(liftedMissing, "get", "/api/music");
  const pl503 = await served(liftedMissing, "post", "/api/music/playlists", { name: "Run", track_ids: [] });
  check("G11. with the music tables missing (PostgREST PGRST205), the library answers 503 with the plain sentence, and so does every music route",
    r503.status === 503 && r503.body.error === NOT_SET_UP && r503.body.reason === "music_not_set_up" && M.NOT_SET_UP === NOT_SET_UP && pl503.status === 503, JSON.stringify(r503) + " " + JSON.stringify(pl503));
  const otherErr = { client: { from: () => new Proxy({}, { get(t, k) { return k === "then" ? (res) => res({ data: null, error: { code: "08006", message: "connection failure" } }) : function () { return this; }; } }), storage: db.client.storage, rpc: db.client.rpc } };
  let passed = false;
  try { await callRoute(liftRoutes(otherErr), "get", "/api/music"); } catch (e) { passed = true; }
  check("G11. any other failure still goes to the error handler; a table named only in the hint is not \"missing\"",
    passed && M.missingTable({ code: "PGRST205", message: "Could not find the table 'public.member_tracks' in the schema cache" }) &&
    M.missingTable({ code: "42P01", message: "relation \"public.member_playlists\" does not exist" }) &&
    !M.missingTable({ code: "PGRST205", message: "Could not find the table 'public.contacts' in the schema cache", hint: "Perhaps you meant the table 'public.member_tracks'" }) &&
    !M.missingTable(null));
  const NS = await openPage({ lifted: liftedMissing, page: "tasks.html" });
  await settle(20);
  const nsText = boxOf(NS).textContent;   // body.textContent would include the inlined scripts
  check("G11. the player shows that sentence where \"Loading your music...\" was, never \"Internal server error\"",
    NS.document.querySelector(".bfm-queue li").textContent === NOT_SET_UP && NS.document.querySelector(".bfm-msg").textContent === NOT_SET_UP &&
    !/Internal server error|Loading your music/.test(nsText), NS.document.querySelector(".bfm-queue li").textContent);
  check("G12. no emoji in anything the boombox draws or says", !/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}\u{200D}\u{20E3}]/u.test(BX + boxOf(D).textContent + boxOf(F).textContent));
  await nowPlayingChecks(c);
  await liveOrderChecks();
  await mixerChecks(c);
  await stageChecks(c);
}

/* ── H. the boombox-mixer ───────────────────────────────────────────────── */
const lit = (w, side) => Array.prototype.filter.call(w.document.querySelectorAll(".bbx-leds[data-side=" + side + "] span"), l => l.style.opacity === "1").length;
/* the boombox's own stylesheet (bf-music.js has a .bfm rule of its own), with a newline in front so its first rule is found too */
const styleText = w => { const s = w.document.getElementById("bf-boombox-style"); return "\n" + (s ? s.textContent : ""); };
const ruleOf = (css, sel) => { const i = css.indexOf("\n" + sel + "{"); return i < 0 ? "" : css.slice(i + 1, css.indexOf("}", i) + 1); };
const pressKey = (w, el, k) => { el.focus(); key(w, el, k); };
async function mixerChecks(c) {
  console.log("\n══ H. the boombox-mixer: the bar first, the slide-out library, the finish, the EQ and the faders ══");
  const { db, lifted, base, T1 } = c;
  const BX = FILES[BOOMBOX] || "";

  /* H1. the bar first, on every page; its place; what it remembers */
  /* NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: a first visit started as the bar on the dashboard AND on a page without the logo.
     AFTER: the dashboard starts as the icon (40 x 36, at 212, 12), and another page shows nothing without music (TH); with music on (T, liveOn)
     it is the bar, top left. The bar beside the logo is still at (212, 10) once the icon opens it. */
  await freshStage(db);
  const D = await openPage(base), DR = boxOf(D);
  const TH = await openPage(Object.assign({}, base, { page: "tasks.html" }));
  const T = await openPage(Object.assign({}, base, liveOn(T1, { page: "tasks.html" }))), TR = boxOf(T);
  check("H1. a first visit never starts as the boombox: the dashboard is the icon, a page without music shows nothing, and with music on it is the bar; the library shut",
    DR.getAttribute("data-state") === "icon" && TR.getAttribute("data-state") === "tag" && shown(T) && !shown(TH) && boxOf(TH).getAttribute("data-away") === "true" &&
    DR.getAttribute("data-library") === "false" && D.document.querySelector("[data-act=bbx-expand]").getAttribute("aria-expanded") === "false",
    DR.getAttribute("data-state") + " " + TR.getAttribute("data-state") + " " + shown(TH));
  closeOne(TH);
  const iconAt = spot(D).join();
  click(D, "[data-act=bbx-open]");
  /* NAMED BEFORE → AFTER (Nov 8 2026, the music button). BEFORE: the icon at (212, 12). AFTER: the music button at (400, 10) (see G2). */
  check("H1. beside the logo the bar sits 12 px to the right, centred on the header (the bar 212, 10; the music button 400, 10); with no logo header, the top-left corner (16, 16); never bottom left",
    iconAt === "400,10" && spot(D).join() === "212,10" && spot(T).join() === "16,16" && T.BFMusic._box().defaultSpot().top === 16 && D.BFBoombox.GAP === 12, iconAt + " " + spot(D) + " " + spot(T));
  /* a logo at the right end of its header: the bar goes to its left, still level with it */
  const RL = await openPage(Object.assign({}, base, { page: "crm.html", extra: '<nav class="top-nav" data-size="1280x60"><span class="brand-badge" data-bf-boombox-anchor>BizForce AI</span></nav>' }));
  const rlSpot = RL.BFMusic._box().defaultSpot();
  check("H1. where the logo ends its header and the bar would not fit to its right, it docks to the logo's left (" + rlSpot.left + ", " + rlSpot.top + ")",
    rlSpot.left === 16 - 12 - 300 || (rlSpot.left === 212 && rlSpot.top === 10), JSON.stringify(rlSpot));
  click(T, "[data-act=bbx-expand]");
  check("H1. pressing the bar expands the boombox in place, from the same spot, down and right, kept on screen",
    TR.getAttribute("data-state") === "box" && spot(T).join() === "16,16" && 16 + 440 <= 1280 && 16 + 250 <= 800 && TR.getAttribute("data-library") === "false");
  /* each jsdom window has its own storage, so the next page is given what this one saved (bf_boombox) */
  check("H1. pressing it is saved: bf_boombox says the boombox, with the library shut", prefsOf(T).state === "box" && prefsOf(T).library === false, JSON.stringify(prefsOf(T)));
  const T2 = await openPage(Object.assign({}, base, liveOn(T1, { page: "tasks.html", boombox: prefsOf(T) })));
  check("H1. the boombox is remembered: the next page opens it again", boxOf(T2).getAttribute("data-state") === "box" && prefsOf(T2).state === "box" && shown(T2));
  click(T2, "[data-act=bbx-minimise]");
  const T3 = await openPage(Object.assign({}, base, liveOn(T1, { page: "tasks.html", boombox: prefsOf(T2) })));
  check("H1. ... and so is the bar, at the same spot", boxOf(T3).getAttribute("data-state") === "tag" && spot(T3).join() === "16,16" && prefsOf(T3).state === "tag");
  const Dg = T3.document.querySelector(".bfm-tag-title");
  ptr(T3, Dg, "pointerdown", 50, 30); ptr(T3, Dg, "pointermove", 450, 330); ptr(T3, Dg, "pointerup", 450, 330);
  const T4 = await openPage(Object.assign({}, base, liveOn(T1, { page: "tasks.html", boombox: prefsOf(T3) })));
  click(T4, "[data-act=bbx-expand]");
  const dragged = spot(T4).join();
  click(T4, "[data-act=bbx-reset]");
  check("H1. a dragged place is remembered (" + dragged + "), and Reset position returns it to the default",
    dragged === "416,316" && spot(T4).join() === "16,16" && !("left" in prefsOf(T4)), dragged + " " + spot(T4));
  [T2, T3, T4, RL].forEach(closeOne);

  /* H2. no Pop out on the face; the body's keys */
  const fkeys = Array.prototype.map.call(D.document.querySelectorAll(".bbx-fkeys button"), b => b.getAttribute("data-act") + ":" + b.getAttribute("aria-label") + ":" + !!b.querySelector("svg"));
  check("H2. no Pop out anywhere on the boombox or the bar: no popout key, no \"Pop out\" words",
    !D.document.querySelector("[data-act=popout]") && !/Pop out/i.test(DR.textContent) && !/Pop out/.test(BX) &&
    !Array.prototype.some.call(DR.querySelectorAll("[aria-label],[title]"), el => /pop.?out/i.test((el.getAttribute("aria-label") || "") + (el.getAttribute("title") || ""))), fkeys.join());
  /* NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: Mute, Library, Reset position, Minimise. AFTER: and Close to icon, two rows of three. */
  check("H2. the body's keys are piano keys with drawn icons and names: Mute, Library, Reset position, Minimise, Close to icon (" + fkeys.length + ")",
    fkeys.join() === "mute:Mute:true,bbx-library:Library:true,bbx-reset:Reset position:true,bbx-minimise:Minimise:true,bbx-close:Close to icon:true" &&
    /"\.bbx-keys button,\.bbx-fkeys button\{/.test(BX) && !!DR.querySelector(".bbx-deck .bbx-fkeys"), fkeys.join());

  /* H3. the library slides out; Escape slides it back; no window */
  const opened = () => D.__calls.filter(x => /^open /.test(x)).length;
  const before = opened();
  click(D, "[data-act=bbx-expand]");
  const panel = D.document.querySelector(".bfm-panel"), drawer = D.document.querySelector(".bfm-drawer");
  const shutAtFirst = panel.hasAttribute("inert") && panel.getAttribute("aria-hidden") === "true";
  click(D, "[data-act=bbx-library]");
  check("H3. Library slides the panel out (no window opened): the panel is live, the key says so, and it is remembered",
    shutAtFirst && DR.getAttribute("data-library") === "true" && !panel.hasAttribute("inert") && !panel.hasAttribute("aria-hidden") &&
    D.document.querySelector("[data-act=bbx-library]").getAttribute("aria-expanded") === "true" && opened() === before && prefsOf(D).library === true,
    shutAtFirst + " " + DR.getAttribute("data-library") + " " + opened());
  const css = styleText(D);
  check("H3. it slides by transform alone: shut it sits translated behind the boombox (up when below, sideways beside it), open it is at rest",
    /transform:translateY\(-104%\);transition:transform \.26s ease-out\}/.test(ruleOf(css, ".bfm-panel")) &&
    ruleOf(css, ".bfm-drawer[data-side=right] .bfm-panel") === ".bfm-drawer[data-side=right] .bfm-panel{transform:translateX(-104%)}" &&
    ruleOf(css, ".bfm-drawer[data-side=left] .bfm-panel") === ".bfm-drawer[data-side=left] .bfm-panel{transform:translateX(104%)}" &&
    ruleOf(css, ".bfm-float[data-state=box][data-library=true] .bfm-panel") === ".bfm-float[data-state=box][data-library=true] .bfm-panel{transform:none}" &&
    ["below", "right", "left"].indexOf(drawer.getAttribute("data-side")) !== -1, drawer.getAttribute("data-side"));
  check("H3. it holds the tracks, the playlists, the queue, Spectrum and Waveform, the Mix, uploads and \"Play when I open BizForce\"",
    [".bfm-queue", ".bfm-playlist", "[data-view=spectrum]", "[data-view=wave]", ".bfm-mix", ".bfm-drop", "#bfmAutoplay", "[data-act=keep-playing]", ".bfm-finish-pick"].every(s => !!panel.querySelector(s)));
  key(D, D.document.querySelector("[data-act=bbx-library]"), "Escape");
  check("H3. Escape slides it back first (the boombox stays open), the focus on Library", DR.getAttribute("data-library") === "false" && DR.getAttribute("data-state") === "box" &&
    panel.hasAttribute("inert") && D.document.activeElement === D.document.querySelector("[data-act=bbx-library]"));
  key(D, D.document.activeElement, "Escape");
  check("H3. ... a second Escape minimises it to the bar", DR.getAttribute("data-state") === "tag");
  click(D, "[data-act=bbx-expand]"); click(D, "[data-act=bbx-library]"); click(D, "[data-act=bbx-library]");
  check("H3. the Library key toggles it shut again, and no window opened all the while", DR.getAttribute("data-library") === "false" && opened() === before);
  click(D, "[data-act=bbx-library]");
  check("H3. \"Keep playing between pages\" is the one thing that opens a window, with its help line",
    opened() === before && D.document.querySelector("#bfmKeepHelp").textContent === "The small window keeps the music going while you move around BizForce; close it to stop." &&
    D.document.querySelector("[data-act=keep-playing]").getAttribute("aria-describedby") === "bfmKeepHelp");
  click(D, ".bfm-panel [data-act=keep-playing]");
  check("H3. ... and choosing it opens music-popout.html", opened() === before + 1 && D.__calls.indexOf("open /music-popout.html") !== -1);
  const pop = FILES[POPOUT] || "";
  check("H3. music-popout.html still works and is restyled: its own heading, the player mounted in it",
    /<h1 class="popout-title">BizForce music<\/h1>/.test(pop) && /<div id="bfMusicPopout"><\/div>/.test(pop) && /\.popout-head/.test(pop));

  /* H4. the finish: Chrome or Black, on the boombox and the bar, kept */
  const tag = D.document.querySelector(".bfm-tag");
  const chromeAtFirst = DR.getAttribute("data-finish") === "chrome";
  D.BFMusic.setFinish("black");
  const tagRule = ruleOf(styleText(D), ".bfm-tag");
  const tokens = s => (s.match(/--bbx-[\w-]+(?=:)/g) || []).sort().join();
  const chromeSet = ruleOf(styleText(D), ".bfm"), blackSet = ruleOf(styleText(D), ".bfm[data-finish=black]");
  check("H4. the finish starts as Chrome, and Black is applied to the root, so to the boombox and the bar alike",
    chromeAtFirst && DR.getAttribute("data-finish") === "black" && tag.closest(".bfm[data-finish=black]") === DR && DR.querySelector(".bbx").closest("[data-finish=black]") === DR);
  check("H4. the bar is painted only from the finish's tokens (its ink and metal), so Black reaches it; no fixed grey",
    /color:var\(--bbx-ink\);background:repeating-linear-gradient\(90deg,var\(--bbx-brush\)[^;]*var\(--bbx-m1\)[^;]*var\(--bbx-m6\) 100%\);/.test(tagRule) &&
    tokens(chromeSet) === tokens(blackSet) && tokens(chromeSet).split(",").length >= 20 && !/#(?:[89a-c][0-9a-f]){3}\b|gr[ae]y/i.test(tagRule), tagRule.slice(0, 200));
  check("H4. the finish is kept on this device (bf_music) and the panel's picker shows it",
    JSON.parse(D.localStorage.getItem("bf_music")).finish === "black" && D.document.querySelector(".bfm-finish-pick[value=black]").checked);
  await wait(D.BFMusic.PLAYER_SAVE_MS || 650); await wait(150); await settle();
  const row = (db.T.user_preferences || []).find(r => r.user_id === UID);
  check("H4. ... and on the account: PUT /api/music/player saves it in user_preferences.music_player",
    D.__calls.indexOf("put /api/music/player") !== -1 && !!row && row.music_player && row.music_player.finish === "black", JSON.stringify(row));
  const FIN = await openPage(Object.assign({}, base, { page: "tasks.html", store: { v: 1, uid: UID, finish: "chrome" } }));
  await settle(20);
  check("H4. a page on another device adopts the account's finish", boxOf(FIN).getAttribute("data-finish") === "black" && FIN.BFMusic.state().finish === "black",
    boxOf(FIN).getAttribute("data-finish"));
  closeOne(FIN);
  const SETTINGS_PICK = (/<div class="ts-choices" id="bfmFinishSetting"[\s\S]*?<\/div>/.exec(FILES[SETTINGS] || "") || [""])[0];
  const SE = await openPage(Object.assign({}, base, { page: "settings.html", extra: SETTINGS_PICK }));
  const blackPick = SE.document.querySelector("#bfmFinishSetting input[value=black]"), chromePick = SE.document.querySelector("#bfmFinishSetting input[value=chrome]");
  const showsAccount = blackPick && blackPick.checked;
  chromePick.checked = true; chromePick.dispatchEvent(new SE.Event("change", { bubbles: true }));
  check("H4. Settings → Theme → Music has \"Music player finish: Chrome / Black\", showing the member's finish and changing it",
    !!SETTINGS_PICK && /role="radiogroup"/.test(SETTINGS_PICK) && /Music player finish/.test(SETTINGS_PICK) && showsAccount &&
    SE.BFMusic.state().finish === "chrome" && boxOf(SE).getAttribute("data-finish") === "chrome" && SE.document.querySelector(".bfm-finish-pick[value=chrome]").checked,
    SETTINGS_PICK.slice(0, 80) + " " + showsAccount);
  const settingsTab = (FILES[SETTINGS] || "").indexOf('id="bfmFinishSetting"') > (FILES[SETTINGS] || "").indexOf('id="tsMusicIntensity"');
  check("H4. ... beside the theme's music settings", settingsTab && (FILES[SETTINGS] || "").indexOf('id="tsMusicIntensity"') !== -1);
  closeOne(SE);
  await wait(800); await settle();

  /* H5. the account's player settings: validated, and plain before migration 157 */
  const put = body => callRoute(lifted, "put", "/api/music/player", body);
  const ok = await put({ finish: "black", eq: { bass: 3.3, treble: -12 } });
  const got = await callRoute(lifted, "get", "/api/music/player");
  check("H5. PUT keeps a valid finish and EQ (rounded to half a dB), and GET reads them back as saved",
    ok.status === 200 && ok.body.player.finish === "black" && ok.body.player.eq.bass === 3.5 && ok.body.player.eq.treble === -12 && ok.body.player.eq.mid === 0 &&
    got.status === 200 && got.body.saved === true && got.body.player.eq.bass === 3.5, JSON.stringify([ok, got]));
  const bad = await Promise.all([{ eq: { bass: 13 } }, { eq: { mid: -12.5 } }, { finish: "gold" }, { finish: "black", volume: 1 }, {}, { eq: { sub: 2 } }, { eq: { bass: "3" } }, { eq: [1] }].map(put));
  check("H5. it refuses with 400 and the field: a band past ±12 dB, an unknown finish, an unknown key, an empty body, an unknown band, a non-number, a non-object",
    bad.every(r => r.status === 400 && typeof r.body.error === "string") && bad[0].body.field === "eq.bass" && bad[1].body.field === "eq.mid" && bad[2].body.field === "finish" &&
    bad[5].body.field === "eq.sub" && bad[6].body.field === "eq.bass", JSON.stringify(bad.map(r => r.status + ":" + r.body.field)));
  const still = await callRoute(lifted, "get", "/api/music/player");
  check("H5. ... and a refused change changes nothing", still.body.player.finish === "black" && still.body.player.eq.bass === 3.5);
  /* NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: storedPlayer gave { finish, eq }. AFTER: { finish, eq, position, stage }, a bad
     position read as "follow" and a bad stage as null (each page then decides). */
  check("H5. lib/music.js: two finishes, three bands, ±12 dB, two positions, three stages; a stored value is read safely whatever it holds",
    M.FINISHES.join() === "chrome,black" && M.EQ_BANDS.join() === "bass,mid,treble" && M.EQ_MAX_DB === 12 && M.POSITIONS.join() === "follow,pinned" && M.STAGES.join() === "icon,tag,box" &&
    JSON.stringify(M.storedPlayer({ finish: "neon", eq: { bass: 40, mid: "x", treble: -2 }, position: "glued", stage: "huge" })) ===
      JSON.stringify({ finish: "chrome", eq: { bass: 0, mid: 0, treble: -2 }, position: "follow", stage: null }) &&
    JSON.stringify(M.storedPlayer(null)) === JSON.stringify(M.playerDefaults()));
  const noCol = { client: { from: tbl => tbl !== "user_preferences" ? db.client.from(tbl) : new Proxy({}, { get(x, k) { return k === "then" ? res => res({ data: null, error: { code: "PGRST204", message: "Could not find the 'music_player' column of 'user_preferences' in the schema cache" } }) : function () { return this; }; } }),
    storage: db.client.storage, rpc: db.client.rpc } };
  const liftedNoCol = liftRoutes(noCol);
  const g503 = await callRoute(liftedNoCol, "get", "/api/music/player"), p503 = await callRoute(liftedNoCol, "put", "/api/music/player", { finish: "black" });
  check("H5. before migration 157 both answer 503 with a plain sentence, never \"Internal server error\"",
    g503.status === 503 && p503.status === 503 && g503.body.reason === "music_player_not_set_up" &&
    g503.body.error === "Your player settings can't be saved to your account yet (migration 157). They're kept on this device." && M.PLAYER_NOT_SET_UP === g503.body.error, JSON.stringify(g503));
  const NC = await openPage({ lifted: liftedNoCol, page: "tasks.html" });
  await settle(20);
  NC.BFMusic.setFinish("black"); await wait(NC.BFMusic.PLAYER_SAVE_MS || 650); await wait(150); await settle();
  /* NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: "Your finish and EQ are kept on this device for now." AFTER: the position too. */
  check("H5. ... and the player says the finish, EQ and position are kept on this device for now, and keeps them",
    NC.document.querySelector(".bfm-player-note").textContent === "Your finish, EQ and position are kept on this device for now." && JSON.parse(NC.localStorage.getItem("bf_music")).finish === "black",
    NC.document.querySelector(".bfm-player-note").textContent);
  closeOne(NC);
  const mig = FILES[MIGRATION_157] || "";
  check("H5. migration 157 adds user_preferences.music_player (jsonb), held to an object of at most 1 KB",
    /alter table (public\.)?user_preferences\s+add column if not exists music_player jsonb/i.test(mig) && /jsonb_typeof\(music_player\) = 'object'/.test(mig) && /pg_column_size\(music_player\) <= 1024/.test(mig),
    mig.slice(0, 160));
  /* NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: "your music player's finish and EQ". AFTER: its finish, EQ, position and last view. */
  check("H5. the data page says user_preferences holds the player's finish, EQ, position and last view",
    /your music player's finish, EQ, position and last view \(icon, bar or boombox\)/.test(FILES[YOURDATA] || "") &&
    /your music player(?:'|&#39;)s finish, EQ, position and last view \(icon, bar or boombox\)/.test(FILES[PRIVACY] || ""));

  /* H6. the EQ: three filters on the way to the speakers, clamped, keyed, kept */
  const E = await openPage(Object.assign({}, base, { page: "tasks.html" }));
  gesture(E); E.BFMusic.playTrack(T1); await settle();
  const F_ = E.BFMusic._filters(), ectx = E.BFMusic._context(), m = E.BFMusic._master();
  check("H6. three BiquadFilters: BASS a low shelf at 120 Hz, MID a peaking filter at 1 kHz, TREBLE a high shelf at 6 kHz",
    !!F_.bass && F_.bass.type === "lowshelf" && F_.bass.frequency.value === 120 && F_.mid.type === "peaking" && F_.mid.frequency.value === 1000 &&
    F_.treble.type === "highshelf" && F_.treble.frequency.value === 6000 && ectx.filters.length === 3, JSON.stringify(F_ && Object.keys(F_)));
  const spl = ectx.splitters[0];
  check("H6. the chain: the master gain → bass → mid → treble → the analyser and the speakers, and the treble's output also feeds the meters",
    m.out[0] === F_.bass && F_.bass.out[0] === F_.mid && F_.mid.out[0] === F_.treble && F_.treble.out.some(n => n.out.indexOf(ectx.destination) !== -1) && F_.treble.out.indexOf(spl) !== -1);
  E.BFMusic.setEq("bass", 30); E.BFMusic.setEq("treble", -40); E.BFMusic.setEq("mid", 4.2);
  check("H6. a gain past ±12 dB is held at the limit, in the filter and the state (and rounded to half a dB)",
    F_.bass.gain.value === 12 && F_.treble.gain.value === -12 && F_.mid.gain.value === 4 && E.BFMusic.state().eq.bass === 12 && E.BFMusic.state().eq.mid === 4,
    [F_.bass.gain.value, F_.mid.gain.value, F_.treble.gain.value].join());
  const kb = E.document.querySelector(".bbx-knob[data-band=bass]"), km = E.document.querySelector(".bbx-knob[data-band=mid]");
  pressKey(E, kb, "Home");
  const atHome = F_.bass.gain.value;
  pressKey(E, kb, "ArrowUp"); pressKey(E, kb, "PageUp");
  const stepped = F_.bass.gain.value;
  pressKey(E, kb, "End"); pressKey(E, kb, "ArrowUp");
  check("H6. the knobs answer the keys: Home −12, an arrow 1 dB, Page Up 3, End +12 and no further; aria-valuenow and the text follow",
    atHome === -12 && stepped === -8 && F_.bass.gain.value === 12 && kb.getAttribute("aria-valuenow") === "12" && kb.getAttribute("aria-valuetext") === "+12 dB" &&
    kb.getAttribute("aria-valuemin") === "-12" && kb.getAttribute("aria-valuemax") === "12" && kb.getAttribute("aria-label") === "Bass", atHome + " " + stepped + " " + F_.bass.gain.value);
  kb.dispatchEvent(new E.MouseEvent("dblclick", { bubbles: true }));
  check("H6. a double-click resets a knob to 0 dB", F_.bass.gain.value === 0 && kb.getAttribute("aria-valuetext") === "0 dB");
  E.BFMusic.setEq("mid", 0);
  ptr(E, km, "pointerdown", 0, 100); ptr(E, km, "pointermove", 0, 98);
  const nearCentre = F_.mid.gain.value;
  ptr(E, km, "pointermove", 0, 60); ptr(E, km, "pointerup", 0, 60);
  E.BFMusic.setEq("mid", 0);
  ptr(E, km, "pointerdown", 0, 100); ptr(E, km, "pointermove", 0, 102); ptr(E, km, "pointerup", 0, 102);
  check("H6. dragging turns it (up raises), with a centre detent: within 0.75 dB of 0 it rests at 0",
    nearCentre === 0 && F_.mid.gain.value === 0 && E.BFBoombox.EQ_MAX === 12, nearCentre + " " + F_.mid.gain.value);
  ptr(E, km, "pointerdown", 0, 100); ptr(E, km, "pointermove", 0, 60); ptr(E, km, "pointerup", 0, 60);
  const raised = F_.mid.gain.value;
  check("H6. ... and 40 px up is +10 dB", raised === 10, raised);
  check("H6. the knob's mark turns with it (by transform)", /^rotate\(\d+(\.\d)?deg\)$/.test(km.querySelector(".bbx-knob-mark").style.transform), km.querySelector(".bbx-knob-mark").style.transform);
  const keptEq = JSON.parse(E.localStorage.getItem("bf_music")).eq;
  await wait(E.BFMusic.PLAYER_SAVE_MS || 650); await wait(150); await settle();
  const eqRow = (db.T.user_preferences || []).find(r => r.user_id === UID);
  check("H6. the EQ is kept for the member: on this device and on the account",
    keptEq.bass === 0 && keptEq.mid === 10 && keptEq.treble === -12 && eqRow.music_player.eq.mid === 10 && eqRow.music_player.eq.treble === -12, JSON.stringify([keptEq, eqRow && eqRow.music_player]));
  const E2 = await openPage(Object.assign({}, base, { page: "tasks.html" }));
  gesture(E2); E2.BFMusic.playTrack(T1); await settle();
  check("H6. ... and the next page's filters and knobs start from it", E2.BFMusic._filters().mid.gain.value === 10 && E2.document.querySelector(".bbx-knob[data-band=mid]").getAttribute("aria-valuenow") === "10");
  E2.BFMusic.pause(); closeOne(E2);

  /* H7. the crossfader and the fader */
  const xf = E.document.querySelector(".bbx-xf");
  pressKey(E, xf, "End");
  const atEnd = E.BFMusic.state().crossfade, outEnd = E.document.querySelector(".bbx-xf-out").textContent;
  pressKey(E, xf, "ArrowLeft"); pressKey(E, xf, "ArrowLeft");
  check("H7. the crossfader sets the Mix, 0 to 12 s, and shows it (End 12 s, two steps back 10 s)",
    atEnd === 12 && outEnd === "12 s" && E.BFMusic.state().crossfade === 10 && E.document.querySelector(".bbx-xf-out").textContent === "10 s" &&
    xf.getAttribute("aria-valuetext") === "10 seconds" && E.document.querySelector(".bfm-mix").value === "10" && E.BFBoombox.MIX_MAX === 12, atEnd + " " + outEnd);
  pressKey(E, xf, "Home");
  check("H7. ... Home turns it off", E.BFMusic.state().crossfade === 0 && E.document.querySelector(".bbx-xf-out").textContent === "Off" && /translateX\(0(\.0)?px\)/.test(E.document.querySelector(".bbx-xf-cap").style.transform));
  const fader = E.document.querySelector(".bbx-fader");
  pressKey(E, fader, "End");
  const gTop = masterGain(E);
  pressKey(E, fader, "PageDown"); pressKey(E, fader, "PageDown"); pressKey(E, fader, "ArrowDown");
  check("H7. the vertical fader sets the master gain: End full, then two pages and a step down to 0.75; aria follows",
    gTop === 1 && near(masterGain(E), 0.75, 0.001) && near(E.BFMusic.state().volume, 0.75, 0.001) && fader.getAttribute("aria-valuenow") === "75" &&
    fader.getAttribute("aria-orientation") === "vertical" && /translateY\(/.test(E.document.querySelector(".bbx-fader-cap").style.transform), gTop + " " + masterGain(E));
  pressKey(E, fader, "Home");
  check("H7. ... and Home silences it", masterGain(E) === 0);
  E.BFMusic.setVolume(0.8);

  /* H8. the meters (E2 starting its music paused this page, as two tabs never sound together; so play again) */
  gesture(E); E.BFMusic.playTrack(T1); await settle();
  SPECTRUM.level = 200; SPECTRUM.left = 1; SPECTRUM.right = 0.25;
  frames(E, 40);
  const L = lit(E, "left"), Rr = lit(E, "right");
  check("H8. where the sound splits, two meters, L and R, each following its own channel (" + L + " and " + Rr + " of 8 lit)",
    E.document.querySelector(".bbx-meter-lbl[data-side=left]").textContent === "L" && E.document.querySelector(".bbx-meter-lbl[data-side=right]").textContent === "R" &&
    /* a channel's level is its RMS x 2.2, clamped: left 1 -> all 8, right 0.25 -> 0.55 -> 4 */
    L === 8 && Rr === 4 && !!E.BFMusic._meters().left && E.BFMusic._meters().left.channel === 0 && E.BFMusic._meters().right.channel === 1, L + " " + Rr);
  E.BFMusic.pause(); await settle(); frames(E, 150);
  check("H8. paused, the meters go dark", lit(E, "left") === 0 && lit(E, "right") === 0);
  SPECTRUM.left = 0; SPECTRUM.right = 0;
  FAKE_AUDIO.split = false;
  const MO = await openPage(Object.assign({}, base, { page: "tasks.html" }));
  gesture(MO); MO.BFMusic.playTrack(T1); await settle(); frames(MO, 40);
  const ml = lit(MO, "left"), mp = lit(MO, "right");
  check("H8. where it cannot split, the meters read the level and its peak (Lvl, Pk), the peak never below the level",
    MO.document.querySelector(".bbx-meter-lbl[data-side=left]").textContent === "Lvl" && MO.document.querySelector(".bbx-meter-lbl[data-side=right]").textContent === "Pk" &&
    ml > 0 && mp >= ml && !MO.BFMusic._meters().left, ml + " " + mp);
  MO.BFMusic.pause(); closeOne(MO);
  FAKE_AUDIO.split = true; SPECTRUM.level = 0;
  closeOne(E);

  /* H9. every mixer control by keyboard, with aria */
  const sliders = Array.prototype.map.call(D.document.querySelectorAll(".bbx-deck [role=slider]"), s => s.getAttribute("aria-label") + ":" + s.getAttribute("tabindex") + ":" +
    (s.hasAttribute("aria-valuemin") && s.hasAttribute("aria-valuemax") && s.hasAttribute("aria-valuenow") && s.hasAttribute("aria-valuetext")));
  check("H9. the mixer's five sliders are focusable and carry their values: Bass, Mid, Treble, Mix (crossfade), Volume",
    sliders.join() === "Bass:0:true,Mid:0:true,Treble:0:true,Mix (crossfade):0:true,Volume:0:true", sliders.join());

  /* H10. the VFD, the ticker, the reels, the sweep and the speakers are still there */
  check("H10. the display, the LED ticker, the reels, the sweep and the speakers remain",
    !!DR.querySelector(".bbx-display .bbx-marquee") && !!DR.querySelector(".bbx-ticker") && DR.querySelectorAll(".bbx-reel").length >= 2 && !!DR.querySelector(".bbx-sweep") &&
    DR.querySelectorAll(".bbx-cone").length >= 2 && DR.querySelectorAll(".bbx-tweeter-dome").length >= 2);
  const svgSrc = BX;
  check("H10. the hyper-real finish is drawn: the handle, the screws, a perforated grille, rubber feet, the brushed face, the bevel and the reflection, and the silver sweep",
    /bbx-handle/.test(svgSrc) && /bbx-screw/.test(svgSrc) && /<pattern id="bbxGrille"/.test(svgSrc) && /fill="url\(#bbxFoot\)"/.test(svgSrc) &&
    /\.bbx-face\{/.test(svgSrc) && /\.bbx-face::before\{/.test(svgSrc) && /@keyframes bbx-sheen\{/.test(svgSrc) && /@keyframes bbx-rim\{/.test(svgSrc) && /@keyframes bbx-bar-sheen\{/.test(svgSrc));

  /* H11. the profile: the member's own, never a visitor's or the preview */
  /* NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: the own profile showed the bar always. AFTER: it follows every page but the dashboard:
     mounted for the owner only, shown (as the bar) only while music is on; without music nothing shows. A visitor and the preview get none at all. */
  await freshStage(db);
  const own = await openPage(Object.assign({}, base, liveOn(T1, { page: "profile.html" })));
  const ownId = await openPage(Object.assign({}, base, liveOn(T1, { page: "profile.html?id=" + UID })));
  const ownQuiet = await openPage(Object.assign({}, base, { page: "profile.html?id=" + UID }));
  const visit = await openPage(Object.assign({}, base, liveOn(T1, { page: "profile.html?id=" + OTHER })));
  const prev = await openPage(Object.assign({}, base, liveOn(T1, { page: "profile.html?id=" + UID + "&bf_preview=1" })));
  check("H11. on the member's own profile it shows as the bar only while music is on (nothing without it); a visitor (another member's id) and the preview get none",
    shown(own) && boxOf(own).getAttribute("data-state") === "tag" && shown(ownId) && !!boxOf(ownQuiet) && !shown(ownQuiet) && !boxOf(visit) && !boxOf(prev),
    [shown(own), shown(ownId), shown(ownQuiet), !!boxOf(visit), !!boxOf(prev)].join());
  closeOne(ownQuiet);
  const prof = FILES[PROFILE] || "";
  check("H11. profile.html loads the session guard (and so the player) only for a signed-in visitor, and carries the mist",
    /document\.write\('<scr' \+ 'ipt src="\/scripts\/bf-session\.js"><\/scr' \+ 'ipt>'\)/.test(prof) && /<script src="\/scripts\/termaximus-presence\.js"><\/script>/.test(prof));
  [own, ownId, visit, prev].forEach(closeOne);

  /* H12. no emoji */
  check("H12. no emoji in the mixer, the panel, the settings or the pop-out", !/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}\u{200D}\u{20E3}]/u.test(BX + FILES[MUSIC] + SETTINGS_PICK + pop + DR.textContent));
  closeOne(D); closeOne(T);
}

/* ── I. three stages, pin or follow, the mixer's spacing (Oct 31 2026) ─────────
   The owner's final adjustments: the headers stay as they were; the deck's
   parts never overlap; the dashboard starts as the icon; icon -> bar ->
   boombox and back; other pages show the player only while music is on;
   the stage and the position are remembered and validated. */
const HEADER_BASE = "9750ee2";   // the frontend before these adjustments: every page's header as the owner left it
const headerOf = html => (lf(html).match(/<header\b[\s\S]*?<\/header>|<nav\b[^>]*\btop-nav\b[\s\S]*?<\/nav>|<[^>]*data-bf-boombox-anchor[^>]*>/g) || []).join("\n");
/* The deck's parts as laid out by the boombox's own stylesheet (computed), in deck pixels, scaled by the phone's --bbx-fit. */
function deckBoxes(w) {
  const r = boxOf(w), q = s => r.querySelector(s), cs = el => w.getComputedStyle(el), px = v => parseFloat(v) || 0;
  const fit = parseFloat(r.style.getPropertyValue("--bbx-fit")) || 1;
  const slot = el => ({ left: px(cs(el).left), top: px(cs(el).top), width: px(cs(el).width), height: px(cs(el).height) });
  const scale = b => ({ left: b.left * fit, top: b.top * fit, right: (b.left + b.width) * fit, bottom: (b.top + b.height) * fit });
  const meters = slot(q(".bbx-meters")), lane = slot(q(".bbx-vol")), fd = slot(q(".bbx-fader")), cap0 = slot(q(".bbx-fader-cap"));
  const ty = parseFloat((/translateY\((-?[\d.]+)px\)/.exec(q(".bbx-fader-cap").style.transform) || [0, "NaN"])[1]);
  const track = { left: lane.left + fd.left, top: lane.top + fd.top, width: fd.width, height: fd.height };
  const cap = { left: track.left + cap0.left, top: track.top + cap0.top + ty, width: cap0.width, height: cap0.height };
  const lblEl = q(".bbx-vol .bbx-lbl"), ls = slot(lblEl);
  const label = { left: lane.left + ls.left, top: lane.top + ls.top, width: ls.width, height: 7 };
  const xs = slot(q(".bbx-xfade")), xcap = slot(q(".bbx-xf-cap"));
  const tx = parseFloat((/translateX\((-?[\d.]+)px\)/.exec(q(".bbx-xf-cap").style.transform) || [0, "0"])[1]);
  const xfCap = { left: xs.left + xcap.left + tx, top: xs.top, width: xcap.width, height: 30 };
  return { fit, ty, meters: scale(meters), track: scale(track), cap: scale(cap), label: scale(label), fkeys: scale(slot(q(".bbx-fkeys"))), xfCap: scale(xfCap),
    lane: scale(lane), labelShown: cs(lblEl).display !== "none" && lblEl.textContent === "Vol" && px(cs(lblEl).width) > 0 };
}
async function stageChecks(c) {
  console.log("\n══ I. three stages (icon, bar, boombox), pin or follow, and the mixer's spacing ══");
  const { db, lifted, base, T1, T2 } = c;
  const BX = FILES[BOOMBOX] || "";
  const css = el => el.ownerDocument.defaultView.getComputedStyle(el);

  /* I1. no header and no logo moved: every page's header markup as it was */
  const { execFileSync } = require("child_process");
  let basePages = [], gitErr = "";
  try { basePages = execFileSync("git", ["-C", FRONTEND, "ls-tree", "-r", "--name-only", HEADER_BASE], { encoding: "utf8" }).split("\n").filter(f => /\.html$/.test(f)); }
  catch (e) { gitErr = e.message; }
  const changedHeaders = [], withHeader = [];
  for (const f of basePages) {
    let was = "";
    try { was = headerOf(execFileSync("git", ["-C", FRONTEND, "show", HEADER_BASE + ":" + f], { encoding: "utf8", maxBuffer: 1 << 26 })); } catch (e) { changedHeaders.push(f + " unreadable"); continue; }
    if (!was) continue;
    withHeader.push(f);
    const now = fs.existsSync(path.join(FRONTEND, f)) ? headerOf(frontText(f)) : "";
    if (now !== was) changedHeaders.push(f);
  }
  check("I1. no header or logo order changed on any page: the header markup of every page (" + withHeader.length + " with one) is identical to " + HEADER_BASE + "'s",
    !gitErr && withHeader.length >= 40 && withHeader.indexOf("dashboard.html") !== -1 && changedHeaders.length === 0, gitErr || changedHeaders.slice(0, 6).join(", "));

  /* I2. the mixer's spacing: the meters and the fader each in their own slot, at every fader position, both finishes, desktop and phone */
  const overlapping = [];
  let labelOk = true, inDeck = true, gaps = [];
  const MX = await openPage(Object.assign({}, base, { boombox: { state: "box" } }));
  const PHX = await openPage(Object.assign({}, base, { boombox: { state: "box" }, width: 390 }));
  for (const [where, w] of [["desktop", MX], ["phone", PHX]]) {
    const bx = w.BFMusic._box();
    for (const fin of ["chrome", "black"]) {
      bx.setFinish(fin);
      for (const v of [0, 0.5, 1]) {
        bx.setVolume(v); bx.setMix(v * 12);
        const b = deckBoxes(w), tag = where + " " + fin + " " + v;
        if (isNaN(b.ty)) overlapping.push(tag + " no fader transform");
        [["meters", "fader track", b.meters, b.track], ["meters", "fader handle", b.meters, b.cap], ["meters", "VOL label", b.meters, b.label],
          ["fader handle", "VOL label", b.cap, b.label], ["meters", "keys", b.meters, b.fkeys], ["fader handle", "keys", b.cap, b.fkeys],
          ["crossfader", "meters", b.xfCap, b.meters]].forEach(([n1, n2, x, y]) => { if (overlaps(x, y)) overlapping.push(tag + ": " + n1 + " x " + n2); });
        if (!b.labelShown) labelOk = false;
        const deckW = 378 * b.fit, deckH = 44 * b.fit;
        [b.meters, b.lane, b.cap, b.label, b.fkeys, b.xfCap].forEach(x => { if (x.left < 0 || x.top < 0 || x.right > deckW + 0.01 || x.bottom > deckH + 0.01) inDeck = false; });
        gaps.push(Math.min(b.track.left, b.cap.left) - b.meters.right);
      }
    }
    if (where === "phone") check("I2. on a phone the boombox is scaled (--bbx-fit " + deckBoxes(w).fit + ") and the spacing scales with it", w.document.querySelector(".bfm-float").getAttribute("data-dock") === "phone" && deckBoxes(w).fit < 1);
  }
  check("I2. the volume fader never overlaps the L/R meters: at min, mid and max, in Chrome and Black, at desktop and phone size (computed boxes; the smallest gap " + Math.min.apply(null, gaps).toFixed(1) + " px)",
    overlapping.length === 0 && Math.min.apply(null, gaps) >= 4, overlapping.slice(0, 4).join(" | "));
  check("I2. ... the meters, the fader's lane and its \"VOL\" label, the Mix and the keys each have their own slot inside the deck, and \"Vol\" is visible",
    labelOk && inDeck && BX.indexOf('".bbx-vol{left:268px;top:2px;width:30px;height:40px}"') !== -1 && /\.bbx-meters\{left:216px;top:2px;width:44px;height:40px;display:flex;justify-content:center/.test(BX));
  closeOne(MX); closeOne(PHX);

  /* I3. the dashboard's first visit: the ICON beside the logo, nothing else, no audio */
  await freshStage(db);
  const DI = await openPage(base), DIR = boxOf(DI);
  await settle(20);
  const icon = DI.document.querySelector(".bfm-icon");
  const signed = () => DI.__calls.filter(x => /\/url$/.test(x)).length;
  /* NAMED BEFORE → AFTER (Nov 8 2026, the music button). BEFORE: the icon at (212, 12), a small drawn boombox in the finish's tokens
     with a sheen, 40 x 36, named "Open music"; on a phone at (212, 12). AFTER: the music button at (400, 10), the note and its wave in
     currentColor, 40 x 40, named "Music player"; on a 390 px phone the space to the centre is too small, so it keeps 24 px from the
     logo: (224, 10). scripts/checkFinishingTouches.js pins the icon, the placement rule and the labels in full. */
  check("I3. the dashboard's first stage is the icon beside the logo (400, 10): the bar and the boombox are not shown, and no audio has started",
    DIR.getAttribute("data-state") === "icon" && DIR.getAttribute("data-home") === "true" && DIR.getAttribute("data-away") === "false" && spot(DI).join() === "400,10" &&
    css(icon).display === "block" && css(DI.document.querySelector(".bfm-tag")).display === "none" && css(DI.document.querySelector(".bbx")).display === "none" &&
    css(DI.document.querySelector(".bfm-drawer")).display === "none" && !DI.BFMusic.playing() && AUDIOS.filter(x => x.win === DI).every(a => a.plays === 0) && signed() === 0,
    DIR.getAttribute("data-state") + " " + spot(DI) + " " + css(icon).display);
  /* NAMED BEFORE → AFTER (Nov 9 2026, golden note icon). BEFORE: the note and its wave (.bfm-note-wave), the svg stroked
     currentColor. AFTER: the golden note (.bfm-gn-glow, .bfm-gn-spiral, .bfm-gn-stem), no colour of its own on the svg, no
     circle, no ellipse, no wave; scripts/checkFinishingTouches.js pins its exact paths and CSS. */
  check("I3. the icon is the music button: the golden note (its glow, spiral and stem), no colour of its own, no circles, named \"Music player\"",
    icon.tagName === "BUTTON" && icon.getAttribute("aria-label") === "Music player" && icon.getAttribute("title") === "Music player" &&
    !!icon.querySelector("svg.bfm-icon-art .bfm-gn-glow") && !!icon.querySelector("svg.bfm-icon-art .bfm-gn-spiral") && !!icon.querySelector("svg.bfm-icon-art .bfm-gn-stem") &&
    /* NAMED BEFORE → AFTER (Nov 9 2026, violet spiral per the approved design). BEFORE: a stroke attribute of currentColor
       was allowed in the markup. AFTER: the markup holds no colour at all (no stroke, color or style attribute, every fill
       "none"); the colours are the CSS's: the stem currentColor, the spiral and glow var(--bf-accent-b, #a855f7). */
    !icon.querySelector("circle,ellipse,.bfm-note-wave") && !icon.querySelector("[stroke],[color],[style],[fill]:not([fill=none])") &&
    DI.BFBoombox.ICON_W === 40 && DI.BFBoombox.ICON_H === 40);
  const PI3 = await openPage(Object.assign({}, base, { width: 390 }));
  check("I3. the icon is in place (pinned, never fixed or dragged), and on a phone it stays beside the logo, not docked",
    DIR.getAttribute("data-pinned") === "true" && css(DIR).position === "absolute" && boxOf(PI3).getAttribute("data-state") === "icon" &&
    boxOf(PI3).getAttribute("data-dock") === "desktop" && spot(PI3).join() === "224,10", boxOf(PI3).getAttribute("data-dock") + " " + spot(PI3));
  closeOne(PI3);

  /* I4. icon -> bar -> boombox, and back; Escape one stage at a time */
  click(DI, "[data-act=bbx-open]");
  const expand = DI.document.querySelector("[data-act=bbx-expand]");
  const s1 = DIR.getAttribute("data-state"), f1 = DI.document.activeElement === expand;
  DI.document.querySelector(".bfm-tag-title").dispatchEvent(new DI.MouseEvent("click", { bubbles: true }));
  const s2 = DIR.getAttribute("data-state"), f2 = DI.document.activeElement === DI.document.querySelector(".bbx-keys [data-act=toggle]");
  check("I4. the icon opens the bar (the focus on \"Open the boombox\"); a press on the bar opens the boombox (the focus on Play)",
    s1 === "tag" && f1 && s2 === "box" && f2 && css(DI.document.querySelector(".bbx")).display === "block" && css(DI.document.querySelector(".bfm-tag")).display === "none", s1 + " " + s2);
  key(DI, DI.document.activeElement, "Escape");
  const e1 = DIR.getAttribute("data-state"), ef1 = DI.document.activeElement === expand;
  key(DI, DI.document.activeElement, "Escape");
  const e2 = DIR.getAttribute("data-state"), ef2 = DI.document.activeElement === icon;
  key(DI, DI.document.activeElement, "Escape");
  check("I4. Escape steps back one stage at a time: the boombox to the bar (focus on Open the boombox), the bar to the icon (focus on the icon), and no further",
    e1 === "tag" && ef1 && e2 === "icon" && ef2 && DIR.getAttribute("data-state") === "icon", e1 + " " + e2);
  click(DI, "[data-act=bbx-open]"); click(DI, "[data-act=bbx-expand]"); click(DI, "[data-act=bbx-library]");
  key(DI, DI.document.querySelector("[data-act=bbx-library]"), "Escape");
  const libFirst = DIR.getAttribute("data-state") === "box" && DIR.getAttribute("data-library") === "false";
  click(DI, "[data-act=bbx-minimise]");
  const minTag = DIR.getAttribute("data-state") === "tag";
  key(DI, DI.document.querySelector(".bfm-tag"), "Enter");
  const enterBox = DIR.getAttribute("data-state") === "box";
  click(DI, ".bbx-fkeys [data-act=bbx-close]");
  const boxToIcon = DIR.getAttribute("data-state") === "icon";
  click(DI, "[data-act=bbx-open]"); click(DI, ".bfm-tag [data-act=bbx-close]");
  check("I4. with the library out, Escape slides it back first; Minimise steps back to the bar; Enter on the bar opens the boombox; \"Close to icon\" on the boombox's body and on the bar goes to the icon",
    libFirst && minTag && enterBox && boxToIcon && DIR.getAttribute("data-state") === "icon", [libFirst, minTag, enterBox, boxToIcon].join());
  // NAMED BEFORE → AFTER (Nov 8 2026, the music button). BEFORE: the icon named "Open music". AFTER: "Music player".
  const names = [["Music player", ".bfm-icon"], ["Open the boombox", ".bfm-tag [data-act=bbx-expand]"], ["Close to icon", ".bfm-tag [data-act=bbx-close]"],
    ["Close to icon", ".bbx-fkeys [data-act=bbx-close]"], ["Stop music", ".bfm-tag [data-act=stop]"], ["Stop music", ".bbx-keys [data-act=stop]"]];
  const misnamed = names.filter(([n, sel]) => { const el = DI.document.querySelector(sel); return !el || el.tagName !== "BUTTON" || el.getAttribute("aria-label") !== n || !el.querySelector("svg"); }).map(x => x[1]);
  check("I4. the accessible names: \"Music player\", \"Open the boombox\", \"Close to icon\" (the bar and the boombox), \"Stop music\" (the bar and the boombox), each a button with a drawn icon",
    misnamed.length === 0, misnamed.join(", "));

  /* I5. other pages: nothing without music; the bar or the boombox follows while it plays */
  await freshStage(db);
  const Q0 = await openPage(Object.assign({}, base, { page: "tasks.html" }));
  const quiet = !shown(Q0) && boxOf(Q0).getAttribute("data-away") === "true" && css(boxOf(Q0)).display === "none";
  gesture(Q0); Q0.BFMusic.playTrack(T1); await settle();
  check("I5. on a page other than the dashboard nothing shows without music; when music plays there, the bar appears",
    quiet && Q0.BFMusic.playing() && shown(Q0) && boxOf(Q0).getAttribute("data-state") === "tag" && Q0.sessionStorage.getItem("bf_music_live") === UID, quiet + " " + shown(Q0));
  click(Q0, "[data-act=bbx-expand]");
  Q0.BFMusic.seek(30);
  Q0.dispatchEvent(new Q0.Event("pagehide"));
  const leftQ = JSON.parse(Q0.localStorage.getItem("bf_music") || "{}"), prefsQ = prefsOf(Q0);
  Q0.BFMusic.pause(); closeOne(Q0);
  const Q1 = await openPage(Object.assign({}, base, { page: "crm.html", store: leftQ, boombox: prefsQ }));
  const atOnce = shown(Q1) && boxOf(Q1).getAttribute("data-state") === "box";
  for (let i = 0; i < 200 && !Q1.BFMusic.playing(); i++) await wait(5);
  check("I5. the next page, while the music carries on, shows the player at once at its last stage (the boombox), and it plays",
    atOnce && Q1.BFMusic.playing() && shown(Q1) && boxOf(Q1).getAttribute("data-state") === "box", atOnce + " " + Q1.BFMusic.playing());
  Q1.BFMusic.pause(); await settle();
  check("I5. paused mid-track in this session it stays", !Q1.BFMusic.playing() && shown(Q1) && Q1.BFMusic.musicOn());
  const Q2 = await openPage(Object.assign({}, base, { page: "tasks.html", store: { v: 1, uid: UID, track_id: T1, position: 40 } }));
  check("I5. ... but a track left paused in another session (no music this session) shows nothing", !shown(Q2) && !Q2.BFMusic.musicOn());
  closeOne(Q2);

  /* I6. Close to icon keeps the music and shows the equaliser; off the dashboard a floating icon keeps a stop within reach; Stop takes the player off the other pages
     NAMED pin change (Part 0, the music gap). BEFORE: "on another page, Close to icon keeps the music playing and the player
     leaves that page (the icon lives on the dashboard)", asserting !shown. AFTER: the floating icon stays on that page while the
     music is on, at the player's last position by the position rule; it opens the bar, whose Stop ends the music and the icon. */
  gesture(Q1); Q1.BFMusic.play(); await settle();
  const Q1R = boxOf(Q1), atPlayer = spot(Q1).join();
  click(Q1, ".bbx-fkeys [data-act=bbx-close]");
  /* NAMED BEFORE → AFTER (Nov 8 2026, the music button). BEFORE: the floating icon was the drawn boombox (#bbxIconBody) and, while
     music played, a four-bar equaliser (.bfm-icon-eq, bbx-icon-eq). AFTER: the music button, whose wave drifts (bfm-note-wave). */
  /* NAMED BEFORE → AFTER (Nov 9 2026, golden note icon). BEFORE: the button's wave drifted (bfm-note-wave). AFTER: its
     golden note's glow pulses (bfm-gn-pulse). */
  const fIcon = Q1.document.querySelector(".bfm-icon"), fWave = Q1.document.querySelector(".bfm-icon .bfm-gn-glow");
  check("I6. on another page, \"Close to icon\" while music plays keeps it playing and leaves a small floating icon, the music button with its glow pulsing",
    Q1.BFMusic.playing() && Q1R.getAttribute("data-state") === "icon" && shown(Q1) && css(fIcon).display === "block" && !!fWave &&
    Q1R.getAttribute("data-playing") === "true" && /bfm-gn-pulse/.test(css(fWave).animation),
    [Q1.BFMusic.playing(), Q1R.getAttribute("data-state"), shown(Q1), css(fIcon).display, fWave && css(fWave).animation].join(" "));
  check("I6. ... where the player was, by the Follow me rule: fixed on screen and not pinned",
    Q1R.getAttribute("data-pinned") === "false" && css(Q1R).position === "fixed" && spot(Q1).join() === atPlayer, Q1R.getAttribute("data-pinned") + " " + css(Q1R).position + " " + spot(Q1) + " vs " + atPlayer);
  click(Q1, ".bfm-icon");
  const fOpened = Q1R.getAttribute("data-state") === "tag" && shown(Q1) && !!Q1.document.querySelector(".bfm-tag [data-act=stop]");
  click(Q1, ".bfm-tag [data-act=stop]"); await settle();
  check("I6. ... pressed, it opens the bar, and the bar's \"Stop music\" stops the music and the player leaves that page",
    fOpened && !Q1.BFMusic.playing() && !shown(Q1), fOpened + " " + Q1.BFMusic.playing() + " " + shown(Q1));
  closeOne(Q1); await settle();
  const QF = await openPage(Object.assign({}, base, liveOn(T1, { page: "crm.html", boombox: { state: "icon" } })));
  QF.localStorage.setItem("bf_music", JSON.stringify(Object.assign(JSON.parse(QF.localStorage.getItem("bf_music") || "{}"), { placement: "pinned" })));
  QF.BFMusic.setPosition("pinned");
  gesture(QF); QF.BFMusic.play(); await settle();
  const QFR = boxOf(QF);
  const fPinned = shown(QF) && QFR.getAttribute("data-state") === "icon" && QFR.getAttribute("data-pinned") === "true" && css(QFR).position === "absolute";
  QF.BFMusic.stop(); await settle();
  check("I6. a page opened at the icon stage while music is on shows the floating icon, by the Pinned rule (absolute, in its home spot); when the music stops, it disappears",
    fPinned && !QF.BFMusic.playing() && !shown(QF), fPinned + " " + shown(QF));
  closeOne(QF); await settle();
  const DQ = await openPage(Object.assign({}, base, { boombox: { state: "tag" } }));
  gesture(DQ); DQ.BFMusic.playTrack(T2); await settle();
  click(DQ, ".bfm-tag [data-act=bbx-close]");
  // NAMED BEFORE → AFTER (Nov 8 2026, the music button). BEFORE: the icon's equaliser showed and went. AFTER: the button's wave drifts and stops.
  // NAMED BEFORE → AFTER (Nov 9 2026, golden note icon). BEFORE: the wave drifted (bfm-note-wave, translateX). AFTER: the glow pulses (bfm-gn-pulse, opacity).
  const eqWave = DQ.document.querySelector(".bfm-icon .bfm-gn-glow");
  check("I6. on the dashboard, \"Close to icon\" keeps the music playing and the music button's glow pulses",
    DQ.BFMusic.playing() && boxOf(DQ).getAttribute("data-state") === "icon" && boxOf(DQ).getAttribute("data-playing") === "true" && shown(DQ) &&
    !!eqWave && /bfm-gn-pulse/.test(css(eqWave).animation) && /@keyframes bfm-gn-pulse\{0%,100%\{opacity:\.22\}50%\{opacity:\.45\}\}/.test(BX),
    eqWave && css(eqWave).animation);
  DQ.BFMusic.pause(); await settle();
  check("I6. ... paused, the glow is still", !!eqWave && !/bfm-gn-pulse/.test(css(eqWave).animation || ""));
  click(DQ, "[data-act=bbx-open]");
  gesture(DQ); DQ.BFMusic.play(); await settle(); CLOCK.t += 1; await settle();
  click(DQ, ".bfm-tag [data-act=stop]"); await settle();
  check("I6. \"Stop music\" stops it, back to the start of the track, and ends this session's music (the dashboard keeps its bar)",
    !DQ.BFMusic.playing() && DQ.BFMusic.position() === 0 && DQ.sessionStorage.getItem("bf_music_live") === null && shown(DQ) && boxOf(DQ).getAttribute("data-state") === "tag");
  const QS = await openPage(Object.assign({}, base, { page: "tasks.html", store: JSON.parse(DQ.localStorage.getItem("bf_music")), boombox: prefsOf(DQ),
    live: DQ.sessionStorage.getItem("bf_music_live") === UID }));
  await wait(QS.BFMusic.RESUME_WAIT_MS + 100); await settle();
  check("I6. ... and after a stop the other pages show nothing", !shown(QS) && !QS.BFMusic.playing());
  closeOne(QS);
  const QP = await openPage(Object.assign({}, base, liveOn(T1, { page: "tasks.html", boombox: { state: "box" } })));
  gesture(QP); QP.BFMusic.play(); await settle();
  const before = shown(QP) && QP.BFMusic.playing();
  click(QP, ".bbx-keys [data-act=stop]"); await settle();
  check("I6. the boombox's own \"Stop music\" on another page stops it and the player leaves that page", before && !QP.BFMusic.playing() && !shown(QP), before + " " + shown(QP));
  closeOne(QP);

  /* I7. the stage is remembered: on this device, and on the account for a new device */
  click(DQ, "[data-act=bbx-expand]");
  await wait((DQ.BFMusic.PLAYER_SAVE_MS || 600) + 200); await settle();
  const rowS = (db.T.user_preferences || []).find(r => r.user_id === UID);
  check("I7. the stage is remembered on this device (bf_boombox) and on the account (user_preferences.music_player.stage)",
    prefsOf(DQ).state === "box" && !!rowS && rowS.music_player.stage === "box", JSON.stringify([prefsOf(DQ), rowS && rowS.music_player]));
  const DN = await openPage(base);
  await settle(20);
  const DN2 = await openPage(Object.assign({}, base, { boombox: { state: "icon" } }));
  await settle(20);
  check("I7. a new device adopts the account's stage (the boombox); a device's own remembered stage wins over it (the icon)",
    boxOf(DN).getAttribute("data-state") === "box" && boxOf(DN2).getAttribute("data-state") === "icon", boxOf(DN).getAttribute("data-state") + " " + boxOf(DN2).getAttribute("data-state"));
  closeOne(DN); closeOne(DN2);

  /* I8. Position: Follow me / Pinned */
  click(DQ, "[data-act=bbx-minimise]");
  const DR = boxOf(DQ);
  const followFixed = css(DR).position === "fixed" && DR.getAttribute("data-pinned") === "false";
  const pick = DQ.document.querySelector(".bfm-position-pick[value=pinned]");
  pick.checked = true; pick.dispatchEvent(new DQ.Event("change", { bubbles: true }));
  const pinnedNow = DR.getAttribute("data-pinned") === "true" && DR.getAttribute("data-position") === "pinned" && css(DR).position === "absolute";
  const reset = DQ.document.querySelector("[data-act=bbx-reset]");
  const was = spot(DQ).join();
  const grab = DQ.document.querySelector(".bfm-tag-title");
  ptr(DQ, grab, "pointerdown", 100, 100); ptr(DQ, grab, "pointermove", 400, 400); ptr(DQ, grab, "pointerup", 400, 400);
  const tagEl = DQ.document.querySelector(".bfm-tag"); tagEl.focus(); key(DQ, tagEl, "ArrowRight");
  const still = spot(DQ).join() === was && !("left" in prefsOf(DQ));
  try { Object.defineProperty(DQ, "scrollY", { configurable: true, get: () => 300 }); Object.defineProperty(DQ, "pageYOffset", { configurable: true, get: () => 300 }); } catch (e) { /* fixed */ }
  DQ.BFMusic._box().place();
  const scrolled = spot(DQ).join();
  check("I8. Follow me is fixed on screen; Pinned is not fixed (position: absolute), sits in its home spot beside the logo and scrolls with the page (300 px down it is 310, in the page)",
    followFixed && pinnedNow && was === "212,10" && scrolled === "212,310", [followFixed, pinnedNow, was, scrolled].join(" "));
  check("I8. pinned it cannot be dragged or nudged by the keys, and \"Reset position\" is hidden",
    still && reset.hidden === true && css(reset).display === "none", still + " " + reset.hidden);
  click(DQ, "[data-act=bbx-expand]");
  check("I8. it applies to the boombox too: pinned, absolute, in its home spot", DR.getAttribute("data-state") === "box" && css(DR).position === "absolute" && spot(DQ).join() === "212,310");
  try { Object.defineProperty(DQ, "scrollY", { configurable: true, get: () => 0 }); Object.defineProperty(DQ, "pageYOffset", { configurable: true, get: () => 0 }); } catch (e) { /* fixed */ }
  await wait((DQ.BFMusic.PLAYER_SAVE_MS || 600) + 200); await settle();
  const rowP = (db.T.user_preferences || []).find(r => r.user_id === UID);
  check("I8. the position is saved on this device (bf_music) and on the account (PUT /api/music/player)",
    JSON.parse(DQ.localStorage.getItem("bf_music")).placement === "pinned" && rowP.music_player.position === "pinned", JSON.stringify(rowP && rowP.music_player));
  const PN = await openPage(Object.assign({}, base, { boombox: { state: "tag" } }));
  await settle(20);
  check("I8. ... and restored: a new device adopts Pinned from the account, and its panel shows it",
    boxOf(PN).getAttribute("data-pinned") === "true" && css(boxOf(PN)).position === "absolute" && PN.document.querySelector(".bfm-position-pick[value=pinned]").checked);
  closeOne(PN);
  const SETPOS = (/<div class="ts-choices" id="bfmPositionSetting"[\s\S]*?<\/div>/.exec(FILES[SETTINGS] || "") || [""])[0];
  const SP = await openPage(Object.assign({}, base, liveOn(T1, { page: "settings.html", extra: SETPOS, boombox: { state: "tag" } })));
  await settle(20);
  const shownPinned = SP.document.querySelector("#bfmPositionSetting input[value=pinned]").checked;
  const fol = SP.document.querySelector("#bfmPositionSetting input[value=follow]");
  fol.checked = true; fol.dispatchEvent(new SP.Event("change", { bubbles: true }));
  const spR = boxOf(SP);
  const dragFrom = spot(SP).join();
  const g2 = SP.document.querySelector(".bfm-tag-title");
  ptr(SP, g2, "pointerdown", 100, 100); ptr(SP, g2, "pointermove", 200, 150); ptr(SP, g2, "pointerup", 200, 150);
  check("I8. Settings → Theme → Music has \"Music player position: Follow me / Pinned\", showing the member's and changing it; Follow me is fixed and draggable again",
    !!SETPOS && /role="radiogroup"/.test(SETPOS) && /Music player position/.test(SETPOS) && /> Follow me</.test(SETPOS) && /> Pinned</.test(SETPOS) && shownPinned &&
    SP.BFMusic.state().placement === "follow" && spR.getAttribute("data-pinned") === "false" && css(spR).position === "fixed" && spot(SP).join() !== dragFrom &&
    !SP.document.querySelector("[data-act=bbx-reset]").hidden && SP.document.querySelector(".bfm-position-pick[value=follow]").checked,
    dragFrom + " " + spot(SP) + " " + shownPinned);
  const posAfter = (FILES[SETTINGS] || "").indexOf('id="bfmPositionSetting"') > (FILES[SETTINGS] || "").indexOf('id="bfmFinishSetting"');
  check("I8. ... beside the finish, in the music settings", posAfter);
  closeOne(SP);
  const put = body => callRoute(lifted, "put", "/api/music/player", body);
  const okP = await put({ position: "pinned", stage: "icon" });
  const badP = await Promise.all([{ position: "glued" }, { position: 1 }, { stage: "huge" }, { stage: null }, { position: "follow", place: "x" }].map(put));
  const keep = await callRoute(lifted, "get", "/api/music/player");
  check("I8. the server validates them: \"follow\" or \"pinned\", \"icon\", \"tag\" or \"box\"; anything else is a 400 with its field, and changes nothing",
    okP.status === 200 && okP.body.player.position === "pinned" && okP.body.player.stage === "icon" &&
    badP.every(r => r.status === 400 && typeof r.body.error === "string") && badP[0].body.field === "position" && badP[1].body.field === "position" &&
    badP[2].body.field === "stage" && badP[3].body.field === "stage" && badP[4].body.field === "place" && badP[0].body.error === "The position is follow or pinned." &&
    keep.body.player.position === "pinned" && keep.body.player.stage === "icon", JSON.stringify(badP.map(r => r.status + ":" + r.body.field)));
  const v0 = M.playerSettings({ position: "pinned" }, { finish: "black", eq: { bass: 2 } });
  check("I8. lib/music.js playerSettings: a position alone keeps the saved finish and EQ",
    !v0.error && v0.value.finish === "black" && v0.value.eq.bass === 2 && v0.value.position === "pinned" && v0.value.stage === null, JSON.stringify(v0));
  await put({ position: "follow" });
  closeOne(DQ); closeOne(DI);

  /* I9. no emoji in anything new */
  const EMO = /[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}\u{200D}\u{20E3}]/u;
  check("I9. no emoji in the icon, the bar, the boombox, the position setting or the guide", !EMO.test(BX + FILES[MUSIC] + SETPOS + FILES[GUIDE]));
}

/* ── G1/G2, live order: the real page files, their scripts run as a browser runs them ──
   NAMED BEFORE → AFTER (Oct 31 2026, "The boombox always appears"). BEFORE: G1 and G2 built a test page of
   their own, with the mist's tag BEFORE the boombox and the player, and evaluated those scripts after it. The
   live dashboard lists bf-music.js BEFORE termaximus-presence.js; bf-music.js decided its mode as it ran,
   found no mist tag yet, stepped aside silently, and no boombox ever appeared, while G1 and G2 passed.
   AFTER: these checks open the REAL page files. Each script tag runs as the browser runs it: at its own
   place while the page is parsed, before the tags after it exist (jsdom does not block its parser on an
   external script, so each one is inlined there and given its real src as it starts), and a script added
   later (bf-session.js loading the player at DOMContentLoaded) is served by its real URL and runs when it
   arrives, after the page is parsed. The API answers as live does: at once with an empty library, never
   (slow), with an error, with the 503 of a library not set up yet; and with no BroadcastChannel. */
/* The server's 503 for a library not set up yet (G11 holds the route to it). */
const LIVE_NOT_SET_UP = "Music isn't set up yet on the server (migration 155). Nothing is lost.";
function frontText(rel) {
  const key = "F:" + rel;
  return FILES[key] !== undefined && FILES[key] !== null ? lf(FILES[key]) : lf(fs.readFileSync(path.join(FRONTEND, rel), "utf8"));
}
function livePage(file, o) {
  o = o || {};
  const { requestInterceptor, VirtualConsole } = require("jsdom");
  const script = rel => o.serve && o.serve[rel] !== undefined ? o.serve[rel] : frontText(rel);
  let html = frontText(file);
  if (o.dropMusicTag) html = html.split('<script src="/scripts/bf-music.js"></script>').join("");
  html = html.replace(/<script src="(\/scripts\/[a-z0-9-]+\.js)"([^>]*)><\/script>/g, (m, src, attrs) =>
    "<script" + attrs + ">document.currentScript.setAttribute(\"src\", " + JSON.stringify(src) + ");\n" +
    script(src.slice(1)).replace(/<\/script/gi, "<\\/script") + "\n</script>");
  const warns = [];
  const vc = new VirtualConsole();
  vc.on("warn", (...a) => warns.push(a.join(" ")));
  const served = [];
  const dom = new JSDOM(html, {
    url: "https://bizforceai.net/" + file.replace(/\.html$/, ""), runScripts: "dangerously", pretendToBeVisual: true, virtualConsole: vc,
    resources: { interceptors: [requestInterceptor(request => {
      const u = new URL(request.url);
      if (u.origin === "https://bizforceai.net" && /^\/scripts\/[a-z0-9-]+\.js$/.test(u.pathname) && fs.existsSync(path.join(FRONTEND, u.pathname))) {
        served.push(u.pathname);
        return new Response(script(u.pathname.slice(1)), { headers: { "Content-Type": "application/javascript" } });
      }
      return new Response("", { status: 404 });
    })] },
    beforeParse(win) {
      win.localStorage.setItem("bf_token", TOKEN);
      win.matchMedia = q => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} });
      win.AudioContext = FakeAudioContext; win.Audio = makeFakeAudio(win);
      win.BroadcastChannel = o.noChannel ? undefined : class extends FakeBC { constructor(n) { super(n); this.win = win; } };
      win.requestAnimationFrame = () => 0; win.cancelAnimationFrame = () => {};
      win.HTMLCanvasElement.prototype.getContext = () => null;
      win.scrollTo = () => {};
      win.fetch = u => {
        const url = String(u);
        if (/\/api\/music$/.test(url)) {
          if (o.api === "slow") return new Promise(() => {});
          if (o.api === "error") return Promise.resolve({ ok: false, status: 500, json: async () => ({ error: "Internal server error" }) });
          if (o.api === "503") return Promise.resolve({ ok: false, status: 503, json: async () => ({ error: LIVE_NOT_SET_UP, reason: "music_not_set_up" }) });
          return Promise.resolve({ ok: true, status: 200, json: async () => ({ tracks: [], playlists: [], bytes_used: 0, caps: { file_bytes: 26214400, total_bytes: 262144000, playlists: 50 } }) });
        }
        return Promise.resolve({ ok: true, status: 200, json: async () => ({}), text: async () => "{}" });
      };
    }
  });
  return { w: dom.window, warns, served, dom };
}
async function untilBox(w, ms) {
  for (let t = 0; t < ms; t += 25) {
    if (w.document.querySelector(".bfm-float .bbx") || w.document.getElementById("bfmFail")) break;
    await wait(25);
  }
  return w.document.querySelector(".bfm-float .bbx");
}
async function liveOrderChecks() {
  console.log("\n══ G1/G2, live order: the real page files, their scripts in their real order ══");
  const dash = frontText("dashboard.html");
  check("G2. live order: the dashboard lists bf-music.js before termaximus-presence.js (the order the live page runs them in), so the player must not depend on it",
    dash.indexOf('<script src="/scripts/bf-music.js"></script>') !== -1 && dash.indexOf('<script src="/scripts/bf-music.js"></script>') < dash.indexOf('<script src="/scripts/termaximus-presence.js"></script>'));
  const scenarios = [["the API answers at once (an empty library)", {}], ["the API never answers (slow)", { api: "slow" }], ["the API errors (500)", { api: "error" }],
    ["the library is not set up (503)", { api: "503" }], ["no BroadcastChannel", { noChannel: true }]];
  for (const [what, o] of scenarios) {
    const p = livePage("dashboard.html", o);
    const box = await untilBox(p.w, 3000);
    const anchor = p.w.document.querySelector("[data-bf-boombox-anchor]");
    /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: drawn as the boombox. AFTER: drawn, and shown as the bar beside the logo.
       NAMED BEFORE → AFTER (Oct 31 2026, three stages). BEFORE: shown as the bar. AFTER: shown as the icon beside the logo (the first visit).
       NAMED BEFORE → AFTER (Nov 8 2026, the music button). BEFORE: the icon named "Open music". AFTER: named "Music player". */
    const fl = box && box.closest(".bfm-float");
    check("G2. live order, the real dashboard, " + what + ": the boombox is drawn, shown as the icon beside the logo, with no warning",
      !!box && !!anchor && p.w.BFMusic && p.w.BFMusic.mode === "float" && fl.getAttribute("data-state") === "icon" && fl.getAttribute("data-away") === "false" &&
      fl.getAttribute("data-home") === "true" && !!fl.querySelector(".bfm-icon[aria-label='Music player']") &&
      !p.w.document.getElementById("bfmFail") && p.warns.filter(x => /\[boombox\]/.test(x)).length === 0,
      JSON.stringify({ box: !!box, mode: p.w.BFMusic && p.w.BFMusic.mode, bbx: p.w.document.querySelectorAll("[class*=bbx]").length, warns: p.warns.slice(0, 2) }));
    if (o.api === "503") {
      await wait(50);
      const msg = p.w.document.querySelector(".bfm-msg");
      check("G2. ... and with the library not set up it says so inside the boombox", !!msg && msg.textContent === LIVE_NOT_SET_UP, msg && msg.textContent);
    }
    p.w.close();
  }
  // a player that arrives after the page has loaded (readyState complete)
  const late = livePage("dashboard.html", { dropMusicTag: true });
  await wait(30);
  const lateState = late.w.document.readyState;
  const s = late.w.document.createElement("script");
  s.src = "/scripts/bf-music.js";
  late.w.document.body.appendChild(s);
  const lateBox = await untilBox(late.w, 3000);
  check("G2. live order: bf-music.js arriving after the page has loaded (readyState " + lateState + ") still draws the boombox", lateState === "complete" && !!lateBox,
    lateState + " " + !!lateBox);
  late.w.close();
  // a start that fails says so: a warning and a small tag, never nothing
  const broken = livePage("dashboard.html", { serve: { "scripts/bf-boombox.js": "window.BFBoombox = { mount: function () { throw new Error(\"the drawing failed\"); } };" } });
  await untilBox(broken.w, 3000);
  const tag = broken.w.document.getElementById("bfmFail");
  check("G2. live order: a boombox that cannot start warns \"[boombox] ...\" in the console and shows a small \"Music couldn't start — reload\" tag",
    !!tag && tag.textContent === "Music couldn't start — reload" && broken.warns.some(x => /^\[boombox\] Music couldn't start — reload: the drawing failed/.test(x)),
    JSON.stringify({ tag: tag && tag.textContent, warns: broken.warns.slice(0, 2) }));
  broken.w.close();
  // every signed-in mist page, as the real file loads it
  const pages = fs.readdirSync(FRONTEND).filter(f => /\.html$/.test(f)).sort()
    .concat(fs.readdirSync(path.join(FRONTEND, "agents")).filter(f => /\.html$/.test(f)).sort().map(f => "agents/" + f));
  const UNTH = (/var UNTHEMED = \[([\s\S]*?)\]/.exec(FILES[THEME]) || ["", ""])[1].match(/"[^"]+"/g).map(x => JSON.parse(x));
  const signedIn = pages.filter(f => {
    const h = frontText(f);
    return /<script src="\/scripts\/termaximus-presence\.js"><\/script>/.test(h) && UNTH.indexOf(f.replace(/^agents\//, "")) === -1 && f !== "music-popout.html" &&
      (/<script src="\/scripts\/bf-session\.js"><\/script>/.test(h) || /<script src="\/scripts\/bf-session\.js" data-clear-only data-music><\/script>/.test(h));
  });
  const missing = [];
  for (let i = 0; i < signedIn.length; i += 6) {
    const batch = signedIn.slice(i, i + 6);
    const opened = batch.map(f => ({ f, p: livePage(f, {}) }));
    for (const x of opened) { if (!(await untilBox(x.p.w, 4000))) missing.push(x.f); }
    opened.forEach(x => x.p.w.close());
  }
  check("G1. live order: on every signed-in mist page, the real file loaded as the browser loads it, the boombox is drawn (" + signedIn.length + " pages, the 7 agents/ pages among them)",
    // NAMED (Nov 4 2026, the Media Library): BEFORE 54 live pages; AFTER 55, with media.html.
    // NAMED (Nov 5 2026, mailbox connection): BEFORE 55 live pages; AFTER 56, with mailbox.html.
    missing.length === 0 && signedIn.length === 56 && signedIn.indexOf("media.html") !== -1 && signedIn.indexOf("mailbox.html") !== -1 && signedIn.filter(f => /^agents\//.test(f)).length === 7, missing.join(", ") + " | " + signedIn.length);
}

/* ── G13. now playing ───────────────────────────────────────────────────── */
const vfdText = w => { const c = w.document.querySelector(".bbx-scroll .bbx-vfd-copy"); return c ? c.textContent : null; };
const tickerText = w => { const c = w.document.querySelector(".bbx-ticker-track .bbx-ticker-text"); return c ? c.textContent : null; };
async function nowPlayingChecks(c) {
  console.log("\n══ G13. now playing: the VFD, the LED ticker, the sweep, the tag ══");
  const { base, add, T1, T2 } = c;
  /* The CSS as the page has it: bf-boombox.js builds some rules from its constants. */
  const N = await openPage(Object.assign({}, base, { page: "tasks.html" }));
  const nb = N.BFMusic._box(), root = boxOf(N), bbx = N.document.querySelector(".bbx");
  const q1 = s => N.document.querySelector(s);
  const BX = (N.document.getElementById("bf-boombox-style") || {}).textContent || "";
  /* nothing loaded */
  nb.render({});
  check("G13. with nothing loaded the VFD and the ticker say \"No track loaded\", nothing scrolls, nothing is announced",
    vfdText(N) === "No track loaded" && tickerText(N) === "No track loaded" && q1(".bbx-marquee").getAttribute("data-scroll") === "false" &&
    q1(".bbx-ticker").getAttribute("data-scroll") === "false" && N.document.querySelectorAll(".bbx-scroll .bbx-vfd-copy").length === 1 &&
    N.document.querySelectorAll(".bbx-ticker-text").length === 1 && q1(".bfm-live").textContent === "" && q1(".bfm-tag-title").textContent === "No track loaded",
    vfdText(N) + " | " + tickerText(N));
  /* a track, from the real player */
  const lib = N.BFMusic.library().tracks.map(t => t.id);
  gesture(N); N.BFMusic.playTrack(T1); await settle();
  const one = N.BFMusic.library().tracks.find(t => t.id === T1);
  const pos = lib.indexOf(T1) + 1, tot = lib.length;
  const two = n => (n < 10 ? "0" : "") + n;
  check("G13. the VFD scrolls \"Title — Artist\" while a track is loaded: two copies, the second hidden from screen readers",
    vfdText(N) === one.title + " — Artist" && q1(".bbx-marquee").getAttribute("data-scroll") === "true" &&
    N.document.querySelectorAll(".bbx-scroll .bbx-vfd-copy").length === 2 && N.document.querySelectorAll(".bbx-scroll .bbx-vfd-copy")[1].getAttribute("aria-hidden") === "true" &&
    q1(".bbx-marquee").getAttribute("title") === one.title + " — Artist", vfdText(N));
  const secs = parseFloat(q1(".bbx-scroll").style.getPropertyValue("--bbx-scroll-s"));
  const line = one.title + " — Artist", hold = 0.12;
  const rate = line.length / (secs * (1 - hold));
  check("G13. at a readable pace (at most 6 characters a second, at least 6 s a loop), holding still at the start of each loop (0% to 12%), by transform only",
    secs >= 6 && rate <= 6 && /@keyframes bbx-loop\{0%,12%\{transform:translateX\(0\)\}100%\{transform:translateX\(-50%\)\}\}/.test(BX) &&
    /\.bbx-marquee\[data-scroll=true\] \.bbx-scroll\{display:inline-block;animation:bbx-loop var\(--bbx-scroll-s, 10s\) linear infinite\}/.test(BX) &&
    /color:var\(--bf-accent-a, #22d3ee\);text-shadow:0 0 2px currentColor,0 0 6px rgba\(var\(--bf-accent-a-rgb/.test(BX), secs + "s " + rate.toFixed(2));
  const longT = "x".repeat(150);
  nb.render({ title: longT, artist: "A" });
  const lsecs = parseFloat(q1(".bbx-scroll").style.getPropertyValue("--bbx-scroll-s"));
  const lrate = (longT + " — A").length / (lsecs * (1 - hold));
  check("G13. a long line keeps the same readable pace (" + lrate.toFixed(1) + " characters a second)", lrate >= 3 && lrate <= 6, lsecs);
  N.BFMusic.pause(); await settle(); gesture(N); N.BFMusic.play(); await settle();
  check("G13. the LED ticker sits along the top under the handle and reads \"NN / TT · Title · Artist · Playlist name\" (" + tickerText(N) + ")",
    tickerText(N) === two(pos) + " / " + two(tot) + " · " + one.title + " · Artist · All tracks" && q1(".bbx-ticker").getAttribute("aria-hidden") === "true" &&
    q1(".bbx-ticker").getAttribute("data-scroll") === "true" && N.document.querySelectorAll(".bbx-ticker-text").length === 2 &&
    /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). BEFORE: left 36, top 26, 242 x 9 on the 320 face. AFTER: left 146, top 32, 148 x 10 on the 440 face, between the speakers. */
    /\.bbx-ticker\{position:absolute;left:146px;top:32px;width:148px;height:10px;/.test(BX) && /\.bbx-ticker::after\{[^}]*background-size:2px 2px\}/.test(BX), tickerText(N));
  const pl = N.BFMusic.library().playlists.find(p => (p.track_ids || []).indexOf(T2) !== -1 && (p.track_ids || []).length > 1);
  if (pl) {
    N.BFMusic.choosePlaylist(pl.id); await settle(); N.BFMusic.playTrack(T2); await settle();
    const ids = N.BFMusic.state().queue, at = ids.indexOf(T2) + 1;
    check("G13. on a playlist the ticker counts that queue and names it (" + tickerText(N) + ")",
      tickerText(N) === two(at) + " / " + two(ids.length) + " · " + N.BFMusic.library().tracks.find(t => t.id === T2).title + " · Artist · " + pl.name, tickerText(N));
    N.BFMusic.choosePlaylist(""); await settle();
  } else check("G13. a playlist with T2 and one more track exists to test the ticker's playlist name", false);
  /* the sweep */
  const s0 = nb.sweeps();
  N.BFMusic.playTrack(T1); await settle();
  check("G13. a new track starts the neon \"Now playing\" sweep across the face, once", nb.sweeps() === s0 + 1 && bbx.getAttribute("data-sweep") === "on" &&
    q1(".bbx-sweep").textContent === "Now playing" && q1(".bbx-sweep").getAttribute("aria-hidden") === "true" &&
    /\.bbx\[data-sweep=on\] \.bbx-sweep\{animation:bbx-sweep 1\.2s cubic-bezier\(\.3,\.6,\.4,1\) 1 both\}/.test(BX) &&
    /@keyframes bbx-sweep\{0%\{transform:translateX\(-150%\);opacity:0\}18%\{opacity:1\}82%\{opacity:1\}100%\{transform:translateX\(150%\);opacity:0\}\}/.test(BX) &&
    /\.bbx\[data-sweep=on\] \.bbx-ticker\{opacity:0\}/.test(BX), nb.sweeps() - s0);
  N.BFMusic.pause(); await settle(); gesture(N); N.BFMusic.play(); await settle();
  N.BFMusic.pause(); await settle(); gesture(N); N.BFMusic.toggle(); await settle(); N.BFMusic.seek(20); await settle();
  check("G13. a pause and a resume (twice), and a seek, start no sweep", nb.sweeps() === s0 + 1 && N.BFMusic.playing(), nb.sweeps() - s0);
  await wait(N.BFBoombox.SWEEP_MS + 150);
  check("G13. after about 1.2 s the sweep is done and the ticker settles in (opacity only)", bbx.getAttribute("data-sweep") === "done" &&
    /\.bbx\[data-sweep=done\] \.bbx-ticker\{animation:bbx-settle \.45s ease-out 1 both\}/.test(BX) && /@keyframes bbx-settle\{from\{opacity:0\}to\{opacity:1\}\}/.test(BX) && N.BFBoombox.SWEEP_MS === 1200);
  N.BFMusic.next(); await settle();
  check("G13. Next is a new track: one more sweep", nb.sweeps() === s0 + 2);
  /* the announcement, once per track */
  const live = q1(".bfm-live");
  const said = live.textContent;
  live.textContent = "MARK";
  N.BFMusic.pause(); await settle(); gesture(N); N.BFMusic.play(); await settle(); N.BFMusic.seek(5); await settle(); N.BFMusic.setVolume(0.3); await settle();
  check("G13. the announcement is made once per track: a pause, a resume, a seek or a volume change never repeats it, and the scrolling copies are not live",
    live.textContent === "MARK" && /^Now playing: .+ by Artist$/.test(said) && !q1(".bbx-marquee").closest("[aria-live]") && !q1(".bbx-ticker").closest("[aria-live]"), said);
  N.BFMusic.next(); await settle();
  check("G13. ... and the next track is announced", /^Now playing: .+ by Artist$/.test(live.textContent) && live.textContent !== "MARK", live.textContent);
  /* the tag's marquee */
  nb.setState("tag");
  nb.render({ title: "One", artist: "Artist", tagText: "One" });
  const clip = q1(".bfm-tag-clip");
  check("G13. a short title on the minimised tag does not scroll", clip.getAttribute("data-overflow") === "false" && !q1(".bfm-tag-ghost") && q1(".bfm-tag-title").textContent === "One");
  const long = "A Title Much Longer Than The Minimised Tag Can Hold";
  nb.render({ title: long, artist: "Artist", tagText: long });
  check("G13. a title longer than the tag scrolls as a marquee: a second copy hidden from screen readers, the whole title as the tooltip",
    clip.getAttribute("data-overflow") === "true" && !!q1(".bfm-tag-ghost") && q1(".bfm-tag-ghost").getAttribute("aria-hidden") === "true" &&
    q1(".bfm-tag-title").textContent === long && clip.getAttribute("title") === long &&
    /\.bfm-tag-clip\[data-overflow=true\] \.bfm-tag-scroll\{display:inline-block;animation:bbx-loop/.test(BX));
  /* measured where the tag is laid out */
  Object.defineProperty(clip, "clientWidth", { configurable: true, get: () => 160 });
  const tt = q1(".bfm-tag-title");
  tt.getBoundingClientRect = () => ({ width: 120 + (clip.getAttribute("data-overflow") === "true" ? 28 : 0) });
  nb.render({ title: long, artist: "Artist", tagText: long });
  const fits = clip.getAttribute("data-overflow") === "false" && !q1(".bfm-tag-ghost");
  tt.getBoundingClientRect = () => ({ width: 260 + (clip.getAttribute("data-overflow") === "true" ? 28 : 0) });
  nb.render({ title: long + ".", artist: "Artist", tagText: long + "." });
  check("G13. laid out, the tag is measured: 120 px of title in 160 px stays still, 260 px scrolls", fits && clip.getAttribute("data-overflow") === "true");
  nb.setState("box");
  /* hidden */
  setHidden(N, true);
  /* NAMED BEFORE → AFTER (Oct 31 2026, the boombox-mixer). the hidden rule also pauses the sheens (see G7). */
  check("G13. while the tab is hidden every scrolling part, the sweep and the sheens are paused", root.getAttribute("data-hidden") === "true" &&
    /\.bfm\[data-hidden=true\] \.bbx-scroll,\.bfm\[data-hidden=true\] \.bbx-ticker-track,\.bfm\[data-hidden=true\] \.bfm-tag-scroll,\.bfm\[data-hidden=true\] \.bbx-sweep,\.bfm\[data-hidden=true\] \.bbx-sheen,\.bfm\[data-hidden=true\] \.bbx-rim-shine,\.bfm\[data-hidden=true\] \.bfm-tag-sheen\{animation-play-state:paused\}/.test(BX));
  setHidden(N, false);
  N.BFMusic.pause(); await settle();
  /* the next page carries on: no sweep */
  const left = JSON.parse(JSON.stringify(Object.assign({}, N.BFMusic.state(), { was_playing: true })));
  closeOne(N);
  const P = await openPage(Object.assign({}, base, { page: "tasks.html", store: left }));
  const t0 = Date.now();
  while (!P.BFMusic.playing() && Date.now() - t0 < 2000) await wait(20);
  check("G13. when the next page carries the track on, no sweep runs: it is not a new track", P.BFMusic.playing() && P.BFMusic._box().sweeps() === 0 &&
    P.document.querySelector(".bbx").getAttribute("data-sweep") === "off", P.BFMusic._box().sweeps());
  P.BFMusic.next(); await settle();
  check("G13. ... and the next new track there sweeps", P.BFMusic._box().sweeps() === 1);
  P.BFMusic.pause(); await settle(); closeOne(P);
}
/* Under reduced motion: still, an ellipsis, the whole line as the tooltip, no sweep. */
async function nowPlayingReducedChecks(RM, track) {
  const q1 = s => RM.document.querySelector(s), bx = RM.BFMusic._box();
  const t = RM.BFMusic.library().tracks.find(x => x.id === track);
  RM.BFMusic.next(); await settle();
  const now = RM.BFMusic.library().tracks.find(x => x.id === RM.BFMusic.state().track_id);
  check("G13. under reduced motion the VFD and the ticker hold still: one copy each, cut short with an ellipsis, the whole line as the tooltip",
    q1(".bbx-marquee").getAttribute("data-scroll") === "false" && q1(".bbx-ticker").getAttribute("data-scroll") === "false" &&
    RM.document.querySelectorAll(".bbx-scroll .bbx-vfd-copy").length === 1 && RM.document.querySelectorAll(".bbx-ticker-text").length === 1 &&
    q1(".bbx-marquee").getAttribute("title") === now.title + " — Artist" && / · Artist · All tracks$/.test(q1(".bbx-ticker").getAttribute("title")) &&
    /\.bbx-marquee\{position:relative;height:12px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;/.test(FILES[BOOMBOX]), q1(".bbx-ticker").getAttribute("title"));
  bx.setState("tag");
  bx.render({ title: "A Title Much Longer Than The Minimised Tag Can Hold", artist: "Artist", tagText: "A Title Much Longer Than The Minimised Tag Can Hold" });
  check("G13. ... the tag's long title does not scroll either, and no sweep has run", q1(".bfm-tag-clip").getAttribute("data-overflow") === "false" && !q1(".bfm-tag-ghost") &&
    q1(".bfm-tag-clip").getAttribute("title") === "A Title Much Longer Than The Minimised Tag Can Hold" && bx.sweeps() === 0 && q1(".bbx").getAttribute("data-sweep") === "off", t && t.title);
  bx.setState("box");
}

function legalPages_musicText() { const lp = require("../lib/legalPages"); return lp.musicTerms().join(" ") + " " + lp.musicPrivacySentence(); }
function masterGain(w) { const m = w.BFMusic._master(); return m ? m.gain.value : NaN; }

function finish() {
  closeAll();
  console.log("\n" + passes + " passed, " + failures + " failed");
  console.log(failures === 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED");
  process.exit(failures === 0 ? 0 : 1);
}
