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
  // the missing tables shown as "Internal server error"
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
  MUSIC, THEME, SESSION, STUDIO, DASH, POPOUT, SETTINGS, TERMS, PRIVACY, GUIDE, BOOMBOX, PRESENCE].forEach(readInto);
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
  check("A12. all " + musicRoutes.length + " music routes (list, upload, rename, delete, URL, playlists create, change, delete) require sign-in first and are rate-limited",
    musicRoutes.length === 8 && musicRoutes.every(x => x.mw[0] === lifted.requireAuth && x.mw.slice(1).some(f => f.__limiter)));

  const sql = FILES[MIGRATION] || "";
  const migNames = fs.readdirSync(path.join(REPO, "supabase", "migrations"));
  const nums = migNames.map(n => Number((/^(\d+)_/.exec(n) || [])[1])).filter(n => n);
  check("A13. migration 155_member_music.sql is the next free number, and the only 155", !!FILES[MIGRATION] && migNames.filter(n => /^155_/.test(n)).length === 1 && Math.max.apply(null, nums) === 155 &&
    nums.filter(n => n === 154).length >= 1);
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
const SPECTRUM = { level: 0 };
class FakeAudioContext {
  constructor() { this.sampleRate = 48000; this.state = "running"; this.destination = {}; }
  get currentTime() { return CLOCK.t; }
  createGain() { return { gain: new FakeParam(1), connect() {} }; }
  createAnalyser() {
    return { fftSize: 2048, get frequencyBinCount() { return this.fftSize / 2; }, smoothingTimeConstant: 0, connect() {},
      getByteFrequencyData(a) { for (let i = 0; i < a.length; i++) a[i] = i < 8 ? SPECTRUM.level : Math.round(SPECTRUM.level / 3); },
      getByteTimeDomainData(a) { a.fill(128); } };
  }
  createMediaElementSource(el) { return { el, connect() {} }; }
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
   boombox's own state (the tag 290 x 40, the boombox 320 x 176, with the
   library 320 x 484), and places from the inline left and top. */
const MIST_TAG = '<script src="/scripts/termaximus-presence.js"></script>';
function layoutStub(win) {
  const HE = win.HTMLElement.prototype;
  const size = el => {
    const ds = el.getAttribute && el.getAttribute("data-size");
    if (ds) { const [sw, sh] = ds.split("x").map(Number); return { w: sw, h: sh }; }
    if (el.classList && el.classList.contains("bfm-float")) {
      const box = el.getAttribute("data-state") === "box", lib = el.getAttribute("data-library") === "true";
      return box ? { w: 320, h: lib ? 484 : 176 } : { w: 290, h: 40 };
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
      if (o.blockPlay) win.__blockPlay = true;
      win.localStorage.setItem("bf_token", TOKEN);
      if (o.store) win.localStorage.setItem("bf_music", JSON.stringify(o.store));
      if (o.boombox) win.localStorage.setItem("bf_boombox", JSON.stringify(o.boombox));
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
     its rotary dial (.bbx-dial, a slider). */
  check("D1. the dashboard's boombox is built, with every control as a drawn icon button (no emoji) and the exact autoplay words",
    BM && BM.mode === "float" && !!A.document.querySelector(".bbx-keys [data-act=toggle] svg") && !!A.document.querySelector("[data-act=shuffle] svg") &&
    !!A.document.querySelector("[data-act=repeat] svg") && !!A.document.querySelector("[data-act=mute] svg") && !!A.document.querySelector("[data-act=popout] svg") &&
    !!A.document.querySelector(".bfm-seek") && !!A.document.querySelector(".bbx-dial[role=slider]") && !!A.document.querySelector(".bfm-mix") && !!A.document.querySelector(".bfm-playlist") &&
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
  const P = await openPage(Object.assign({}, base, { store: autoStore }));
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
  click(A, "[data-act=popout]");
  check("D6. Pop out opens music-popout.html", A.__calls.indexOf("open /music-popout.html") !== -1);
  const B = await openPage(Object.assign({}, base, { popout: true }));
  await settle(30);
  clearInterval(watch);
  check("D6. the handoff: the page goes silent first and the pop-out plays on from the same track and place; never two at once",
    !A.BFMusic.playing() && B.BFMusic.playing() && B.BFMusic.audible() && B.BFMusic.state().track_id === T2 && near(B.BFMusic.position(), 33, 0.01) && violations.length === 0,
    "A " + A.BFMusic.playing() + " B " + B.BFMusic.playing() + " audible " + B.BFMusic.audible() + " track " + (B.BFMusic.state().track_id === T2) + " at " + B.BFMusic.position() + " " + violations.slice(0, 3).join("; "));
  B.BFMusic._tick(); await settle();
  check("D6. the page shows \"Playing in the pop-out player\"", A.BFMusic.popoutAlive() && A.document.querySelector(".bfm-remote").textContent === "Playing in the pop-out player" &&
    A.document.querySelector(".bfm").getAttribute("data-remote") === "true");
  A.BFMusic.play(); await settle();
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
  click(Z, "[data-act=popout]");
  check("D7. a blocked pop-up is said plainly", /blocked the pop-out window/.test(Z.document.querySelector(".bfm-msg").textContent));

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
     press \"Play\""). AFTER: it names the boombox beside the logo and its own keys, "Library" and "Pop out". */
  check("F4. the dashboard's guide names the boombox and its own labels, \"Library\" and \"Pop out\"",
    /Beside the logo, the boombox plays your own music; \\"Library\\" holds your tracks and uploads, and \\"Pop out\\" keeps it playing between pages\./.test(tip) &&
    !!A.document.querySelector("[data-act=bbx-library][aria-label=Library]") && /Pop out/.test(A.document.querySelector(".bfm-panel [data-act=popout]").textContent));
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
     with the player loaded all the same, and must still show no boombox. */
  const want = [], refuse = [], wrong = [];
  for (const f of pages) {
    const html = lf(fs.readFileSync(path.join(FRONTEND, f), "utf8"));
    if (!/termaximus-presence\.js/.test(html) || f === "music-popout.html") continue;
    const guarded = /<script src="\/scripts\/bf-session\.js"><\/script>/.test(html);
    const card = UNTHEMED.indexOf(f) !== -1;
    const expected = guarded && !card;
    (expected ? want : refuse).push(f);
    if (!guarded && !card) { if (/bf-music\.js|bf-boombox\.js/.test(html)) wrong.push(f + " has it"); continue; }
    const on = await presenceOn(f, html);
    if (on !== expected) wrong.push(f + (on ? " has it" : " lacks it"));
  }
  check("G1. the boombox is on every signed-in page that has the mist (" + want.length + " pages)", want.length >= 30 && wrong.filter(x => / lacks it$/.test(x)).length === 0, wrong.join(", "));
  check("G1. ... and never on a public page or a card, even with the player loaded (" + refuse.join(", ") + ")",
    refuse.indexOf("card-view.html") !== -1 && wrong.filter(x => / has it$/.test(x)).length === 0, wrong.join(", "));
  const loaders = pages.filter(f => /\/scripts\/bf-music\.js/.test(fs.readFileSync(path.join(FRONTEND, f), "utf8")));
  const sessionLoads = /bf-music\.js/.test(FILES[SESSION]);
  check("G1. the player loads only where a member is signed in: through the session guard, or on the dashboard and the pop-out",
    sessionLoads && loaders.every(f => f === "dashboard.html" || f === "music-popout.html"), loaders.join());

  /* G2. the dashboard: beside the logo, and every capability of the old panel in the expanded view */
  const D = await openPage(base);
  const DR = boxOf(D);
  check("G2. on the dashboard it opens as the boombox in the top bar, 12 px right of the BizForce AI logo and level with it",
    !!DR && DR.getAttribute("data-state") === "box" && DR.style.left === "212px" && DR.style.top === "10px", DR && DR.getAttribute("style"));
  click(D, "[data-act=bbx-library]");
  const CAPS = [["play and pause", ".bbx-keys [data-act=toggle]"], ["previous", ".bbx-keys [data-act=prev]"], ["next", ".bbx-keys [data-act=next]"],
    ["shuffle", ".bbx-keys [data-act=shuffle]"], ["repeat", ".bbx-keys [data-act=repeat]"], ["mute", ".bbx-low [data-act=mute]"], ["volume", ".bbx-dial[role=slider]"],
    ["seek", ".bbx-display .bfm-seek"], ["the time", ".bbx-display .bfm-cur"], ["the live strip", ".bbx-display .bfm-viz"],
    ["Spectrum", ".bfm-panel [data-view=spectrum]"], ["Waveform", ".bfm-panel [data-view=wave]"], ["Mix", ".bfm-panel .bfm-mix"],
    ["the playlists", ".bfm-panel .bfm-playlist"], ["new playlist", ".bfm-panel [data-act=pl-new]"], ["rename playlist", ".bfm-panel [data-act=pl-rename]"],
    ["delete playlist", ".bfm-panel [data-act=pl-delete]"], ["the queue", ".bfm-panel .bfm-queue"], ["a draggable queue item", ".bfm-panel .bfm-item[draggable=true]"],
    ["upload (the drop zone)", ".bfm-panel .bfm-drop"], ["the file picker", ".bfm-panel [data-act=choose]"], ["choose files", ".bfm-panel [data-act=choose]"], ["Play when I open BizForce", ".bfm-panel #bfmAutoplay"],
    ["Pop out", ".bfm-panel [data-act=popout]"]];
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
  const F = await openPage(Object.assign({}, base, { page: "tasks.html" }));
  const FR = boxOf(F), tag = F.document.querySelector(".bfm-tag"), grabAt = F.document.querySelector(".bfm-tag-title");
  check("G4. on any other page it starts as the tag, bottom left", FR.getAttribute("data-state") === "tag" && spot(F).join() === "16," + (800 - 40 - 16));
  ptr(F, grabAt, "pointerdown", 100, 700); ptr(F, grabAt, "pointermove", 103, 702);
  const under = spot(F).join();
  ptr(F, grabAt, "pointermove", 300, 500); ptr(F, grabAt, "pointerup", 300, 500);
  check("G4. a press becomes a drag only past the mist's 6 px; then it follows the pointer and is saved on release",
    F.BFBoombox.DRAG_THRESHOLD === 6 && under === "16,744" && spot(F).join() === "216,544" && prefsOf(F).left === 216 && prefsOf(F).top === 544, under + " " + spot(F));
  ptr(F, grabAt, "pointerdown", 300, 500); ptr(F, grabAt, "pointermove", 9000, 9000); ptr(F, grabAt, "pointerup", 9000, 9000);
  const far = spot(F).join();
  ptr(F, grabAt, "pointerdown", 300, 500); ptr(F, grabAt, "pointermove", -9000, -9000); ptr(F, grabAt, "pointerup", -9000, -9000);
  check("G4. it is clamped fully on screen, at every edge", far === (1280 - 290) + "," + (800 - 40) && spot(F).join() === "0,0", far + " " + spot(F));
  const mistSrc = (/function _tmxClampPosition\(left, top, el\) \{[\s\S]*?\n  \}\n/.exec(FILES[PRESENCE]) || [""])[0];
  let same = !!mistSrc;
  if (same) {
    const fakeWin = { innerWidth: 1280, innerHeight: 800 };
    const mistClamp = new Function("window", "root", mistSrc + "\nreturn _tmxClampPosition;")(fakeWin, null);
    [[-50, -50, 290, 40], [5000, 5000, 290, 40], [400, 300, 320, 484], [1100, 790, 320, 176], [10, 10, 2000, 2000]].forEach(([l, t, ew, eh]) => {
      const el = { offsetWidth: ew, offsetHeight: eh };
      if (JSON.stringify(mistClamp(l, t, el)) !== JSON.stringify(F.BFBoombox.clampPosition(l, t, el))) same = false;
    });
  }
  check("G4. the clamp is the mist's own rule (_tmxClampPosition), giving the same place for the same inputs", same);
  tag.focus();
  key(F, tag, "ArrowRight"); key(F, tag, "ArrowDown", { shiftKey: true });
  check("G4. the arrow keys move the focused tag 10 px, 40 with Shift, and it is saved", spot(F).join() === "10,40" && prefsOf(F).left === 10 && prefsOf(F).top === 40, spot(F));
  key(F, tag, "Home");
  check("G4. Home resets it to its default place and forgets the saved one", spot(F).join() === "16,744" && !("left" in prefsOf(F)));
  ptr(F, grabAt, "pointerdown", 100, 700); ptr(F, grabAt, "pointermove", 2000, 700); ptr(F, grabAt, "pointerup", 2000, 700);
  F.__w = 900; F.dispatchEvent(new F.Event("resize"));
  check("G4. a smaller window re-clamps it, so it stays fully on screen", spot(F)[0] === 900 - 290, spot(F));
  F.__w = 1280; F.dispatchEvent(new F.Event("resize"));
  click(F, "[data-act=bbx-expand]");
  ptr(F, F.document.querySelector(".bbx-body-grip"), "pointerdown", 100, 100); ptr(F, F.document.querySelector(".bbx-body-grip"), "pointermove", 140, 60);
  ptr(F, F.document.querySelector(".bbx-body-grip"), "pointerup", 140, 60);
  const moved = spot(F).join();
  click(F, "[data-act=bbx-reset]");
  check("G4. the boombox's handle drags it too, and the reset key puts it back and keeps the focus on the handle",
    moved === (1280 - 320) + "," + (800 - 484 - 40) && spot(F).join() === "16," + (800 - 484 - 16) && !("left" in prefsOf(F)) &&
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
  check("G5. Expand opens the boombox with the library, focuses its Play key, and remembers it",
    FR.getAttribute("data-state") === "box" && FR.getAttribute("data-library") === "true" && expand.getAttribute("aria-expanded") === "true" &&
    F.document.activeElement === F.document.querySelector(".bbx-keys [data-act=toggle]") && prefsOf(F).state === "box");
  key(F, F.document.activeElement, "Escape");
  check("G5. Escape returns it to the tag, with the focus on Expand", FR.getAttribute("data-state") === "tag" && F.document.activeElement === expand);
  const tagKeys = ["toggle", "next", "bbx-expand"].every(a => !!tag.querySelector("[data-act=" + a + "]"));
  check("G5. the tag holds the title, a tiny wave, play/pause, next and expand", tagKeys && tag.querySelectorAll(".bfm-tag-wave span").length === 5 && !!tag.querySelector(".bfm-tag-title"));

  /* G6. never over the mist or the open chat box */
  const MIST = '<div id="tmx-presence-root" data-size="120x120" style="position:fixed;left:400px;top:60px"></div>';
  const N = await openPage(Object.assign({}, base, { extra: MIST }));
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
    /function place\(\)[\s\S]*?nudge\(\);[\s\S]*?\n    \}/.test(BX) && /if \(drag\.moved\) \{ nudge\(\); saveSpot\(\); \}/.test(BX) && /setInterval\(function \(\) \{ if \(state && !drag\.on\) nudge\(\); \}, 1500\)/.test(BX));

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
  check("G7. the tweeters shimmer with the highs, and the LEDs light with the level (all 12 at full, 3 of 6 a side at half)",
    dome > 0.95 && Number(q1(".bbx-tweeter-dome").style.opacity) === 0.55 && litFull === 12 && litHalf === 3, dome + " " + litFull + " " + litHalf);
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
  const styled = Array.prototype.filter.call(MO.document.querySelectorAll(".bbx *, .bfm-tag *"), el => {
    for (let i = 0; i < el.style.length; i++) if (["transform", "opacity", "--bbx-scroll-s"].indexOf(el.style.item(i)) === -1) return true;
    return false;
  }).map(el => el.getAttribute("class") + ": " + el.getAttribute("style"));
  const styleProps = new Set((BX.match(/\.style\.(\w+)\s*=(?!=)/g) || []).map(x => /\.style\.(\w+)/.exec(x)[1]));
  const placeOnly = (BX.match(/\w+\.style\.(left|top|right|bottom)\s*=/g) || []).every(x => /^root\./.test(x));
  const frames_ = (BX.match(/@keyframes [\w-]+\{[\s\S]*?\}\}/g) || []);
  const kfOk = frames_.length >= 2 && frames_.every(k => (k.match(/[\w-]+(?=:)/g) || []).every(p => p === "transform" || p === "opacity"));
  const transOk = (BX.match(/transition:[^;}"]+/g) || []).every(t => t.split(",").every(p => /^(transition:)?\s*transform\b/.test(p.trim()) || /none/.test(p)));
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
  check("G7. a long title scrolls on the display (two copies, the second hidden from screen readers), and the title is announced",
    q1(".bbx-marquee").getAttribute("data-long") === "true" && MO.document.querySelectorAll(".bbx-scroll span").length === 2 &&
    MO.document.querySelectorAll(".bbx-scroll span")[1].getAttribute("aria-hidden") === "true" && q1(".bfm-live").getAttribute("aria-live") === "polite" &&
    q1(".bfm-live").textContent === "Now playing: A Very Long Title For The Marquee by Artist");
  setHidden(MO, true);
  const hidAt = bx.motion().angle;
  frames(MO, 5);
  check("G7. hidden, it stops: no frame runs, nothing turns, and the marquee is paused", bx.motion().angle === hidAt && MO.__raf.length === 0 &&
    boxOf(MO).getAttribute("data-hidden") === "true" && /\.bfm\[data-hidden=true\] \.bbx-marquee \.bbx-scroll\{animation-play-state:paused\}/.test(BX));
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
    RM.document.querySelector(".bfm-viz").getAttribute("data-viz") === "static" && RM.document.querySelector(".bbx-marquee").getAttribute("data-long") === "false" &&
    /@media \(prefers-reduced-motion: reduce\)\{\.bbx-marquee \.bbx-scroll\{animation:none!important\}/.test(BX), JSON.stringify(rm));
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
  const t0 = Date.now();
  const P2 = await openPage(Object.assign({}, base, { page: "tasks.html", store: left }));
  while (!P2.BFMusic.playing() && Date.now() - t0 < 2000) await wait(20);
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
  check("G8. the help text says so, word for word", F.document.querySelector(".bfm-continuity").textContent === "Moving between pages pauses for a moment. For unbroken music, use Pop out." &&
    F.BFMusic.CONTINUITY_NOTE === "Moving between pages pauses for a moment. For unbroken music, use Pop out.");

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
  for (let i = 0; i < 75 && !(R1.BFMusic._levels().bass > 0.5); i++) await wait(20);
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
}

function legalPages_musicText() { const lp = require("../lib/legalPages"); return lp.musicTerms().join(" ") + " " + lp.musicPrivacySentence(); }
function masterGain(w) { const m = w.BFMusic._master(); return m ? m.gain.value : NaN; }

function finish() {
  closeAll();
  console.log("\n" + passes + " passed, " + failures + " failed");
  console.log(failures === 0 ? "ALL CHECKS PASSED" : "CHECKS FAILED");
  process.exit(failures === 0 ? 0 : 1);
}
