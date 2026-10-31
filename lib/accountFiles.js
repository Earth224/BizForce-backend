/* ══════════════════════════════════════════════════════════════════════════
   lib/accountFiles.js — the files a member uploaded, found, kept for buyers,
   and removed when the account is deleted.

   FOUR BUCKETS, AND HOW EACH NAMES A MEMBER'S FILES
     bf-public         public URLs. POST /api/bfp/upload-url builds
                       `<folder>/<user id>/<time>_<name>`; the folder is the
                       page's choice (avatars, banners, videos, music,
                       music-art, portfolio, products, card-media,
                       marketplace-media). Rows store the full public URL.
                       Theme backdrop photos are uploaded through the server
                       (POST /api/themes/photo) to
                       `theme-photos/<user id>/<time>.<ext>`, and found here
                       by the same folder listing as every other folder.
     bf-books          private. Every path begins `<user id>/`: book PDFs,
                       EPUBs and covers, cover-wrap backgrounds and layers
                       (`<user id>/wrap_…`), editor images
                       (`<user id>/editorimg_…`). Rows store the bare path.
     bf-digital-goods  private. `<user id>/<time>_<name>`, the file a listing
                       sells. Rows store the bare path; buyers get a signed
                       URL per order.
     bf-music          private (migration 155). `<user id>/<time>.<ext>`, the
                       member's own music library (lib/music.js). Rows
                       (member_tracks) store the bare path; the player gets a
                       signed URL that expires.

   A FILE IS THE MEMBER'S when either:
     - one of their rows records it (FILE_TABLES below): a bf-public URL whose
       key has their id as a whole folder name, or a bare path under
       `<their id>/` in that table's bucket; or
     - it is listed under their folder: `<their id>/` in bf-books,
       bf-digital-goods and bf-music, `<folder>/<their id>/` in bf-public.
   Never by a bare prefix: "abc" does not own "abcd/…". keyUnder is the one
   place that decides it.

   KEPT FOR BUYERS. A listing another member bought is not deleted with the
   seller: it is taken off sale (status "paused", or left "sold") and stays,
   so each buyer's download still finds its file, through the order's own
   snapshot (migration 113) or, for older orders, through the listing. The
   seller is shown on the order as a deleted member, as every kept order is.
   So, per bucket:
     bf-digital-goods  kept when it is the file of a listing someone bought,
                       or the file an order recorded; otherwise deleted
     bf-public         kept when it is a picture or video of a listing someone
                       bought; otherwise deleted
     bf-books          never sold through the marketplace; always deleted
     bf-music          never sold; always deleted

   REMOVAL comes after the rows are deleted, in batches of REMOVE_BATCH per
   bucket. A batch Storage refuses is written to pending_storage_deletions
   (migration 144), and retryPendingDeletions removes it later; the daily
   job pending_storage_deletions runs it. At ALERT_AT failed attempts the
   owner gets one ops alert, and the retries go on until the file is gone.

   NOTHING HERE TALKS TO THE NETWORK by itself: the Supabase client, its
   storage and the alerts are passed in, so scripts/checkAccountFiles.js runs
   all of it against stubs.
   ══════════════════════════════════════════════════════════════════════════ */

const PUBLIC = "bf-public";
const BOOKS = "bf-books";
const GOODS = "bf-digital-goods";
const MUSIC = "bf-music";
const BUCKETS = [PUBLIC, BOOKS, GOODS, MUSIC];

const PUBLIC_MARKER = "/storage/v1/object/public/" + PUBLIC + "/";
const PAGE_SIZE = 1000;
const MAX_PAGES = 500;
const LIST_DEPTH = 8;
const REMOVE_BATCH = 100;
const ALERT_AT = 5;
const RETRY_JOB_NAME = "pending_storage_deletions";
const QUEUE_TABLE = "pending_storage_deletions";

/* The member's rows that can record a file. `bare` is the bucket a bare path
   in that row belongs to; bf-public files are always recorded as URLs. */
const FILE_TABLES = [
  { table: "users", owner: "id" },
  { table: "profiles", owner: "user_id" },
  { table: "bf_profiles", owner: "user_id" },
  { table: "profile_products", owner: "user_id" },
  { table: "profile_portfolio", owner: "user_id" },
  { table: "profile_music", owner: "user_id" },
  { table: "profile_videos", owner: "user_id" },
  { table: "bf_music_tracks", owner: "user_id" },
  { table: "bf_videos", owner: "user_id" },
  { table: "digital_cards", owner: "user_id" },
  { table: "content_library", owner: "user_id" },
  { table: "crowdfunding_campaigns", owner: "owner_id" },
  { table: "bizbooks", owner: "owner_id", bare: BOOKS },
  { table: "cover_wraps", owner: "owner_id", bare: BOOKS },
  { table: "marketplace_listings", owner: "seller_id", bare: GOODS },
  { table: "member_tracks", owner: "user_id", bare: MUSIC }
];

function errorText(err) {
  if (!err) return "unknown error";
  if (typeof err === "string") return err;
  return String(err.message || err.error || JSON.stringify(err));
}
function fail(what, error) {
  var e = new Error(what + ": " + errorText(error));
  e.step = what;
  return e;
}
function chunks(list, size) {
  var out = [];
  for (var i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
}

/* THE GUARD. `key` is inside the folder `prefix`: "abc/x" is under "abc",
   "abcd/x" is not. */
function keyUnder(key, prefix) {
  return typeof key === "string" && !!prefix && key.indexOf(prefix + "/") === 0;
}

/* A bf-public key is the member's when their id is one of its folders, below
   the first (`<folder>/<id>/…`; a folder may itself contain "/"). */
function publicKeyOwned(key, userId) {
  if (typeof key !== "string" || !userId) return false;
  var parts = key.split("/");
  for (var i = 1; i < parts.length - 1; i++) {
    if (keyUnder(key, parts.slice(0, i).join("/") + "/" + userId)) return true;
  }
  return false;
}

function hostOf(base) {
  try { return base ? new URL(base).host : null; } catch (err) { return null; }
}

/* A bf-public object URL to its key, or null. Same rule as the server's
   bfPublicUrlToKey: our host when known, the public marker, decodeURI. */
function publicUrlToKey(value, host) {
  if (typeof value !== "string" || !value) return null;
  var parsed;
  try { parsed = new URL(value); } catch (err) { return null; }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  if (host && parsed.host !== host) return null;
  var at = parsed.pathname.indexOf(PUBLIC_MARKER);
  if (at === -1) return null;
  var encoded = parsed.pathname.slice(at + PUBLIC_MARKER.length);
  if (!encoded) return null;
  try { return decodeURI(encoded) || null; } catch (err) { return null; }
}

/* Every string inside a value: columns, JSON objects and arrays, and text
   that is itself JSON (designs and book content are stored both ways). */
function eachString(value, visit, depth) {
  depth = depth || 0;
  if (depth > 40 || value === null || value === undefined) return;
  if (typeof value === "string") {
    visit(value);
    var t = value.trim();
    if ((t[0] === "{" || t[0] === "[") && t.length > 1) {
      var parsed = null;
      try { parsed = JSON.parse(t); } catch (err) { parsed = null; }
      if (parsed && typeof parsed === "object") eachString(parsed, visit, depth + 1);
    }
    return;
  }
  if (Array.isArray(value)) { value.forEach(function (v) { eachString(v, visit, depth + 1); }); return; }
  if (typeof value === "object") Object.keys(value).forEach(function (k) { eachString(value[k], visit, depth + 1); });
}

const URL_IN_TEXT = /https?:\/\/[^\s"'<>()\\]+/g;

/* The files one row records as the member's: [{ bucket, path }]. */
function filesInRow(row, bare, userId, host) {
  var found = [];
  eachString(row, function (s) {
    var urls = s.match(URL_IN_TEXT) || [];
    urls.forEach(function (u) {
      var key = publicUrlToKey(u, host);
      if (key && publicKeyOwned(key, userId)) found.push({ bucket: PUBLIC, path: key });
    });
    if (bare && keyUnder(s, userId)) found.push({ bucket: bare, path: s });
  });
  return found;
}

/* Every row of `table` matching `filter`, a page at a time. */
async function readPaged(supabase, table, filter, onPage) {
  for (var page = 0; page < MAX_PAGES; page++) {
    var from = page * PAGE_SIZE;
    var r = await filter(supabase.from(table).select("*")).range(from, from + PAGE_SIZE - 1);
    if (r.error) throw fail(table + " could not be read", r.error);
    var rows = r.data || [];
    await onPage(rows);
    if (rows.length < PAGE_SIZE) return;
  }
  throw fail(table + " could not be read", "more than " + (MAX_PAGES * PAGE_SIZE) + " rows");
}

/* Every object under `prefix/` in `bucket`, folders followed. */
async function listUnder(storage, bucket, prefix, depth) {
  var keys = [];
  for (var page = 0; page < MAX_PAGES; page++) {
    var r = await storage.from(bucket).list(prefix, { limit: PAGE_SIZE, offset: page * PAGE_SIZE });
    if (r.error) throw fail(bucket + "/" + prefix + " could not be listed", r.error);
    var items = r.data || [];
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      if (!it || !it.name) continue;
      var key = prefix ? prefix + "/" + it.name : it.name;
      if (it.id === null || it.id === undefined) {
        if ((depth || 0) < LIST_DEPTH) keys = keys.concat(await listUnder(storage, bucket, key, (depth || 0) + 1));
      } else {
        keys.push(key);
      }
    }
    if (items.length < PAGE_SIZE) return keys;
  }
  throw fail(bucket + "/" + prefix + " could not be listed", "more than " + (MAX_PAGES * PAGE_SIZE) + " entries");
}

/* The top-level folders of a bucket (bf-public's upload folders). */
async function rootFolders(storage, bucket) {
  var names = [];
  for (var page = 0; page < MAX_PAGES; page++) {
    var r = await storage.from(bucket).list("", { limit: PAGE_SIZE, offset: page * PAGE_SIZE });
    if (r.error) throw fail(bucket + " could not be listed", r.error);
    var items = r.data || [];
    items.forEach(function (it) { if (it && it.name && (it.id === null || it.id === undefined)) names.push(it.name); });
    if (items.length < PAGE_SIZE) return names;
  }
  throw fail(bucket + " could not be listed", "more than " + (MAX_PAGES * PAGE_SIZE) + " folders");
}

function fileId(f) { return f.bucket + "\u0000" + f.path; }

/* opts: { supabase, storage, userId, publicUrlBase }
   Every object the member owns, once each: [{ bucket, path, reason }].
   Throws when a table or a folder cannot be read: a list that might be
   missing files is never used to delete. */
async function filesOwnedBy(opts) {
  var supabase = opts.supabase, storage = opts.storage, userId = opts.userId;
  var host = hostOf(opts.publicUrlBase);
  if (!userId) throw fail("no member", "userId is empty");
  var out = [], seen = {};
  function add(bucket, path, reason) {
    var f = { bucket: bucket, path: path };
    if (seen[fileId(f)]) return;
    seen[fileId(f)] = true;
    out.push({ bucket: bucket, path: path, reason: reason });
  }

  for (var i = 0; i < FILE_TABLES.length; i++) {
    var t = FILE_TABLES[i];
    await readPaged(supabase, t.table, function (q) { return q.eq(t.owner, userId); }, function (rows) {
      rows.forEach(function (row) {
        filesInRow(row, t.bare, userId, host).forEach(function (f) { add(f.bucket, f.path, "recorded in " + t.table); });
      });
    });
  }

  var books = await listUnder(storage, BOOKS, userId, 0);
  books.forEach(function (k) { if (keyUnder(k, userId)) add(BOOKS, k, "in " + BOOKS + " under the member's folder"); });
  var goods = await listUnder(storage, GOODS, userId, 0);
  goods.forEach(function (k) { if (keyUnder(k, userId)) add(GOODS, k, "in " + GOODS + " under the member's folder"); });
  var music = await listUnder(storage, MUSIC, userId, 0);
  music.forEach(function (k) { if (keyUnder(k, userId)) add(MUSIC, k, "in " + MUSIC + " under the member's folder"); });
  var folders = await rootFolders(storage, PUBLIC);
  for (var j = 0; j < folders.length; j++) {
    var mine = folders[j] + "/" + userId;
    var listed = await listUnder(storage, PUBLIC, mine, 0);
    listed.forEach(function (k) { if (keyUnder(k, mine)) add(PUBLIC, k, "in " + PUBLIC + " under " + folders[j] + "/<member>"); });
  }
  return out;
}

/* opts: { supabase, userId, publicUrlBase }
   What stays because another member bought it:
     { listings: [listing ids bought by someone else], files: [{ bucket, path, reason }], orders: n }
   Throws when listings or orders cannot be read. */
async function keptForBuyers(opts) {
  var supabase = opts.supabase, userId = opts.userId;
  var host = hostOf(opts.publicUrlBase);
  var listings = [];
  await readPaged(supabase, "marketplace_listings", function (q) { return q.eq("seller_id", userId); },
    function (rows) { listings = listings.concat(rows); });
  var byId = {};
  listings.forEach(function (l) { byId[l.id] = l; });

  var orders = [], seenOrder = {};
  function take(rows) {
    rows.forEach(function (o) {
      if (seenOrder[o.id] || !o.buyer_id || o.buyer_id === userId) return;
      seenOrder[o.id] = true;
      orders.push(o);
    });
  }
  await readPaged(supabase, "marketplace_orders", function (q) { return q.eq("seller_id", userId); }, take);
  var ids = Object.keys(byId);
  for (var c of chunks(ids, 100)) {
    await readPaged(supabase, "marketplace_orders", function (q) { return q.in("listing_id", c); }, take);
  }

  var sold = [], files = [], seen = {};
  function keep(bucket, path, reason) {
    var f = { bucket: bucket, path: path };
    if (!path || seen[fileId(f)]) return;
    seen[fileId(f)] = true;
    files.push({ bucket: bucket, path: path, reason: reason });
  }
  orders.forEach(function (o) {
    if (o.listing_id && byId[o.listing_id] && sold.indexOf(o.listing_id) === -1) sold.push(o.listing_id);
    if (o.digital_file_path) keep(GOODS, o.digital_file_path, "the file order " + o.id + " bought");
  });
  sold.forEach(function (id) {
    var l = byId[id];
    if (l.digital_file_path) keep(GOODS, l.digital_file_path, "the file of listing " + id + ", which another member bought");
    eachString(l.media, function (s) {
      (s.match(URL_IN_TEXT) || []).forEach(function (u) {
        var key = publicUrlToKey(u, host);
        if (key) keep(PUBLIC, key, "a picture or video of listing " + id + ", which another member bought");
      });
    });
  });
  return { listings: sold, files: files, orders: orders.length };
}

/* The member's files minus what is kept for buyers. */
function toRemove(owned, kept) {
  var keepIds = {};
  (kept.files || []).forEach(function (f) { keepIds[fileId(f)] = true; });
  return owned.filter(function (f) { return !keepIds[fileId(f)]; });
}

/* Writes files Storage refused to the queue. Returns how many could NOT be
   written (they are then named in the log and an alert by the caller). */
async function queue(supabase, files, error, nowIso) {
  try {
    var rows = files.map(function (f) {
      return { bucket: f.bucket, path: f.path, attempts: 1, last_error: errorText(error).slice(0, 500), last_attempt_at: nowIso, created_at: nowIso };
    });
    var r = await supabase.from(QUEUE_TABLE).upsert(rows, { onConflict: "bucket,path", ignoreDuplicates: true });
    if (r && r.error) return { queued: 0, error: errorText(r.error) };
    return { queued: files.length, error: null };
  } catch (err) {
    return { queued: 0, error: errorText(err) };
  }
}

/* opts: { supabase, storage, files: [{ bucket, path }], now }
   Removes in batches per bucket. Never throws. Returns
   { deleted, queued, not_queued, failures: [{ bucket, paths, error }] }. */
async function removeFiles(opts) {
  var supabase = opts.supabase, storage = opts.storage;
  var nowIso = (opts.now || new Date()).toISOString();
  var result = { deleted: 0, queued: 0, not_queued: 0, failures: [] };
  for (var b = 0; b < BUCKETS.length; b++) {
    var bucket = BUCKETS[b];
    var paths = (opts.files || []).filter(function (f) { return f.bucket === bucket; }).map(function (f) { return f.path; });
    for (var batch of chunks(paths, REMOVE_BATCH)) {
      var error = null;
      try {
        var r = await storage.from(bucket).remove(batch);
        if (r && r.error) error = r.error;
      } catch (err) {
        error = err;
      }
      if (!error) { result.deleted += batch.length; continue; }
      var q = await queue(supabase, batch.map(function (p) { return { bucket: bucket, path: p }; }), error, nowIso);
      result.queued += q.queued;
      result.not_queued += batch.length - q.queued;
      result.failures.push({ bucket: bucket, paths: batch, error: errorText(error), queue_error: q.error });
    }
  }
  return result;
}

/* opts: { supabase, storage, alerts, now, log }
   One pass over the queue: each file Storage now removes leaves it; each
   failure counts one more attempt, and the files that reach ALERT_AT in this
   pass raise ONE alert. Returns { tried, removed, failed, alerted }.
   Throws when the queue cannot be read or written. */
async function retryPendingDeletions(opts) {
  var supabase = opts.supabase, storage = opts.storage;
  var nowIso = (opts.now || new Date()).toISOString();
  var rows = [];
  await readPaged(supabase, QUEUE_TABLE, function (q) { return q.order("created_at", { ascending: true }); },
    function (page) { rows = rows.concat(page); });
  var out = { tried: rows.length, removed: 0, failed: 0, alerted: 0 };
  var stuck = [];
  for (var b = 0; b < BUCKETS.length; b++) {
    var bucket = BUCKETS[b];
    var mine = rows.filter(function (r) { return r.bucket === bucket; });
    for (var batch of chunks(mine, REMOVE_BATCH)) {
      var error = null;
      try {
        var r = await storage.from(bucket).remove(batch.map(function (x) { return x.path; }));
        if (r && r.error) error = r.error;
      } catch (err) {
        error = err;
      }
      if (!error) {
        var gone = await supabase.from(QUEUE_TABLE).delete().in("id", batch.map(function (x) { return x.id; }));
        if (gone.error) throw fail(QUEUE_TABLE + " could not be updated", gone.error);
        out.removed += batch.length;
        continue;
      }
      for (var row of batch) {
        var attempts = (Number(row.attempts) || 0) + 1;
        var u = await supabase.from(QUEUE_TABLE).update({ attempts: attempts, last_error: errorText(error).slice(0, 500), last_attempt_at: nowIso }).eq("id", row.id);
        if (u.error) throw fail(QUEUE_TABLE + " could not be updated", u.error);
        out.failed++;
        if (attempts === ALERT_AT) stuck.push({ bucket: bucket, path: row.path, error: errorText(error) });
      }
    }
  }
  if (stuck.length && opts.alerts && opts.alerts.storageDeletionStuck) {
    await opts.alerts.storageDeletionStuck({ files: stuck, attempts: ALERT_AT });
    out.alerted = stuck.length;
  }
  return out;
}

/* The daily claim in job_runs: one run per UTC day across every process. */
async function claimDailyJob(supabase, jobName, day, nowIso) {
  var fresh = { job_name: jobName, last_run_on: day, started_at: nowIso, finished_at: null, last_error: null };
  var ins = await supabase.from("job_runs").insert(fresh).select("job_name");
  if (!ins.error) return true;
  if (ins.error.code !== "23505") throw fail("job_runs could not be claimed", ins.error);
  var upd = await supabase.from("job_runs")
    .update({ last_run_on: day, started_at: nowIso, finished_at: null, last_error: null })
    .eq("job_name", jobName)
    .or("last_run_on.is.null,last_run_on.neq." + day)
    .select("job_name");
  if (upd.error) throw fail("job_runs could not be claimed", upd.error);
  return (upd.data || []).length > 0;
}

/* The daily job. opts: { supabase, storage, alerts, now, log }.
   Never throws: what went wrong is in job_runs.last_error and the log. */
async function runRetryJob(opts) {
  var log = opts.log || console;
  var now = opts.now || new Date();
  var nowIso = now.toISOString();
  var day = nowIso.slice(0, 10);
  var claimed;
  try { claimed = await claimDailyJob(opts.supabase, RETRY_JOB_NAME, day, nowIso); } catch (err) {
    log.error("[account-files] retry not claimed: " + errorText(err));
    return { claimed: false, error: errorText(err) };
  }
  if (!claimed) return { claimed: false };
  var result = null, error = null;
  try { result = await retryPendingDeletions(opts); } catch (err) { error = errorText(err); }
  try {
    await opts.supabase.from("job_runs").update({ finished_at: new Date().toISOString(), last_error: error }).eq("job_name", RETRY_JOB_NAME);
  } catch (err) { /* the log line below still says it */ }
  if (error) log.error("[account-files] retry failed: " + error);
  else log.log("[account-files] retry: " + result.tried + " queued, " + result.removed + " removed, " + result.failed + " still failing" + (result.alerted ? ", " + result.alerted + " alerted" : ""));
  return { claimed: true, result: result, error: error };
}

module.exports = {
  BUCKETS, FILE_TABLES, REMOVE_BATCH, ALERT_AT, RETRY_JOB_NAME, QUEUE_TABLE,
  keyUnder, publicKeyOwned, publicUrlToKey, filesInRow,
  filesOwnedBy, keptForBuyers, toRemove, removeFiles, retryPendingDeletions, claimDailyJob, runRetryJob
};
