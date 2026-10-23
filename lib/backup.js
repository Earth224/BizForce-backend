// ── Nightly operational backup ───────────────────────────────────────────────
//
// WHY THIS DOES NOT GO THROUGH sendEmail, deliberately.
//
// server.js:1305-1310 states that sendEmail is the only way mail leaves this
// system, and it is right about the mail it was written for. That function
// serves mail sent TO CONTACTABLE PEOPLE: it demands a contact to attribute the
// send to, it derives consent before sending, it writes a row into the
// email_sends deliverability ledger, and it attaches RFC 8058 one-click
// unsubscribe headers.
//
// This message is none of those things. It is operational mail from the system
// to its own operator. There is no contact, because the operator is not a
// customer. There is no consent dimension, because nobody opted into their own
// backups. It belongs in no deliverability ledger, because a backup is not
// marketing and counting it against a bounce rate would be noise.
//
// And the unsubscribe headers are the reason this MUST NOT reuse sendEmail
// rather than merely need not. Those headers promise a mailbox provider that a
// POST to that URL, with no human present and no confirmation step, unsubscribes
// the recipient. Gmail and Yahoo probe such links unattended. An operator whose
// mailbox auto-clicked its own backup unsubscribe link would revoke consent for
// the very address the backups are sent to, and the backups would stop —
// silently, with the job still logging clean runs every night, until the day
// someone needed a restore and found nothing. A backup system that can be
// switched off by a spam filter is not a backup system.
//
// So this module opens its own Resend client. It reads the key from the same
// place sendEmail does (server.js:1340) and sends from the same address
// (server.js:1330), so there is still one API key and one sending identity.
// What it does not inherit is the contact machinery — which is exactly the part
// that does not apply.
//
// It takes the Supabase client by injection and never builds its own, so there
// is one service-key client in the process. It never requires server.js: that
// would be a cycle, since server.js requires this.
//
// ── What a backup file is (format version 2) ─────────────────────────────────
//
// A backup is one or more PART files, each emailed on its own and each
// verifiable on its own. A part is binary:
//
//   "BFBK"                       4 bytes, the magic
//   header length                4 bytes, big-endian
//   header                       JSON, UTF-8: { format, version, cipher, iv,
//                                manifest }, never a row of data
//   auth tag                     16 bytes, AES-256-GCM's
//   ciphertext                   AES-256-GCM of gzip(JSON { units: [rows, ...] })
//
// The first three are the GCM "additional authenticated data", so the header
// is in the clear but cannot be altered: a changed table name, count, hash or
// part number fails the auth tag exactly as a changed byte of data does.
//
// The manifest: backup_id (shared by every part), created_at, commit, part and
// parts, units (this part's tables, each { table, chunk, chunks, rows, sha256
// of that unit's rows as JSON }) and tables (every table in the whole backup,
// with its row count and status, repeated in every part so any one part says
// what the full set must contain). A table too big for one part is split by
// rows into chunks; it is never cut short.
//
// The key is BACKUP_ENCRYPTION_KEY, base64 of exactly 32 bytes. It is never in
// a file, an email or a log line. With no key, or a malformed one, nothing is
// read and nothing is sent: there is no plaintext fallback.
//
// scripts/restoreBackup.js opens these files. scripts/checkBackupRestore.js
// backs up a fixture database, restores it into an empty one and compares
// every row.

const zlib = require("zlib");
const crypto = require("crypto");
const { Resend } = require("resend");

// ── Which tables, and why ────────────────────────────────────────────────────
//
// Every table the migrations create is in exactly one of the three lists below.
// scripts/checkBackupRestore.js reads supabase/migrations and FAILS when a table
// is in none of them, so a new table is a decision, never a silent gap.
//
// MUST BACK UP, in RESTORE ORDER: a table comes after every table it holds a
// foreign key to, so a restore can insert top to bottom (the check proves this
// against the migrations' REFERENCES clauses).
const BACKUP_TABLES = [
  "users",                       // the accounts: email, name, password hash; nearly every table hangs off it
  "profiles",                    // each account's public profile
  "user_preferences",            // each account's settings (Termaximus presence, mist position)
  "webauthn_credentials",        // passkey PUBLIC keys; without them every passkey must be registered again
  "subscriptions",               // who pays for what plan: Stripe ids, status, period dates
  "user_wallets",                // BizCash balances: money
  "wallet_transactions",         // every BizCash movement: money, and the history behind each balance
  "revenue_events",              // revenue recorded from Stripe events: money
  "model_calls",                 // what each model call cost and for whom: the only spend record
  "business_profiles",           // each user's business: name, offer, audience
  "businesses",                  // legacy business records (foundation table), the user's own
  "bf_profiles",                 // profile pages users built
  "profile_products",            // products on those pages
  "profile_portfolio",           // portfolio entries on those pages
  "profile_music",               // music on those pages
  "profile_videos",              // videos on those pages
  "bf_music_tracks",             // uploaded track records
  "bf_videos",                   // uploaded video records
  "digital_cards",               // users' digital business cards
  "inventory_items",             // the store's stock (after profile_products, which it references)
  "inventory_movements",         // every stock movement (after inventory_items)
  "contacts",                    // users' contacts: the consent ledger's spine
  "consent_events",              // who agreed to what and when: legal evidence, append-only
  "email_sends",                 // every email sent, with bounces and complaints: suppression depends on it
  "outreach_sends",              // every outreach sent: stops a person being contacted twice
  "lead_captures",               // people who gave an email or phone, with consent
  "crm_customers",               // the CRM: customers (after contacts)
  "crm_activities",              // the CRM: what happened with each customer
  "icp_profiles",                // ideal-customer profiles users wrote
  "prospects",                   // prospects (after crm_customers and icp_profiles)
  "bsky_leads",                  // the lead book every radar fills: the sales pipeline is keyed on it, and old posts cannot be found again
  "reddit_leads",                // the same, from Reddit
  "sales_lead_pipeline",         // the sales pipeline: where each lead stands
  "sms_subscribers",             // SMS opt-ins: consent
  "sms_campaigns",               // SMS campaigns users wrote
  "sms_campaign_enrollments",    // who is in which campaign (after both of the above)
  "sms_campaign_messages",       // each campaign's messages
  "sms_send_log",                // every SMS sent: compliance evidence
  "ai_agents",                   // users' agents
  "agent_assignments",           // what each agent is assigned
  "agent_autonomy",              // the consent toggle for agents acting alone
  "agent_schedules",             // when each agent runs
  "agent_memory",                // what each agent has learned about the user's business; users read and edit it
  "agent_collaborations",        // agent-to-agent work records, the user's own
  "agent_proposals",             // proposals awaiting the user's approval
  "email_sequences",             // approved email sequences (after agent_proposals)
  "email_sequence_enrollments",  // who is in which sequence and at which step
  "social_post_drafts",          // social drafts (after agent_proposals)
  "ai_tasks",                    // every agent run and its result: the history users read at /api/ai/tasks
  "executive_dispatches",        // the executive's dispatches (after ai_tasks)
  "testimonial_screen_removals", // the passages the testimonial screen took out of a result: the original text exists nowhere else
  "ai_reports",                  // reports agents wrote
  "self_reviews",                // weekly and monthly self-reviews
  "saved_prompts",               // prompts users saved
  "routines",                    // routines users built
  "oracle_sync",                 // the Oracle's state per user
  "oracle_messages",             // conversations with the Oracle
  "content_library",             // everything users saved to their library
  "seo_refused_drafts",          // refused articles that were already paid for
  "bizbooks",                    // books users wrote
  "cover_wraps",                 // their covers
  "bizdoc_documents",            // documents users wrote
  "bizdoc_signatures",           // signatures on them (after bizdoc_documents)
  "marketplace_listings",        // what users sell
  "marketplace_orders",          // what was bought: money (after marketplace_listings)
  "crowdfunding_campaigns",      // users' campaigns
  "campaign_donations",          // donations to them: money (after crowdfunding_campaigns)
  "bfc_transfers",               // BizCash sent between members, both parties: money (after users)
  "user_certifications",         // certifications users earned
  "inner_iq_results",            // assessment results
  "birth_records",               // birth details users entered for readings
  "calendar_events",             // users' calendars
  "notifications",               // what users were told
  "messages",                    // messages between users
  "chat_messages",               // chat history
  "tasks",                       // users' task lists
  "automation_queue",            // automations users queued
  "moderation_logs",             // who banned whom and why: append-only, cannot be re-derived
  "admin_flags",                 // admin flags on accounts
  "pending_storage_deletions"    // files of deleted accounts still to be removed; a restore without it would leave them in storage for good
];

// CAN SKIP: state the system rebuilds by itself, or a log that matters only
// for a short time. Restoring one would be useless or harmful.
const SKIPPED_TABLES = {
  job_runs:          "scheduler claims and last-run times; every job writes its row again on its next run",
  ops_alerts:        "open-alert dedupe state; an alert still true is raised again by the next scan",
  radar_status:      "each radar's latest tick; rewritten every tick",
  youtube_api_calls: "the YouTube quota ledger; only today's rows mean anything, and Google resets the quota daily",
  engine_visits:     "a traffic log of arrivals from radar replies; a metric, not anyone's work or money",
  usage_logs:        "legacy usage log; nothing reads or writes it",
  backup_runs:       "the history of these backups; each backup is its own record"
};

// EXCLUDE: must not leave the database, even encrypted. Each is a credential or
// a security token; after a restore, people sign in again or re-enter them.
const EXCLUDED_TABLES = {
  auth_sessions:       "sign-in sessions (refresh-token hashes); a restore signs everyone out, which is the safe outcome",
  webauthn_challenges: "single-use passkey challenges that expire in minutes",
  user_api_keys:       "users' own provider API keys (bring-your-own-key); users re-enter them",
  push_subscriptions:  "browser push credentials (endpoint, p256dh, auth); browsers re-subscribe on the next visit"
};

// Tables whose id comes from a sequence (bigserial or identity). A restore
// inserts the old ids, which leaves the sequence behind them; restoreBackup.js
// prints the setval for each so the next insert does not collide.
const SEQUENCE_TABLES = ["model_calls", "testimonial_screen_removals", "oracle_messages"];

// ── The file ─────────────────────────────────────────────────────────────────
const FORMAT = "bizforce-backup";
const FORMAT_VERSION = 2;
const CIPHER = "aes-256-gcm";
const MAGIC = Buffer.from("BFBK", "ascii");
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

// Resend accepts at most 40 MB per email, attachments counted AFTER base64
// encoding. Base64 is 4/3, so a 25 MiB part is 34.95 MB on the wire, leaving
// 5 MB for the text and headers. A bigger backup becomes more parts, one email
// each; it is never truncated to fit.
const RESEND_EMAIL_LIMIT_BYTES = 40 * 1000 * 1000;
const PART_MAX_BYTES = 25 * 1024 * 1024;

// What one units[] entry adds to a header: table name, chunk numbers, row
// count and a 64-character sha256, with room to spare.
const UNIT_HEADER_BYTES = 256;

// Rows per request. PostgREST caps a response at its own max-rows regardless of
// what the range asks for, which is precisely why the count is checked against
// what actually arrived rather than assumed from the range that was requested.
const PAGE_SIZE = 1000;

// Matches sendEmail's sending identity (server.js:1330). One sender, so the
// reputation this mail accrues is the same reputation everything else accrues,
// rather than a second identity nobody is watching.
const FROM_EMAIL = "BizForce AI <hello@mail.bizforceai.net>";

// The tag every failure line carries. One distinctive string to search Railway
// logs for, so "did last night's backup actually send" is a single query and not
// an exercise in reading around a successful-looking log.
const FAIL = "[NightlyBackup][FAILED]";

// YYYY-MM-DD from an ISO timestamp. A named step because the filename is what
// someone reads when picking which of thirty attachments to restore.
function isoDate(iso) {
  return String(iso).slice(0, 10);
}

function errorText(error) {
  return String((error && error.message) || error);
}

function backupError(code, message) {
  var error = new Error(message);
  error.code = code;
  return error;
}

function sha256Hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

/* BACKUP_ENCRYPTION_KEY: base64 of exactly 32 bytes. The problem text names
   what is wrong and never repeats the value. */
function parseBackupKey(raw) {
  var text = String(raw == null ? "" : raw).trim();
  if (!text) {
    return { ok: false, reason: "key_missing", problem: "BACKUP_ENCRYPTION_KEY is not set" };
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(text) || text.length % 4 !== 0) {
    return { ok: false, reason: "key_malformed", problem: "BACKUP_ENCRYPTION_KEY is not valid base64" };
  }
  var key = Buffer.from(text, "base64");
  if (key.length !== KEY_BYTES) {
    return { ok: false, reason: "key_malformed",
      problem: "BACKUP_ENCRYPTION_KEY decodes to " + key.length + " bytes; it must be exactly " + KEY_BYTES };
  }
  return { ok: true, key: key };
}

/* One part file: header in the clear (authenticated), rows encrypted. */
function sealPart(header, units, key, iv) {
  var headerBuf = Buffer.from(JSON.stringify(header), "utf8");
  var lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(headerBuf.length, 0);
  var aad = Buffer.concat([MAGIC, lenBuf, headerBuf]);
  var plain = zlib.gzipSync(Buffer.from(JSON.stringify({ units: units }), "utf8"));
  var cipher = crypto.createCipheriv(CIPHER, key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad);
  var ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([aad, cipher.getAuthTag(), ciphertext]);
}

/* The header of a part, read WITHOUT the key. Nothing in it is trusted until
   openPart has checked the auth tag. */
function readPartHeader(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < MAGIC.length + 4 || !buf.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw backupError("not_a_backup", "not a BizForce backup part (no BFBK header)");
  }
  var headerLen = buf.readUInt32BE(MAGIC.length);
  var headerEnd = MAGIC.length + 4 + headerLen;
  if (headerEnd + TAG_BYTES > buf.length) {
    throw backupError("not_a_backup", "the file is shorter than its header says: it was cut off");
  }
  var header;
  try {
    header = JSON.parse(buf.subarray(MAGIC.length + 4, headerEnd).toString("utf8"));
  } catch (error) {
    throw backupError("not_a_backup", "the header is not readable JSON");
  }
  if (!header || header.format !== FORMAT) throw backupError("not_a_backup", "not a BizForce backup part (format " + (header && header.format) + ")");
  if (header.version !== FORMAT_VERSION) throw backupError("unsupported_version", "backup format version " + header.version + "; this code reads version " + FORMAT_VERSION);
  if (header.cipher !== CIPHER) throw backupError("unsupported_version", "cipher " + header.cipher + "; this code reads " + CIPHER);
  return {
    header: header,
    aad: buf.subarray(0, headerEnd),
    tag: buf.subarray(headerEnd, headerEnd + TAG_BYTES),
    ciphertext: buf.subarray(headerEnd + TAG_BYTES)
  };
}

/* Decrypts and verifies ONE part: the auth tag (wrong key, or any byte of the
   file changed), then every unit's row count and sha256. Throws a coded error
   on the first thing that does not hold; returns only what was proven. */
function openPart(buf, key) {
  var p = readPartHeader(buf);
  var manifest = p.header.manifest || {};
  var label = "part " + manifest.part + " of " + manifest.parts;
  var iv = Buffer.from(String(p.header.iv || ""), "base64");
  if (iv.length !== IV_BYTES) throw backupError("not_a_backup", label + ": the IV is not " + IV_BYTES + " bytes");
  var decipher = crypto.createDecipheriv(CIPHER, key, iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(p.aad);
  decipher.setAuthTag(p.tag);
  var plain;
  try {
    plain = Buffer.concat([decipher.update(p.ciphertext), decipher.final()]);
  } catch (error) {
    throw backupError("auth_failed", label + " failed authentication: the key is wrong, or the file was altered");
  }
  var payload;
  try {
    payload = JSON.parse(zlib.gunzipSync(plain).toString("utf8"));
  } catch (error) {
    throw backupError("bad_payload", label + ": authenticated, but the contents do not unpack (" + errorText(error) + ")");
  }
  var units = manifest.units || [];
  if (!payload || !Array.isArray(payload.units) || payload.units.length !== units.length) {
    throw backupError("bad_payload", label + ": the contents do not match the manifest's " + units.length + " units");
  }
  var opened = [];
  for (var i = 0; i < units.length; i++) {
    var unit = units[i];
    var rows = payload.units[i];
    if (!Array.isArray(rows) || rows.length !== unit.rows) {
      throw backupError("count_mismatch", label + ": " + unit.table + " chunk " + unit.chunk + " holds " +
        (Array.isArray(rows) ? rows.length : "no") + " rows; the manifest says " + unit.rows);
    }
    if (sha256Hex(JSON.stringify(rows)) !== unit.sha256) {
      throw backupError("sha_mismatch", label + ": " + unit.table + " chunk " + unit.chunk + " does not match its sha256");
    }
    opened.push({ table: unit.table, chunk: unit.chunk, chunks: unit.chunks, rows: rows });
  }
  return { manifest: manifest, units: opened };
}

/* Opened parts back into whole tables. Every part must belong to one backup,
   every part number must be there once, every chunk of every table must be
   there, and each table must hold the rows the manifest counted. Problems are
   returned, not thrown, so a dry run can list all of them. */
function assembleParts(openedParts) {
  var problems = [];
  if (!openedParts.length) return { manifest: null, tables: new Map(), problems: ["no parts were given"] };
  var first = openedParts[0].manifest;
  var seen = new Map();
  openedParts.forEach(function (o) {
    if (o.manifest.backup_id !== first.backup_id) {
      problems.push("part " + o.manifest.part + " belongs to backup " + o.manifest.backup_id + ", not " + first.backup_id);
    } else if (seen.has(o.manifest.part)) {
      problems.push("part " + o.manifest.part + " was given twice");
    } else {
      seen.set(o.manifest.part, o);
    }
  });
  var missing = [];
  for (var n = 1; n <= first.parts; n++) if (!seen.has(n)) missing.push(n);
  if (missing.length) problems.push("parts missing: " + missing.join(", ") + " of " + first.parts);

  var chunks = new Map();
  Array.from(seen.keys()).sort(function (a, b) { return a - b; }).forEach(function (k) {
    seen.get(k).units.forEach(function (u) {
      if (!chunks.has(u.table)) chunks.set(u.table, []);
      chunks.get(u.table).push(u);
    });
  });
  var tables = new Map();
  Object.keys(first.tables || {}).forEach(function (name) {
    var info = first.tables[name];
    if (info.status === "ERROR") {
      problems.push(name + " was not captured by this backup (" + (info.error || "error") + ")");
      return;
    }
    var list = (chunks.get(name) || []).slice().sort(function (a, b) { return a.chunk - b.chunk; });
    var expectChunks = list.length ? list[0].chunks : null;
    var complete = expectChunks !== null && list.length === expectChunks &&
      list.every(function (u, i) { return u.chunk === i + 1 && u.chunks === expectChunks; });
    if (!complete) {
      if (!missing.length) problems.push(name + ": chunks are missing or repeated");
      return;
    }
    var rows = [];
    list.forEach(function (u) { rows = rows.concat(u.rows); });
    var expected = info.status === "INCOMPLETE" ? info.returned : info.rows;
    if (rows.length !== expected) {
      problems.push(name + ": " + rows.length + " rows in the parts; the manifest counted " + expected);
      return;
    }
    if (info.status === "INCOMPLETE") {
      problems.push(name + " is a PARTIAL copy: " + rows.length + " of " + info.rows + " rows were read that night");
    }
    tables.set(name, rows);
  });
  return { manifest: first, tables: tables, problems: problems };
}

/* Restore order: BACKUP_TABLES' order (parents first), then any table an older
   backup holds that the list no longer names. */
function restoreOrder(names) {
  var given = new Set(names);
  var ordered = BACKUP_TABLES.filter(function (t) { return given.has(t); });
  names.forEach(function (t) { if (ordered.indexOf(t) === -1) ordered.push(t); });
  return ordered;
}

function gzipLength(value) {
  return zlib.gzipSync(Buffer.from(JSON.stringify(value), "utf8")).length;
}

/* A table's rows as units no bigger than budget once gzipped. Too big: halved,
   and each half again, until every piece fits. Never shortened: a single row
   that cannot fit is an error, and the caller sends nothing. */
function splitRows(table, rows, budget) {
  if (gzipLength(rows) <= budget) return [rows];
  if (rows.length < 2) {
    throw backupError("row_too_large", "one row of " + table + " is larger than a part may be (" + budget +
      " bytes compressed); a second destination is needed for this backup");
  }
  var half = Math.ceil(rows.length / 2);
  return splitRows(table, rows.slice(0, half), budget).concat(splitRows(table, rows.slice(half), budget));
}

/* Captured tables to sealed parts, each at most limit bytes. */
function buildParts(opts) {
  var captured = opts.captured;   // [{ table, rows }] in BACKUP_TABLES order
  var limit = opts.limit;
  var base = {
    format: FORMAT, version: FORMAT_VERSION, cipher: CIPHER, iv: Buffer.alloc(IV_BYTES).toString("base64"),
    manifest: { backup_id: opts.backupId, created_at: opts.createdAt, commit: opts.commit,
      part: 99999, parts: 99999, units: [], tables: opts.tables }
  };
  // magic, length, tag, a header with no units, and the payload's JSON punctuation
  var fixed = MAGIC.length + 4 + TAG_BYTES + Buffer.byteLength(JSON.stringify(base), "utf8") + 64;
  var budget = limit - fixed - UNIT_HEADER_BYTES;
  if (budget <= 0) throw backupError("part_over_limit", "a part may be " + limit + " bytes, but its header alone needs " + fixed);

  var units = [];
  captured.forEach(function (c) {
    var pieces = splitRows(c.table, c.rows, budget);
    var kept = pieces.reduce(function (n, p) { return n + p.length; }, 0);
    if (kept !== c.rows.length) {
      throw backupError("truncated", c.table + ": " + kept + " of " + c.rows.length + " rows survived splitting; nothing is sent");
    }
    pieces.forEach(function (rows, i) {
      units.push({ table: c.table, chunk: i + 1, chunks: pieces.length, rows: rows, gz: gzipLength(rows) });
    });
  });

  var groups = [];
  var current = null;
  var used = 0;
  units.forEach(function (u) {
    var cost = u.gz + UNIT_HEADER_BYTES;
    if (current && used + cost > limit) { groups.push(current); current = null; }
    if (!current) { current = []; used = fixed; }
    current.push(u);
    used += cost;
  });
  if (current) groups.push(current);

  var randomBytes = opts.randomBytes || crypto.randomBytes;
  return groups.map(function (group, i) {
    var iv = randomBytes(IV_BYTES);
    var header = {
      format: FORMAT, version: FORMAT_VERSION, cipher: CIPHER, iv: iv.toString("base64"),
      manifest: {
        backup_id: opts.backupId, created_at: opts.createdAt, commit: opts.commit,
        part: i + 1, parts: groups.length,
        units: group.map(function (u) {
          return { table: u.table, chunk: u.chunk, chunks: u.chunks, rows: u.rows.length, sha256: sha256Hex(JSON.stringify(u.rows)) };
        }),
        tables: opts.tables
      }
    };
    var file = sealPart(header, group.map(function (u) { return u.rows; }), opts.key, iv);
    if (file.length > limit) {
      throw backupError("part_over_limit", "part " + (i + 1) + " came to " + file.length + " bytes, over the " + limit +
        "-byte limit; nothing is sent rather than a cut-down backup");
    }
    return { part: i + 1, parts: groups.length, file: file, units: header.manifest.units };
  });
}

/* Reads one table whole: an exact count first, then pages until the count is
   reached. Returns { rows, info } where info is the manifest's entry. */
async function readTable(supabase, name, log) {
  // ── The count comes first, and on its own ───────────────────────────────
  // head: true asks PostgREST for the count and NO ROWS AT ALL, so the count
  // the pages are checked against is taken before the first row is read.
  var headRes = await supabase.from(name).select("*", { count: "exact", head: true });
  if (headRes.error) {
    log.error(FAIL + " table " + name + " could not be counted — " + errorText(headRes.error) +
      ". Continuing with the remaining tables.");
    return { rows: [], info: { rows: null, status: "ERROR", error: errorText(headRes.error) } };
  }
  var count = (typeof headRes.count === "number") ? headRes.count : null;
  // No count means no way to prove the dump is whole, and a table that cannot
  // be verified must not be recorded as if it were. Nothing is fetched.
  if (count === null) {
    log.error(FAIL + " table " + name + " returned no exact count. Not fetched, because completeness could not be verified.");
    return { rows: [], info: { rows: null, status: "ERROR", error: "exact count unavailable" } };
  }

  // ── Pagination ──────────────────────────────────────────────────────────
  // The count stays the authority: it decides how many pages to ask for and it
  // is what the result is checked against, so a page that comes back short
  // cannot quietly end the loop and pass as complete.
  var rows = [];
  var pageErr = null;
  for (var offset = 0; offset < count; offset += PAGE_SIZE) {
    var pageRes = await supabase.from(name).select("*").range(offset, offset + PAGE_SIZE - 1);
    if (pageRes.error) {
      // A failed page does not abandon the table. What was already fetched is
      // kept and the table is marked INCOMPLETE.
      pageErr = errorText(pageRes.error);
      log.error(FAIL + " table " + name + " failed on the page starting at " + offset + " — " + pageErr +
        ". Keeping the " + rows.length + " rows already fetched and marking the table INCOMPLETE.");
      break;
    }
    var page = pageRes.data || [];
    rows = rows.concat(page);
    if (page.length < PAGE_SIZE) break;
  }

  // ── The reconciliation that makes this backup trustworthy ───────────────
  // Equal is the only thing that earns OK; anything else is recorded as a
  // partial copy rather than presented as a whole one.
  if (rows.length !== count) {
    log.error(FAIL + " table " + name + " accumulated " + rows.length + " rows but the exact count is " + count +
      ". Marked INCOMPLETE — the backup holds a PARTIAL copy of this table.");
    var info = { rows: count, status: "INCOMPLETE", returned: rows.length };
    if (pageErr) info.error = pageErr;
    return { rows: rows, info: info };
  }
  return { rows: rows, info: { rows: count, status: "OK" } };
}

function resendSender(apiKey) {
  var resend = new Resend(apiKey);
  return function (message) { return resend.emails.send(message); };
}

/* The run itself. Returns the result; runNightlyBackup records it. */
async function buildAndSend(deps, env, log, startedAt) {
  var supabase = deps.supabase;
  if (!supabase) {
    log.error(FAIL + " no supabase client was injected. Nothing was read and nothing was sent.");
    return { sent: false, reason: "no_supabase" };
  }

  // THE KEY COMES FIRST. A backup that cannot be encrypted is not built, so no
  // table is read and nothing can leave in the clear. There is no fallback.
  var keyInfo = parseBackupKey(env.BACKUP_ENCRYPTION_KEY);
  if (!keyInfo.ok) {
    log.error(FAIL + " " + keyInfo.problem + ". The backup was NOT built and NOT sent: a backup is never sent unencrypted. " +
      "Create a key with: node -e \"console.log(require('crypto').randomBytes(32).toString('base64'))\"");
    return { sent: false, reason: keyInfo.reason,
      alert: "Backup not encrypted: key " + (keyInfo.reason === "key_missing" ? "missing" : "malformed") };
  }

  // The destination is read here and nowhere else, and it is NOT a parameter.
  // A caller that could pass a destination is a caller that could get it wrong.
  // There is deliberately no fallback address.
  var toEmail = (env.BACKUP_EMAIL_TO || "").trim();
  if (!toEmail) {
    log.error(FAIL + " BACKUP_EMAIL_TO is not set. The backup was NOT built and NOT sent. " +
      "Set BACKUP_EMAIL_TO to the operator address that should receive the nightly dump. " +
      "There is no default and there will not be one.");
    return { sent: false, reason: "no_destination" };
  }

  // Same source as sendEmail (server.js:1340), same trim.
  var send = deps.send;
  if (!send) {
    var apiKey = (env.RESEND_API_KEY || "").trim();
    if (!apiKey) {
      log.error(FAIL + " RESEND_API_KEY is not set. The backup was NOT built and NOT sent.");
      return { sent: false, reason: "not_configured" };
    }
    send = resendSender(apiKey);
  }

  // ONE TABLE MUST NEVER END THE RUN. An unreadable table is a gap recorded
  // against its name; the other tables still go out, and the run is reported
  // as incomplete so the owner is told.
  var tables = {};
  var captured = [];
  var counts = {};
  var totalRows = 0;
  var incomplete = [];
  var errored = [];
  for (var i = 0; i < BACKUP_TABLES.length; i++) {
    var name = BACKUP_TABLES[i];
    var read;
    try {
      read = await readTable(supabase, name, log);
    } catch (error) {
      log.error(FAIL + " table " + name + " threw — " + errorText(error) + ". Continuing with the remaining tables.");
      read = { rows: [], info: { rows: null, status: "ERROR", error: errorText(error) } };
    }
    tables[name] = read.info;
    if (read.info.status === "ERROR") { errored.push(name); continue; }
    if (read.info.status === "INCOMPLETE") incomplete.push(name);
    captured.push({ table: name, rows: read.rows });
    counts[name] = read.rows.length;
    totalRows += read.rows.length;
  }

  var backupId = (deps.randomBytes || crypto.randomBytes)(8).toString("hex");
  var parts;
  try {
    parts = buildParts({
      captured: captured, tables: tables, key: keyInfo.key, limit: deps.partMaxBytes || PART_MAX_BYTES,
      backupId: backupId, createdAt: startedAt, commit: env.RAILWAY_GIT_COMMIT_SHA || null, randomBytes: deps.randomBytes
    });
  } catch (error) {
    log.error(FAIL + " the backup could not be packed — " + errorText(error) + ". NOTHING WAS SENT.");
    return { sent: false, reason: error.code || "pack_failed", error: errorText(error), counts: counts, totalRows: totalRows };
  }
  var bytes = parts.reduce(function (n, p) { return n + p.file.length; }, 0);

  // Said plainly in the subject so a partial backup is visible in a notification
  // preview, without opening the mail.
  var stem = "bizforce-backup-" + isoDate(startedAt) + "-" + backupId.slice(0, 8);
  var flags = (incomplete.length ? " — INCOMPLETE: " + incomplete.join(", ") : "") +
    (errored.length ? " — ERRORED: " + errored.join(", ") : "");
  for (var k = 0; k < parts.length; k++) {
    var part = parts[k];
    var filename = stem + "-part" + part.part + "of" + part.parts + ".bfbk";
    var summary =
      "Generated: " + startedAt + "\n" +
      "Backup id: " + backupId + "\n" +
      "This is part " + part.part + " of " + part.parts + " (" + part.file.length + " bytes). Keep every part.\n" +
      "Total rows in the backup: " + totalRows + " across " + captured.length + " tables\n" +
      "INCOMPLETE: " + (incomplete.join(", ") || "none") + "\n" +
      "ERRORED: " + (errored.join(", ") || "none") + "\n\n" +
      "Tables in this part:\n" +
      part.units.map(function (u) {
        return "  " + u.table + (u.chunks > 1 ? " (chunk " + u.chunk + " of " + u.chunks + ")" : "") + ": " + u.rows + " rows";
      }).join("\n") + "\n\n" +
      "Encrypted with AES-256-GCM under BACKUP_ENCRYPTION_KEY, which is not in this email.\n" +
      "Restore with scripts/restoreBackup.js in the backend repo (--dry-run first).\n" +
      "Schema is not in this file. It lives in supabase/migrations/ in the backend repo.\n" +
      "Supabase Storage objects (bf-books, bf-public) are NOT covered by this backup.";
    var result;
    try {
      // No List-Unsubscribe headers here, and the note at the top of this file
      // is the whole reason why.
      result = await send({
        from: FROM_EMAIL,
        to: toEmail,
        subject: "BizForce backup " + isoDate(startedAt) + " — " + totalRows + " rows — part " + part.part + " of " + part.parts + flags,
        text: summary,
        attachments: [{ filename: filename, content: part.file.toString("base64") }]
      });
    } catch (error) {
      log.error(FAIL + " the Resend call for part " + part.part + " of " + part.parts + " threw — " + errorText(error) +
        ". " + k + " of " + parts.length + " parts were delivered; this backup is NOT whole.");
      return { sent: false, reason: "provider_threw", error: errorText(error), backupId: backupId, parts: parts.length, partsSent: k, counts: counts, totalRows: totalRows };
    }
    // The SDK reports provider-side rejection on the returned object instead of
    // throwing (server.js:1494-1499). Read the result.
    if (result && result.error) {
      log.error(FAIL + " Resend rejected part " + part.part + " of " + part.parts + " — " + errorText(result.error) +
        ". " + k + " of " + parts.length + " parts were delivered; this backup is NOT whole.");
      return { sent: false, reason: "provider_error", error: errorText(result.error), backupId: backupId, parts: parts.length, partsSent: k, counts: counts, totalRows: totalRows };
    }
    if (!(result && result.data && result.data.id)) {
      log.error(FAIL + " Resend returned neither a message id nor an error for part " + part.part + " of " + part.parts +
        ", so there is no evidence it was accepted. Treating the backup as NOT sent.");
      return { sent: false, reason: "no_provider_id", backupId: backupId, parts: parts.length, partsSent: k, counts: counts, totalRows: totalRows };
    }
  }

  // The byte size is on the success line on purpose: an absurdly small backup
  // stays invisible unless the number is printed next to the word sent.
  log.log("[NightlyBackup] Sent " + stem + " to " + toEmail + " — " + totalRows + " rows across " + captured.length +
    " tables, " + parts.length + " part(s), " + bytes + " bytes encrypted." + flags.replace(/ — /g, " "));

  return {
    sent: true,
    complete: incomplete.length === 0 && errored.length === 0,
    backupId: backupId,
    parts: parts.length,
    bytes: bytes,
    totalRows: totalRows,
    counts: counts,
    incomplete: incomplete,
    errored: errored
  };
}

/* One row in backup_runs per run, whatever happened. Never throws: a backup
   that ran is not undone because its record could not be written. */
async function recordRun(supabase, result, startedAt, finishedAt, commit, log) {
  if (!supabase) return;
  try {
    var written = await supabase.from("backup_runs").insert({
      started_at: startedAt,
      finished_at: finishedAt,
      ok: !!(result.sent && result.complete),
      sent: !!result.sent,
      reason: result.sent ? (result.complete ? null : "incomplete") : (result.reason || "unknown"),
      error: result.error ? String(result.error).slice(0, 2000) : null,
      backup_id: result.backupId || null,
      parts: result.parts || null,
      bytes: result.bytes || null,
      total_rows: typeof result.totalRows === "number" ? result.totalRows : null,
      counts: result.counts || {},
      problems: { incomplete: result.incomplete || [], errored: result.errored || [] },
      commit: commit || null
    });
    if (written && written.error) log.error(FAIL + " could not record the run in backup_runs: " + errorText(written.error));
  } catch (error) {
    log.error(FAIL + " could not record the run in backup_runs: " + errorText(error));
  }
}

/* deps: { supabase, env?, send?, now?, log?, partMaxBytes?, randomBytes? }.
   Never throws; every run is recorded in backup_runs. */
async function runNightlyBackup(deps) {
  deps = deps || {};
  var env = deps.env || process.env;
  var log = deps.log || console;
  var now = deps.now || Date.now;
  var startedAt = new Date(now()).toISOString();
  var result;
  try {
    result = await buildAndSend(deps, env, log, startedAt);
  } catch (error) {
    log.error(FAIL + " the run threw — " + errorText(error) + ".");
    result = { sent: false, reason: "threw", error: errorText(error) };
  }
  await recordRun(deps.supabase, result, startedAt, new Date(now()).toISOString(), env.RAILWAY_GIT_COMMIT_SHA, log);
  return result;
}

module.exports = {
  runNightlyBackup,
  parseBackupKey,
  sealPart,
  readPartHeader,
  openPart,
  assembleParts,
  restoreOrder,
  buildParts,
  BACKUP_TABLES,
  SKIPPED_TABLES,
  EXCLUDED_TABLES,
  SEQUENCE_TABLES,
  PART_MAX_BYTES,
  RESEND_EMAIL_LIMIT_BYTES,
  FORMAT_VERSION,
  CIPHER
};
