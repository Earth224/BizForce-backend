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

const zlib = require("zlib");
const { Resend } = require("resend");

// Every table worth keeping. Three are deliberately absent:
//
//   ai_tasks, agent_memory, bsky_leads
//
// All three are high-volume and regenerable — a task queue, accumulated agent
// scratch memory, and scraped lead records the radars re-derive. Backing them up
// would dominate the attachment size while protecting data that costs nothing
// but time to reproduce. Their absence is a decision, not an oversight; if one
// of them ever holds something irreplaceable, move that thing out of this list's
// blind spot rather than quietly widening the list.
const BACKUP_TABLES = [
  "sales_lead_pipeline",
  "ai_reports",
  "oracle_messages",
  "ai_agents",
  "agent_collaborations",
  "profiles",
  "users",
  "agent_proposals",
  "sms_send_log",
  "marketplace_listings",
  "bizbooks",
  "cover_wraps",
  "user_wallets",
  "email_sends",
  "bizdoc_documents",
  "content_library",
  "wallet_transactions",
  "sms_campaigns",
  "outreach_sends",
  "contacts",
  "inner_iq_results",
  "subscriptions",
  "business_profiles",
  "bf_profiles",
  "profile_products",
  "profile_portfolio",
  "digital_cards",
  "sms_subscribers",
  "sms_campaign_messages",
  "sms_campaign_enrollments",
  "oracle_sync",
  "user_preferences",
  "marketplace_orders",
  "crowdfunding_campaigns",
  "bizdoc_signatures",
  "job_runs",
  "agent_autonomy",
  "consent_events",
  "agent_assignments",
  "bf_videos",
  "bf_music_tracks",
  "user_certifications",
  "revenue_events",
  "birth_records",
  "campaign_donations",
  "automation_queue",
  "posts",
  "usage_logs",
  "deals",
  "messages",
  "calendar_events",
  "push_subscriptions",
  "businesses",
  "social_post_drafts",
  "chat_messages",
  "follows",
  "profile_music",
  "profile_videos",
  "lead_captures",
  "user_api_keys",
  "tasks",
  "notifications",
  "analytics_events"
];

// Above this, a table is skipped rather than partially captured. A truncated
// table recorded as if whole is worse than an honest gap.
const ROW_CAP = 2000;

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

async function runNightlyBackup({ supabase }) {
  var generatedAt = new Date().toISOString();

  if (!supabase) {
    console.error(FAIL + " no supabase client was injected. Nothing was read and nothing was sent.");
    return { sent: false, reason: "no_supabase" };
  }

  // The destination is read here and nowhere else, and it is NOT a parameter.
  // A caller that could pass a destination is a caller that could get it wrong.
  // There is deliberately no fallback address: mailing a database dump to a
  // hardcoded default would be considerably worse than not mailing it at all.
  var toEmail = (process.env.BACKUP_EMAIL_TO || "").trim();
  if (!toEmail) {
    console.error(FAIL + " BACKUP_EMAIL_TO is not set. The backup was NOT built and NOT sent. " +
      "Set BACKUP_EMAIL_TO to the operator address that should receive the nightly dump. " +
      "There is no default and there will not be one.");
    return { sent: false, reason: "no_destination" };
  }

  // Same source as sendEmail (server.js:1340), same trim, so a key carrying a
  // stray newline behaves identically in both paths.
  var apiKey = (process.env.RESEND_API_KEY || "").trim();
  if (!apiKey) {
    console.error(FAIL + " RESEND_API_KEY is not set. The backup was NOT built and NOT sent.");
    return { sent: false, reason: "not_configured" };
  }

  var tables    = {};
  var manifest  = {};
  var totalRows = 0;

  var incomplete = [];
  var skipped    = [];
  var errored    = [];

  for (var i = 0; i < BACKUP_TABLES.length; i++) {
    var name = BACKUP_TABLES[i];

    // ONE TABLE MUST NEVER END THE RUN. A table dropped by a migration, renamed,
    // or unreadable is a gap in this backup — not a reason to abandon the other
    // sixty. The error string is recorded against the table so the manifest says
    // which are missing and why, and the mail still goes out.
    try {
      // ── The count comes first, and on its own ───────────────────────────────
      // head: true asks PostgREST for the count and NO ROWS AT ALL. That is what
      // makes the size check below free: an oversize table is identified and
      // skipped without a single row crossing the wire, so the cap costs one
      // cheap request rather than a partial download that is then thrown away.
      var headRes = await supabase
        .from(name)
        .select("*", { count: "exact", head: true });

      if (headRes.error) {
        tables[name]   = [];
        manifest[name] = {
          count:  null,
          status: "ERROR",
          error:  String((headRes.error && headRes.error.message) || headRes.error)
        };
        errored.push(name);
        console.error(FAIL + " table " + name + " could not be counted — " +
          ((headRes.error && headRes.error.message) || headRes.error) +
          ". Continuing with the remaining tables.");
        continue;
      }

      var count = (typeof headRes.count === "number") ? headRes.count : null;

      // No count means no way to prove the dump is whole, and a table that cannot
      // be verified must not be recorded as if it were. Nothing is fetched.
      if (count === null) {
        tables[name]   = [];
        manifest[name] = {
          count:  null,
          status: "ERROR",
          error:  "exact count unavailable; refusing to claim a completeness that cannot be checked"
        };
        errored.push(name);
        console.error(FAIL + " table " + name + " returned no exact count. " +
          "Not fetched, because completeness could not be verified.");
        continue;
      }

      // ── The cap, evaluated BEFORE the first row is fetched ──────────────────
      // Skipped rather than truncated, and nothing is read, so an oversize table
      // costs exactly the head request above and no data transfer.
      if (count > ROW_CAP) {
        tables[name]   = [];
        manifest[name] = { count: count, status: "SKIPPED_TOO_LARGE" };
        skipped.push(name);
        console.error(FAIL + " table " + name + " has " + count + " rows, over the " +
          ROW_CAP + " cap. SKIPPED before any read — this table is NOT in tonight's backup.");
        continue;
      }

      // ── Pagination ──────────────────────────────────────────────────────────
      // Ranges of PAGE_SIZE until the accumulated rows reach the count taken
      // above. The count from the head request stays the authority throughout: it
      // decides how many pages to ask for and it is what the result is checked
      // against, so a page that comes back short cannot quietly end the loop and
      // pass as complete.
      var rows     = [];
      var pageErr  = null;

      for (var offset = 0; offset < count; offset += PAGE_SIZE) {
        var pageRes = await supabase
          .from(name)
          .select("*")
          .range(offset, offset + PAGE_SIZE - 1);

        if (pageRes.error) {
          // A failed page does not abandon the table. What was already fetched is
          // kept and the table is marked INCOMPLETE, so the backup holds the rows
          // it managed to read and says plainly that it holds only some of them.
          pageErr = String((pageRes.error && pageRes.error.message) || pageRes.error);
          console.error(FAIL + " table " + name + " failed on the page starting at " +
            offset + " — " + pageErr + ". Keeping the " + rows.length +
            " rows already fetched and marking the table INCOMPLETE.");
          break;
        }

        var page = pageRes.data || [];
        rows = rows.concat(page);

        // A short page before the count is reached means there is no more to be
        // had from this range walk. Stopping here rather than looping on an empty
        // range; the length check below is what turns it into INCOMPLETE.
        if (page.length < PAGE_SIZE) {
          break;
        }
      }

      // ── The reconciliation that makes this backup trustworthy ───────────────
      // Accumulated length against the authoritative count. Equal is the only
      // thing that earns OK; anything else is recorded as a partial copy rather
      // than presented as a whole one.
      if (rows.length !== count) {
        tables[name]   = rows;
        manifest[name] = {
          count:    count,
          status:   "INCOMPLETE",
          returned: rows.length
        };
        if (pageErr) { manifest[name].error = pageErr; }
        incomplete.push(name);
        totalRows += rows.length;
        console.error(FAIL + " table " + name + " accumulated " + rows.length +
          " rows but the exact count is " + count + ". Marked INCOMPLETE — " +
          "the attachment holds a PARTIAL copy of this table.");
        continue;
      }

      tables[name]   = rows;
      manifest[name] = { count: count, status: "OK" };
      totalRows += rows.length;
    } catch (error) {
      tables[name]   = [];
      manifest[name] = {
        count:  null,
        status: "ERROR",
        error:  String((error && error.message) || error)
      };
      errored.push(name);
      console.error(FAIL + " table " + name + " threw — " +
        ((error && error.message) || error) + ". Continuing with the remaining tables.");
    }
  }

  var payload = {
    generated_at: generatedAt,
    tables:       tables,
    manifest:     manifest
  };

  var gz;
  try {
    gz = zlib.gzipSync(Buffer.from(JSON.stringify(payload), "utf8"));
  } catch (error) {
    console.error(FAIL + " could not serialise or gzip the backup — " +
      ((error && error.message) || error) + ". NOTHING WAS SENT.");
    return { sent: false, reason: "gzip_failed" };
  }

  var filename = "bizforce-backup-" + isoDate(generatedAt) + ".json.gz";

  // Said plainly in the subject so a partial backup is visible in a notification
  // preview, without opening the mail or the attachment.
  var subject = "BizForce backup " + isoDate(generatedAt) + " — " + totalRows + " rows";
  if (skipped.length)    { subject += " — SKIPPED: " + skipped.join(", "); }
  if (incomplete.length) { subject += " — INCOMPLETE: " + incomplete.join(", "); }
  if (errored.length)    { subject += " — ERRORED: " + errored.join(", "); }

  var summary =
    "Generated: " + generatedAt + "\n" +
    "Tables attempted: " + BACKUP_TABLES.length + "\n" +
    "Total rows captured: " + totalRows + "\n" +
    "Compressed size: " + gz.length + " bytes\n" +
    "SKIPPED_TOO_LARGE: " + (skipped.join(", ") || "none") + "\n" +
    "INCOMPLETE: " + (incomplete.join(", ") || "none") + "\n" +
    "ERRORED: " + (errored.join(", ") || "none") + "\n\n" +
    "Schema is not in this file. It lives in supabase/migrations/ in the backend repo.\n" +
    "Supabase Storage objects (bf-books, bf-public) are NOT covered by this backup.";

  var result;
  try {
    var resend = new Resend(apiKey);

    result = await resend.emails.send({
      from:    FROM_EMAIL,
      to:      toEmail,
      subject: subject,
      text:    summary,
      // No List-Unsubscribe headers here, and the note at the top of this file is
      // the whole reason why: their absence is what keeps a mailbox provider from
      // being able to switch the backups off.
      attachments: [
        {
          filename: filename,
          content:  gz.toString("base64")
        }
      ]
    });
  } catch (error) {
    console.error(FAIL + " the Resend call threw — " +
      ((error && error.message) || error) + ". The backup was built (" +
      gz.length + " bytes) but NOT delivered.");
    return { sent: false, reason: "provider_threw" };
  }

  // THE FAILURE MODE THIS BLOCK EXISTS FOR. The SDK reports provider-side
  // rejection on the returned object instead of throwing, exactly as sendEmail
  // notes at server.js:1494-1499. A run that only try/catches would read a
  // rejected send as a successful one and log a clean night. Read the result.
  if (result && result.error) {
    console.error(FAIL + " Resend rejected the message — " +
      ((result.error && result.error.message) || String(result.error)) +
      ". The backup was built (" + gz.length + " bytes) but NOT delivered.");
    return { sent: false, reason: "provider_error" };
  }

  var providerId = (result && result.data && result.data.id) || null;
  if (!providerId) {
    console.error(FAIL + " Resend returned neither a message id nor an error, so " +
      "there is no evidence the backup was accepted. Treating as NOT sent. " +
      "The backup was built (" + gz.length + " bytes).");
    return { sent: false, reason: "no_provider_id" };
  }

  // The byte size is on the success line on purpose. An empty or absurdly small
  // attachment is the shape of a backup that ran, sent, and holds nothing — and
  // that stays invisible unless the number is printed next to the word sent.
  console.log("[NightlyBackup] Sent " + filename + " to " + toEmail + " — " +
    totalRows + " rows across " + BACKUP_TABLES.length + " tables, " +
    gz.length + " bytes gzipped, provider id " + providerId + "." +
    (skipped.length    ? " SKIPPED: " + skipped.join(", ") + "." : "") +
    (incomplete.length ? " INCOMPLETE: " + incomplete.join(", ") + "." : "") +
    (errored.length    ? " ERRORED: " + errored.join(", ") + "." : ""));

  return {
    sent:       true,
    bytes:      gz.length,
    totalRows:  totalRows,
    skipped:    skipped,
    incomplete: incomplete,
    errored:    errored
  };
}

module.exports = { runNightlyBackup };
