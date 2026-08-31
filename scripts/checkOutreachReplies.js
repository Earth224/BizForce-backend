/* checkOutreachReplies.js — manually run, read-only.
 *
 *   node scripts/checkOutreachReplies.js
 *
 * Answers one question: did any outreach reply we posted to Bluesky get a
 * human answer? It reads outreach_sends, fetches each reply's thread from
 * Bluesky, and counts direct replies whose author is not us.
 *
 * Read-only by construction: the only Supabase call is a select, and there is
 * no insert, update, upsert or delete anywhere in this file. Nothing is
 * written to disk and no Anthropic call is made. It registers no timer, cron
 * or route — it runs once, prints, and exits.
 *
 * Never printed: SUPABASE_SERVICE_KEY, BLUESKY_APP_PASSWORD, the accessJwt, or
 * our own did. Handles and post text are printed, since that is the report.
 */

require("dotenv").config();

const { createClient } = require("@supabase/supabase-js");

const BSKY_BASE = "https://bsky.social";
const THREAD_DEPTH = 2;
const REQUEST_SPACING_MS = 1000;
const TEXT_PREVIEW_CHARS = 100;

function sleep(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

/* Names only, never values — this runs in a terminal whose scrollback is not a
   secret store. */
function missingEnvNames() {
  const required = [
    "SUPABASE_URL",
    "SUPABASE_SERVICE_KEY",
    "BLUESKY_IDENTIFIER",
    "BLUESKY_APP_PASSWORD"
  ];
  return required.filter(function (name) {
    const value = process.env[name];
    return typeof value !== "string" || value.trim() === "";
  });
}

/* Post text is free-form and may contain newlines, which would break one row of
   the report across several lines and make the output hard to scan. */
function previewText(text) {
  if (typeof text !== "string") return "(no text)";
  const flat = text.replace(/\s+/g, " ").trim();
  if (flat.length <= TEXT_PREVIEW_CHARS) return flat;
  return flat.slice(0, TEXT_PREVIEW_CHARS) + "…";
}

function formatSentAt(sentAt) {
  if (!sentAt) return "(no sent_at)";
  const parsed = new Date(sentAt);
  if (isNaN(parsed.getTime())) return String(sentAt);
  return parsed.toISOString();
}

async function createSession() {
  const response = await fetch(BSKY_BASE + "/xrpc/com.atproto.server.createSession", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      identifier: process.env.BLUESKY_IDENTIFIER,
      password: process.env.BLUESKY_APP_PASSWORD
    })
  });

  const body = await response.text();

  if (!response.ok) {
    console.error("Bluesky authentication failed — HTTP " + response.status);
    console.error(body);
    process.exit(1);
  }

  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (parseError) {
    console.error("Bluesky authentication returned unparseable JSON — HTTP " + response.status);
    console.error(body);
    process.exit(1);
  }

  if (!parsed.accessJwt || !parsed.did) {
    console.error("Bluesky authentication returned no accessJwt or did — HTTP " + response.status);
    console.error(body);
    process.exit(1);
  }

  return parsed;
}

/* Returns { ok, thread, reason }. A missing, deleted or blocked thread is a
   normal outcome for this report, not an error: the reply may have been taken
   down by its author or the whole account blocked us since we sent it. */
async function fetchThread(uri, accessJwt) {
  const url = BSKY_BASE + "/xrpc/app.bsky.feed.getPostThread" +
    "?uri=" + encodeURIComponent(uri) +
    "&depth=" + THREAD_DEPTH;

  let response;
  try {
    response = await fetch(url, {
      headers: { Authorization: "Bearer " + accessJwt }
    });
  } catch (networkError) {
    return {
      ok: false,
      reason: "request failed: " + (networkError && networkError.message ? networkError.message : networkError)
    };
  }

  const body = await response.text();

  if (!response.ok) {
    // NotFound comes back as a 400 with an error code, not as an empty 200.
    return { ok: false, reason: "HTTP " + response.status + " " + previewText(body) };
  }

  let parsed;
  try {
    parsed = JSON.parse(body);
  } catch (parseError) {
    return { ok: false, reason: "unparseable JSON response" };
  }

  const thread = parsed.thread;
  if (!thread || !thread.post) {
    // notFoundPost and blockedPost carry no .post at all.
    return { ok: false, reason: thread && thread.$type ? String(thread.$type) : "no thread in response" };
  }

  return { ok: true, thread: thread };
}

async function main() {
  const missing = missingEnvNames();
  if (missing.length > 0) {
    console.error("Missing required environment variable(s): " + missing.join(", "));
    process.exit(1);
  }

  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_KEY,
    {
      auth: {
        persistSession: false
      }
    }
  );

  const { data: rows, error: sendsError } = await supabase
    .from("outreach_sends")
    .select("id, user_id, lead_post_uri, source, platform_uri, sent_at")
    .not("platform_uri", "is", null)
    .order("sent_at", { ascending: true });

  if (sendsError) {
    console.error("outreach_sends query failed: " +
      (sendsError.message || sendsError) +
      " details=" + (sendsError.details || "none") +
      " hint=" + (sendsError.hint || "none") +
      " code=" + (sendsError.code || "none"));
    process.exit(1);
  }

  const sends = rows || [];

  if (sends.length === 0) {
    console.log("No outreach_sends rows have a platform_uri — nothing to check.");
    process.exit(0);
  }

  console.log("Checking " + sends.length + " outreach reply/replies for human answers.");
  console.log("");

  const session = await createSession();
  const ourDid = session.did;

  let answered = 0;
  let unavailable = 0;

  for (let i = 0; i < sends.length; i++) {
    const row = sends[i];

    if (i > 0) await sleep(REQUEST_SPACING_MS);

    const header = "[" + (i + 1) + "/" + sends.length + "] " +
      formatSentAt(row.sent_at) + "  source=" + (row.source || "(none)");

    const result = await fetchThread(row.platform_uri, session.accessJwt);

    if (!result.ok) {
      unavailable++;
      console.log(header);
      console.log("    lead: " + (row.lead_post_uri || "(none)"));
      console.log("    NOT FOUND OR DELETED (" + result.reason + ")");
      console.log("");
      continue;
    }

    const post = result.thread.post;
    const replies = Array.isArray(result.thread.replies) ? result.thread.replies : [];

    // Our own reply shows up in its own thread's replies when we replied to
    // ourselves; anything authored by ourDid is not a human answer to us.
    // Entries with no .post are notFound/blocked children and cannot be
    // attributed to anyone, so they do not count either.
    const humanReplies = replies.filter(function (child) {
      return child && child.post && child.post.author && child.post.author.did !== ourDid;
    });

    if (humanReplies.length > 0) answered++;

    console.log(header);
    console.log("    lead: " + (row.lead_post_uri || "(none)"));
    console.log("    our reply: replyCount=" + (post.replyCount || 0) +
      " likeCount=" + (post.likeCount || 0));
    console.log("    human answers: " + humanReplies.length);

    for (let j = 0; j < humanReplies.length; j++) {
      const child = humanReplies[j];
      const handle = child.post.author.handle || "(unknown handle)";
      const text = child.post.record ? child.post.record.text : null;
      console.log("      @" + handle + ": " + previewText(text));
    }

    console.log("");
  }

  console.log("---");
  console.log("Rows checked: " + sends.length +
    " | with at least one human reply: " + answered +
    " | not found or deleted: " + unavailable);
}

main().catch(function (error) {
  console.error("checkOutreachReplies failed: " +
    (error && error.stack ? error.stack : error));
  process.exit(1);
});
