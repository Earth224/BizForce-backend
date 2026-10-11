/* checkOutreachReplies.js — read-only; runs on RECORDED FIXTURES by default.
 *
 *   node scripts/checkOutreachReplies.js                          fixtures, no network
 *   CHECK_LIVE_BLUESKY=true node scripts/checkOutreachReplies.js  the live account
 *
 * Answers one question: did any outreach reply we posted to Bluesky get a
 * human answer? It reads outreach_sends, fetches each reply's thread from
 * Bluesky, and counts direct replies whose author is not us.
 *
 * BY DEFAULT THERE IS NO NETWORK AT ALL. The suite runs every check*.js, and a
 * live login on every suite run was hammering the one Bluesky account the Lead
 * Radar captures with (eight HTTP 429s in one day). So by default the same
 * counting logic runs against recorded answers in the real shapes — a
 * createSession answer, getPostThread answers (a thread with a human reply, one
 * with only our own, a NotFound 400, a notFoundPost) and outreach_sends rows —
 * through a stubbed fetch, and the counts are ASSERTED: a wrong count fails
 * the check. Neither Bluesky nor Supabase is contacted.
 *
 * A LIVE RUN happens only when CHECK_LIVE_BLUESKY is exactly "true". It logs
 * in once (one createSession), then reads each thread a second apart — the
 * report it always produced, against the real account.
 *
 * Read-only by construction: the only Supabase call (live only) is a select,
 * and there is no insert, update, upsert or delete anywhere in this file.
 * Nothing is written to disk and no Anthropic call is made. It registers no
 * timer, cron or route — it runs once, prints, and exits.
 *
 * Never printed: SUPABASE_SERVICE_KEY, BLUESKY_APP_PASSWORD, the accessJwt, or
 * our own did. Handles and post text are printed, since that is the report.
 */

require("dotenv").config();

const LIVE = process.env.CHECK_LIVE_BLUESKY === "true";

const BSKY_BASE = "https://bsky.social";
const THREAD_DEPTH = 2;
const REQUEST_SPACING_MS = LIVE ? 1000 : 0;
const TEXT_PREVIEW_CHARS = 100;

function sleep(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

/* ── the recorded answers (fixture mode) ───────────────────────────────────── */
const OUR_DID = "did:plc:fixtureourselves0000000";
const FIXTURE_SENDS = [
  { id: 1, user_id: "fixture-owner", lead_post_uri: "at://did:plc:lead1/app.bsky.feed.post/1", source: "bluesky",
    platform_uri: "at://" + OUR_DID + "/app.bsky.feed.post/answered", sent_at: "2026-09-01T10:00:00.000Z" },
  { id: 2, user_id: "fixture-owner", lead_post_uri: "at://did:plc:lead2/app.bsky.feed.post/2", source: "bluesky",
    platform_uri: "at://" + OUR_DID + "/app.bsky.feed.post/only-ours", sent_at: "2026-09-02T10:00:00.000Z" },
  { id: 3, user_id: "fixture-owner", lead_post_uri: "at://did:plc:lead3/app.bsky.feed.post/3", source: "bluesky",
    platform_uri: "at://" + OUR_DID + "/app.bsky.feed.post/deleted", sent_at: "2026-09-03T10:00:00.000Z" },
  { id: 4, user_id: "fixture-owner", lead_post_uri: "at://did:plc:lead4/app.bsky.feed.post/4", source: "bluesky",
    platform_uri: "at://" + OUR_DID + "/app.bsky.feed.post/blocked", sent_at: "2026-09-04T10:00:00.000Z" }
];
function threadPost(uri, did, handle, text, replyCount) {
  return { uri: uri, cid: "bafyfixture", author: { did: did, handle: handle }, record: { $type: "app.bsky.feed.post", text: text, createdAt: "2026-09-05T00:00:00.000Z" },
    replyCount: replyCount, likeCount: 0, repostCount: 0, indexedAt: "2026-09-05T00:00:00.000Z" };
}
const FIXTURE_THREADS = {};
FIXTURE_THREADS[FIXTURE_SENDS[0].platform_uri] = { status: 200, body: { thread: {
  $type: "app.bsky.feed.defs#threadViewPost",
  post: threadPost(FIXTURE_SENDS[0].platform_uri, OUR_DID, "us.bsky.social", "Our reply", 2),
  replies: [
    { $type: "app.bsky.feed.defs#threadViewPost", post: threadPost("at://did:plc:human/app.bsky.feed.post/a", "did:plc:human", "human.bsky.social", "Thanks, that helped", 0), replies: [] },
    { $type: "app.bsky.feed.defs#threadViewPost", post: threadPost("at://" + OUR_DID + "/app.bsky.feed.post/b", OUR_DID, "us.bsky.social", "Our follow-up", 0), replies: [] },
    { $type: "app.bsky.feed.defs#notFoundPost", uri: "at://did:plc:gone/app.bsky.feed.post/c", notFound: true }
  ] } } };
FIXTURE_THREADS[FIXTURE_SENDS[1].platform_uri] = { status: 200, body: { thread: {
  $type: "app.bsky.feed.defs#threadViewPost",
  post: threadPost(FIXTURE_SENDS[1].platform_uri, OUR_DID, "us.bsky.social", "Our reply", 1),
  replies: [{ $type: "app.bsky.feed.defs#threadViewPost", post: threadPost("at://" + OUR_DID + "/app.bsky.feed.post/d", OUR_DID, "us.bsky.social", "Ours again", 0), replies: [] }] } } };
FIXTURE_THREADS[FIXTURE_SENDS[2].platform_uri] = { status: 400, body: { error: "NotFound", message: "Post not found: " + FIXTURE_SENDS[2].platform_uri } };
FIXTURE_THREADS[FIXTURE_SENDS[3].platform_uri] = { status: 200, body: { thread: { $type: "app.bsky.feed.defs#notFoundPost", uri: FIXTURE_SENDS[3].platform_uri, notFound: true } } };
// What the fixtures must count, the same way the live run counts.
const FIXTURE_EXPECTED = { rows: 4, answered: 1, unavailable: 2, humanRepliesPerRow: [1, 0, null, null] };

const fixtureCalls = { createSession: 0, getPostThread: 0 };
function fixtureResponse(status, body) {
  const text = JSON.stringify(body);
  return Promise.resolve({ ok: status >= 200 && status < 300, status: status, text: function () { return Promise.resolve(text); } });
}
// The stubbed fetch: answers only the two calls this script makes, from the recordings.
function fixtureFetch(url, init) {
  const u = String(url);
  if (u === BSKY_BASE + "/xrpc/com.atproto.server.createSession" && init && init.method === "POST") {
    fixtureCalls.createSession++;
    return fixtureResponse(200, { accessJwt: "fixture-access-jwt", refreshJwt: "fixture-refresh-jwt", handle: "us.bsky.social", did: OUR_DID, active: true });
  }
  const m = u.match(/^https:\/\/bsky\.social\/xrpc\/app\.bsky\.feed\.getPostThread\?uri=([^&]+)&depth=\d+$/);
  if (m) {
    fixtureCalls.getPostThread++;
    const recorded = FIXTURE_THREADS[decodeURIComponent(m[1])];
    return recorded ? fixtureResponse(recorded.status, recorded.body) : fixtureResponse(400, { error: "NotFound", message: "no recording" });
  }
  return Promise.reject(new Error("fixture fetch: no recording for " + u));
}

const http = LIVE ? fetch : fixtureFetch;

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
  const response = await http(BSKY_BASE + "/xrpc/com.atproto.server.createSession", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      identifier: LIVE ? process.env.BLUESKY_IDENTIFIER : "fixture.bsky.social",
      password: LIVE ? process.env.BLUESKY_APP_PASSWORD : "fixture-password"
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
    response = await http(url, {
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

// The sends to check: live, from outreach_sends; otherwise the recorded rows.
async function loadSends() {
  if (!LIVE) return FIXTURE_SENDS;

  const { createClient } = require("@supabase/supabase-js");
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
  return rows || [];
}

async function main() {
  if (LIVE) {
    const missing = missingEnvNames();
    if (missing.length > 0) {
      console.error("Missing required environment variable(s): " + missing.join(", "));
      process.exit(1);
    }
    console.log("LIVE run against the real Bluesky account (CHECK_LIVE_BLUESKY=true): one login, then one read per reply.");
  } else {
    console.log("Fixture run: recorded createSession and getPostThread answers, no network. Set CHECK_LIVE_BLUESKY=true for the live account.");
  }

  const sends = await loadSends();

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
  const humanRepliesPerRow = [];

  for (let i = 0; i < sends.length; i++) {
    const row = sends[i];

    if (i > 0 && REQUEST_SPACING_MS) await sleep(REQUEST_SPACING_MS);

    const header = "[" + (i + 1) + "/" + sends.length + "] " +
      formatSentAt(row.sent_at) + "  source=" + (row.source || "(none)");

    const result = await fetchThread(row.platform_uri, session.accessJwt);

    if (!result.ok) {
      unavailable++;
      humanRepliesPerRow.push(null);
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
    humanRepliesPerRow.push(humanReplies.length);

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

  // Fixture mode is a check: the counts must be the recorded answers' counts.
  if (!LIVE) {
    let failures = 0;
    function check(label, ok, detail) {
      if (ok) console.log("    pass  " + label);
      else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
    }
    console.log("");
    check("rows checked: " + FIXTURE_EXPECTED.rows, sends.length === FIXTURE_EXPECTED.rows, sends.length);
    check("one human reply counted, ours and an unattributable child not", answered === FIXTURE_EXPECTED.answered, answered);
    check("a NotFound 400 and a notFoundPost are both 'not found or deleted'", unavailable === FIXTURE_EXPECTED.unavailable, unavailable);
    check("human replies per row: " + JSON.stringify(FIXTURE_EXPECTED.humanRepliesPerRow),
      JSON.stringify(humanRepliesPerRow) === JSON.stringify(FIXTURE_EXPECTED.humanRepliesPerRow), JSON.stringify(humanRepliesPerRow));
    check("exactly one login (createSession) for the whole run", fixtureCalls.createSession === 1, fixtureCalls.createSession);
    check("one thread read per row", fixtureCalls.getPostThread === FIXTURE_EXPECTED.rows, fixtureCalls.getPostThread);
    console.log("");
    if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
    console.log("ALL CHECKS PASSED (fixtures; no network)");
  }
}

main().catch(function (error) {
  console.error("checkOutreachReplies failed: " +
    (error && error.stack ? error.stack : error));
  process.exit(1);
});
