require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");
const { BskyAgent } = require("@atproto/api");
const { createBskyGate } = require("./lib/bskyGate");
// NAMED (Nov 23 2026, LR-1): mastodonRadar.js is removed. Mastodon lead search and replies are gone by the owner's rule (Threads replaces it in LR-2).
const memberRadar = require("./lib/memberRadar");

const BLUESKY_IDENTIFIER  = process.env.BLUESKY_IDENTIFIER;
const BLUESKY_APP_PASSWORD = process.env.BLUESKY_APP_PASSWORD;
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

/* NAMED (Nov 23 2026, LR-2): LEAD RADAR IS EVERY MEMBER'S. BEFORE this file searched Bluesky every five minutes for
   two FIXED lists of the owner's phrases (KEYWORDS, BIZFORCE_KEYWORDS), wrote the posts to the shared bsky_leads
   table and scored them with fixed prompts about the owner's products (scoreNewLeads). AFTER:
     the two lists are REMOVED; their words move into the owner's own Fingerprint
       (scripts/oneoff/lr2SeedOwner.js), and the owner is searched and scored like any member;
     radarTick runs lib/memberRadar.js: each member's Fingerprint, their sources, their leads (member_leads), their
       scoring on their own AI allowance (server.js hands in callModel = callAnthropicText, which enforces the
       member's daily call limit and monthly spend limit, picks their own key first and writes the ledger row);
     bsky_leads stays as a read-only archive (the owner's view in agents/sales.html, GET /api/leads/archive).
   Scoring is still switched by ENABLE_LEAD_SCORING ("true" scores; anything else captures only, and leads wait). */
const SCORER_AGENT_TYPE = memberRadar.AGENT_TYPE;
const SCORER_LEDGER_ROUTE = memberRadar.SCORE_ROUTE;

/* server.js requires this file, so it cannot be required back: it hands in what the member radar needs
   (tierOf, names, categoryName, categoryNames, callModel, threadsSearch, ownerId) before the radar starts. With none
   handed in the tick captures nothing, because a member cannot be told from a free account without it. */
var memberDeps = null;
function setMemberRadarDeps(deps) {
  memberDeps = deps && typeof deps.tierOf === "function" && typeof deps.callModel === "function" ? deps : null;
  return !!memberDeps;
}

/* ONE SESSION, ONE GATE (lib/bskyGate.js), shared with server.js's sender: the
   session is reused, a login happens only when there is none (and once more on
   an expired token), and a 429 anywhere stops every Bluesky call until the
   back-off ends. The radar gives each tick a budget of one login attempt, so a
   failing login can no longer be retried for each of its searches. */
const agent = new BskyAgent({ service: "https://bsky.social" });
const bskyGate = createBskyGate({
  agent: agent,
  credentials: function () { return { identifier: BLUESKY_IDENTIFIER, password: BLUESKY_APP_PASSWORD }; }
});

// The session for a caller outside a tick (server.js). true when there is one.
async function ensureBskyLogin() {
  var session = await bskyGate.ensureSession();
  return session.ok === true;
}

/* A searchPosts for the member radar, through the gate. A back-off in force searches nothing (rate_limited). The
   tick's budget of one login is shared by every search in it. */
function bskySearchFor(tickBudget) {
  return async function (keyword, sinceIso) {
    if (bskyGate.backoffRemainingMs() > 0) {
      return { ok: false, reason: "rate_limited", resumes_at: new Date(bskyGate.backoffUntil()).toISOString() };
    }
    var call = await bskyGate.call(function (a) {
      return a.app.bsky.feed.searchPosts({ q: keyword, limit: 25, sort: "latest", since: sinceIso });
    }, tickBudget);
    if (!call.ok) return { ok: false, reason: call.reason, resumes_at: call.resumes_at || null, error: call.error || null };
    var posts = call.value && call.value.data && Array.isArray(call.value.data.posts) ? call.value.data.posts : [];
    return { ok: true, posts: posts };
  };
}

/* ── THE HEARTBEAT (migration 135, public.radar_status) ─────────────────────
   One row per source, overwritten by the running radar: when the process
   starts the radar, and at the end of every tick, with what the Bluesky part
   did. It answers "is the radar running?" from the database.

   ONLY A STARTED RADAR WRITES IT. radarStarted is set by startLeadRadar alone,
   so loading this file writes nothing.

   NEVER IN THE WAY. A heartbeat write that fails is logged and never throws.

   NOTHING UNCOUNTED IS A 0. searches and captured are null when not counted. */
var RADAR_HEARTBEAT_SOURCE = "bluesky";
var radarStarted = false;

async function writeRadarHeartbeat(fields, when, source) {
  if (!radarStarted) return;
  try {
    var result = await supabase
      .from("radar_status")
      .upsert(Object.assign({ source: source || RADAR_HEARTBEAT_SOURCE }, fields), { onConflict: "source" });
    if (result && result.error) {
      console.error("[LeadRadar] heartbeat (" + when + ") not written: " + (result.error.message || result.error) + ". The radar carries on.");
    }
  } catch (heartbeatErr) {
    console.error("[LeadRadar] heartbeat (" + when + ") not written: " + ((heartbeatErr && heartbeatErr.message) || heartbeatErr) + ". The radar carries on.");
  }
}

/* The tick's Bluesky part as a radar_status row (migration 135's outcomes). */
function tickHeartbeat(startedAt, result) {
  var b = (result && result.bluesky) || null;
  var row = { last_tick_started_at: startedAt, last_tick_finished_at: new Date().toISOString(), searches: null, captured: null, resumes_at: null, last_error: null };
  if (!b) { row.last_outcome = "nothing_new"; row.searches = 0; row.captured = 0; return row; }
  if (b.error) { row.last_outcome = "error"; row.last_error = String(b.error).slice(0, 1000); return row; }
  row.searches = b.searched;
  row.captured = b.captured;
  if (b.stopped === "rate_limited") row.last_outcome = "backoff";
  else if (b.stopped === "no_credentials") row.last_outcome = "no_credentials";
  else if (b.stopped && !b.searched) row.last_outcome = "login_failed";
  else row.last_outcome = b.captured > 0 ? "captured" : "nothing_new";
  return row;
}

var radarRunning = false;
var noDepsLogged = false;
var scoringDisabledLogged = false;

async function radarTick() {
  if (radarRunning) {
    console.log("[LeadRadar] Tick skipped — previous run still in progress");
    return;
  }
  radarRunning = true;
  var startedAt = new Date().toISOString();
  var result = null;
  try {
    if (!memberDeps) {
      if (!noDepsLogged) { noDepsLogged = true; console.error("[LeadRadar] NOT RUNNING — server.js handed in no member radar (setMemberRadarDeps)."); }
      return;
    }
    var scoringOn = process.env.ENABLE_LEAD_SCORING === "true";
    if (!scoringOn && !scoringDisabledLogged) {
      scoringDisabledLogged = true;
      console.log("[LeadRadar] Scoring disabled (ENABLE_LEAD_SCORING not true) — members' leads are captured and wait unscored");
    }
    var deps = Object.assign({}, memberDeps, {
      sb: supabase,
      env: process.env,
      scoringOn: scoringOn,
      bskySearch: bskySearchFor({ logins: 1 }),
      platformHandle: BLUESKY_IDENTIFIER || null,
      youtube: process.env.ENABLE_YOUTUBE_RADAR === "true" ? require("./youtubeRadar").memberYoutubeDeps() : null
    });
    result = await memberRadar.runTick(deps);
    console.log("[LeadRadar] tick: " + JSON.stringify(result).slice(0, 600));
  } catch (err) {
    console.error("[LeadRadar] radarTick error:", err.message || err);
    result = { bluesky: { error: (err && err.message) || String(err) } };
  } finally {
    if (memberDeps) await writeRadarHeartbeat(tickHeartbeat(startedAt, result), "tick");
    radarRunning = false;
  }
}

/* track(name, handle) registers the five-minute interval with server.js's
   graceful shutdown (lib/gracefulShutdown.js), so a SIGTERM stops it. */
async function startLeadRadar(track) {
  radarStarted = true;
  await writeRadarHeartbeat({ process_started_at: new Date().toISOString() }, "process start");
  radarTick().catch(function (err) {
    console.error("[LeadRadar] Initial run error:", err.message || err);
  });
  var handle = setInterval(radarTick, 300000);
  if (typeof track === "function") track("leadRadarTick", handle);
  return handle;
}

module.exports = { startLeadRadar, radarTick, tickHeartbeat, bskyAgent: agent, bskyGate, ensureBskyLogin, bskySearchFor,
  setMemberRadarDeps, SCORER_AGENT_TYPE, SCORER_LEDGER_ROUTE };
