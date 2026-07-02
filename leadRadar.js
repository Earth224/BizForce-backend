require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");
const { BskyAgent } = require("@atproto/api");

const BLUESKY_IDENTIFIER  = process.env.BLUESKY_IDENTIFIER;
const BLUESKY_APP_PASSWORD = process.env.BLUESKY_APP_PASSWORD;
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const KEYWORDS = [
  "natural energy supplement",
  "low libido",
  "male vitality",
  "herbal aphrodisiac",
  "quantum jumping",
  "law of assumption",
  "manifestation method",
  "reality shifting"
];

const agent = new BskyAgent({ service: "https://bsky.social" });
var agentLoggedIn = false;

async function ensureBskyLogin() {
  if (!BLUESKY_IDENTIFIER || !BLUESKY_APP_PASSWORD) {
    console.log("[LeadRadar] skipped: missing or invalid Bluesky credentials");
    return false;
  }
  try {
    await agent.login({
      identifier: BLUESKY_IDENTIFIER,
      password:   BLUESKY_APP_PASSWORD
    });
    agentLoggedIn = true;
    return true;
  } catch (err) {
    console.error("[LeadRadar] Bluesky login failed:", err.message || err);
    agentLoggedIn = false;
    return false;
  }
}

async function withBsky(fn) {
  if (!agentLoggedIn) {
    var ok = await ensureBskyLogin();
    if (!ok) return null;
  }
  try {
    return await fn(agent);
  } catch (err) {
    var isAuthError =
      (err.status === 401) ||
      (err.error && (err.error === "AuthRequired" || err.error === "ExpiredToken"));
    if (isAuthError) {
      console.warn("[LeadRadar] Session expired, re-logging in...");
      agentLoggedIn = false;
      var ok = await ensureBskyLogin();
      if (!ok) return null;
      return await fn(agent);
    }
    throw err;
  }
}

async function runLeadRadarOnce() {
  try {
    for (var i = 0; i < KEYWORDS.length; i++) {
      var keyword = KEYWORDS[i];
      try {
        var result = await withBsky(function (a) {
          return a.app.bsky.feed.searchPosts({ q: keyword, limit: 25, sort: "latest" });
        });

        if (!result || !result.data || !result.data.posts) continue;

        var rows = result.data.posts.map(function (post) {
          return {
            post_uri:        post.uri,
            post_cid:        post.cid,
            author_did:      post.author.did,
            author_handle:   post.author.handle,
            post_text:       (post.record && post.record.text) || null,
            matched_keyword: keyword,
            lang:            (post.record && post.record.langs && post.record.langs[0]) || null
          };
        });

        if (!rows.length) continue;

        var { error } = await supabase
          .from("bsky_leads")
          .upsert(rows, { onConflict: "post_uri", ignoreDuplicates: true });

        if (error) {
          console.error("[LeadRadar] Supabase upsert error for keyword '" + keyword + "':", error.message);
          continue;
        }

        console.log("[LeadRadar] " + keyword + " -> " + rows.length + " new leads");

      } catch (kwErr) {
        console.error("[LeadRadar] Error processing keyword '" + keyword + "':", kwErr.message || kwErr);
      }
    }
  } catch (err) {
    console.error("[LeadRadar] runLeadRadarOnce error:", err.message || err);
  }
}

var radarRunning = false;

async function radarTick() {
  if (radarRunning) {
    console.log("[LeadRadar] Tick skipped — previous run still in progress");
    return;
  }
  radarRunning = true;
  try {
    await runLeadRadarOnce();
  } catch (err) {
    console.error("[LeadRadar] radarTick error:", err.message || err);
  } finally {
    radarRunning = false;
  }
}

async function startLeadRadar() {
  radarTick().catch(function (err) {
    console.error("[LeadRadar] Initial run error:", err.message || err);
  });
  setInterval(radarTick, 300000);
}

module.exports = { runLeadRadarOnce, startLeadRadar };
