require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");
const { BskyAgent } = require("@atproto/api");
const Anthropic = require("@anthropic-ai/sdk");

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
  "reality shifting",
  "natural remedy for energy",
  "always tired no energy",
  "help with low libido",
  "boost my energy naturally",
  "cant focus tired all day",
  "anyone tried tongkat ali",
  "how to manifest",
  "does manifestation work",
  "quantum jumping method"
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
    await scoreNewLeads();
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

async function scoreNewLeads() {
  try {
    var { data, error } = await supabase
      .from("bsky_leads")
      .select("*")
      .eq("status", "new")
      .order("created_at", { ascending: true })
      .limit(20);

    if (error) {
      console.error("[LeadRadar] scoreNewLeads query error:", error.message);
      return;
    }

    var leads = data || [];
    console.log("[LeadRadar] scoring " + leads.length + " leads");

    var anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    var scoredCount = 0;

    for (var i = 0; i < leads.length; i++) {
      var lead = leads[i];
      var updatePayload;

      try {
        var prompt =
          "You are a buying-intent classifier for three products:\n" +
          "- War Horse: a natural male vitality and energy supplement\n" +
          "- Tongkat Ali: a natural herbal supplement for male energy and libido\n" +
          "- Quantum Jumping book: an esoteric self-help / manifestation book\n\n" +
          "Given this social media post, score how likely the author is actively looking to buy something in these categories.\n\n" +
          "Post: " + JSON.stringify(lead.post_text || "") + "\n\n" +
          "Respond with ONLY a valid JSON object, no markdown, no code fences, no explanation:\n" +
          "{\"score\": <integer 0-100>, \"reason\": \"<one short sentence>\", \"product\": \"<War Horse | Tongkat Ali | Quantum Jumping book | none>\"}";

        var response = await anthropic.messages.create({
          model:      "claude-haiku-4-5-20251001",
          max_tokens: 300,
          messages:   [{ role: "user", content: [{ type: "text", text: prompt }] }]
        });

        var raw = (response.content && response.content[0] && response.content[0].text) || "";
        var cleaned = raw.replace(/^```[a-z]*\n?/i, "").replace(/```$/, "").trim();
        var result = JSON.parse(cleaned);

        updatePayload = {
          intent_score:      result.score,
          intent_reason:     result.reason,
          suggested_product: result.product,
          status:            "scored"
        };

        console.log("[LeadRadar] scored lead " + lead.id + ": score=" + result.score + " product=" + result.product + " reason=" + result.reason);

      } catch (scoreErr) {
        console.error("[LeadRadar] Failed to score lead " + lead.id + ":", scoreErr.message || scoreErr);
        updatePayload = { intent_score: 0, status: "scored" };
      }

      var { error: updateErr } = await supabase
        .from("bsky_leads")
        .update(updatePayload)
        .eq("id", lead.id);

      if (updateErr) {
        console.error("[LeadRadar] Failed to update lead " + lead.id + ":", updateErr.message);
      } else {
        scoredCount++;
      }
    }

    console.log("[LeadRadar] scored " + scoredCount + " leads");

  } catch (err) {
    console.error("[LeadRadar] scoreNewLeads error:", err.message || err);
  }
}

module.exports = { runLeadRadarOnce, startLeadRadar, scoreNewLeads };
