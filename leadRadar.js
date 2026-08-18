require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");
const { BskyAgent } = require("@atproto/api");
const Anthropic = require("@anthropic-ai/sdk");
const { runMastodonRadarOnce } = require("./mastodonRadar");
const { runYoutubeRadarOnce } = require("./youtubeRadar");

const BLUESKY_IDENTIFIER  = process.env.BLUESKY_IDENTIFIER;
const BLUESKY_APP_PASSWORD = process.env.BLUESKY_APP_PASSWORD;
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const resolveAnthropicKey = require("./lib/resolveAnthropicKey")(supabase);

// The same account as CAPTURE_OWNER_ID in server.js, and the two must move
// together. It was inlined bare at the resolveAnthropicKey call site, which
// made that impossible to see: one literal here, one literal there, no name
// tying them together, and changing either one leaves the other silently on
// the old value.
//
// Not imported, because server.js does not export it — and requiring server.js
// from here would be a circular import, since server.js already requires this
// file. Two literals is the cost of that; a shared name and this comment are
// what make the pair findable in the meantime.
//
// WHAT IT SELECTS: whose row in user_api_keys pays for the scoring calls.
// Nothing else. It is not the tenant the leads belong to — bsky_leads has no
// tenant column at all, no user_id and no owner of any kind, so there is no
// ownership here for this value to express.
//
// When multi-tenancy lands both literals disappear, and this comment is the
// note that says there were two of them.
const SCORING_ACCOUNT_ID = "ea887c6e-e278-4a15-b7e9-cd78a9949b78";

const KEYWORDS = [
  "natural energy supplement",
  "low libido",
  "male vitality",
  "herbal aphrodisiac",
  "quantum jumping",
  "law of assumption",
  "manifestation method",
  "natural remedy for energy",
  "always tired no energy",
  "help with low libido",
  "boost my energy naturally",
  "cant focus tired all day",
  "anyone tried tongkat ali",
  "how to manifest",
  "does manifestation work",
  "quantum jumping method",
  "neville goddard",
  "law of attraction",
  "how to quantum jump",
  "neville goddard method",
  "sats manifestation",
  "manifestation not working",
  "how to manifest faster",
  "living in the end",
  "revision method neville"
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
var scoringDisabledLogged = false;

async function radarTick() {
  if (radarRunning) {
    console.log("[LeadRadar] Tick skipped — previous run still in progress");
    return;
  }
  radarRunning = true;
  try {
    await runLeadRadarOnce();

    try {
      await runMastodonRadarOnce();
    } catch (mastodonErr) {
      console.error("[LeadRadar] MastodonRadar cycle error:", mastodonErr.message || mastodonErr);
    }

    try {
      await runYoutubeRadarOnce();
    } catch (youtubeErr) {
      console.error("[LeadRadar] YoutubeRadar cycle error:", youtubeErr.message || youtubeErr);
    }

    // Capture above is free — network calls only. Scoring below is the paid
    // half: scoreNewLeads() calls the Claude API up to 20x per tick, so it is
    // gated separately and leads keep accumulating unscored while it is off.
    if (process.env.ENABLE_LEAD_SCORING === "true") {
      await scoreNewLeads();
    } else if (!scoringDisabledLogged) {
      scoringDisabledLogged = true;
      console.log("[LeadRadar] Scoring disabled (ENABLE_LEAD_SCORING not true) — captured leads are accumulating unscored");
    }
  } catch (err) {
    console.error("[LeadRadar] radarTick error:", err.message || err);
  } finally {
    radarRunning = false;
  }
}

async function startLeadRadar() {
  // Ungated. The tick used to sit behind ENABLE_AUTO_JOBS because it chained
  // into scoreNewLeads(), which calls the Claude API up to 20x per tick — that
  // spend is now gated separately by ENABLE_LEAD_SCORING inside radarTick, so
  // the reason no longer applies to the tick as a whole. What is left is
  // capture (Bluesky, Mastodon, YouTube), which costs nothing and should
  // always run: leads not collected are gone for good.
  radarTick().catch(function (err) {
    console.error("[LeadRadar] Initial run error:", err.message || err);
  });
  setInterval(radarTick, 300000);
}

/* The four values the scoring prompt tells the model to choose from, and the
   only four this file will persist. Written out literally rather than derived
   from the prompt string, so that editing one without the other is a visible
   mismatch between two adjacent lists instead of a silent widening of what
   counts as a product.

   Order and spelling match the prompt's closing line exactly. "none" is a
   member: it is the value the prompt asks for on teachers and sellers, and the
   value anything unrecognised is stored as. */
const SCORER_ALLOWED_PRODUCTS = ["War Horse", "Tongkat Ali", "Quantum Jumping book", "none"];

async function scoreNewLeads() {
  try {
    // Ordered by score_attempts first so a lead that has failed twice does not
    // sit at the front of the FIFO queue and consume a slot on every tick while
    // fresh captures wait behind it. created_at breaks the tie within an
    // attempt count, which preserves the oldest-first behaviour for the rows
    // that have never been tried.
    var { data, error } = await supabase
      .from("bsky_leads")
      .select("*")
      .eq("status", "new")
      .order("score_attempts", { ascending: true })
      .order("created_at", { ascending: true })
      .limit(20);

    if (error) {
      console.error("[LeadRadar] scoreNewLeads query error:", error.message);
      return;
    }

    var leads = data || [];
    console.log("[LeadRadar] scoring " + leads.length + " leads");

    var apiKey = await resolveAnthropicKey(SCORING_ACCOUNT_ID);
    var anthropic = new Anthropic({ apiKey: apiKey });
    // Counted apart, not together. A deferred lead is not a scored lead — it
    // has no score, it is going back on the queue, and the only thing that
    // happened to it was a failed call. A summary that adds the two together
    // reports a healthy-looking number while every call in the batch is
    // failing, which is exactly the condition this counter should surface.
    var scoredCount   = 0;
    var deferredCount = 0;

    for (var i = 0; i < leads.length; i++) {
      var lead = leads[i];
      var updatePayload;

      try {
        // The prompt used to interpolate post_text and nothing else, so the
        // classifier could not tell a searched-for distress phrase from a
        // hashtag it was never looking for. That distinction is measurable:
        // mastodon pulls hashtag timelines and returns 617 scored rows for 7
        // leads above 70 — a Claude call per row to find one buyer per 88.
        // Bluesky searches free-text distress phrases and returns 105 above 70
        // from 1,690, one per 16. The difference is what the query finds, not
        // what the classifier does; a hashtag timeline is a list of people
        // publishing about a topic, a phrase search is a list of people
        // describing a problem. Telling the classifier which one it is reading
        // is the cheapest correction available — one line of prompt, no extra
        // call, no change to what gets captured.
        var source  = lead.source || "bluesky";
        var matched = lead.matched_keyword || "";
        var discovery = source === "mastodon"
          ? "pulled from the #" + matched + " hashtag timeline"
          : "found by searching for the phrase " + JSON.stringify(matched);

        var prompt =
          "You are a buyer-intent classifier for three products:\n" +
          "- War Horse: a natural male vitality and energy supplement\n" +
          "- Tongkat Ali: a natural herbal supplement for male energy and libido\n" +
          "- Quantum Jumping book: an esoteric self-help / manifestation book\n\n" +
          "Your job is to separate SEEKERS from TEACHERS/SELLERS.\n\n" +
          "Score HIGH (60-100) ONLY when the post shows a real individual expressing personal desire, struggle, confusion, or genuine openness to a method or product — someone who might actually buy.\n" +
          "Examples of high scores: asking for recommendations, venting about low energy or low libido, sharing personal frustration, saying they want to try something, admitting confusion about a method.\n\n" +
          "Score LOW (0-24) when the account appears to be teaching, coaching, promoting, or selling — even if the topic is a perfect match. Creators, coaches, and sellers are competition, not buyers.\n" +
          "Examples of low scores: sharing tips, explaining techniques to followers, promoting their own program or product, posting motivational content, using phrases like 'here is how', 'I teach', 'my clients', 'DM me'.\n\n" +
          "Score MIDDLE (25-59) for ambiguous posts where intent is unclear.\n\n" +
          "The Source line tells you how the post was found. A post pulled from a hashtag timeline is far more likely to be a broadcaster than a seeker, because hashtagging is a publishing behaviour — weight accordingly.\n\n" +
          "Only assign a product tag to genuine seekers. For teachers/sellers set product to 'none'.\n\n" +
          "Source: " + source + ", " + discovery + "\n" +
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

        // Valid JSON is not a valid score. Everything below used to be written
        // through untouched, so whatever the model put in those two fields
        // became the row — and both are read as though the prompt's contract
        // had been enforced somewhere. It never was.
        //
        // intent_score is compared numerically in five places (>= 60 for the
        // autoloop, >= 40 for the buyer segment, an operator-supplied
        // min_score, and two order-bys). A string lands in an integer column
        // and errors the write; a 150 quietly outranks every genuine lead in
        // the table and is drafted first, forever.
        //
        // suggested_product is compared as an EXACT string: the buyer segment
        // is .neq("suggested_product", "none"). Anything off-list therefore
        // reads as a product — "War Horse supplement", "None", "N/A" and
        // "unclear" all pass a not-equal-to-none test and qualify the lead for
        // outreach that the classifier was signalling against.
        var rawScore = result ? result.score : undefined;
        var numericScore =
          typeof rawScore === "number" ? rawScore :
          (typeof rawScore === "string" && rawScore.trim() !== "" ? Number(rawScore) : NaN);

        // Not a number at all means the model did not do the task, which is the
        // same class of failure as unparseable output — so it takes the same
        // route. Throwing here lands in the catch below, which leaves the row
        // 'new' for two more attempts rather than persisting a fabricated zero.
        // A clamp cannot rescue this: there is no number to clamp.
        if (!Number.isFinite(numericScore)) {
          throw new Error("scorer returned a non-numeric score: " + JSON.stringify(rawScore));
        }

        var score = Math.min(100, Math.max(0, Math.round(numericScore)));

        // Exact match or nothing. Deliberately case-sensitive and untrimmed
        // against the four values the prompt names, because a near-miss is not
        // evidence of intent — it is evidence the model went off-contract, and
        // guessing which product it meant is how an off-list string becomes a
        // public reply about the wrong product.
        var product = SCORER_ALLOWED_PRODUCTS.indexOf(result ? result.product : undefined) !== -1
          ? result.product
          : "none";

        if (score !== numericScore) {
          console.warn("[LeadRadar] lead " + lead.id + ": score " + JSON.stringify(rawScore) + " coerced to " + score);
        }
        if (product !== (result ? result.product : undefined)) {
          console.warn("[LeadRadar] lead " + lead.id + ": product " + JSON.stringify(result ? result.product : undefined) + " is not one of the four allowed values, stored as none");
        }

        updatePayload = {
          intent_score:      score,
          intent_reason:     result.reason,
          suggested_product: product,
          status:            "scored"
        };

        // Logs what was STORED, not what the model said. The two can differ now,
        // and the warnings above are what record that they did.
        console.log("[LeadRadar] scored lead " + lead.id + ": score=" + score + " product=" + product + " reason=" + result.reason);

      } catch (scoreErr) {
        // This path used to write { intent_score: 0, status: "scored" }, which
        // ended the lead's life: the next query filters status = 'new', so a
        // timeout or a malformed response was never retried and was recorded
        // identically to a post the model had genuinely read and rated zero.
        // 27 rows across bluesky and youtube carry intent_score 0 with a null
        // intent_reason, which is that signature. A swallowed failure is worse
        // than a visible one because the row still looks scored — nothing in
        // the table says the call never happened. The reason string is what
        // tells a real zero and a dead call apart, and it was absent precisely
        // because the failure path never wrote one.
        var attempts = (lead.score_attempts || 0) + 1;

        console.error("[LeadRadar] Failed to score lead " + lead.id + " (attempt " + attempts + " of 3):", scoreErr.message || scoreErr);

        if (attempts < 3) {
          // status is left as "new" — not written at all — so the lead comes
          // back on a later tick. intent_score stays untouched rather than
          // being zeroed, because no score was ever produced.
          updatePayload = { score_attempts: attempts };
          console.log("[LeadRadar] lead " + lead.id + " left new for retry, attempt " + attempts + " of 3");
        } else {
          updatePayload = {
            score_attempts: attempts,
            intent_score:   0,
            intent_reason:  "scoring failed after 3 attempts",
            status:         "scored"
          };
          console.log("[LeadRadar] lead " + lead.id + " gave up after " + attempts + " attempts, marked scored with a failure reason");
        }
      }

      var { error: updateErr } = await supabase
        .from("bsky_leads")
        .update(updatePayload)
        .eq("id", lead.id);

      if (updateErr) {
        console.error("[LeadRadar] Failed to update lead " + lead.id + ":", updateErr.message);
      } else if (updatePayload.status === "scored") {
        scoredCount++;
      } else {
        deferredCount++;
      }
    }

    console.log("[LeadRadar] scored " + scoredCount + " leads, deferred " + deferredCount + " for retry");

  } catch (err) {
    console.error("[LeadRadar] scoreNewLeads error:", err.message || err);
  }
}

module.exports = { runLeadRadarOnce, startLeadRadar, scoreNewLeads, bskyAgent: agent, ensureBskyLogin };
