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

/* How far back a capture reaches, in days. This bounds what is FETCHED only —
   the outreach loop enforces its own window on post_created_at before it
   spends anything (OUTREACH_MAX_POST_AGE_DAYS in server.js). Deliberately two
   numbers: capturing wider than you contact is cheap and leaves scored history
   behind, and collapsing them into one would mean widening the archive
   silently widened who gets messaged. */
const CAPTURE_WINDOW_DAYS = 7;

/* Search phrases, not topics. This distinction is the whole list.

   The old list searched the SUBJECT — "low libido", "law of attraction",
   "male vitality", "neville goddard". Everyone who talks about a subject
   matches a subject word, and in these two niches the people talking are
   overwhelmingly the ones selling: coaches, affiliate accounts, supplement
   brands, manifestation teachers posting daily. The last scoring batch came
   back uniformly score=12, product=none, safe=false, with reasons reading
   "publishing behavior indicates a teacher/activist, not a seeker" and
   "broadcasting their own product." The scorer was right every time. It was
   being handed a list of broadcasters and correctly refusing all of them.

   The two leads that ever converted were not on-topic posts. They were
   QUESTIONS put to the room:

     "Ok chat real question: if you're having a problem with low libido, what's
      done stuff you can do to help get your sex drive back up?"
     "For the health conscious or nutritionist. Is there anything I can eat
      specifically that will naturally boost my energy and mood?"

   Neither contains a product name. What they share is grammar — first person,
   asking, admitting a problem, inviting strangers to answer. A seller almost
   never writes "what helped your", "why isn't my", "does it actually work",
   because those sentences concede that something did not work. That concession
   is the buying signal, and it is what these phrases search for.

   Kept short on purpose. Bluesky ANDs the words of an unquoted query rather
   than matching the phrase, so every extra word is another term the post must
   contain — a seven-word question would match almost nothing. Three to five
   words keeps the seeker-shaped words ("anyone", "tried", "helped", "why",
   "actually") as the binding constraint while leaving the sentence around them
   free to vary.

   25 phrases, the same count as before, so the per-tick search cost is
   unchanged. */
const KEYWORDS = [
  // Supplements: libido, energy, fatigue.
  "anyone tried tongkat ali",
  "does tongkat ali actually work",
  "get my sex drive back",
  "what helped your low libido",
  "why is my libido low",
  "struggling with low libido",
  "what worked for low libido",
  "recommendations for low energy",
  "anyone else always tired",
  "what supplements actually work",
  "anyone recommend an energy supplement",
  "anything to eat for energy",
  "supplement recommendations for fatigue",
  "anyone had luck with ashwagandha",

  // The book: manifestation, law of assumption, quantum jumping.
  "why isn't my manifestation working",
  "manifestation isn't working for me",
  "does manifestation actually work",
  "how do i actually manifest",
  "am i manifesting wrong",
  "what helped you manifest",
  "anyone had luck manifesting",
  "struggling with law of assumption",
  "is law of assumption real",
  "anyone tried quantum jumping",
  "does quantum jumping actually work"
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
        /* Ask the platform for recent posts instead of discarding stale ones
           after the fact. searchPosts takes `since` as an inclusive datetime,
           so a page of 25 is 25 recent candidates rather than 25 that may all
           predate the window.

           Computed per call, never hoisted to module scope: this process runs
           for weeks, and a cutoff captured at require() time would freeze the
           window on the day of the deploy and widen it by a day every day.

           The endpoint filters on `sortAt`, which the lexicon states may not
           match the `createdAt` stored below. The two disagree for a backdated
           or late-federated post, so this narrows what is fetched but is not
           the authority on freshness — the outreach query re-checks
           post_created_at against its own window before spending anything. */
        var sinceIso = new Date(Date.now() - CAPTURE_WINDOW_DAYS * 24 * 60 * 60 * 1000).toISOString();

        var result = await withBsky(function (a) {
          return a.app.bsky.feed.searchPosts({ q: keyword, limit: 25, sort: "latest", since: sinceIso });
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
            lang:            (post.record && post.record.langs && post.record.langs[0]) || null,

            /* When the post was AUTHORED, which is not what created_at holds —
               that is when this row was captured, and the two drift by however
               long the post sat before a search surfaced it. Recency decisions
               need the former, so it is stored rather than inferred from the
               capture time.

               record.createdAt is author-supplied; indexedAt is the relay's own
               observation and is the fallback when the record carries no
               timestamp at all. Null when neither exists, which the outreach
               query treats as ineligible rather than as fresh. */
            post_created_at: (post.record && post.record.createdAt) || post.indexedAt || null
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

/* The only two answers the suitability screen may give. Just the exact string
   "SAFE" clears a lead for outreach; this list exists so an off-contract answer
   can be told apart from a deliberate "UNSAFE" and logged as the contract
   violation it is, instead of passing silently as a refusal. */
const SCORER_SAFETY_VALUES = ["SAFE", "UNSAFE"];

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

    /* ── Which key, and what happens when it stops working ──────────────────
       resolveAnthropicKey reads an encrypted BYOK key out of user_api_keys and
       already falls back to the environment key for every failure it can see:
       no row, a query error, or a decrypt that throws. What it cannot see is
       the failure that actually happened here — the ciphertext decrypted
       perfectly into a real, well-formed key that Anthropic has since stopped
       accepting. AES-GCM authenticates, so a wrong ENCRYPTION_SECRET or a
       tampered row throws rather than yielding garbage; a key that decrypts
       cleanly and 401s is therefore not a crypto problem at all, and no amount
       of care inside the resolver could have caught it.

       That is the gap this closes. The resolved key is used first, and a 401
       from it switches to the environment key once, in place, for the rest of
       the batch.

       Both keys are logged by SOURCE and never by value. */
    var envApiKey = process.env.ANTHROPIC_API_KEY;
    var resolvedApiKey = null;

    try {
      resolvedApiKey = await resolveAnthropicKey(SCORING_ACCOUNT_ID);
    } catch (resolveErr) {
      // The resolver swallows its own decrypt failures, so reaching here means
      // the Supabase read itself threw. Not fatal: the environment key below is
      // a complete substitute.
      console.error("[LeadRadar] resolveAnthropicKey threw, falling back to the environment key:", resolveErr.message || resolveErr);
    }

    /* Nothing left to try. Worth its own message rather than a generic failure,
       because every other cause defers leads for retry and this one must not:
       there is no key, so 20 leads would each burn an attempt against a
       condition no retry can change, and three ticks later they would be marked
       "scoring failed after 3 attempts" by a bug that never involved them. */
    if (!resolvedApiKey && !envApiKey) {
      console.error("[LeadRadar] NO ANTHROPIC KEY AVAILABLE — resolveAnthropicKey returned nothing and ANTHROPIC_API_KEY is unset. Skipping scoring entirely; " + leads.length + " lead(s) left untouched with their attempt counts unchanged. Set ANTHROPIC_API_KEY or repair the stored BYOK key for the scoring account.");
      return;
    }

    /* The resolver hands back the environment key itself in most of its
       fallback paths, so an equality check is the only way to report the source
       honestly — otherwise a resolver fallback would be logged as BYOK. */
    var usingEnvKey = !resolvedApiKey || resolvedApiKey === envApiKey;
    var activeApiKey = resolvedApiKey || envApiKey;

    if (!resolvedApiKey) {
      console.warn("[LeadRadar] resolveAnthropicKey returned no key for the scoring account — using the platform environment key (ANTHROPIC_API_KEY).");
    }
    console.log("[LeadRadar] scoring with the " + (usingEnvKey ? "platform environment key (ANTHROPIC_API_KEY)" : "stored BYOK key for the scoring account") + ".");

    var anthropic = new Anthropic({ apiKey: activeApiKey });

    // Latched, so the switch is announced once per batch rather than once per
    // lead. 20 leads against a dead key would otherwise print 20 identical
    // warnings and bury the one line that matters.
    var authFallbackUsed = false;

    function isAuthFailure(err) {
      if (!err) return false;
      if (err.status === 401 || (err.response && err.response.status === 401)) return true;
      // The SDK surfaces status on the error, but a transport-level wrapper can
      // hide it; the message is the backstop, never the primary test.
      var message = String(err.message || "");
      return /\b401\b/.test(message) || /invalid x-api-key|authentication_error|API key is invalid/i.test(message);
    }

    /* One retry, only for auth, only once per batch. Anything else — a rate
       limit, a timeout, a malformed response — is not a key problem and is left
       to the per-lead catch below, which defers the lead and counts the attempt
       exactly as it always has. */
    async function createScoringMessage(params) {
      try {
        return await anthropic.messages.create(params);
      } catch (err) {
        if (!isAuthFailure(err)) throw err;

        if (!authFallbackUsed && envApiKey && activeApiKey !== envApiKey) {
          authFallbackUsed = true;
          activeApiKey = envApiKey;
          anthropic = new Anthropic({ apiKey: envApiKey });
          console.warn("[LeadRadar] KEY FALLBACK: the stored BYOK key for the scoring account was rejected with 401 (it decrypted fine, so it is revoked or expired, not corrupted). Switching to the platform environment key (ANTHROPIC_API_KEY) for the rest of this batch. Repair or remove the stored key to stop paying this retry every tick.");

          /* The retry needs its own tagging. Without it the second 401 escapes
             as an ordinary error and the lead that triggered the fallback — and
             only that lead — gets an attempt counted against a dead key, while
             every lead after it is correctly spared. One row punished for being
             first is precisely the kind of near-invisible damage the attempt
             counter exists to prevent. A non-auth failure here is a real
             per-lead failure and is left alone. */
          try {
            return await anthropic.messages.create(params);
          } catch (retryErr) {
            if (isAuthFailure(retryErr)) {
              retryErr.__leadRadarAuthDead = true;
            }
            throw retryErr;
          }
        }

        // Both keys rejected, or the only key there was. Tagged so the loop can
        // abandon the batch instead of feeding 20 leads into a retry counter
        // over a condition that is identical for every one of them.
        err.__leadRadarAuthDead = true;
        throw err;
      }
    }
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

          "SECOND, SEPARATE JUDGEMENT — SUITABILITY.\n" +
          "Decide whether this person is a SAFE recipient of an unsolicited PUBLIC reply from a stranger that mentions a supplement or a book.\n\n" +
          "This is NOT the same question as intent, and it is not a stricter version of it. Someone can want help badly and still be a person nobody should approach this way. Judge it on its own evidence, and never let a high score pull this answer toward SAFE.\n\n" +
          "Answer UNSAFE whenever ANY of the following is true, no matter how high the score:\n" +
          "- The post mentions prescription medication, psychiatric medication, hormone therapy, birth control, or any named medical condition or diagnosis.\n" +
          "- The post expresses distress, crisis, hopelessness, or self-harm, or asks for help in an emotional rather than a practical sense.\n" +
          "- The person is describing a medical situation they are under a doctor's care for.\n" +
          "- The post is about a minor, or the author appears to be a minor.\n" +
          "- A stranger replying with a product link would reasonably read as intrusive rather than helpful.\n\n" +
          "Answer SAFE ONLY when the person is openly asking for suggestions, recommendations, or ideas in a way that invites replies from strangers. If you are unsure, answer UNSAFE.\n\n" +

          "Source: " + source + ", " + discovery + "\n" +
          "Post: " + JSON.stringify(lead.post_text || "") + "\n\n" +
          "Respond with ONLY a valid JSON object, no markdown, no code fences, no explanation:\n" +
          "{\"score\": <integer 0-100>, \"reason\": \"<one short sentence>\", \"product\": \"<War Horse | Tongkat Ali | Quantum Jumping book | none>\", \"safety\": \"<SAFE | UNSAFE>\"}";

        var response = await createScoringMessage({
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

        /* Suitability, validated the same way product is and for a sharper
           version of the same reason: only the exact string "SAFE" clears a
           lead, and every other value on earth — "safe", "Safe", true, "yes",
           null, a missing key, a model that ignored the field entirely — lands
           on UNSAFE. Written as a positive test against one literal rather than
           a negative test against a list of refusals, because a negative test
           fails open: the day the model answers something nobody enumerated,
           an .indexOf(...) === -1 check would read it as clearance.

           The default direction is the whole point of the field. A lead wrongly
           held back costs one unsent reply; a lead wrongly cleared is a public
           product pitch at someone in a crisis or under a doctor's care. Those
           are not comparable, so the ambiguous case resolves to the cheap
           mistake every time. */
        var rawSafety    = result ? result.safety : undefined;
        var outreachSafe = rawSafety === "SAFE";

        if (score !== numericScore) {
          console.warn("[LeadRadar] lead " + lead.id + ": score " + JSON.stringify(rawScore) + " coerced to " + score);
        }
        if (product !== (result ? result.product : undefined)) {
          console.warn("[LeadRadar] lead " + lead.id + ": product " + JSON.stringify(result ? result.product : undefined) + " is not one of the four allowed values, stored as none");
        }
        // Separate from the value itself: an off-contract answer and a genuine
        // "UNSAFE" both store false, and only this line tells them apart. If
        // the model starts returning a boolean or a lowercase word, every lead
        // silently stops being eligible — this is the warning that says why.
        if (SCORER_SAFETY_VALUES.indexOf(rawSafety) === -1) {
          console.warn("[LeadRadar] lead " + lead.id + ": safety " + JSON.stringify(rawSafety) + " is not SAFE or UNSAFE, stored as UNSAFE");
        }

        updatePayload = {
          intent_score:      score,
          intent_reason:     result.reason,
          suggested_product: product,
          outreach_safe:     outreachSafe,
          status:            "scored"
        };

        // Logs what was STORED, not what the model said. The two can differ now,
        // and the warnings above are what record that they did.
        console.log("[LeadRadar] scored lead " + lead.id + ": score=" + score + " product=" + product + " safe=" + outreachSafe + " reason=" + result.reason);

      } catch (scoreErr) {
        /* Not this lead's fault, and not this lead's attempt to spend. Every
           remaining lead in the batch would fail identically against the same
           dead key, so the batch is abandoned here rather than counted through:
           20 leads x 3 attempts would mark the whole queue "scoring failed
           after 3 attempts" for a credentials problem none of them caused, and
           that verdict is permanent — status becomes 'scored' and the query
           that finds work never looks at them again.

           Left untouched instead, attempt counts unchanged, to be picked up on
           the next tick once a working key is in place. */
        if (scoreErr && scoreErr.__leadRadarAuthDead) {
          console.error("[LeadRadar] NO WORKING ANTHROPIC KEY — " + (authFallbackUsed ? "both the stored BYOK key and the platform environment key were rejected with 401" : "the only available key was rejected with 401") + ". Abandoning this scoring batch after " + scoredCount + " scored; the remaining " + (leads.length - i) + " lead(s) are left untouched with their attempt counts unchanged. No retry will fix this — replace the key.");
          break;
        }

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
          // outreach_safe is deliberately NOT written here. This lead reached
          // "scored" without any model ever having read it, so there is no
          // suitability judgement to record — and leaving the column null is
          // what keeps it out of the outreach query, which treats null as
          // ineligible. Writing false would say "screened and refused", which
          // is a different and untrue statement.
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
