require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const SUBREDDITS = [
  "supplements",
  "testosterone",
  "nootropics",
  "Biohackers",
  "erectiledysfunction",
  "StackAdvice",
  "manifestation",
  "lawofattraction",
  "NevilleGoddard"
];

async function fetchSubreddit(sub) {
  try {
    var res = await fetch("https://www.reddit.com/r/" + sub + "/new.json?limit=100", {
      headers: { "User-Agent": "BizForce Radar/1.0 (by /u/earthrose422)" }
    });
    var json = await res.json();
    var children = (json.data && json.data.children) || [];
    return children.map(function (child) {
      return {
        reddit_id:      child.data.name,
        title:          child.data.title,
        body:           child.data.selftext,
        author:         child.data.author,
        subreddit:      child.data.subreddit,
        permalink:      "https://www.reddit.com" + child.data.permalink,
        reddit_created: new Date(child.data.created_utc * 1000).toISOString()
      };
    });
  } catch (err) {
    console.error("[RedditRadar] fetch failed for r/" + sub + ":", err.message || err);
    return [];
  }
}

const BUYER_KEYWORDS = [
  "low energy",
  "no energy",
  "always tired",
  "low libido",
  "sex drive",
  "stamina",
  "erectile",
  "brain fog",
  "natural remedy",
  "supplement for",
  "anyone tried",
  "recommend",
  "help with",
  "manifest",
  "law of attraction",
  "quantum jump"
];

async function runRedditRadarOnce() {
  try {
    for (var i = 0; i < SUBREDDITS.length; i++) {
      var sub = SUBREDDITS[i];
      try {
        var posts = await fetchSubreddit(sub);

        var matched = [];
        for (var j = 0; j < posts.length; j++) {
          var post = posts[j];
          var haystack = ((post.title || "") + " " + (post.body || "")).toLowerCase();
          var keyword = null;
          for (var k = 0; k < BUYER_KEYWORDS.length; k++) {
            if (haystack.indexOf(BUYER_KEYWORDS[k].toLowerCase()) !== -1) {
              keyword = BUYER_KEYWORDS[k];
              break;
            }
          }
          if (keyword) {
            matched.push({
              reddit_id:      post.reddit_id,
              title:          post.title,
              body:           post.body,
              author:         post.author,
              subreddit:      post.subreddit,
              permalink:      post.permalink,
              reddit_created: post.reddit_created,
              matched_keyword: keyword
            });
          }
        }

        if (matched.length) {
          var { error } = await supabase
            .from("reddit_leads")
            .upsert(matched, { onConflict: "reddit_id", ignoreDuplicates: true });

          if (error) {
            console.error("[RedditRadar] Supabase upsert error for r/" + sub + ":", error.message);
          }
        }

        console.log("[RedditRadar] r/" + sub + " -> " + matched.length + " new buyer-intent posts");

      } catch (subErr) {
        console.error("[RedditRadar] Error processing r/" + sub + ":", subErr.message || subErr);
      }

      if (i < SUBREDDITS.length - 1) {
        await new Promise(function (resolve) { setTimeout(resolve, 2000); });
      }
    }
  } catch (err) {
    console.error("[RedditRadar] runRedditRadarOnce error:", err.message || err);
  }
}

var redditRadarRunning = false;

async function redditRadarTick() {
  if (redditRadarRunning) {
    console.log("[RedditRadar] Tick skipped — previous run still in progress");
    return;
  }
  redditRadarRunning = true;
  try {
    await runRedditRadarOnce();
  } catch (err) {
    console.error("[RedditRadar] tick error:", err.message || err);
  } finally {
    redditRadarRunning = false;
  }
}

async function startRedditRadar() {
  redditRadarTick().catch(function (err) {
    console.error("[RedditRadar] initial run error:", err.message || err);
  });
  setInterval(redditRadarTick, 300000);
}

module.exports = { runRedditRadarOnce, startRedditRadar };
