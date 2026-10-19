require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");
const { YOUTUBE_API_UNITS, youtubeCaps, youtubeUnitsToday, reserveYoutubeUnits } = require("./lib/youtubeQuota");

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const YOUTUBE_API_KEY      = process.env.YOUTUBE_API_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// Every keyword is processed on every run. The rotating slice that used to
// live here existed only to protect the daily quota when this ran on the
// shared 5-minute radar tick; MIN_RUN_INTERVAL_MS now protects that quota
// directly, and rotating on top of it would just delay coverage for no gain.
/* Question-shaped, like the Bluesky list — but aimed one step further away,
   and that difference matters when editing this.

   These strings do not search comments. search.list searches VIDEOS, and the
   comments harvested from the videos it returns are what become leads. So the
   target is not "a comment phrased as a question", it is "a video whose
   comment section fills up with people asking questions".

   Question-titled videos are the ones that do that. A video called "Does
   Tongkat Ali Actually Work?" collects comments like "tried it for 3 months,
   nothing, what else is there" — someone who bought, was disappointed, and is
   still looking. A video called "Tongkat Ali Reviews" collects the channel's
   own affiliate audience, which is where the old topic-word list was fishing.
   Same correction as the Bluesky list, one layer removed: the seeker is in the
   comments under the question, not under the topic.

   Still exactly 8. The quota arithmetic below is written against that number,
   and adding a ninth silently changes the daily unit cost. */
const KEYWORDS = [
  // Supplements: libido, energy, fatigue.
  "does tongkat ali actually work",
  "how to increase libido naturally",
  "why am i always tired",
  "what supplements actually work",
  "how to boost energy naturally",

  // The book: manifestation, law of assumption, quantum jumping.
  "why isn't my manifestation working",
  "does manifestation actually work",
  "does quantum jumping actually work"
];

// runYoutubeRadarOnce is called from leadRadar.js radarTick every 5 minutes,
// a tick shared with Bluesky and Mastodon, neither of which has a quota
// problem. YouTube therefore throttles itself rather than slowing the tick.
//
// Quota: every call reserves its units in youtube_api_calls before it is sent
// (lib/youtubeQuota.js), and before each search.list the pass checks that the
// search and every comment call it can lead to still fit both caps:
// YOUTUBE_DAILY_UNIT_CAP (default 5000, the whole key, all callers, per UTC
// day) and YOUTUBE_RADAR_DAILY_UNITS (default 2500, the radar's share). A full
// pass is at most 8 × (100 + 4 × 1) = 832 units, so at the defaults the radar
// runs about three full passes a day and then stops until the UTC day turns.
// The 3-hour interval still spaces the passes; the caps are what bound spend.
const MIN_RUN_INTERVAL_MS = 3 * 60 * 60 * 1000; // 3 hours

// Deliberately in-process: it resets on redeploy, which costs at most one
// extra pass. A persistent counter would mean a table and a migration for a
// problem this size.
let lastRunStartedAt = 0;

// Videos per search, and so the most comment calls one search can lead to.
var SEARCH_MAX_RESULTS = 4;
// A search's worst case in units: the search and one comment call per video.
var SEARCH_WORST_CASE_UNITS = YOUTUBE_API_UNITS["search.list"] + SEARCH_MAX_RESULTS * YOUTUBE_API_UNITS["commentThreads.list"];

async function fetchSearchResults(keyword) {
  var url = "https://www.googleapis.com/youtube/v3/search" +
    "?part=snippet&q=" + encodeURIComponent(keyword) +
    "&type=video&order=date&maxResults=" + SEARCH_MAX_RESULTS + "&key=" + YOUTUBE_API_KEY;
  var response = await fetch(url);
  if (!response.ok) {
    let errBody = "";
    try { errBody = await response.text(); } catch (e) {}
    throw new Error("search.list HTTP " + response.status + " :: " + errBody);
  }
  return response.json();
}

// Returns null (skip quietly) when comments are disabled for the video, throws
// on any other error. A 403 is not on its own enough to conclude that comments
// are disabled — YouTube also returns 403 for quotaExceeded and for a disabled
// or invalid key — so the body has to be read to tell them apart. Treating
// every 403 as benign meant a quota exhaustion during the comment phase
// produced zero output and was indistinguishable from a video with no comments.
async function fetchCommentThreads(videoId) {
  var url = "https://www.googleapis.com/youtube/v3/commentThreads" +
    "?part=snippet&videoId=" + encodeURIComponent(videoId) +
    "&maxResults=20&order=relevance&key=" + YOUTUBE_API_KEY;
  var response = await fetch(url);
  if (response.status === 403) {
    let forbiddenBody = "";
    try { forbiddenBody = await response.text(); } catch (e) {}
    if (forbiddenBody.indexOf("commentsDisabled") !== -1) {
      return null;
    }
    throw new Error("commentThreads.list HTTP 403 :: " + forbiddenBody);
  }
  if (!response.ok) {
    throw new Error("commentThreads.list HTTP " + response.status);
  }
  return response.json();
}

async function runYoutubeRadarOnce() {
  // Silent on the skip path: the caller ticks every 5 minutes, so a log line
  // here would fire ~35 times per gap and drown everything else in the log.
  if (Date.now() - lastRunStartedAt < MIN_RUN_INTERVAL_MS) return;

  // Stamped at the start rather than at the end so an overlapping or slow run
  // cannot open a second window while the first is still going.
  lastRunStartedAt = Date.now();

  // Without this the key is interpolated into every URL as the literal string
  // "undefined" and every request fails. That is exactly what happened between
  // 2026-07-08 and 2026-08-03: YOUTUBE_API_KEY was absent from Railway, every
  // call sent undefined, and the only symptom was a repeating "API key not
  // valid" in the logs.
  if (!YOUTUBE_API_KEY) {
    console.error("[YoutubeRadar] YOUTUBE_API_KEY is not set — every request would send the literal string 'undefined' and fail. Skipping run.");
    return;
  }

  /* FAIL CLOSED: an unusable cap means no YouTube call this pass. Logged once:
     a pass happens at most once every MIN_RUN_INTERVAL_MS. */
  var caps = youtubeCaps(process.env);
  if (caps.error) {
    console.error("[YoutubeRadar] No YouTube call this pass: " + caps.error + ".");
    return;
  }

  // Reserve a call's units BEFORE it is sent. false (logged once) ends the pass.
  var stopPass = false;
  async function reserve(method) {
    try {
      await reserveYoutubeUnits(supabase, { caller: "radar", method: method });
      return true;
    } catch (ledgerErr) {
      console.error("[YoutubeRadar] No YouTube call this pass: " + (ledgerErr.message || ledgerErr) + ".");
      stopPass = true;
      return false;
    }
  }

  try {
    var keywords = KEYWORDS;

    for (var i = 0; i < keywords.length; i++) {
      if (stopPass) break;
      var keyword = keywords[i];

      /* Both caps, read fresh from the ledger before each search: the search
         and every comment call it can lead to must fit. A ledger that cannot
         be read means no call. */
      var used;
      try {
        used = await youtubeUnitsToday(supabase);
      } catch (readErr) {
        console.error("[YoutubeRadar] No YouTube call this pass: " + (readErr.message || readErr) + ".");
        break;
      }
      if (used.total + SEARCH_WORST_CASE_UNITS > caps.daily || used.radar + SEARCH_WORST_CASE_UNITS > caps.radar) {
        console.log("[YoutubeRadar] Pass stopped before '" + keyword + "': " + used.total + " of " + caps.daily +
          " units used today (radar " + used.radar + " of " + caps.radar + "), and the next search can cost " + SEARCH_WORST_CASE_UNITS + ".");
        break;
      }
      if (!(await reserve("search.list"))) break;

      try {
        var searchData = await fetchSearchResults(keyword);
        var videoItems = (searchData && searchData.items) || [];
        var videoIds = videoItems
          .map(function (item) { return item.id && item.id.videoId; })
          .filter(Boolean);

        if (!videoIds.length) continue;

        var rows = [];

        for (var v = 0; v < videoIds.length && v < SEARCH_MAX_RESULTS; v++) {
          var videoId = videoIds[v];
          if (!(await reserve("commentThreads.list"))) break;
          try {
            var commentsData = await fetchCommentThreads(videoId);
            if (!commentsData) continue; // comments disabled — skip quietly

            var commentItems = commentsData.items || [];

            commentItems.forEach(function (item) {
              var thread = item.snippet && item.snippet.topLevelComment;
              var commentSnippet = thread && thread.snippet;
              if (!thread || !commentSnippet) return;

              rows.push({
                post_uri:        "https://www.youtube.com/watch?v=" + videoId + "&lc=" + thread.id,
                post_cid:        null,
                author_did:      null,
                author_handle:   commentSnippet.authorDisplayName || null,
                post_text:       commentSnippet.textOriginal || commentSnippet.textDisplay || null,
                matched_keyword: keyword,
                lang:            null,
                source:          "youtube",

                /* youtube is not in SCORABLE_SOURCES in leadRadar.js, so these
                   rows are captured as signal and never enter the scorer queue,
                   which selects status = new. Left at the column default of new
                   they would sit in that queue forever without ever being drained. */
                status:          "signal",

                /* The COMMENT's publish time, which is the post being captured
                   here — not the video's. An old comment on a new video and a
                   new comment on an old video are opposite cases, and only the
                   comment's own timestamp separates them. updatedAt is the
                   fallback for an edited comment whose publishedAt is somehow
                   absent; both are RFC 3339 strings.

                   commentThreads.list has no date parameter to narrow the fetch
                   with — its optional params are maxResults, moderationStatus,
                   order, pageToken, searchTerms and textFormat. search.list
                   does take publishedAfter, but that bounds which VIDEOS are
                   discovered, not which comments come back, so it would drop
                   fresh comments on older videos while still admitting
                   years-old comments on new ones. Left alone deliberately. */
                post_created_at: commentSnippet.publishedAt || commentSnippet.updatedAt || null
              });
            });
          } catch (videoErr) {
            console.error("[YoutubeRadar] Error fetching comments for video '" + videoId + "':", videoErr.message || videoErr);
          }
        }

        if (!rows.length) continue;

        var { error } = await supabase
          .from("bsky_leads")
          .upsert(rows, { onConflict: "post_uri", ignoreDuplicates: true });

        if (error) {
          console.error("[YoutubeRadar] Supabase upsert error for keyword '" + keyword + "':", error.message);
          continue;
        }

        console.log("[YoutubeRadar] " + keyword + " -> " + rows.length + " new leads");

      } catch (kwErr) {
        console.error("[YoutubeRadar] Error processing keyword '" + keyword + "':", kwErr.message || kwErr);
      }
    }
  } catch (err) {
    console.error("[YoutubeRadar] runYoutubeRadarOnce error:", err.message || err);
  }
}

module.exports = { runYoutubeRadarOnce, KEYWORDS };
