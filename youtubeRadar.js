require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const YOUTUBE_API_KEY      = process.env.YOUTUBE_API_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// Every keyword is processed on every run. The rotating slice that used to
// live here existed only to protect the daily quota when this ran on the
// shared 5-minute radar tick; MIN_RUN_INTERVAL_MS now protects that quota
// directly, and rotating on top of it would just delay coverage for no gain.
const KEYWORDS = [
  "low libido help",
  "boost energy naturally",
  "natural male vitality",
  "tongkat ali reviews",
  "always tired no energy",
  "how to manifest",
  "neville goddard method",
  "quantum jumping"
];

// runYoutubeRadarOnce is called from leadRadar.js radarTick every 5 minutes,
// a tick shared with Bluesky and Mastodon, neither of which has a quota
// problem. YouTube therefore throttles itself rather than slowing the tick.
//
// Quota arithmetic: 8 keywords at 100 units per search.list is 800 units per
// full pass; 8 passes a day is 6,400 units, inside the 10,000/day free quota
// with headroom for commentThreads.list at 1 unit each and for manual testing.
const MIN_RUN_INTERVAL_MS = 3 * 60 * 60 * 1000; // 3 hours

// Deliberately in-process: it resets on redeploy, which costs at most one
// extra pass. A persistent counter would mean a table and a migration for a
// problem this size.
let lastRunStartedAt = 0;

async function fetchSearchResults(keyword) {
  var url = "https://www.googleapis.com/youtube/v3/search" +
    "?part=snippet&q=" + encodeURIComponent(keyword) +
    "&type=video&order=date&maxResults=4&key=" + YOUTUBE_API_KEY;
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

  try {
    var keywords = KEYWORDS;

    for (var i = 0; i < keywords.length; i++) {
      var keyword = keywords[i];
      try {
        var searchData = await fetchSearchResults(keyword);
        var videoItems = (searchData && searchData.items) || [];
        var videoIds = videoItems
          .map(function (item) { return item.id && item.id.videoId; })
          .filter(Boolean);

        if (!videoIds.length) continue;

        var rows = [];

        for (var v = 0; v < videoIds.length; v++) {
          var videoId = videoIds[v];
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

module.exports = { runYoutubeRadarOnce };
