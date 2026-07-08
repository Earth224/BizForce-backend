require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const YOUTUBE_API_KEY      = process.env.YOUTUBE_API_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// Kept small and processed as a rotating slice (not all at once) to protect
// the YouTube Data API's daily quota — search.list and commentThreads.list
// calls are both expensive relative to the default quota.
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

const KEYWORDS_PER_RUN = 4;

// Splits KEYWORDS into fixed-size groups and picks one group based on the
// current UTC hour, so a caller invoking this on any schedule still covers
// every keyword over the course of a day without ever processing more than
// KEYWORDS_PER_RUN in a single call.
function getRotatingKeywords() {
  var groupCount = Math.ceil(KEYWORDS.length / KEYWORDS_PER_RUN);
  var groupIndex = new Date().getUTCHours() % groupCount;
  var start = groupIndex * KEYWORDS_PER_RUN;
  return KEYWORDS.slice(start, start + KEYWORDS_PER_RUN);
}

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

// Returns null (skip quietly) when comments are disabled for the video
// (YouTube returns 403 for that specific case), throws on any other error.
async function fetchCommentThreads(videoId) {
  var url = "https://www.googleapis.com/youtube/v3/commentThreads" +
    "?part=snippet&videoId=" + encodeURIComponent(videoId) +
    "&maxResults=20&order=relevance&key=" + YOUTUBE_API_KEY;
  var response = await fetch(url);
  if (response.status === 403) {
    return null;
  }
  if (!response.ok) {
    throw new Error("commentThreads.list HTTP " + response.status);
  }
  return response.json();
}

async function runYoutubeRadarOnce() {
  try {
    var keywords = getRotatingKeywords();

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
                source:          "youtube"
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
