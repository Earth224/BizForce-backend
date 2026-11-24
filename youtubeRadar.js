require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");
const { YOUTUBE_API_UNITS, youtubeCaps, youtubeUnitsToday, youtubeUtcDay, reserveYoutubeUnits } = require("./lib/youtubeQuota");
const { isUsefulYoutubeComment } = require("./lib/youtubeFilter");

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const YOUTUBE_API_KEY      = process.env.YOUTUBE_API_KEY;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

/* NAMED (Nov 23 2026, LR-2): YOUTUBE FOR EACH MEMBER. BEFORE this file ran ONE platform pass every 3 hours over a
   fixed list of eight video searches (the owner's own products) and wrote bsky_leads rows with status "signal".
   AFTER it is the YouTube half of lib/memberRadar.js: a member with YouTube switched on in their Fingerprint has
   one of their own keywords searched at most every 3 hours, from an EQUAL SHARE of the radar's daily units
   (lib/memberRadar.js youtubeShare), and the comments become that member's leads (member_leads, source youtube,
   opened, never replied to; deleted after 30 days). The fixed list moves into the owner's Fingerprint
   (scripts/oneoff/lr2SeedOwner.js).

   Quota, unchanged in kind: every call reserves its units in youtube_api_calls BEFORE it is sent
   (lib/youtubeQuota.js), as caller "radar" and now with the member's user_id, and no call is made when the ledger
   cannot be read or written. A search and its comment calls must fit the whole key's cap
   (YOUTUBE_DAILY_UNIT_CAP), the radar's (YOUTUBE_RADAR_DAILY_UNITS) and the member's share. */

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
// or invalid key — so the body has to be read to tell them apart.
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

/* The radar units this member has used today (caller radar, their user_id). null when the ledger cannot be read. */
async function unitsUsedBy(userId, nowMs) {
  var r = await supabase.from("youtube_api_calls").select("units").eq("created_on", youtubeUtcDay(nowMs)).eq("caller", "radar").eq("user_id", userId).limit(5000);
  if (r.error) return null;
  return (r.data || []).reduce(function (sum, row) { return sum + (Number(row.units) || 0); }, 0);
}

async function unitsToday(nowMs) {
  try { return await youtubeUnitsToday(supabase, nowMs); } catch (e) { console.error("[YoutubeRadar] " + (e.message || e)); return null; }
}

/* One member's search: the videos for `keyword` and their comments, every call's units reserved first under the
   member's id. Returns [{ id, text, author, published_at, url }]; [] when no call could be made. */
async function searchComments(userId, keyword) {
  if (!YOUTUBE_API_KEY) {
    console.error("[YoutubeRadar] YOUTUBE_API_KEY is not set; no YouTube call made.");
    return [];
  }
  async function reserve(method) {
    try { await reserveYoutubeUnits(supabase, { caller: "radar", method: method, user_id: userId }); return true; }
    catch (ledgerErr) { console.error("[YoutubeRadar] No YouTube call: " + (ledgerErr.message || ledgerErr) + "."); return false; }
  }
  var out = [];
  if (!(await reserve("search.list"))) return out;
  var searchData;
  try { searchData = await fetchSearchResults(keyword); } catch (e) { console.error("[YoutubeRadar] search failed: " + (e.message || e)); return out; }
  var videoIds = ((searchData && searchData.items) || []).map(function (item) { return item.id && item.id.videoId; }).filter(Boolean);
  for (var v = 0; v < videoIds.length && v < SEARCH_MAX_RESULTS; v++) {
    if (!(await reserve("commentThreads.list"))) break;
    var data;
    try { data = await fetchCommentThreads(videoIds[v]); } catch (e) { console.error("[YoutubeRadar] comments failed: " + (e.message || e)); continue; }
    if (!data) continue;
    (data.items || []).forEach(function (item) {
      var thread = item.snippet && item.snippet.topLevelComment;
      var sn = thread && thread.snippet;
      if (!thread || !sn) return;
      out.push({
        id: thread.id,
        text: sn.textOriginal || sn.textDisplay || "",
        author: sn.authorDisplayName || null,
        // The COMMENT's own time, not the video's (updatedAt for an edited comment with no publishedAt).
        published_at: sn.publishedAt || sn.updatedAt || null,
        url: "https://www.youtube.com/watch?v=" + videoIds[v] + "&lc=" + thread.id
      });
    });
  }
  return out;
}

/* What lib/memberRadar.js captureYoutube needs (deps.youtube). */
function memberYoutubeDeps() {
  return {
    caps: function () { return youtubeCaps(process.env); },
    worstCase: SEARCH_WORST_CASE_UNITS,
    unitsUsedBy: unitsUsedBy,
    unitsToday: unitsToday,
    searchComments: searchComments,
    useful: isUsefulYoutubeComment
  };
}

module.exports = { SEARCH_MAX_RESULTS, SEARCH_WORST_CASE_UNITS, fetchSearchResults, fetchCommentThreads, unitsUsedBy, unitsToday, searchComments, memberYoutubeDeps };
