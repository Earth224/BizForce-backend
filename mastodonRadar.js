require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const MASTODON_INSTANCE    = process.env.MASTODON_INSTANCE || "https://mastodon.social";

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const HASHTAGS = [
  "libido",
  "testosterone",
  "malehealth",
  "virility",
  "aphrodisiac",
  "herbalism",
  "biohacking",
  "manifestation",
  "lawofattraction",
  "lawofassumption",
  "nevillegoddard",
  "manifesting"
];

// Strips HTML tags from a Mastodon status's `content` field (which is
// rendered HTML, e.g. "<p>text</p>") down to plain text, decoding the
// handful of entities Mastodon actually emits.
function stripHtml(html) {
  if (!html) return "";
  return String(html)
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, "\"")
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();
}

async function fetchTagTimeline(hashtag) {
  var url = MASTODON_INSTANCE + "/api/v1/timelines/tag/" + encodeURIComponent(hashtag) + "?limit=40";
  var response = await fetch(url);
  if (!response.ok) {
    throw new Error("HTTP " + response.status);
  }
  return response.json();
}

async function runMastodonRadarOnce() {
  try {
    for (var i = 0; i < HASHTAGS.length; i++) {
      var hashtag = HASHTAGS[i];
      try {
        var statuses = await fetchTagTimeline(hashtag);

        if (!Array.isArray(statuses) || !statuses.length) continue;

        var rows = statuses.map(function (status) {
          return {
            post_uri:        status.url,
            post_id:         status.id != null ? String(status.id) : null,
            post_cid:        null,
            author_did:      null,
            author_handle:   status.account && status.account.acct,
            post_text:       stripHtml(status.content),
            matched_keyword: hashtag,
            lang:            status.language || null,
            source:          "mastodon"
          };
        });

        if (!rows.length) continue;

        var { error } = await supabase
          .from("bsky_leads")
          .upsert(rows, { onConflict: "post_uri", ignoreDuplicates: true });

        if (error) {
          console.error("[MastodonRadar] Supabase upsert error for hashtag '" + hashtag + "':", error.message);
          continue;
        }

        console.log("[MastodonRadar] " + hashtag + " -> " + rows.length + " new leads");

      } catch (tagErr) {
        console.error("[MastodonRadar] Error processing hashtag '" + hashtag + "':", tagErr.message || tagErr);
      }
    }
  } catch (err) {
    console.error("[MastodonRadar] runMastodonRadarOnce error:", err.message || err);
  }
}

module.exports = { runMastodonRadarOnce };
