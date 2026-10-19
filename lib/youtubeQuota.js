// ── YouTube API units: reserved against a daily cap before they are spent ────
//
// Every YouTube Data API call RESERVES its units first: a row in
// public.youtube_api_calls (migration 138) is inserted BEFORE the request is
// sent, so a call that fails, times out or is never answered still counts.
// Today's spend is the sum of today's rows (a UTC date), over every caller.
//
// FAIL CLOSED. If the ledger cannot be read or written — the table not existing
// yet included — no YouTube call is made. If a cap variable is set to anything
// but a positive whole number, no YouTube call is made. A caller checks both
// before every request and stops its pass on the first failure.
//
// No model call, no network: this module is given the Supabase client and
// requires nothing.

/* Units per call. From the YouTube Data API's quota cost table, as recorded in
   youtubeRadar.js since 5746f53 (search.list 100, commentThreads.list 1).
   APPROXIMATE: NOT re-verified in this build, which made no external call;
   check them against Google's own quota calculator before trusting the caps
   to the unit. */
var YOUTUBE_API_UNITS = {
  "search.list": 100,
  "commentThreads.list": 1
};

// The whole API key, all callers, per UTC day.
var YOUTUBE_DAILY_UNIT_CAP_DEFAULT = 5000;
// The radar's share of it, per UTC day.
var YOUTUBE_RADAR_DAILY_UNITS_DEFAULT = 2500;

var YOUTUBE_LEDGER_PAGE = 1000;

/* A cap from the environment, on agentScheduleMaxPerTick's three outcomes:
   absent or blank gives the default; a positive whole number is honoured;
   anything else — "0", "-1", "abc", "2.5" — is null, and null means no
   YouTube call at all, never the default. A typo must not raise the cap. */
function youtubeCap(raw, dflt) {
  if (raw == null || String(raw).trim() === "") {
    return dflt;
  }

  var parsed = Number(String(raw).trim());
  if (Number.isFinite(parsed) && Number.isInteger(parsed) && parsed > 0) {
    return parsed;
  }

  return null;
}

// Both caps, and the reason no call may be made when either is unusable.
function youtubeCaps(env) {
  env = env || process.env;
  var daily = youtubeCap(env.YOUTUBE_DAILY_UNIT_CAP, YOUTUBE_DAILY_UNIT_CAP_DEFAULT);
  var radar = youtubeCap(env.YOUTUBE_RADAR_DAILY_UNITS, YOUTUBE_RADAR_DAILY_UNITS_DEFAULT);
  var error = daily === null ? "YOUTUBE_DAILY_UNIT_CAP is set but is not a positive whole number"
    : radar === null ? "YOUTUBE_RADAR_DAILY_UNITS is set but is not a positive whole number"
    : null;
  return { daily: daily, radar: radar, error: error };
}

function youtubeUtcDay(nowMs) {
  return new Date(typeof nowMs === "number" ? nowMs : Date.now()).toISOString().slice(0, 10);
}

/* Today's units, all callers and the radar's own. Throws when the ledger
   cannot be read, and the caller treats a throw as "no call". Paged, because
   a day at the default cap can hold thousands of one-unit rows. */
async function youtubeUnitsToday(supabase, nowMs) {
  var day = youtubeUtcDay(nowMs);
  var total = 0, radar = 0;
  for (var from = 0; ; from += YOUTUBE_LEDGER_PAGE) {
    var page = await supabase
      .from("youtube_api_calls")
      .select("caller, units")
      .eq("created_on", day)
      .order("id", { ascending: true })
      .range(from, from + YOUTUBE_LEDGER_PAGE - 1);
    if (page.error) {
      throw new Error("youtube_api_calls could not be read: " + page.error.message);
    }
    var rows = page.data || [];
    rows.forEach(function (row) {
      var units = Number(row.units) || 0;
      total += units;
      if (row.caller === "radar") radar += units;
    });
    if (rows.length < YOUTUBE_LEDGER_PAGE) break;
  }
  return { day: day, total: total, radar: radar };
}

/* Reserve one call's units, before the call. Throws when the row cannot be
   written; the caller must then not make the call. Units are never given
   back: a call that fails after this still spent them. */
async function reserveYoutubeUnits(supabase, entry, nowMs) {
  var units = YOUTUBE_API_UNITS[entry.method];
  if (!units) {
    throw new Error("no unit cost is recorded for " + entry.method);
  }
  var result = await supabase
    .from("youtube_api_calls")
    .insert({
      created_on: youtubeUtcDay(nowMs),
      caller: entry.caller,
      user_id: entry.user_id || null,
      units: units
    });
  if (result.error) {
    throw new Error("youtube_api_calls could not be written: " + result.error.message);
  }
  return units;
}

module.exports = {
  YOUTUBE_API_UNITS: YOUTUBE_API_UNITS,
  YOUTUBE_DAILY_UNIT_CAP_DEFAULT: YOUTUBE_DAILY_UNIT_CAP_DEFAULT,
  YOUTUBE_RADAR_DAILY_UNITS_DEFAULT: YOUTUBE_RADAR_DAILY_UNITS_DEFAULT,
  youtubeCap: youtubeCap,
  youtubeCaps: youtubeCaps,
  youtubeUtcDay: youtubeUtcDay,
  youtubeUnitsToday: youtubeUnitsToday,
  reserveYoutubeUnits: reserveYoutubeUnits
};
