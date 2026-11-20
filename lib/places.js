"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   A member's place, for the Local feed (P2-1, Nov 19 2026; migration 189).

   The member types it in Settings, Local: a city, a region (a state, a
   province, a county) and a country, chosen from COUNTRY_CODES, the ISO
   3166-1 alpha-2 list. It is NEVER taken from the device: no geolocation, no
   IP lookup. "Show my posts in Local" (local_opt_in) is off until the member
   turns it on; while it is off the place is kept but nothing of it is shown.

   The columns are bf_profiles.place_city, place_region, place_country and
   local_opt_in. The database holds the shape (each text 1 to 80 characters,
   the country two capital letters); this file holds the list the country
   must come from, which a CHECK could not.
   ══════════════════════════════════════════════════════════════════════════ */

const COUNTRY_CODES = (
  "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
  "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR " +
  "GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP " +
  "KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT " +
  "MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW " +
  "SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG " +
  "UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW"
).split(" ");

const PLACE_TEXT_MAX = 80;

/* One typed field: trimmed, inner whitespace made single, at most 80
   characters; empty is null (not set). */
function placeText(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string") return undefined;
  const t = value.replace(/\s+/g, " ").trim();
  if (!t) return null;
  if (t.length > PLACE_TEXT_MAX) return undefined;
  return t;
}

/* The body of PUT /api/me/place, checked: { updates } (only the keys the
   body carried) or { error, field }. */
function placeUpdates(body) {
  const b = body || {};
  const updates = {};
  for (const key of ["place_city", "place_region"]) {
    if (!Object.prototype.hasOwnProperty.call(b, key)) continue;
    const v = placeText(b[key]);
    if (v === undefined) return { error: (key === "place_city" ? "The city" : "The region") + " must be text of at most " + PLACE_TEXT_MAX + " characters.", field: key };
    updates[key] = v;
  }
  if (Object.prototype.hasOwnProperty.call(b, "place_country")) {
    const c = b.place_country;
    if (c === null || c === "") updates.place_country = null;
    else if (typeof c === "string" && COUNTRY_CODES.indexOf(c) !== -1) updates.place_country = c;
    else return { error: "Choose the country from the list.", field: "place_country" };
  }
  if (Object.prototype.hasOwnProperty.call(b, "local_opt_in")) {
    if (typeof b.local_opt_in !== "boolean") return { error: "\"Show my posts in Local\" is on or off.", field: "local_opt_in" };
    updates.local_opt_in = b.local_opt_in;
  }
  return { updates: updates };
}

/* The place as the member's own Settings reads it. */
function placeReply(row) {
  const r = row || {};
  return {
    place_city: r.place_city || null,
    place_region: r.place_region || null,
    place_country: COUNTRY_CODES.indexOf(r.place_country) !== -1 ? r.place_country : null,
    local_opt_in: r.local_opt_in === true
  };
}

module.exports = { COUNTRY_CODES, PLACE_TEXT_MAX, placeText, placeUpdates, placeReply };
