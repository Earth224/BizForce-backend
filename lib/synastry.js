// ── Synastry — the aspects between two natal charts ──────────────────────────
//
// UNWIRED ON PURPOSE. Nothing imports this yet: no route, no timer, no line in
// server.js. Comparing two charts is a separate decision from being able to
// compare them, and this file makes no assumption about which caller arrives.
//
// PURE. Two chart objects in, one result out. No database, no network, no
// injection, no clock — the same inputs always produce the same output. That is
// not incidental: a synastry result is a claim about two people's charts, and a
// function that could reach anything else is a function whose answer could
// change for reasons that have nothing to do with either of them.
//
// The charts are expected in the shape computeNatalChart returns (server.js):
// { available, timeKnown, moonUncertain, planets: [{ name, sign, degree,
// longitude, retrograde }], ascendant, midheaven, houses, ... }.

/* THE ORBS, AND THE ONE THING TO KNOW ABOUT THEM.
   An orb is an INTERPRETIVE CHOICE, not a measured fact. The angle between two
   planets is measurable to arc-seconds; how close to exact it must be before it
   "counts" as an aspect is a convention, and traditions disagree — some work
   far tighter than these, some allow wider for the luminaries, some vary the
   orb by which planets are involved rather than by which aspect it is.

   The values below are one common middle-of-the-road set. They are not derived
   from anything in this codebase and nothing validates them; they are a
   starting position. THIS CONSTANT IS THE SINGLE PLACE TO CHANGE THEM — no orb
   is written anywhere else in this file, so widening trines is one edit here
   and not a hunt through the comparison loop. */
const ASPECTS = [
  { name: "conjunction", angle:   0, orb: 8 },
  { name: "sextile",     angle:  60, orb: 5 },
  { name: "square",      angle:  90, orb: 7 },
  { name: "trine",       angle: 120, orb: 7 },
  { name: "opposition",  angle: 180, orb: 8 }
];

/* The shortest way round the circle between two ecliptic longitudes.

   Longitudes run 0-360 and the circle wraps, so a raw subtraction makes 350°
   and 10° look 340° apart when they are 20° apart and conjunct. Taking the
   absolute difference and folding anything over 180 back through 360 gives the
   separation as an angle in 0-180, which is the range every aspect above is
   defined in. */
function angularSeparation(lonA, lonB) {
  var diff = Math.abs(Number(lonA) - Number(lonB));
  return diff > 180 ? 360 - diff : diff;
}

/* Whether a chart's Moon position can be trusted.

   The Moon moves roughly 13° a day — more than every orb in ASPECTS. Without an
   exact birth time its longitude can therefore be wrong by more than the whole
   window an aspect is judged inside, which means a lunar aspect computed from a
   timeless chart is not a weak measurement, it is an unmeasured one.

   Both flags are checked though computeNatalChart currently derives one from
   the other (`moonUncertain: !timeKnown`). Reading only the derived field would
   make this silently wrong for any future chart source that sets timeKnown
   without it, and reading only timeKnown would ignore a chart that marked its
   Moon uncertain for some other reason. */
function moonIsUncertain(chart) {
  if (!chart) return true;
  if (chart.moonUncertain === true) return true;
  if (chart.timeKnown === false) return true;
  return false;
}

/* Whether a chart's positions were computed at an assumed hour.

   computeNatalChart sets `timeAssumed: !parsedTime.known` alongside
   `timeKnown: parsedTime.known`, so the two are exact inverses today and either
   answers this. Both are read for the same reason moonIsUncertain reads two
   fields: a future chart source that sets one and not the other should not
   silently pass as precise.

   Deliberately SEPARATE from moonIsUncertain even though the underlying
   condition is currently identical, because the two mean different things and
   are used for different jobs. This one says "read these orbs as approximate".
   That one says "this particular aspect may not exist at all". Folding them
   into one flag would lose the distinction the next two comments exist to
   preserve. */
function timeWasAssumed(chart) {
  if (!chart) return false;
  if (chart.timeAssumed === true) return true;
  if (chart.timeKnown === false) return true;
  return false;
}

/* THE QUIET NOTE, once on the result rather than on every row.

   An orb printed to two decimal places from a chart computed at an assumed
   hour claims a precision the input never had. Every position in such a chart
   moved between the real birth time and the assumed one — the Sun by up to a
   degree across a day, the faster planets by more — so every orb derived from
   it is approximate, not exact, and a reader given "0.19°" has no way to know
   that from the number.

   This is the companion to the Moon rule and covers the case that one does
   not. The Moon rule catches aspects whose EXISTENCE is in doubt; this catches
   aspects that almost certainly exist but whose reported tightness should not
   be read literally. Leaving it out would let every non-lunar orb be read as
   measured.

   ONE NOTE, NOT A FLAG PER ASPECT. Marking all 29 rows of a typical result
   would make the marking meaningless — everything highlighted is nothing
   highlighted — and would bury the two rows where the flag genuinely changes
   whether to believe the aspect. The Moon alone is marked per-aspect because
   the Moon alone drifts far enough to matter at that level. */
function buildTimeNote(assumedA, assumedB) {
  if (!assumedA && !assumedB) return null;

  var subject =
    (assumedA && assumedB) ? "Both charts were" :
    assumedA               ? "The first chart was" :
                             "The second chart was";

  return subject + " computed at an assumed birth time. Every position in " +
    (assumedA && assumedB ? "them" : "it") +
    " therefore reflects an hour that was not supplied, so the orbs reported here are " +
    "approximate rather than exact and should not be read to the decimal place. The Moon is the " +
    "only body whose drift over a day is large enough to threaten whether an aspect exists at " +
    "all, which is why it alone is marked per-aspect.";
}

function emptyResult(reason) {
  return {
    available:      false,
    reason:         reason,
    aspects:        [],
    count:          0,
    uncertainCount: 0,
    // Present and null so the shape is the same whether or not there was
    // anything to compare — a caller reading result.note never has to check
    // that the key exists first.
    note:           null
  };
}

/* Every planet in chart A against every planet in chart B.

   ORDERED PAIRS, and that is the difference between synastry and a single
   chart. Within one chart, Sun-Moon and Moon-Sun are the same fact recorded
   twice, so only the unordered pairs are taken. Across two charts they are
   different facts about different people: A's Sun on B's Moon is not A's Moon
   on B's Sun, and collapsing them would discard half the comparison. So the
   loop is a full cross product, |A| x |B|, with no i<j guard.

   ANGLES AND HOUSES ARE DELIBERATELY NOT USED. ascendant, midheaven and houses
   are null in every chart computed without an exact birth time, and for the
   second person in a synastry pair that is the normal case rather than the
   exception — a user typically knows their partner's birthday and not the hour
   of it. A comparison that quietly includes angle contacts would therefore work
   fully for the user and partially for almost everyone they compare themselves
   to, with nothing on screen explaining the difference. Never offering them is
   honest; offering them and usually failing is not. Only `planets` is read. */
function computeSynastryAspects(chartA, chartB) {
  if (!chartA || !chartB) {
    return emptyResult("A chart is missing. Synastry needs two charts.");
  }

  var planetsA = Array.isArray(chartA.planets) ? chartA.planets : null;
  var planetsB = Array.isArray(chartB.planets) ? chartB.planets : null;

  if (!planetsA || !planetsB) {
    return emptyResult("A chart has no planets array, so there is nothing to compare.");
  }

  if (!planetsA.length || !planetsB.length) {
    return emptyResult("A chart has no planet positions, so there is nothing to compare.");
  }

  var moonUncertainA = moonIsUncertain(chartA);
  var moonUncertainB = moonIsUncertain(chartB);

  var aspects        = [];
  var uncertainCount = 0;

  for (var i = 0; i < planetsA.length; i++) {
    var a = planetsA[i];
    if (!a || a.longitude == null || !a.name) continue;

    for (var j = 0; j < planetsB.length; j++) {
      var b = planetsB[j];
      if (!b || b.longitude == null || !b.name) continue;

      var separation = angularSeparation(a.longitude, b.longitude);

      for (var k = 0; k < ASPECTS.length; k++) {
        var aspect = ASPECTS[k];
        // How far from exact. Reported rather than discarded: "trine, 0.4° from
        // exact" and "trine, 6.8° from exact" are the same aspect and not the
        // same statement, and a caller that only learns an aspect EXISTS cannot
        // tell them apart or rank them.
        var orb = Math.abs(separation - aspect.angle);
        if (orb > aspect.orb) continue;

        /* THE MOON RULE. Marked, never dropped and never silently included.
           An aspect computed against an unknown position looks exactly like a
           measured one — same shape, same number of decimal places, same
           confidence on screen — and that is the fabricated-measurement problem
           this codebase has been removing everywhere else: a plausible figure
           standing where a missing one should be.

           Dropping them would be a different failure of the same kind, because
           the caller could not tell an absent aspect from one that was never
           checked. So they are returned with the reason attached and the choice
           of what to do with them belongs to the caller, not to this file. */
        var uncertain = false;
        var uncertainReason = null;

        var aIsUncertainMoon = a.name === "Moon" && moonUncertainA;
        var bIsUncertainMoon = b.name === "Moon" && moonUncertainB;

        if (aIsUncertainMoon || bIsUncertainMoon) {
          uncertain = true;
          var which =
            (aIsUncertainMoon && bIsUncertainMoon) ? "Both charts' Moon positions are" :
            aIsUncertainMoon                       ? "The first chart's Moon position is" :
                                                     "The second chart's Moon position is";
          uncertainReason = which + " unreliable: no exact birth time, and the Moon moves " +
            "about 13 degrees a day — further than any orb used here, so this aspect may not exist at all.";
          uncertainCount++;
        }

        aspects.push({
          from:            { chart: "a", planet: a.name, sign: a.sign || null, longitude: a.longitude },
          to:              { chart: "b", planet: b.name, sign: b.sign || null, longitude: b.longitude },
          aspect:          aspect.name,
          exactAngle:      aspect.angle,
          separation:      separation,
          orb:             orb,
          uncertain:       uncertain,
          uncertainReason: uncertainReason
        });

        // One pair produces at most one aspect: the orbs above never overlap,
        // so a separation inside one aspect's window cannot be inside another's.
        break;
      }
    }
  }

  // Tightest first. The orb is the only ranking this function can justify —
  // anything about which aspects "matter more" is interpretation and belongs to
  // whatever renders this, not here.
  aspects.sort(function (x, y) { return x.orb - y.orb; });

  /* An OBJECT, not a bare array. A caller that destructures `aspects` and
     `count` keeps working when this grows a field; one that was handed an array
     would have to be rewritten to learn anything new. */
  return {
    available:      true,
    reason:         null,
    aspects:        aspects,
    count:          aspects.length,
    uncertainCount: uncertainCount,
    note:           buildTimeNote(timeWasAssumed(chartA), timeWasAssumed(chartB))
  };
}

module.exports = { computeSynastryAspects, ASPECTS };
