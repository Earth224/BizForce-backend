"use strict";

var Astronomy = require("astronomy-engine");

var NATAL_PLANET_NAMES = ["Sun","Moon","Mercury","Venus","Mars","Jupiter","Saturn","Uranus","Neptune","Pluto"];

// Mirrors server.js:10456 exactly. Same bodies, same aberration flag, same
// ecl.elon read, no rounding.
function computeEclipticLongitudes(utcDate) {
  var longitudes = {};
  NATAL_PLANET_NAMES.forEach(function (name) {
    var vec = Astronomy.GeoVector(Astronomy.Body[name], utcDate, true);
    var ecl = Astronomy.Ecliptic(vec);
    longitudes[name] = ecl.elon;
  });
  return longitudes;
}

var ASPECTS = [
  { name: "conjunction", angle: 0,   orb: 3.0 },
  { name: "sextile",     angle: 60,  orb: 2.0 },
  { name: "square",      angle: 90,  orb: 3.0 },
  { name: "trine",       angle: 120, orb: 3.0 },
  { name: "opposition",  angle: 180, orb: 3.0 }
];

// Days for one degree of motion, roughly. Used only to size the search step so
// no exact hit is stepped over, and to classify reporting speed.
var BODY_SPEED = {
  Moon:    { daysPerDegree: 0.076, klass: "fast"   },
  Sun:     { daysPerDegree: 1.01,  klass: "medium" },
  Mercury: { daysPerDegree: 0.7,   klass: "medium" },
  Venus:   { daysPerDegree: 0.8,   klass: "medium" },
  Mars:    { daysPerDegree: 1.9,   klass: "medium" },
  Jupiter: { daysPerDegree: 12.0,  klass: "slow"   },
  Saturn:  { daysPerDegree: 30.0,  klass: "slow"   },
  Uranus:  { daysPerDegree: 84.0,  klass: "slow"   },
  Neptune: { daysPerDegree: 164.0, klass: "slow"   },
  Pluto:   { daysPerDegree: 248.0, klass: "slow"   }
};

// Wrap to [-180, +180). Continuous everywhere except at the antipode, where it
// jumps from just under +180 to -180. findExact guards against that jump.
function wrap180(x) {
  return ((((x + 180) % 360) + 360) % 360) - 180;
}

// Unsigned 0..180 separation.
function separation(a, b) {
  return Math.abs(wrap180(a - b));
}

// Signed distance from exact aspect, in degrees. Zero at exactness.
// For a target angle t, exactness is at wrap180(diff) = +t or -t; the two
// branches are the same point when t is 0 or 180.
function offsetFromAspect(transitLon, natalLon, angle, branch) {
  return wrap180(transitLon - natalLon - branch * angle);
}

function branchesFor(angle) {
  return (angle === 0 || angle === 180) ? [1] : [1, -1];
}

function lonAt(body, time) {
  var vec = Astronomy.GeoVector(Astronomy.Body[body], time, true);
  return Astronomy.Ecliptic(vec).elon;
}

// Root-find the instant the aspect is exact inside a bracket already known to
// contain a sign change. f1 and f2 are passed in because the caller computed
// them from the sampled timeline; recomputing them here would undo the point of
// sampling.
//
// CRITICAL: Astronomy.Search CANNOT be trusted to report absence. It fits a
// quadratic and returns null when the fit does not land inside the bracket,
// which is indistinguishable from "no crossing here". Measured: the bracket
// 2026-09-09..2026-09-19 for Saturn trine a natal Uranus at 253.0320 carries a
// genuine sign change from +0.1258 to -0.5760, and Search returns null on it.
// Narrow the same bracket by five days and it returns the answer at once.
//
// An earlier version of this file treated that null as "no transit" and
// silently dropped real events - six of twenty-two on one test chart, including
// a Saturn trine six weeks out. Losing a transit is worse than any other failure
// this module can have, because the output still looks complete.
//
// So: Search for speed, and bisection whenever it declines. Bisection cannot
// fail on a bracketed sign change - it only halves - and at roughly twelve
// iterations for one-minute precision over a three-day bracket it costs
// nothing. The caller has already proven the sign change exists; this function's
// only job is to locate it, never to second-guess whether it is there.
function findExactBracketed(body, natalLon, angle, branch, t1, t2, f1, f2) {
  var f = function (t) {
    return offsetFromAspect(lonAt(body, t), natalLon, angle, branch);
  };

  var found = Astronomy.Search(f, t1, t2, {
    dt_tolerance_seconds: 60,
    init_f1: f1,
    init_f2: f2
  });
  if (found) return found;

  return bisectExact(f, t1, t2, f1, f2);
}

// Plain bisection to one-minute precision. Total by construction: given
// endpoints of opposite sign it always returns an instant between them.
function bisectExact(f, t1, t2, f1, f2) {
  var lo = t1, hi = t2, fLo = f1;
  var toleranceDays = 60 / 86400;

  for (var i = 0; i < 60 && (hi.tt - lo.tt) > toleranceDays; i++) {
    var mid = lo.AddDays((hi.tt - lo.tt) / 2);
    var fMid = f(mid);
    if (fMid === 0) return mid;
    if ((fMid < 0) === (fLo < 0)) {
      lo = mid;
      fLo = fMid;
    } else {
      hi = mid;
    }
  }
  return lo.AddDays((hi.tt - lo.tt) / 2);
}

/**
 * @param natalLongitudes  { Sun: deg, ... } from computeEclipticLongitudes
 * @param nowUtc           Date
 * @param opts.forwardDays how far ahead to search for exact hits (default 180)
 * @param opts.transiting  which bodies transit (default: all but Moon)
 * @param opts.natalTargets which natal points receive (default: all ten)
 *
 * COST. The obvious implementation — for every (body, target, aspect, branch),
 * walk forward and root-find — recomputes each body's longitude roughly ninety
 * times over, once per target x aspect x branch combination. Measured at 54,194
 * GeoVector evaluations for one report, about 1.3 seconds, of which well under
 * a hundredth was distinct work.
 *
 * A body's position at a given instant does not depend on which natal point or
 * aspect is being tested. So each body's longitude is sampled ONCE across the
 * window, and every combination then scans that array for sign changes in pure
 * arithmetic. Astronomy.Search runs only inside a bracket already known to
 * contain a crossing.
 *
 * This matters beyond speed. computeTransitReport is synchronous, and Node is
 * single-threaded: a 1.3-second synchronous call does not make one route slow,
 * it stops the entire process, and every other in-flight request waits behind
 * it. Sampling also lets the step be made FINER rather than coarser, since
 * samples are now nearly free — which closes the real correctness risk, a
 * retrograde station sitting so close to an exact aspect that both crossings
 * fall inside one coarse step and neither is found.
 */
function computeTransits(natalLongitudes, nowUtc, opts) {
  opts = opts || {};
  var forwardDays = opts.forwardDays || 180;
  var transiting = opts.transiting || NATAL_PLANET_NAMES.filter(function (n) { return n !== "Moon"; });
  var targets = opts.natalTargets || NATAL_PLANET_NAMES;

  var t0 = Astronomy.MakeTime(nowUtc);
  var results = [];

  transiting.forEach(function (body) {
    var speed = BODY_SPEED[body];

    // Half a degree of the body's own motion, clamped. Fine enough that a
    // retrograde loop tight against an exact aspect still produces two distinct
    // bracketed crossings; coarse enough that a slow planet over a year is a
    // few hundred samples rather than tens of thousands.
    var step = Math.max(0.25, Math.min(3, speed.daysPerDegree * 0.5));

    // Sample the body once across the whole window. Everything below reads this
    // array and never touches the ephemeris again except inside a bracket.
    var times = [];
    var lons = [];
    for (var d = 0; d <= forwardDays; d += step) {
      var t = t0.AddDays(d);
      times.push(t);
      lons.push(lonAt(body, t));
    }
    if (times[times.length - 1].tt < t0.AddDays(forwardDays).tt) {
      var tLast = t0.AddDays(forwardDays);
      times.push(tLast);
      lons.push(lonAt(body, tLast));
    }

    var lonNow = lons[0];

    // One extra evaluation per body, not per combination, for applying vs
    // separating. Sampled at a fixed small fraction of the body's own motion so
    // a slow planet is not judged on a change beneath floating-point noise.
    var probeTime = t0.AddDays(Math.max(0.02, speed.daysPerDegree * 0.05));
    var lonProbe = lonAt(body, probeTime);

    targets.forEach(function (target) {
      var natalLon = natalLongitudes[target];

      ASPECTS.forEach(function (aspect) {
        branchesFor(aspect.angle).forEach(function (branch) {
          var offNow = offsetFromAspect(lonNow, natalLon, aspect.angle, branch);
          var absOff = Math.abs(offNow);

          // Scan the precomputed timeline for sign changes. Pure arithmetic on
          // an array already in memory. Retrograde motion can carry a body over
          // the same aspect two or three times; each crossing is its own
          // bracket and its own event.
          var hits = [];
          for (var i = 0; i < lons.length - 1; i++) {
            var f1 = offsetFromAspect(lons[i], natalLon, aspect.angle, branch);
            var f2 = offsetFromAspect(lons[i + 1], natalLon, aspect.angle, branch);
            if (f1 === 0) { hits.push(times[i]); continue; }
            if ((f1 < 0) === (f2 < 0)) continue;
            if (Math.abs(f1 - f2) > 180) continue; // antipodal wrap, not a crossing
            var hit = findExactBracketed(body, natalLon, aspect.angle, branch,
                                         times[i], times[i + 1], f1, f2);
            if (hit) hits.push(hit);
            if (hits.length >= 5) break;
          }

          if (absOff > aspect.orb && hits.length === 0) return;

          var offLater = offsetFromAspect(lonProbe, natalLon, aspect.angle, branch);
          var motion = Math.abs(offLater) < absOff ? "applying" : "separating";

          results.push({
            transiting: body,
            natal: target,
            aspect: aspect.name,
            exactAngle: aspect.angle,
            orb: Number(absOff.toFixed(3)),
            withinOrb: absOff <= aspect.orb,
            status: absOff <= aspect.orb ? "active" : "upcoming",
            motion: motion,
            speedClass: speed.klass,
            passes: hits.length,
            exactDates: hits.map(function (h) { return h.date.toISOString(); })
          });
        });
      });
    });
  });

  results.sort(function (a, b) {
    if (a.withinOrb !== b.withinOrb) return a.withinOrb ? -1 : 1;
    return a.orb - b.orb;
  });
  return results;
}

module.exports = {
  computeEclipticLongitudes: computeEclipticLongitudes,
  computeTransits: computeTransits,
  separation: separation,
  wrap180: wrap180,
  ASPECTS: ASPECTS,
  NATAL_PLANET_NAMES: NATAL_PLANET_NAMES
};

var SLOW_BODIES = ["Jupiter", "Saturn", "Uranus", "Neptune", "Pluto"];

/**
 * The two products, computed separately because they answer different questions.
 *
 *   active    what is in effect right now, any transiting body except the Moon.
 *   calendar  dated exact hits ahead, SLOW BODIES ONLY. A Mercury trine that is
 *             exact next Tuesday and gone by Wednesday is not forecast, it is
 *             noise, and noise is what makes a subscriber cancel. Only the
 *             outer planets produce events worth naming a date for.
 */
function computeTransitReport(natalLongitudes, nowUtc, opts) {
  opts = opts || {};
  var active = computeTransits(natalLongitudes, nowUtc, {
    forwardDays: opts.activeForwardDays || 45,
    transiting: opts.activeTransiting ||
      NATAL_PLANET_NAMES.filter(function (n) { return n !== "Moon"; })
  }).filter(function (r) { return r.status === "active"; });

  var calendar = computeTransits(natalLongitudes, nowUtc, {
    forwardDays: opts.calendarForwardDays || 365,
    transiting: SLOW_BODIES
  }).filter(function (r) { return r.passes > 0; });

  var events = [];
  calendar.forEach(function (r) {
    r.exactDates.forEach(function (d) {
      events.push({
        date: d,
        transiting: r.transiting,
        natal: r.natal,
        aspect: r.aspect,
        passOf: r.passes,
        motionNow: r.motion,
        orbNow: r.orb
      });
    });
  });
  events.sort(function (a, b) { return a.date < b.date ? -1 : 1; });

  return { computedAt: nowUtc.toISOString(), active: active, events: events };
}

module.exports.computeTransitReport = computeTransitReport;
module.exports.SLOW_BODIES = SLOW_BODIES;
