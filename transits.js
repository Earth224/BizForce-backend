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

// Root-find the instant the aspect is exact inside [t1, t2].
// Guards against the antipodal wrap producing a false sign change.
function findExact(body, natalLon, angle, branch, t1, t2) {
  var f = function (t) {
    return offsetFromAspect(lonAt(body, t), natalLon, angle, branch);
  };
  var f1 = f(t1), f2 = f(t2);
  if (f1 === 0) return t1;
  if ((f1 < 0) === (f2 < 0)) return null;
  if (Math.abs(f1 - f2) > 180) return null; // wrap artefact, not a real crossing
  return Astronomy.Search(f, t1, t2, { dt_tolerance_seconds: 60, init_f1: f1, init_f2: f2 });
}

/**
 * @param natalLongitudes  { Sun: deg, Moon: deg, ... } from computeEclipticLongitudes
 * @param nowUtc           Date
 * @param opts.forwardDays how far ahead to search for exact hits (default 180)
 * @param opts.transiting  which bodies transit (default: all but Moon)
 * @param opts.natalTargets which natal points receive (default: all ten)
 */
function computeTransits(natalLongitudes, nowUtc, opts) {
  opts = opts || {};
  var forwardDays = opts.forwardDays || 180;
  var transiting = opts.transiting || NATAL_PLANET_NAMES.filter(function (n) { return n !== "Moon"; });
  var targets = opts.natalTargets || NATAL_PLANET_NAMES;

  var t0 = Astronomy.MakeTime(nowUtc);
  var tEnd = t0.AddDays(forwardDays);
  var results = [];

  transiting.forEach(function (body) {
    var speed = BODY_SPEED[body];
    // Step must be well under the time it takes to cross the whole orb, or an
    // exact hit can be stepped over entirely. Half an orb-width of motion.
    var step = Math.max(0.25, Math.min(10, speed.daysPerDegree * 1.5));
    var lonNow = lonAt(body, t0);

    targets.forEach(function (target) {
      var natalLon = natalLongitudes[target];

      ASPECTS.forEach(function (aspect) {
        branchesFor(aspect.angle).forEach(function (branch) {
          var offNow = offsetFromAspect(lonNow, natalLon, aspect.angle, branch);
          var absOff = Math.abs(offNow);

          // Scan forward for every exact hit in the window. Retrograde motion
          // can produce two or three passes over the same aspect; each one is
          // a separate event and the multi-pass case is the one people pay to
          // understand.
          var hits = [];
          var t = t0;
          while (t.tt < tEnd.tt && hits.length < 5) {
            var tNext = t.AddDays(step);
            if (tNext.tt > tEnd.tt) tNext = tEnd;
            var hit = findExact(body, natalLon, aspect.angle, branch, t, tNext);
            if (hit) hits.push(hit);
            if (tNext.tt === tEnd.tt) break;
            t = tNext;
          }

          if (absOff > aspect.orb && hits.length === 0) return;

          // Applying vs separating: sample the offset a short interval later.
          // Shrinking magnitude means the aspect is closing.
          var probe = t0.AddDays(Math.max(0.02, speed.daysPerDegree * 0.05));
          var offLater = offsetFromAspect(lonAt(body, probe), natalLon, aspect.angle, branch);
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
