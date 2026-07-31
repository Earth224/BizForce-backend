"use strict";

// A bounded, TTL'd, in-process cache. No dependency, no network, no database.
//
// This exists for one shape of problem: a value that is expensive to compute,
// deterministic given its key, and cheap to recompute if lost. Transit reports
// are exactly that — roughly 1.5 seconds of ephemeris arithmetic that yields the
// identical answer every time for a given natal chart on a given day.
//
// Deliberately NOT persistent. A transit report is arithmetic, not state.
// Persisting it to Postgres would buy durability nobody needs and cost a
// migration, a schema surface and a staleness question. A cold cache after a
// redeploy costs one recomputation.
//
// Two bounds, both required, because a cache with only one is a memory leak
// wearing a disguise:
//   maxEntries — hard ceiling on size. Oldest-inserted evicted first.
//   ttlMs      — hard ceiling on age. Nothing is served stale.
//
// Insertion-ordered eviction, not true LRU. For this workload they are close to
// identical and a Map's native ordering makes it exact and free. If a future
// caller needs real recency ordering, `get` would need to re-insert on hit —
// which is a deliberate change, not an oversight.

function createTtlCache(options) {
  options = options || {};
  var maxEntries = options.maxEntries || 500;
  var ttlMs = options.ttlMs || 24 * 60 * 60 * 1000;
  var store = new Map();
  var hits = 0;
  var misses = 0;
  var evictions = 0;
  var expirations = 0;

  function get(key) {
    var entry = store.get(key);
    if (!entry) {
      misses += 1;
      return undefined;
    }
    if (Date.now() - entry.storedAt > ttlMs) {
      store.delete(key);
      expirations += 1;
      misses += 1;
      return undefined;
    }
    hits += 1;
    return entry.value;
  }

  function set(key, value) {
    if (store.has(key)) store.delete(key);
    store.set(key, { value: value, storedAt: Date.now() });
    while (store.size > maxEntries) {
      var oldest = store.keys().next().value;
      store.delete(oldest);
      evictions += 1;
    }
    return value;
  }

  // Compute-on-miss. The producer is synchronous; if it throws, nothing is
  // cached and the error propagates unchanged to the caller.
  //
  // LIMITATION: a producer that legitimately returns `undefined` will be re-run
  // on every call, because `undefined` is the miss sentinel. null, 0, false and
  // "" all cache correctly. No current caller returns undefined; if one ever
  // does, this needs a separate has() check rather than a silent slowdown.
  function getOrCompute(key, produce) {
    var found = get(key);
    if (found !== undefined) return found;
    return set(key, produce());
  }

  function stats() {
    return {
      size: store.size,
      maxEntries: maxEntries,
      ttlMs: ttlMs,
      hits: hits,
      misses: misses,
      evictions: evictions,
      expirations: expirations
    };
  }

  function clear() {
    store.clear();
  }

  return {
    get: get,
    set: set,
    getOrCompute: getOrCompute,
    stats: stats,
    clear: clear
  };
}

module.exports = createTtlCache;
