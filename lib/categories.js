"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   THE ONE CATEGORY LIST (P3-3, Nov 23 2026; migration 200's categories table).
   Posts and the Market (listings, services and the garage sale) file under the
   same list, read from the table here and nowhere else: GET /api/categories
   serves it to the composer, the Market filter and the listing form, and
   lib/posts.js and the listing routes check a slug against it. No copy of the
   list lives in code.

   list(sb)       the active categories in sort order: [{ slug, name, group }].
                  Kept for CACHE_MS per database client, so a busy feed reads the
                  table about once a minute; a read error throws and nothing is
                  kept.
   find(sb, slug) the active category with that slug, or null.
   nameOf(list, slug) its name in a list already read, or null.
   ══════════════════════════════════════════════════════════════════════════ */
const CACHE_MS = 60 * 1000;
const SLUG_RE = /^[a-z][a-z0-9_]*$/;
const cache = new WeakMap();

function isSlug(v) { return typeof v === "string" && v.length < 41 && SLUG_RE.test(v); }

async function list(sb) {
  const hit = cache.get(sb);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.rows;
  const r = await sb.from("categories").select("slug, name, parent_group, sort_order").eq("active", true).order("sort_order", { ascending: true }).limit(200);
  if (r.error) throw r.error;
  const rows = (r.data || []).filter(function (c) { return c && isSlug(c.slug) && typeof c.name === "string" && c.name; })
    .map(function (c) { return { slug: c.slug, name: c.name, group: c.parent_group || null }; });
  cache.set(sb, { at: Date.now(), rows: rows });
  return rows;
}

async function find(sb, slug) {
  if (!isSlug(slug)) return null;
  const rows = await list(sb);
  return rows.find(function (c) { return c.slug === slug; }) || null;
}

function nameOf(rows, slug) {
  const c = (rows || []).find(function (x) { return x.slug === slug; });
  return c ? c.name : null;
}

/* Forget what was kept (a check that changes the table between reads). */
function forget(sb) { cache.delete(sb); }

module.exports = { CACHE_MS, isSlug, list, find, nameOf, forget };
