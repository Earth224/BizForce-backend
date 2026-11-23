"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   _categories.js — the one category list for the checks (P3-3, Nov 23 2026).

   rows() reads migration 200's seed (INSERT INTO public.categories ...), so a
   check's fake database holds exactly the table's 32 rows (slug, name,
   parent_group, sort_order, active true) and no check types the list itself.
   ══════════════════════════════════════════════════════════════════════════ */
const fs = require("fs");
const path = require("path");

const MIGRATION = path.join(__dirname, "..", "supabase", "migrations", "200_categories_and_intent.sql");

function rows() {
  const sql = fs.readFileSync(MIGRATION, "utf8");
  const a = sql.indexOf("INSERT INTO public.categories (slug, name, parent_group, sort_order) VALUES");
  const b = sql.indexOf("ON CONFLICT (slug) DO NOTHING;", a);
  if (a < 0 || b < 0) throw new Error("migration 200's categories seed was not found");
  const out = [];
  const re = /\(\s*'([a-z_]+)'\s*,\s*'((?:[^']|'')*)'\s*,\s*(?:'([a-z_]+)'|NULL)\s*,\s*(\d+)\s*\)/g;
  let m;
  const body = sql.slice(a, b);
  while ((m = re.exec(body))) out.push({ slug: m[1], name: m[2].replace(/''/g, "'"), parent_group: m[3] || null, sort_order: Number(m[4]), active: true });
  return out;
}

module.exports = { MIGRATION, rows };
