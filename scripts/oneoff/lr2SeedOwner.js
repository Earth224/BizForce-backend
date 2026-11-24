/* ═══════════════════════════════════════════════════════════════════════════
   scripts/oneoff/lr2SeedOwner.js — LR-2 (Nov 23 2026): the old platform radar's words move into the
   owner's own Lead Radar Fingerprint.
     node scripts/oneoff/lr2SeedOwner.js            dry run: reads only, writes nothing
     node scripts/oneoff/lr2SeedOwner.js --apply    writes the owner's Fingerprint (needs migration 204)

   WHERE THE WORDS COME FROM. Until LR-2 the radar searched three fixed lists for the owner: leadRadar.js
   KEYWORDS (25 Bluesky questions about the owner's supplements and book), BIZFORCE_KEYWORDS (7 phrases from
   businesses the ad networks refused) and youtubeRadar.js KEYWORDS (8 video searches). LR-2 removed the lists;
   they are copied here, word for word, from backend 65c0825.

   WHAT IS WRITTEN. A Fingerprint holds at most 12 words (lib/leadFingerprint.js MAX_WORDS), so 12 are moved:
   the 7 BizForce phrases (the platform's own business) and one question from each of the five other themes
   (supplements, libido, energy, manifestation, quantum jumping). The other words are listed as NOT MOVED: the
   owner swaps any of them in from the Fingerprint screen. NAMED (Nov 24 2026, LR-2B): they are stored as the owner's
   spare words (agent_memory, memory_key lead_radar_spare_words), shown there as chips that swap in. The keywords field is then locked (edited_fields),
   so an automatic rebuild never replaces it. Sources: Inside BizForce, Bluesky and YouTube on (the old radar
   searched Bluesky and YouTube), Threads off until the owner connects it. Every other field is built
   automatically from what BizForce holds (lib/leadFingerprint.js rebuild), as for any member.
   Nothing else is written: no lead, no model call, no post, no message.
   ═══════════════════════════════════════════════════════════════════════════ */
"use strict";
const path = require("path");
process.chdir(path.join(__dirname, "..", ".."));
require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");
const FP = require("../../lib/leadFingerprint");
const { OWNER_ACCOUNT_ID } = require("../../lib/ownerAccount");
const APPLY = process.argv.indexOf("--apply") !== -1;

const OLD_BLUESKY = ["anyone tried tongkat ali", "does tongkat ali actually work", "get my sex drive back", "what helped your low libido",
  "why is my libido low", "struggling with low libido", "what worked for low libido", "recommendations for low energy", "anyone else always tired",
  "what supplements actually work", "anyone recommend an energy supplement", "anything to eat for energy", "supplement recommendations for fatigue",
  "anyone had luck with ashwagandha", "why isn't my manifestation working", "manifestation isn't working for me", "does manifestation actually work",
  "how do i actually manifest", "am i manifesting wrong", "what helped you manifest", "anyone had luck manifesting", "struggling with law of assumption",
  "is law of assumption real", "anyone tried quantum jumping", "does quantum jumping actually work"];
const OLD_BIZFORCE = ["ad account disabled", "meta rejected my ad", "stripe froze my account", "shadowbanned my business", "can't advertise supplements",
  "payment processor dropped me", "my account got flagged selling"];
const OLD_YOUTUBE = ["does tongkat ali actually work", "how to increase libido naturally", "why am i always tired", "what supplements actually work",
  "how to boost energy naturally", "why isn't my manifestation working", "does manifestation actually work", "does quantum jumping actually work"];

const MOVED = OLD_BIZFORCE.concat(["anyone tried tongkat ali", "what helped your low libido", "recommendations for low energy",
  "why isn't my manifestation working", "anyone tried quantum jumping"]);
const SOURCES = { bizforce: true, bluesky: true, youtube: true, threads: false };

function all() {
  var out = [];
  OLD_BLUESKY.concat(OLD_BIZFORCE, OLD_YOUTUBE).forEach(function (w) { var n = FP.normalizeWord(w); if (n && out.indexOf(n) === -1) out.push(n); });
  return out;
}

async function main() {
  const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
  const moved = FP.wordList(MOVED, FP.MAX_WORDS);
  if (moved.length !== MOVED.length) throw new Error("a moved word does not normalize or repeats: " + JSON.stringify(MOVED));
  const notMoved = all().filter(function (w) { return moved.indexOf(w) === -1; });
  console.log((APPLY ? "APPLY" : "DRY RUN") + " " + new Date().toISOString() + ", owner " + OWNER_ACCOUNT_ID);
  console.log("OLD LISTS: Bluesky " + OLD_BLUESKY.length + ", BizForce " + OLD_BIZFORCE.length + ", YouTube " + OLD_YOUTUBE.length + "; " + all().length + " distinct words.");
  console.log("WOULD MOVE into the owner's Fingerprint keywords (" + moved.length + " of at most " + FP.MAX_WORDS + ", locked against rebuilds):");
  moved.forEach(function (w, i) { console.log("  " + (i + 1) + ". " + w); });
  console.log("NOT MOVED (over the 12-word limit; the owner can swap any in from the Fingerprint screen): " + notMoved.length);
  notMoved.forEach(function (w) { console.log("  - " + w); });
  console.log("SOURCES: " + JSON.stringify(SOURCES));

  // What the automatic build gives the owner's other fields (reads only).
  const src = await FP.loadSources(sb, OWNER_ACCOUNT_ID, new Date().toISOString());
  const built = FP.buildFields(src);
  console.log("AUTOMATIC FIELDS (built from the owner's listings, Offer posts and profile; read only): " + JSON.stringify({
    categories: built.categories, place_city: built.place_city, place_region: built.place_region,
    offer_summary: built.offer_summary, who_you_serve: built.who_you_serve, automatic_keywords_replaced: built.keywords }));

  const existing = await sb.from("lead_fingerprints").select("user_id, keywords, sources, edited_fields").eq("user_id", OWNER_ACCOUNT_ID).maybeSingle();
  if (existing.error) {
    console.log("CURRENT: lead_fingerprints cannot be read (" + (existing.error.code || "") + " " + existing.error.message + "): migration 204 is not applied yet, so --apply would stop here.");
    if (APPLY) process.exitCode = 1;
    return;
  }
  console.log("CURRENT: " + (existing.data ? JSON.stringify(existing.data) : "the owner has no Fingerprint yet; --apply builds one first."));
  // NAMED (Nov 24 2026, LR-2B): the 23 words that do not fit are kept as the owner's spare words (lib/leadFingerprint.js
  // SPARE_KEY), shown on the Fingerprint screen to swap in. A run that finds everything in place changes nothing.
  const spareNow = await FP.readSpare(sb, OWNER_ACCOUNT_ID);
  console.log("CURRENT SPARE WORDS: " + spareNow.words.length + (spareNow.id ? " (agent_memory row " + spareNow.id + ")" : " (none stored)"));
  const cur = existing.data;
  const S = FP.sourcesOf(cur && cur.sources);
  const changes = [];
  if (!cur) changes.push("create the Fingerprint");
  else {
    if (JSON.stringify(FP.wordList(cur.keywords || [], FP.MAX_WORDS)) !== JSON.stringify(moved)) changes.push("keywords");
    if ((cur.edited_fields || []).indexOf("keywords") === -1) changes.push("lock keywords");
    if (Object.keys(SOURCES).some(function (k) { return S[k] !== SOURCES[k]; })) changes.push("sources");
  }
  if (JSON.stringify(spareNow.words) !== JSON.stringify(notMoved)) changes.push("spare words (" + notMoved.length + ")");
  console.log("WOULD CHANGE: " + (changes.length ? changes.join(", ") : "nothing (everything is already in place)"));
  if (!APPLY) { console.log("Nothing was written (dry run)."); return; }
  if (!changes.length) { console.log("Nothing to write."); return; }

  const nowIso = new Date().toISOString();
  const row = cur ? await FP.getOrBuild(sb, OWNER_ACCOUNT_ID, nowIso) : await FP.rebuild(sb, OWNER_ACCOUNT_ID, nowIso);
  const edit = FP.validateEdit({ keywords: moved, sources: SOURCES }, null);
  if (!edit.ok) throw new Error("the seed does not validate: " + edit.error);
  const written = await FP.writeRow(sb, OWNER_ACCOUNT_ID, FP.applyEdit(row, edit, nowIso));
  console.log("WRITTEN: " + JSON.stringify(FP.shape(written)));
  const spare = await FP.writeSpare(sb, OWNER_ACCOUNT_ID, notMoved, nowIso);
  console.log("SPARE WORDS WRITTEN: " + spare.length);
}

main().catch(function (err) { console.error("STOPPED: " + ((err && err.message) || err)); process.exitCode = 1; });
