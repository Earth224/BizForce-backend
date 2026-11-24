/* ═════════════════════════════════════════════════════════════════════════
   checkOutreachDestination.js — a reply may link to one URL, the member's
   own listing, and a reply that links anywhere else is held, never posted.

   NAMED (Nov 23 2026, LR-2): BEFORE this ran the real convertSingleLead
   (server.js) and proved every Mr. Earth Rose product had one destination,
   https://mrearthrose.com/, that the drafter was given it as the only URL,
   and that a draft linking MrEarthRose.com/libido (an invented 404), Stripe,
   swordvitality.com or mrearthrose.net/warhorse was held. AFTER LR-2 removed
   convertSingleLead, OUTREACH_PRODUCT_DESTINATIONS and the owner's outreach
   (the original is in git, 65c0825). The rule it guarded still holds, for
   every member: the one URL a reply may carry is the member's own listing
   (lib/leadReplies.js linkRejection, applied by POST /api/leads/:id/send
   before anything is reserved or posted, and by cleanDraft to every draft).

   WHAT THIS PROVES, with no model call, no database and no network:
     1. Removed: convertSingleLead and OUTREACH_PRODUCT_DESTINATIONS are in no
        code.
     2. With the link switched on, the member's own listing passes in every
        form the model may write it (scheme, www, case, a trailing full stop);
        the old adversarial links are refused, each with bad_link: an
        invented path, a Stripe checkout, another domain, a look-alike host,
        another listing and the listing with a query added.
     3. With the link off, any link at all is refused, the listing included.
     4. A draft is cleaned by code: every link but the listing is removed, and
        the listing is added once when the member asked for it.
     5. The send route refuses a bad link (422 bad_link) before it reserves
        or posts, and posts the text only after that test.

   MUTATIONS (MUTATE=<name> edits lib/leadReplies.js or lib/leadRoutes.js IN
   MEMORY; MUTATE=all runs each):
     no-rejection    linkRejection never refuses                   → 2, 3
     host-only       a link to any path on the listing's host passes → 2
     draft-keeps     cleanDraft keeps every link                     → 4
     send-unchecked  the send route skips the link test              → 5
   ═════════════════════════════════════════════════════════════════════════ */
"use strict";
const fs = require("fs"), path = require("path"), Module = require("module");
const REPO = path.join(__dirname, "..");
const MUT = require("./_shared");
const MUTATE = process.env.MUTATE || "";

const LRP = "lib/leadReplies.js", RT = "lib/leadRoutes.js";
const MUTATIONS = {
  "no-rejection": [[LRP, "  var links = linksIn(text);\n  if (!links.length) return null;", "  var links = linksIn(text);\n  if (true) return null;"]],
  "host-only": [[LRP, "    if (n !== allowed) {", "    if (n.split(\"/\")[0] !== allowed.split(\"/\")[0]) {"]],
  "draft-keeps": [[LRP, "  linksIn(t).forEach(function (u) { if (normalUrl(u) !== allowed) t = t.split(u).join(\"\"); });", ""]],
  "send-unchecked": [[RT, "      var bad = LR.linkRejection(text, link);\n      if (bad) return", "      var bad = null;\n      if (bad) return"]]
};
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

const FILES = {};
["server.js", LRP, RT].forEach(f => { FILES[f] = fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n"); });
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = MUT.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}
const loaded = {};
function load(rel) {
  if (loaded[rel]) return loaded[rel];
  const m = new Module(path.join(REPO, rel), module);
  m.filename = path.join(REPO, rel);
  m.paths = Module._nodeModulePaths(path.dirname(m.filename));
  const realRequire = m.require.bind(m);
  m.require = n => n === "./leadReplies" ? load(LRP) : realRequire(n);
  m._compile(FILES[rel], m.filename);
  loaded[rel] = m.exports;
  return m.exports;
}

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
const code = src => src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");

(async function main() {
  console.log("\n══ 1. the owner's outreach destinations are removed ══");
  const gone = ["convertSingleLead", "OUTREACH_PRODUCT_DESTINATIONS"].filter(n => code(FILES["server.js"]).indexOf(n) !== -1);
  check("convertSingleLead and OUTREACH_PRODUCT_DESTINATIONS are in no code", gone.length === 0, gone.join(", "));

  const L = load(LRP);
  const LISTING = "https://bizforceai.net/listing.html?id=7f1c";
  console.log("\n══ 2. with the link on, only the member's own listing ══");
  const ok = [LISTING, "bizforceai.net/listing.html?id=7f1c", "https://www.bizforceai.net/listing.html?id=7f1c", "HTTPS://BIZFORCEAI.NET/listing.html?id=7f1c", LISTING + "."];
  const okOut = ok.map(u => [u, L.linkRejection("A plumber can clear that today. " + u, LISTING)]);
  check("the listing passes in every form the model may write it", okOut.every(o => o[1] === null), JSON.stringify(okOut.filter(o => o[1])));
  const bad = ["MrEarthRose.com/libido", "https://buy.stripe.com/abc123", "https://swordvitality.com/", "mrearthrose.net/warhorse",
    "https://bizforceai.net.evil.co/listing.html?id=7f1c", "https://bizforceai.net/listing.html?id=9999", LISTING + "&ref=x", "https://bizforceai.net/pricing.html"];
  const badOut = bad.map(u => [u, L.linkRejection("Try this: " + u, LISTING)]);
  check("every other link is refused with bad_link (an invented path, Stripe, another domain, a look-alike host, another listing, a query added, another page)",
    badOut.every(o => o[1] && o[1].code === "bad_link"), JSON.stringify(badOut.filter(o => !o[1]).map(o => o[0])));
  check("…and a listing plus one other link is refused too", (L.linkRejection(LISTING + " and also swordvitality.com", LISTING) || {}).code === "bad_link");

  console.log("\n══ 3. with the link off, no link at all ══");
  const off = [LISTING].concat(bad).map(u => [u, L.linkRejection("See " + u, null)]);
  check("every link is refused, the member's own listing included", off.every(o => o[1] && o[1].code === "bad_link"), JSON.stringify(off.filter(o => !o[1]).map(o => o[0])));
  check("a reply with no link passes", L.linkRejection("A plumber can clear that today.", null) === null);

  console.log("\n══ 4. a draft is cleaned by code ══");
  const cleaned = L.cleanDraft("A plumber can clear that today, see MrEarthRose.com/libido or https://buy.stripe.com/x", LISTING);
  check("every link but the listing is removed, and the listing is added once", cleaned.indexOf("mrearthrose") === -1 && cleaned.toLowerCase().indexOf("mrearthrose") === -1 &&
    cleaned.indexOf("stripe") === -1 && cleaned.split(LISTING).length === 2, cleaned);
  const plain = L.cleanDraft("A plumber can clear that today, see swordvitality.com", null);
  check("with the link off, the draft carries no link", L.linksIn(plain).length === 0, plain);

  console.log("\n══ 5. the send route tests the link before anything is reserved or posted ══");
  {
    const R = load(RT);
    const handlers = {}, posts = [];
    let reserved = 0;
    const app = { get() {}, put() {}, post(p) { handlers["post " + p] = arguments[arguments.length - 1]; } };
    const lead = { id: "b0000000-0000-4000-8000-0000000000b1", user_id: "u1", source: "bluesky", external_id: "at://did:plc:a/app.bsky.feed.post/1", posted_at: new Date().toISOString(),
      outreach_safe: true, reply_invited: true, score: 80, status: "new", text: "Who fixes drains?" };
    const listingRow = { id: "7f1c" };
    const q = (t) => { const b = { select() { return b; }, eq() { return b; }, update() { return b; }, order() { return b; }, limit() { return b; },
      maybeSingle: async () => ({ data: lead, error: null }), then: (res) => res(t === "marketplace_listings" ? { data: [listingRow], error: null } : { error: null }) }; return b; };
    R.mountLeadRoutes(app, { sb: { from: q }, requireAuth() {}, requireActiveSubscription() {}, ownerId: "owner", siteOrigin: "https://bizforceai.net",
      postingAccount: async () => ({ kind: "member", handle: "m.bsky.social" }),
      actAs: async (u, a, fn) => ({ ok: true, value: await fn({ getPosts: async (x) => ({ data: { posts: [{ uri: x.uris[0], cid: "c" }] } }), post: async (rec) => { posts.push(rec.text); return { uri: "at://p/1" }; } }) }),
      actFailure: (res) => res.status(502).json({}), linkFacets: () => [], replyRefsFor: (p) => ({ root: p, parent: p }), caps: { perMember: 5, ceiling: 25 }, sendLive: () => true, threads: {} });
    const realReserve = L.reserveReply;
    L.reserveReply = async () => { reserved++; return { ok: true, id: "s", release: async () => {} }; };
    const run = async (text, addLink) => { const res = { statusCode: 200, body: null, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
      await handlers["post /api/leads/:id/send"]({ user: { id: "u1", role: "user" }, params: { id: lead.id }, body: { text, add_link: addLink } }, res, (e) => { res.statusCode = 500; res.body = String(e); }); return res; };
    try {
      const r1 = await run("Try MrEarthRose.com/libido", true);
      check("a reply linking elsewhere: 422 bad_link, nothing reserved, nothing posted", r1.statusCode === 422 && r1.body.code === "bad_link" && reserved === 0 && posts.length === 0, JSON.stringify(r1.body));
      const r2 = await run("A plumber can clear that today. " + LISTING, true);
      check("a reply linking the member's own listing is posted, exactly as approved", r2.statusCode === 200 && posts.length === 1 && posts[0] === "A plumber can clear that today. " + LISTING, JSON.stringify(r2.body));
      const r3 = await run("A plumber can clear that today. " + LISTING, false);
      check("the same reply with the link switched off is refused", r3.statusCode === 422 && r3.body.code === "bad_link" && posts.length === 1, JSON.stringify(r3.body));
    } finally { L.reserveReply = realReserve; }
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
})().catch(e => { console.error("\nThe check threw: " + (e && e.stack || e)); process.exit(1); });
