/* ═══════════════════════════════════════════════════════════════════════════
   checkLeadRadarPages.js — who sees what on the two lead pages, and what they no longer claim.

   NAMED BEFORE → AFTER (Nov 23 2026, LR-2). BEFORE this file booted agents/lead-radar.html and agents/sales.html
   against the 403 "lead_radar_unavailable" the four owner-only lead routes sent a non-owner, and proved the server's
   sentence was shown with no Convert, Draft or "Post Public Replies" control; and, as the control, the owner's leads
   with Draft and "Post my reply" on agents/sales.html. AFTER Lead Radar is every member's (lib/leadRoutes.js, members
   only): agents/lead-radar.html was rebuilt to the owner's boards (LeadsHome, LeadsReply, LeadsFingerprint), the owner
   routes are gone, and agents/sales.html points to Lead Radar, with the owner's old leads as a read-only archive
   (GET /api/leads/archive). So this file now proves, in jsdom with fetch replaced:

     lead-radar.html
       - signed out (no token): "Sign in to see Lead Radar." and a Sign in link, and NO lead request;
       - a free account (bfAccess tier free): the members panel state ("Lead Radar is for members", "Join to unlock",
         which opens the site's members panel), and NO lead request;
       - the server answering 402 (a lapsed member): the same members panel, and the site's panel is opened;
       - the server answering 401: the sign-in state;
       - the server failing (500): "could not load", never an empty list or "0 leads";
       - a member: the stats, the chips for the sources that are on, the cards with their badge, text and green match
         line, Save and Not a fit, the footer line; and none of the old page's controls (Show Noise, Refresh, Load More,
         Draft Engagement, a chart).
     sales.html
       - a member (the archive answers 403): only the pointer to Lead Radar; no archive, no lead card, and no control
         that drafts, sends or converts;
       - the owner (the archive answers 200): the archive, read only: its cards and board carry no button that acts;
       - neither calls a removed route (GET /api/leads, /api/agents/sales/leads, lead-status, pipeline, convert,
         send-approved).
     The copy: the old claims are gone from the pages that carried them, and the members' sentences are there.

   NOTHING HERE TOUCHES THE DATABASE OR THE NETWORK. External scripts are not loaded; bfAccess is a stub.

   MUTATE=<name> edits a page as it is loaded; MUTATE=all runs each in its own process and passes only if every one
   fails a check. An unmatched search text is an ERROR (scripts/_shared.js), never a catch.
   ═══════════════════════════════════════════════════════════════════════════ */

const path = require("path");
const fs = require("fs");
const { JSDOM, VirtualConsole } = require("jsdom");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUT = require("./_shared");

const MUTATIONS = {
  // NAMED (Nov 23 2026, LR-2): BEFORE "ignore-refusal" made the 403 branch unreachable. AFTER the 402 branch.
  "ignore-refusal": ["radar", "if (res.status === 402) { showState(\"members_only\");", "if (false) { showState(\"members_only\");"],
  // a free account asks for the leads anyway
  "free-loads-leads": ["radar", "if (a.tier === \"free\") { showState(\"members_only\"); return; }\n", ""],
  // a signed-out visitor asks for the leads anyway
  "signed-out-loads": ["radar", "if (!tok()) { showState(\"signed_out\"); return; }", "if (false) { showState(\"signed_out\"); return; }"],
  // the archive is drawn for an answer that is not the archive's (a member's 403)
  "archive-for-anyone": ["sales", ".then(function (r) { return r.ok ? r.json() : null; })", ".then(function (r) { return r.json().then(function (d) { return Object.assign({ leads: [] }, d); }); })"]
};
if (process.env.MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));
const MUTATE = process.env.MUTATE || "";
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const PAGES = {
  radar: path.join(FRONTEND, "agents", "lead-radar.html"),
  sales: path.join(FRONTEND, "agents", "sales.html"),
  dashboard: path.join(FRONTEND, "dashboard.html")
};
Object.keys(PAGES).forEach(function (k) {
  if (!fs.existsSync(PAGES[k])) { console.error("Frontend page not found: " + PAGES[k] + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(1); }
});

// The routes LR-2 removed: no page may call them.
const REMOVED = ["/api/agents/sales/leads", "/api/agents/sales/lead-status", "/api/agents/sales/pipeline", "/api/agents/sales/convert",
  "/api/agents/sales/send-approved", "/api/leads/youtube-signals", "/api/leads/draft-reply"];

const NOW = Date.now();
const iso = (mins) => new Date(NOW - mins * 60000).toISOString();
const LEADS = [
  { id: "n1", source: "bizforce", author_handle: "maria", author_place: "Austin", posted_at: iso(30), text: "Need a plumber for a leaking kitchen sink this week.",
    match_reason: "Home services in Austin", status: "new", need_post_id: "p1", can_reply: false },
  { id: "b1", source: "bluesky", author_handle: "sam.bsky.social", posted_at: iso(120), text: "Anyone know a good plumber in Austin? Water heater died.",
    match_reason: "Strong match: asks for a plumber nearby", status: "new", reply_invited: true, can_reply: true, url: "https://bsky.app/profile/sam/post/1" },
  { id: "y1", source: "youtube", author_handle: "Viewer", posted_at: iso(600), text: "How do I fix a dripping tap myself?", matched_keyword: "dripping tap",
    status: "new", can_reply: false, url: "https://www.youtube.com/watch?v=x&lc=y" }
];
const LIST = { leads: LEADS, stats: { new_this_week: 7, replied: 2, won: 1 }, sources_on: { bizforce: true, bluesky: true, youtube: true, threads: false }, weaker_hidden: 0 };
const ARCHIVE = {
  leads: [{ post_uri: "at://old/1", author_handle: "old.bsky.social", post_text: "an old find", intent_score: 72, status: "scored", sales_status: "replied" }],
  pipeline: [{ lead_post_uri: "at://old/1", status: "replied", last_draft: "an old reply" }]
};

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 300) + "]" : "")); }
}
function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
function reply(status, body) {
  return { ok: status >= 200 && status < 300, status: status, json: function () { return Promise.resolve(body); }, text: function () { return Promise.resolve(JSON.stringify(body)); } };
}
function textOf(el) { return el ? el.textContent.replace(/\s+/g, " ").trim() : null; }

/* Boots one page. o.token (default true), o.tier (bfAccess), o.answer(path, method) -> [status, body]. */
async function boot(pageKey, o) {
  o = o || {};
  let html = fs.readFileSync(PAGES[pageKey], "utf8");
  if (MUTATE && MUTATIONS[MUTATE][0] === pageKey) html = MUT.replaceOnce(html, MUTATIONS[MUTATE][1], MUTATIONS[MUTATE][2], MUTATE);
  const seen = { fetched: [], panel: 0, confirms: 0, errors: [] };
  const vc = new VirtualConsole();
  vc.on("jsdomError", function (e) { seen.errors.push(String(e && e.message || e).split("\n")[0]); });
  const dom = new JSDOM(html, {
    url: "https://bizforce.test/agents/" + path.basename(PAGES[pageKey]),
    runScripts: "dangerously", pretendToBeVisual: true, virtualConsole: vc,
    beforeParse: function (window) {
      if (o.token !== false) window.localStorage.setItem("bf_token", "check-token");
      window.confirm = function () { seen.confirms += 1; return false; };
      window.alert = function () {};
      window.bfAccess = { ready: Promise.resolve({ tier: o.tier || "member" }), showPanel: function () { seen.panel += 1; } };
      window.fetch = function (url, opts) {
        const p = String(url).replace(/^https?:\/\/[^/]+/, "").split("?")[0];
        const method = (opts && opts.method) || "GET";
        seen.fetched.push(method + " " + p);
        const a = o.answer ? o.answer(p, method) : null;
        return Promise.resolve(a ? reply(a[0], a[1]) : reply(404, {}));
      };
      window.Chart = function () { seen.chart = true; return { destroy: function () {} }; };
    }
  });
  const doc = dom.window.document;
  for (let i = 0; i < 60; i++) {
    await sleep(25);
    if (pageKey === "radar") {
      const st = doc.getElementById("lrState");
      if ((st && !st.hidden) || doc.querySelector("#lrList .lr-card")) break;
    } else if (seen.fetched.some(f => /\/api\/leads\/archive$/.test(f))) { await sleep(100); break; }
  }
  await sleep(100);
  return { window: dom.window, doc: doc, seen: seen };
}
const leadReads = (seen) => seen.fetched.filter(f => / \/api\/leads/.test(f));
const removedCalls = (seen) => seen.fetched.filter(f => REMOVED.some(r => f.endsWith(" " + r)));

(async function main() {
  if (MUTATE) console.log("\n!! MUTATION: " + MUTATE + " (in memory)");

  console.log("\n══ lead-radar.html — signed out ══");
  {
    const p = await boot("radar", { token: false });
    const st = p.doc.getElementById("lrState");
    check("the sign-in state: \"Sign in to see Lead Radar.\" and a Sign in link", st && !st.hidden && st.getAttribute("data-state") === "signed_out" &&
      /Sign in to see Lead Radar\./.test(textOf(st)) && !!st.querySelector('a[href="/app.html"]'), textOf(st));
    check("no lead request is made", leadReads(p.seen).length === 0, p.seen.fetched.join(", "));
    check("the tabs and the lists stay hidden", p.doc.getElementById("lrTabs").hidden && p.doc.getElementById("lrLeads").hidden);
    p.window.close();
  }

  console.log("\n══ lead-radar.html — a free account ══");
  {
    const p = await boot("radar", { tier: "free", answer: (r) => r.indexOf("/api/leads") === 0 ? [200, LIST] : null });
    const st = p.doc.getElementById("lrState");
    check("the members panel state: \"Lead Radar is for members\" and \"Join to unlock\"", st && !st.hidden && st.getAttribute("data-state") === "members_only" &&
      /Lead Radar is for members/.test(textOf(st)) && /Join to unlock/.test(textOf(st)), textOf(st));
    check("no lead request is made", leadReads(p.seen).length === 0, p.seen.fetched.join(", "));
    const join = p.doc.getElementById("lrJoin");
    if (join) join.click();
    check("Join to unlock opens the site's members panel", p.seen.panel === 1, p.seen.panel);
    check("no lead card is in the document", p.doc.querySelectorAll("#lrList .lr-card[data-lead]").length === 0);
    p.window.close();
  }

  console.log("\n══ lead-radar.html — the server refuses (402, 401) or fails ══");
  {
    const p = await boot("radar", { answer: (r) => r.indexOf("/api/leads") === 0 ? [402, { error: "Lead Radar is for members.", code: "members_only" }] : null });
    const st = p.doc.getElementById("lrState");
    check("402: the members panel state, and the site's members panel is opened", st && !st.hidden && st.getAttribute("data-state") === "members_only" && p.seen.panel === 1,
      textOf(st) + " panel " + p.seen.panel);
    check("402: no lead card, and the tabs stay hidden", p.doc.querySelectorAll(".lr-card[data-lead]").length === 0 && p.doc.getElementById("lrTabs").hidden);
    p.window.close();
    const q = await boot("radar", { answer: (r) => r.indexOf("/api/leads") === 0 ? [401, { error: "Sign in." }] : null });
    check("401: the sign-in state", q.doc.getElementById("lrState").getAttribute("data-state") === "signed_out" && !q.doc.getElementById("lrState").hidden);
    q.window.close();
    const e = await boot("radar", { answer: (r) => r.indexOf("/api/leads") === 0 ? [500, { error: "down" }] : null });
    const es = e.doc.getElementById("lrState");
    check("500: \"could not load\", never an empty list or a count of 0 leads", es && !es.hidden && /could not load/.test(textOf(es)) &&
      e.doc.querySelectorAll(".lr-card[data-lead]").length === 0 && e.doc.getElementById("lrLeads").hidden, textOf(es));
    e.window.close();
  }

  console.log("\n══ lead-radar.html — a member ══");
  {
    const posted = [];
    const p = await boot("radar", { answer: (r, m) => {
      if (r === "/api/leads") return [200, LIST];
      const s = /^\/api\/leads\/([^/]+)\/status$/.exec(r);
      if (s && m === "POST") { posted.push(s[1]); return [200, { lead: Object.assign({}, LEADS.find(l => l.id === s[1]), { status: "saved" }) }]; }
      return null;
    } });
    const d = p.doc;
    const cards = d.querySelectorAll("#lrList .lr-card[data-lead]");
    check("the leads tab shows: the tabs, the three stats as served (7 new this week, 2 replied, 1 won)",
      !d.getElementById("lrTabs").hidden && textOf(d.getElementById("lrStatNew")) === "7" && textOf(d.getElementById("lrStatReplied")) === "2" && textOf(d.getElementById("lrStatWon")) === "1");
    // NAMED (Nov 24 2026, LR-3): BEFORE "only the Leads and Fingerprint tabs (no empty Inbound or Get found tab)". AFTER Inbound is
    // built (LeadsInbound; checkInbound), so three tabs; Get found (LR-4) is still not shown.
    // NAMED (Nov 25 2026, LR-4): BEFORE "only the Leads, Inbound and Fingerprint tabs (no empty Get found tab)". AFTER Get found is
    // built (LeadsFound; checkGetFound, checkDesignFidelity J), so all four tabs the board draws.
    check("the four tabs: Leads, Inbound, Get found and Fingerprint",
      d.querySelectorAll("#lrTabs [role=tab]").length === 4 && textOf(d.getElementById("lrTabs")).replace(/\s+/g, " ").trim() === "Leads Inbound Get found Fingerprint", textOf(d.getElementById("lrTabs")));
    const chips = Array.prototype.map.call(d.querySelectorAll("#lrChips .lr-chip"), c => textOf(c));
    check("chips: All and each source that is on (Threads is off, so no Threads chip)", JSON.stringify(chips) === JSON.stringify(["All", "Inside BizForce", "Bluesky", "YouTube"]), JSON.stringify(chips));
    check("a card for each lead, each with its badge and its text", cards.length === 3 &&
      /BIZFORCE NEED/.test(textOf(cards[0])) && /BLUESKY · ASKED THE ROOM/.test(textOf(cards[1])) && /YOUTUBE COMMENT/.test(textOf(cards[2])) &&
      textOf(cards[1].querySelector(".lr-text")) === LEADS[1].text, Array.prototype.map.call(cards, c => textOf(c)).join(" | "));
    check("the green match line is the server's reason (none on a YouTube comment)", textOf(cards[1].querySelector(".lr-match")) === LEADS[1].match_reason && !cards[2].querySelector(".lr-match"));
    check("a Need offers I can help (to the post), Save and Not a fit; a Bluesky lead invited to reply offers Draft a reply and Open post",
      !!cards[0].querySelector('a[href="/home.html?post=p1"]') && !!cards[0].querySelector('[data-act="save"]') && !!cards[0].querySelector('[data-act="dismiss"]') &&
      !!cards[1].querySelector('[data-act="draft"]') && !!cards[1].querySelector('a[href="' + LEADS[1].url + '"]'));
    check("the footer says who sends", /You approve every reply\. BizForce never messages anyone for you\./.test(textOf(d.body)));
    check("none of the old page's controls: Show Noise, Refresh, Load More, Draft Engagement, a chart",
      !d.getElementById("noiseBtn") && !d.getElementById("refreshBtn") && !d.getElementById("loadMoreBtn") && d.querySelectorAll(".draft-btn").length === 0 &&
      !p.seen.chart && !/chart\.js/.test(fs.readFileSync(PAGES.radar, "utf8")));
    cards[0].querySelector('[data-act="save"]').click();
    for (let i = 0; i < 40 && !posted.length; i++) await sleep(25);
    check("Save asks the server for exactly that lead's status, once", JSON.stringify(posted) === '["n1"]', JSON.stringify(posted));
    check("no removed route is called, and no confirm dialog", removedCalls(p.seen).length === 0 && p.seen.confirms === 0, removedCalls(p.seen).join(", "));
    p.window.close();
  }

  console.log("\n══ sales.html — a member, then the owner ══");
  {
    const p = await boot("sales", { answer: (r) => r === "/api/leads/archive" ? [403, { error: "Only the owner account can read the archive." }] : null });
    const d = p.doc;
    check("a member: the pointer to Lead Radar", !!d.getElementById("salesRadarPointer") && !!d.querySelector('#salesRadarPointer a[href="/agents/lead-radar.html"]'));
    check("a member: no archive is drawn for a 403", d.getElementById("salesArchive").hidden === true && d.querySelectorAll(".sales-lead-card").length === 0,
      textOf(d.getElementById("salesLeadsList")));
    check("no control drafts, sends or converts", !d.querySelector(".sales-convert-btn, .sales-approve-btn, .sales-approve-text, #salesConvertAllBtn") &&
      Array.prototype.every.call(d.querySelectorAll("button, a"), el => !/Post Public Replies|Post my reply|Draft reply|Convert/.test(el.textContent)));
    check("no removed route is called, and no confirm dialog", removedCalls(p.seen).length === 0 && p.seen.confirms === 0, removedCalls(p.seen).join(", "));
    p.window.close();
    const o = await boot("sales", { answer: (r) => r === "/api/leads/archive" ? [200, ARCHIVE] : null });
    const od = o.doc;
    check("the owner: the archive, read only, with its old lead", od.getElementById("salesArchive").hidden === false && od.querySelectorAll("#salesLeadsList .sales-lead-card").length === 1 &&
      /an old find/.test(textOf(od.getElementById("salesLeadsList"))), textOf(od.getElementById("salesLeadsList")));
    check("the archive's cards carry no button", od.querySelectorAll("#salesLeadsList button").length === 0);
    check("the owner: no removed route is called either", removedCalls(o.seen).length === 0, removedCalls(o.seen).join(", "));
    o.window.close();
  }

  console.log("\n══ the copy ══");
  {
    const radar = fs.readFileSync(PAGES.radar, "utf8"), sales = fs.readFileSync(PAGES.sales, "utf8"), dash = fs.readFileSync(PAGES.dashboard, "utf8");
    check("dashboard tile no longer says real-time leads captured for you", dash.indexOf("Real-time buying-intent leads captured from Bluesky, scored and ranked.") === -1);
    // NAMED (Nov 23 2026, LR-2): BEFORE the tile said it ran on one account, enabled only for its owner. AFTER the members' sentence.
    check("dashboard tile: every member's, and every reply approved", !/single social account|enabled only for the account that owns it/.test(dash) &&
      dash.indexOf("People asking for what you offer, found inside BizForce, on Bluesky and on YouTube from your Fingerprint. You approve every reply before it posts.") !== -1);
    check("lead-radar.html no longer says 'your market' or one keyword set and one account", !/in your market|One keyword set and one social account/.test(radar));
    check("no page says the reply comes from anyone's account but the member's own", sales.indexOf("your own connected") === -1 || /own connected Bluesky account/.test(radar));
    check("sales.html opens no confirm dialog and has no bulk reply", !/confirm\(/.test(sales) && sales.indexOf("convertAllHighIntent") === -1);
    check("no page promises leads are on their way", radar.indexOf("No scored leads yet. The radar runs every 5 minutes.") === -1 && sales.indexOf("No captured leads yet. Lead Radar scans every 5 minutes.") === -1);
    check("neither page names a removed route", REMOVED.every(r => radar.indexOf(r) === -1 && sales.indexOf(r) === -1), REMOVED.filter(r => radar.indexOf(r) !== -1 || sales.indexOf(r) !== -1).join(", "));
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("checkLeadRadarPages crashed:", err && (err.stack || err.message) || err);
  process.exit(1);
});
