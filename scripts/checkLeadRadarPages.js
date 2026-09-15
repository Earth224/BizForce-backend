/* ══════════════════════════════════════════════════════════════════════════
   checkLeadRadarPages.js — what the two lead pages do with the 403 the four
   lead routes now send, and what they no longer claim.

   COMPANION TO checkLeadRadarOwnerGate.js. That file proves the backend
   refuses a non-owner with code "lead_radar_unavailable" before reading a
   row. This one boots agents/lead-radar.html and agents/sales.html from the
   frontend checkout in jsdom, answers their lead fetches with that exact
   refusal, and asserts what the document then contains:

     - the server's own sentence, verbatim, where the lead list would be
     - NO Convert control and NO "Post Public Replies" control anywhere in
       the document — absent, not disabled. querySelectorAll, not a
       visibility check: a hidden button is still a button.
     - no lead card, no Draft Engagement button, no Load More
     - window.confirm never called

   And, as the control, the same two pages booted against a 200 with sample
   leads, which must render the cards and the controls — so the removal is
   shown to be conditional on the refusal rather than the page having lost
   its buttons altogether.

   The copy checks are the second half: the four claims the report named are
   asserted gone from the pages that carried them, and the phrases that
   replaced them are asserted present.

   NOTHING HERE TOUCHES THE DATABASE OR THE NETWORK. fetch is replaced in
   the window before any page script runs; external scripts (chart.js,
   bf-session.js, the termaximus helpers) are not loaded, which is why
   bf_token is seeded into localStorage by hand — bf-session.js would have
   redirected to the login page without it.

   MUTATION. MUTATE=ignore-refusal rewrites both pages as they are loaded so
   their refusal branch can never be taken. The refusal-mode checks must go
   red; the control-mode and copy checks stay green. Run it after any edit
   to this file.
   ══════════════════════════════════════════════════════════════════════════ */

const path = require("path");
const fs = require("fs");
const { JSDOM, VirtualConsole } = require("jsdom");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATING = process.env.MUTATE === "ignore-refusal";

const PAGES = {
  radar: path.join(FRONTEND, "agents", "lead-radar.html"),
  sales: path.join(FRONTEND, "agents", "sales.html"),
  dashboard: path.join(FRONTEND, "dashboard.html")
};
Object.keys(PAGES).forEach(function (k) {
  if (!fs.existsSync(PAGES[k])) {
    console.error("Frontend page not found: " + PAGES[k] + " (set BIZFORCE_FRONTEND_DIR).");
    process.exit(1);
  }
});

/* The exact body the backend sends. Kept in step by hand with
   LEAD_RADAR_UNAVAILABLE in server.js; checkLeadRadarOwnerGate.js prints
   the live one. The page must show `error` verbatim, so the text matters. */
const REFUSAL = {
  error: "Lead Radar runs against a single connected social account and is not enabled for your account. " +
         "Leads, scoring and public replies are only available on the account that owns those credentials.",
  code: "lead_radar_unavailable"
};

const LEAD_ROUTES = ["/api/leads", "/api/agents/sales/leads", "/api/agents/sales/lead-status", "/api/agents/sales/pipeline"];

const SAMPLE_LEADS = [
  { id: "a", post_uri: "at://did:plc:a/app.bsky.feed.post/1", author_handle: "one.bsky.social", post_text: "anyone tried tongkat ali?", matched_keyword: "anyone tried tongkat ali", intent_score: 81, intent_reason: "asks the room", suggested_product: "Tongkat Ali", source: "bluesky", status: "scored", sales_status: "new", created_at: "2026-09-01T00:00:00Z" },
  { id: "b", post_uri: "at://did:plc:b/app.bsky.feed.post/2", author_handle: "two.bsky.social", post_text: "why isn't my manifestation working", matched_keyword: "why isn't my manifestation working", intent_score: 64, intent_reason: "seeker", suggested_product: "Quantum Jumping book", source: "bluesky", status: "scored", sales_status: "new", created_at: "2026-09-01T00:00:00Z" }
];
const SAMPLE_PIPELINE = { new: [], drafted: [], contacted: [], replied: [], converted: [] };

let failures = 0;
function check(label, ok, detail) {
  if (ok) console.log("    pass  " + label);
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + detail + "]" : "")); }
}

function sleep(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

/* Builds a Response-shaped object the pages' .then chains accept. */
function reply(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status: status,
    json: function () { return Promise.resolve(body); },
    text: function () { return Promise.resolve(JSON.stringify(body)); }
  };
}

function mutate(html, needle, label) {
  const hits = html.split(needle).length - 1;
  if (hits !== 1) {
    console.error("MUTATION REFUSED: expected exactly one `" + needle + "` in " + label + ", found " + hits + ".");
    process.exit(1);
  }
  return html.replace(needle, "false");
}

/* Boots one page. mode is "refuse" (every lead route answers the 403) or
   "serve" (they answer 200 with the samples). Returns the window and the
   record of what was fetched and whether confirm was ever called. */
async function boot(pageKey, mode) {
  let html = fs.readFileSync(PAGES[pageKey], "utf8");

  if (MUTATING) {
    if (pageKey === "radar") html = mutate(html, 'res.status === 403 && res.data.code === "lead_radar_unavailable"', "lead-radar.html");
    if (pageKey === "sales") html = mutate(html, 'return status === 403 && !!data && data.code === "lead_radar_unavailable";', "sales.html");
  }

  const seen = { fetched: [], confirms: 0, errors: [] };
  const virtualConsole = new VirtualConsole();
  virtualConsole.on("jsdomError", function (e) { seen.errors.push(String(e && e.message || e).split("\n")[0]); });

  const dom = new JSDOM(html, {
    url: "https://bizforce.test/agents/" + path.basename(PAGES[pageKey]),
    runScripts: "dangerously",
    pretendToBeVisual: true,
    virtualConsole: virtualConsole,
    beforeParse: function (window) {
      try { window.localStorage.setItem("bf_token", "check-token"); } catch (e) { /* jsdom always has it */ }
      window.confirm = function () { seen.confirms += 1; return false; };
      window.alert = function () {};
      window.fetch = function (url) {
        const u = String(url);
        const routePath = u.replace(/^https?:\/\/[^/]+/, "").split("?")[0];
        seen.fetched.push(routePath);
        if (LEAD_ROUTES.indexOf(routePath) !== -1) {
          if (mode === "refuse") return Promise.resolve(reply(403, REFUSAL));
          if (routePath === "/api/agents/sales/pipeline") return Promise.resolve(reply(200, { pipeline: SAMPLE_PIPELINE }));
          return Promise.resolve(reply(200, { leads: SAMPLE_LEADS }));
        }
        /* Everything else the pages ask for on boot is out of scope: an
           empty 404 exercises their own error handling and nothing more. */
        return Promise.resolve(reply(404, {}));
      };
      /* chart.js is not loaded; the pages guard their chart code with
         try/catch, but a stub keeps that noise out of the run. */
      window.Chart = function () { return { destroy: function () {} }; };
    }
  });

  /* Wait for the lead fetches to have been answered and rendered. */
  const doc = dom.window.document;
  const settled = function () {
    if (pageKey === "radar") return !!doc.querySelector("#leadsList .empty-state, #leadsList .lead-card");
    /* The list ships with a "Loading leads…" placeholder; it has settled once
       that is gone and, in refuse mode, once the pipeline board has too. */
    const list = doc.querySelector("#salesLeadsList");
    const board = doc.querySelector("#salesPipelineBoard");
    if (!list || /Loading leads/.test(list.textContent)) return false;
    if (mode === "refuse") return !!(board && board.querySelector('[data-state="lead_radar_unavailable"]'));
    return true;
  };
  for (let i = 0; i < 60 && !settled(); i++) await sleep(50);
  await sleep(150);

  return { window: dom.window, doc: doc, seen: seen };
}

function textOf(el) { return el ? el.textContent.replace(/\s+/g, " ").trim() : null; }

(async function main() {
  if (MUTATING) console.log("\n!! MUTATION: both pages' refusal branches are now unreachable — the refusal-mode checks below must fail.");

  /* ── lead-radar.html, refused ─────────────────────────────────────────── */
  console.log("\n══ lead-radar.html — server refuses ══");
  {
    const p = await boot("radar", "refuse");
    const d = p.doc;
    const state = d.querySelector('#leadsList [data-state="lead_radar_unavailable"]');
    console.log("    fetched: " + p.seen.fetched.join(", "));
    console.log("    read-back #leadsList: " + JSON.stringify(textOf(d.querySelector("#leadsList"))));
    console.log("    read-back #leadsCount: " + JSON.stringify(textOf(d.querySelector("#leadsCount"))));
    check("the list shows the refusal state", !!state);
    check("with the server's sentence, verbatim", textOf(state) === REFUSAL.error, textOf(state) || textOf(d.querySelector("#leadsList")));
    check("the count reads as not enabled, not as a number of leads", /Not enabled/.test(textOf(d.querySelector("#leadsCount")) || ""), textOf(d.querySelector("#leadsCount")));
    check("no lead card is in the document", d.querySelectorAll(".lead-card").length === 0, d.querySelectorAll(".lead-card").length + " cards");
    check("no Draft Engagement button is in the document", d.querySelectorAll(".draft-btn").length === 0);
    check("no Load More button is in the document", !d.getElementById("loadMoreBtn"));
    check("the Show Noise button is not displayed", (d.getElementById("noiseBtn") || {}).style && d.getElementById("noiseBtn").style.display === "none");
    check("nothing on the page still says leads are on their way", !/runs every 5 minutes|No scored leads yet/.test(textOf(d.querySelector("#leadsList")) || ""));
    check("confirm was never called", p.seen.confirms === 0);
    p.window.close();
  }

  /* ── lead-radar.html, served (the control) ────────────────────────────── */
  console.log("\n══ lead-radar.html — server serves leads (control) ══");
  {
    const p = await boot("radar", "serve");
    const d = p.doc;
    check("lead cards render", d.querySelectorAll(".lead-card").length === SAMPLE_LEADS.length, d.querySelectorAll(".lead-card").length + " cards");
    check("Draft Engagement buttons render", d.querySelectorAll(".draft-btn").length === SAMPLE_LEADS.length);
    check("no refusal state is shown", !d.querySelector('[data-state="lead_radar_unavailable"]'));
    p.window.close();
  }

  /* ── sales.html, refused ──────────────────────────────────────────────── */
  console.log("\n══ sales.html — server refuses ══");
  {
    const p = await boot("sales", "refuse");
    const d = p.doc;
    const state = d.querySelector('#salesLeadsList [data-state="lead_radar_unavailable"]');
    const boardState = d.querySelector('#salesPipelineBoard [data-state="lead_radar_unavailable"]');
    console.log("    fetched: " + p.seen.fetched.filter(function (r) { return LEAD_ROUTES.indexOf(r) !== -1; }).join(", "));
    console.log("    read-back #salesLeadsList: " + JSON.stringify(textOf(d.querySelector("#salesLeadsList"))));
    console.log("    read-back #salesPipelineBoard: " + JSON.stringify(textOf(d.querySelector("#salesPipelineBoard"))));
    console.log("    read-back #salesConvertAllBtn: " + JSON.stringify(d.getElementById("salesConvertAllBtn") ? d.getElementById("salesConvertAllBtn").outerHTML : null));
    check("the lead list shows the refusal state", !!state);
    check("with the server's sentence, verbatim", textOf(state) === REFUSAL.error, textOf(state) || textOf(d.querySelector("#salesLeadsList")));
    check("the pipeline board shows the refusal too, not five empty columns", !!boardState, textOf(d.querySelector("#salesPipelineBoard")));
    check("the Post Public Replies button is ABSENT from the document (getElementById)", d.getElementById("salesConvertAllBtn") === null);
    check("the Post Public Replies button is ABSENT from the document (querySelectorAll by id)", d.querySelectorAll('[id="salesConvertAllBtn"]').length === 0);
    check("no element in the document reads Post Public Replies",
      Array.prototype.every.call(d.querySelectorAll("button, a"), function (el) { return !/Post Public Replies/.test(el.textContent); }));
    check("no per-lead Convert button is in the document", d.querySelectorAll(".sales-convert-btn").length === 0, d.querySelectorAll(".sales-convert-btn").length + " buttons");
    check("no lead card is in the document", d.querySelectorAll(".sales-lead-card").length === 0);
    check("no disabled stand-in was left behind", d.querySelectorAll("button[disabled]").length === 0 ||
      Array.prototype.every.call(d.querySelectorAll("button[disabled]"), function (el) { return !/Convert|Post Public|Re-Draft/.test(el.textContent); }));
    check("nothing on the page still says leads are on their way", !/scans every 5 minutes|No captured leads yet/.test(textOf(d.querySelector("#salesLeadsList")) || ""));
    check("confirm was never called", p.seen.confirms === 0);
    p.window.close();
  }

  /* ── sales.html, served (the control) ─────────────────────────────────── */
  console.log("\n══ sales.html — server serves leads (control) ══");
  {
    const p = await boot("sales", "serve");
    const d = p.doc;
    check("lead cards render", d.querySelectorAll(".sales-lead-card").length === SAMPLE_LEADS.length, d.querySelectorAll(".sales-lead-card").length + " cards");
    check("per-lead Convert buttons render", d.querySelectorAll(".sales-convert-btn").length === SAMPLE_LEADS.length);
    check("the Post Public Replies button is present", d.getElementById("salesConvertAllBtn") !== null);
    check("no refusal state is shown", !d.querySelector('[data-state="lead_radar_unavailable"]'));
    check("the confirm names the server's configured account, not a connected one — single", (function () {
      const btn = d.querySelector(".sales-convert-btn");
      if (!btn) return false;
      p.window.confirm = function (msg) { p.seen.lastConfirm = msg; return false; };
      btn.click();
      return typeof p.seen.lastConfirm === "string" &&
        /configured on the server/.test(p.seen.lastConfirm) && /not from an account you connected/.test(p.seen.lastConfirm) &&
        !/your own connected/.test(p.seen.lastConfirm);
    })(), p.seen.lastConfirm);
    check("— and bulk", (function () {
      const btn = d.getElementById("salesConvertAllBtn");
      if (!btn) return false;
      p.seen.lastConfirm = null;
      btn.click();
      return typeof p.seen.lastConfirm === "string" &&
        /configured on the server/.test(p.seen.lastConfirm) && !/your own connected/.test(p.seen.lastConfirm);
    })(), p.seen.lastConfirm);
    p.window.close();
  }

  /* ── the copy ─────────────────────────────────────────────────────────── */
  console.log("\n══ the four claims, gone from the source ══");
  {
    const radar = fs.readFileSync(PAGES.radar, "utf8");
    const sales = fs.readFileSync(PAGES.sales, "utf8");
    const dash = fs.readFileSync(PAGES.dashboard, "utf8");
    check("dashboard tile no longer says real-time leads captured for you",
      dash.indexOf("Real-time buying-intent leads captured from Bluesky, scored and ranked.") === -1);
    check("dashboard tile says it runs on one account and who it is enabled for",
      /single social account/.test(dash) && /enabled only for the account that owns it/.test(dash));
    check("lead-radar subtitle no longer says 'your market'", !/in your market/.test(radar));
    check("lead-radar subtitle says one keyword set, one account", /One keyword set and one social account/.test(radar));
    check("no confirm dialog says 'your own connected'", sales.indexOf("your own connected") === -1);
    check("both confirm dialogs say the account is the server's, not a connected one",
      (sales.match(/configured on the server for this deployment — not from an account you connected/g) || []).length === 2);
    check("lead-radar empty state no longer promises leads", radar.indexOf("No scored leads yet. The radar runs every 5 minutes.") === -1);
    check("sales empty state no longer promises leads", sales.indexOf("No captured leads yet. Lead Radar scans every 5 minutes.") === -1);
  }

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures); process.exit(1); }
  console.log("ALL CHECKS PASSED");
  process.exit(0);
})().catch(function (err) {
  console.error("checkLeadRadarPages crashed:", err && (err.stack || err.message) || err);
  process.exit(1);
});
