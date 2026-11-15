"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkShopifyRequestsPage — the owner's Shopify data requests page.

   Frontend shopify-requests.html (W3, Nov 15 2026): the site owner's list of
   Shopify customer data requests, from GET /api/admin/shopify-data-requests
   (admin only), with a "Mark answered" button that asks first and then calls
   POST /api/admin/shopify-data-requests/:id/answered.

   WHAT THIS PROVES (the page RUN in jsdom, its fetch answered by a fake API)
     A. Signed out (no bf_token) the page asks nothing and shows only "This
        page is for the site owner."; a member the server answers 401 or 403
        sees the same line and nothing else: no list, heading or button.
     B. The owner sees open requests first, the nearest deadline first, then
        those answered in the last 30 days (an older answer is not shown);
        each open request shows the shop, the received date, the deadline with
        the days left (or overdue), the request id, the order ids and whether
        the owner email was sent.
     C. "Mark answered" asks first and calls nothing; Cancel calls nothing;
        "Yes, mark answered" makes exactly one POST to
        /api/admin/shopify-data-requests/<id>/answered with the member's token,
        and the row moves to the answered list. A failed POST leaves the row
        open with the server's reason.
     D. No requests: "No Shopify data requests."
     E. The page's own parts: no emoji; the back link to Executive HQ
        (dashboard.html); the legal footer; noindex; the owner tool link sits
        in bf-command-center.js's admin-only System section; the data request
        email carries the page's full address; lib/appMap.json lists the page.

   Nothing here touches the network or a real database.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), Module = require("module");
const MUT = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const realRequire = Module.createRequire(path.join(REPO, "server.js"));
const readFe = (f) => fs.readFileSync(path.join(FRONTEND, f), "utf8").replace(/\r\n/g, "\n");
const readBe = (f) => fs.readFileSync(path.join(REPO, f), "utf8").replace(/\r\n/g, "\n");

const PAGE = "shopify-requests.html";
const CC = "scripts/bf-command-center.js";
// An emoji, built from its code point so this file holds none.
const EMOJI_CHAR = String.fromCodePoint(0x1F4E6);

const MUTATIONS = {
  "signed-out-shows-page": ["page", "  if (!token) { showOwnerOnly(); return; }", "  if (!token) { showOwnerView(); return; }"],
  "forbidden-shows-page": ["page", "    if (res.status === 401 || res.status === 403) { showOwnerOnly(); return; }", "    if (res.status === 401) { showOwnerOnly(); return; }"],
  "open-latest-first": ["page", "  open.sort(function (a, b) { return String(a.deadline).localeCompare(String(b.deadline)); });",
    "  open.sort(function (a, b) { return String(b.deadline).localeCompare(String(a.deadline)); });"],
  "answered-above-open": ["page", "  area.innerHTML = html;\n}", "  area.innerHTML = html.split('<h2').slice(1).reverse().map(function (x) { return '<h2' + x; }).join('');\n}"],
  "old-answered-shown": ["page", "    return !isNaN(t) && now - t <= RECENT_ANSWERED_MS;", "    return !isNaN(t);"],
  "no-days-left": ["page", "fact(\"Deadline\", dateText(r.deadline) + (r.open ? \" (\" + esc(daysLeftText(r.deadline)) + \")\" : \"\"))", "fact(\"Deadline\", dateText(r.deadline))"],
  "no-order-ids": ["page", "    + fact(\"Order ids\", orders, true)\n", ""],
  "no-email-state": ["page", "    + fact(\"Owner email\", r.owner_notified_at ? \"Sent \" + dateText(r.owner_notified_at) : \"Not sent\")\n", ""],
  "no-confirm-step": ["page", "  if (action === \"ask\") { confirming[id] = true; delete rowErrors[id]; render(); }", "  if (action === \"ask\") { confirming[id] = true; markAnswered(id); }"],
  "cancel-sends": ["page", "  else if (action === \"cancel\") { delete confirming[id]; render(); }", "  else if (action === \"cancel\") { markAnswered(id); }"],
  "wrong-route": ["page", "encodeURIComponent(id) + \"/answered\", {", "encodeURIComponent(id) + \"/answer\", {"],
  "post-without-token": ["page", "    headers: { \"Authorization\": \"Bearer \" + token, \"Content-Type\": \"application/json\" }", "    headers: { \"Content-Type\": \"application/json\" }"],
  "row-not-updated": ["page", "    replaceRequest(body.request);\n", ""],
  "failure-hidden": ["page", "    if (rowErrors[r.id]) html += '<span class=\"action-error\">' + esc(rowErrors[r.id]) + '</span>';\n", ""],
  "no-empty-state": ["page", "'<p class=\"empty-state\" id=\"emptyState\">No Shopify data requests.</p>'", "''"],
  "emoji-in-page": ["page", "Data Requests</h1>", "Data Requests " + EMOJI_CHAR + "</h1>"],
  "no-back-link": ["page", "    <a href=\"dashboard.html\" class=\"back-link\">", "    <a href=\"index.html\" class=\"back-link\">"],
  "link-for-everyone": ["cc", "            if (!isAdmin()) { return; }\n            // Owner-only tool (W3, Nov 15 2026): the Shopify data requests page.\n",
    "            // Owner-only tool (W3, Nov 15 2026): the Shopify data requests page.\n"],
  "email-short-link": ["hooks", "const REQUESTS_PAGE_URL = \"https://bizforceai.net/shopify-requests.html\";", "const REQUESTS_PAGE_URL = \"/shopify-requests.html\";"]
};
const NAMES = Object.keys(MUTATIONS);
const MUTATE = process.env.MUTATE || "";
if (MUTATE === "all") MUT.runAllMutations(__filename, NAMES);
if (MUTATE && MUTATE !== "all" && NAMES.indexOf(MUTATE) === -1) { console.error("Unknown MUTATE=" + MUTATE + ". Known: " + NAMES.join(", ")); process.exit(2); }

let failures = 0, passes = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}
function section(t) { console.log("\n" + t); }
const UNHANDLED = [];
process.on("unhandledRejection", function (e) { UNHANDLED.push(e); });

const FILES = { page: readFe(PAGE), cc: readFe(CC), hooks: readBe("lib/shopifyWebhooks.js"), map: readBe("lib/appMap.json") };
if (MUTATE && MUTATE !== "all") {
  const m = MUTATIONS[MUTATE];
  FILES[m[0]] = MUT.replaceOnce(FILES[m[0]], m[1], m[2], MUTATE);
  console.log("\n!! MUTATION: " + MUTATE);
}

let JSDOM = null;
try { JSDOM = realRequire("jsdom").JSDOM; } catch (e) { JSDOM = null; }

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.now();
const iso = (ms) => new Date(ms).toISOString();
const ID = { soon: "aaaaaaaa-0000-4000-8000-000000000001", later: "aaaaaaaa-0000-4000-8000-000000000002",
  late: "aaaaaaaa-0000-4000-8000-000000000003", recent: "aaaaaaaa-0000-4000-8000-000000000004", old: "aaaaaaaa-0000-4000-8000-000000000005" };
function req(id, shop, receivedMs, extra) {
  return Object.assign({ id: id, shop: shop, received_at: iso(receivedMs), deadline: iso(receivedMs + 30 * DAY), owner_notified_at: null,
    answered_at: null, open: true, request_details: { customer_id: "7", orders_requested: ["1001", "1002"], data_request_id: "9001" } }, extra || {});
}
function fixtures() {
  return [
    // Newest first, as the server sends them.
    req(ID.later, "later-shop.myshopify.com", NOW - 5 * DAY - 3600 * 1000, { owner_notified_at: iso(NOW - 5 * DAY), request_details: { customer_id: "8", orders_requested: ["2001"], data_request_id: "9002" } }),
    req(ID.recent, "recent-shop.myshopify.com", NOW - 12 * DAY, { answered_at: iso(NOW - 2 * DAY), open: false, owner_notified_at: iso(NOW - 12 * DAY) }),
    req(ID.soon, "soon-shop.myshopify.com", NOW - 25 * DAY - 3600 * 1000, { request_details: { customer_id: "9", orders_requested: [], data_request_id: "9003" } }),
    req(ID.late, "late-shop.myshopify.com", NOW - 32 * DAY - 3600 * 1000),
    req(ID.old, "old-shop.myshopify.com", NOW - 70 * DAY, { answered_at: iso(NOW - 45 * DAY), open: false })
  ];
}

/* The page in jsdom; fetch is the fake API. opts: token, list (status, body), post (status, body). */
function openPage(opts) {
  const calls = [];
  const dom = new JSDOM(FILES.page, {
    url: "https://bizforceai.net/" + PAGE, runScripts: "dangerously", pretendToBeVisual: true,
    beforeParse(w) {
      try { if (opts.token) w.localStorage.setItem("bf_token", opts.token); } catch (e) { /* none */ }
      w.fetch = function (url, init) {
        init = init || {};
        const call = { url: String(url), method: (init.method || "GET").toUpperCase(), headers: init.headers || {} };
        calls.push(call);
        let answer = { status: 404, body: { error: "not found" } };
        if (call.method === "GET" && /\/api\/admin\/shopify-data-requests$/.test(call.url)) answer = opts.list;
        if (call.method === "POST") answer = typeof opts.post === "function" ? opts.post(call) : opts.post;
        const p = Promise.resolve({ ok: answer.status >= 200 && answer.status < 300, status: answer.status,
          json: function () { return Promise.resolve(JSON.parse(JSON.stringify(answer.body))); } });
        p.catch(function () {});
        return p;
      };
    }
  });
  return { dom: dom, w: dom.window, d: dom.window.document, calls: calls };
}
const tick = () => new Promise((r) => setTimeout(r, 0));
async function settle() { for (let i = 0; i < 10; i++) await tick(); }
// The text a visitor sees in .page: hidden elements left out.
function visibleText(node) {
  if (node.nodeType === 3) return node.nodeValue;
  if (node.nodeType !== 1 || node.hidden || /^(SCRIPT|STYLE)$/.test(node.tagName)) return "";
  let t = "";
  node.childNodes.forEach(function (c) { t += visibleText(c); });
  return t;
}
const squash = (s) => String(s).replace(/\s+/g, " ").trim();
function cardsIn(d, listId) { const l = d.getElementById(listId); return l ? Array.from(l.querySelectorAll(".request-card")) : []; }
function cardOf(d, id) { return d.querySelector('.request-card[data-request-id="' + id + '"]'); }
function factOf(card, label) {
  const row = Array.from(card.querySelectorAll(".request-facts div")).find(function (x) { return squash(x.querySelector("dt").textContent) === label; });
  return row ? squash(row.querySelector("dd").textContent) : null;
}
function click(page, btn) { btn.dispatchEvent(new page.w.MouseEvent("click", { bubbles: true })); }
function button(card, text) { return Array.from(card.querySelectorAll("button")).find(function (b) { return squash(b.textContent) === text; }); }

(async function main() {
  if (!JSDOM) { check("0. jsdom is installed", false); console.log("\nCHECKS FAILED"); process.exit(1); }
  const OWNER_LINE = "This page is for the site owner.";
  const CHROME = "Executive HQ BizForce AI";

  /* ── A ─────────────────────────────────────────────────────────────────── */
  section("A. a visitor who is not the owner sees only the owner line");
  for (const kase of [{ name: "signed out", token: null }, { name: "a member the server answers 403", token: "member-token", status: 403 },
    { name: "a member whose session the server refuses (401)", token: "stale-token", status: 401 }]) {
    const pg = openPage({ token: kase.token, list: { status: kase.status || 200, body: kase.status ? { error: "Admin access required" } : { requests: fixtures(), open: 3 } } });
    await settle();
    const text = squash(visibleText(pg.d.querySelector(".page")));
    check("A1. " + kase.name + ": the page shows only \"" + OWNER_LINE + "\" (under the back link)", text === CHROME + " " + OWNER_LINE, text);
    check("A2. " + kase.name + ": no request, heading or button is on the page", pg.d.querySelectorAll(".request-card, h1, h2, button").length === 0 ||
      Array.from(pg.d.querySelectorAll(".request-card, h1, h2, button")).every(function (n) { return !n.closest(".page") || n.closest("[hidden]"); }));
    if (!kase.token) check("A3. signed out, the page asks the server nothing", pg.calls.length === 0, JSON.stringify(pg.calls));
    else check("A3. " + kase.name + ": one request, GET /api/admin/shopify-data-requests with the token", pg.calls.length === 1 &&
      /\/api\/admin\/shopify-data-requests$/.test(pg.calls[0].url) && pg.calls[0].headers.Authorization === "Bearer " + kase.token, JSON.stringify(pg.calls));
    pg.w.close();
  }

  /* ── B ─────────────────────────────────────────────────────────────────── */
  section("B. the owner sees open requests first, then those answered in the last 30 days");
  let posted = [];
  const owner = openPage({ token: "owner-token", list: { status: 200, body: { requests: fixtures(), open: 3 } },
    post: function (call) {
      posted.push(call);
      const id = decodeURIComponent(call.url.split("/shopify-data-requests/")[1].split("/")[0]);
      const was = fixtures().find(function (r) { return r.id === id; });
      return { status: 200, body: { request: Object.assign({}, was, { answered_at: iso(Date.now()), open: false }) } };
    } });
  await settle();
  {
    const d = owner.d;
    check("B1. the owner view is shown and the owner line is not", d.getElementById("ownerView").hidden === false && d.getElementById("ownerOnly").hidden === true);
    const heads = Array.from(d.querySelectorAll("#requestsArea h2")).map(function (h) { return squash(h.textContent); });
    check("B2. two lists, open first: \"Open (3)\" then \"Answered in the last 30 days\"", JSON.stringify(heads) === JSON.stringify(["Open (3)", "Answered in the last 30 days"]), JSON.stringify(heads));
    const all = Array.from(d.querySelectorAll("#requestsArea .request-card")).map(function (c) { return c.getAttribute("data-request-id"); });
    check("B3. the open requests, nearest deadline first (overdue, then 5 days left, then 25), then the recent answer",
      JSON.stringify(all) === JSON.stringify([ID.late, ID.soon, ID.later, ID.recent]), JSON.stringify(all));
    check("B4. an answer older than 30 days is not shown", !cardOf(d, ID.old));
    const later = cardOf(d, ID.later), soon = cardOf(d, ID.soon), late = cardOf(d, ID.late);
    check("B5. each open request shows its shop", squash(later.querySelector(".request-shop").textContent) === "later-shop.myshopify.com");
    const rec = new Date(NOW - 5 * DAY - 3600 * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
    const dl = new Date(NOW + 25 * DAY - 3600 * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
    check("B6. the received date", factOf(later, "Received") === rec, factOf(later, "Received"));
    check("B7. the deadline with the days left", factOf(later, "Deadline") === dl + " (25 days left)", factOf(later, "Deadline"));
    check("B8. ... and an overdue one says so", /\(overdue by 2 days\)$/.test(factOf(late, "Deadline") || "") && /\(5 days left\)$/.test(factOf(soon, "Deadline") || ""),
      factOf(late, "Deadline") + " / " + factOf(soon, "Deadline"));
    check("B9. the request id and the order ids", factOf(later, "Request id") === "9002" && factOf(later, "Order ids") === "2001" &&
      factOf(late, "Order ids") === "1001, 1002" && factOf(soon, "Order ids") === "None named", [factOf(later, "Request id"), factOf(later, "Order ids"), factOf(soon, "Order ids")].join(" / "));
    const sent = new Date(NOW - 5 * DAY).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
    check("B10. whether the owner email was sent", factOf(later, "Owner email") === "Sent " + sent && factOf(soon, "Owner email") === "Not sent",
      factOf(later, "Owner email") + " / " + factOf(soon, "Owner email"));
    check("B11. only open requests carry \"Mark answered\"", [ID.late, ID.soon, ID.later].every(function (id) { return !!button(cardOf(d, id), "Mark answered"); }) &&
      cardOf(d, ID.recent).querySelectorAll("button").length === 0);
  }

  /* ── C ─────────────────────────────────────────────────────────────────── */
  section("C. Mark answered asks first, then calls the route once");
  {
    const d = owner.d;
    click(owner, button(cardOf(d, ID.soon), "Mark answered"));
    await settle();
    const card = cardOf(d, ID.soon);
    check("C1. pressing \"Mark answered\" asks first and calls nothing", posted.length === 0 && /^Mark this request answered\?/.test(squash((card.querySelector(".confirm-text") || {}).textContent || "")) &&
      !!button(card, "Yes, mark answered") && !!button(card, "Cancel"), posted.length);
    click(owner, button(card, "Cancel"));
    await settle();
    check("C2. Cancel calls nothing and puts the button back", posted.length === 0 && !!button(cardOf(d, ID.soon), "Mark answered") && !cardOf(d, ID.soon).querySelector(".confirm-text"), posted.length);
    click(owner, button(cardOf(d, ID.soon), "Mark answered"));
    await settle();
    click(owner, button(cardOf(d, ID.soon), "Yes, mark answered"));
    await settle();
    check("C3. \"Yes, mark answered\" makes exactly one POST to /api/admin/shopify-data-requests/<id>/answered with the member's token",
      posted.length === 1 && posted[0].url === "https://dynamic-prosperity-production-5382.up.railway.app/api/admin/shopify-data-requests/" + ID.soon + "/answered" &&
      posted[0].headers.Authorization === "Bearer owner-token", JSON.stringify(posted));
    const open = cardsIn(d, "openList").map(function (c) { return c.getAttribute("data-request-id"); });
    const answered = cardsIn(d, "answeredList").map(function (c) { return c.getAttribute("data-request-id"); });
    check("C4. the row moves to the answered list, with no button", open.indexOf(ID.soon) === -1 && answered[0] === ID.soon && cardOf(d, ID.soon).querySelectorAll("button").length === 0 &&
      squash(d.querySelector("#requestsArea h2").textContent) === "Open (2)", JSON.stringify({ open: open, answered: answered }));
  }
  owner.w.close();
  {
    const fail = openPage({ token: "owner-token", list: { status: 200, body: { requests: fixtures(), open: 3 } }, post: { status: 500, body: { error: "The database did not answer." } } });
    await settle();
    click(fail, button(cardOf(fail.d, ID.later), "Mark answered"));
    await settle();
    click(fail, button(cardOf(fail.d, ID.later), "Yes, mark answered"));
    await settle();
    const card = cardOf(fail.d, ID.later);
    check("C5. a failed POST leaves the row open with the server's reason", card && card.closest("#openList") &&
      squash((card.querySelector(".action-error") || {}).textContent || "") === "The database did not answer.", card && card.outerHTML.slice(0, 300));
    fail.w.close();
  }

  /* ── D ─────────────────────────────────────────────────────────────────── */
  section("D. no requests");
  {
    const none = openPage({ token: "owner-token", list: { status: 200, body: { requests: [], open: 0 } } });
    await settle();
    check("D1. \"No Shopify data requests.\" and no list", squash(none.d.getElementById("requestsArea").textContent) === "No Shopify data requests." &&
      none.d.querySelectorAll(".request-card, #requestsArea h2").length === 0, squash(none.d.getElementById("requestsArea").textContent));
    none.w.close();
    const onlyOld = openPage({ token: "owner-token", list: { status: 200, body: { requests: fixtures().filter(function (r) { return r.id === ID.old; }), open: 0 } } });
    await settle();
    check("D2. only an answer older than 30 days: the same empty line", squash(onlyOld.d.getElementById("requestsArea").textContent) === "No Shopify data requests.",
      squash(onlyOld.d.getElementById("requestsArea").textContent));
    onlyOld.w.close();
  }

  /* ── E ─────────────────────────────────────────────────────────────────── */
  section("E. the page's own parts");
  const EMOJI = /\p{Extended_Pictographic}|&#x?(1f[0-9a-f]{3}|[0-9]{6});/iu;
  check("E1. no emoji in the page or in this check", !EMOJI.test(FILES.page) && !EMOJI.test(fs.readFileSync(__filename, "utf8")));
  check("E2. the back link goes to Executive HQ (dashboard.html)", /<a href="dashboard\.html" class="back-link">[\s\S]*?Executive HQ\s*<\/a>/.test(FILES.page));
  check("E3. the legal footer links, noindex, and the theme tag first in <head>",
    FILES.page.indexOf("<footer class=\"bf-legal-footer\" data-bf-legal-footer></footer>\n<script src=\"/scripts/bf-legal-footer.js\"></script>") !== -1 &&
    FILES.page.indexOf("<meta name=\"robots\" content=\"noindex\"/>") !== -1 && /<head>\n<script src="\/scripts\/bf-theme\.js"><\/script>/.test(FILES.page));
  const sys = (/function drawSystem\(\) \{[\s\S]*?\n        \}\n/.exec(FILES.cc) || [""])[0];
  const gate = sys.indexOf("if (!isAdmin()) { return; }"), lnk = sys.indexOf("link(\"shopify-requests.html\", \"Shopify data requests\")");
  check("E4. Executive HQ's Command Center links the page from its admin-only System section (after the isAdmin() return), and only there",
    gate !== -1 && lnk > gate && FILES.cc.split("shopify-requests.html").length === 2, "gate " + gate + ", link " + lnk);
  const HOOKS = realRequire("./lib/shopifyWebhooks");
  check("E5. the data request email names the page's full address",
    /const REQUESTS_PAGE_URL = "https:\/\/bizforceai\.net\/shopify-requests\.html";/.test(FILES.hooks) && HOOKS.REQUESTS_PAGE_URL === "https://bizforceai.net/shopify-requests.html");
  let map = null;
  try { map = JSON.parse(FILES.map); } catch (e) { map = null; }
  check("E6. lib/appMap.json lists the page", !!map && JSON.stringify(map).indexOf("\"" + PAGE + "\"") !== -1);

  await settle();
  check("no unhandled rejection", UNHANDLED.length === 0, UNHANDLED.map(String).join("; "));
  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(function (e) { console.log("    FAIL  the check itself threw: " + (e && e.stack || e)); process.exit(1); });
