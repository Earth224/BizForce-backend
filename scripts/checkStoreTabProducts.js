#!/usr/bin/env node
/* checkStoreTabProducts.js — NAMED (Nov 15 2026, S4): the Store tab once a store is connected, and the
   "Propose a change" buttons on both pages that carry them.

   THE PAGE RUNS IN JSDOM: store-agent.html's markup (its script tags left out), then the two scripts the
   Store tab runs, scripts/store-changes.js and scripts/store-connect.js, in that order, against a stubbed
   API. No network, no database, no model call. The visual check is scripts/browserCheckAgents.js (S4).

     A. THE FOLD. With no store connected, the connect form (platform picker, store field, checkbox,
        Connect) shows as before and "Connect another store" does not. With one or more, the form is
        folded behind "Connect another store" (aria-expanded, aria-controls the form); the button opens
        and closes it. A store that needs reconnecting keeps the form open (its line says "Connect it
        again below"), and so does Shopify opening the page to finish. The connect message line sits
        outside the fold, so a return's answer shows either way.
     B. THE PRODUCTS. Under each connected store, its synced products from GET /api/inventory/items with
        store_connection_id (the rows inventory.html lists): name, SKU, the stock (labelled with the
        chosen Shopify location), the store price with the store's currency, and the same "Propose a
        change" control from scripts/store-changes.js on the rows inventory.html gives one (a synced
        row: the form when changes are allowed, the read-only line when not). Paged as inventory.html
        pages: limit and offset, has_more, Previous and Next, 10, 25, 50 or 100 a page, the same
        "Showing ..." words. None synced: "No synced products yet. Press Sync now."
     C. THE BUTTONS. "Propose a change" and "Propose" carry the site's button classes for both pages:
        action-btn (defined by store-agent.html) and bf-btn (css/bizforce-ui.css, which inventory.html
        loads). Each page defines exactly one of the two, so nothing is styled twice and nothing is bare.
     R. THE ROUTE. GET /api/inventory/items?store_connection_id= narrows to that store's rows, after the
        caller's own (user_id first), and refuses anything but a UUID with a 400; without it, the list
        is as before.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each in its own process (each must be caught). */
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";

const PAGE = "store-agent.html", CONNECT = "scripts/store-connect.js", CHANGES = "scripts/store-changes.js",
  INVENTORY = "inventory.html", UI_CSS = "css/bizforce-ui.css", SERVER = "server.js";
const FRONT_FILES = [PAGE, CONNECT, CHANGES, INVENTORY, UI_CSS];

const MUTATIONS = {
  // A: the form never folds
  "fold-never": [[CONNECT, "    var open = !any || held || formOpen;\n", "    var open = true;\n"]],
  // A: the form folds with no store connected too
  "fold-with-none": [[CONNECT, "    var open = !any || held || formOpen;\n", "    var open = held || formOpen;\n"]],
  // A: a store that needs reconnecting folds the form its line points to
  "reconnect-folded": [[CONNECT, "    var held = formHeld || list.some(function (c) { return c && c.status === \"needs_reconnect\"; });\n", "    var held = formHeld;\n"]],
  // A: the button does nothing
  "toggle-unwired": [[CONNECT, "    if (byId(\"storeConnectAnother\")) byId(\"storeConnectAnother\").addEventListener(\"click\", toggleForm);\n", ""]],
  // A: aria-expanded is never set on open
  "toggle-no-aria": [[CONNECT, "    byId(\"storeConnectAnother\").setAttribute(\"aria-expanded\", formOpen ? \"true\" : \"false\");\n", ""]],
  // A: the message line goes back inside the fold
  "msg-inside-fold": [[PAGE, "      </div>\n      <div class=\"store-msg\" id=\"storeConnectMsg\"></div>\n    </section>\n",
    "        <div class=\"store-msg\" id=\"storeConnectMsg\"></div>\n      </div>\n    </section>\n"]],
  // B: every store's list shows every synced item
  "products-unfiltered": [[CONNECT, "\"/api/inventory/items?store_connection_id=\" + encodeURIComponent(c.id) + \"&limit=\"", "\"/api/inventory/items?limit=\""]],
  // B: the empty wording drifts
  "products-empty-wording": [[CONNECT, "\"No synced products yet. Press Sync now.\"", "\"No products.\""]],
  // B: no control on the rows
  "products-no-control": [[CONNECT, "      if (node) slot.appendChild(node);\n    }\n    row.appendChild(slot);", "    }\n    row.appendChild(slot);"]],
  // B: the price loses its currency
  "products-no-currency": [[CONNECT, "    price.appendChild(el(\"p\", \"store-prod-value\", priceWith(it.unit_price, c.currency)));", "    price.appendChild(el(\"p\", \"store-prod-value\", priceWith(it.unit_price, null)));"]],
  // B: the stock is not labelled with the Shopify location
  "products-no-location": [[CONNECT, "    return c.platform === \"shopify\" && c.stock_scope === \"location\" && c.location_name ? \"Stock at \" + c.location_name : \"Stock\";", "    return \"Stock\";"]],
  // B: Next does not page
  "pager-next-stuck": [[CONNECT, "if (!page.hasMore) return; page.offset += page.limit; renderProducts(c, box);", "if (!page.hasMore) return; renderProducts(c, box);"]],
  // B: the page size is ignored
  "pager-size-ignored": [[CONNECT, "page.limit = Number(size.value) || 25; page.offset = 0;", "page.offset = 0;"]],
  // C: the buttons are bare on inventory.html again
  "propose-bare-on-inventory": [[CHANGES, "\"action-btn action-btn--ghost bf-btn bf-btn-ghost store-change-open\"", "\"action-btn action-btn--ghost store-change-open\""]],
  "propose-send-bare-on-inventory": [[CHANGES, "\"action-btn bf-btn store-change-send\"", "\"action-btn store-change-send\""]],
  // R: the route ignores the store
  "route-unfiltered": [[SERVER, "    if (storeConnectionId !== undefined) itemQuery = itemQuery.eq(\"store_connection_id\", storeConnectionId);\n", ""]],
  // R: the route takes anything
  "route-accepts-any": [[SERVER, "    if (storeConnectionId !== undefined && !(typeof storeConnectionId === \"string\" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(storeConnectionId))) {",
    "    if (false) {"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
FRONT_FILES.forEach(f => {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(2); }
  FILES[f] = lf(fs.readFileSync(p, "utf8"));
});
FILES[SERVER] = lf(fs.readFileSync(path.join(REPO, SERVER), "utf8"));
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 600) + "]" : "")); }
}
process.on("unhandledRejection", e => check("no page request is left unhandled", false, (e && e.message) || e));
const J = JSON.stringify;
const API = "https://dynamic-prosperity-production-5382.up.railway.app";
const flush = async n => { for (let i = 0; i < (n || 20); i++) await new Promise(r => setImmediate(r)); };

/* ── fixtures ── */
const C_SHOP = "a1111111-1111-4111-8111-111111111111", C_WOO = "a2222222-2222-4222-8222-222222222222";
const conn = (id, extra) => Object.assign({ id: id, platform: "shopify", store: "maple.myshopify.com", status: "connected", permission: "read_write",
  currency: "USD", connected_since: "2026-11-01T00:00:00Z", last_sync_at: "2026-11-14T00:00:00Z", stock_scope: "location", location_name: "Main warehouse", location_id: "gid://shopify/Location/1" }, extra || {});
const item = (i, connId, extra) => Object.assign({ id: "b0000000-0000-4000-8000-" + String(i).padStart(12, "0"), name: "Product " + i, sku: "SKU-" + i,
  quantity_on_hand: i, unit_price: (10 + i) + ".50", source: "shopify", store_connection_id: connId, status: "active" }, extra || {});
const SHOP_ITEMS = Array.from({ length: 30 }, (_, k) => item(k + 1, C_SHOP));

function runPage(answer) {
  const html = FILES[PAGE].replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "");
  const dom = new JSDOM(html, { url: "https://bizforceai.net/store-agent.html", runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  w.localStorage.setItem("bf_token", "tok");
  const calls = [];
  w.fetch = function (url, init) {
    const u = String(url).replace(API, ""), method = (init && init.method) || "GET";
    calls.push(method + " " + u);
    const a = answer(u, method) || { status: 404, body: { error: "not in this fixture" } };
    const pr = Promise.resolve({ ok: a.status < 300, status: a.status, json: function () { return Promise.resolve(a.body); } });
    pr.catch(function () {});
    return pr;
  };
  w.eval(FILES[CHANGES] + "\n//# sourceURL=" + CHANGES);
  w.eval(FILES[CONNECT] + "\n//# sourceURL=" + CONNECT);
  return { w: w, doc: w.document, calls: calls };
}
function answers(conns, itemsFor) {
  return function (u, method) {
    if (u === "/api/store/connections" && method === "GET") return { status: 200, body: { connections: conns, shopify_available: true, etsy_available: true, amazon_available: true, amazon_draft: false } };
    if (/^\/api\/store\/changes(\?|$)/.test(u)) return { status: 200, body: { changes: [] } };
    const m = /^\/api\/inventory\/items\?(.*)$/.exec(u);
    if (m && method === "GET") {
      const q = new URLSearchParams(m[1]);
      const limit = Number(q.get("limit")), offset = Number(q.get("offset"));
      const all = itemsFor(q.get("store_connection_id"));
      const rows = all.slice(offset, offset + limit);
      return { status: 200, body: { items: rows, limit: limit, offset: offset, has_more: offset + limit < all.length } };
    }
    return null;
  };
}
const shown = (w, n) => { for (let e = n; e && e.nodeType === 1; e = e.parentElement) { if (e.hidden || w.getComputedStyle(e).display === "none") return false; } return !!n; };

(async function () {
  /* ── A ── */
  console.log("\n══ A. the connect form: open with no store, folded behind \"Connect another store\" with one ══");
  let p = runPage(answers([], () => []));
  await flush();
  const fNone = { form: shown(p.w, p.doc.getElementById("storeConnectForm")), another: shown(p.w, p.doc.getElementById("storeConnectAnother")),
    text: p.doc.getElementById("storeConnections").textContent };
  check("A1. no store connected: the connect form (picker, store field, checkbox, Connect) shows as before; no \"Connect another store\"",
    fNone.form && !fNone.another && fNone.text === "No store connected yet." && shown(p.w, p.doc.getElementById("storePickShopify")) &&
    shown(p.w, p.doc.getElementById("storeShop")) && shown(p.w, p.doc.getElementById("storeShopifyAllow")) && shown(p.w, p.doc.getElementById("storeShopifyBtn")), J(fNone));

  p = runPage(answers([conn(C_SHOP)], id => (id === C_SHOP ? SHOP_ITEMS : [])));
  await flush();
  const btn = p.doc.getElementById("storeConnectAnother"), form = p.doc.getElementById("storeConnectForm");
  const f1 = { form: shown(p.w, form), another: shown(p.w, btn), text: btn && btn.textContent, exp: btn && btn.getAttribute("aria-expanded"), ctl: btn && btn.getAttribute("aria-controls"),
    cls: btn && btn.className, inForm: ["storePickShopify", "storeShop", "storeShopifyAllow", "storeShopifyBtn", "storeUrl", "storeConnectBtn", "storeEtsyBtn", "storeAmazonBtn"].every(id => form.contains(p.doc.getElementById(id))) };
  check("A2. one store connected: the form is folded and \"Connect another store\" shows (a ghost button, aria-expanded false, aria-controls the form); the form holds the picker, fields, boxes and Connect buttons",
    !f1.form && f1.another && f1.text === "Connect another store" && f1.exp === "false" && f1.ctl === "storeConnectForm" && f1.cls === "action-btn action-btn--ghost" && f1.inForm, J(f1));
  btn.click();
  const f2 = { form: shown(p.w, form), exp: btn.getAttribute("aria-expanded"), another: shown(p.w, btn) };
  btn.click();
  const f3 = { form: shown(p.w, form), exp: btn.getAttribute("aria-expanded") };
  check("A3. the button opens the form (aria-expanded true) and closes it again", f2.form && f2.exp === "true" && f2.another && !f3.form && f3.exp === "false", J([f2, f3]));
  const msg = p.doc.getElementById("storeConnectMsg");
  check("A4. the connect message line sits outside the fold, so a return's answer shows while the form is folded",
    !!msg && !form.contains(msg) && msg.parentNode === p.doc.getElementById("storeConnect") && shown(p.w, msg), msg && msg.parentNode && msg.parentNode.id);

  p = runPage(answers([conn(C_SHOP, { status: "needs_reconnect" })], () => []));
  await flush();
  const f4 = { form: shown(p.w, p.doc.getElementById("storeConnectForm")), another: shown(p.w, p.doc.getElementById("storeConnectAnother")),
    warn: /Connect it again below/.test(p.doc.getElementById("storeConnections").textContent) };
  check("A5. a store that needs reconnecting keeps the form open under its \"Connect it again below\" line, with no button", f4.form && !f4.another && f4.warn, J(f4));

  /* ── B ── */
  console.log("\n══ B. a connected store's synced products, paged as inventory.html pages ══");
  p = runPage(answers([conn(C_SHOP), conn(C_WOO, { platform: "woocommerce", store: "https://shop.example.com", permission: "read", currency: "EUR", stock_scope: null, location_name: null })],
    id => (id === C_SHOP ? SHOP_ITEMS : id === C_WOO ? [item(91, C_WOO, { source: "woocommerce", unit_price: "8.00" }), item(92, C_WOO, { source: null, sku: null })] : [])));
  await flush(40);
  const box = p.doc.getElementById("storeProducts-" + C_SHOP), boxW = p.doc.getElementById("storeProducts-" + C_WOO);
  const rowsOf = b => b ? Array.prototype.map.call(b.querySelectorAll(".store-prod"), r => ({
    name: r.querySelector(".store-prod-name").textContent, sku: r.querySelector(".store-prod-sku").textContent,
    stock: r.querySelector(".store-prod-stock .store-prod-value").textContent, stockLabel: r.querySelector(".store-prod-stock .store-prod-label").textContent,
    price: r.querySelector(".store-prod-price .store-prod-value").textContent,
    open: (r.querySelector(".store-change-open") || {}).textContent || null, ro: (r.querySelector(".store-change-readonly") || {}).textContent || null })) : [];
  const r1 = rowsOf(box), rW = rowsOf(boxW);
  const itemCalls = p.calls.filter(c => /\/api\/inventory\/items/.test(c));
  check("B1. each connected store asks for its own synced items: store_connection_id, limit 25, offset 0 (inventory.html's first page)",
    itemCalls.indexOf("GET /api/inventory/items?store_connection_id=" + C_SHOP + "&limit=25&offset=0") !== -1 &&
    itemCalls.indexOf("GET /api/inventory/items?store_connection_id=" + C_WOO + "&limit=25&offset=0") !== -1, J(itemCalls));
  check("B2. the rows sit under their store, after its Sync now and Disconnect: name, SKU, stock at the chosen Shopify location, store price with the currency",
    !!box && box.parentNode.className === "store-conn" && r1.length === 25 && J(r1[0]) === J({ name: "Product 1", sku: "SKU SKU-1", stock: "1", stockLabel: "Stock at Main warehouse", price: "11.50 USD", open: "Propose a change", ro: null }) &&
    rW.length === 2 && rW[0].stockLabel === "Stock" && rW[0].price === "8.00 EUR" && rW[1].sku === "No SKU", J([r1[0], rW]));
  check("B3. the same control inventory.html shows, on the same rows: \"Propose a change\" where changes are allowed, the read-only line where not, nothing on a manual row",
    r1.every(r => r.open === "Propose a change" && r.ro === null) && rW[0].open === null && rW[0].ro === "Read only: reconnect with changes allowed to propose changes" &&
    rW[1].open === null && rW[1].ro === null, J(rW));
  const pager = box && box.querySelector(".store-pager");
  const pinfo = () => ({ info: pager.querySelector(".store-pager-info").textContent, prev: pager.querySelector(".store-pager-prev").disabled, next: pager.querySelector(".store-pager-next").disabled,
    sizes: Array.prototype.map.call(pager.querySelectorAll("select option"), o => o.value), size: pager.querySelector("select").value, label: (pager.querySelector("label") || {}).textContent });
  const pg1 = pager ? pinfo() : null;
  check("B4. the pager as inventory.html's: \"Showing 1–25, and there are more.\", Previous off, Next on, 10, 25, 50 or 100 per page (25)",
    !!pg1 && !pager.hidden && pg1.info === "Showing 1–25, and there are more." && pg1.prev === true && pg1.next === false && J(pg1.sizes) === J(["10", "25", "50", "100"]) && pg1.size === "25" && pg1.label === "Per page", J(pg1));
  box.querySelector(".store-pager-next").click();
  await flush(30);
  const box2 = p.doc.getElementById("storeProducts-" + C_SHOP), pager2 = box2.querySelector(".store-pager");
  const pg2 = { rows: rowsOf(box2).map(r => r.name), info: pager2.querySelector(".store-pager-info").textContent, prev: pager2.querySelector(".store-pager-prev").disabled, next: pager2.querySelector(".store-pager-next").disabled };
  check("B5. Next asks for offset 25 and shows the last 5: \"Showing 26–30. End of the list.\", Next off, Previous on",
    p.calls.indexOf("GET /api/inventory/items?store_connection_id=" + C_SHOP + "&limit=25&offset=25") !== -1 && pg2.rows.length === 5 && pg2.rows[0] === "Product 26" &&
    pg2.info === "Showing 26–30. End of the list." && pg2.next === true && pg2.prev === false, J(pg2));
  const sel = pager2.querySelector("select");
  sel.value = "10"; sel.dispatchEvent(new p.w.Event("change", { bubbles: true }));
  await flush(30);
  const box3 = p.doc.getElementById("storeProducts-" + C_SHOP);
  check("B6. a page size of 10 starts again at the first page: limit 10, offset 0, ten rows",
    p.calls.indexOf("GET /api/inventory/items?store_connection_id=" + C_SHOP + "&limit=10&offset=0") !== -1 && rowsOf(box3).length === 10 &&
    box3.querySelector(".store-pager-info").textContent === "Showing 1–10, and there are more.", J(p.calls.slice(-2)));

  p = runPage(answers([conn(C_SHOP)], () => []));
  await flush(30);
  const empty = p.doc.getElementById("storeProducts-" + C_SHOP);
  check("B7. nothing synced: \"No synced products yet. Press Sync now.\", no pager",
    !!empty && empty.querySelector(".store-products-empty") && empty.querySelector(".store-products-empty").textContent === "No synced products yet. Press Sync now." &&
    empty.querySelector(".store-pager").hidden === true, empty && empty.textContent);

  /* ── C ── */
  console.log("\n══ C. \"Propose a change\" and \"Propose\": the site's button classes on both pages ══");
  p = runPage(answers([conn(C_SHOP)], id => SHOP_ITEMS.slice(0, 1)));
  await flush(30);
  const openB = p.doc.querySelector(".store-change-open"), sendB = p.doc.querySelector(".store-change-send");
  check("C1. \"Propose a change\" is action-btn action-btn--ghost and bf-btn bf-btn-ghost; \"Propose\" is action-btn and bf-btn",
    !!openB && !!sendB && J(openB.className.split(" ")) === J(["action-btn", "action-btn--ghost", "bf-btn", "bf-btn-ghost", "store-change-open"]) &&
    J(sendB.className.split(" ")) === J(["action-btn", "bf-btn", "store-change-send"]), J([openB && openB.className, sendB && sendB.className]));
  const page = FILES[PAGE], inv = FILES[INVENTORY], css = FILES[UI_CSS];
  const linksUi = t => /<link[^>]+href="\/css\/bizforce-ui\.css"/.test(t);
  check("C2. store-agent.html styles action-btn and action-btn--ghost itself and does not load bizforce-ui.css (no bf-btn there)",
    /\n\s*\.action-btn \{/.test(page) && /\n\s*\.action-btn--ghost \{/.test(page) && !linksUi(page) && !/\.bf-btn/.test(page));
  check("C3. inventory.html loads css/bizforce-ui.css, whose .bf-btn and .bf-btn.bf-btn-ghost rules style the buttons, and defines no action-btn",
    linksUi(inv) && /(^|\n)\.bf-btn,/.test(css) && /(^|\n)\.bf-btn\.bf-btn-ghost,/.test(css) && !/\.action-btn/.test(inv));
  check("C4. inventory.html still loads scripts/store-changes.js and leaves each synced row its slot", /<script src="\/scripts\/store-changes\.js"><\/script>/.test(inv) && /data-store-item=/.test(inv));

  /* ── R ── */
  console.log("\n══ R. GET /api/inventory/items?store_connection_id= ══");
  const src = FILES[SERVER];
  const a = src.indexOf("app.get(\"/api/inventory/items\", requireAuth,"), b = src.indexOf("app.post(\"/api/inventory/items\", requireAuth,");
  let route = null;
  const qlog = [];
  const ROWS = [{ id: "r1", user_id: "u1", store_connection_id: C_SHOP }, { id: "r2", user_id: "u1", store_connection_id: C_WOO }, { id: "r3", user_id: "u2", store_connection_id: C_SHOP }];
  function sb() {
    return { from: function (t) { const calls = []; qlog.push(calls); const q = {};
      ["select", "order"].forEach(k => { q[k] = function () { calls.push([k].concat([].slice.call(arguments))); return q; }; });
      q.eq = function (col, v) { calls.push(["eq", col, v]); return q; };
      q.range = function (x, y) { calls.push(["range", x, y]); let rows = ROWS.slice(); calls.filter(c => c[0] === "eq").forEach(c => { rows = rows.filter(r => r[c[1]] === c[2]); });
        return Promise.resolve({ data: rows.slice(x, y + 1), error: null }); };
      return q; } };
  }
  if (a !== -1 && b > a) {
    const ctx = { app: { get: function (pth, mw, h) { route = h; } }, requireAuth: function () {}, supabase: sb(),
      parseListRange: function () { return { ok: true, limit: 25, offset: 0 }; }, Promise: Promise, RegExp: RegExp };
    vm.createContext(ctx);
    vm.runInContext(src.slice(a, b), ctx, { filename: "server.js (inventory items GET)" });
  }
  const call = async query => { const res = { code: 200, body: null, status(c) { this.code = c; return this; }, json(x) { this.body = x; return this; } };
    let err = null; await route({ user: { id: "u1" }, query: query }, res, e => { err = e; }); return { code: res.code, body: res.body, err: err }; };
  if (route) {
    const one = await call({ store_connection_id: C_SHOP });
    const eqs = qlog[qlog.length - 1].filter(c => c[0] === "eq").map(c => c[1]);
    const plain = await call({});
    const bad = await call({ store_connection_id: "x' or 1=1" }), arr = await call({ store_connection_id: [C_SHOP, C_WOO] });
    check("R1. with store_connection_id: only the caller's rows from that store (user_id first, then store_connection_id)",
      one.code === 200 && J(one.body.items.map(r => r.id)) === J(["r1"]) && J(eqs) === J(["user_id", "store_connection_id"]), J([one.body, eqs]));
    check("R2. without it: the caller's whole list, as before (one eq, on user_id)",
      plain.code === 200 && J(plain.body.items.map(r => r.id)) === J(["r1", "r2"]) && J(qlog[qlog.length - 1].filter(c => c[0] === "eq").map(c => c[1])) === J(["user_id"]), J(plain.body));
    check("R3. anything but one UUID is refused, 400, before a read", bad.code === 400 && bad.body.field === "store_connection_id" && arr.code === 400, J([bad, arr]));
  } else check("R0. the route is found in server.js", false, "not found");

  console.log("\n" + passes + " passed, " + failures + " failed");
  if (failures) { console.log("CHECKS FAILED"); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the check ran to the end  [" + (e && e.stack || e) + "]"); process.exit(1); });
