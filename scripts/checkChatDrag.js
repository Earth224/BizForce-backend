"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkChatDrag — the Termaximus chat box (the Guide/Oracle box the mist
   opens, scripts/termaximus-presence.js) moves by its header bar the way the
   mist moves, stays on screen, is remembered on this device, and keeps the
   phone layout as it was.

   Frontend "Termaximus chat box can be moved like the mist" added the drag.
   The whole presence script runs in jsdom, with a small fake layout (jsdom
   lays nothing out): the box is 288 × 340 at its default corner, or where
   its inline left/top put it; the mist is 110 × 110.

     C1  dragging by the header moves the box (and its glow) by the pointer's
         travel, mouse and touch alike; pressing an input, the header's
         buttons or the messages moves nothing; a press under the 6px
         threshold moves nothing;
     C2  it stays fully on screen: while dragged, on load from a stored spot,
         from the default corner on a short window, and after a resize;
     C3  the spot is saved on release under tmx_chat_pos and restored on the
         next load; the reset button and a double-click on the header return
         it to the default corner and forget it;
     C4  tmx_chat_pos is a device preference: on bf-session.js's LEFT ON
         PURPOSE list, in checkOfflineMode's KEPT inventory, and left in
         place by clearDevice();
     C5  at 860px and below nothing drags, the stored spot is not applied,
         the header is not a tab stop and the reset button is hidden, so the
         phone layout is unchanged; widening again restores the spot;
     C6  the header is focusable and the arrow keys nudge it (Shift for 4×),
         saved and clamped; Home resets; keys on the buttons move nothing;
     C7  the mist's own drag still clamps the mist, on the same function.
         (Not asserted: the mist restoring its stored spot on load. It never
         has: _tmxRestorePosition() runs before TMX_POS_KEY is assigned, so it
         reads localStorage key "undefined". Left as it was; reported.)

   No network (fetch is a stub), no database.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check. A mutation
   whose search text does not match exactly once is an ERROR.

   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const PRESENCE = "scripts/termaximus-presence.js", SESSION = "scripts/bf-session.js", OFFLINE_CHECK = "scripts/checkOfflineMode.js";

const MUTATIONS = {
  // pressing inside an input (or anywhere in the box) starts a drag (C1)
  "drag-from-input": [[PRESENCE, '    if (target.closest("button, input, textarea, select, a, label")) return false;\n    return !!target.closest("#tmx-chat-header");\n', "    return true;\n"]],
  // the header's buttons start a drag instead of staying clickable (C1)
  "buttons-grab": [[PRESENCE, '    if (target.closest("button, input, textarea, select, a, label")) return false;\n', ""]],
  // the box is placed wherever the pointer or the stored spot says, unclamped (C2)
  "no-clamp": [[PRESENCE, "    var c = _tmxClampPosition(left, top, chat);\n", "    var c = { left: left, top: top };\n"]],
  // a resize no longer re-clamps it (C2, C5)
  "no-resize-clamp": [[PRESENCE, '  window.addEventListener("resize", _tmxChatRestore);\n', ""]],
  // the spot is not saved on release (C3)
  "not-saved": [[PRESENCE, "      _tmxChatSave(_tmxClampPosition(rect.left, rect.top, chat));\n", ""]],
  // reset moves it but remembers the dragged spot (C3)
  "reset-keeps-spot": [[PRESENCE, "    try { localStorage.removeItem(TMX_CHAT_POS_KEY); } catch (err) {}\n", ""]],
  // the key is missing from bf-session.js's KEPT list (C4)
  "key-missing-from-kept": [[SESSION, "tmx_mist_corner,\n     tmx_chat_pos and tmx_agent_language", "tmx_mist_corner\n     and tmx_agent_language"]],
  // ... or from checkOfflineMode's inventory (C4)
  "key-missing-from-inventory": [[OFFLINE_CHECK, '      tmx_chat_pos: "where the Termaximus chat box sits",\n', ""]],
  // phones can drag it too (C5)
  "drag-on-phones": [[PRESENCE, "    return window.innerWidth > TMX_CHAT_DRAG_MIN_W;\n", "    return true;\n"]],
  // the arrow keys do nothing (C6)
  "no-arrow-keys": [[PRESENCE, "    if (!dx && !dy) return;\n", "    if (true) return;\n"]],
  // the header is never a tab stop (C6)
  "header-not-focusable": [[PRESENCE, '    chatHeader.setAttribute("tabindex", "0");\n', ""]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));

let JSDOM, VirtualConsole;
try { ({ JSDOM, VirtualConsole } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
[PRESENCE, SESSION].forEach(f => {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.log("    FAIL  frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)"); process.exit(1); }
  FILES[f] = lf(fs.readFileSync(p, "utf8"));
});
FILES[OFFLINE_CHECK] = lf(fs.readFileSync(path.join(REPO, OFFLINE_CHECK), "utf8"));

if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [file, from, to] of edits) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}

/* ── the default corner, read from the script (top-right unless tmx_mist_corner says otherwise) ── */
const CORNERS = (() => {
  const m = /var MIST_CORNERS = (\{[\s\S]*?\n  \});/.exec(FILES[PRESENCE]);
  try { return m ? vm.runInNewContext("(" + m[1] + ")") : {}; } catch (e) { return {}; }
})();
const CHAT_W = 288, CHAT_H = 340, MIST_W = 110, MIST_H = 110;
const px = (spec, k) => { const m = new RegExp("\\b" + k + ":\\s*(\\d+)px").exec(spec || ""); return m ? +m[1] : null; };

/* ── a page with the presence script loaded, laid out by hand ── */
function page(opts) {
  opts = opts || {};
  const vc = new VirtualConsole();   // canvas "not implemented" and the like are not this check's business
  const dom = new JSDOM('<!doctype html><html><head></head><body><h1>Dashboard</h1></body></html>',
    { url: "https://bizforceai.com/dashboard.html", runScripts: "outside-only", pretendToBeVisual: true, virtualConsole: vc });
  const w = dom.window;
  const size = { w: opts.w || 1280, h: opts.h || 800 };
  Object.defineProperty(w, "innerWidth", { configurable: true, get: () => size.w });
  Object.defineProperty(w, "innerHeight", { configurable: true, get: () => size.h });
  const corner = CORNERS[opts.corner || "top-right"] || {};
  const box = el => {
    if (el.id === "tmx-chat" || el.id === "tmx-chat-glow-wrap") return { w: Math.min(CHAT_W, size.w - 16), h: CHAT_H, spec: corner.chat };
    if (el.id === "tmx-presence-root") return { w: MIST_W, h: MIST_H, spec: corner.root };
    return null;
  };
  Object.defineProperty(w.HTMLElement.prototype, "offsetWidth", { configurable: true, get() { const b = box(this); return b ? b.w : 0; } });
  Object.defineProperty(w.HTMLElement.prototype, "offsetHeight", { configurable: true, get() { const b = box(this); return b ? b.h : 0; } });
  w.HTMLElement.prototype.getBoundingClientRect = function () {
    const b = box(this);
    if (!b) return { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 };
    const st = this.style, set = v => v !== "" && v !== "auto";
    const left = set(st.left) ? parseFloat(st.left) : (px(b.spec, "left") !== null ? px(b.spec, "left") : size.w - px(b.spec, "right") - b.w);
    const top = set(st.top) ? parseFloat(st.top) : (px(b.spec, "top") !== null ? px(b.spec, "top") : size.h - px(b.spec, "bottom") - b.h);
    return { left, top, right: left + b.w, bottom: top + b.h, width: b.w, height: b.h, x: left, y: top };
  };
  w.fetch = () => { const p = Promise.reject(new Error("no network in this check")); p.catch(() => {}); return p; };
  w.localStorage.setItem("bf_token", "tok");
  if (opts.corner) w.localStorage.setItem("tmx_mist_corner", opts.corner);
  Object.keys(opts.store || {}).forEach(k => w.localStorage.setItem(k, opts.store[k]));
  let loadError = null;
  try { w.eval(FILES[PRESENCE]); } catch (e) { loadError = e; }
  const doc = w.document, $ = id => doc.getElementById(id);
  const rect = () => $("tmx-chat") ? $("tmx-chat").getBoundingClientRect() : { left: NaN, top: NaN };
  const ptr = (type, el, x, y, kind) => el.dispatchEvent(new w.PointerEvent(type, { bubbles: true, cancelable: true, clientX: x, clientY: y, pointerId: 1, pointerType: kind || "mouse", button: 0 }));
  function drag(el, dx, dy, kind) {
    const r = el.getBoundingClientRect ? rect() : null, x = (r ? r.left : 0) + 40, y = (r ? r.top : 0) + 12;
    ptr("pointerdown", el, x, y, kind);
    ptr("pointermove", el, x + dx / 2, y + dy / 2, kind);
    ptr("pointermove", el, x + dx, y + dy, kind);
    ptr("pointerup", el, x + dx, y + dy, kind);
  }
  function resize(nw, nh) { size.w = nw; size.h = nh; w.dispatchEvent(new w.Event("resize")); }
  const key = (el, k, shift) => el.dispatchEvent(new w.KeyboardEvent("keydown", { key: k, shiftKey: !!shift, bubbles: true, cancelable: true }));
  const stored = () => { const v = w.localStorage.getItem("tmx_chat_pos"); try { return v ? JSON.parse(v) : null; } catch (e) { return v; } };
  const inline = el => ({ left: el.style.left, top: el.style.top, right: el.style.right, bottom: el.style.bottom });
  return { w, doc, $, rect, drag, resize, key, stored, inline, loadError, size, ptr };
}
const at = (r, left, top) => r && Math.abs(r.left - left) < 0.01 && Math.abs(r.top - top) < 0.01;
const json = r => JSON.stringify({ left: r.left, top: r.top });
const onScreen = (r, W, H) => r.left >= 0 && r.top >= 0 && r.left + Math.min(CHAT_W, W - 16) <= W && r.top + CHAT_H <= H;

(async function main() {
  const TR = CORNERS["top-right"] || {};
  const DEF = { left: 1280 - px(TR.chat, "right") - CHAT_W, top: px(TR.chat, "top") };   // 812, 320 on a 1280 × 800 window
  check("C0. the default corners were read from MIST_CORNERS (top-right chat at top 320, right 180)",
    DEF.left === 812 && DEF.top === 320, JSON.stringify(DEF));

  console.log("\n══ C1. the header drags; inputs, buttons and the messages do not ══");
  {
    const p = page();
    check("C1. the presence script loads in jsdom with the chat box, its header and a reset button", !p.loadError && !!p.$("tmx-chat-header") && !!p.$("tmx-chat-reset"),
      p.loadError && p.loadError.message);
    check("C1. with nothing stored, the box sits at its default corner, with no inline position", at(p.rect(), DEF.left, DEF.top) && p.inline(p.$("tmx-chat")).left === "", json(p.rect()));
    p.drag(p.$("tmx-chat-title"), -300, 70);
    check("C1. dragging the header's title by (-300, +70) moves the box by exactly that", at(p.rect(), DEF.left - 300, DEF.top + 70), json(p.rect()));
    const g = p.$("tmx-chat-glow-wrap").style;
    check("C1. ... and its glow moves with it", g.left === (DEF.left - 300) + "px" && g.top === (DEF.top + 70) + "px" && g.right === "auto", g.left + " " + g.top);
    p.drag(p.$("tmx-chat-header"), 50, 20, "touch");
    check("C1. a touch drag on the header bar moves it too", at(p.rect(), DEF.left - 250, DEF.top + 90), json(p.rect()));
    check("C1. the header takes no touch scrolling above 860px, so a finger drags it instead of scrolling the page",
      /"@media \(min-width: 861px\) \{ #tmx-chat-header \{ cursor: move; touch-action: none;/.test(FILES[PRESENCE]));
  }
  {
    const p = page(), before = json(p.rect());
    const targets = ["tmx-guide-input", "tmx-chat-input", "tmx-chat-close", "tmx-chat-reset", "tmx-chat-msgs"];
    const moved = targets.filter(id => { const el = p.$(id); if (!el) return true; p.drag(el, -200, 100); return json(p.rect()) !== before; });
    check("C1. pressing the Guide input, the Oracle input, Close, Reset or the messages and moving 200px moves nothing", moved.length === 0 && p.stored() === null, moved.join(","));
    const t = p.$("tmx-chat-title"), r = p.rect();
    p.ptr("pointerdown", t, r.left + 40, r.top + 12); p.ptr("pointermove", t, r.left + 43, r.top + 15); p.ptr("pointerup", t, r.left + 43, r.top + 15);
    check("C1. a press that travels under the 6px threshold moves nothing and saves nothing", json(p.rect()) === before && p.stored() === null, json(p.rect()));
  }

  console.log("\n══ C2. always fully on screen ══");
  {
    const p = page();
    p.drag(p.$("tmx-chat-title"), -5000, -5000);
    check("C2. dragged far up and left, it stops at the top-left edge (0, 0)", at(p.rect(), 0, 0), json(p.rect()));
    p.drag(p.$("tmx-chat-title"), 9000, 9000);
    check("C2. dragged far down and right, it stops at the bottom-right edge (992, 460)", at(p.rect(), 1280 - CHAT_W, 800 - CHAT_H), json(p.rect()));
    check("C2. ... and the spot saved is the clamped one", JSON.stringify(p.stored()) === JSON.stringify({ left: 992, top: 460 }), JSON.stringify(p.stored()));
  }
  {
    const p = page({ store: { tmx_chat_pos: JSON.stringify({ left: 5000, top: -300 }) } });
    check("C2. on load, a stored spot off screen is clamped on screen (992, 0)", at(p.rect(), 992, 0), json(p.rect()));
    const q = page({ h: 500 });
    check("C2. on load with nothing stored, a default corner that runs off a short window (500px) is pulled on screen (top 160)",
      at(q.rect(), DEF.left, 500 - CHAT_H) && onScreen(q.rect(), 1280, 500) && q.stored() === null, json(q.rect()));
  }
  {
    const p = page({ store: { tmx_chat_pos: JSON.stringify({ left: 900, top: 400 }) } });
    check("C2. a stored spot on screen is used as it is (900, 400)", at(p.rect(), 900, 400), json(p.rect()));
    p.resize(1000, 600);
    check("C2. after a resize to 1000 × 600 it is clamped back on screen (712, 260)", at(p.rect(), 712, 260) && onScreen(p.rect(), 1000, 600), json(p.rect()));
    p.resize(1400, 900);
    check("C2. ... and a resize back up returns it to the spot that was saved (900, 400)", at(p.rect(), 900, 400), json(p.rect()));
  }

  console.log("\n══ C3. remembered on this device; reset returns the default ══");
  let saved = null;
  {
    const p = page();
    p.drag(p.$("tmx-chat-title"), -400, 120);
    saved = p.stored();
    check("C3. releasing a drag saves the spot under tmx_chat_pos", JSON.stringify(saved) === JSON.stringify({ left: DEF.left - 400, top: DEF.top + 120 }), JSON.stringify(saved));
    const q = page({ store: { tmx_chat_pos: JSON.stringify(saved) } });
    check("C3. the next page load puts it back there", at(q.rect(), DEF.left - 400, DEF.top + 120), json(q.rect()));
    q.$("tmx-chat-reset").dispatchEvent(new q.w.MouseEvent("click", { bubbles: true, cancelable: true }));
    check("C3. the reset button returns it to the default corner and forgets the spot", at(q.rect(), DEF.left, DEF.top) && q.inline(q.$("tmx-chat")).left === "" &&
      q.inline(q.$("tmx-chat-glow-wrap")).left === "" && q.stored() === null, json(q.rect()) + " " + JSON.stringify(q.stored()));
    check("C3. ... and Close is still the header's last button, with Reset just before it", q.$("tmx-chat-reset").nextElementSibling === q.$("tmx-chat-close"));
  }
  {
    const p = page({ store: { tmx_chat_pos: JSON.stringify({ left: 100, top: 100 }) } });
    p.$("tmx-chat-header").dispatchEvent(new p.w.MouseEvent("dblclick", { bubbles: true, cancelable: true }));
    check("C3. a double-click on the header returns it to the default corner and forgets the spot", at(p.rect(), DEF.left, DEF.top) && p.stored() === null, json(p.rect()));
    const q = page({ store: { tmx_chat_pos: JSON.stringify({ left: 100, top: 100 }) } });
    q.$("tmx-chat-close").dispatchEvent(new q.w.MouseEvent("dblclick", { bubbles: true, cancelable: true }));
    check("C3. ... but a double-click on Close does not", at(q.rect(), 100, 100) && q.stored() !== null, json(q.rect()));
  }
  {
    const p = page({ corner: "bottom-left", store: { tmx_chat_pos: JSON.stringify({ left: 300, top: 50 }) } });
    p.$("tmx-chat-reset").dispatchEvent(new p.w.MouseEvent("click", { bubbles: true, cancelable: true }));
    const BL = CORNERS["bottom-left"] || {};
    check("C3. reset honours the corner chosen in Settings (bottom-left)", at(p.rect(), px(BL.chat, "left"), 800 - px(BL.chat, "bottom") - CHAT_H), json(p.rect()));
  }

  console.log("\n══ C4. tmx_chat_pos is a device preference, kept at sign-out ══");
  {
    check("C4. the script's key is tmx_chat_pos", /\n  var TMX_CHAT_POS_KEY    = "tmx_chat_pos";\n/.test(FILES[PRESENCE]));
    const S = FILES[SESSION];
    const a = S.indexOf("LEFT ON PURPOSE"), b = S.indexOf("fails on any storage key", a);
    const keptBlock = a === -1 || b === -1 ? "" : S.slice(a, b);
    check("C4. bf-session.js's LEFT ON PURPOSE (KEPT) list names tmx_chat_pos", /\btmx_chat_pos\b/.test(keptBlock), keptBlock.slice(0, 200));
    check("C4. ... and not as a per-member key cleared at sign-out", !/"tmx_chat_pos"/.test(S));
    const O = FILES[OFFLINE_CHECK];
    const k0 = O.indexOf("    const KEPT = {\n"), k1 = O.indexOf("\n    };\n", k0);
    check("C4. checkOfflineMode's storage-key inventory lists it in KEPT", k0 !== -1 && /\n      tmx_chat_pos: "[^"]+",/.test(O.slice(k0, k1)), O.slice(k0, k0 + 80));
    const m = new Map([["tmx_chat_pos", "{\"left\":1,\"top\":2}"], ["bf_token", "t"]]);
    const ls = { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), key: i => [...m.keys()][i] || null, get length() { return m.size; } };
    const ss = { getItem: () => null, setItem() {}, removeItem() {}, key: () => null, length: 0 };
    const ctx = { localStorage: ls, sessionStorage: ss, console, document: { currentScript: { hasAttribute: n => n === "data-clear-only" } }, indexedDB: { deleteDatabase() {} } };
    ctx.window = ctx;
    try { vm.createContext(ctx); vm.runInContext(FILES[SESSION], ctx); ctx.BFSession.clearDevice(); } catch (e) { m.set("err", e.message); }
    check("C4. clearDevice() signs the member out and leaves tmx_chat_pos where it was", !m.has("bf_token") && m.get("tmx_chat_pos") === "{\"left\":1,\"top\":2}" && !m.has("err"), [...m.keys()].join(","));
  }

  console.log("\n══ C5. 860px and below: no dragging, the phone layout unchanged ══");
  {
    const p = page({ w: 860, store: { tmx_chat_pos: JSON.stringify({ left: 100, top: 100 }) } });
    const chatInline = p.inline(p.$("tmx-chat"));
    check("C5. at 860px the stored spot is not applied: the box keeps its corner, with no inline position", chatInline.left === "" && chatInline.top === "" && chatInline.right === "",
      JSON.stringify(chatInline));
    const before = json(p.rect());
    p.drag(p.$("tmx-chat-title"), -300, 100);
    check("C5. ... a header drag moves nothing and saves nothing", json(p.rect()) === before && JSON.stringify(p.stored()) === JSON.stringify({ left: 100, top: 100 }), json(p.rect()));
    p.key(p.$("tmx-chat-header"), "ArrowLeft");
    check("C5. ... the arrow keys move nothing, and the header is not a tab stop", json(p.rect()) === before && !p.$("tmx-chat-header").hasAttribute("tabindex"));
    check("C5. ... the reset button is hidden at 860px and below", /"@media \(max-width: 860px\) \{ #tmx-chat-reset \{ display: none; \} \}",/.test(FILES[PRESENCE]));
    p.resize(1280, 800);
    check("C5. widening past 860px applies the stored spot (100, 100) and makes the header focusable", at(p.rect(), 100, 100) && p.$("tmx-chat-header").getAttribute("tabindex") === "0", json(p.rect()));
    p.resize(800, 800);
    check("C5. narrowing to 800px returns it to the corner, the stored spot kept for next time",
      p.inline(p.$("tmx-chat")).left === "" && p.inline(p.$("tmx-chat-glow-wrap")).left === "" && JSON.stringify(p.stored()) === JSON.stringify({ left: 100, top: 100 }), JSON.stringify(p.inline(p.$("tmx-chat"))));
  }

  console.log("\n══ C6. keyboard: focusable header, arrow keys nudge ══");
  {
    const p = page({ store: { tmx_chat_pos: JSON.stringify({ left: 500, top: 300 }) } });
    const h = p.$("tmx-chat-header");
    h.focus();
    check("C6. the header is a tab stop with a label that says how to move it", h.getAttribute("tabindex") === "0" && p.doc.activeElement === h && /arrow keys/.test(h.getAttribute("aria-label") || ""));
    p.key(h, "ArrowRight"); p.key(h, "ArrowDown");
    check("C6. ArrowRight then ArrowDown move it 10px each, and the spot is saved", at(p.rect(), 510, 310) && JSON.stringify(p.stored()) === JSON.stringify({ left: 510, top: 310 }), json(p.rect()));
    p.key(h, "ArrowLeft", true); p.key(h, "ArrowUp", true);
    check("C6. Shift+ArrowLeft and Shift+ArrowUp move it 40px", at(p.rect(), 470, 270), json(p.rect()));
    for (let i = 0; i < 40; i++) p.key(h, "ArrowUp", true);
    check("C6. the arrow keys cannot push it off screen", at(p.rect(), 470, 0), json(p.rect()));
    p.key(p.$("tmx-chat-close"), "ArrowRight"); p.key(p.$("tmx-chat-reset"), "ArrowRight");
    check("C6. arrow keys pressed on Close or Reset move nothing", at(p.rect(), 470, 0), json(p.rect()));
    p.key(h, "Home");
    check("C6. Home returns it to the default corner and forgets the spot", at(p.rect(), DEF.left, DEF.top) && p.stored() === null, json(p.rect()));
  }

  console.log("\n══ C7. the mist's own drag is unchanged ══");
  {
    const p = page(), root = p.$("tmx-presence-root"), r0 = root.getBoundingClientRect();
    p.ptr("pointerdown", root, r0.left + 50, r0.top + 50); p.ptr("pointermove", root, r0.left + 5050, r0.top + 5050); p.ptr("pointerup", root, r0.left + 5050, r0.top + 5050);
    const r = root.style;
    check("C7. the mist dragged far down and right still stops at its own size from the edge (1170, 690)", r.left === (1280 - MIST_W) + "px" && r.top === (800 - MIST_H) + "px", r.left + " " + r.top);
    check("C7. ... and the chat box did not move with it", at(p.rect(), DEF.left, DEF.top) && p.stored() === null, json(p.rect()));
    check("C7. the chat box is clamped by the mist's own function (_tmxClampPosition), passed the box", (FILES[PRESENCE].match(/_tmxClampPosition\([^)]*, chat\)/g) || []).length >= 3 &&
      /\n  function _tmxClampPosition\(left, top, el\) \{\n    el = el \|\| root;\n/.test(FILES[PRESENCE]));
  }

  console.log("\n" + (failures === 0 ? "ALL CHECKS PASSED (" + passes + ")" : "CHECKS FAILED: " + failures + " failing, " + passes + " passing"));
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => { console.log("    FAIL  harness crashed: " + (e && e.stack || e)); process.exit(1); });
