"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkCardEditorTabs — the Digital Card maker's optional QR code and its
   editing options in compact tabs (Nov 11 2026, card QR optional, editor tabs).

   Frontend "Card maker: QR switch, corner and generator; editing options in
   compact tabs" made the card's own QR code optional and off by default
   (media_layout.show_qr, qr_corner), added a QR Code tab with a generator, and
   moved the editing options under the theme into five scripts/bf-tabs.js tabs
   (Text, Frame, Background, Motion, QR Code). The left Card Details panel, the
   preview, the theme swatches and everything from Save Card down stay outside.

   THE PAGES RUN IN JSDOM with their own scripts (bf-card.js, bf-tabs.js, the
   page's own), QRCode / html2canvas / jsPDF stubbed and recorded, every
   request answered 500 (the public card's own fetch answered with a stubbed
   card). No network. lib/cardPage.js is required as the server runs it.

     S1  storage: show_qr is a boolean and qr_corner one of the four corners,
         server-side (sanitizeMediaLayout); anything else is dropped; a new
         card (POST) starts with media_layout {}, so no show_qr: off;
     S2  the editor: off by default (the preview, getFields, the switch);
         a missing show_qr, or anything but true, is off; true is on;
     S3  off means no QR anywhere: none drawn, the QR block, its "Scan to
         connect" label and the video QR not displayed, and the PNG, print
         file and shared image (html2canvas snapshots of the preview) taken
         with none; the public card the same, and its og:image is never a QR;
     S4  on: drawn in the chosen corner, in the editor and on the public card;
     S5  the generator: the card's own link when empty, an http or https link
         typed, nothing else (javascript:, data:, ftp:, spaces); PNG and SVG
         downloads made in the browser with no request;
     T1  every editing control in exactly one tab, the briefed one, with its
         markup (id, handler, value) as it was at PRE (output for output);
     T2  the left panel, preview, swatches, action row, bleed guides, status,
         support link, Visits and Leads outside the tabs and never hidden;
     T3  ARIA tablist / tab / tabpanel, arrows, Home and End; #ed-<tab>;
         sessionStorage bf_card_ed_tab (no localStorage); default Text;
         hidden truly hides; the row scrolls sideways; the pills are smaller;
     T4  the preview keeps updating whichever tab is open.

   MUTATE=<name> edits the files IN MEMORY. MUTATE=all runs each in its own
   process and passes only if every one fails at least one check.
   BIZFORCE_FRONTEND_DIR overrides the frontend location.
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
// The frontend commit before this change (the even orbit sky).
const PRE = "080740d";

const DC = "digital-cards.html", CV = "card-view.html", TABS_JS = "scripts/bf-tabs.js", BFCARD = "scripts/bf-card.js";
const CPL_PATH = path.join(REPO, "lib", "cardPage.js");

const MUTATIONS = {
  // the card's QR on by default (S2)
  "qr-default-on": [[DC, "var showQr = false;\n", "var showQr = true;\n"]],
  // a saved card without show_qr read as on (S2)
  "missing-means-on": [[DC, "  showQr = qml.show_qr === true;\n", "  showQr = qml.show_qr !== false;\n"]],
  // the public card draws its QR whatever the owner chose (S3)
  "qr-on-public-when-off": [[CV, "  var on = ml.show_qr === true;\n", "  var on = true;\n"]],
  // the PNG taken with the QR shown though it is off (S3)
  "qr-in-png-when-off": [[DC, "    var canvas = await html2canvas(el, { scale: 3, useCORS: true, allowTaint: false });\n    var link = document.createElement(\"a\");\n",
    "    el.classList.remove(\"qr-off\");\n    var canvas = await html2canvas(el, { scale: 3, useCORS: true, allowTaint: false });\n    var link = document.createElement(\"a\");\n"]],
  // the print file taken with the QR shown though it is off (S3)
  "qr-in-print-when-off": [[DC, "    /* Render at 3x (", "    el.classList.remove(\"qr-off\");\n    /* Render at 3x ("]],
  // the "Scan to connect" label left on the card when the QR is off (S3)
  "scan-label-left": [[DC, "              <canvas id=\"qrCanvas\" width=\"90\" height=\"90\"></canvas>\n            </div>\n            <div class=\"card-qr-label\">Scan to connect</div>\n          </div>\n",
    "              <canvas id=\"qrCanvas\" width=\"90\" height=\"90\"></canvas>\n            </div>\n          </div>\n          <div class=\"card-qr-label\">Scan to connect</div>\n"]],
  // the corner choice ignored (S4)
  "corner-ignored": [[DC, "  qrCorner = QR_CORNERS.indexOf(c) !== -1 ? c : \"bottom-right\";\n", "  qrCorner = \"bottom-right\";\n"]],
  // the generator takes any scheme (S5)
  "generator-accepts-javascript-url": [[DC, "  return (u.protocol === \"http:\" || u.protocol === \"https:\") && !!u.hostname;\n", "  return !!u.protocol;\n"]],
  // the generator asks a web service for the image (S5)
  "generator-calls-network": [[DC, "  var t = drawQrGenerator();\n  if (!t.url) return;\n",
    "  var t = drawQrGenerator();\n  if (!t.url) return;\n  fetch(\"https://api.qrserver.com/v1/create-qr-code/?data=\" + encodeURIComponent(t.url));\n"]],
  // a control left out of the tabs (T1)
  "control-lost": [[DC, "            <div class=\"cust-lbl\">Background Overlay <span class=\"cust-val-badge\" id=\"bgOverlayVal\">0%</span></div>\n            <input type=\"range\" class=\"media-ctrl-sl\" style=\"width:100%;margin-top:2px\" id=\"bgOverlaySlider\" min=\"0\" max=\"100\" value=\"0\" oninput=\"applyBgOverlay(+this.value)\">\n", ""]],
  // a control's id changed in the move (T1)
  "control-id-changed": [[DC, "id=\"cardAccentColorInp\"", "id=\"cardAccentColorInput\""]],
  // the action row moved into a tab (T2)
  "action-row-in-tab": [[DC, "\n        </div>\n      </div>\n      <hr class=\"cust-divider\">\n\n      <div class=\"action-row\">", "\n      <div class=\"action-row\">"],
    [DC, "      </div>\n      <div id=\"supportOwnLink\"", "      </div>\n        </div>\n      </div>\n      <hr class=\"cust-divider\">\n      <div id=\"supportOwnLink\""]],
  // a page rule that shows every panel whatever hidden says (T3)
  "hidden-overridden": [[DC, "    #cardEdTabs .ed-panel[hidden]{display:none!important}\n", "    #cardEdTabs .ed-panel{display:flex!important}\n"]],
  // the tab not remembered (T3)
  "tab-not-remembered": [[DC, "    storage: { kind: \"session\", key: \"bf_card_ed_tab\" },\n", "    storage: { kind: \"session\", key: \"bf_card_ed_tab_\" + Math.random() },\n"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
function file(f) {
  if (FILES[f] === undefined) {
    const p = path.join(FRONTEND, f);
    if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(2); }
    FILES[f] = lf(fs.readFileSync(p, "utf8"));
  }
  return FILES[f];
}
[DC, CV, TABS_JS, BFCARD].forEach(file);
if (MUTATE) {
  for (const [f, from, to] of MUTATIONS[MUTATE]) FILES[f] = s.replaceOnce(file(f), from, to, MUTATE + " in " + f);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}
const gitShow = f => lf(execFileSync("git", ["show", PRE + ":" + f], { cwd: FRONTEND, maxBuffer: 1 << 27 }).toString("utf8"));
const CPL = require(CPL_PATH);
const SERVER = lf(fs.readFileSync(path.join(REPO, "server.js"), "utf8"));

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 500) + "]" : "")); }
}
process.on("unhandledRejection", e => check("no page request is left unhandled", false, (e && e.message) || e));
const J = JSON.stringify;

const SKIP = /bf-theme|bf-session|bf-offline|termaximus|bf-legal-footer|bf-paywall|media-picker|^https?:/;
function scripts(raw) {
  const out = [], re = /<script(?:\s+src="([^"]+)")?[^>]*>([\s\S]*?)<\/script>/g; let m;
  while ((m = re.exec(raw))) {
    if (m[1]) { if (SKIP.test(m[1])) continue; out.push({ src: m[1].charAt(0) === "/" ? m[1].slice(1) : m[1] }); }
    else out.push({ code: m[2] });
  }
  return out;
}
const settle = ms => new Promise(r => setTimeout(r, ms || 40));

/* A page, mounted with its own scripts and recorded stubs.
   o.hash, o.session, o.card (the public card's answer), o.path (the address), o.files */
async function mount(page, o) {
  o = o || {};
  const files = Object.assign({}, FILES, o.files || {});
  const raw = files[page];
  const url = "https://bizforceai.net/" + (o.path || page) + (o.hash || "");
  const dom = new JSDOM(raw.replace(/<script[\s\S]*?<\/script>/g, ""), { url, runScripts: "dangerously", pretendToBeVisual: true }); // inline onclick / oninput run; the page's script tags are stripped and run below
  const w = dom.window;
  const log = { qr: [], dataUrls: [], svgs: [], snaps: [], fetches: [], xhr: [], downloads: [], images: [] };
  try { w.localStorage.setItem("bf_token", "check-token"); } catch (e) { /* none */ }
  try { Object.keys(o.session || {}).forEach(k => w.sessionStorage.setItem(k, o.session[k])); } catch (e) { /* none */ }
  w.fetch = (u, init) => {
    log.fetches.push(String(u));
    let r = null;
    if (o.card && /\/api\/cards\/(slug|share)\//.test(String(u))) r = { ok: true, status: 200, json: () => Promise.resolve({ card: o.card, support_links: [] }) };
    const p = Promise.resolve(r || { ok: false, status: 500, json: () => Promise.resolve({ error: "check" }), blob: () => Promise.resolve({ type: "", size: 0 }) });
    p.catch(() => {});
    return p;
  };
  const XO = w.XMLHttpRequest.prototype.open;
  w.XMLHttpRequest.prototype.open = function (m, u) { log.xhr.push(String(u)); return XO.apply(this, arguments); };
  w.XMLHttpRequest.prototype.send = function () { /* nothing leaves */ };
  const img = Object.getOwnPropertyDescriptor(w.HTMLImageElement.prototype, "src");
  Object.defineProperty(w.HTMLImageElement.prototype, "src", { configurable: true, get() { return img.get.call(this); }, set(v) { log.images.push(String(v)); img.set.call(this, v); } });
  w.QRCode = {
    toCanvas(canvas, text, opts, cb) { log.qr.push({ id: canvas && canvas.id, text: String(text), width: opts && opts.width }); if (canvas) canvas.setAttribute("data-drawn", String(text)); if (cb) cb(null); },
    toDataURL(text, opts, cb) { log.dataUrls.push({ text: String(text), width: opts && opts.width }); cb(null, "data:image/png;base64,QUJD"); },
    toString(text, opts, cb) { log.svgs.push({ text: String(text), type: opts && opts.type }); cb(null, "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"); }
  };
  w.html2canvas = async el => {
    const d = w.document;
    log.snaps.push({ el: el && el.id, qrShown: visible(w, d.getElementById("cardQrBlock")), labelShown: visible(w, d.querySelector("#cardPreview .card-qr-label")),
      videoQrShown: visible(w, d.getElementById("cardVideoQR")), qrDrawn: !!(d.getElementById("qrCanvas") || { getAttribute() { return null; } }).getAttribute("data-drawn") });
    throw new Error("check: snapshot recorded");
  };
  w.jspdf = { jsPDF: function () { throw new Error("check"); } };
  // jsdom has no canvas: a 2D context whose drawing calls do nothing.
  const ctx2d = new Proxy({}, { get: (t, k) => (k in t ? t[k] : () => {}), set: (t, k, v) => { t[k] = v; return true; } });
  w.HTMLCanvasElement.prototype.getContext = function () { return ctx2d; };
  w.URL.createObjectURL = b => { log.blob = b; return "blob:check"; };
  w.URL.revokeObjectURL = () => {};
  w.HTMLAnchorElement.prototype.click = function () { if (this.download) log.downloads.push({ name: this.download, href: this.href }); };
  w.HTMLElement.prototype.scrollIntoView = function () {};
  w.console.error = () => {}; w.console.warn = () => {};
  w.alert = () => {};
  const errors = [];
  for (const sc of scripts(raw)) {
    try {
      if (sc.code !== undefined) { w.eval(sc.code); continue; }
      const code = files[sc.src] !== undefined ? files[sc.src] : (fs.existsSync(path.join(FRONTEND, sc.src)) ? lf(fs.readFileSync(path.join(FRONTEND, sc.src), "utf8")) : null);
      if (code !== null) w.eval(code);
    } catch (e) { errors.push((sc.src || "inline") + ": " + e.message); }
  }
  if (w.document.readyState === "loading") await new Promise(r => w.document.addEventListener("DOMContentLoaded", r));
  await settle(o.wait || 60);
  return { w, d: w.document, errors, log };
}
// Shown: no hidden ancestor and no ancestor with a computed display of none.
function visible(w, el) {
  if (!el) return false;
  for (let n = el; n && n.nodeType === 1; n = n.parentNode) {
    if (n.hidden) return false;
    if (w.getComputedStyle(n).display === "none") return false;
  }
  return true;
}
const inside = (node, anc) => { for (let n = node; n; n = n.parentNode) if (n === anc) return true; return false; };
const panelOf = (d, node) => { for (let n = node; n && n !== d; n = n.parentNode) if (n.getAttribute && n.getAttribute("role") === "tabpanel") return n.id.replace("edPanel-", ""); return null; };
const selected = d => { const t = d.querySelector("#cardEdTablist [role='tab'][aria-selected='true']"); return t ? t.getAttribute("data-ed-tab") : null; };
const shown = d => Array.prototype.filter.call(d.querySelectorAll("#cardEdTabs [role='tabpanel']"), p => !p.hidden).map(p => p.id.replace("edPanel-", ""));
const norm = html => html.replace(/\s+/g, " ").replace(/> </g, "><").trim();
const CORNERS = ["bottom-right", "bottom-left", "top-right", "top-left"];

// The controls and the tab each belongs in, as briefed.
const IDS = {
  text: ["cardFontSel", "customFontPicker", "fontPickerSelected", "fontPickerLabel", "fontPickerDropdown", "textEffectSel", "cardTextColorInp", "cardTextColorVal",
    "cardAccentColorInp", "cardAccentColorVal", "dividerSel"],
  frame: ["cornerSel", "borderSel_none", "textureSel"],
  background: ["bgOverlayVal", "bgOverlaySlider", "fi-still-img", "stillImgLibraryBtn", "stillImgName", "stillImgRemoveBtn", "stillImgCropControls", "stillImgZoomVal",
    "stillImgZoomSlider", "stillBgColorInp", "stillBgColorVal", "stillOverlayVal", "stillOverlaySlider", "stillTextToggle"],
  motion: ["transitionDurVal", "transitionDurSlider"],
  qr: ["qrShowToggle", "qrGenUrl", "qrGenUseCard", "qrGenNote", "qrGenCanvas", "qrGenPngBtn", "qrGenSvgBtn"]
};
IDS.frame = ["cornerSel", "textureSel"];
const ATTRS = { text: [["data-layout", 3]], frame: [["data-border", 5], ["data-bweight", 4]], background: [["data-still-mode", 3]], motion: [["data-vtrans", 10]], qr: [["data-qr-corner", 4]] };
const RESETS = { text: ["applyTextColor('')", "applyAccentColor('')"], background: ["applyStillBgColor('#000000')"] };
const OUTSIDE = ["fName", "fTitle", "fCompany", "fEmail", "fPhone", "fWebsite", "cardPreview", "cardBgColorInp", "cardBgColorVal", "saveBtn", "printExportBtn", "shareImageBtn",
  "bleedCheck", "saveStatus", "supportOwnLink", "cardStats", "cardLeads", "fDiscoverable", "fLeadForm"];

(async () => {
  /* ── S1. storage ── */
  console.log("\n══ S1. storage: show_qr a boolean, qr_corner a corner, server-side ══");
  const SAN = v => CPL.sanitizeMediaLayout(v).value;
  check("S1 lib/cardPage.js allows show_qr as a boolean and qr_corner as one of the four corners",
    J(CPL.MEDIA_LAYOUT_ALLOWLIST.show_qr) === J({ type: "boolean" }) && J(CPL.MEDIA_LAYOUT_ALLOWLIST.qr_corner) === J({ type: "enum", values: CORNERS }) && J(CPL.QR_CORNERS) === J(CORNERS));
  const bad = [{ show_qr: "true" }, { show_qr: 1 }, { show_qr: "yes" }, { show_qr: null }, { qr_corner: "center" }, { qr_corner: "BOTTOM-RIGHT" }, { qr_corner: 1 }, { qr_corner: "<script>" }];
  check("S1 a show_qr that is not a boolean, or a qr_corner that is not one of the four, is dropped", bad.every(b => J(SAN(b)) === "{}"), J(bad.map(SAN)));
  check("S1 true, false and each corner are kept as sent", J(SAN({ show_qr: true, qr_corner: "top-left" })) === J({ show_qr: true, qr_corner: "top-left" }) &&
    J(SAN({ show_qr: false })) === J({ show_qr: false }) && CORNERS.every(c => SAN({ qr_corner: c }).qr_corner === c));
  check("S1 the server sends media_layout through sanitizeMediaLayout, a new card starts with media_layout {} (no show_qr: off), and the public card gets what was saved",
    /var layout = cardPage\.sanitizeMediaLayout\(body\.media_layout\);/.test(SERVER) && /\n        media_layout: \{\},\n/.test(SERVER) && /media_layout: row\.media_layout \|\| \{\}/.test(SERVER));
  const head = q => CPL.renderCardHead(Object.assign({ full_name: "Jane Doe", job_title: "CEO", company: "Acme", slug: "jane-doe", media_layout: { show_qr: q } }, {})).join("\n");
  const ogOf = h => (/property="og:image" content="([^"]*)"/.exec(h) || [])[1] || "";
  check("S3 the public card's og:image is never a QR code, with the QR on or off", ogOf(head(false)) === ogOf(head(true)) && !/qr/i.test(ogOf(head(true))) && ogOf(head(true)) === CPL.DEFAULT_IMAGE, ogOf(head(true)));

  /* ── S2/S3. the editor, off by default ── */
  console.log("\n══ S2-S3. the editor: off by default, no QR anywhere when off ══");
  const E = await mount(DC);
  const d = E.d, w = E.w;
  check("the card maker's scripts run without an error", E.errors.length === 0, E.errors.join(" | "));
  const cp = d.getElementById("cardPreview");
  check("S2 off by default: the preview has qr-off and qr-bottom-right, the switch is unticked, getFields sends show_qr false and qr_corner bottom-right",
    cp.classList.contains("qr-off") && cp.classList.contains("qr-bottom-right") && d.getElementById("qrShowToggle").checked === false &&
    w.getFields().media_layout.show_qr === false && w.getFields().media_layout.qr_corner === "bottom-right", cp.className);
  w.activeSlug = "jane-doe";
  w.updatePreview();
  await w.generateQR();
  await settle(450);
  const cardQr = () => E.log.qr.filter(x => x.id === "qrCanvas" || x.id === "qrVideoCanvas");
  check("S3 off: no QR is drawn on the card, even once it has a link", cardQr().length === 0, J(cardQr()));
  check("S3 off: the QR block, its \"Scan to connect\" label and the video QR are not displayed",
    !visible(w, d.getElementById("cardQrBlock")) && !visible(w, d.querySelector("#cardPreview .card-qr-label")) && (cp.classList.add("video-mode"), !visible(w, d.getElementById("cardVideoQR"))) &&
    (cp.classList.remove("video-mode"), true) && d.querySelectorAll("#cardPreview .card-qr-label").length === 1);
  check("S3 off: the text column takes the card's width (no room kept for a QR)", w.getComputedStyle(d.querySelector("#cardPreview .card-left")).paddingRight === "0px");
  await w.downloadCard(); await w.exportPrintFile(); await w.shareCardImage();
  check("S3 off: the PNG, the print file and the shared image are taken of the preview with no QR and no label",
    E.log.snaps.length === 3 && E.log.snaps.every(x => x.el === "cardPreview" && !x.qrShown && !x.labelShown && !x.qrDrawn), J(E.log.snaps));
  // a saved card: missing, null, a string, false all mean off; true is on
  const fill = ml => { w.fillForm({ full_name: "Jane", theme: "dark", media_layout: ml }); return [w.getFields().media_layout.show_qr, cp.classList.contains("qr-off"), d.getElementById("qrShowToggle").checked]; };
  const offs = [undefined, null, {}, { show_qr: "true" }, { show_qr: 1 }, { show_qr: false }].map(fill);
  check("S2 a saved card with no show_qr, or anything but true, opens with the QR off", offs.every(x => J(x) === J([false, true, false])), J(offs));
  const onFill = fill({ show_qr: true, qr_corner: "top-left" });
  check("S2 a saved card with show_qr true opens with it on, in its corner", J(onFill) === J([true, false, true]) && cp.classList.contains("qr-top-left") && w.getFields().media_layout.qr_corner === "top-left", J(onFill));
  fill({ show_qr: true, qr_corner: "middle" });
  check("S2 an unknown corner is bottom-right", cp.classList.contains("qr-bottom-right") && w.getFields().media_layout.qr_corner === "bottom-right");
  fill({});

  /* ── S4. on, in the corner ── */
  console.log("\n══ S4. on: drawn, in the chosen corner ══");
  E.log.qr.length = 0; E.log.snaps.length = 0;
  d.getElementById("qrShowToggle").checked = true;
  d.getElementById("qrShowToggle").dispatchEvent(new w.Event("change", { bubbles: true }));
  await settle(20);
  check("S4 the switch on: the QR is drawn (the public link with via=qr) and shown with its label, and getFields sends show_qr true",
    cardQr().some(x => x.id === "qrCanvas" && x.text === "https://bizforceai.net/c/jane-doe?via=qr") && visible(w, d.getElementById("cardQrBlock")) &&
    visible(w, d.querySelector("#cardPreview .card-qr-label")) && w.getFields().media_layout.show_qr === true, J(cardQr()));
  const cornerSeen = CORNERS.map(c => {
    d.querySelector("[data-qr-corner='" + c + "']").click();
    const on = CORNERS.filter(k => cp.classList.contains("qr-" + k));
    return [c, J(on) === J([c]) && w.getFields().media_layout.qr_corner === c && d.querySelector("[data-qr-corner='" + c + "']").getAttribute("aria-pressed") === "true"];
  });
  check("S4 each corner button puts the card in that corner alone, and it is saved", cornerSeen.every(x => x[1]), J(cornerSeen));
  const css = (/<style>([\s\S]*?)<\/style>/.exec(FILES[DC]) || [])[1] || "";
  check("S4 the corners are drawn by CSS on the preview: top corners at the top, left corners on the left, upright cards included, and the video QR follows",
    css.indexOf(".card-preview.qr-off .card-right,.card-preview.qr-off .card-video-qr-ov{display:none!important}") !== -1 &&
    css.indexOf(".card-preview.qr-top-right:not(.orient-vertical) .card-right,.card-preview.qr-top-left:not(.orient-vertical) .card-right{justify-content:flex-start}") !== -1 &&
    css.indexOf(".card-preview.qr-bottom-left:not(.orient-vertical) .card-inner,.card-preview.qr-top-left:not(.orient-vertical) .card-inner{flex-direction:row-reverse}") !== -1 &&
    css.indexOf(".card-preview.orient-vertical.qr-top-right .card-inner,.card-preview.orient-vertical.qr-top-left .card-inner{flex-direction:column-reverse}") !== -1 &&
    css.indexOf(".card-preview.orient-vertical.qr-top-right .card-right,.card-preview.orient-vertical.qr-bottom-right .card-right{flex-direction:row-reverse}") !== -1 &&
    css.indexOf(".card-preview.qr-top-right .card-video-qr-ov,.card-preview.qr-top-left .card-video-qr-ov{bottom:auto;top:10px}") !== -1 &&
    css.indexOf(".card-preview.qr-bottom-left .card-video-qr-ov,.card-preview.qr-top-left .card-video-qr-ov{right:auto;left:10px}") !== -1);
  d.querySelector("[data-qr-corner='bottom-right']").click();
  await w.downloadCard();
  check("S4 on: the PNG is taken with the QR shown", E.log.snaps.length === 1 && E.log.snaps[0].qrShown && E.log.snaps[0].labelShown, J(E.log.snaps));
  d.getElementById("qrShowToggle").checked = false;
  d.getElementById("qrShowToggle").dispatchEvent(new w.Event("change", { bubbles: true }));
  check("S2 turning it off again is saved as show_qr false (sent on every save)", w.getFields().media_layout.show_qr === false && cp.classList.contains("qr-off"));

  /* ── S5. the generator ── */
  console.log("\n══ S5. the QR Code tab's generator ══");
  d.getElementById("edTab-qr").click();
  const gen = d.getElementById("qrGenUrl"), note = d.getElementById("qrGenNote");
  const genDraw = v => { E.log.qr.length = 0; gen.value = v; gen.dispatchEvent(new w.Event("input", { bubbles: true })); const g = E.log.qr.filter(x => x.id === "qrGenCanvas"); return { text: g.length ? g[g.length - 1].text : null, png: d.getElementById("qrGenPngBtn").disabled, note: note.textContent }; };
  const own = genDraw("");
  check("S5 empty: the card's own public link (with via=qr), drawn large, whether or not the QR is on the card",
    own.text === "https://bizforceai.net/c/jane-doe?via=qr" && own.png === false && cp.classList.contains("qr-off") && E.log.qr.some(x => x.id === "qrGenCanvas" && x.width >= 200), J(own));
  const okLinks = ["https://example.com/menu", "http://example.com/a?b=1"].map(v => [v, genDraw(v).text === v]);
  check("S5 a typed http or https link is drawn as typed", okLinks.every(x => x[1]), J(okLinks));
  const badLinks = ["javascript:alert(1)", "JAVASCRIPT:alert(1)", "data:text/html,<b>x</b>", "ftp://example.com/f", "mailto:a@example.com", "https://exa mple.com", "example.com", "https://"]
    .map(v => [v, genDraw(v)]);
  check("S5 anything else is refused: nothing drawn, the downloads off, and a note says what to type", badLinks.every(x => x[1].text === null && x[1].png === true && /http:\/\/ or https:\/\//.test(x[1].note)), J(badLinks));
  const before = E.log.fetches.length + E.log.xhr.length + E.log.images.length;
  genDraw("https://example.com/menu");
  E.log.downloads.length = 0;
  w.downloadQrGenerator("png"); w.downloadQrGenerator("svg");
  await settle(20);
  check("S5 Download QR (PNG) and (SVG): made in the browser by the QR library, saved as qr-code.png and qr-code.svg",
    J(E.log.downloads.map(x => x.name)) === J(["qr-code.png", "qr-code.svg"]) && E.log.downloads[0].href.indexOf("data:image/png") === 0 && E.log.downloads[1].href === "blob:check" &&
    E.log.dataUrls.some(x => x.text === "https://example.com/menu" && x.width >= 1000) && E.log.svgs.some(x => x.text === "https://example.com/menu" && x.type === "svg") &&
    E.log.blob && E.log.blob.type === "image/svg+xml", J([E.log.downloads, E.log.dataUrls, E.log.svgs]));
  check("S5 no request is made to draw or download a QR (no fetch, XHR or image load)", E.log.fetches.length + E.log.xhr.length + E.log.images.length === before,
    J([E.log.fetches.slice(-3), E.log.xhr, E.log.images]));
  E.log.downloads.length = 0;
  genDraw("javascript:alert(1)");
  w.downloadQrGenerator("png"); w.downloadQrGenerator("svg");
  await settle(20);
  check("S5 a refused link downloads nothing", E.log.downloads.length === 0, J(E.log.downloads));
  w.close();

  /* ── S3/S4 on the public card ── */
  console.log("\n══ S3-S4. the public card ══");
  const CARD = { id: "c1", slug: "jane-doe", full_name: "Jane Doe", job_title: "CEO", company: "Acme", email: "jane@example.com", phone: "+1 555 0100", website: "https://example.com", theme: "dark" };
  async function pub(ml) {
    const P = await mount(CV, { path: "c/jane-doe", card: Object.assign({}, CARD, ml === undefined ? {} : { media_layout: ml }), wait: 120 });
    const pd = P.d, pc = pd.getElementById("cardPreview"), block = pd.getElementById("cvQrBlock");
    const row = block && block.parentNode;
    const r = { errors: P.errors, drawn: P.log.qr.map(x => x.id + "=" + x.text), shown: visible(P.w, block), label: visible(P.w, pd.querySelector("#cvQrBlock .card-qr-label")),
      labels: pd.querySelectorAll(".card-qr-label").length, row: row ? (row.classList.contains("card-top-row") ? "top" : row.id === "cvBottomRow" ? "bottom" : "other") : null,
      left: !!(row && row.classList.contains("qr-left")), cls: CORNERS.filter(k => pc.classList.contains("qr-" + k)), off: pc.classList.contains("qr-off") };
    pd.getElementById("vidBox").style.display = "block";
    r.videoQr = visible(P.w, pd.querySelector("#vidBox .card-video-qr-ov"));
    P.w.close();
    return r;
  }
  const offCases = [undefined, null, {}, { show_qr: "true" }, { show_qr: false, qr_corner: "top-left" }];
  const offPub = [];
  for (const ml of offCases) offPub.push(await pub(ml));
  check("S3 public card, QR off (no media_layout, null, {}, \"true\", false): no QR drawn, the block, label and video QR not displayed",
    offPub.every(r => r.errors.length === 0 && r.drawn.length === 0 && !r.shown && !r.label && !r.videoQr && r.off && r.labels === 1), J(offPub));
  const onPub = {};
  for (const c of CORNERS) onPub[c] = await pub({ show_qr: true, qr_corner: c });
  const want = { "bottom-right": ["bottom", false], "bottom-left": ["bottom", true], "top-right": ["top", false], "top-left": ["top", true] };
  check("S4 public card, QR on: both codes drawn with the public link and via=qr, the block shown in the chosen corner's row and side, the video QR shown",
    CORNERS.every(c => { const r = onPub[c]; return r.errors.length === 0 && J(r.drawn) === J(["qrCanvas=https://bizforceai.net/c/jane-doe?via=qr", "qrVideoCanvas=https://bizforceai.net/c/jane-doe?via=qr"]) &&
      r.shown && r.label && r.videoQr && !r.off && r.row === want[c][0] && r.left === want[c][1] && J(r.cls) === J([c]); }), J(onPub));
  const noCorner = await pub({ show_qr: true });
  check("S4 public card, QR on with no corner saved: bottom-right", noCorner.row === "bottom" && noCorner.left === false && J(noCorner.cls) === J(["bottom-right"]), J(noCorner));
  check("S4 public card: the video QR follows the corner, and a hidden block keeps no room", FILES[CV].indexOf("#cardPreview.qr-off .card-video-qr-ov,#cardPreview.qr-off #vidBox .card-video-qr-ov{display:none!important}") !== -1 &&
    FILES[CV].indexOf("#cardPreview.qr-bottom-left .card-video-qr-ov,#cardPreview.qr-top-left .card-video-qr-ov{right:auto;left:16px}") !== -1 && /<div class="cv-qr-block" id="cvQrBlock" hidden>/.test(FILES[CV]));
  const shellOk = (() => { try { return fs.readFileSync(path.join(REPO, "lib", "cardShell.generated.js"), "utf8").indexOf("cvQrBlock") !== -1; } catch (e) { return false; } })();
  check("S3 the server's card shell (lib/cardShell.generated.js) is built from this card-view.html", shellOk);

  /* ── T1-T4. the tabs ── */
  console.log("\n══ T1-T2. every control in exactly one tab; the rest outside ══");
  const T = await mount(DC);
  const td = T.d, tw = T.w;
  const wrap = td.getElementById("cardEdTabs");
  const tabs = Array.prototype.slice.call(td.querySelectorAll("#cardEdTablist [role='tab']"));
  check("T1 the tabs are Text, Frame, Background, Motion, QR Code", J(tabs.map(t => t.textContent)) === J(["Text", "Frame", "Background", "Motion", "QR Code"]), J(tabs.map(t => t.textContent)));
  const wrongId = [];
  Object.keys(IDS).forEach(tab => IDS[tab].forEach(id => {
    const n = td.querySelectorAll("[id='" + id + "']");
    if (n.length !== 1 || panelOf(td, n[0]) !== tab) wrongId.push(id + "@" + (n.length === 1 ? panelOf(td, n[0]) : n.length + "x"));
  }));
  Object.keys(ATTRS).forEach(tab => ATTRS[tab].forEach(([a, count]) => {
    const n = Array.prototype.slice.call(td.querySelectorAll("[" + a + "]"));
    if (n.length !== count || !n.every(x => panelOf(td, x) === tab)) wrongId.push(a + "@" + n.map(x => panelOf(td, x)).join("/"));
  }));
  Object.keys(RESETS).forEach(tab => RESETS[tab].forEach(on => {
    const n = Array.prototype.filter.call(td.querySelectorAll("button"), b => b.getAttribute("onclick") === on);
    if (n.length !== 1 || panelOf(td, n[0]) !== tab) wrongId.push(on + "@" + n.map(x => panelOf(td, x)).join("/"));
  }));
  const drag = Array.prototype.filter.call(td.querySelectorAll("#cardEdTabs div"), x => x.textContent === "drag preview to reposition");
  if (drag.length !== 1 || panelOf(td, drag[0]) !== "background") wrongId.push("drag-note");
  check("T1 every control is in exactly one tab, the briefed one, and every id is on exactly one element", wrongId.length === 0, wrongId.join(", "));
  // output for output: each control of PRE's options block is here, unchanged
  const OLD = new JSDOM(gitShow(DC).replace(/<script[\s\S]*?<\/script>/g, "")).window.document;
  const oldWrap = OLD.querySelector(".cust-wrap");
  const ctl = root => Array.prototype.filter.call(root.querySelectorAll("[id],[data-layout],[data-border],[data-bweight],[data-still-mode],[data-vtrans],button,input,select"), () => true);
  const oldCtl = ctl(oldWrap).map(x => norm(x.outerHTML));
  const NEW = new JSDOM(FILES[DC].replace(/<script[\s\S]*?<\/script>/g, "")).window.document;
  const newWrap = NEW.getElementById("cardEdTabs");
  const newCtl = ctl(newWrap).filter(x => x.getAttribute("role") !== "tabpanel" && !inside(x, NEW.getElementById("edPanel-qr")) && !inside(x, NEW.getElementById("cardEdTablist"))).map(x => norm(x.outerHTML));
  const lost = oldCtl.filter(h => newCtl.indexOf(h) === -1), added = newCtl.filter(h => oldCtl.indexOf(h) === -1);
  check("T1 every control of the old options block (" + oldCtl.length + ") is in the tabs exactly as it was (id, handler, value), and the first four tabs add none",
    oldCtl.length === 58 && lost.length === 0 && added.length === 0 && newCtl.length === oldCtl.length, J({ lost: lost.slice(0, 3), added: added.slice(0, 3), old: oldCtl.length, now: newCtl.length }));
  const notIn = OUTSIDE.filter(id => { const n = td.getElementById(id); return !n || inside(n, wrap); });
  const actions = td.querySelector(".action-row"), themes = td.querySelector(".theme-selector");
  const order = (a, b) => !!(a && b && (a.compareDocumentPosition(b) & tw.Node.DOCUMENT_POSITION_FOLLOWING));
  check("T2 the left panel, preview, theme swatches with their colour and Reset, action row, bleed guides, status, support link, Visits and Leads are outside the tabs",
    notIn.length === 0 && actions && !inside(actions, wrap) && actions.querySelectorAll("button").length === 6 && themes && !inside(themes, wrap) &&
    order(themes, wrap) && order(td.getElementById("cardPreview"), wrap) && order(wrap, actions) && order(actions, td.getElementById("cardStats")), notIn.join(","));
  const always = () => OUTSIDE.concat([]).every(id => visible(tw, td.getElementById(id)) || id === "supportOwnLink") && visible(tw, actions) && visible(tw, themes);
  const alwaysSeen = ["text", "frame", "background", "motion", "qr"].map(t => { td.getElementById("edTab-" + t).click(); return [t, always()]; });
  check("T2 whichever tab is open, all of them stay shown", alwaysSeen.every(x => x[1]), J(alwaysSeen));

  console.log("\n══ T3. ARIA, keys, hashes, remembering, hidden ══");
  T.w.close();
  const A = await mount(DC);
  const ad = A.d, aw = A.w;
  const list = ad.getElementById("cardEdTablist");
  const atabs = Array.prototype.slice.call(ad.querySelectorAll("#cardEdTablist [role='tab']"));
  check("T3 one tablist in the options; each tab a button with aria-controls its tabpanel, which is aria-labelledby it",
    !!list && list.getAttribute("role") === "tablist" && ad.querySelectorAll("#cardEdTabs [role='tablist']").length === 1 && atabs.length === 5 && atabs.every(t => t.tagName === "BUTTON" && t.parentNode === list &&
      ad.getElementById(t.getAttribute("aria-controls")) && ad.getElementById(t.getAttribute("aria-controls")).getAttribute("role") === "tabpanel" &&
      ad.getElementById(t.getAttribute("aria-controls")).getAttribute("aria-labelledby") === t.id));
  check("T3 the default is Text: selected, the only panel shown, the only tab in the tab order", selected(ad) === "text" && J(shown(ad)) === J(["text"]) &&
    atabs.filter(t => t.getAttribute("tabindex") === "0").length === 1 && atabs[0].getAttribute("tabindex") === "0");
  const key = (k, from) => { const t = ad.getElementById("edTab-" + from); t.focus(); t.dispatchEvent(new aw.KeyboardEvent("keydown", { key: k, bubbles: true })); return selected(ad); };
  check("T3 Right from Text is Frame, Left from Text wraps to QR Code, End is QR Code, Home is Text, and focus follows",
    key("ArrowRight", "text") === "frame" && key("ArrowLeft", "text") === "qr" && key("End", "frame") === "qr" && key("Home", "qr") === "text" && ad.activeElement === ad.getElementById("edTab-text"), selected(ad));
  ad.getElementById("edTab-background").click();
  check("T3 pressing a tab shows its panel alone and writes #ed-background", selected(ad) === "background" && J(shown(ad)) === J(["background"]) && aw.location.hash === "#ed-background", aw.location.hash);
  check("T3 the tab is remembered in sessionStorage bf_card_ed_tab, and nothing is kept in localStorage", aw.sessionStorage.getItem("bf_card_ed_tab") === "background" &&
    Object.keys(aw.localStorage).every(k => !/bf_card_ed_tab/.test(k)), Object.keys(aw.localStorage).join(","));
  const hiddenOk = Array.prototype.every.call(ad.querySelectorAll("#cardEdTabs [role='tabpanel']"), p => (aw.getComputedStyle(p).display === "none") === (p.id !== "edPanel-background"));
  check("T3 hidden truly hides: '#cardEdTabs .ed-panel[hidden]' is display:none !important, no page rule forces a panel's display, and only the open panel is displayed",
    css.indexOf("#cardEdTabs .ed-panel[hidden]{display:none!important}") !== -1 && !/\.(ed|deck)-panel(?!\[hidden\])[^{,]*\{[^}]*display:[^;}]*!important/.test(css) &&
    FILES[TABS_JS].indexOf(".deck-panel[hidden] { display: none !important; }") !== -1 && hiddenOk);
  check("T3 the tab row scrolls sideways on a narrow screen, and its pills are smaller than the agent pages'",
    list.classList.contains("deck-tabs-scroll") && /\.ed-tabs \.deck-tab\{font-size:\.66rem;[^}]*padding:5px 10px/.test(css) && FILES[TABS_JS].indexOf("font-size: .82rem") !== -1);
  check("T3 digital-cards.html loads bf-tabs.js (no new library) and starts the tabs with BFTabs.create, #ed- hashes and the session key",
    /<script src="\/scripts\/bf-tabs\.js"><\/script>/.test(FILES[DC]) && /hash: function \(n\) \{ return "#ed-" \+ n; \},/.test(FILES[DC]) && /storage: \{ kind: "session", key: "bf_card_ed_tab" \},/.test(FILES[DC]) &&
    /fallback: "text",/.test(FILES[DC]));
  A.w.close();
  const hashes = {};
  for (const t of ["text", "frame", "background", "motion", "qr"]) { const H = await mount(DC, { hash: "#ed-" + t }); hashes[t] = selected(H.d) === t && J(shown(H.d)) === J([t]); H.w.close(); }
  check("T3 each address #ed-text, #ed-frame, #ed-background, #ed-motion, #ed-qr opens its tab", Object.values(hashes).every(Boolean), J(hashes));
  const R = await mount(DC, { session: { bf_card_ed_tab: "motion" } });
  check("T3 with no address, the remembered tab opens (Motion)", selected(R.d) === "motion" && J(shown(R.d)) === J(["motion"]), selected(R.d));
  R.w.close();
  const R2 = await mount(DC, { session: { bf_card_ed_tab: "motion" }, hash: "#ed-qr" });
  check("T3 an address beats the remembered tab", selected(R2.d) === "qr", selected(R2.d));
  R2.w.close();
  const R3 = await mount(DC, { session: { bf_card_ed_tab: "nonsense" }, hash: "#something-else" });
  check("T3 an unknown tab or address falls back to Text", selected(R3.d) === "text", selected(R3.d));
  R3.w.close();

  console.log("\n══ T4. the preview keeps updating from every tab ══");
  const U = await mount(DC);
  const ud = U.d, uw = U.w;
  const results = [];
  const fire = (el, type) => el.dispatchEvent(new uw.Event(type, { bubbles: true }));
  const nameEl = ud.getElementById("fName");
  const tabActions = {
    text: () => { ud.getElementById("textEffectSel").value = "glow"; fire(ud.getElementById("textEffectSel"), "change"); return uw.getFields().media_layout.text_effect === "glow"; },
    frame: () => { ud.querySelector("[data-border='gold']").click(); return ud.getElementById("cardPreview").classList.contains("border-gold"); },
    background: () => { const sl = ud.getElementById("bgOverlaySlider"); sl.value = "40"; fire(sl, "input"); return uw.getFields().media_layout.bg_overlay === 40 && ud.getElementById("bgOverlayVal").textContent === "40%"; },
    motion: () => { ud.querySelector("[data-vtrans='iris']").click(); return uw.getFields().media_layout.vid_transition === "iris" && ud.querySelector("[data-vtrans='iris']").classList.contains("active"); },
    qr: () => { ud.getElementById("qrShowToggle").click(); return !ud.getElementById("cardPreview").classList.contains("qr-off"); }
  };
  for (const t of Object.keys(tabActions)) {
    ud.getElementById("edTab-" + t).click();
    nameEl.value = "Name in " + t; fire(nameEl, "input");
    results.push([t, ud.getElementById("pName").textContent === "Name in " + t, tabActions[t]()]);
  }
  check("T4 with each tab open, typing a name updates the preview, and that tab's controls still work", results.every(r => r[1] && r[2]), J(results));
  U.w.close();

  console.log("");
  if (failures) { console.log("CHECKS FAILED: " + failures + " of " + (passes + failures)); process.exit(1); }
  console.log("ALL " + passes + " CHECKS PASSED");
  process.exit(0);
})().catch(e => { console.log("    FAIL  the harness stopped: " + ((e && e.stack) || e)); process.exit(1); });
