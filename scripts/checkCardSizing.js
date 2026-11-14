#!/usr/bin/env node
/* checkCardSizing.js — NAMED (Nov 13 2026, Q5b): business-card sizing with no scroll, inline panels, a balanced
   sign-in page, "Create Your Own" to Create Account, and the Wallet button's condition.

   C. card-view.html (also served as /c/<slug> through lib/cardShell.generated.js):
      both orientations are business cards: 1.75 : 1 lying down, width min(560px, 92vw, the free height x 1.75);
      1 : 1.75 standing up, height min(560px, the free height, 92vw x 1.75). The free height is the screen less
      --cv-reserve, which fitCard() measures (everything but the card), so the card, its buttons and the footer fit
      with no scrollbar. The buttons are in the flow under the card; Support and the lead form open inline under
      the buttons. jsdom applies the stylesheet (no layout): positions, ratios and order are read here, the
      geometry at six screen sizes in scripts/browserCheckCardMaker.js.
   P. digital-cards.html: the maker's preview has the same ratios and caps.
   A. app.html: one centred column, two from 1024px; the plan, the renewal line and Start Subscription as three
      blocks with a gap; the checkbox a checkbox; the footer at the bottom of a column body; every field id and name
      as before; the renewal line's markup exact and its words the server's, word for word; #create and
      ?tab=create open Create Account, anything else Sign In. Geometry in scripts/browserCheckSignIn.js.
   L. "Create Your Own" goes to app.html#create, as do the home page's Get Started and suppressed.html's
      Create your account. W. the Wallet button: google_wallet true, and not an iPhone or iPad.

   No network, no database. BIZFORCE_FRONTEND_DIR overrides the frontend. MUTATE=<name> | all. */
const fs = require("fs");
const path = require("path");
const s = require("./_shared");

const REPO = path.join(__dirname, "..");
const FRONTEND = process.env.BIZFORCE_FRONTEND_DIR || path.join(REPO, "..", "BizForce-fronyend");
const MUTATE = process.env.MUTATE || "";
const CV = "card-view.html", DC = "digital-cards.html", APP = "app.html", IDX = "index.html", SUP = "suppressed.html", RC = "scripts/bf-renew-consent.js";
const SHELL = "lib/cardShell.generated.js";

const MUTATIONS = {
  // the upright card fills the screen again
  "vertical-full-height-back": [[CV, "    #cardViewport.cv-vertical #cardPreview{position:relative;inset:auto;aspect-ratio:1 / 1.75;flex:none}",
    "    #cardViewport.cv-vertical #cardPreview{position:absolute;inset:0;width:100%;height:100%;flex:none}"]],
  // a card that is not 1.75 : 1
  "card-ratio-wrong": [[CV, "      width:var(--cv-w);height:calc(var(--cv-w) / 1.75);", "      width:var(--cv-w);height:calc(var(--cv-w) / 1.5);"]],
  // the buttons over the card's art again
  "buttons-over-card": [[CV, "    .card-actions{position:relative;bottom:auto;left:auto;right:auto;padding:0;background:none;flex-wrap:wrap;width:min(560px,92vw);flex:none}",
    "    .card-actions{position:absolute;bottom:0;left:0;right:0;padding:0;background:none;flex-wrap:wrap;width:min(560px,92vw);flex:none}"]],
  // Support and the lead form as overlays near the bottom again
  "panels-as-overlay": [[CV, "    #cvSupport,#cvLead{position:static;width:min(560px,92vw);", "    #cvSupport,#cvLead{position:absolute;left:12px;right:12px;bottom:92px;width:min(560px,92vw);"]],
  // the sign-in page jammed left again
  "signin-panel-left-jammed": [[APP, "      max-width: 1080px;\n      margin: 0 auto;\n      display: grid;", "      max-width: 1080px;\n      margin: 0;\n      display: grid;"]],
  // the renewal line runs into Start Subscription
  "consent-overlaps-button": [[APP, "      flex-direction: column;\n      gap: 14px;\n      margin: 18px 26px 0;", "      flex-direction: column;\n      gap: 0;\n      margin: 18px 26px 0;"]],
  // the body is a row again: the footer floats beside the panel
  "footer-floats": [[APP, "      flex-direction: column;\n      align-items: stretch;\n      justify-content: flex-start;\n      padding: 24px;", "      align-items: center;\n      justify-content: center;\n      padding: 24px;"]],
  // "Create Your Own" back to the sign-in default
  "create-link-to-signin": [[CV, "href=\"https://bizforceai.net/app.html#create\"", "href=\"https://bizforceai.net/app.html\""]],
  // the renewal line carries words of its own
  "consent-wording-changed": [[APP, "<span data-bf-renew-consent-text></span></label>", "<span data-bf-renew-consent-text>I agree to automatic renewal.</span></label>"]],
  // a field id renamed
  "field-id-changed": [[APP, "<input id=\"rterms\" name=\"accept_terms\"", "<input id=\"rtermsBox\" name=\"accept_terms\""]],
  // extras
  "create-hash-ignored": [[APP, "  if (wantsCreate()) showRegister();\n", ""]],
  "preview-ratio-old": [[DC, "    .card-preview.orient-vertical{aspect-ratio:1/1.75;max-width:320px}", "    .card-preview.orient-vertical{aspect-ratio:9/16;max-width:390px}"]],
  "no-refit": [[CV, "    fitCard();\n    setTimeout(fitCard, 0);\n", ""]],
  "checkbox-unstyled": [[APP, ".renew-consent input[type=\"checkbox\"] { width: 18px; height: 18px; flex: 0 0 auto; margin: 2px 0 0; padding: 0; -webkit-appearance: checkbox; appearance: auto;",
    ".renew-consent input { width: 18px; height: 18px; flex: 0 0 auto; margin: 2px 0 0;"]],
  "wallet-android-only": [[CV, "c.google_wallet !== true || cvAppleMobile() || !cardRef()", "c.google_wallet !== true || !/Android/i.test(navigator.userAgent || \"\") || !cardRef()"]]
};

if (MUTATE === "all") s.runAllMutations(__filename, Object.keys(MUTATIONS));
if (MUTATE && !MUTATIONS[MUTATE]) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }

const lf = t => t.replace(/\r\n/g, "\n");
const FILES = {};
[CV, DC, APP, IDX, SUP, RC].forEach(f => {
  const p = path.join(FRONTEND, f);
  if (!fs.existsSync(p)) { console.error("Frontend file not found: " + p + " (set BIZFORCE_FRONTEND_DIR)."); process.exit(2); }
  FILES[f] = lf(fs.readFileSync(p, "utf8"));
});
FILES[SHELL] = lf(fs.readFileSync(path.join(REPO, SHELL), "utf8"));
if (MUTATE) {
  for (const [file, from, to] of MUTATIONS[MUTATE]) FILES[file] = s.replaceOnce(FILES[file], from, to, MUTATE + " in " + file);
  console.log("\n!! MUTATION: " + MUTATE + " (in memory)");
}

let JSDOM;
try { ({ JSDOM } = require("jsdom")); } catch (e) { console.log("    FAIL  jsdom could not be loaded: " + e.message); process.exit(1); }
let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined && detail !== "" ? "  [" + String(detail).slice(0, 500) + "]" : "")); }
}
const J = JSON.stringify;
const API = "https://dynamic-prosperity-production-5382.up.railway.app";
const flush = async n => { for (let i = 0; i < (n || 12); i++) await new Promise(r => setTimeout(r, 0)); };
const strip = h => h.replace(/<script\b[^>]*>[\s\S]*?<\/script>/g, "");
const inlineScripts = h => (h.match(/<script>\n?([\s\S]*?)<\/script>/g) || []).map(x => x.replace(/^<script>\n?/, "").replace(/<\/script>$/, ""));
const windows = [];
function cssRules(doc) {
  const out = [];
  for (const sh of Array.from(doc.styleSheets)) {
    let rules; try { rules = Array.from(sh.cssRules); } catch (e) { continue; }
    for (const r of rules) {
      if (r.media) for (const ir of Array.from(r.cssRules)) out.push({ media: r.media.mediaText, sel: ir.selectorText, style: ir.style });
      else if (r.selectorText) out.push({ media: "", sel: r.selectorText, style: r.style });
    }
  }
  return out;
}

/* The public card in jsdom: the markup, bf-card.js and the inline scripts against a stubbed API. */
const CARD = { slug: "jane-doe", full_name: "Jane Doe", job_title: "Founder", company: "Northwind Tea", email: "jane@example.test", phone: "+1 555 0100",
  website: "https://example.test", theme: "dark", show_email: true, show_phone: true, google_wallet: true, lead_form: true, form_token: "t", form_issued_at: "2026-11-13T00:00:00Z" };
async function runCard(ml, ua) {
  const dom = new JSDOM(strip(FILES[CV]), { url: "https://bizforceai.net/c/jane-doe", runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window; windows.push(w);
  const agent = ua || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36";
  Object.defineProperty(w.navigator, "userAgent", { get: () => agent, configurable: true });
  const errors = [];
  w.fetch = function (u) {
    const p = String(u).replace(API, "");
    const body = /^\/api\/cards\/slug\//.test(p) ? { card: Object.assign({}, CARD, { media_layout: ml }), support_links: [] } : {};
    const pr = Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body), blob: () => Promise.resolve({ type: "", size: 0 }) }); pr.catch(() => {}); return pr;
  };
  w.navigator.sendBeacon = () => true;
  w.HTMLMediaElement.prototype.load = function () {};
  w.HTMLCanvasElement.prototype.getContext = function () { return null; };
  try { w.eval(fs.readFileSync(path.join(FRONTEND, "scripts/bf-card.js"), "utf8")); } catch (e) { errors.push("bf-card: " + e.message); }
  for (const code of inlineScripts(FILES[CV])) { try { w.eval(code); } catch (e) { errors.push(e.message); } }
  await flush(30);
  return { w, d: w.document, errors };
}

(async function main() {
  /* ── C ── */
  console.log("\n══ C. the public card: a business card both ways, the buttons and panels under it, no scroll ══");
  const cv = FILES[CV];
  const H = await runCard({}), V = await runCard({ orientation: "vertical" });
  const cs = (R, id) => R.w.getComputedStyle(R.d.getElementById(id));
  check("C0. the page's scripts run in jsdom without an error, both orientations", H.errors.length === 0 && V.errors.length === 0, J([H.errors, V.errors]));
  check("C1. horizontal: the card is 1.75 : 1, width min(560px, 92vw, the free height x 1.75), height the width / 1.75",
    cs(H, "cardPreview").aspectRatio === "1.75 / 1" && cs(H, "cardPreview").position === "relative" &&
    cv.indexOf("      --cv-w:min(560px, 92vw, calc(var(--cv-avail) * 1.75));\n      width:var(--cv-w);height:calc(var(--cv-w) / 1.75);") !== -1,
    J([cs(H, "cardPreview").aspectRatio, cs(H, "cardPreview").position]));
  check("C2. vertical: 1 : 1.75, height min(560px, the free height, 92vw x 1.75), width the height / 1.75; in the flow, never the full screen",
    cs(V, "cardPreview").aspectRatio === "1 / 1.75" && cs(V, "cardPreview").position === "relative" && V.d.getElementById("cardViewport").classList.contains("cv-vertical") &&
    cv.indexOf("      --cv-h:min(560px, var(--cv-avail), calc(92vw * 1.75));\n      width:calc(var(--cv-h) / 1.75);height:var(--cv-h);") !== -1 &&
    !/height:100dvh/.test(cv) && cv.indexOf("max-width:430px") === -1, J([cs(V, "cardPreview").aspectRatio, cs(V, "cardPreview").position]));
  check("C3. the free height is the screen (100svh, 100vh where svh is unknown) less --cv-reserve",
    /:root\{--cv-reserve:200px;--cv-avail:calc\(100vh - var\(--cv-reserve\)\)\}/.test(cv) && /@supports \(height:100svh\)\{:root\{--cv-avail:calc\(100svh - var\(--cv-reserve\)\)\}\}/.test(cv));
  const fit = (cv.match(/function fitCard\(\) \{[\s\S]*?\n\}\n/) || [""])[0];
  check("C4. no scroll: fitCard() sets --cv-reserve to everything but the card (paddings, gaps, shown rows, the footer), skipping hidden panels and absolute layers",
    /if \(el === card\) \{ n\+\+; return; \}/.test(fit) && /el\.hidden \|\| s\.display === "none" \|\| s\.position === "absolute" \|\| s\.position === "fixed"/.test(fit) &&
    /footer\.bf-legal-footer/.test(fit) && /setProperty\("--cv-reserve", Math\.ceil\(sum \+ 2\) \+ "px"\)/.test(fit));
  check("C5. ...run once the card is drawn, on resize, on load, and when the buttons, the audio bar or the footer change size",
    cv.indexOf("    renderCardWallet(cardData);\n    fitCard();\n    setTimeout(fitCard, 0);\n") !== -1 && cv.indexOf("window.addEventListener(\"resize\", fitCard);") !== -1 &&
    /new ResizeObserver\(function \(\) \{ fitCard\(\); \}\)/.test(cv) && /\["cardActions", "cvAudioBar"\]/.test(cv));
  H.w.document.documentElement.style.removeProperty("--cv-reserve");
  H.w.fitCard();
  check("C6. fitCard() in the page sets a reserve in px", /^\d+px$/.test(H.w.document.documentElement.style.getPropertyValue("--cv-reserve")), H.w.document.documentElement.style.getPropertyValue("--cv-reserve"));
  check("C7. the page is a column one screen tall: the card's column grows, the footer under it, no sideways scroll",
    H.w.getComputedStyle(H.d.body).flexDirection === "column" && /min-height:100svh/.test(cv) && cs(H, "cardViewport").flexGrow === "1" && cs(H, "cardViewport").justifyContent === "center" &&
    H.w.getComputedStyle(H.d.body).overflowX === "hidden");
  const after = (R, a, b) => !!(R.d.getElementById(a).compareDocumentPosition(R.d.getElementById(b)) & 4);
  for (const [R, name] of [[H, "horizontal"], [V, "vertical"]]) {
    check("C8. " + name + ": the buttons are in the flow, directly under the card (not inside it, not over it), the audio bar between",
      cs(R, "cardActions").position === "relative" && !R.d.getElementById("cardPreview").contains(R.d.getElementById("cardActions")) && after(R, "cardPreview", "cardActions") &&
      R.d.getElementById("cvAudioBar").parentNode === R.d.getElementById("cardViewport") && after(R, "cvAudioBar", "cardActions") && cs(R, "cardActions").display === "flex",
      J([cs(R, "cardActions").position, R.d.getElementById("cvAudioBar").parentNode.id]));
    check("C9. " + name + ": Support and the lead form open inline, directly under the buttons (static, after the row), and push the footer down",
      cs(R, "cvSupport").position === "static" && cs(R, "cvLead").position === "static" && R.d.getElementById("cardActions").nextElementSibling === R.d.getElementById("cvSupport") &&
      R.d.getElementById("cvSupport").nextElementSibling === R.d.getElementById("cvLead") && R.d.getElementById("cvSupport").parentNode === R.d.getElementById("cardViewport"),
      J([cs(R, "cvSupport").position, cs(R, "cvLead").position]));
  }
  const lb = H.d.getElementById("cvLeadBtn");
  lb.click();
  check("C10. \"Leave your details\" opens the form in place (shown, static), and again closes it", H.d.getElementById("cvLead").hidden === false && cs(H, "cvLead").position === "static" &&
    (lb.click(), H.d.getElementById("cvLead").hidden === true));
  check("C11. the text, the QR and the overlays scale with the card (container units), with readable minimums",
    /#cardPreview \.card-name\{font-size:clamp\(\.95rem,6\.4cqw,2\.3rem\)/.test(cv) && /#cardPreview \.card-contact-line\{font-size:clamp\(\.6rem,2\.4cqw,\.82rem\)\}/.test(cv) &&
    /#cardPreview\.orient-vertical \.card-name\{font-size:clamp\(1rem,10cqw,2\.2rem\)\}/.test(cv) && /container-type:size;container-name:cvcard;/.test(cv) &&
    /#cardPreview #qrCanvas\{width:clamp\(36px,19cqh,64px\)!important/.test(cv) && !/calc\(env\(safe-area-inset-bottom,0px\) \+ 128px\) 28px;/.test(cv));
  check("C12. the server's card shell (/c/<slug>) is built from this page and carries the same rules",
    FILES[SHELL].indexOf("--cv-w:min(560px, 92vw, calc(var(--cv-avail) * 1.75))") !== -1 && FILES[SHELL].indexOf("function fitCard()") !== -1 &&
    FILES[SHELL].indexOf("app.html#create") !== -1);

  /* ── P ── */
  console.log("\n══ P. the maker's preview: the public card's ratios and caps ══");
  const M = new JSDOM(strip(FILES[DC]), { pretendToBeVisual: true }).window; windows.push(M);
  const mp = M.document.getElementById("cardPreview");
  const h1 = [M.getComputedStyle(mp).aspectRatio, M.getComputedStyle(mp).maxWidth];
  mp.classList.add("orient-vertical");
  const v1 = [M.getComputedStyle(mp).aspectRatio, M.getComputedStyle(mp).maxWidth];
  check("P1. the preview is 1.75 : 1 up to 560px wide, and standing up 1 : 1.75 up to 320px wide (560px tall), like the public card: " + J(h1) + ", " + J(v1),
    J(h1) === J(["1.75 / 1", "560px"]) && J(v1) === J(["1/1.75", "320px"]), J([h1, v1]));

  /* ── A ── */
  console.log("\n══ A. app.html: centred, balanced, nothing overlapping ══");
  const app = FILES[APP];
  async function runApp(url) {
    const dom = new JSDOM(strip(app), { url: url, runScripts: "outside-only", pretendToBeVisual: true });
    const w = dom.window; windows.push(w);
    const errors = [];
    w.fetch = function (u) {
      const p = String(u).replace(API, "");
      const body = /\/api\/billing\/consent/.test(p) ? { text: "SERVER WORDS: renews every month until you cancel.", version: "2026-10-01" } : {};
      const pr = Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) }); pr.catch(() => {}); return pr;
    };
    try { w.eval(FILES[RC]); } catch (e) { errors.push("bf-renew-consent: " + e.message); }
    for (const code of inlineScripts(app)) { try { w.eval(code); } catch (e) { errors.push(e.message); } }
    w.document.dispatchEvent(new w.Event("DOMContentLoaded"));
    await flush(30);
    return { w, d: w.document, errors };
  }
  const A = await runApp("https://bizforceai.net/app.html");
  const ad = A.d, acs = el => A.w.getComputedStyle(el);
  const wrap = ad.querySelector("main.wrap");
  check("A0. the page's scripts run in jsdom", A.errors.length === 0, J(A.errors));
  check("A1. the body is a column: the page centred in the screen, the legal footer at the bottom centre (not beside the panel)",
    acs(ad.body).flexDirection === "column" && acs(ad.body).alignItems === "stretch" && acs(wrap).flexGrow === "1" &&
    /body > footer\.bf-legal-footer \{\n      flex: none;\n      width: 100%;\n      margin: 24px auto 0;/.test(app) &&
    Array.from(ad.body.children).filter(e => e.tagName !== "SCRIPT").pop().tagName === "FOOTER", J([acs(ad.body).flexDirection, acs(ad.body).alignItems]));
  check("A2. the page is centred: a grid in a 1080px container with equal margins (margin 0 auto), its column centred",
    acs(wrap).display === "grid" && acs(wrap).maxWidth === "1080px" && acs(wrap).marginLeft === "auto" && acs(wrap).marginRight === "auto" && acs(wrap).justifyContent === "center",
    J([acs(wrap).display, acs(wrap).maxWidth, acs(wrap).marginLeft, acs(wrap).justifyContent]));
  const rules = cssRules(ad);
  const desk = rules.filter(r => /min-width:\s*1024px/.test(r.media));
  const dw = desk.filter(r => r.sel === ".wrap")[0];
  check("A3. one column below 1024px (the brand, then the panel); two from 1024px: the brand left, the 460px panel right",
    acs(wrap).gridTemplateColumns === "minmax(0, 460px)" && !!dw && dw.style.gridTemplateColumns === "minmax(0, 1fr) 460px" &&
    Array.from(wrap.children).map(e => e.className).join() === "brand,panel-col" && !!ad.querySelector(".panel-col > section.card") &&
    !!ad.querySelector(".panel-col > .forgot > a[href=\"/\"]") && desk.some(r => r.sel === ".brand-points" && r.style.display === "block"),
    J([acs(wrap).gridTemplateColumns, dw && dw.style.gridTemplateColumns, Array.from(wrap.children).map(e => e.className)]));
  check("A4. the brand: the logo, the wordmark, the tagline as it was, and three lines taken from this page's own copy",
    !!ad.querySelector(".brand img.brand-logo[alt=\"\"]") && ad.querySelector(".brand h1").textContent === "BizForce AI" &&
    ad.querySelector(".brand p").textContent === "Business-owner AI network for growth, automation, leads, and revenue." &&
    J(Array.from(ad.querySelectorAll(".brand-points li")).map(l => l.textContent)) === J(["One subscription covers all 18 AI business agents.",
      "Deploy AI agents for SEO, sales, content, ads, analytics, social, storefronts, PR, and R&D.", "Specialists spanning marketing, operations, and executive strategy."]) &&
    app.indexOf("One subscription covers all 18 AI business agents. Lead Radar") !== -1 && app.indexOf("Deploy AI agents for SEO, sales, content, ads, analytics, social, storefronts, PR, and R&amp;D") !== -1 &&
    app.indexOf("18 specialists in all, spanning marketing, operations, and executive strategy.") !== -1);
  const sub = ad.querySelector(".subscribe");
  check("A5. the plan, the renewal line and Start Subscription are three blocks in one column with a 14px gap: nothing overlaps",
    !!sub && acs(sub).display === "flex" && acs(sub).flexDirection === "column" &&
    app.indexOf(".subscribe {\n      display: flex;\n      flex-direction: column;\n      gap: 14px;\n      margin: 18px 26px 0;") !== -1 &&
    Array.from(sub.children).map(e => e.id || e.className).join() === "plan,renew-consent,subscribeBtn" && acs(ad.querySelector(".renew-consent")).marginTop === "0px" &&
    acs(ad.querySelector(".plan")).marginTop === "0px",
    J([sub && Array.from(sub.children).map(e => e.id || e.className)]));
  const box = ad.querySelector("[data-bf-renew-consent-box]");
  check("A6. the renewal checkbox is a checkbox (18px, no padding, its own look), aligned with its label's first line",
    acs(box).width === "18px" && acs(box).height === "18px" && acs(box).paddingLeft === "0px" && acs(box).appearance === "auto" && acs(box).marginTop === "2px",
    J([acs(box).width, acs(box).paddingLeft, acs(box).appearance]));
  check("A7. the renewal line's markup is exactly the one bf-renew-consent.js documents (no words of its own), and its words are the server's, word for word",
    app.indexOf("<label class=\"renew-consent\" data-bf-renew-consent hidden><input type=\"checkbox\" data-bf-renew-consent-box> <span data-bf-renew-consent-text></span></label>") !== -1 &&
    FILES[RC].indexOf("<label class=\"renew-consent\" data-bf-renew-consent hidden><input type=\"checkbox\" data-bf-renew-consent-box> <span data-bf-renew-consent-text></span></label>") !== -1 &&
    ad.querySelector("[data-bf-renew-consent-text]").textContent === "SERVER WORDS: renews every month until you cancel." &&
    ad.querySelector(".plan strong").textContent === "BizForce AI All Access — $199/month", ad.querySelector("[data-bf-renew-consent-text]").textContent);
  const IDS = ["loginTab", "registerTab", "loginForm", "le", "lp", "loginBtn", "passkeyBtn", "forgotBtn", "registerForm", "rb", "re", "rp", "rterms", "registerBtn", "status", "err", "subscribeBtn"];
  const NAMES = { le: "email", lp: "password", rb: "business_name", re: "register_email", rp: "register_password", rterms: "accept_terms" };
  check("A8. every field id and name is as it was", IDS.every(id => (app.match(new RegExp("id=\"" + id + "\"", "g")) || []).length === 1) &&
    Object.keys(NAMES).every(id => ad.getElementById(id) && ad.getElementById(id).getAttribute("name") === NAMES[id]), J(IDS.filter(id => !ad.getElementById(id))));
  const active = d => [d.getElementById("loginForm").classList.contains("active"), d.getElementById("registerForm").classList.contains("active"), d.getElementById("registerTab").classList.contains("active")];
  check("A9. app.html opens on Sign In", J(active(ad)) === J([true, false, false]), J(active(ad)));
  const A2 = await runApp("https://bizforceai.net/app.html#create"), A3 = await runApp("https://bizforceai.net/app.html?tab=create"), A4 = await runApp("https://bizforceai.net/app.html#signin");
  check("A10. app.html#create and ?tab=create open on Create Account; any other hash stays on Sign In",
    J(active(A2.d)) === J([false, true, true]) && J(active(A3.d)) === J([false, true, true]) && J(active(A4.d)) === J([true, false, false]), J([active(A2.d), active(A3.d), active(A4.d)]));
  const presence = lf(fs.readFileSync(path.join(FRONTEND, "scripts/termaximus-presence.js"), "utf8"));
  check("A11. the login page keeps its theme (bf-theme.js first in head) and no mist (app is in termaximus-presence.js's TMX_NO_MIST_PAGES)",
    /^<!DOCTYPE html>\n<html lang="en">\n<head>\n<script src="\/scripts\/bf-theme\.js"><\/script>/.test(app) &&
    /var TMX_NO_MIST_PAGES = \[[^\]]*"app"[^\]]*\];/.test(presence));

  /* ── L, W ── */
  console.log("\n══ L. links to Create Account; W. the Wallet button ══");
  check("L1. the public card's \"Create Your Own\" opens app.html#create", /<a class="cv-btn cv-btn-create" href="https:\/\/bizforceai\.net\/app\.html#create">/.test(cv) && cv.indexOf("digital-cards.html\">") === -1);
  check("L2. the home page's two Get Started links and suppressed.html's two Create your account links open Create Account",
    (FILES[IDX].match(/<a class="bf-btn" href="app\.html#create">Get Started<\/a>/g) || []).length === 2 &&
    (FILES[SUP].match(/<a class="bf-btn" href="\/app\.html#create">Create your account<\/a>/g) || []).length === 2);
  const UA = { android: "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/130.0 Mobile Safari/537.36", iphone: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1" };
  const Wa = await runCard({}, UA.android), Wi = await runCard({}, UA.iphone);
  check("W1. the Wallet button shows with google_wallet on a desktop and on Android, never on an iPhone",
    H.d.getElementById("cvWalletBtn").hidden === false && Wa.d.getElementById("cvWalletBtn").hidden === false && Wi.d.getElementById("cvWalletBtn").hidden === true,
    J([H.d.getElementById("cvWalletBtn").hidden, Wa.d.getElementById("cvWalletBtn").hidden, Wi.d.getElementById("cvWalletBtn").hidden]));

  windows.forEach(w => { try { w.close(); } catch (e) {} });
  console.log("\n" + passes + " passed, " + failures + " failed");
  process.exit(failures ? 1 : 0);
})().catch(e => { console.log("    FAIL  the check crashed: " + (e && e.stack || e)); process.exit(1); });
