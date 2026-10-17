"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   checkSeoFdaRail — the SEO writer's supplement compliance rail also refuses
   the policy-check rulebook's fda_disease_claims group, at generation and at
   publish, except a match in a sentence that is only a caution; the writer's
   prompt says clinical markers count as conditions; and Claims Scan lists a
   caution sentence apart from its findings.

   POST /api/agents/seo/generate-post, the publish_blog_post executor and
   measureClaimsScan are lifted from server.js with everything they call and
   run in a vm against a recording stub database and a scripted model.
   TEST ROWS ARE ISOLATED BY CONSTRUCTION: no database, network or model is
   reached, nothing is read from or written to any real account, and the one
   account id used is made up.

   WHAT THIS PROVES
     A. isCautionOnlySentence: the three whole-sentence templates, with the
        60-character slot cap, and nothing added before or after them.
     B. The sentence splitter: full stop, ! and ? followed by whitespace or the
        end, line breaks, and block markup; inline markup is not a break and a
        decimal point is not one either. Offsets point into the original text.
     C. The 17 lines measured in the last report, each at generation (201 and
        filed, or 422 at stage "compliance" and stored in seo_refused_drafts)
        AND at publish (published, or thrown with nothing written). Every
        DISEASE CLAIM line is refused; F2, F3 and the low-blood-pressure line
        pass the FDA group; F6 is still refused by the profile.
     D. A refusal names fda_disease_claims as the rule, with the matched text.
     E. The six lawful structure/function phrases still pass both points.
     F. Never-exempt patterns stay caught inside a caution sentence: verb +
        marker, relief from, drug-free, protects against, prevents.
     G. Claims Scan returns F2 under caution_sentences, not findings, and its
        note says the SEO writer allows those sentences.
     H. The writer's prompt carries the clinical-marker line, right after
        "Do not name the condition at all.", and the generation prompt sent to
        the model carries it.
     I. Reuse: the FDA group is run through scanAdPolicy; the rail holds no
        disease pattern of its own; there is no repair path for it.

   MUTATE=<name> edits server.js IN MEMORY (nothing on disk is touched).
   MUTATE=all runs each in its own process; an unmatched search text is an
   ERROR, never a catch (scripts/_shared.js).
   ══════════════════════════════════════════════════════════════════════════ */

const fs = require("fs"), path = require("path"), vm = require("vm"), net = require("net"), dns = require("dns");
const REPO = path.join(__dirname, "..");
const MUTATE = process.env.MUTATE || "";
const MUT = require("./_shared");
const s = MUT;

const NETWORK = [];
net.Socket.prototype.connect = function () { NETWORK.push("socket"); throw new Error("checkSeoFdaRail: no network"); };
dns.lookup = function (host) { NETWORK.push("dns " + host); throw new Error("checkSeoFdaRail: no network"); };

const SERVER = "server.js";
const MARKER_LINE = "      \"- Name a clinical marker as something this product affects. Blood sugar, blood glucose, blood pressure, \" +\n" +
  "      \"cholesterol, LDL, HDL, triglycerides, A1c, thyroid levels and bone density count as conditions here. A caution \" +\n" +
  "      \"such as 'If you take blood pressure medication, consult your doctor before use.' is allowed as its own sentence.\\n\" +\n";
const MUTATIONS = {
  // the old unsafe rule: any caution trigger in the sentence, and no benefit verb, exempts it
  "any-caution-trigger": [[SERVER, "  return CAUTION_ONLY_SENTENCES.some(function (t) { return t.test(s); });",
    "  return /consult (your|a) (doctor|physician|healthcare (provider|professional))|talk to your doctor|if you (take|are taking|have|have been diagnosed with)|" +
    "not (recommended|intended|suitable) for|(do not|don't) use if|seek medical advice/i.test(s) && " +
    "!/\\b(help|helps|aid|support|supports|improve|promote|maintain|reduce|relieve|lower|boost|manage|combat|fight|ease|soothe|address|target|restore|sharpen|correct)\\b/i.test(s);"]],
  // publish_blog_post no longer runs the FDA group
  "no-publish-fda": [[SERVER, "complianceText, 5)\n        .concat(fdaRailViolations(complianceProfile, complianceText));", "complianceText, 5);"]],
  // generation no longer runs the FDA group
  "no-generation-fda": [[SERVER, "complianceText, 5)\n          .concat(fdaRailViolations(complianceProfile, complianceText));", "complianceText, 5);"]],
  // "relief from" can be exempted by a caution sentence
  "relief-from-exemptable": [[SERVER, "\"\\\\brelief from\\\\b\", ", ""]],
  // the clinical-marker line is gone from the writer's prompt
  "drop-marker-line": [[SERVER, MARKER_LINE, ""]]
};
if (MUTATE === "all") MUT.runAllMutations(__filename, Object.keys(MUTATIONS));

let SRC = fs.readFileSync(path.join(REPO, SERVER), "utf8").replace(/\r\n/g, "\n");
if (MUTATE) {
  const edits = MUTATIONS[MUTATE];
  if (!edits) { console.error("Unknown MUTATE=" + MUTATE + ". Known: all, " + Object.keys(MUTATIONS).join(", ")); process.exit(2); }
  for (const [, from, to] of edits) SRC = MUT.replaceOnce(SRC, from, to, MUTATE + " in " + SERVER);
  console.log("\n!! MUTATION: " + MUTATE);
}

let passes = 0, failures = 0;
function check(label, ok, detail) {
  if (ok) { passes++; console.log("    pass  " + label); }
  else { failures++; console.log("    FAIL  " + label + (detail !== undefined ? "  [" + String(detail).slice(0, 400) + "]" : "")); }
}

/* ── lifting ──────────────────────────────────────────────────────────────── */
const STUBS = new Set([...s.STUBS].filter(n => n !== "COMPLIANCE_PROFILES" && n !== "COMPLIANCE_DISCLAIMER").concat(["OWNER_ACCOUNT_ID"]));
const SPANS = [];
{
  const re = /^(?:(?:async )?function [A-Za-z_$][A-Za-z0-9_$]*[(]|app[.][a-z]+[(])/gm; let m;
  while ((m = re.exec(SRC))) { const end = s.braceMatch(SRC, SRC.indexOf("{", m.index)); if (end > 0) SPANS.push([m.index, end]); }
}
function definitionOf(name) {
  let m = new RegExp("^(?:async )?function " + name + "\\(", "m").exec(SRC);
  if (m) return SRC.slice(m.index, s.braceMatch(SRC, SRC.indexOf(") {", m.index) + 2));
  const re = new RegExp("^(?:var|const|let) " + name + "[ \t]*=[ \t]*", "gm");
  while ((m = re.exec(SRC)) && SPANS.some(([x, y]) => m.index > x && m.index < y)) { /* a local */ }
  if (!m) return null;
  const brk = /;\n/g; brk.lastIndex = m.index + m[0].length;
  let b;
  while ((b = brk.exec(SRC))) {
    const next = SRC[b.index + b[0].length];
    if (next === undefined || next === "\n" || /[^\s]/.test(next)) return SRC.slice(m.index, b.index + 1);
  }
  return null;
}
const uncommented = (code) => code.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:"'\\])\/\/[^\n]*/g, "$1");
function closure(root) {
  const have = new Map();
  const queue = [...new Set(uncommented(root).match(/[A-Za-z_$][A-Za-z0-9_$]*/g))];
  while (queue.length) {
    const name = queue.shift();
    if (have.has(name) || STUBS.has(name)) continue;
    const def = definitionOf(name);
    if (!def) continue;
    try { new vm.Script(def); } catch (e) { continue; }
    have.set(name, def);
    new Set(uncommented(def).match(/[A-Za-z_$][A-Za-z0-9_$]*/g)).forEach(id => { if (!have.has(id) && !STUBS.has(id)) queue.push(id); });
  }
  return { code: [...have.values()].sort((x, y) => SRC.indexOf(x) - SRC.indexOf(y)).join("\n\n") + "\n\n" + root, names: [...have.keys()] };
}

const GEN_ROUTE = s.routeCode(SRC, "seo/generate-post");
const PUB_SIG = "  publish_blog_post: async function (proposal) {";
const pubAt = SRC.indexOf(PUB_SIG);
if (pubAt < 0) { console.log("    FAIL  publish_blog_post not found"); process.exit(1); }
const pubOpen = SRC.indexOf("{", pubAt + PUB_SIG.length - 1);
const PUB_CODE = "var __publish = async function (proposal) " + SRC.slice(pubOpen, s.braceMatch(SRC, pubOpen)) + ";";
const HELPERS = "this.__api = { isCautionOnlySentence: isCautionOnlySentence, splitComplianceSentences: splitComplianceSentences, " +
  "scanFdaRail: scanFdaRail, fdaNeverExemptPatterns: fdaNeverExemptPatterns, measureClaimsScan: measureClaimsScan, " +
  "COMPLIANCE_PROFILES: COMPLIANCE_PROFILES, COMPLIANCE_DISCLAIMER: COMPLIANCE_DISCLAIMER, AD_POLICY_RULES: AD_POLICY_RULES };";
const GEN_LIFT = closure(GEN_ROUTE);
const PUB_LIFT = closure(PUB_CODE);
const API_LIFT = closure(HELPERS);

/* ── a database that records what it is asked to write ── */
const AUTHOR = "aaaaaaaa-0000-4000-8000-0000000000f1";
const HANDLE = "check-handle";
const LISTINGS = [{ id: "11111111-2222-3333-4444-555555555555", title: "Wool Hat", slug: "wool-hat", category: "apparel", description: "A hand-knitted wool hat." }];
function fakeDb() {
  const writes = [], drafts = [];
  function q(table) {
    const st = { insert: null };
    const b = {};
    ["select", "eq", "neq", "gte", "lte", "gt", "in", "is", "not", "order", "limit", "ilike"].forEach(k => { b[k] = () => b; });
    b.insert = (p) => {
      if (table === "seo_refused_drafts") { drafts.push(JSON.parse(JSON.stringify(p))); return Promise.resolve({ data: null, error: null }); }
      st.insert = p; writes.push({ table: table, payload: JSON.parse(JSON.stringify(p)) }); return b;
    };
    b.maybeSingle = () => Promise.resolve({ data: table === "bf_profiles" ? { username: HANDLE } : null, error: null });
    b.single = () => Promise.resolve(st.insert ? { data: Object.assign({ id: "row-1" }, st.insert), error: null } : { data: null, error: null });
    b.then = (res, rej) => Promise.resolve({ data: table === "marketplace_listings" ? LISTINGS : [], error: null }).then(res, rej);
    return b;
  }
  return { client: { from: q }, writes: writes, drafts: drafts };
}
function baseCtx(db, modelText) {
  const prompts = [];
  const ctx = {
    supabase: db.client, nowIso: () => "2026-10-17T12:00:00.000Z", process: { env: {} }, require: require, Buffer: Buffer, URL: URL,
    console: { log() {}, warn() {}, error() {} },
    requireAuth: 0, requireActiveSubscription: 0, aiLimiter: 0,
    resolvePreferredLanguage: async () => null,
    buildLanguageInstruction: () => "",
    AGENT_SYSTEM_PROMPTS: { seo: "SEO SYSTEM" },
    OWNER_ACCOUNT_ID: "00000000-0000-4000-8000-0000000000ff",
    callAnthropicText: async (prompt) => {
      prompts.push(prompt);
      if (prompts.length > 3) throw new Error("checkSeoFdaRail: the route looped on the model");
      return { text: modelText, stopReason: "end_turn" };
    }
  };
  return { ctx: ctx, prompts: prompts };
}

/* ── the article the scripted model returns, with one line of interest ── */
let DISCLAIMER = "";
function bodyWith(line) {
  const pad = "<p>" + "Wool keeps its shape when it is washed cool and dried flat, away from direct heat. ".repeat(5) + "</p>";
  return "<h2>How to look after a wool hat</h2>" + pad + "<p>" + line + "</p>" + pad +
    '<p>The <a href="/listing/wool-hat">wool hat</a> is knitted by hand.</p>' + "<p>" + DISCLAIMER + "</p>";
}
function article(line) {
  return "---TITLE---\nHow to look after a wool hat\n---SLUG---\nhow-to-look-after-a-wool-hat\n---META_DESCRIPTION---\nA plain answer.\n" +
    "---KEYWORD---\nwool hat care\n---INTERNAL_LINKS---\n/listing/wool-hat\n---REASONING---\nA question people ask.\n---BODY---\n" + bodyWith(line);
}
async function generate(line) {
  const db = fakeDb();
  const b = baseCtx(db, article(line));
  let handler = null;
  b.ctx.app = { post() { handler = arguments[arguments.length - 1]; } };
  vm.createContext(b.ctx);
  vm.runInContext(GEN_LIFT.code, b.ctx);
  const res = { statusCode: 200, body: undefined, status(c) { this.statusCode = c; return this; }, json(p) { this.body = JSON.parse(JSON.stringify(p)); return this; } };
  let nextErr = null;
  await handler({ user: { id: AUTHOR }, body: { topic: "wool hat care", compliance_profile: "supplement_vitality" } }, res, (e) => { nextErr = e || new Error("next"); });
  return { status: res.statusCode, body: res.body || {}, writes: db.writes, drafts: db.drafts, prompts: b.prompts, nextErr: nextErr && String(nextErr.message || nextErr) };
}
async function publish(payload) {
  const db = fakeDb();
  const b = baseCtx(db, "");
  vm.createContext(b.ctx);
  vm.runInContext(PUB_LIFT.code, b.ctx);
  let result = null, thrown = null;
  try { result = await b.ctx.__publish({ id: "proposal-1", user_id: AUTHOR, payload: JSON.parse(JSON.stringify(payload)) }); }
  catch (e) { thrown = String((e && e.message) || e); }
  return { result: result, thrown: thrown, writes: db.writes };
}

/* ── the 17 lines ──────────────────────────────────────────────────────── */
const DISEASE = "DISEASE CLAIM", CAUTION = "SAFETY / CAUTION", NEUTRAL = "NEUTRAL MENTION";
// [id, line, class, expected: "pass" | "fda" (refused by the FDA group) | "profile" (refused by the profile)]
const LINES = [
  ["F1", "Supports healthy blood sugar levels.", DISEASE, "fda"],
  ["F2", "If you take blood pressure medication, consult your doctor before use.", CAUTION, "pass"],
  ["F3", "Not recommended for people with heart conditions.", CAUTION, "pass"],
  ["F4", "Helps lower cholesterol naturally.", DISEASE, "fda"],
  ["F5", "May support healthy circulation and stamina.", NEUTRAL, "pass"],
  ["F6", "If you have been diagnosed with diabetes, talk to your doctor first.", CAUTION, "profile"],
  ["F7", "Promotes normal blood flow.", NEUTRAL, "pass"],
  ["F8", "Relief from high blood pressure without drugs.", DISEASE, "fda"],
  ["A1", "If you have high blood pressure, this formula is for you.", DISEASE, "fda"],
  ["A2", "If you take blood pressure medication, you may no longer need it.", DISEASE, "fda"],
  ["A3", "If you are taking cholesterol drugs, try this instead.", DISEASE, "fda"],
  ["A4", "If you have been diagnosed with prediabetes, start here.", DISEASE, "fda"],
  ["A5", "Lowers blood sugar. Consult your doctor before use.", DISEASE, "fda"],
  ["A6", "Consult your doctor, then watch your blood pressure drop.", DISEASE, "fda"],
  ["A7", "Not recommended for people with heart conditions; everyone else sees better cholesterol numbers.", DISEASE, "fda"],
  ["X1", "Do not use if you have low blood pressure.", CAUTION, "pass"],
  ["X2", "Not intended for people with diabetes who want to stop insulin and feel better.", DISEASE, "profile"]
];
const LAWFUL = ["Supports healthy circulation.", "Helps maintain normal energy levels.", "Supports immune function.",
  "Supports stamina.", "Supports confidence.", "Promotes general wellbeing."];

function genOutcome(g) {
  const v = (g.body && g.body.violations) || [];
  if (g.status === 201 && g.writes.length === 1 && g.writes[0].table === "agent_proposals") return "pass";
  if (g.status === 422 && g.writes.length === 0 && g.drafts.length === 1 && g.drafts[0].stage === "compliance") {
    return v.some(x => x.rule !== "fda_disease_claims") ? "profile" : (v.length && v.every(x => x.rule === "fda_disease_claims") ? "fda" : "?");
  }
  return "other:" + g.status + "/" + (g.drafts[0] && g.drafts[0].stage) + "/" + g.writes.length + "/" + (g.nextErr || (g.body && g.body.error));
}
function pubOutcome(p) {
  if (!p.thrown && p.writes.length === 1) return "pass";
  if (p.thrown && p.writes.length === 0 && /violates the 'supplement_vitality' compliance profile and was not published/.test(p.thrown)) {
    const named = p.thrown.split("; ").map(x => / — fda_disease_claims$/.test(x));
    return named.some(n => !n) ? "profile" : "fda";
  }
  return "other:" + (p.thrown || "written " + p.writes.length);
}

(async function main() {
  const API = (() => { const c = { console: { log() {}, warn() {}, error() {} } }; vm.createContext(c); vm.runInContext(API_LIFT.code, c); return c.__api; })();
  DISCLAIMER = API.COMPLIANCE_DISCLAIMER;
  check("the route, the executor and the helpers were lifted with both rulebooks",
    ["scanFdaRail", "fdaRailViolations", "isCautionOnlySentence", "splitComplianceSentences", "scanAdPolicy", "AD_POLICY_RULES", "findComplianceViolations", "COMPLIANCE_PROFILES"]
      .every(n => GEN_LIFT.names.indexOf(n) !== -1 && PUB_LIFT.names.indexOf(n) !== -1), GEN_LIFT.names.length + "/" + PUB_LIFT.names.length);

  /* ── A. the templates ──────────────────────────────────────────────── */
  console.log("\n══ A. isCautionOnlySentence ══");
  const YES = ["If you take blood pressure medication, consult your doctor before use.", "Consult your doctor.", "Talk to your doctor first.",
    "If you have been diagnosed with diabetes, talk to your doctor first.", "Ask a pharmacist before taking this product.",
    "check with your healthcare provider before using this.", "Not recommended for people with heart conditions.", "Not suitable for children.",
    "Do not use if you have low blood pressure.", "Don't use if pregnant.", "Seek medical advice.", "If you have a heart condition, seek medical advice first.",
    "  Not   intended for   people with heart conditions.  ", "Not recommended for " + "a".repeat(60) + "."];
  const NO = ["Not recommended for " + "a".repeat(61) + ".", "Consult your doctor", "Consult your doctor!", "Consult your doctor, then watch your blood pressure drop.",
    "Lowers blood sugar. Consult your doctor before use.", "If you have high blood pressure, this formula is for you.",
    "Not recommended for people with heart conditions; everyone else sees better cholesterol numbers.", "Please consult your doctor before use.",
    "Not recommended for people with heart conditions, but great for everyone else.", "If you take " + "b".repeat(61) + ", consult your doctor.", ""];
  YES.forEach(t => check("A. a caution sentence: " + JSON.stringify(t.length > 80 ? t.slice(0, 40) + "… (" + t.length + " chars)" : t), API.isCautionOnlySentence(t) === true));
  NO.forEach(t => check("A. not a caution-only sentence: " + JSON.stringify(t.length > 80 ? t.slice(0, 40) + "… (" + t.length + " chars)" : t), API.isCautionOnlySentence(t) === false));

  /* ── B. the splitter ───────────────────────────────────────────────── */
  console.log("\n══ B. the sentence splitter ══");
  const SPLIT = [
    ["One. Two.", ["One.", "Two."]],
    ["Is it? Yes! Fine.", ["Is it?", "Yes!", "Fine."]],
    ["line one\nline two", ["line one", "line two"]],
    ["<p>One</p><p>Two</p>", ["One", "Two"]],
    ["<h2>Heading</h2><ul><li>first</li><li>second</li></ul>", ["Heading", "first", "second"]],
    ["Consult your doctor.<br>Lowers blood sugar.", ["Consult your doctor.", "Lowers blood sugar."]],
    ["<p>If you take <strong>blood pressure</strong> medication, consult your <a href=\"/x\">doctor</a> before use.</p>",
      ["If you take blood pressure medication, consult your doctor before use."]],
    ["Take 2.5 mg daily. Done.", ["Take 2.5 mg daily.", "Done."]],
    ["No end here", ["No end here"]]
  ];
  SPLIT.forEach(([text, want]) => {
    const got = API.splitComplianceSentences(text);
    check("B. " + JSON.stringify(text) + " splits into " + JSON.stringify(want), JSON.stringify(got.map(x => x.text)) === JSON.stringify(want), JSON.stringify(got.map(x => x.text)));
  });
  const offText = "Wool is warm. If you take blood pressure medication, consult your doctor before use.";
  const offs = API.splitComplianceSentences(offText);
  check("B. offsets point into the original text: the second sentence starts where it does in the source",
    offs.length === 2 && offText.slice(offs[1].start, offs[1].end).trim() === offs[1].text && offs[0].start === 0, JSON.stringify(offs));

  /* ── C, D. the 17 lines at both rail points ────────────────────────── */
  console.log("\n══ C. the 17 lines, at generation and at publish ══");
  const clean = await generate("Supports healthy circulation.");
  const template = clean.writes[0] && clean.writes[0].payload && clean.writes[0].payload.payload;
  check("C. a clean article is filed, giving the publish payload", clean.status === 201 && !!template && template.compliance_profile === "supplement_vitality",
    clean.status + " " + JSON.stringify(clean.body).slice(0, 300));
  const rows = [];
  for (const [id, line, cls, want] of LINES) {
    const g = await generate(line);
    const p = await publish(Object.assign({}, template || {}, { body: bodyWith(line) }));
    const gen = genOutcome(g), pub = pubOutcome(p);
    rows.push({ id, line, cls, want, gen, pub, g, p });
    console.log("    " + id.padEnd(3) + " " + cls.padEnd(16) + " gen " + gen.padEnd(8) + " pub " + pub.padEnd(8) + " " + line);
    check("C. " + id + " (" + cls + ") at generation: " + want, gen === want, gen);
    check("C. " + id + " (" + cls + ") at publish: " + want, pub === want, pub);
  }
  check("C. every DISEASE CLAIM line is refused at both points", rows.filter(r => r.cls === DISEASE).every(r => r.gen !== "pass" && r.pub !== "pass"));
  check("C. F2, F3 and the low-blood-pressure line pass the FDA group at both points",
    rows.filter(r => ["F2", "F3", "X1"].indexOf(r.id) !== -1).every(r => r.gen === "pass" && r.pub === "pass"));
  const f6 = rows.find(r => r.id === "F6");
  check("C. F6 is still refused by the profile, for naming diabetes, and its caution is not an FDA violation",
    f6.gen === "profile" && f6.g.body.violations.some(v => v.matched.toLowerCase() === "diabetes") && !f6.g.body.violations.some(v => v.rule === "fda_disease_claims") &&
    !/fda_disease_claims/.test(f6.p.thrown || ""), JSON.stringify(f6.g.body.violations));
  console.log("\n══ D. the refusal names the rulebook ══");
  const f1 = rows.find(r => r.id === "F1");
  console.log("    generation: " + JSON.stringify(f1.g.body));
  console.log("    publish:    " + f1.p.thrown);
  check("D. at generation: 422, the profile's error, each violation { matched, rule: \"fda_disease_claims\" }",
    f1.g.status === 422 && /violates the 'supplement_vitality' compliance profile\. No post was created\./.test(f1.g.body.error) &&
    f1.g.body.violations.length > 0 && f1.g.body.violations.every(v => v.rule === "fda_disease_claims" && typeof v.matched === "string") &&
    f1.g.body.violations.some(v => /blood sugar/i.test(v.matched)), JSON.stringify(f1.g.body));
  check("D. at generation: the refused draft is stored with stage \"compliance\" and the same violations",
    f1.g.drafts.length === 1 && f1.g.drafts[0].stage === "compliance" && JSON.stringify(f1.g.drafts[0].refusal || f1.g.drafts[0]).indexOf("fda_disease_claims") !== -1, JSON.stringify(f1.g.drafts[0]).slice(0, 300));
  check("D. at publish: thrown, naming the matched text and fda_disease_claims, nothing written",
    /matched "Supports healthy blood sugar" — fda_disease_claims/.test(f1.p.thrown || "") && f1.p.writes.length === 0, f1.p.thrown);
  check("D. no repair or retry for it: one model call at generation", rows.filter(r => r.gen === "fda").every(r => r.g.prompts.length === 1),
    rows.map(r => r.id + ":" + r.g.prompts.length).join(","));

  /* ── E. lawful phrases ─────────────────────────────────────────────── */
  console.log("\n══ E. six lawful structure/function phrases ══");
  for (const phrase of LAWFUL) {
    const g = await generate(phrase);
    const p = await publish(Object.assign({}, template || {}, { body: bodyWith(phrase) }));
    check("E. passes generation and publish: \"" + phrase + "\"", genOutcome(g) === "pass" && pubOutcome(p) === "pass", genOutcome(g) + " / " + pubOutcome(p));
  }

  /* ── F. never exempt ───────────────────────────────────────────────── */
  console.log("\n══ F. never-exempt patterns inside a caution sentence ══");
  const never = API.fdaNeverExemptPatterns();
  check("F. all five never-exempt patterns are found in the FDA group", Array.isArray(never) && never.length === 5, never && never.map(p => p.source.slice(0, 20)).join(" | "));
  const NEVER = [
    ["verb + marker", "Not recommended for people who lower blood pressure daily."],
    ["relief from", "Do not use if you need relief from high blood pressure."],
    ["drug-free", "Do not use if you want a drug-free alternative."],
    ["protects against", "Not intended for people it protects against infection."],
    // "colds", not "disease": the profile's treatment-verb pattern would refuse "prevents disease" first.
    ["prevents", "Do not use if you expect it prevents colds."]
  ];
  for (const [what, line] of NEVER) {
    const rail = API.scanFdaRail(line);
    const g = await generate(line);
    const p = await publish(Object.assign({}, template || {}, { body: bodyWith(line) }));
    check("F. " + what + ": the sentence fits a template, and is still refused at both points", API.isCautionOnlySentence(line) && rail.cautions.length === 0 &&
      rail.refused.length > 0 && genOutcome(g) === "fda" && pubOutcome(p) === "fda", JSON.stringify(rail) + " " + genOutcome(g) + "/" + pubOutcome(p));
  }

  /* ── G. Claims Scan ────────────────────────────────────────────────── */
  console.log("\n══ G. Claims Scan lists a caution sentence apart ══");
  const F2 = LINES[1][1];
  const cs = API.measureClaimsScan("supplement_vitality", [{ source: "pasted text", fields: [{ field: "text", text: F2 }] }], { pasted_text: 1 }, null, null);
  console.log("    " + JSON.stringify({ findings: cs.findings, caution_sentences: cs.caution_sentences, note: cs.note }));
  check("G. F2 is under caution_sentences with its text and position, and is not a finding",
    cs.findings_total === 0 && cs.findings.length === 0 && cs.caution_sentences.length === 1 && cs.caution_sentences[0].matched_text === "blood pressure" &&
    cs.caution_sentences[0].position === 12 && cs.caution_sentences[0].sentence === F2 && cs.caution_sentences[0].source === "pasted text", JSON.stringify(cs));
  check("G. the note says those sentences are allowed in the SEO writer", /listed under caution_sentences and not counted as findings, because the SEO writer allows those sentences/.test(cs.note), cs.note);
  const cs1 = API.measureClaimsScan("supplement_vitality", [{ source: "pasted text", fields: [{ field: "text", text: LINES[0][1] }] }], { pasted_text: 1 }, null, null);
  check("G. F1 is still a finding, and nothing is under caution_sentences", cs1.findings_total > 0 && cs1.caution_sentences.length === 0 &&
    cs1.findings.some(f => f.rules.some(r => r.rule_id === "fda_disease_claims")), JSON.stringify(cs1.findings.map(f => f.matched_text)));
  check("G. the route answers with measureClaimsScan's result", /measured: measureClaimsScan\(profileName, items, scanned, overCap, overCapReason\),/.test(SRC));

  /* ── H. the prompt ─────────────────────────────────────────────────── */
  console.log("\n══ H. the writer's prompt ══");
  const prompt = API.COMPLIANCE_PROFILES.supplement_vitality.prompt;
  const MARKER = "- Name a clinical marker as something this product affects. Blood sugar, blood glucose, blood pressure, cholesterol, LDL, HDL, " +
    "triglycerides, A1c, thyroid levels and bone density count as conditions here. A caution such as 'If you take blood pressure medication, " +
    "consult your doctor before use.' is allowed as its own sentence.\n";
  check("H. the profile prompt carries the marker line right after \"Do not name the condition at all.\"",
    prompt.indexOf("name the condition at all.\n" + MARKER + "- Claim approval,") !== -1, prompt.slice(prompt.indexOf("name the condition"), prompt.indexOf("name the condition") + 200));
  check("H. the prompt sent to the model at generation carries it", (clean.prompts[0] || "").indexOf(MARKER) !== -1);

  /* ── I. reuse ──────────────────────────────────────────────────────── */
  console.log("\n══ I. the FDA group is reused, not copied ══");
  const railCode = ["scanFdaRail", "fdaRailViolations", "fdaNeverExemptPatterns"].map(definitionOf).join("\n");
  check("I. the rail runs scanAdPolicy and picks fda_disease_claims by id", /scanAdPolicy\(scanned\)/.test(railCode) && /var FDA_RAIL_RULE_ID = "fda_disease_claims";/.test(SRC));
  check("I. the rail functions hold no regular-expression literal", !/\/[^/\n*][^/\n]*\/[gimsuy]*(?=[.,);\s])/.test(uncommented(railCode)), railCode.length);
  check("I. both rail points add fdaRailViolations to the profile's violations",
    (SRC.match(/findComplianceViolations\(complianceProfile, complianceText, 5\)\n\s+\.concat\(fdaRailViolations\(complianceProfile, complianceText\)\);/g) || []).length === 2);
  check("I. no model call or network outside the scripted model", NETWORK.length === 0, NETWORK.join(","));

  console.log("\n" + (failures ? failures + " FAILED, " + passes + " passed" : "ALL " + passes + " CHECKS PASSED"));
  process.exit(failures ? 1 : 0);
})().catch(e => { console.log("    FAIL  the check itself threw: " + (e && e.stack)); process.exit(1); });
