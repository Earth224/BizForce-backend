/* ═══════════════════════════════════════════════════════════════════════════
   checkSignupCanonical.js — one account per inbox (P3-1, Nov 20 2026).

   WHAT IT PROVES
     A. THE RULE (lib/emailCanonical.js canonicalEmail): lower case and
        trimmed; the +tag removed for every domain; dots removed for gmail.com
        and googlemail.com; googlemail.com read as gmail.com; the test domain
        bizforceai.invalid never folded; a local part that would fold to
        nothing kept as it is; no "@" only lowercased.
     B. THE SAME RULE AS THE DATABASE: every case of A is asked of the live
        public.email_canonical() (migration 195, read-only rpc) and must give
        the same answer; the migration's text names each rule.
     C. THE REGISTER ROUTE (POST /api/auth/register, lifted, a fake database):
        a second spelling of a used inbox is 409 "An account already uses this
        email" (reason email_in_use) and nothing is written; the unique index's
        23505 on the insert gets the same 409; a fresh inbox goes on to the
        insert; the folded address is what is asked.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
require("dotenv").config();
const H = require("./_p21Harness");

const SERVER = "@server.js", EC = "@lib/emailCanonical.js", MIG = "@supabase/migrations/195_users_email_canonical.sql";
const MUTATIONS = {
  // the route never asks who holds the folded address
  "no-canonical-check": [[SERVER, "    if (canonicalHolder) {\n", "    if (false) {\n"]],
  // the insert's 23505 is thrown, not answered
  "unique-not-mapped": [[SERVER, "      if (userError.code === \"23505\") {\n        return res.status(409).json({ error: require(\"./lib/emailCanonical\").ALREADY_USED", "      if (false) {\n        return res.status(409).json({ error: require(\"./lib/emailCanonical\").ALREADY_USED"]],
  // Gmail dots kept
  "gmail-dots-kept": [[EC, "  if (GMAIL_DOMAINS.indexOf(dom) !== -1) loc2 = loc2.split(\".\").join(\"\");", "  if (false) loc2 = loc2.split(\".\").join(\"\");"]],
  // the +tag kept
  "tag-kept": [[EC, "  var loc2 = loc.split(\"+\")[0];", "  var loc2 = loc;"]],
  // the test domain folded like any other
  "exempt-folded": [[EC, "  if (dom === EXEMPT_DOMAIN) return e;\n", ""]],
  // the route asks the address as typed, not folded
  "asks-raw-email": [[SERVER, "      .eq(\"email_canonical\", signupCanonical)", "      .eq(\"email_canonical\", email)"]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, EC, MIG]);
const { FILES, check, finish, J, has } = T;
const E = T.libRequire("./lib/emailCanonical");

const CASES = [
  ["John.Doe+news@Gmail.com", "johndoe@gmail.com"],
  ["  JOHN.DOE@gmail.com ", "johndoe@gmail.com"],
  ["j.o.h.n.doe@googlemail.com", "johndoe@gmail.com"],
  ["jane+shop@example.com", "jane@example.com"],
  ["jane.smith@example.com", "jane.smith@example.com"],
  ["Jane.Smith+a+b@Example.COM", "jane.smith@example.com"],
  ["hiram-test1+x@bizforceai.invalid", "hiram-test1+x@bizforceai.invalid"],
  ["Hiram.BFTest2@BizForceAI.invalid", "hiram.bftest2@bizforceai.invalid"],
  ["+x@site.com", "+x@site.com"],
  ["...@gmail.com", "...@gmail.com"],
  ["no-at-sign", "no-at-sign"],
  ["a@b@gmail.com", "a@b@gmail.com"]
];

(async function main() {
  console.log("\n══ A. the rule ══");
  const wrong = CASES.filter(([inp, want]) => E.canonicalEmail(inp) !== want).map(([inp, want]) => inp + " -> " + E.canonicalEmail(inp) + " (want " + want + ")");
  check("A1. every case folds as the rule says (" + CASES.length + ")", wrong.length === 0, wrong.join(" | "));
  check("A2. null and undefined are null", E.canonicalEmail(null) === null && E.canonicalEmail(undefined) === null);
  check("A3. the answer is the sentence the brief names", E.ALREADY_USED === "An account already uses this email");

  console.log("\n══ B. the same rule as the database ══");
  const sql = FILES[MIG] || "";
  check("B1. migration 195 lowercases and trims, cuts the +tag, drops Gmail dots, reads googlemail as gmail and leaves bizforceai.invalid alone",
    has(sql, "lower(btrim(p_email))") && has(sql, "split_part(s.loc, '+', 1)") && has(sql, "replace(split_part(s.loc, '+', 1), '.', '')") &&
    has(sql, "WHEN s.dom = 'googlemail.com' THEN 'gmail.com'") && has(sql, "WHEN x.dom = 'bizforceai.invalid' THEN x.e") && has(sql, "WHEN x.loc2 IS NULL OR x.loc2 = '' THEN x.e"));
  if (process.env.MUTATE) {
    check("B2. (skipped under MUTATE: the live database is asked once, in the plain run)", true);
  } else {
    const { createClient } = require("@supabase/supabase-js");
    const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);
    const diffs = [];
    for (const [inp] of CASES) {
      const r = await sb.rpc("email_canonical", { p_email: inp });
      if (r.error) { diffs.push(inp + ": " + r.error.message); continue; }
      if (r.data !== E.canonicalEmail(inp)) diffs.push(inp + ": db " + r.data + ", js " + E.canonicalEmail(inp));
    }
    check("B2. the live public.email_canonical() gives the JS answer for every case (" + CASES.length + ")", diffs.length === 0, diffs.join(" | "));
  }

  console.log("\n══ C. the register route ══");
  const SRC = FILES[SERVER];
  function world(o) {
    const db = H.fakeDb(function (table, q) {
      if (table === "users" && q.op === "select" && H.filterVal(q, "eq", "email")) return { data: null, error: null };
      if (table === "users" && q.op === "select" && H.filterVal(q, "eq", "email_canonical") !== undefined) {
        return { data: H.filterVal(q, "eq", "email_canonical") === o.held ? { id: "someone" } : null, error: null };
      }
      if (table === "profiles" && q.op === "select") return { data: null, error: null };
      if (table === "users" && q.op === "insert") return o.insertError ? { data: null, error: o.insertError } : { data: null, error: { code: "XX999", message: "stop here" } };
      return { data: null, error: null };
    });
    const fn = H.route(SRC, "post", "/api/auth/register", {
      supabase: db.client, authLimiter: 0,
      bcrypt: { hash: async () => "hash" }, crypto: { randomBytes: () => ({ toString: () => "tok" }) }
    }, T.libRequire);
    return { db, fn };
  }
  const body = email => ({ body: { email, password: "long enough pw", business_name: "Rose Co", accept_terms: true }, ip: "1.2.3.4" });
  let w = world({ held: "johndoe@gmail.com" });
  let r = w.fn ? await w.fn(body("John.Doe+shop@gmail.com")) : { status: 0 };
  const asked = w.db.log.filter(q => q.table === "users" && H.filterVal(q, "eq", "email_canonical") !== undefined).map(q => H.filterVal(q, "eq", "email_canonical"));
  check("C1. a second spelling of a used inbox: 409 \"An account already uses this email\", reason email_in_use", r.status === 409 && r.body && r.body.error === E.ALREADY_USED && r.body.reason === "email_in_use", J([r.status, r.body]));
  check("C2. ...the folded address is what is asked, and nothing is written", J(asked) === J(["johndoe@gmail.com"]) && !w.db.log.some(q => q.op !== "select"), J([asked, w.db.log.filter(q => q.op !== "select").map(q => q.table + ":" + q.op)]));
  w = world({ held: "nobody@gmail.com", insertError: { code: "23505", message: "duplicate key value violates unique constraint \"users_email_canonical_key\"" } });
  r = await w.fn(body("fresh@example.com"));
  check("C3. two sign-ups at once: the unique index's 23505 is the same 409", r.status === 409 && r.body && r.body.error === E.ALREADY_USED && r.body.reason === "email_in_use", J([r.status, r.body, r.err && r.err.message]));
  w = world({ held: "nobody@gmail.com" });
  r = await w.fn(body("fresh@example.com"));
  check("C4. a fresh inbox goes on to the insert", w.db.log.some(q => q.table === "users" && q.op === "insert") && r.status !== 409, J([r.status, r.body]));
  finish();
})().catch(e => { console.log("    FAIL  the check threw: " + (e && e.stack || e)); process.exit(1); });
