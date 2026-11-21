/* ═══════════════════════════════════════════════════════════════════════════
   checkStorageAccount.js — storage per account (P3-1, Nov 20 2026;
   lib/storageAccount.js, migrations 196 to 198).

   WHAT IT PROVES
     A. THE LIMITS: free 50 MB, member 500 MB, the owner exempt (counted, never
        refused), all from lib/membership.js.
     B. RESERVE (lib/storageAccount.js, a fake rpc): it asks
        storage_account_reserve with the account, bucket, path, whole bytes
        and the limit; a fit is null (go on); a refusal is 413
        account_storage_full with one plain sentence (the limit, what is used,
        the file, nothing uploaded; a free account is told what joining
        gives); an rpc error or a throw is 503, nothing stored (fails closed).
     C. RELEASE: asks storage_account_release; a failure is logged and
        answers 0, never a throw (an over-count can only refuse an upload).
     D. EVERY UPLOAD IN server.js RESERVES FIRST: each .upload( and
        createSignedUploadUrl( sits in a statement that calls
        storageAccountReserve before it, after the shared guard. EVERY REMOVE
        RELEASES: each storage .remove( sits in a statement that calls
        storageAccountRelease (or ReleaseMany).
     E. THE SIGNED UPLOAD: POST /api/bfp/upload-url is rate limited, reserves
        the DECLARED size and releases when no URL is made; POST
        /api/bfp/upload-check reserves the size that ARRIVED and, over the
        limit, deletes the file, releases it and refuses.
     F. THE LIBRARIES: lib/postMedia.js counts a post photo after the guard and
        before the upload and releases on failure; lib/memberVideos.js counts a
        video, releases on a refused finalize, a delete and retention, and
        server.js hands it both hooks; lib/accountFiles.js removeFiles (run
        here, fakes) releases every file it removes or queues, so media and
        music deletes and account deletion all follow.
     G. LIVE (the plain run, BIZFORCE_CHECK_USER_ID): on the check account, a
        file is counted; the same path again replaces its size (the declared
        then the arrived); a limit it does not fit is refused and nothing is
        counted; release frees it and the totals are back where they were.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
require("dotenv").config();
const H = require("./_p21Harness");
const s = require("./_shared");

const SERVER = "@server.js", SA = "@lib/storageAccount.js", MEM = "@lib/membership.js", AF = "@lib/accountFiles.js", PM = "@lib/postMedia.js", MV = "@lib/memberVideos.js";
const MUTATIONS = {
  "owner-limited": [[SA, "  if (who && who.owner === true) return EXEMPT_LIMIT;\n", ""]],
  "fails-open": [[SA, "    return { status: 503, body: { error: UNCHECKED_SENTENCE, reason: \"account_storage_unchecked\" } };", "    return null;"]],
  "member-limit-50": [[MEM, "const STORAGE_MEMBER_BYTES = 500 * MB;", "const STORAGE_MEMBER_BYTES = 50 * MB;"]],
  "release-throws": [[SA, "    console.error(\"[storage-account] release failed for \" + bucket + \"/\" + path + \": \" + ((e && e.message) || e) + \" — the file is still counted.\");\n    return 0;", "    throw e;"]],
  "check-not-rereserved": [[SERVER, "    const arrived = await storageAccountReserve(req.user.id, \"bf-public\", req.body.path, buf.length);\n    if (arrived) {", "    const arrived = null;\n    if (arrived) {"]],
  "signed-no-release": [[SERVER, "    if (error) {\n      await storageAccountRelease(\"bf-public\", storagePath);\n      console.error(\"[upload-url] Supabase error:\"", "    if (error) {\n      console.error(\"[upload-url] Supabase error:\""]],
  "files-not-released": [[AF, "    if (f && f.bucket && f.path && BUCKETS.indexOf(f.bucket) !== -1) await SA.release(supabase, f.bucket, f.path);", "    if (false) await SA.release(supabase, f.bucket, f.path);"]],
  "post-photo-unreserved": [[PM, "  var counted = await deps.account(MM.BUCKET, key, checked.size);\n  if (counted) return counted;\n", ""]],
  "upload-url-unlimited": [[SERVER, 'app.post("/api/bfp/upload-url", requireAuth, uploadUrlLimiter, async', 'app.post("/api/bfp/upload-url", requireAuth, async']],
  // the media library upload stores without counting (D1 catches it)
  "media-route-unreserved": [[SERVER, "const mediaAccount = await storageAccountReserve(userId, memberMedia.BUCKET, path, checked.size);", "const mediaAccount = null;"]]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, SA, MEM, AF, PM, MV]);
const { FILES, check, finish, J, has } = T;
const S = FILES[SERVER] || "";
const A = T.libRequire("./lib/storageAccount");
const M = T.libRequire("./lib/membership");
const MB = 1024 * 1024;

function rpcFake(answer) {
  const calls = [];
  return { calls, sb: { rpc: async (name, args) => { calls.push([name, args]); return typeof answer === "function" ? answer(name, args) : answer; } } };
}
const quiet = async fn => { const e = console.error; console.error = () => {}; try { return await fn(); } finally { console.error = e; } };

/* The top-level statement of server.js around pos: the last "\napp." / "\nasync function " / "\nfunction " before it, to its brace. */
function enclosing(src, pos) {
  let start = -1;
  ["\napp.", "\nasync function ", "\nfunction "].forEach(k => { const i = src.lastIndexOf(k, pos); if (i > start) start = i; });
  if (start < 0) return null;
  const open = src.indexOf("{", src.indexOf(start === src.lastIndexOf("\napp.", pos) ? "function" : "(", start));
  const end = s.braceMatch(src, open);
  return end > pos ? { start, text: src.slice(start, end + 1), at: pos - start } : null;
}
function sites(src, re) { const out = []; let m; while ((m = re.exec(src)) !== null) out.push(m.index); return out; }
const lineOf = pos => S.slice(0, pos).split("\n").length;

(async function main() {
  console.log("\n══ A. the limits ══");
  check("A1. free 50 MB, member 500 MB", M.STORAGE_FREE_BYTES === 50 * MB && M.STORAGE_MEMBER_BYTES === 500 * MB && M.storageLimitFor("free") === 50 * MB && M.storageLimitFor("member") === 500 * MB);
  check("A2. the owner is exempt: the largest safe number, so counted and never refused", A.limitFor({ owner: true, tier: "free" }) === Number.MAX_SAFE_INTEGER && A.limitFor({ owner: false, tier: "free" }) === 50 * MB);
  check("A3. no tier at all is the free limit", A.limitFor(null) === 50 * MB && A.limitFor({}) === 50 * MB);

  console.log("\n══ B. reserve ══");
  let f = rpcFake({ data: { ok: true, used_bytes: 10 }, error: null });
  let r = await A.reserve(f.sb, "U1", { tier: "free", owner: false }, "bf-public", "a/U1/x.png", 1234.6);
  check("B1. a fit goes on (null), asked of storage_account_reserve with the account, bucket, path, whole bytes and the limit",
    r === null && f.calls.length === 1 && f.calls[0][0] === "storage_account_reserve" &&
    J(f.calls[0][1]) === J({ p_user: "U1", p_bucket: "bf-public", p_path: "a/U1/x.png", p_bytes: 1235, p_limit: 50 * MB }), J(f.calls));
  f = rpcFake({ data: { ok: false, used_bytes: 49 * MB }, error: null });
  r = await A.reserve(f.sb, "U1", { tier: "free", owner: false }, "bf-public", "p", 2 * MB);
  check("B2. a free account over its limit: 413 account_storage_full, used, limit and file sizes",
    r && r.status === 413 && r.body.reason === "account_storage_full" && r.body.used_bytes === 49 * MB && r.body.limit_bytes === 50 * MB && r.body.file_bytes === 2 * MB, J(r));
  check("B3. ...one plain sentence: the limit, what is used, the file, nothing uploaded, and what joining gives",
    r && r.body.error === "Your account can store 50 MB of files and 49 MB is used, so this 2 MB file does not fit. Nothing was uploaded. Delete files you no longer need, or join BizForce for 500 MB.", r && r.body.error);
  f = rpcFake({ data: { ok: false, used_bytes: 499 * MB }, error: null });
  r = await A.reserve(f.sb, "U2", { tier: "member", owner: false }, "bf-music", "p", 3 * MB);
  check("B4. a member over 500 MB is told to delete files, not to join", r && r.status === 413 && /store 500 MB/.test(r.body.error) && /no longer need\.$/.test(r.body.error), r && r.body.error);
  f = rpcFake({ data: null, error: { message: "down" } });
  r = await quiet(() => A.reserve(f.sb, "U1", { tier: "free" }, "bf-public", "p", 5));
  check("B5. an rpc error: 503 account_storage_unchecked, nothing stored (fails closed)", r && r.status === 503 && r.body.reason === "account_storage_unchecked" && r.body.error === A.UNCHECKED_SENTENCE, J(r));
  f = rpcFake(() => { throw new Error("network"); });
  r = await quiet(() => A.reserve(f.sb, "U1", { tier: "free" }, "bf-public", "p", 5));
  check("B6. a throw: the same 503", r && r.status === 503, J(r));
  f = rpcFake({ data: { ok: true }, error: null });
  await A.reserve(f.sb, "OWNER", { tier: "member", owner: true }, "bf-video", "p", 900 * MB);
  check("B7. the owner is asked with the exempt limit (so the file is still counted)", f.calls[0][1].p_limit === Number.MAX_SAFE_INTEGER, J(f.calls));

  console.log("\n══ C. release ══");
  f = rpcFake({ data: 4096, error: null });
  check("C1. release asks storage_account_release and answers the bytes freed", (await A.release(f.sb, "bf-public", "p")) === 4096 && J(f.calls[0]) === J(["storage_account_release", { p_bucket: "bf-public", p_path: "p" }]));
  f = rpcFake({ data: null, error: { message: "down" } });
  let threw = false, got;
  try { got = await quiet(() => A.release(f.sb, "bf-public", "p")); } catch (e) { threw = true; }
  check("C2. a failed release is logged and answers 0, never a throw", !threw && got === 0, String(threw) + " " + got);
  f = rpcFake({ data: 10, error: null });
  check("C3. releaseMany frees each path and skips empty ones; nothing asked for no bucket or path",
    (await A.releaseMany(f.sb, "bf-books", ["a", null, "b", ""])) === 20 && f.calls.length === 2 && (await A.release(f.sb, "", "x")) === 0 && f.calls.length === 2);

  console.log("\n══ D. every upload reserves first, every remove releases (server.js) ══");
  const ups = sites(S, /\.upload\(|\.createSignedUploadUrl\(/g);
  const badUp = ups.filter(pos => {
    const e = enclosing(S, pos); if (!e) return true;
    const before = e.text.slice(0, e.at);
    return before.lastIndexOf("storageAccountReserve(") === -1 || before.lastIndexOf("storageGuard(") === -1 || before.lastIndexOf("storageGuard(") > before.lastIndexOf("storageAccountReserve(");
  });
  check("D1. each of the " + ups.length + " uploads sits after the shared guard and then storageAccountReserve", ups.length >= 15 && badUp.length === 0, badUp.map(lineOf).join(", "));
  const rms = sites(S, /storage\s*\.from\([^)]*\)\s*\.remove\(/g);
  const badRm = rms.filter(pos => { const e = enclosing(S, pos); return !e || !/storageAccountRelease(Many)?\(/.test(e.text.slice(e.at)); });
  check("D2. each of the " + rms.length + " storage removes is followed by storageAccountRelease in its statement", rms.length >= 10 && badRm.length === 0, badRm.map(lineOf).join(", "));
  check("D3. the server's wrappers: owner and tier from getUserPlan (accessTier); a plan lookup that fails counts as free, never exempt",
    has(S, "who = { owner: isOwnerAccount(userId), tier: accessTier(await getUserPlan(userId)) };") && has(S, "who = { owner: isOwnerAccount(userId), tier: \"free\" };") &&
    has(S, "return require(\"./lib/storageAccount\").reserve(supabase, userId, who, bucket, path, bytes);"));

  console.log("\n══ E. the signed upload ══");
  const uu = H.routeStatement(S, "post", "/api/bfp/upload-url") || "";
  check("E1. POST /api/bfp/upload-url is rate limited (uploadUrlLimiter)", has(S, 'app.post("/api/bfp/upload-url", requireAuth, uploadUrlLimiter, async function') && /const uploadUrlLimiter = rateLimit\(/.test(S));
  check("E2. ...it reserves the DECLARED size, and releases when no signed URL is made (2 places)",
    has(uu, "storageAccountReserve(req.user.id, \"bf-public\", storagePath, Number(req.body.size))") && uu.split("await storageAccountRelease(\"bf-public\", storagePath);").length - 1 === 2 &&
    uu.indexOf("storageAccountReserve(") < uu.indexOf(".createSignedUploadUrl("));
  const uc = H.routeStatement(S, "post", "/api/bfp/upload-check") || "";
  const ra = uc.indexOf("storageAccountReserve(req.user.id, \"bf-public\", req.body.path, buf.length)");
  check("E3. POST /api/bfp/upload-check reserves the size that ARRIVED; over the limit the file is removed, released and refused",
    ra !== -1 && uc.indexOf(".remove([req.body.path])", ra) !== -1 && uc.indexOf("storageAccountRelease(\"bf-public\", req.body.path)", ra) !== -1 && has(uc.slice(ra), "return res.status(arrived.status).json(arrived.body);"));
  check("E4. ...a refused (not what it said) upload is released too", uc.indexOf("storageAccountRelease(\"bf-public\", req.body.path)") < ra && uc.indexOf("storageAccountRelease(\"bf-public\", req.body.path)") !== -1);

  console.log("\n══ F. the libraries ══");
  const P = FILES[PM] || "";
  const pg = P.indexOf("var full = await deps.guard(checked.size);"), pa = P.indexOf("var counted = await deps.account(MM.BUCKET, key, checked.size);"), pu = P.indexOf(".upload(key, checked.bytes");
  check("F1. a post photo: the guard, then counted, then uploaded; a failed upload, a failed row and over the cap each release",
    pg !== -1 && pa > pg && pu > pa && P.split("await deps.release(MM.BUCKET, key);").length - 1 === 3, [pg, pa, pu].join(" "));
  const V = FILES[MV] || "";
  check("F2. a video: counted before the signed URL, released on a refusal, a failed URL, a delete and retention",
    V.indexOf("deps.storageAccount(userId, BUCKET, path, b.bytes)") !== -1 && V.indexOf("deps.storageAccount(userId, BUCKET, path, b.bytes)") < V.indexOf("createSignedUploadUrl(path)") &&
    has(V, "if (row.path && typeof deps.storageRelease === \"function\") await deps.storageRelease(BUCKET, row.path);") && (V.match(/removeMany\(storage, .*deps\.storageRelease\)/g) || []).length === 5);
  check("F3. ...server.js hands the video library both hooks", has(S, "    storageAccount: storageAccountReserve,\n    storageRelease: storageAccountRelease\n"));
  const AFL = T.libRequire("./lib/accountFiles");
  const rel = rpcFake({ data: 1, error: null });
  const sb = Object.assign(H.fakeDb(() => ({ data: null, error: null })).client, { rpc: rel.sb.rpc });
  const storage = { from: b => ({ remove: async p => (b === "bf-music" ? { error: { message: "busy" } } : { data: p, error: null }) }) };
  const out = await quiet(() => AFL.removeFiles({ supabase: sb, storage, files: [{ bucket: "bf-public", path: "a" }, { bucket: "bf-music", path: "m" }, { bucket: "nope", path: "z" }], now: new Date("2026-11-20T12:00:00Z") }));
  const freed = rel.calls.filter(c => c[0] === "storage_account_release").map(c => c[1].p_bucket + "/" + c[1].p_path);
  check("F4. removeFiles releases every file it removes or queues, and none outside its buckets", J(freed) === J(["bf-public/a", "bf-music/m"]) && out.deleted === 1, J([freed, out]));

  console.log("\n══ G. live, on the check account ══");
  const CHECK_USER = process.env.BIZFORCE_CHECK_USER_ID;
  if (process.env.MUTATE || !CHECK_USER) {
    check("G. (skipped" + (process.env.MUTATE ? " under MUTATE" : ": BIZFORCE_CHECK_USER_ID not set") + ")", !!process.env.MUTATE, "set BIZFORCE_CHECK_USER_ID");
  } else {
    const { createClient } = require("@supabase/supabase-js");
    const live = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY);
    const totals = async () => { const t = await live.from("storage_account_totals").select("bytes, files").eq("user_id", CHECK_USER).maybeSingle(); if (t.error) throw t.error; return { bytes: Number(t.data && t.data.bytes) || 0, files: Number(t.data && t.data.files) || 0 }; };
    const path = "check-storage-account/" + CHECK_USER + "/" + Date.now() + ".bin";
    const t0 = await totals();
    try {
      const a = await A.reserve(live, CHECK_USER, { tier: "free", owner: false }, "bf-public", path, 1000);
      const t1 = await totals();
      check("G1. a file that fits is counted: +1000 bytes, +1 file", a === null && t1.bytes === t0.bytes + 1000 && t1.files === t0.files + 1, J([a, t0, t1]));
      const b = await A.reserve(live, CHECK_USER, { tier: "free", owner: false }, "bf-public", path, 400);
      const t2 = await totals();
      check("G2. the same path again replaces its size (declared 1000, arrived 400): +400, still +1 file", b === null && t2.bytes === t0.bytes + 400 && t2.files === t0.files + 1, J([b, t2]));
      const big = await A.reserve(live, CHECK_USER, { tier: "free", owner: false }, "bf-public", path + ".big", 60 * MB);
      const t3 = await totals();
      check("G3. a 60 MB file on a free account is refused (413) and nothing is counted", big && big.status === 413 && t3.bytes === t2.bytes && t3.files === t2.files, J([big && big.status, t3]));
    } finally {
      const freed = await A.release(live, "bf-public", path);
      await A.release(live, "bf-public", path + ".big");
      const t4 = await totals();
      check("G4. release frees it, and the totals are back where they were", freed === 400 && t4.bytes === t0.bytes && t4.files === t0.files, J([freed, t0, t4]));
    }
  }
  finish();
})().catch(e => { console.log("    FAIL  the check threw: " + (e && e.stack || e)); process.exit(1); });
