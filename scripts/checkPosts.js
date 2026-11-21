"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkPosts.js — posts, who sees them, the Following feed and Talk (P2-3,
   Nov 20 2026; migrations 193 and 194; lib/posts.js).

   Every rule runs against an in-memory database (scripts/_p23Db.js) that keeps
   migration 194's keys and counters; never the real database, never the network.

   WHAT THIS PROVES
     A. A NEW POST'S SHAPE: text and photo only, public or followers, at most
        2200 characters (counted as characters, not bytes), a text post has
        text and no photos, a photo post 1 to 4 photos.
     B. MAKING ONE: published at once ("Your post is up."), with the place only
        while "Show my posts in Local" is on; the content policy refuses with
        its one sentence and saves nothing; an unclear match is held (pending)
        with a queue item; a new account posts at once (P3-1, instant use: the
        new_member hold is gone), a public post needs a confirmed email (403
        email_unverified, nothing saved; a followers post does not); a queue
        that cannot be written leaves no post (503); ten a day.
     C. WHO SEES IT: the author (unless removed); anyone else only when it is
        published, not hidden by moderation, no block either way, the author's
        pages public, and public or followed.
     D. THE FOLLOWING FEED: the viewer's own and followed members' posts,
        newest first, ten a page, a cursor that neither skips nor repeats a
        post (equal times included), muted members left out, a bad cursor 400;
        under three follows it suggests public members (never the viewer,
        someone followed, blocked or muted), those with recent posts first.
     E. EDIT AND DELETE: the author's only; an edit is screened again (an
        unclear match sends it back to review); a delete is status removed.
     F. TALK: oldest first; one level of replies (a reply to a reply joins the
        top comment); 1000 characters; a deleted comment is a tombstone that
        keeps its replies; only the post's author hides; blocked and muted
        members' comments are left out; 60 an hour.
     G. NOTICES: a like (grouped per post per hour, its text counting the
        others, one push), a comment, a reply; never for your own action.
     H. MODERATION: kept publishes a held post; hidden hides; removed removes;
        an author's own delete is not undone by a later "kept".
     I. THE ROUTES: every P2-3 posts route is in server.js with its sign-in,
        and making a post or a photo needs an active plan.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");
const { memDb } = require("./_p23Db");

const SERVER = "@server.js", POSTS = "@lib/posts.js";
const MUTATIONS = {
  "followers-seen-by-all": [[POSTS, '    if (p.audience !== "public" && !(ctx.viewer && ctx.following.has(p.author_id))) continue;\n', ""]],
  "pending-shown": [[POSTS, '    if (p.status !== "published" || hidden.has(p.id)) continue;', "    if (hidden.has(p.id)) continue;"]],
  "private-author-shown": [[POSTS, "    if (!(await authorPublic(deps, ctx, p.author_id))) continue;\n", ""]],
  "blocked-shown": [[POSTS, "    if (ctx.blocked.has(p.author_id)) continue;\n", ""]],
  "feed-keeps-muted": [[POSTS, "    if (opts.feed && ctx.muted.has(p.author_id)) continue;\n", ""]],
  // NAMED (Nov 20 2026, P3-1): BEFORE new-member-published and unknown-age-waved, on the new_member hold, which is gone (instant use).
  // AFTER the public post's confirmed email: without the check an unconfirmed author posts publicly (B7 catches it).
  "unverified-posts-public": [[POSTS, "  if (v.audience === \"public\" && !(await authorVerified(deps, userId))) return", "  if (false) return"]],
  "place-without-opt-in": [[POSTS, "  if (!r || r.local_opt_in !== true) return", "  if (!r) return"]],
  "queue-failure-keeps-post": [[POSTS, "    if (!q) { await undo(); return fail(503,", "    if (false) { await undo(); return fail(503,"]],
  "posts-unlimited": [[POSTS, ">= POSTS_PER_DAY)", ">= 1e9)"]],
  "cursor-skips-ties": [[POSTS, '  return q.or(col + ".lt." + quoted(c.at) + ",and(" + col + ".eq." + quoted(c.at) + ",id.lt." + c.id + ")");', '  return q.lt(col, c.at);']],
  "body-bytes-not-chars": [[POSTS, "  if (chars(body) > BODY_MAX)", "  if (Buffer.byteLength(body) > BODY_MAX)"]],
  "edit-unscreened": [[POSTS, "  if (!screened.ok) return { status: 400, body: CP.refusalBody(screened) };\n  var findings = screened.review ? screened.review.findings : null;\n  var patch = { body: text };",
    "  var findings = null;\n  var patch = { body: text };"]],
  "edit-anyones": [[POSTS, "  if (!post || post.author_id !== userId || post.status === \"removed\") return notAvailable();\n  var text = body && body.body;", "  if (!post) return notAvailable();\n  var text = body && body.body;"]],
  "reply-nests": [[POSTS, "    if (parent.parent_id) {", "    if (false) {"]],
  "tombstone-deletes": [[POSTS, '  var u = await deps.sb.from("post_comments").update({ status: "deleted", body: DELETED_BODY }).eq("id", commentId).eq("author_id", viewerId);',
    '  var u = await deps.sb.from("post_comments").delete().eq("id", commentId).eq("author_id", viewerId);']],
  "anyone-hides": [[POSTS, "  if (!post || post.author_id !== viewerId) return fail(404, MESSAGES.commentGone);", "  if (!post) return fail(404, MESSAGES.commentGone);"]],
  "comments-show-muted": [[POSTS, "    return !(x.author_id && (ctx.blocked.has(x.author_id) || ctx.muted.has(x.author_id)));", "    return !(x.author_id && ctx.blocked.has(x.author_id));"]],
  "likes-not-grouped": [[POSTS, "  var row = (open.data || [])[0];\n  if (!row) {", "  var row = (open.data || [])[0];\n  if (true) {"]],
  "self-like-notice": [[POSTS, "  if (post.author_id === likerId) return;\n", ""]],
  "kept-revives-deleted": [[POSTS, '    if (!p || (p.status === "removed" && state !== "removed")) return { changed: false };', "    if (!p) return { changed: false };"]],
  // NAMED (Nov 20 2026, P3-1): BEFORE post-without-plan took requireActiveSubscription off. AFTER posting is free, so the mutation puts it back (I1 catches it).
  "post-needs-plan": [[SERVER, 'app.post("/api/posts", requireAuth, postRoute(', 'app.post("/api/posts", requireAuth, requireActiveSubscription, postRoute(']]
};
const T = H.setup(__filename, MUTATIONS, [SERVER, POSTS, "@lib/postMedia.js"]);
const { FILES, check, J, has } = T;
const P = T.libRequire("./lib/posts");

const ME = "11111111-1111-4111-8111-111111111111", THEM = "22222222-2222-4222-8222-222222222222", OTHER = "33333333-3333-4333-8333-333333333333";
const NEWBIE = "44444444-4444-4444-8444-444444444444", PRIV = "55555555-5555-4555-8555-555555555555", MUTED = "66666666-6666-4666-8666-666666666666";
const NOBODY = "77777777-7777-4777-8777-777777777777", FAN = "88888888-8888-4888-8888-888888888888", BLOCKER = "99999999-9999-4999-8999-999999999999";
const NOW0 = "2026-11-20T12:00:00.000Z";
const OLD = "2026-01-01T00:00:00.000Z";
const PUBLIC = new Set([ME, THEM, OTHER, NEWBIE, MUTED, NOBODY, FAN, BLOCKER]);
const quiet = async fn => { const w = console.warn, e = console.error; console.warn = () => {}; console.error = () => {}; try { return await fn(); } finally { console.warn = w; console.error = e; } };

function world(extra) {
  // NAMED (Nov 20 2026, P3-1): every author has confirmed their email (public posts need it; checkEmailVerified runs the unconfirmed one)
  const users = [ME, THEM, OTHER, PRIV, MUTED, FAN, BLOCKER].map(id => ({ id, created_at: OLD, email_verified_at: OLD })).concat([{ id: NEWBIE, created_at: "2026-11-19T12:00:00.000Z", email_verified_at: OLD }]);
  const names = { [ME]: "rose", [THEM]: "tom", [OTHER]: "olga", [NEWBIE]: "nell", [PRIV]: "pat", [MUTED]: "mo", [NOBODY]: "nobody", [FAN]: "fay", [BLOCKER]: "bea" };
  const seed = Object.assign({
    users, posts: [], post_media: [], post_comments: [], post_likes: [], post_saves: [], post_share_days: [], notifications: [], moderation_queue: [],
    follows: [], member_blocks: [], member_mutes: [], member_media: [], profiles: [],
    bf_profiles: Object.keys(names).map((id, i) => ({ user_id: id, username: names[id], display_name: names[id].toUpperCase(), avatar_url: null, updated_at: new Date(Date.UTC(2026, 10, 1 + i)).toISOString(),
      place_city: "Leeds", place_region: "West Yorkshire", place_country: "GB", local_opt_in: id === THEM }))
  }, extra || {});
  const db = memDb(seed);
  const pushes = [];
  let clock = NOW0;
  const deps = { sb: db.client, now: () => clock, claims: () => null, ownerPublic: async id => PUBLIC.has(id), push: async (u, p) => { pushes.push([u, p]); }, env: {} };
  return { db, deps, pushes, setNow: v => { clock = v; } };
}
function post(id, author, extra) {
  return Object.assign({ id, author_id: author, kind: "text", body: "Hello from " + author.slice(0, 4), audience: "public", status: "published",
    place_city: null, place_region: null, place_country: null, like_count: 0, comment_count: 0, save_count: 0, share_count: 0,
    created_at: "2026-11-19T10:00:00.000Z", published_at: "2026-11-19T10:00:00.000Z", removed_at: null }, extra || {});
}
const pid = n => "aaaaaaaa-0000-4000-8000-" + String(n).padStart(12, "0");

(async function main() {
  /* ── A ── */
  console.log("\n══ A. a new post's shape ══");
  const v = P.validateNew;
  check("A1. text and photo only: a video post is refused with the sentence that says the other kinds come later",
    v({ kind: "video", body: "x" }).error === P.MESSAGES.kind && v({ kind: "text", body: "x" }).kind === "text" && J(P.KINDS_NOW) === J(["text", "photo"]));
  check("A2. public or followers; public when not given", v({ body: "x" }).audience === "public" && v({ body: "x", audience: "followers" }).audience === "followers" &&
    v({ body: "x", audience: "friends" }).field === "audience");
  const wide = String.fromCodePoint(0x20000).repeat(2200);   // a CJK ideograph: one character, two UTF-16 units, four bytes
  check("A3. 2200 characters at most, counted as characters: 2200 four-byte characters pass, 2201 letters do not", !v({ body: wide }).error && v({ body: "a".repeat(2201) }).error === P.MESSAGES.bodyLong);
  check("A4. a text post needs text and has no photos", v({ body: "   " }).error === P.MESSAGES.textEmpty && v({ body: "x", media: [{ media_id: pid(1) }] }).error === P.MESSAGES.textPhotos);
  check("A5. a photo post has 1 to 4 photos", v({ kind: "photo", media: [] }).error === P.MESSAGES.photosNone &&
    v({ kind: "photo", media: [1, 2, 3, 4, 5].map(n => ({ media_id: pid(n) })) }).error === P.MESSAGES.photosMany && !v({ kind: "photo", media: [{ media_id: pid(1) }] }).error);

  /* ── B ── */
  console.log("\n══ B. making one ══");
  let w = world();
  let r = await P.createPost(w.deps, ME, { body: "  Fresh bread today.  " });
  const mine = w.db.t.posts[0];
  check("B1. published at once: 201, \"Your post is up.\", status published with published_at, the text trimmed", r.status === 201 && r.body.message === "Your post is up." &&
    mine && mine.status === "published" && mine.published_at === NOW0 && mine.body === "Fresh bread today." && r.body.post.mine === true && r.body.post.link === "/p/" + mine.id, J(r));
  check("B2. no place without \"Show my posts in Local\"", mine && mine.place_city === null && mine.place_country === null);
  r = await P.createPost(w.deps, THEM, { body: "Market day." });
  const theirs = w.db.t.posts.find(p => p.author_id === THEM);
  check("B3. with it on, the place is copied from the profile", theirs && theirs.place_city === "Leeds" && theirs.place_region === "West Yorkshire" && theirs.place_country === "GB");
  const before = w.db.t.posts.length;
  r = await P.createPost(w.deps, ME, { body: "Selling recalled cribs" });
  check("B4. the content policy refuses with its one sentence, and nothing is saved", r.status === 400 && r.body.reason === "content_policy" && w.db.t.posts.length === before, J(r.body));
  r = await P.createPost(w.deps, ME, { body: "Our new wine list" });
  const held = w.db.t.posts.find(p => p.body === "Our new wine list");
  check("B5. an unclear match is held for review: pending, no published_at, a queue item, the waiting sentence", r.status === 201 && held && held.status === "pending" && held.published_at === null &&
    r.body.message === P.MESSAGES.pending && w.db.t.moderation_queue.some(q => q.object_type === "post" && q.object_id === held.id), J(r.body));
  /* NAMED (Nov 20 2026, P3-1): BEFORE B6 "an account younger than the BizCash hold posts as pending, queued as new_member" and
     B7 "an account whose age is unknown is held, never waved through" (H5). AFTER instant use: a new account posts at once, and a
     public post needs a confirmed email instead. B8 now holds an unclear match from the new account. */
  r = await P.createPost(w.deps, NEWBIE, { body: "Hi all" });
  const nb = w.db.t.posts.find(p => p.author_id === NEWBIE);
  check("B6. a one-day-old account posts at once: 201, published, held false, no new_member queue item", r.status === 201 && nb && nb.status === "published" && r.body.held === false &&
    !w.db.t.moderation_queue.some(q => q.source === "new_member"), J([r.body.held, w.db.t.moderation_queue.map(q => q.source)]));
  const nBefore = w.db.t.posts.length;
  r = await P.createPost(w.deps, NOBODY, { body: "Who am I" });
  check("B7. an author whose email is not confirmed: a public post is 403 email_unverified with the resend link, and nothing is saved",
    r.status === 403 && r.body.reason === "email_unverified" && r.body.blocked === "post_public" && typeof r.body.resend_url === "string" && w.db.t.posts.length === nBefore, J(r.body));
  r = await P.createPost(w.deps, NOBODY, { body: "Just for my followers", audience: "followers" });
  check("B7. ...a followers-only post from the same author goes up", r.status === 201 && w.db.t.posts.some(p => p.author_id === NOBODY && p.audience === "followers"), J(r.body));
  w.db.failOn("moderation_queue", "insert");
  const n0 = w.db.t.posts.length;
  r = await quiet(() => P.createPost(w.deps, NEWBIE, { body: "Our new wine list, again" }));
  check("B8. a queue that cannot be written leaves no post: 503 queue_unavailable", r.status === 503 && r.body.reason === "queue_unavailable" && w.db.t.posts.length === n0, J(r.body));
  w = world();
  for (let i = 0; i < 10; i++) w.db.t.posts.push(post(pid(100 + i), ME, { created_at: "2026-11-20T0" + (i % 10) + ":00:00.000Z" }));
  r = await P.createPost(w.deps, ME, { body: "Eleventh" });
  check("B9. ten a day: the eleventh in 24 hours is 429", r.status === 429 && r.body.reason === "rate_limited" && w.db.t.posts.length === 10, J(r));

  /* ── C ── */
  console.log("\n══ C. who sees it ══");
  w = world({
    follows: [{ follower_id: FAN, following_id: ME, created_at: OLD }],
    member_blocks: [{ blocker_id: BLOCKER, blocked_id: ME }],
    moderation_queue: [{ object_type: "post", object_id: pid(5), state: "hidden" }]
  });
  w.db.t.posts.push(post(pid(1), ME), post(pid(2), ME, { audience: "followers" }), post(pid(3), ME, { status: "pending", published_at: null }),
    post(pid(4), ME, { status: "removed" }), post(pid(5), ME), post(pid(6), PRIV));
  const sees = async (viewer, id) => (await P.getPost(w.deps, viewer, id)).status === 200;
  check("C1. a public post: anyone signed in", await sees(OTHER, pid(1)) && await sees(FAN, pid(1)));
  check("C2. a followers post: its followers and its author only", await sees(FAN, pid(2)) && !(await sees(OTHER, pid(2))) && await sees(ME, pid(2)));
  check("C3. a pending post: its author only", await sees(ME, pid(3)) && !(await sees(FAN, pid(3))));
  check("C4. a removed post: nobody, its author included", !(await sees(ME, pid(4))) && !(await sees(OTHER, pid(4))));
  check("C5. hidden by moderation: not to others", !(await sees(OTHER, pid(5))));
  check("C6. a block either way: not seen (the blocker and the blocked)", !(await sees(BLOCKER, pid(1))));
  check("C7. an author whose pages are not public: not seen", !(await sees(OTHER, pid(6))));
  const na = await P.getPost(w.deps, OTHER, pid(2));
  check("C8. what is not seen answers 404 not_available, the same as a post that does not exist", na.status === 404 && na.body.reason === "not_available" &&
    J((await P.getPost(w.deps, OTHER, pid(999))).body) === J(na.body));
  const byMe = await P.postsByAuthor(w.deps, OTHER, ME);
  check("C9. a member's posts, to another member: only what they may see", byMe.status === 200 && J(byMe.body.posts.map(p => p.id).sort()) === J([pid(1)]), J(byMe.body.posts.map(p => p.id)));
  const byMeOwn = await P.postsByAuthor(w.deps, ME, ME);
  check("C10. to their author: pending ones too (marked), never removed ones", J(byMeOwn.body.posts.map(p => p.id + ":" + p.status).sort()) === J([pid(1) + ":published", pid(2) + ":published", pid(3) + ":pending", pid(5) + ":published"]),
    J(byMeOwn.body.posts.map(p => p.id + ":" + p.status)));

  /* ── D ── */
  console.log("\n══ D. the Following feed ══");
  w = world({ follows: [{ follower_id: ME, following_id: THEM, created_at: OLD }, { follower_id: ME, following_id: MUTED, created_at: OLD }],
    member_mutes: [{ muter_id: ME, muted_id: MUTED }] });
  const at = i => new Date(Date.UTC(2026, 10, 19, 0, 0, 0) + Math.floor((i + 1) / 2) * 60000).toISOString();   // pairs share a time, and a pair spans each page break
  for (let i = 0; i < 24; i++) w.db.t.posts.push(post(pid(200 + i), i % 2 ? THEM : ME, { published_at: at(i), created_at: at(i) }));
  w.db.t.posts.push(post(pid(300), OTHER, { published_at: at(30) }), post(pid(301), MUTED, { published_at: at(31) }));
  const seen = [];
  let cursor, pages = 0, page;
  do {
    page = await P.followingFeed(w.deps, ME, cursor);
    pages++;
    page.body.posts.forEach(p => seen.push(p.id));
    cursor = page.body.next_cursor;
  } while (cursor && pages < 6);
  const want = w.db.t.posts.filter(p => p.author_id === ME || p.author_id === THEM).sort((a, b) => a.published_at < b.published_at ? 1 : a.published_at > b.published_at ? -1 : a.id < b.id ? 1 : -1).map(p => p.id);
  check("D1. the viewer's own and followed members' posts, newest first, ten a page, every one once (pairs at the same time included)",
    J(seen) === J(want) && pages === 3 && new Set(seen).size === seen.length, pages + " pages, " + seen.length + " posts");
  check("D2. a muted member's posts and an unfollowed member's posts are left out", seen.indexOf(pid(301)) === -1 && seen.indexOf(pid(300)) === -1);
  const bad = await P.followingFeed(w.deps, ME, "nonsense");
  check("D3. a cursor that is not one is 400", bad.status === 400 && bad.body.error === P.MESSAGES.cursor);
  const first = await P.followingFeed(w.deps, ME);
  check("D4. the first page carries following_count and any_posts; under three follows, suggestions", first.body.following_count === 2 && first.body.any_posts === true && Array.isArray(first.body.suggestions));
  w.db.t.member_blocks = [{ blocker_id: BLOCKER, blocked_id: ME }];
  w.db.t.posts.push(post(pid(400), FAN, { published_at: "2026-11-18T00:00:00.000Z" }));
  const sug = (await P.followingFeed(w.deps, ME)).body.suggestions.map(s => s.user_id);
  check("D5. suggestions: never the viewer, someone followed, blocked or muted, or a page that is not public; recent posters first",
    sug.indexOf(ME) === -1 && sug.indexOf(THEM) === -1 && sug.indexOf(MUTED) === -1 && sug.indexOf(BLOCKER) === -1 && sug.indexOf(PRIV) === -1 && J(sug.slice(0, 2).sort()) === J([OTHER, FAN].sort()) && sug.length === 4, J(sug));
  const nobodyFeed = await P.followingFeed(w.deps, OTHER);
  check("D6. a member who follows no one sees their own posts and suggestions, never anyone else's posts", nobodyFeed.body.posts.every(p => p.author.id === OTHER) && nobodyFeed.body.suggestions.length > 0);

  /* ── E ── */
  console.log("\n══ E. edit and delete ══");
  w = world();
  w.db.t.posts.push(post(pid(1), ME));
  r = await P.editPost(w.deps, THEM, pid(1), { body: "Mine now" });
  check("E1. another member cannot edit it (404, nothing changed)", r.status === 404 && w.db.t.posts[0].body.indexOf("Hello") === 0);
  r = await P.editPost(w.deps, ME, pid(1), { body: "Selling recalled cribs" });
  check("E2. an edit is screened again: a refusal changes nothing", r.status === 400 && w.db.t.posts[0].body.indexOf("Hello") === 0);
  r = await P.editPost(w.deps, ME, pid(1), { body: "Wine tasting tonight" });
  check("E3. an unclear match sends it back to review, with a queue item", r.status === 200 && w.db.t.posts[0].status === "pending" && r.body.message === P.MESSAGES.editPending &&
    w.db.t.moderation_queue.some(q => q.object_id === pid(1)), J(r.body));
  r = await P.deletePost(w.deps, THEM, pid(1));
  const r2 = await P.deletePost(w.deps, ME, pid(1));
  check("E4. only its author deletes it: status removed, removed_at, removed_reason author", r.status === 404 && r2.status === 200 && w.db.t.posts[0].status === "removed" &&
    w.db.t.posts[0].removed_reason === "author" && w.db.t.posts[0].removed_at === NOW0);

  /* ── F ── */
  console.log("\n══ F. Talk ══");
  w = world({ member_mutes: [{ muter_id: OTHER, muted_id: MUTED }], member_blocks: [{ blocker_id: OTHER, blocked_id: BLOCKER }] });
  w.db.t.posts.push(post(pid(1), ME));
  const say = async (who, body, parent) => P.addComment(w.deps, who, pid(1), { body, parent_id: parent });
  w.setNow("2026-11-20T12:00:01.000Z"); const c1 = await say(THEM, "First!");
  w.setNow("2026-11-20T12:00:02.000Z"); const c2 = await say(OTHER, "Reply to Tom", c1.body.comment.id);
  w.setNow("2026-11-20T12:00:03.000Z"); const c3 = await say(FAN, "Reply to Olga", c2.body.comment.id);
  w.setNow("2026-11-20T12:00:04.000Z"); await say(MUTED, "Muted words");
  w.setNow("2026-11-20T12:00:05.000Z"); await say(BLOCKER, "Blocked words");
  check("F1. one level: a reply to a reply joins the top comment", c2.body.comment.parent_id === c1.body.comment.id && c3.body.comment.parent_id === c1.body.comment.id, J([c2.body, c3.body]));
  let list = await P.listComments(w.deps, OTHER, pid(1));
  check("F2. oldest first; a muted or blocked member's comments are left out for the viewer", J(list.body.comments.map(c => c.body)) === J(["First!", "Reply to Tom", "Reply to Olga"]), J(list.body.comments.map(c => c.body)));
  check("F3. the count is the post's own, kept by the trigger", list.body.comment_count === 5 && w.db.t.posts[0].comment_count === 5);
  r = await say(THEM, "x".repeat(1001));
  check("F4. 1000 characters at most; empty is refused", r.status === 400 && r.body.error === P.MESSAGES.commentLong && (await say(THEM, "   ")).status === 400);
  await P.deleteComment(w.deps, THEM, c1.body.comment.id);
  list = await P.listComments(w.deps, ME, pid(1));
  const top = list.body.comments[0];
  check("F5. a deleted comment is a tombstone, \"[deleted]\" with no author, and its replies stay", top.deleted === true && top.body === "[deleted]" && top.author === null &&
    list.body.comments.filter(c => c.parent_id === c1.body.comment.id).length === 2);
  r = await P.hideComment(w.deps, THEM, c2.body.comment.id);
  const r3 = await P.hideComment(w.deps, ME, c2.body.comment.id);
  check("F6. only the post's author hides a comment on it", r.status === 404 && r3.status === 200 && w.db.t.post_comments.find(c => c.id === c2.body.comment.id).status === "hidden");
  check("F7. a hidden comment is gone from Talk", (await P.listComments(w.deps, ME, pid(1))).body.comments.every(c => c.id !== c2.body.comment.id));
  w = world();
  w.db.t.posts.push(post(pid(1), ME));
  for (let i = 0; i < 60; i++) w.db.t.post_comments.push({ id: pid(500 + i), post_id: pid(1), author_id: THEM, parent_id: null, body: "c", status: "published", created_at: "2026-11-20T11:30:00.000Z" });
  r = await P.addComment(w.deps, THEM, pid(1), { body: "61st" });
  check("F8. 60 an hour: the 61st is 429", r.status === 429 && r.body.reason === "rate_limited");

  /* ── G ── */
  console.log("\n══ G. notices ══");
  w = world();
  w.db.t.posts.push(post(pid(1), ME));
  await P.like(w.deps, THEM, pid(1), true);
  w.setNow("2026-11-20T12:10:00.000Z");
  await P.like(w.deps, OTHER, pid(1), true);
  const likes = w.db.t.notifications.filter(n => n.type === "like");
  check("G1. likes within the hour are one notice, its text counting the others, pushed once", likes.length === 1 && likes[0].message === "OLGA and 1 other liked your post." &&
    likes[0].actor_id === OTHER && likes[0].object_type === "post" && likes[0].object_id === pid(1) && w.pushes.length === 1, J(likes));
  w.setNow("2026-11-20T13:30:00.000Z");
  await P.like(w.deps, FAN, pid(1), true);
  check("G2. a like after the hour starts a new notice", w.db.t.notifications.filter(n => n.type === "like").length === 2 && w.pushes.length === 2);
  const own = world();
  own.db.t.posts.push(post(pid(1), ME));
  await P.like(own.deps, ME, pid(1), true);
  check("G3. liking your own post tells no one", own.db.t.notifications.length === 0 && own.pushes.length === 0 && own.db.t.posts[0].like_count === 1);
  const c = await P.addComment(w.deps, THEM, pid(1), { body: "Lovely" });
  await P.addComment(w.deps, OTHER, pid(1), { body: "Agreed", parent_id: c.body.comment.id });
  const kinds = w.db.t.notifications.filter(n => n.type !== "like").map(n => n.type + ">" + n.user_id.slice(0, 2));
  check("G4. a comment tells the post's author; a reply tells the comment's author and the post's author", J(kinds) === J(["comment>11", "reply>22", "comment>11"]), J(kinds));
  check("G5. each notice links to the post's Talk", w.db.t.notifications.filter(n => n.type !== "like").every(n => n.link === "/home.html?post=" + pid(1) + "&talk=1"));

  /* ── H ── */
  console.log("\n══ H. moderation ══");
  w = world();
  w.db.t.posts.push(post(pid(1), ME, { status: "pending", published_at: null }), post(pid(2), ME), post(pid(3), ME, { status: "removed", removed_reason: "author" }));
  const k = await P.applyDecision(w.db.client, { object_type: "post", object_id: pid(1) }, "kept", NOW0);
  check("H1. kept publishes a held post, with published_at", k.published === true && w.db.t.posts[0].status === "published" && w.db.t.posts[0].published_at === NOW0);
  await P.applyDecision(w.db.client, { object_type: "post", object_id: pid(2) }, "removed", NOW0);
  check("H2. removed removes it (removed_reason moderation)", w.db.t.posts[1].status === "removed" && w.db.t.posts[1].removed_reason === "moderation");
  const kd = await P.applyDecision(w.db.client, { object_type: "post", object_id: pid(3) }, "kept", NOW0);
  check("H3. kept never brings back a post its author deleted", kd.changed === false && w.db.t.posts[2].status === "removed");

  /* ── I ── */
  console.log("\n══ I. the routes ══");
  const S = FILES[SERVER];
  // NAMED (Nov 20 2026, P3-1): BEFORE making a post and a post photo needed an active plan (requireActiveSubscription). AFTER both are free.
  const ROUTES = [["post", "/api/posts", "requireAuth, postRoute("], ["post", "/api/posts/photos", "requireAuth, postPhotoLimiter,"],
    ["get", "/api/posts/saved", "requireAuth, postRoute("], ["get", "/api/posts/:id", "requireAuth, postRoute("], ["patch", "/api/posts/:id", "requireAuth, postRoute("],
    ["delete", "/api/posts/:id", "requireAuth, postRoute("], ["get", "/api/posts/:id/comments", "requireAuth, postRoute("], ["post", "/api/posts/:id/comments", "requireAuth, postRoute("],
    ["delete", "/api/comments/:id", "requireAuth, postRoute("], ["post", "/api/comments/:id/hide", "requireAuth, postRoute("], ["get", "/api/feed/following", "requireAuth, postRoute("]];
  const missing = ROUTES.filter(([m, p, mw]) => !has(S, "app." + m + "(\"" + p + "\", " + mw));
  check("I1. each route is there with its sign-in; making a post and a post photo are free (sign-in only)", missing.length === 0 && !has(S, 'app.post("/api/posts", requireAuth, requireActiveSubscription') && !has(S, 'app.post("/api/posts/photos", requireAuth, requireActiveSubscription'), J(missing));
  check("I2. the routes pass the server's own pieces: the claims screen, ownerPagePublic, Web Push",
    has(S, "  return { sb: supabase, now: nowIso, claims: blueskyClaimsRefusal, ownerPublic: ownerPagePublic, push: sendPushToUser, env: process.env };"));
  check("I3. a member's posts answer a visitor not signed in, with a signed-in viewer's blocks applied (viewerIdFrom)",
    has(S, 'app.get("/api/posts/by/:userId", postRoute(async function (req) {\n  return require("./lib/posts").postsByAuthor(postDeps(), await viewerIdFrom(req), req.params.userId, req.query.cursor);'));
  check("I4. no emoji in lib/posts.js or this check", !/\p{Extended_Pictographic}/u.test(FILES[POSTS] + require("fs").readFileSync(__filename, "utf8")));

  T.finish();
})().catch(e => { check("the check ran to the end", false, e && (e.stack || e.message || JSON.stringify(e))); T.finish(); });
