"use strict";
/* ═══════════════════════════════════════════════════════════════════════════
   checkSocialGraph.js — Follow, Like, Save and Share (P2-3, Nov 20 2026;
   migration 194; lib/posts.js, server.js, lib/yourData.js, lib/backup.js).

   The rules run against an in-memory database (scripts/_p23Db.js) that keeps
   migration 194's primary keys and its counters (posts_count_bump).

   WHAT THIS PROVES
     A. FOLLOW: by id or by handle (with or without @); yourself 400; nobody
        404; a block either way 404 not_available and no row; following twice
        is one row and one notice; the notice is type follow (object_type
        follow, object_id the follower, a link to their page) with one push;
        100 a day; unfollow removes only the member's own row.
     B. A BLOCK ENDS THE FOLLOWS: POST /api/blocks removes the follows between
        the two, both ways, and no one else's.
     C. COUNTS AND LISTS: followers and following, i_follow, follows_me and
        self; a page that is not public answers 404 to others but not to its
        owner; members the viewer blocked are left out of both; the lists page
        50 at a time and only answer "followers" or "following".
     D. LIKE, SAVE, SHARE: the counts move by the trigger, once per member (a
        second like is not a second row); unlike and unsave take it back; a
        share counts once per member per post per UTC day; a post the member
        may not see (followers only, pending, blocked) is 404 and nothing is
        written; 200 likes an hour; Saved is the member's own, newest first.
     E. MIGRATION 194: the five tables with their keys, the not-yourself rule,
        the 1000-character comment rule, the four counters, row level
        security on and every grant revoked (only the server reads them).
     F. THE MEMBER'S DATA: Your data lists and deletes them (a comment becomes
        a tombstone), the backup takes them (not the share tally), and
        GET /api/notifications leaves out a muted member's notices.
     G. NAMED (Nov 21 2026, P3-1B, the owner's rule): COMMENTS. A free account
        comments only on posts by other free accounts (and on its own); on a
        paid member's post it is 403 with the members panel and one sentence,
        and nothing is written; GET .../comments tells the app (can_comment,
        comment_rule); a member comments anywhere they can see.
        NAMED (Nov 22 2026, FX3): before an attempt Talk shows lib/membership.js
        TALK_MEMBERS_ONLY (one source, sent by the server, never copied into
        the app) with Join; the refusal after an attempt keeps its own
        sentence; a member sees neither.

   MUTATE=<name> applies one mutation in memory; MUTATE=all runs each.
   ═══════════════════════════════════════════════════════════════════════════ */
const H = require("./_p21Harness");
const { memDb } = require("./_p23Db");

const SERVER = "@server.js", POSTS = "@lib/posts.js", MIG = "@supabase/migrations/194_social_graph.sql", YD = "@lib/yourData.js", BK = "@lib/backup.js";
const MEMB = "@lib/membership.js", FEED = "scripts/bf-feed.js";   // NAMED (Nov 22 2026, FX3)
const MUTATIONS = {
  "follow-across-block": [[POSTS, "  if (await SF.blockedEitherWay(deps.sb, viewerId, target)) return notAvailable();\n", ""]],
  "follow-self": [[POSTS, "  if (target === viewerId) return fail(400, MESSAGES.self);\n", ""]],
  "follows-unlimited": [[POSTS, ">= FOLLOWS_PER_DAY)", ">= 1e9)"]],
  "follow-no-notice": [[POSTS, '      await notice(deps, { user_id: target, type: "follow"', '      if (false) await notice(deps, { user_id: target, type: "follow"']],
  "unfollow-anyones": [[POSTS, '  var del = await deps.sb.from("follows").delete().eq("follower_id", viewerId).eq("following_id", targetId);', '  var del = await deps.sb.from("follows").delete().eq("following_id", targetId);']],
  "unfollow-one-way": [[POSTS, '",following_id.eq." + b + "),and(follower_id.eq." + b + ",following_id.eq." + a + ")")', '",following_id.eq." + b + ")")']],
  "block-keeps-follows": [[SERVER, '      if (table === "member_blocks") await require("./lib/posts").unfollowBoth(supabase, req.user.id, target);\n', ""]],
  "counts-show-blocked": [[POSTS, "return f.following_id === userId && !ctx.blocked.has(f.follower_id);", "return f.following_id === userId;"]],
  "private-counts": [[POSTS, "  if (ctx.viewer && await SF.blockedEitherWay(deps.sb, ctx.viewer, userId)) return false;\n  return authorPublic(deps, ctx, userId);", "  if (ctx.viewer && await SF.blockedEitherWay(deps.sb, ctx.viewer, userId)) return false;\n  return true;"]],
  "like-unseen-post": [[POSTS, '  if (!(await canSee(deps, ctx, post)) || post.status !== "published") return notAvailable();\n  var added = false;', "  if (!post) return notAvailable();\n  var added = false;"]],
  "likes-unlimited": [[POSTS, ">= LIKES_PER_HOUR)", ">= 1e9)"]],
  "share-every-time": [[POSTS, "{ post_id: post.id, user_id: ctx.viewer, day: day }", "{ post_id: post.id, user_id: ctx.viewer, day: now(deps) }"]],
  "migration-no-self-rule": [[MIG, "  CHECK (follower_id <> following_id);", "  CHECK (true);"]],
  "migration-rls-off": [[MIG, "ALTER TABLE public.post_saves ENABLE ROW LEVEL SECURITY;\n", ""]],
  "notices-show-muted": [[SERVER, "(blockedSet.has(n.actor_id) || mutedNoticeSet.has(n.actor_id))", "blockedSet.has(n.actor_id)"]],
  "yourdata-no-follows": [[YD, '  { table: "follows", group: "profile",', '  { table: "follows_gone", group: "profile",']],
  // NAMED (Nov 21 2026, P3-1B): the comment rule (section G)
  "free-comments-member-post": [[POSTS, "  if (rule) return membersOnly(deps, rule, \"members_only\");\n", ""]],
  "free-blocked-on-free": [[POSTS, "  if ((await tierOf(deps, post.author_id)) !== \"member\") return null;\n", ""]],
  // NAMED (Nov 22 2026, FX3): Talk before an attempt (section G4, G6-G8)
  "talk-rule-is-refusal": [[POSTS, "comment_rule: rule ? require(\"./membership\").TALK_MEMBERS_ONLY : null", "comment_rule: rule"]],
  "talk-rule-for-members": [[POSTS, "comment_rule: rule ? require(\"./membership\").TALK_MEMBERS_ONLY : null", "comment_rule: require(\"./membership\").TALK_MEMBERS_ONLY"]],
  "refusal-is-talk": [[POSTS, "  if (rule) return membersOnly(deps, rule, \"members_only\");\n", "  if (rule) return membersOnly(deps, require(\"./membership\").TALK_MEMBERS_ONLY, \"members_only\");\n"]],
  "talk-wording-changed": [[MEMB, "const TALK_MEMBERS_ONLY = \"Comments on members' posts are for members. Join to add yours.\";", "const TALK_MEMBERS_ONLY = \"Comments on members' posts are for members.\";"]],
  "talk-copied-in-feed": [[FEED, "      if (r.body.can_comment === false) talkRule(r.body.comment_rule);", "      if (r.body.can_comment === false) talkRule(r.body.comment_rule || \"Comments on members' posts are for members. Join to add yours.\");"]],
  "feed-ignores-rule": [[FEED, "      if (r.body.can_comment === false) talkRule(r.body.comment_rule);", "      if (r.body.can_comment === false) talkRule(null);"]],
  "feed-no-join": [[FEED, "      '<a class=\"bfp-send bfp-tm-join\" href=\"/billing.html\">Join</a></div>';", "      '</div>';"]],
  "feed-refusal-replaced": [[FEED, "if (r.body && r.body.reason === \"members_only\") { talkRule(r.body.error); return; }", "if (r.body && r.body.reason === \"members_only\") { talkRule(talkState.rule); return; }"]]
  // (no mutant for commentRule's own-post line: a free viewer's own post has a free author, so the next line answers the same)
};
const T = H.setup(__filename, MUTATIONS, [SERVER, POSTS, MIG, YD, BK, MEMB, FEED]);
const { FILES, check, J, has } = T;
const P = T.libRequire("./lib/posts");

const ME = "11111111-1111-4111-8111-111111111111", THEM = "22222222-2222-4222-8222-222222222222", OTHER = "33333333-3333-4333-8333-333333333333";
const PRIV = "55555555-5555-4555-8555-555555555555", FAN = "88888888-8888-4888-8888-888888888888", BLOCKER = "99999999-9999-4999-8999-999999999999";
const GHOST = "77777777-7777-4777-8777-777777777777";
const NOW0 = "2026-11-20T12:00:00.000Z", OLD = "2026-01-01T00:00:00.000Z";
const PUBLIC = new Set([ME, THEM, OTHER, FAN, BLOCKER]);

function world(extra) {
  const names = { [ME]: "rose", [THEM]: "tom", [OTHER]: "olga", [PRIV]: "pat", [FAN]: "fay", [BLOCKER]: "bea" };
  const db = memDb(Object.assign({
    users: Object.keys(names).map(id => ({ id, created_at: OLD })), profiles: [],
    bf_profiles: Object.keys(names).map(id => ({ user_id: id, username: names[id], display_name: names[id].toUpperCase(), avatar_url: null })),
    posts: [], post_media: [], post_likes: [], post_saves: [], post_share_days: [], post_comments: [], notifications: [], moderation_queue: [],
    follows: [], member_blocks: [], member_mutes: []
  }, extra || {}));
  const pushes = [];
  let clock = NOW0;
  const deps = { sb: db.client, now: () => clock, claims: () => null, ownerPublic: async id => PUBLIC.has(id), push: async (u, p) => { pushes.push([u, p]); }, env: {} };
  return { db, deps, pushes, setNow: v => { clock = v; } };
}
const pid = n => "aaaaaaaa-0000-4000-8000-" + String(n).padStart(12, "0");
const post = (id, author, extra) => Object.assign({ id, author_id: author, kind: "text", body: "Hi", audience: "public", status: "published", like_count: 0, comment_count: 0, save_count: 0, share_count: 0,
  created_at: "2026-11-19T10:00:00.000Z", published_at: "2026-11-19T10:00:00.000Z" }, extra || {});
const f = (a, b, at) => ({ follower_id: a, following_id: b, created_at: at || OLD });

(async function main() {
  /* ── A ── */
  console.log("\n══ A. follow ══");
  let w = world({ member_blocks: [{ blocker_id: BLOCKER, blocked_id: ME }] });
  let r = await P.follow(w.deps, ME, { user_id: THEM });
  check("A1. by id: 201, one row, following true", r.status === 201 && r.body.following === true && w.db.t.follows.length === 1 && w.db.t.follows[0].follower_id === ME && w.db.t.follows[0].following_id === THEM);
  r = await P.follow(w.deps, ME, { handle: "@OLGA" });
  check("A2. by handle, with @ and in any case", r.status === 201 && r.body.user_id === OTHER);
  r = await P.follow(w.deps, ME, { user_id: ME });
  check("A3. yourself: 400 \"You can't follow yourself.\"", r.status === 400 && r.body.error === P.MESSAGES.self);
  r = await P.follow(w.deps, ME, { user_id: GHOST });
  const r2 = await P.follow(w.deps, ME, { handle: "nobody_here" });
  check("A4. nobody: 404", r.status === 404 && r2.status === 404 && r.body.error === P.MESSAGES.noMember);
  const nb = w.db.t.follows.length;
  r = await P.follow(w.deps, ME, { user_id: BLOCKER });
  const rb = await P.follow(w.deps, BLOCKER, { user_id: ME });
  check("A5. a block either way: 404 not_available, no row", r.status === 404 && r.body.reason === "not_available" && rb.status === 404 && w.db.t.follows.length === nb);
  await P.follow(w.deps, ME, { user_id: THEM });
  const fn = w.db.t.notifications.filter(n => n.type === "follow" && n.user_id === THEM);
  check("A6. following twice is one row and one notice", w.db.t.follows.filter(x => x.following_id === THEM).length === 1 && fn.length === 1);
  check("A7. the notice: type follow, object_type follow, object_id the follower, a link to their page, one push",
    fn[0] && fn[0].actor_id === ME && fn[0].object_type === "follow" && fn[0].object_id === ME && fn[0].link === "/@rose" && fn[0].message === "ROSE started following you." &&
    w.pushes.filter(p => p[0] === THEM).length === 1, J(fn));
  w = world({ follows: Array.from({ length: 100 }, (_, i) => f(ME, "bbbbbbbb-0000-4000-8000-" + String(i).padStart(12, "0"), "2026-11-20T0" + (i % 10) + ":00:00.000Z")) });
  r = await P.follow(w.deps, ME, { user_id: THEM });
  check("A8. 100 a day: the 101st is 429", r.status === 429 && r.body.reason === "rate_limited");
  w = world({ follows: [f(ME, THEM), f(OTHER, THEM)] });
  r = await P.unfollow(w.deps, ME, THEM);
  check("A9. unfollow removes only the member's own row", r.status === 200 && r.body.following === false && J(w.db.t.follows.map(x => x.follower_id)) === J([OTHER]));

  /* ── B ── */
  console.log("\n══ B. a block ends the follows ══");
  w = world({ follows: [f(ME, THEM), f(THEM, ME), f(OTHER, THEM), f(ME, OTHER)] });
  await P.unfollowBoth(w.db.client, ME, THEM);
  check("B1. unfollowBoth removes both directions between the two and no one else's", J(w.db.t.follows.map(x => x.follower_id + ">" + x.following_id).sort()) === J([ME + ">" + OTHER, OTHER + ">" + THEM].sort()),
    J(w.db.t.follows));
  const S = FILES[SERVER] || "";
  const addAt = S.indexOf("function safetyAdd(table, mine, theirs, flag) {");
  const blockRoute = addAt === -1 ? "" : S.slice(addAt, S.indexOf("\nfunction safetyRemove(", addAt));
  check("B2. POST /api/blocks (safetyAdd) calls it once the block is saved, and not for a mute", has(S, 'app.post("/api/blocks", requireAuth, blockLimiter, safetyAdd("member_blocks",') &&
    blockRoute.indexOf("if (saved.error) throw saved.error;") < blockRoute.indexOf("unfollowBoth") && has(blockRoute, 'if (table === "member_blocks") await require("./lib/posts").unfollowBoth(supabase, req.user.id, target);'));

  /* ── C ── */
  console.log("\n══ C. counts and lists ══");
  w = world({ follows: [f(ME, THEM), f(OTHER, THEM), f(FAN, THEM), f(THEM, ME), f(PRIV, THEM)], member_blocks: [{ blocker_id: ME, blocked_id: FAN }] });
  r = await P.followCounts(w.deps, ME, THEM);
  check("C1. followers and following, i_follow and follows_me; a member the viewer blocked is left out", r.status === 200 && r.body.followers === 3 && r.body.following === 1 &&
    r.body.i_follow === true && r.body.follows_me === true && r.body.self === false, J(r.body));
  r = await P.followCounts(w.deps, null, THEM);
  check("C2. a visitor not signed in gets the counts of a public page, with no i_follow", r.status === 200 && r.body.followers === 4 && r.body.i_follow === false);
  r = await P.followCounts(w.deps, ME, PRIV);
  const own = await P.followCounts(w.deps, PRIV, PRIV);
  check("C3. a page that is not public: 404 to others, its owner still sees their own", r.status === 404 && own.status === 200 && own.body.self === true);
  r = await P.followCounts(w.deps, FAN, ME);
  check("C4. across a block: 404", r.status === 404);
  const fl = await P.followList(w.deps, ME, THEM, "followers");
  check("C5. the followers list: names and links, the viewer's own follow marked, the blocked member left out", fl.status === 200 &&
    J(fl.body.people.map(p => p.username).sort()) === J(["olga", "pat", "rose"]) && fl.body.people.find(p => p.user_id === ME).self === true, J(fl.body.people.map(p => p.username)));
  check("C6. only followers or following", (await P.followList(w.deps, ME, THEM, "friends")).status === 404 && (await P.followList(w.deps, ME, THEM, "following")).body.people.length === 1);
  w = world({ follows: Array.from({ length: 60 }, (_, i) => f("cccccccc-0000-4000-8000-" + String(i).padStart(12, "0"), THEM, new Date(Date.UTC(2026, 9, 1) + i * 60000).toISOString())) });
  const p1 = await P.followList(w.deps, ME, THEM, "followers");
  const p2 = await P.followList(w.deps, ME, THEM, "followers", p1.body.next_cursor);
  check("C7. 50 a page, then the rest, newest first, none twice", p1.body.people.length === 50 && p2.body.people.length === 10 && !p2.body.next_cursor &&
    new Set(p1.body.people.concat(p2.body.people).map(p => p.user_id)).size === 60);

  /* ── D ── */
  console.log("\n══ D. like, save, share ══");
  w = world({ follows: [f(FAN, ME)], member_blocks: [{ blocker_id: BLOCKER, blocked_id: ME }] });
  w.db.t.posts.push(post(pid(1), ME), post(pid(2), ME, { audience: "followers" }), post(pid(3), ME, { status: "pending", published_at: null }));
  r = await P.like(w.deps, THEM, pid(1), true);
  await P.like(w.deps, THEM, pid(1), true);
  check("D1. a like moves like_count by one, and liking again is not a second like", r.status === 200 && r.body.liked === true && w.db.t.posts[0].like_count === 1 && w.db.t.post_likes.length === 1);
  r = await P.like(w.deps, THEM, pid(1), false);
  check("D2. unlike takes it back", r.body.liked === false && w.db.t.posts[0].like_count === 0 && w.db.t.post_likes.length === 0);
  await P.save(w.deps, THEM, pid(1), true);
  check("D3. a save moves save_count", w.db.t.posts[0].save_count === 1);
  const n0 = w.db.writes().length;
  const nope = [await P.like(w.deps, OTHER, pid(2), true), await P.like(w.deps, THEM, pid(3), true), await P.like(w.deps, BLOCKER, pid(1), true), await P.save(w.deps, OTHER, pid(2), true)];
  check("D4. a post the member may not see (followers only, pending, across a block) is 404, and nothing is written", nope.every(x => x.status === 404) && w.db.writes().length === n0, J(nope.map(x => x.status)));
  check("D5. a follower may like a followers-only post", (await P.like(w.deps, FAN, pid(2), true)).status === 200 && w.db.t.posts[1].like_count === 1);
  await P.share(w.deps, THEM, pid(1));
  r = await P.share(w.deps, THEM, pid(1));
  check("D6. a share counts once per member per post per day; the answer carries the link", r.status === 200 && r.body.share_count === 1 && r.body.link === "/p/" + pid(1) && w.db.t.post_share_days.length === 1);
  w.setNow("2026-11-21T09:00:00.000Z");
  r = await P.share(w.deps, THEM, pid(1));
  check("D7. the next UTC day counts again", r.body.share_count === 2 && w.db.t.post_share_days.map(x => x.day).join(",") === "2026-11-20,2026-11-21");
  w = world({ post_likes: Array.from({ length: 200 }, (_, i) => ({ post_id: "dddddddd-0000-4000-8000-" + String(i).padStart(12, "0"), user_id: THEM, created_at: "2026-11-20T11:30:00.000Z" })) });
  w.db.t.posts.push(post(pid(1), ME));
  r = await P.like(w.deps, THEM, pid(1), true);
  check("D8. 200 likes an hour: the 201st is 429, and nothing is written", r.status === 429 && r.body.reason === "rate_limited" && w.db.t.posts[0].like_count === 0);
  w = world();
  w.db.t.posts.push(post(pid(1), ME), post(pid(2), THEM), post(pid(3), OTHER, { status: "removed" }));
  w.setNow("2026-11-20T10:00:00.000Z"); await P.save(w.deps, FAN, pid(1), true);
  w.setNow("2026-11-20T11:00:00.000Z"); await P.save(w.deps, FAN, pid(2), true);
  w.db.t.post_saves.push({ post_id: pid(3), user_id: FAN, created_at: "2026-11-20T11:30:00.000Z" }, { post_id: pid(1), user_id: ME, created_at: "2026-11-20T11:40:00.000Z" });
  r = await P.savedPosts(w.deps, FAN);
  check("D9. Saved: the member's own saves, newest first, never a removed post", J(r.body.posts.map(p => p.id)) === J([pid(2), pid(1)]) && r.body.posts.every(p => p.saved === true), J(r.body.posts.map(p => p.id)));

  /* ── E ── */
  console.log("\n══ E. migration 194 ══");
  const M = FILES[MIG] || "";
  check("E1. the five tables and their keys", ["follows", "post_likes", "post_saves", "post_comments", "post_share_days"].every(t => has(M, "CREATE TABLE IF NOT EXISTS public." + t + " (")) &&
    has(M, "PRIMARY KEY (follower_id, following_id)") && (M.match(/PRIMARY KEY \(post_id, user_id\)/g) || []).length === 2 && has(M, "PRIMARY KEY (post_id, user_id, day)"));
  check("E2. no one follows themself; a comment is 1 to 1000 characters with a known status", has(M, "  CHECK (follower_id <> following_id);") && has(M, "  CHECK (char_length(body) BETWEEN 1 AND 1000);") &&
    has(M, "  CHECK (status IN ('published','hidden','removed','deleted'));"));
  check("E3. the four counters, each moved by its own trigger, never below 0", has(M, "SET %I = GREATEST(0, %I + $1) WHERE id = $2") &&
    ["post_likes_count", "post_saves_count", "post_shares_count", "post_comments_count"].every(t => has(M, "CREATE TRIGGER " + t + " AFTER INSERT OR DELETE ON public.")));
  const tables = ["follows", "post_likes", "post_saves", "post_comments", "post_share_days"];
  check("E4. row level security on and every grant revoked: only the server reads them", tables.every(t => has(M, "ALTER TABLE public." + t + " ENABLE ROW LEVEL SECURITY;") && has(M, "REVOKE ALL ON public." + t + " FROM anon, authenticated;")) &&
    !/CREATE POLICY/i.test(M) && /^BEGIN;/m.test(M) && /^COMMIT;/m.test(M));
  check("E5. paste-safe: no \"<=\" or \">=\" in it", M.indexOf("<=") === -1 && M.indexOf(">=") === -1);

  /* ── F ── */
  console.log("\n══ F. the member's data ══");
  const Y = T.libRequire("./lib/yourData");
  const entry = t => (Y.DATA || []).find(e => e.table === t);
  check("F1. Your data lists the follows both ways, the likes, saves, share tally (not exported), posts, their photos and comments",
    entry("follows") && J(entry("follows").owner) === J(["follower_id", "following_id"]) && entry("post_likes") && entry("post_saves") && entry("post_share_days") && entry("post_share_days").export === false &&
    entry("posts") && entry("post_media") && entry("post_comments"));
  check("F2. deleting an account tombstones its comments (the replies stay) and deletes the rest, comments first",
    entry("post_comments") && entry("post_comments").onDelete === "comment" && Y.DELETE_ORDER.indexOf("post_comments") !== -1 && Y.DELETE_ORDER.indexOf("post_comments") < Y.DELETE_ORDER.indexOf("posts") &&
    Y.DELETE_ORDER.indexOf("follows") !== -1 && Y.DELETE_ORDER.indexOf("post_media") < Y.DELETE_ORDER.indexOf("posts"));
  const B = T.libRequire("./lib/backup");
  check("F3. the backup takes posts, their photos, follows, likes, saves and comments; the share tally is excluded",
    ["posts", "post_media", "follows", "post_likes", "post_saves", "post_comments"].every(t => B.BACKUP_TABLES.indexOf(t) !== -1) && !!B.EXCLUDED_TABLES.post_share_days);
  const notices = H.routeStatement(FILES[SERVER], "get", "/api/notifications") || "";
  check("F4. GET /api/notifications leaves out notices from a member the viewer blocked or muted",
    has(notices, "(blockedSet.has(n.actor_id) || mutedNoticeSet.has(n.actor_id))") && has(notices, 'const mutedNoticeSet = await require("./lib/safety").mutedIds(supabase, req.user.id);'));


  /* ── G (NAMED, Nov 21 2026, P3-1B, the owner's rule) ── */
  console.log("\n══ G. comments: a free account comments on free accounts' posts only ══");
  {
    const RULE = T.libRequire("./lib/membership").FREE_RULES.comment_member_post;
    const TALK = T.libRequire("./lib/membership").TALK_MEMBERS_ONLY;   // NAMED (Nov 22 2026, FX3)
    const PANEL = { title: "Members get this" };
    const FREE_IDS = new Set([FAN, OTHER]);   // ME and THEM are paid members
    const gw = world({ posts: [post(pid(81), ME), post(pid(82), OTHER), post(pid(83), FAN)] });
    gw.deps.tierOf = async id => (FREE_IDS.has(id) ? "free" : "member");
    gw.deps.membersPanel = () => PANEL;
    let g = await P.addComment(gw.deps, FAN, pid(81), { body: "Lovely bread" });
    const g1Refusal = g.body && g.body.error;   // NAMED (Nov 22 2026, FX3): G7
    check("G1. a free account on a paid member's post: 403 members_only, the owner's sentence and the members panel, nothing written",
      g.status === 403 && g.body.reason === "members_only" && g.body.error === RULE && J(g.body.members_panel) === J(PANEL) && gw.db.t.post_comments.length === 0, J(g));
    g = await P.addComment(gw.deps, FAN, pid(82), { body: "Same here" });
    const g2 = await P.addComment(gw.deps, FAN, pid(83), { body: "My own post" });
    check("G2. ...on another free account's post, and on its own, it comments", g.status === 201 && g2.status === 201 && gw.db.t.post_comments.length === 2, J([g.status, g2.status]));
    g = await P.addComment(gw.deps, THEM, pid(81), { body: "Member to member" });
    const g3 = await P.addComment(gw.deps, ME, pid(82), { body: "Member on a free post" });
    check("G3. a member comments on a member's post and on a free account's", g.status === 201 && g3.status === 201, J([g.status, g3.status]));
    const lf = await P.listComments(gw.deps, FAN, pid(81)), lm = await P.listComments(gw.deps, THEM, pid(81)), lo = await P.listComments(gw.deps, FAN, pid(82));
    // NAMED (Nov 22 2026, FX3): BEFORE comment_rule === RULE (the refusal itself). AFTER the sentence for before an attempt.
    check("G4. the comments list tells the app: can_comment false and the before-an-attempt sentence for a free account on a member's post; true and no sentence otherwise (a member sees none)",
      lf.status === 200 && lf.body.can_comment === false && lf.body.comment_rule === TALK && lf.body.comments.length === 1 &&
      lm.body.can_comment === true && lm.body.comment_rule === null && lo.body.can_comment === true, J([lf.body.can_comment, lf.body.comment_rule, lm.body.can_comment, lo.body.can_comment]));
    check("G5. the sentence says what is allowed instead", /for members/.test(RULE) && /posts by other free accounts/.test(RULE) && /Nothing was posted\.$/.test(RULE), RULE);
    /* NAMED (Nov 22 2026, FX3): Talk before an attempt. */
    const WANT = "Comments on members' posts are for members. Join to add yours.";
    const REFUSAL = "Comments on members' posts are for members. You can comment on posts by other free accounts. Nothing was posted.";
    const fsx = require("fs"), px = require("path");
    const frontFiles = [];
    [".", "scripts"].forEach(d => { try { fsx.readdirSync(px.join(H.FRONTEND, d)).filter(n => /[.](js|html)$/.test(n)).forEach(n => frontFiles.push(d === "." ? n : d + "/" + n)); } catch (e) {} });
    const copies = frontFiles.filter(n => /Join to add yours/.test((n === FEED ? FILES[FEED] : fsx.readFileSync(px.join(H.FRONTEND, n), "utf8")) || ""));
    const backCopies = [SERVER, POSTS].filter(k => /Join to add yours/.test(FILES[k] || ""));
    check("G6. the Talk sentence is said once, in lib/membership.js, word for word; no copy in server.js, lib/posts.js or any frontend page or script (" + frontFiles.length + " read)",
      TALK === WANT && T.count(FILES[MEMB], WANT) === 1 && frontFiles.length > 50 && copies.length === 0 && backCopies.length === 0, J([TALK, copies, backCopies]));
    check("G7. the refusal after an attempt keeps its own sentence, word for word, and is not the Talk sentence", RULE === REFUSAL && g1Refusal === REFUSAL && RULE !== TALK, J([RULE, g1Refusal]));
    const FD = FILES[FEED] || "";
    check("G8. Talk (scripts/bf-feed.js) shows the server's sentence when can_comment is false, in the box with Join (billing.html) in place of the form; after a refused attempt, the server's refusal",
      T.has(FD, "      if (r.body.can_comment === false) talkRule(r.body.comment_rule);") &&
      T.has(FD, "<p class=\"bfp-tm-h\" id=\"bfpTalkRule\"></p>' +\n      '<a class=\"bfp-send bfp-tm-join\" href=\"/billing.html\">Join</a></div>';") &&
      T.has(FD, "    form.hidden = !!rule; box.hidden = !rule;\n    talk.querySelector(\"#bfpTalkRule\").textContent = rule || \"\";") &&
      T.has(FD, "if (r.body && r.body.reason === \"members_only\") { talkRule(r.body.error); return; }") && !/TALK_MEMBERS[^_]/.test(FD));
  }
  T.finish();
})().catch(e => { check("the check ran to the end", false, e && (e.stack || e.message || JSON.stringify(e))); T.finish(); });
