"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   The Inbox (P2-1, Nov 19 2026): messages, approvals and notifications in one
   place (inbox.html), and the rules its routes share.

   MESSAGES IN PAGES. A thread is read 50 messages at a time, newest first
   from the server and shown oldest first; "Earlier messages" asks for the 50
   before the oldest one shown (?before=<its created_at>). Nothing reads a
   whole thread at once any more. The conversation list is built from the
   newest CONVERSATION_SCAN messages the member sent or received, grouped by
   the other person; ?before=<the oldest scanned> reads the next stretch.

   UNREAD WITHOUT A NEW COLUMN. A message's notice (POST /api/messages) is a
   notification of type "message" with actor_id the sender and object_id the
   message (migration 190). A conversation's unread count is the member's
   unread "message" notices from that person; opening the thread marks them
   read (POST /api/inbox/read/:userId). The messages table itself is
   unchanged.

   NOTIFICATIONS THAT OPEN SOMETHING. link is a path on this site only (it
   starts with one "/", never "//", at most 300 characters), the same rule as
   migration 190's notifications_link_check, so a notice never sends a member
   off-site.
   ══════════════════════════════════════════════════════════════════════════ */

const THREAD_PAGE = 50;
const THREAD_PAGE_MAX = 100;
const CONVERSATION_SCAN = 500;
const NOTIFICATIONS_PAGE = 100;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LINK_RE = /^\/[^/]/;
const LINK_MAX = 300;
const OBJECT_TYPES = ["post", "comment", "message", "proposal", "listing", "order", "tip", "follow", "report", "review", "campaign"];

const RECEIVER_MISSING = "There is no member with that id. Nothing was sent.";
const NOTICE_MISSING = "That notification is not one of yours.";

function isUuid(value) { return typeof value === "string" && UUID_RE.test(value); }

/* A "before" cursor: an ISO time, or null for "from the newest". Anything
   else is { error } (a 400), never silently the newest. */
function parseBefore(raw) {
  if (raw === undefined || raw === null || raw === "") return { before: null };
  const s = String(raw);
  if (s.length > 40 || !/^\d{4}-\d{2}-\d{2}T[\d:.]+(Z|[+-]\d{2}:?\d{2})$/.test(s) || isNaN(Date.parse(s))) return { error: "before must be a time from an earlier page." };
  return { before: new Date(s).toISOString() };
}

function pageLimit(raw) {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1) return THREAD_PAGE;
  return Math.min(n, THREAD_PAGE_MAX);
}

/* A notification's link, or null when it is not a path on this site. */
function safeLink(link) {
  return typeof link === "string" && link.length <= LINK_MAX && LINK_RE.test(link) ? link : null;
}

/* The notice a new message leaves for its receiver. */
function messageNotice(receiverId, senderId, messageId) {
  return {
    user_id: receiverId,
    type: "message",
    title: "New message",
    message: "You received a new business message.",
    read: false,
    actor_id: senderId,
    object_type: "message",
    object_id: messageId,
    link: "/inbox.html?with=" + senderId
  };
}

/* The newest messages the member sent or received, as one row per other
   person, newest conversation first. rows are newest first. */
function groupConversations(rows, me, unreadByActor) {
  const seen = new Map();
  (rows || []).forEach(function (row) {
    const other = row.sender_id === me ? row.receiver_id : row.sender_id;
    if (!other || seen.has(other)) return;
    seen.set(other, {
      other_id: other,
      last_message: String(row.content || "").slice(0, 120),
      last_at: row.created_at,
      last_from_me: row.sender_id === me,
      unread: (unreadByActor && unreadByActor[other]) || 0
    });
  });
  return Array.from(seen.values());
}

/* Unread "message" notices, counted by who sent them. */
function unreadByActor(rows) {
  const out = {};
  (rows || []).forEach(function (r) { if (r && r.actor_id) out[r.actor_id] = (out[r.actor_id] || 0) + 1; });
  return out;
}

/* A thread page read newest first with one extra row: { messages (oldest
   first), has_more, next_before }. */
function threadPage(rowsNewestFirst, limit) {
  const rows = (rowsNewestFirst || []).slice();
  const hasMore = rows.length > limit;
  const page = rows.slice(0, limit).reverse();
  return { messages: page, has_more: hasMore, next_before: hasMore && page.length ? page[0].created_at : null };
}

/* What the Inbox shows of a person: their handle and name from bf_profiles,
   else the business name from profiles; their avatar. */
function personFrom(bf, legacy) {
  const b = bf || {}, l = legacy || {};
  return {
    username: b.username || null,
    name: b.display_name || l.business_name || l.full_name || (b.username ? "@" + b.username : "Member"),
    avatar_url: b.avatar_url || l.logo_url || null
  };
}

module.exports = {
  THREAD_PAGE, THREAD_PAGE_MAX, CONVERSATION_SCAN, NOTIFICATIONS_PAGE, UUID_RE, LINK_RE, LINK_MAX, OBJECT_TYPES,
  RECEIVER_MISSING, NOTICE_MISSING,
  isUuid, parseBefore, pageLimit, safeLink, messageNotice, groupConversations, unreadByActor, threadPage, personFrom
};
