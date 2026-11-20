"use strict";
/* ══════════════════════════════════════════════════════════════════════════
   Member handles (P2-1, Nov 19 2026).

   bf_profiles.username is THE handle: the /@handle address (_redirects sends
   it to seller.html?u=<handle>), the storefront, the support page, sending
   BizCash by username. Migration 189 holds the format in the database:

     bf_profiles_username_format  CHECK (username IS NULL OR
                                  username ~ '^[a-z0-9_][a-z0-9_-]{2,29}$')

   HANDLE_PATTERN below is that pattern character for character
   (scripts/checkHandles.js compares the two), so a handle this file accepts
   is one the database accepts. Three rules on top of the format:

     reserved   a handle in reserved_handles (migration 189: admin, bizforce,
                support, help, ...) is refused with a 409 and RESERVED_MESSAGE;
     taken      a handle another member holds is refused with a 409 and
                TAKEN_MESSAGE;
     the race   two members claiming the same free handle at the same moment
                both pass the "is it taken" read; the database's unique index
                on lower(username) (migration 040) lets one write through and
                refuses the other with Postgres error 23505. isUniqueViolation
                turns that refusal into the same 409 as "taken", never a 500.

   The legacy profiles.username (PUT /api/profile/me) follows the same rules,
   so the two never disagree about what a handle may be.
   ══════════════════════════════════════════════════════════════════════════ */

const HANDLE_PATTERN = "^[a-z0-9_][a-z0-9_-]{2,29}$";
const HANDLE_RE = new RegExp(HANDLE_PATTERN);
const HANDLE_MIN = 3;
const HANDLE_MAX = 30;

const FORMAT_MESSAGE = "A handle is 3 to 30 characters: lowercase letters, numbers, _ and -, not starting with -.";
const RESERVED_MESSAGE = "That handle is reserved for BizForce. Choose another.";
const TAKEN_MESSAGE = "That handle is already taken. Choose another.";

/* What a member typed, as a candidate handle: a leading @ dropped, lowercase,
   any other character a "-", runs of "-" made one, no "-" at either end. It
   is NOT cut short: a handle longer than 30 is refused by handleProblem, so a
   member is never given a handle they did not type. An empty answer means
   "no handle". */
function normalizeHandle(value) {
  return String(value == null ? "" : value)
    .trim()
    .replace(/^@+/, "")
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/* null when the handle has the database's format, else the sentence to show. */
function handleProblem(handle) {
  if (typeof handle !== "string" || handle.length < HANDLE_MIN || handle.length > HANDLE_MAX || !HANDLE_RE.test(handle)) return FORMAT_MESSAGE;
  return null;
}

/* Postgres's unique_violation: the second of two writes racing for one handle. */
function isUniqueViolation(error) {
  return !!error && (error.code === "23505" || /duplicate key value violates unique constraint/i.test(String(error.message || "")));
}

/* true when reserved_handles holds the handle. A failed read throws: an
   unknown answer never lets a reserved handle through. */
async function isReserved(supabase, handle) {
  const found = await supabase.from("reserved_handles").select("handle").eq("handle", handle).maybeSingle();
  if (found.error) throw found.error;
  return !!found.data;
}

/* The whole check for a handle a member is claiming, short of the write:
   { handle } when it may be written, { status, error, reason } when not. The
   write itself still meets the unique index; the caller turns its 23505 into
   { status: 409, error: TAKEN_MESSAGE } with isUniqueViolation. */
async function checkClaim(supabase, opts) {
  const handle = normalizeHandle(opts.raw);
  if (!handle) return { handle: null };
  const problem = handleProblem(handle);
  if (problem) return { status: 400, error: problem, reason: "handle_format" };
  if (await isReserved(supabase, handle)) return { status: 409, error: RESERVED_MESSAGE, reason: "handle_reserved" };
  const existing = await supabase.from(opts.table).select("user_id").ilike("username", handle.replace(/[\\%_]/g, "\\$&")).maybeSingle();
  if (existing.error) throw existing.error;
  if (existing.data && existing.data.user_id !== opts.userId) return { status: 409, error: TAKEN_MESSAGE, reason: "handle_taken" };
  return { handle: handle };
}

module.exports = {
  HANDLE_PATTERN, HANDLE_RE, HANDLE_MIN, HANDLE_MAX,
  FORMAT_MESSAGE, RESERVED_MESSAGE, TAKEN_MESSAGE,
  normalizeHandle, handleProblem, isUniqueViolation, isReserved, checkClaim
};
