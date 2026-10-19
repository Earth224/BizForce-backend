// ── YouTube comments worth reading: one deterministic filter ─────────────────
//
// The first live pass (Oct 19, 2026) stored mostly link spam ("Official
// Website: https://siteoficial.cloud/…"), one-word replies ("Correct") and
// off-topic chatter (Portuguese replies under a libido video). This is the one
// test that decides which comments are kept: youtubeRadar.js stores only the
// comments it keeps, and GET /api/leads/youtube-signals applies it again to
// the rows it reads, rows captured before the filter existed included.
//
// A comment is kept only if all three hold, tested in this order; the first
// that fails is the reason:
//   link       it contains no link: http(s)://, www., or a bare domain;
//   too_short  it has at least YOUTUBE_MIN_WORDS words, where a word has at
//              least one letter or digit (emoji and punctuation are not words);
//   off_topic  it contains a topic term of the keyword it matched.
//
// No model call, no network, no database: plain string tests.

var YOUTUBE_MIN_WORDS = 6;

/* A bare domain is letters, a dot, then a top-level domain: one from this
   list anywhere ("gmail.com"), or any 2–24 letters when a path follows
   ("siteoficial.cloud/EchoXen"). Two-letter TLDs that are also common words
   (in, me, us, co, so, to, it, is, am, at, be, do, no, my, de, es) are left
   out, so "…it.So I tried" is not a link. A full stop ending a sentence is
   never followed by 2+ letters, and a decimal ("2.5 mg") has no letters, so
   neither matches. */
var YOUTUBE_LINK_TLDS = [
  "com", "net", "org", "info", "biz", "io", "ai", "app", "dev", "cloud", "shop", "store",
  "online", "site", "website", "xyz", "top", "club", "vip", "pro", "live", "life", "link",
  "click", "space", "fun", "tech", "health", "ly", "tv", "gg", "cc", "ru", "br", "uk"
];
var YOUTUBE_URL_RE = /https?:\/\/|\bwww\./i;
var YOUTUBE_BARE_DOMAIN_RE = /(^|[^\p{L}\p{N}._-])[\p{L}\p{N}-]*\p{L}[\p{L}\p{N}-]*(?:\.[\p{L}\p{N}-]+)*\.([a-z]{2,24})(?![\p{L}\p{N}])(\/)?/giu;

function youtubeHasLink(text) {
  if (YOUTUBE_URL_RE.test(text)) return true;
  YOUTUBE_BARE_DOMAIN_RE.lastIndex = 0;
  var m;
  while ((m = YOUTUBE_BARE_DOMAIN_RE.exec(text)) !== null) {
    if (YOUTUBE_LINK_TLDS.indexOf(m[2].toLowerCase()) !== -1 || m[3] === "/") return true;
  }
  return false;
}

// A word has at least one letter or digit: "❤️❤️❤️." and "👉" are not words.
function youtubeWordCount(text) {
  return String(text).trim().split(/\s+/).filter(function (t) { return /[\p{L}\p{N}]/u.test(t); }).length;
}

/* Plural and -ing tolerance, nothing more: lower-case, drop apostrophes, drop
   a trailing "ing" (words over 5 letters) or a single trailing "s" (over 3,
   not "ss"), then a trailing "e" (over 3). supplement/supplements,
   work/working, jump/jumping, increase/increasing each share a stem. */
function youtubeStem(word) {
  var w = String(word).toLowerCase().replace(/['’]/g, "");
  if (w.length > 5 && /ing$/.test(w)) w = w.slice(0, -3);
  else if (w.length > 3 && /s$/.test(w) && !/ss$/.test(w)) w = w.slice(0, -1);
  if (w.length > 3 && /e$/.test(w)) w = w.slice(0, -1);
  return w;
}

// Whole words: letters and digits, with an inner apostrophe kept (isn't).
function youtubeWords(text) {
  return String(text).toLowerCase().match(/[\p{L}\p{N}]+(?:['’][\p{L}\p{N}]+)*/gu) || [];
}

/* The full stopword list. A keyword's topic terms are its words minus these,
   compared by stem (so "working" is dropped as "work" is). */
var YOUTUBE_STOPWORDS = [
  "a", "an", "the", "and", "or", "but", "if", "so", "of", "in", "on", "at", "by", "for",
  "from", "to", "with", "about", "into", "is", "are", "am", "was", "were", "be", "been",
  "being", "do", "does", "did", "doing", "done", "have", "has", "had", "i", "me", "my",
  "you", "your", "we", "our", "they", "their", "it", "its", "this", "that", "these",
  "those", "what", "why", "how", "when", "where", "who", "which", "isn't", "aren't",
  "doesn't", "don't", "can", "can't", "will", "would", "should", "could", "not", "no",
  "always", "actually", "really", "work", "naturally", "get", "make"
];
var YOUTUBE_STOP_STEMS = YOUTUBE_STOPWORDS.map(youtubeStem);

function youtubeTopicTerms(matchedKeyword) {
  var terms = [];
  youtubeWords(matchedKeyword || "").forEach(function (w) {
    if (YOUTUBE_STOP_STEMS.indexOf(youtubeStem(w)) === -1 && terms.indexOf(w) === -1) terms.push(w);
  });
  return terms;
}

/* { keep: true, reason: null } or { keep: false, reason: "link" | "too_short"
   | "off_topic" }. A missing text has no link and no words: too_short. A
   keyword with no topic terms keeps nothing: off_topic. */
function isUsefulYoutubeComment(text, matchedKeyword) {
  var t = text == null ? "" : String(text);
  if (youtubeHasLink(t)) return { keep: false, reason: "link" };
  if (youtubeWordCount(t) < YOUTUBE_MIN_WORDS) return { keep: false, reason: "too_short" };
  var topicStems = youtubeTopicTerms(matchedKeyword).map(youtubeStem);
  var onTopic = youtubeWords(t).some(function (w) { return topicStems.indexOf(youtubeStem(w)) !== -1; });
  if (!onTopic) return { keep: false, reason: "off_topic" };
  return { keep: true, reason: null };
}

module.exports = {
  isUsefulYoutubeComment,
  youtubeTopicTerms,
  youtubeHasLink,
  youtubeWordCount,
  youtubeStem,
  YOUTUBE_STOPWORDS,
  YOUTUBE_LINK_TLDS,
  YOUTUBE_MIN_WORDS
};
