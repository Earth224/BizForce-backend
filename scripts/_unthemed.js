/* scripts/_unthemed.js — frontend text with every Block 4d theme token resolved
   to its own fallback: what a page draws with no theme saved.

   Block 4d (Phase C) turned every original-palette literal on the app's
   pages into a token that falls back to that literal, and added an empty
   middle stop to every gradient. A check that pins page text from before
   reads it through unthemed() and so pins the same text, now proved to be
   what the page draws by default. scripts/checkThemeSpectrums.js proves that
   unthemed() of every file equals the file at frontend 5dcfa3c (except the
   files Block 4d edited by hand), so nothing else can hide behind it.

   The forms it resolves, and only these:
     var(--bf-accent-<t>, #rrggbb)               → #rrggbb
     var(--bf-accent-<t>-rgb, r, g, b)           → r, g, b
     var(--bf-<accent|btn|mark|guide>-mid, )     → nothing
     var(--tmx-chat-glow-mid, )                  → nothing
     (typeof BFTheme !== "undefined" ? BFTheme.color(Q--bf-accent-<t>Q, QcQ) : QcQ)  → QcQ
     the same inside markup in a string: Q + (…) + Q  → c
     style="<stroke|fill|stop-color>:var(--bf-accent-<t>, #c)"  → <attr>="#c" */
"use strict";
function unthemed(text) {
  return String(text)
    .replace(/(["'])\s\+\s\(typeof BFTheme !== "undefined" \? BFTheme\.color\(\1--bf-accent-[a-z0-9]+\1, \1([^"']*)\1\) : \1\2\1\)\s\+\s\1/g, "$2")
    .replace(/\$\{typeof BFTheme !== "undefined" \? BFTheme\.color\("--bf-accent-[a-z0-9]+", "([^"]*)"\) : "\1"\}/g, "$1")
    .replace(/\(typeof BFTheme !== "undefined" \? BFTheme\.color\((["'])--bf-accent-[a-z0-9]+\1, \1([^"']*)\1\) : \1\2\1\)/g, "$1$2$1")
    .replace(/style="(stroke|fill|stop-color):var\(--bf-accent-[a-z0-9]+, (#[0-9a-f]{6})\)"/g, "$1=\"$2\"")
    .replace(/var\(--(?:bf-(?:accent|btn|mark|guide)|tmx-chat-glow)-mid, \)/g, "")
    .replace(/var\(--bf-accent-[a-z0-9]+-rgb, ([0-9,\s]+)\)/g, "$1")
    .replace(/var\(--bf-accent-[a-z0-9]+, (#[0-9a-f]{6})\)/g, "$1");
}
module.exports = { unthemed: unthemed };
