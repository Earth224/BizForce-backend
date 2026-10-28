/* ══════════════════════════════════════════════════════════════════════════
   lib/gracefulShutdown.js — restarts that finish what they started, and
   crashes that say so (launch item #7, 2026-10-27).

   THE DEFECT. Railway replaces the process on every deploy and every restart
   by sending SIGTERM. server.js had no handler for it, so Node's default ran:
   the process died on the spot. A request half-way through (a checkout, a
   model call that had already been paid for, a wallet transfer) was cut off
   with no answer, and a cron pass could be stopped between its claim and its
   writes. Nothing listened for unhandledRejection or uncaughtException either,
   so a crash was a stack trace in a log nobody was reading.

   WHAT HAPPENS NOW, on SIGTERM or SIGINT:
     1. draining() turns true at once. server.js's first middleware answers any
        NEW request with a 503 and Connection: close, so a client retries on the
        replacement process instead of starting work here.
     2. Every cron task and interval registered here is stopped, so no job
        starts while the process is going away.
     3. server.close() stops accepting connections and waits for the requests
        already in flight; idle keep-alive sockets are closed so they do not
        hold it open.
     4. When the last in-flight request finishes, the process exits 0. If that
        takes longer than the timeout (SHUTDOWN_TIMEOUT_MS, default 10000 ms,
        parsed as a whole number from 1000 to 120000; anything else is the
        default), the remaining connections are destroyed and the process
        exits 1, saying how many were still open.
     A second signal while draining changes nothing: the first shutdown is
     already running and keeps its own timeout.

   CRASHES. unhandledRejection is logged with its stack and raised as an ops
   alert (key process_unhandled_rejection, fingerprinted by the error's first
   line, so lib/opsAlert.js's 6-hour dedupe sends one email per distinct
   error), and the process keeps serving: a promise nobody awaited is a bug to
   fix, not a reason to drop every request in flight. uncaughtException is
   logged and alerted the same way (key process_uncaught_exception), and then
   the process shuts down as above and exits 1, because after a synchronous
   throw nobody caught, the process's state cannot be trusted. Railway starts a
   fresh one. The alert is awaited for at most ALERT_WAIT_MS before the
   shutdown begins, so the email has its chance to leave.

   ONLY WHEN server.js IS THE PROGRAM. The checks load server.js; a check's
   own crash must stay a crash with a stack trace, and must never email the
   owner. server.js installs these handlers only under require.main === module.

   Nothing here knows about Express, node-cron or Supabase: the server, the
   jobs, the process, the clock and the alert are all passed in, which is how
   scripts/checkLaunchBlockB.js drives every path with fakes.
   ══════════════════════════════════════════════════════════════════════════ */

"use strict";

const SHUTDOWN_TIMEOUT_DEFAULT_MS = 10000;
const SHUTDOWN_TIMEOUT_MIN_MS = 1000;
const SHUTDOWN_TIMEOUT_MAX_MS = 120000;
const ALERT_WAIT_MS = 3000;

function shutdownTimeoutMs(env) {
  const raw = env && env.SHUTDOWN_TIMEOUT_MS;
  if (raw == null || String(raw).trim() === "") return SHUTDOWN_TIMEOUT_DEFAULT_MS;
  const n = Number(String(raw).trim());
  return Number.isInteger(n) && n >= SHUTDOWN_TIMEOUT_MIN_MS && n <= SHUTDOWN_TIMEOUT_MAX_MS ? n : SHUTDOWN_TIMEOUT_DEFAULT_MS;
}

function errorFirstLine(err) {
  if (err && err.stack) return String(err.stack).split("\n").slice(0, 2).join(" | ").trim();
  if (err && err.message) return String(err.message);
  return String(err);
}

/* options: { timeoutMs, log, exit, setTimer, clearTimer }. log has .log and
   .error; exit(code) ends the process; setTimer/clearTimer default to the
   global ones. */
function createShutdown(options) {
  const o = options || {};
  const log = o.log || console;
  const exit = o.exit || function (code) { process.exit(code); };
  const setTimer = o.setTimer || setTimeout;
  const clearTimer = o.clearTimer || clearTimeout;
  const timeoutMs = o.timeoutMs || SHUTDOWN_TIMEOUT_DEFAULT_MS;

  const state = { draining: false, signal: null, server: null, jobs: [], intervals: [], exitCode: null };

  function setServer(server) { state.server = server; return server; }

  /* A node-cron task (anything with .stop()), registered as it is scheduled. */
  function trackJob(name, task) { state.jobs.push({ name: name, task: task }); return task; }

  /* A setInterval handle, cleared on shutdown. */
  function trackInterval(name, handle) { state.intervals.push({ name: name, handle: handle }); return handle; }

  function draining() { return state.draining; }

  function finish(code, why) {
    if (state.exitCode !== null) return;
    state.exitCode = code;
    log[code === 0 ? "log" : "error"]("[shutdown] " + why + " Exiting " + code + ".");
    exit(code);
  }

  /* Returns true when this call started the shutdown, false when one was
     already running. exitCode is what a clean drain exits with: 0 for a
     signal, 1 after an uncaught exception. */
  function shutdown(signal, exitCode) {
    if (state.draining) {
      log.log("[shutdown] " + signal + " received while already draining after " + state.signal + "; still waiting.");
      return false;
    }
    const cleanCode = exitCode == null ? 0 : exitCode;
    state.draining = true;
    state.signal = signal;
    log.log("[shutdown] " + signal + " received. Refusing new requests, stopping " + state.jobs.length + " cron job(s) and " +
      state.intervals.length + " interval(s), and waiting up to " + timeoutMs + " ms for requests in flight.");

    state.jobs.forEach(function (j) {
      try { j.task.stop(); } catch (e) { log.error("[shutdown] could not stop cron job " + j.name + ": " + ((e && e.message) || e)); }
    });
    state.intervals.forEach(function (i) {
      try { clearInterval(i.handle); } catch (e) { log.error("[shutdown] could not clear interval " + i.name + ": " + ((e && e.message) || e)); }
    });

    const server = state.server;
    if (!server) { finish(cleanCode, "No HTTP server was listening."); return true; }

    const timer = setTimer(function () {
      let open = null;
      try {
        if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      } catch (e) { /* the process is exiting either way */ }
      try { if (typeof server.connectionCount === "number") open = server.connectionCount; } catch (e) { open = null; }
      finish(1, "Requests were still in flight after " + timeoutMs + " ms" + (open === null ? "" : " (" + open + " connection(s))") +
        "; their connections were closed.");
    }, timeoutMs);
    if (timer && typeof timer.unref === "function") timer.unref();

    try {
      server.close(function (err) {
        clearTimer(timer);
        if (err) finish(1, "The HTTP server did not close cleanly: " + ((err && err.message) || err) + ".");
        else finish(cleanCode, "Every request in flight finished; the HTTP server is closed.");
      });
      if (typeof server.closeIdleConnections === "function") server.closeIdleConnections();
    } catch (e) {
      clearTimer(timer);
      finish(1, "server.close threw: " + ((e && e.message) || e) + ".");
    }
    return true;
  }

  /* Express middleware: while draining, a new request is refused with 503 and
     told to reconnect elsewhere. */
  function gate(req, res, next) {
    if (!state.draining) return next();
    res.setHeader("Connection", "close");
    res.setHeader("Retry-After", "5");
    return res.status(503).json({ error: "BizForce is restarting. Try again in a few seconds.", code: "RESTARTING" });
  }

  return { setServer, trackJob, trackInterval, draining, shutdown, gate, state, timeoutMs };
}

/* proc: the process (or a fake with .on). alert(key, info) returns a promise
   (opsAlerts.raise). Installs SIGTERM, SIGINT, unhandledRejection and
   uncaughtException. */
function installProcessHandlers(proc, shutdownApi, alert, options) {
  const o = options || {};
  const log = o.log || console;
  const setTimer = o.setTimer || setTimeout;
  const alertWaitMs = o.alertWaitMs == null ? ALERT_WAIT_MS : o.alertWaitMs;

  function raise(key, what, err) {
    const first = errorFirstLine(err);
    let sent;
    try {
      sent = Promise.resolve(alert(key, {
        what: what, error: first, fingerprint: first,
        where: "Railway logs: the BizForce backend service, around the time of this email",
        log_tag: key === "process_uncaught_exception" ? "[process] UNCAUGHT EXCEPTION" : "[process] UNHANDLED REJECTION"
      }));
    } catch (e) {
      sent = Promise.reject(e);
    }
    return sent.catch(function (e) { log.error("[process] the ops alert " + key + " could not be raised: " + ((e && e.message) || e)); });
  }

  proc.on("SIGTERM", function () { shutdownApi.shutdown("SIGTERM", 0); });
  proc.on("SIGINT", function () { shutdownApi.shutdown("SIGINT", 0); });

  proc.on("unhandledRejection", function (reason) {
    log.error("[process] UNHANDLED REJECTION (still serving): " + ((reason && reason.stack) || reason));
    raise("process_unhandled_rejection", "A promise was rejected and nothing handled it; the server kept running", reason);
  });

  proc.on("uncaughtException", function (err) {
    log.error("[process] UNCAUGHT EXCEPTION (shutting down, Railway restarts it): " + ((err && err.stack) || err));
    const raised = raise("process_uncaught_exception", "An exception nobody caught stopped the server; Railway restarts it", err);
    let started = false;
    function go() { if (started) return; started = true; shutdownApi.shutdown("uncaughtException", 1); }
    raised.then(go, go);
    const t = setTimer(go, alertWaitMs);
    if (t && typeof t.unref === "function") t.unref();
  });
}

module.exports = {
  SHUTDOWN_TIMEOUT_DEFAULT_MS, SHUTDOWN_TIMEOUT_MIN_MS, SHUTDOWN_TIMEOUT_MAX_MS, ALERT_WAIT_MS,
  shutdownTimeoutMs, createShutdown, installProcessHandlers, errorFirstLine
};
