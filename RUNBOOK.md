# BizForce runbook

What to do when something breaks. `README.md` has the variables, jobs and deploy order this refers to.

**Where things are**

- Railway: the BizForce backend service. Its **Deployments** tab lets you roll back, **Logs** has the search box, and **Variables** holds the settings.
- Supabase: the project dashboard. Use the **Table editor** for `job_runs`, `ops_alerts`, `model_calls` and `pending_storage_deletions`, and the **SQL Editor** for migrations.
- Health: `https://dynamic-prosperity-production-5382.up.railway.app/health` returns `healthy` (HTTP 200) when the server is up and the database answers, or `unhealthy` (HTTP 503) when it doesn't.

## When an alert email arrives

Each alert email has the subject `[BizForce ALERT] <what broke>`. The body gives the **alert key**, the error, and where to look: a Railway log search term and a Supabase table. A key is emailed once, then again only if the error changes, or after 6 hours if it is still open. When the problem clears, one `[BizForce RESOLVED]` email follows. Open alerts are listed in the `ops_alerts` table.

| Alert key | What it means | What to do |
|---|---|---|
| `health_db` | The database did not answer `/health` three times in a row. | Open Supabase. If the project is paused or down, see "When the database is down" below. If Supabase looks fine, check the Railway logs for `[health]` and look at recent deploys. It clears on its own at the next probe that answers. |
| `job:<job_name>` | A scheduled job recorded an error in `job_runs.last_error`. | Search the Railway logs for the job's name, for example `[SelfReview]` or `[AgentSchedules]`. Fix the cause. It clears once the job's next run finishes with no error. To stop a job meanwhile, set its gate (README, Background jobs) to off and redeploy. |
| `ops_scan` | The 30-minute alert scan itself failed, so other alerts may be missing. | Check the `job_runs` row `ops_alert_scan` and the Railway logs for `[OpsAlert]`. This is usually a database problem, so treat it like `health_db`. |
| `backup_failed` | The nightly backup did not send, or sent with a table missing or partial. "Backup not encrypted" means `BACKUP_ENCRYPTION_KEY` is missing or malformed. | See "When a backup fails" below. |
| `backup_stale` | No backup has succeeded in 30 hours, although `ENABLE_NIGHTLY_BACKUP` is `true`. | See "When a backup fails" below. |
| `stripe_webhook` | The Stripe webhook handler threw while processing an event. The event's effect, such as a subscription update, may not have been recorded. | See "When a payment fails" below. In Stripe, go to Developers, then Webhooks, and resend the failed event once the cause is fixed. |
| `marketplace_usd_refused` | A USD marketplace payment arrived. USD sales between members are switched off, so it was refused. | Find the checkout session named in the email in Stripe and refund it there. Nobody should be able to start one: check what created it. |
| `schedule_paused:<user>:<agent>` | A member's scheduled agent run failed several times in a row and paused itself. | Look at that member's recent runs in the Railway logs (`[AgentSchedules] PAUSED`). Fix the cause; the member turns the schedule back on. |
| `storage_deletion_stuck` | Files from a deleted account could not be removed from Storage after repeated attempts. The retries continue. | Open `pending_storage_deletions` (`attempts`, `last_error`) and the named bucket in Supabase Storage. Remove the files by hand if Storage keeps refusing. |
| `storage_deletion_unqueued` | An account delete removed the account's rows, but some files were neither removed nor queued for deletion. | The Railway log line `[your-data] delete user=<id>` lists the paths. Delete them in Supabase Storage by hand. |
| `platform_spend_80` | Today's platform AI spend reached 80% of `PLATFORM_DAILY_SPEND_CAP_USD`. | See "When the spend ceiling trips" below, before it reaches 100%. |
| `platform_spend_unreadable` | Today's spend could not be read, so every member's model call is refused (the ceiling fails closed). The owner's calls still work. | This is a database problem: check Supabase and the `model_calls` table. Calls resume as soon as the read works again. |
| `platform_spend_cap_misconfigured` | `PLATFORM_DAILY_SPEND_CAP_USD` is set to something that is not a positive number, so every member's model call is refused. | In Railway Variables, fix the value or delete it (the default is $25), then redeploy. |
| `process_unhandled_rejection` | A promise failed and nothing handled it. The server kept running. | Search the Railway logs for `[process] UNHANDLED REJECTION` to find the stack trace, then fix the code that dropped the error. One email is sent per distinct error. |
| `process_uncaught_exception` | An uncaught exception stopped the server. It drained its in-flight requests and exited, and Railway started a new one. | Search the logs for `[process] UNCAUGHT EXCEPTION` and fix it. If it repeats in a restart loop, roll back to the last good deploy (Railway, Deployments, Redeploy). |

## When Railway is down, or the backend will not start

1. **Is it Railway, or us?** Check `status.railway.com`. If Railway has an incident, there is nothing to fix on our side. The frontend on Netlify stays up, and pages show their "could not reach the server" messages. Wait for it to clear, then confirm `/health` says `healthy`.
2. **A deploy that will not start:** in Railway, open Deployments, then the failed deploy's logs. A crash at startup usually means a missing variable or a syntax error. Redeploy the last good deployment, then fix the cause on `main`.
3. **Started but unhealthy:** `/health` returns 503, so the database is not answering. See below.
4. **Restarts:** a deploy sends the old process SIGTERM. It refuses new requests with a 503 ("BizForce is restarting"), finishes in-flight requests for up to `SHUTDOWN_TIMEOUT_MS` (10 s), stops every cron job and exits. A few 503s during a deploy are expected, and browsers retry. To give long requests more time, raise `SHUTDOWN_TIMEOUT_MS`, and give Railway a drain time at least that long (Railway's draining setting in Railway's docs), or Railway stops the process first.

**When the database is down:** check the Supabase status page and the project's dashboard. A project paused for inactivity is resumed from its dashboard. Nothing in the backend needs restarting: the next probe that answers clears `health_db`, and model calls resume on their own.

**Set up an uptime monitor** on `/health` (UptimeRobot, Better Stack, or any HTTP monitor) that alerts on anything but HTTP 200, checking every 5 minutes. It is the only thing that notices when the whole server is down, because every alert email above is sent by the server itself.

## When the spend ceiling trips

Members see: "BizForce has reached today's AI usage limit; it resets at midnight UTC." The response is a 429 with code `PLATFORM_DAILY_SPEND_LIMIT`. No model call is made, and the owner's account still works.

1. **Find who is spending.** In the Supabase SQL editor:
   ```sql
   select user_id, count(*) as calls, sum(input_tokens) as input_tokens, sum(output_tokens) as output_tokens
   from model_calls where created_on = current_date and funded_by is distinct from 'user'
   group by user_id order by output_tokens desc limit 20;
   ```
2. **A runaway** (one account, or a job looping): stop the source. Ban the account, or set the job's gate to off and redeploy. The per-account caps (`MODEL_CALLS_DAILY_LIMIT_PER_USER`, `MODEL_SPEND_MONTHLY_LIMIT_USD_PER_USER`) can be lowered too.
3. **Real growth:** raise `PLATFORM_DAILY_SPEND_CAP_USD` in Railway Variables and redeploy. It takes effect on the next model call.
4. **Check suite rows:** rows from test accounts, such as the check suite's fixtures, are not counted (`lib/testAccounts.js`). If the ceiling trips right after a suite run, look for an account that should be a test account and isn't.
5. It resets on its own at midnight UTC.

## When a backup fails

1. Read the alert's error. "Backup not encrypted" means `BACKUP_ENCRYPTION_KEY` is missing or not base64 of exactly 32 bytes: restore it from your offline copy, **never generate a new one** (a new key cannot open old backups). "Table missing" or "partial" names the table: check it exists and that a migration was not skipped.
2. Search the Railway logs for `[NightlyBackup]`. A Resend error means the email did not send; check the Resend dashboard (domain status, quota) and `BACKUP_EMAIL_TO`.
3. If `backup_stale` arrived with no `backup_failed`, the job is not running at all. Check `ENABLE_NIGHTLY_BACKUP` is exactly `true` and the startup log says `runNightlyBackup scheduled`.
4. After the fix, wait for the next run (`BACKUP_CRON`), or set `BACKUP_CRON` to a time a few minutes ahead, redeploy, then set it back. The alert clears on the next success.
5. Once a quarter, run the restore drill in `README.md`. A backup nobody has restored is a hope, not a backup.

## When a payment fails

**A member's renewal failed** (Stripe marks the subscription `past_due`): nothing to do at first. Stripe retries the card on its own schedule and emails the member. The member keeps access for `SUBSCRIPTION_PAST_DUE_GRACE_DAYS` (14) from when the payment fell due. If Stripe gives up, the subscription becomes `canceled` or `unpaid`, and access ends. The member can pay from Billing at any time.

**The webhook failed** (`stripe_webhook` alert): the payment may have succeeded in Stripe while BizForce did not record it, so a member who paid could be shown as unsubscribed.

1. In Stripe, go to Developers, then Webhooks, then the endpoint `/api/webhook`, and find the failed event and its error.
2. Search the Railway logs for `Stripe webhook handler failed`, fix the cause, and redeploy.
3. Resend the event from Stripe, then check the member's row in the `subscriptions` table matches Stripe.
4. If the error is a signature failure for every event, `STRIPE_WEBHOOK_SECRET` does not match the endpoint's signing secret in Stripe. Copy it again from Stripe into Railway Variables.

**A member was charged but has no access:** find their subscription in Stripe and compare it with their row in the `subscriptions` table. If the webhook never arrived, resend the event as above. Refunds are made in Stripe (Payments, then the payment, then Refund), as `refund.html` describes.
