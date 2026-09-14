-- 109_model_calls_funded_by.sql
--
-- WHICH KEY PAID FOR EACH MODEL CALL.
--
-- model_calls has recorded what was spent since migration 103, but never whose
-- key paid for it. resolveAnthropicKey falls back to the platform key on every
-- miss — no stored key, an unreadable row, a failed decrypt — and did so
-- silently, so a call that was meant to be funded by a user's own key and was
-- actually funded by the platform's looked exactly like one that was never
-- meant to be. There was no way to ask the database how much of the spend the
-- platform absorbed, for whom, or why.
--
-- DELIBERATELY NULLABLE, WITH NO DEFAULT.
--
-- There are 23 rows in this table that predate this column. A DEFAULT would
-- stamp every one of them with a value nobody measured — and 'platform' would
-- even be the CORRECT guess today, since user_api_keys is empty, which is
-- precisely what makes it dangerous: an invented value that happens to be
-- right is indistinguishable from a recorded one, and stays indistinguishable
-- after it stops being right. NULL means "written before this column existed"
-- and is the only honest thing those rows can say.
--
-- So a total over this column must state its NULL bucket rather than quietly
-- fold it into either side. The queries below do.

ALTER TABLE public.model_calls
  ADD COLUMN IF NOT EXISTS funded_by text,
  ADD COLUMN IF NOT EXISTS fallback_reason text;

-- The constraint permits NULL on purpose, for the 23 rows above. Every row
-- written from migration 109 onward sets it.
ALTER TABLE public.model_calls
  DROP CONSTRAINT IF EXISTS model_calls_funded_by_check;

ALTER TABLE public.model_calls
  ADD CONSTRAINT model_calls_funded_by_check
  CHECK (funded_by IS NULL OR funded_by IN ('user', 'platform'));

ALTER TABLE public.model_calls
  DROP CONSTRAINT IF EXISTS model_calls_fallback_reason_check;

ALTER TABLE public.model_calls
  ADD CONSTRAINT model_calls_fallback_reason_check
  CHECK (
    fallback_reason IS NULL
    OR fallback_reason IN ('no_user', 'no_key_stored', 'lookup_failed', 'decrypt_failed')
  );

COMMENT ON COLUMN public.model_calls.funded_by IS
  'Which Anthropic key paid for this call: ''user'' = the caller''s own stored BYOK key was decrypted and used; ''platform'' = ANTHROPIC_API_KEY. NULL means the row predates migration 109 and the key that paid for it was never recorded — it is NOT a synonym for ''platform'' and must not be counted as one.';

COMMENT ON COLUMN public.model_calls.fallback_reason IS
  'Why the platform key paid when it did. NULL when funded_by = ''user'', and also NULL on rows predating migration 109. ''no_user'' = the call site named no user, so the platform was always going to pay (a background pass the platform initiates). ''no_key_stored'' = a user was named but has no anthropic row in user_api_keys. ''lookup_failed'' = user_api_keys could not be read. ''decrypt_failed'' = a key is stored but could not be decrypted, which is the one value here that means something is broken rather than merely absent.';

-- Answers "how many calls did the platform key pay for, and for which users":
--
--   SELECT funded_by, fallback_reason, user_id, count(*), sum(input_tokens + output_tokens)
--   FROM public.model_calls
--   GROUP BY funded_by, fallback_reason, user_id
--   ORDER BY count(*) DESC;
--
-- The rows with funded_by IS NULL are the pre-109 ones. They are their own
-- bucket in that result and are not to be read as either answer.
--
-- Supports grouping and the "which of my users am I subsidising" scan without
-- forcing a sequential scan once this table stops being small.
CREATE INDEX IF NOT EXISTS model_calls_funded_by_idx
  ON public.model_calls (funded_by, user_id);
