-- ============================================================================
-- 127_model_calls_thinking_tokens.sql
--
-- WHAT THIS IS
--   One column on model_calls: thinking_tokens, how many of the row's
--   output_tokens were the model's reasoning, read from the API's
--   usage.output_tokens_details.thinking_tokens by recordModelCall in server.js.
--
-- WHY
--   Both Sonnets think by default, the thinking comes back as blocks with no
--   text, and callAnthropicText keeps text only. Those tokens are billed and
--   count against max_tokens, but nothing recorded them: clean-6b's 19,904
--   output tokens held about 9,300 of reasoning nobody could see, and its seo
--   task was cut off with 17% of its budget as usable text. output_tokens stays
--   the billed total; output_tokens - thinking_tokens is the visible answer.
--
-- NULL MEANS NOT REPORTED, NOT ZERO
--   A model that does not think (Haiku as called here) may return no details at
--   all. The row then leaves this column NULL. 0 is written only when the API
--   said 0. Existing rows stay NULL: their split was never measured.
--
-- BEFORE THIS IS APPLIED, an insert naming the column is refused whole by
-- PostgREST. recordModelCall names it only when the API reported a number, and
-- on that refusal re-inserts without it, logging which migration restores it.
-- The spend is recorded either way.
--
-- APPLY BY HAND, once, in the SQL editor.
-- ============================================================================

alter table public.model_calls
  add column if not exists thinking_tokens integer;

alter table public.model_calls
  drop constraint if exists model_calls_thinking_tokens_within_output;

alter table public.model_calls
  add constraint model_calls_thinking_tokens_within_output
    check (thinking_tokens is null or (thinking_tokens >= 0 and thinking_tokens <= output_tokens));
