-- CHANGES the database. CREATES a column: ai_tasks.output, jsonb, nullable.
--
-- WHY THIS EXISTS. The per-agent tool routes - the twenty-nine POST
-- /api/agents/<agent>/<tool> handlers - return a structured body: a `measured`
-- block of arithmetic the server did, a `provenance` block saying what was and
-- was not read, and the parsed content itself. Until now not one of them wrote
-- anything down. Every run was spent, returned, and gone: no history, no way to
-- compare two runs, no way to tell what a tool said last week.
--
-- ai_tasks already holds every prompt task, and Task History already reads it,
-- so the structured body goes on that table rather than on a second one. It
-- goes in its own jsonb column rather than serialised into `result`, because
-- `result` is rendered as markdown by Task History and a JSON blob there would
-- read as a wall of braces. `result` instead carries a readable rendering of
-- the same run, produced by the server, so the row displays correctly in the
-- existing history list with no frontend change.
--
-- NULL for prompt tasks, deliberately. Their output IS prose, it lives in
-- `result`, and a duplicate of it here would be a second copy to keep in step.
-- Nullable rather than defaulted so the column says nothing about rows that
-- predate it.
--
-- Already applied to the live database on 2026-09-11, before this file was
-- written.

alter table public.ai_tasks add column if not exists output jsonb;

comment on column public.ai_tasks.output is
  'Structured response body of a per-agent tool route (measured, provenance, parsed content). NULL for prompt tasks, whose output is prose in result. result carries a readable rendering of the same run for Task History.';
