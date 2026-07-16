-- Backfill: bizdoc_documents.content column added live in v17. Idempotent. Documents live truth.

ALTER TABLE bizdoc_documents ADD COLUMN IF NOT EXISTS content text;
