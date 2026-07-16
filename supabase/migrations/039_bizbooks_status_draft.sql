-- Add 'draft' to bizbooks.status allowed values (Biz-EBook template/draft flow). Idempotent — drop-then-recreate.
-- Documents a live change already applied in Supabase.

ALTER TABLE bizbooks DROP CONSTRAINT IF EXISTS bizbooks_status_check;
ALTER TABLE bizbooks ADD CONSTRAINT bizbooks_status_check
  CHECK (status IN ('ready','processing','failed','draft'));
