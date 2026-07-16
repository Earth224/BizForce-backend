-- Backfill: columns added live to bizbooks after 035. Idempotent — safe no-op if already present.
-- Documents live truth; not required to run against the existing DB.

ALTER TABLE bizbooks ADD COLUMN IF NOT EXISTS storage_path_epub text; -- EPUB sibling of storage_path (nullable — PDF-only books have no EPUB)
ALTER TABLE bizbooks ADD COLUMN IF NOT EXISTS cover_path text; -- path within bf-books to an uploaded/generated cover image
ALTER TABLE bizbooks ADD COLUMN IF NOT EXISTS content text; -- editor HTML source (Biz-EBook in-editor authoring + regenerate flow)
ALTER TABLE bizbooks ADD COLUMN IF NOT EXISTS trim_size text DEFAULT 'letter'; -- PDF trim size key, e.g. '6x9', 'letter'
ALTER TABLE bizbooks ADD COLUMN IF NOT EXISTS page_count integer; -- generated PDF's rendered page count
ALTER TABLE bizbooks ADD COLUMN IF NOT EXISTS cover_design jsonb; -- Cover Designer state saved against this book
