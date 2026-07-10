CREATE TABLE IF NOT EXISTS bizdoc_documents (
id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
owner_id uuid NOT NULL,
template_type text NOT NULL,
title text NOT NULL,
fields jsonb NOT NULL DEFAULT '{}',
party_name text,
party_email text,
status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','sent','signed','voided')),
created_at timestamptz NOT NULL DEFAULT now(),
updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bizdoc_signatures (
id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
document_id uuid NOT NULL REFERENCES bizdoc_documents(id) ON DELETE CASCADE,
signer_id uuid,
signer_name text NOT NULL,
signer_email text,
signature_data text NOT NULL,
signed_at timestamptz NOT NULL DEFAULT now(),
ip_address text,
user_agent text
);

ALTER TABLE bizdoc_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE bizdoc_signatures ENABLE ROW LEVEL SECURITY;

CREATE POLICY bizdoc_documents_select ON bizdoc_documents
FOR SELECT USING (owner_id = auth.uid());
CREATE POLICY bizdoc_documents_insert ON bizdoc_documents
FOR INSERT WITH CHECK (owner_id = auth.uid());
CREATE POLICY bizdoc_documents_update ON bizdoc_documents
FOR UPDATE USING (owner_id = auth.uid());
CREATE POLICY bizdoc_documents_delete ON bizdoc_documents
FOR DELETE USING (owner_id = auth.uid());

CREATE POLICY bizdoc_signatures_select ON bizdoc_signatures
FOR SELECT USING (
EXISTS (SELECT 1 FROM bizdoc_documents d WHERE d.id = document_id AND d.owner_id = auth.uid())
);
