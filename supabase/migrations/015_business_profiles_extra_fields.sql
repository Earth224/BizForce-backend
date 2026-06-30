-- Migration 015: Add extra context fields to business_profiles
-- Covers fields used by the POST upsert that were missing from 014.

ALTER TABLE business_profiles ADD COLUMN IF NOT EXISTS business_type     text;
ALTER TABLE business_profiles ADD COLUMN IF NOT EXISTS offer             text;
ALTER TABLE business_profiles ADD COLUMN IF NOT EXISTS products_services text;
ALTER TABLE business_profiles ADD COLUMN IF NOT EXISTS description       text;
