-- +goose Up
-- Lean per-user custom-attribute bag, the source for claim mappers with
-- source_type=2. Loaded on the row the claim resolver already reads. Not
-- indexable/searchable (acceptable for claim emission; EAV is the upgrade path
-- if attribute search is ever needed).
ALTER TABLE users ADD COLUMN attributes JSON NULL;

-- +goose Down
ALTER TABLE users DROP COLUMN attributes;
