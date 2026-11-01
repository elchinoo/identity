-- Row MACs: an HMAC under a subkey of the vault data key over the security-relevant fields of each row (see rowmac.py).
-- Null on rows written before this migration: they are ignored until `identity adopt-rowmacs` signs them.
ALTER TABLE idp_user ADD COLUMN IF NOT EXISTS mac text;
ALTER TABLE idp_federated ADD COLUMN IF NOT EXISTS mac text;
ALTER TABLE idp_membership ADD COLUMN IF NOT EXISTS mac text;
ALTER TABLE idp_app ADD COLUMN IF NOT EXISTS mac text;
ALTER TABLE idp_role_grant ADD COLUMN IF NOT EXISTS mac text;
ALTER TABLE signing_key ADD COLUMN IF NOT EXISTS mac text;
ALTER TABLE oauth_code ADD COLUMN IF NOT EXISTS mac text;
ALTER TABLE oauth_refresh ADD COLUMN IF NOT EXISTS mac text;
ALTER TABLE federation_provider ADD COLUMN IF NOT EXISTS mac text;
