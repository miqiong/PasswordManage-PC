-- SQLCipher 主库：仅密文记录；salt/verifier 见应用数据目录 vault_bootstrap.bin
CREATE TABLE IF NOT EXISTS vault_records (
  record_id TEXT PRIMARY KEY NOT NULL,
  encrypted_payload BLOB NOT NULL,
  payload_nonce BLOB NOT NULL,
  dek_wrapped BLOB NOT NULL,
  dek_nonce BLOB NOT NULL,
  version INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_vault_records_updated_at ON vault_records(updated_at);
