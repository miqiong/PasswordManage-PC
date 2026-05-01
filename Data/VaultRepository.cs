using Microsoft.Data.Sqlite;
using PasswordManage.PC.Crypto;

namespace PasswordManage.PC.Data;

public sealed class VaultRepository
{
    private readonly VaultDatabase _db;

    public VaultRepository(VaultDatabase db) => _db = db;

    public async Task UpsertRecordAsync(EncryptedRecordRow row, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO vault_records (
              record_id, encrypted_payload, payload_nonce, dek_wrapped, dek_nonce, version, updated_at, deleted
            ) VALUES (
              $id, $ep, $pn, $dw, $dn, $v, $u, $d
            )
            ON CONFLICT(record_id) DO UPDATE SET
              encrypted_payload = excluded.encrypted_payload,
              payload_nonce = excluded.payload_nonce,
              dek_wrapped = excluded.dek_wrapped,
              dek_nonce = excluded.dek_nonce,
              version = excluded.version,
              updated_at = excluded.updated_at,
              deleted = excluded.deleted;
            """;
        cmd.Parameters.AddWithValue("$id", row.RecordId);
        cmd.Parameters.Add("$ep", SqliteType.Blob).Value = row.EncryptedPayload;
        cmd.Parameters.Add("$pn", SqliteType.Blob).Value = row.PayloadNonce;
        cmd.Parameters.Add("$dw", SqliteType.Blob).Value = row.DekWrapped;
        cmd.Parameters.Add("$dn", SqliteType.Blob).Value = row.DekNonce;
        cmd.Parameters.AddWithValue("$v", row.Version);
        cmd.Parameters.AddWithValue("$u", row.UpdatedAt);
        cmd.Parameters.AddWithValue("$d", row.Deleted ? 1 : 0);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<EncryptedRecordRow?> GetRecordAsync(string recordId, CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT record_id, encrypted_payload, payload_nonce, dek_wrapped, dek_nonce, version, updated_at, deleted
            FROM vault_records WHERE record_id = $id LIMIT 1;
            """;
        cmd.Parameters.AddWithValue("$id", recordId);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        return ReadRow(reader);
    }

    /// <summary>仅查询 record_id / updated_at / version，不读取密文列。</summary>
    public async Task<IReadOnlyList<VaultRecordSummary>> ListActiveSummariesAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT record_id, updated_at, version
            FROM vault_records WHERE deleted = 0 ORDER BY updated_at DESC;
            """;
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var list = new List<VaultRecordSummary>();
        while (await reader.ReadAsync(ct))
            list.Add(new VaultRecordSummary(reader.GetString(0), reader.GetString(1), reader.GetInt32(2)));
        return list;
    }

    public async Task<IReadOnlyList<EncryptedRecordRow>> ListActiveAsync(CancellationToken ct = default)
    {
        await using var conn = await _db.OpenAsync(ct);
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT record_id, encrypted_payload, payload_nonce, dek_wrapped, dek_nonce, version, updated_at, deleted
            FROM vault_records WHERE deleted = 0 ORDER BY updated_at DESC;
            """;
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var list = new List<EncryptedRecordRow>();
        while (await reader.ReadAsync(ct))
            list.Add(ReadRow(reader));
        return list;
    }

    private static EncryptedRecordRow ReadRow(SqliteDataReader reader) =>
        new(
            RecordId: reader.GetString(0),
            EncryptedPayload: (byte[])reader["encrypted_payload"],
            PayloadNonce: (byte[])reader["payload_nonce"],
            DekWrapped: (byte[])reader["dek_wrapped"],
            DekNonce: (byte[])reader["dek_nonce"],
            Version: reader.GetInt32(5),
            UpdatedAt: reader.GetString(6),
            Deleted: reader.GetInt32(7) != 0
        );
}
