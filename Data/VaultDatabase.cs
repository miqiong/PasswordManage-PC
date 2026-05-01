using Microsoft.Data.Sqlite;

namespace PasswordManage.PC.Data;

/// <summary>PRD §一.9：SQLCipher + 建表。口令为 32 字节原始密钥经 Base64 后的 ASCII（与 Android 一致）。</summary>
public sealed class VaultDatabase : IDisposable
{
    private readonly string _connectionString;
    private readonly string _pragmaKeyLiteral;
    private bool _disposed;

    public VaultDatabase(string dbPath, ReadOnlySpan<byte> rawDbKey32)
    {
        _connectionString = $"Data Source={dbPath}";
        var keyStr = Convert.ToBase64String(rawDbKey32);
        _pragmaKeyLiteral = keyStr.Replace("'", "''");
    }

    public const string InitSql = """
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
""";

    public async Task InitializeAsync(CancellationToken ct = default)
    {
        SQLitePCL.Batteries_V2.Init();
        await using var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync(ct);
        await using (var pragma = conn.CreateCommand())
        {
            pragma.CommandText = $"PRAGMA key = '{_pragmaKeyLiteral}';";
            await pragma.ExecuteNonQueryAsync(ct);
        }
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = InitSql;
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<SqliteConnection> OpenAsync(CancellationToken ct = default)
    {
        var conn = new SqliteConnection(_connectionString);
        await conn.OpenAsync(ct);
        await using var pragma = conn.CreateCommand();
        pragma.CommandText = $"PRAGMA key = '{_pragmaKeyLiteral}';";
        await pragma.ExecuteNonQueryAsync(ct);
        return conn;
    }

    /// <summary>释放连接池中的空闲连接，避免锁定后仍缓存已打开句柄。</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        try
        {
            SQLitePCL.Batteries_V2.Init();
            using var c = new SqliteConnection(_connectionString);
            SqliteConnection.ClearPool(c);
        }
        catch
        {
            // 不向外抛出；不记录可能含路径的连接串
        }
    }
}
