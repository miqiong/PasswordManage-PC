namespace PasswordManage.PC.Data;

/// <summary>列表用元数据（不含密文 BLOB），避免为列表批量解密。</summary>
public sealed record VaultRecordSummary(string RecordId, string UpdatedAt, int Version);
