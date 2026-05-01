using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PasswordManage.PC.Crypto;

public sealed record PlainRecord(
    string Title,
    string Username,
    string Password,
    string Url,
    string Note,
    IReadOnlyList<string> Tags
);

public sealed record EncryptedRecordRow(
    string RecordId,
    byte[] EncryptedPayload,
    byte[] PayloadNonce,
    byte[] DekWrapped,
    byte[] DekNonce,
    int Version,
    string UpdatedAt,
    bool Deleted
);

public sealed class RecordEncryptor
{
    private readonly CryptoService _crypto;
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public RecordEncryptor(CryptoService crypto) => _crypto = crypto;

    public static byte[] BuildAad(string recordId, int version, string updatedAt) =>
        Encoding.UTF8.GetBytes($"{recordId}|{version}|{updatedAt}");

    public EncryptedRecordRow Encrypt(string recordId, PlainRecord plain, byte[] kek, int version, string updatedAt)
    {
        var aad = BuildAad(recordId, version, updatedAt);
        var payloadBytes = JsonSerializer.SerializeToUtf8Bytes(plain, JsonOpts);
        var dek = _crypto.RandomBytes(32);
        var (pNonce, encPayload) = _crypto.Seal(dek, payloadBytes, aad);
        var (dNonce, dekWrapped) = _crypto.Seal(kek, dek, aad);
        CryptographicOperations.ZeroMemory(payloadBytes);
        CryptographicOperations.ZeroMemory(dek);
        return new EncryptedRecordRow(recordId, encPayload, pNonce, dekWrapped, dNonce, version, updatedAt, false);
    }

    public PlainRecord Decrypt(EncryptedRecordRow row, byte[] kek)
    {
        var aad = BuildAad(row.RecordId, row.Version, row.UpdatedAt);
        var dek = _crypto.Open(kek, row.DekNonce, row.DekWrapped, aad);
        try
        {
            var plainBytes = _crypto.Open(dek, row.PayloadNonce, row.EncryptedPayload, aad);
            try
            {
                return JsonSerializer.Deserialize<PlainRecord>(plainBytes, JsonOpts)
                       ?? throw new CryptographicException("invalid payload");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plainBytes);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }
}
