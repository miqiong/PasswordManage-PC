using PasswordManage.PC.Crypto;
using Xunit;

namespace PasswordManage.PC.Tests;

public class RecordEncryptorTests
{
    [Fact]
    public void EncryptDecrypt_RoundTrip()
    {
        var crypto = new CryptoService();
        var enc = new RecordEncryptor(crypto);
        var kek = crypto.RandomBytes(32);
        var recordId = Guid.NewGuid().ToString();
        var updatedAt = "2026-05-01T12:00:00Z";
        var plain = new PlainRecord("t", "u", "p", "https://x", "n", new[] { "a", "b" });
        var row = enc.Encrypt(recordId, plain, kek, 1, updatedAt);
        var back = enc.Decrypt(row, kek);
        Assert.Equal(plain.Title, back.Title);
        Assert.Equal(plain.Tags.ToArray(), back.Tags.ToArray());
    }
}
