using System.Security.Cryptography;
using PasswordManage.PC.Crypto;
using PasswordManage.PC.Data;
using Xunit;

namespace PasswordManage.PC.Tests;

public class VaultDatabaseTests : IAsyncLifetime
{
    private string _dir = null!;

    public Task InitializeAsync()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"vault_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
        return Task.CompletedTask;
    }

    public Task DisposeAsync()
    {
        try
        {
            foreach (var f in Directory.GetFiles(_dir))
                try { File.Delete(f); } catch { }
            Directory.Delete(_dir, true);
        }
        catch { }
        return Task.CompletedTask;
    }

    [Fact]
    public async Task BootstrapAndRecord_Persist()
    {
        var dbPath = Path.Combine(_dir, "vault.db");
        var meta = new MetaStore(_dir);

        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);
        var pwd = "unit-test-password"u8.ToArray();
        var mpv = new MasterPasswordVerifier();
        var (kek, verifier) = mpv.DeriveKekAndVerifier(pwd, salt);
        meta.Write(salt, verifier);

        var dbKey = mpv.DeriveDatabasePassphrase(kek);
        var db = new VaultDatabase(dbPath, dbKey);
        await db.InitializeAsync();
        var repo = new VaultRepository(db);

        var crypto = new CryptoService();
        var enc = new RecordEncryptor(crypto);
        var id = Guid.NewGuid().ToString();
        var row = enc.Encrypt(id, new PlainRecord("t", "u", "p", "u", "n", Array.Empty<string>()), kek, 1, "2026-05-01T00:00:00Z");
        await repo.UpsertRecordAsync(row);

        var loaded = await repo.GetRecordAsync(id);
        Assert.NotNull(loaded);
        var plain = enc.Decrypt(loaded!, kek);
        Assert.Equal("t", plain.Title);

        CryptographicOperations.ZeroMemory(kek);
        CryptographicOperations.ZeroMemory(dbKey);
        CryptographicOperations.ZeroMemory(pwd);
        db.Dispose();
    }
}
