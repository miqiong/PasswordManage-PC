using System.IO;
using System.Security.Cryptography;

namespace PasswordManage.PC.Data;

/// <summary>引导数据：salt(16) + verifier(32)，与密文库文件并列存储。</summary>
public sealed class MetaStore
{
    private readonly string _path;

    public MetaStore(string vaultDirectory)
    {
        _path = Path.Combine(vaultDirectory, "vault_bootstrap.bin");
    }

    public bool Exists =>
        File.Exists(_path) && new FileInfo(_path).Length == SaltLen + VerifierLen;

    private const int SaltLen = 16;
    private const int VerifierLen = 32;

    public void Write(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> verifier)
    {
        if (salt.Length != SaltLen || verifier.Length != VerifierLen)
            throw new ArgumentException("invalid salt/verifier length");
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        using var fs = File.Open(_path, FileMode.Create, FileAccess.Write, FileShare.None);
        fs.Write(salt);
        fs.Write(verifier);
        fs.Flush(true);
    }

    public bool TryRead(out byte[] salt, out byte[] verifier)
    {
        salt = Array.Empty<byte>();
        verifier = Array.Empty<byte>();
        if (!Exists) return false;
        try
        {
            var all = File.ReadAllBytes(_path);
            if (all.Length != SaltLen + VerifierLen) return false;
            salt = all.AsSpan(0, SaltLen).ToArray();
            verifier = all.AsSpan(SaltLen, VerifierLen).ToArray();
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void Clear()
    {
        try
        {
            if (!File.Exists(_path)) return;
            var len = (int)new FileInfo(_path).Length;
            if (len > 0)
            {
                var junk = new byte[len];
                RandomNumberGenerator.Fill(junk);
                File.WriteAllBytes(_path, junk);
                CryptographicOperations.ZeroMemory(junk);
            }
            File.Delete(_path);
        }
        catch { /* best effort */ }
    }
}
