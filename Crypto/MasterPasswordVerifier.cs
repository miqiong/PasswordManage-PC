using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace PasswordManage.PC.Crypto;

/// <summary>
/// Argon2id + HKDF-SHA256 + verifier。禁止记录主密码、MasterKey、KEK、DB 口令或 verifier 原文。
/// </summary>
public sealed class MasterPasswordVerifier
{
    private const int SaltLen = 16;
    private const int MasterKeyLen = 32;
    private const int MemoryKiB = 131072;
    private const int Iterations = 3;
    private const int Parallelism = 2;
    private static readonly byte[] InfoKek = Encoding.UTF8.GetBytes("vault-kek-v1");
    private static readonly byte[] InfoVerifierKey = Encoding.UTF8.GetBytes("vault-verifierkey-v1");
    private static readonly byte[] InfoDbKey = Encoding.UTF8.GetBytes("vault-sqlcipher-v1");
    private static readonly byte[] VerifierLabel = Encoding.UTF8.GetBytes("vault-verifier-v1");

    public byte[] DeriveMasterKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt)
    {
        if (salt.Length != SaltLen) throw new ArgumentException("salt must be 16 bytes");
        var passwordBytes = password.ToArray();
        var saltBytes = salt.ToArray();
        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = saltBytes,
                DegreeOfParallelism = Parallelism,
                Iterations = Iterations,
                MemorySize = MemoryKiB
            };
            return argon2.GetBytes(MasterKeyLen);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(saltBytes);
        }
    }

    /// <summary>RFC 5869 HKDF-SHA256（Extract 与 Android 对齐）。</summary>
    public byte[] HkdfSha256(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> info, int length)
    {
        var prk = HkdfExtractSha256(ikm);
        var infoCopy = info.ToArray();
        try
        {
            return HkdfExpandSha256(prk, infoCopy, length);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(prk);
            CryptographicOperations.ZeroMemory(infoCopy);
        }
    }

    private static byte[] HkdfExtractSha256(ReadOnlySpan<byte> ikm)
    {
        var ikmCopy = ikm.ToArray();
        try
        {
            using var hmac = new HMACSHA256(new byte[32]);
            return hmac.ComputeHash(ikmCopy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ikmCopy);
        }
    }

    /// <summary>HKDF-Expand；使用固定 <see cref="byte[]"/>，禁止用 <see cref="List{T}"/> 累积密钥字节。</summary>
    private static byte[] HkdfExpandSha256(byte[] prk, byte[] info, int length)
    {
        var result = new byte[length];
        byte[]? t = null;
        try
        {
            byte counter = 1;
            var offset = 0;
            while (offset < length)
            {
                byte[]? data = null;
                try
                {
                    var tLen = t?.Length ?? 0;
                    data = new byte[tLen + info.Length + 1];
                    if (tLen > 0)
                        Buffer.BlockCopy(t!, 0, data, 0, tLen);
                    Buffer.BlockCopy(info, 0, data, tLen, info.Length);
                    data[^1] = counter;
                    using var hmac = new HMACSHA256(prk);
                    var newT = hmac.ComputeHash(data);
                    if (t != null)
                        CryptographicOperations.ZeroMemory(t);
                    t = newT;
                    var take = Math.Min(t.Length, length - offset);
                    Buffer.BlockCopy(t, 0, result, offset, take);
                    offset += take;
                    counter++;
                }
                finally
                {
                    if (data != null)
                        CryptographicOperations.ZeroMemory(data);
                }
            }
            return result;
        }
        finally
        {
            if (t != null)
                CryptographicOperations.ZeroMemory(t);
        }
    }

    public byte[] DeriveKek(byte[] masterKey) => HkdfSha256(masterKey, InfoKek, MasterKeyLen);

    public byte[] DeriveVerifierKey(byte[] masterKey) => HkdfSha256(masterKey, InfoVerifierKey, MasterKeyLen);

    public byte[] DeriveDatabasePassphrase(byte[] kek) => HkdfSha256(kek, InfoDbKey, MasterKeyLen);

    public byte[] BuildVerifier(byte[] verifierKey)
    {
        using var hmac = new HMACSHA256(verifierKey);
        return hmac.ComputeHash(VerifierLabel);
    }

    public bool VerifyMasterPassword(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> storedVerifier)
    {
        byte[]? mk = null;
        byte[]? vk = null;
        byte[]? candidate = null;
        try
        {
            mk = DeriveMasterKey(password, salt);
            vk = DeriveVerifierKey(mk);
            candidate = BuildVerifier(vk);
            if (candidate.Length != storedVerifier.Length)
                return false;
            return CryptographicOperations.FixedTimeEquals(candidate, storedVerifier);
        }
        finally
        {
            if (mk != null) CryptographicOperations.ZeroMemory(mk);
            if (vk != null) CryptographicOperations.ZeroMemory(vk);
            if (candidate != null) CryptographicOperations.ZeroMemory(candidate);
        }
    }

    public (byte[] Kek, byte[] Verifier) DeriveKekAndVerifier(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt)
    {
        var mk = DeriveMasterKey(password, salt);
        try
        {
            var kek = DeriveKek(mk);
            var vk = DeriveVerifierKey(mk);
            var verifier = BuildVerifier(vk);
            CryptographicOperations.ZeroMemory(vk);
            return (kek, verifier);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mk);
        }
    }
}
