using System.Security.Cryptography;

namespace PasswordManage.PC.Crypto;

/// <summary>PRD §一.12：AES-256-GCM AEAD（.NET 内置 AesGcm，非 ECB）。</summary>
public sealed class CryptoService
{
    public byte[] RandomBytes(int length)
    {
        if (length <= 0) throw new ArgumentOutOfRangeException(nameof(length));
        var b = new byte[length];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    /// <summary>返回 (nonce 12 字节, ciphertext||tag)。</summary>
    public (byte[] Nonce, byte[] CiphertextWithTag) Seal(byte[] key32, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        if (key32.Length != 32) throw new ArgumentException("key must be 32 bytes");
        var nonce = RandomBytes(12);
        using var aes = new AesGcm(key32, 16);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[16];
        aes.Encrypt(nonce, plaintext, cipher, tag, aad);
        var combined = new byte[cipher.Length + tag.Length];
        Buffer.BlockCopy(cipher, 0, combined, 0, cipher.Length);
        Buffer.BlockCopy(tag, 0, combined, cipher.Length, tag.Length);
        return (nonce, combined);
    }

    public byte[] Open(byte[] key32, byte[] nonce, byte[] ciphertextWithTag, ReadOnlySpan<byte> aad)
    {
        if (key32.Length != 32) throw new ArgumentException("key must be 32 bytes");
        if (nonce.Length != 12) throw new ArgumentException("nonce must be 12 bytes");
        if (ciphertextWithTag.Length < 16) throw new CryptographicException("invalid ciphertext");
        var cipherLen = ciphertextWithTag.Length - 16;
        var cipher = new byte[cipherLen];
        var tag = new byte[16];
        Buffer.BlockCopy(ciphertextWithTag, 0, cipher, 0, cipherLen);
        Buffer.BlockCopy(ciphertextWithTag, cipherLen, tag, 0, 16);
        var plain = new byte[cipherLen];
        using var aes = new AesGcm(key32, 16);
        aes.Decrypt(nonce, cipher, tag, plain, aad);
        return plain;
    }
}
