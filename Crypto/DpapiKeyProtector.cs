using System.Security.Cryptography;

namespace PasswordManage.PC.Crypto;

// ProtectedData 位于 net8.0-windows 目标框架

public sealed class DpapiKeyProtector
{
    public byte[] Protect(ReadOnlySpan<byte> plain) =>
        ProtectedData.Protect(plain.ToArray(), optionalEntropy: null, DataProtectionScope.CurrentUser);

    public byte[] Unprotect(ReadOnlySpan<byte> blob) =>
        ProtectedData.Unprotect(blob.ToArray(), optionalEntropy: null, DataProtectionScope.CurrentUser);
}
