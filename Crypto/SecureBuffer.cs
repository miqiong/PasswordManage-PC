namespace PasswordManage.PC.Crypto;

public sealed class SecureBuffer : IDisposable
{
    private byte[] _data;

    public SecureBuffer(byte[] data) => _data = data ?? throw new ArgumentNullException(nameof(data));

    public ReadOnlySpan<byte> Span => _data;

    public void Dispose()
    {
        if (_data.Length > 0)
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(_data);
        _data = Array.Empty<byte>();
    }
}
