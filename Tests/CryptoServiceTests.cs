using PasswordManage.PC.Crypto;
using Xunit;

namespace PasswordManage.PC.Tests;

public class CryptoServiceTests
{
    private readonly CryptoService _c = new();

    [Fact]
    public void SealOpen_RoundTrip()
    {
        var key = _c.RandomBytes(32);
        var pt = "hello vault"u8.ToArray();
        var aad = "record|1|ts"u8.ToArray();
        var (nonce, ct) = _c.Seal(key, pt, aad);
        var outBytes = _c.Open(key, nonce, ct, aad);
        Assert.Equal(pt, outBytes);
    }
}
