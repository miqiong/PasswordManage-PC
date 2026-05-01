using System.Security.Cryptography;
using PasswordManage.PC.Crypto;
using Xunit;

namespace PasswordManage.PC.Tests;

public class MasterPasswordVerifierTests
{
    private readonly MasterPasswordVerifier _v = new();

    [Fact]
    public void SamePasswordSameSalt_SameVerifier()
    {
        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);
        var pwd = "correct horse battery staple"u8.ToArray();
        var (_, a) = _v.DeriveKekAndVerifier(pwd, salt);
        var (_, b) = _v.DeriveKekAndVerifier(pwd, salt);
        Assert.Equal(a, b);
    }

    [Fact]
    public void WrongPassword_VerifyFails()
    {
        var salt = new byte[16];
        RandomNumberGenerator.Fill(salt);
        var good = "secret-a"u8.ToArray();
        var bad = "secret-b"u8.ToArray();
        var (_, stored) = _v.DeriveKekAndVerifier(good, salt);
        Assert.True(_v.VerifyMasterPassword(good, salt, stored));
        Assert.False(_v.VerifyMasterPassword(bad, salt, stored));
    }
}
