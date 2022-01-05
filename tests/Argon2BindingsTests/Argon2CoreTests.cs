using Xunit;
using Argon2Bindings;
using Argon2Bindings.Enums;
using Argon2Bindings.Results;

namespace Argon2BindingsTests;

public class Argon2CoreTests
{
    [Theory]
    [InlineData(null, "test")]
    [InlineData("", "test")]
    [InlineData("test", null)]
    [InlineData("test", "")]
    public void Argon2Core_Verify_Should_Throw_When_PasswordOrEncodedHashIsNullOrEmpty(
        string password,
        string encodedHash)
    {
        // Assert
        Assert.Throws<ArgumentException>(() => Argon2Core.Verify(password, encodedHash));
    }

    [Fact]
    public void Argon2Core_Verify_Should_Return_True_When_ValidPasswordProvided()
    {
        // Arrange
        var password = "test";
        var encodedHash = "$argon2i$v=19$m=2048,t=3,p=1$dGVzdGluZzQ1Ng$VaMcEYLV/tlKirCtI1MOF5UfaD6BCQvbTNggdHDVLNo";

        // Act
        var result = Argon2Core.Verify(password, encodedHash);

        // Assert
        Assert.NotNull(result);
        Assert.True(result.Success);
    }

    [Fact]
    public void Argon2Core_Verify_Should_Return_False_When_InvalidPasswordProvided()
    {
        // Arrange
        var password = "testing1234";
        var encodedHash = "$argon2i$v=19$m=2048,t=3,p=1$dGVzdGluZzQ1Ng$VaMcEYLV/tlKirCtI1MOF5UfaD6BCQvbTNggdHDVLNo";

        // Act
        var result = Argon2Core.Verify(password, encodedHash);

        // Assert
        Assert.NotNull(result);
        Assert.False(result.Success);
    }

    [Fact]
    public void Argon2Core_Verify_Should_Return_FalseWithError_When_EncodedHashIsInvalid()
    {
        // Arrange
        var password = "test";

        // Salt removed
        var encodedHash = "$argon2i$v=19$m=2048,t=3,p=1$VaMcEYLV/tlKirCtI1MOF5UfaD6BCQvbTNggdHDVLNo";

        // Act
        Argon2VerifyResult result = Argon2Core.Verify(password, encodedHash);

        // Assert
        Assert.NotNull(result);
        Assert.False(result.Success);
        Assert.NotEmpty(result.Error!);
    }

    [Fact]
    public void Argon2Core_Verify_Should_Return_FalseWithError_When_TypeIsInvalid()
    {
        // Arrange
        var password = "test";

        // Salt removed
        var encodedHash = "$argon2i$v=19$m=2048,t=3,p=1$VaMcEYLV/tlKirCtI1MOF5UfaD6BCQvbTNggdHDVLNo";

        // Act
        Argon2VerifyResult result = Argon2Core.Verify(password, encodedHash, (Argon2Type)(-1));

        // Assert
        Assert.NotNull(result);
        Assert.False(result.Success);
        Assert.NotEmpty(result.Error!);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Argon2Core_Hash_Should_Throw_When_PasswordStringIsNullOrEmpty(
        string password)
    {
        // Assert
        Assert.Throws<ArgumentException>(() => Argon2Core.Hash(password));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new byte[] { })]
    public void Argon2Core_Hash_Should_Throw_When_PasswordCollectionsIsNullOrEmpty(
        byte[] password)
    {
        // Assert
        Assert.Throws<ArgumentException>(() => Argon2Core.Hash(password));
    }

    [Fact]
    public void Argon2Core_Hash_Should_Return_SaltTooShortResult_When_SaltStringIsTooShort()
    {
        // Arrange
        string password = "test";
        string salt = "tst";

        // Act
        var result = Argon2Core.Hash(password, salt);

        Assert.NotNull(result);
        Assert.Equal(Argon2Result.SaltTooShort, result.Status);
    }

    [Theory]
    [InlineData("test", "test1234",
        "$argon2i$v=19$m=4096,t=3,p=1$dGVzdDEyMzQ$mz9PE6IpsqOkYnbENJtM7XWf01XTOBmf5MBkg1IN/Pw")]
    [InlineData("test123", "testing123",
        "$argon2i$v=19$m=4096,t=3,p=1$dGVzdGluZzEyMw$kOLXgBFKUW5B5jPZY+Ra+uJr4k/h+s742dEQeqJ1xuI")]
    public void Argon2Core_Hash_Should_Return_ValidEncodedHash_When_ValidParametersProvided_Using_DefaultContext(
        string password,
        string salt,
        string expectedEncodedHash)
    {
        // Arrange
        var context = new Argon2Context();

        // Act
        var result = Argon2Core.Hash(password, salt, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(expectedEncodedHash, result.EncodedHash);
    }

    [Theory]
    [InlineData("test", "testing456", "40466673a1b16ff19366744ae0db8bac2fa65e2595a6c8e712108bcf62f66467")]
    [InlineData("testing123", "testing6", "6b50b0efc71314d6f69164066e97182884a28e2dc6e2769d555c364e76d89735")]
    public void Argon2Core_Hash_Should_Return_ValidRawHash_When_ValidParametersProvided_Using_DefaultContext(
        string password,
        string salt,
        string expectedRawHashHex)
    {
        // Arrange
        var context = new Argon2Context();

        // Act
        var result = Argon2Core.Hash(password, salt, context, false);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(expectedRawHashHex.ToUpper(), result.RawHash.ToHexString());
    }

    [Fact]
    public void Argon2Core_Hash_Should_Return_ErrorResult_When_InvalidArgon2TypeSetInContext()
    {
        // Arrange
        var password = "testing";
        var salt = "testing1234";
        var context = new Argon2Context { Type = (Argon2Type)(-1) };

        // Act
        var result = Argon2Core.Hash(password, salt, context, false);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(Argon2Result.IncorrectType, result.Status);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Argon2Core_ContextHash_Should_Throw_When_PasswordStringIsNullOrEmpty(
        string password)
    {
        // Assert
        Assert.Throws<ArgumentException>(() => Argon2Core.ContextHash(password));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new byte[] { })]
    public void Argon2Core_ContextHash_Should_Throw_When_PasswordCollectionIsNullOrEmpty(
        byte[] password)
    {
        // Assert
        Assert.Throws<ArgumentException>(() => Argon2Core.ContextHash(password));
    }

    [Fact]
    public void Argon2Core_ContextHash_Should_Return_ErrorResult_When_InvalidContextProvided()
    {
        // Arrange
        var context = new Argon2Context { Type = (Argon2Type)(-1) };

        // Act
        Argon2HashResult result = Argon2Core.ContextHash("test", context: context);

        // Assert
        Assert.NotNull(result);
        Assert.NotEqual(Argon2Result.Ok, result.Status);
    }

    [Theory]
    [InlineData("test", "testing123", "1f07729a6e5ae8b4032d6a187a7b30292653491c5e6fea5eca8deb73dabe5704")]
    public void Argon2Core_ContextHash_Should_Return_ValidHash_When_ValidParametersProvided_Using_DefaultContext(
        string password,
        string salt,
        string expectedHash)
    {
        // Arrange
        var context = new Argon2Context();

        // Act
        var result = Argon2Core.ContextHash(password, salt, context);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(expectedHash.ToUpper(), result.RawHash.ToHexString());
    }
}