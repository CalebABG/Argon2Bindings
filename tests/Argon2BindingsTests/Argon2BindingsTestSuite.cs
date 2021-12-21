using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Argon2Bindings;
using Argon2Bindings.Enums;
using Xunit;

namespace Argon2BindingsTests;

// Arrange
// Act
// Assert

public class Argon2BindingsTestSuite
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Argon2Utilities_ValidateString_Should_Throw_When_InputIsNullOrEmpty(
        string input)
    {
        // Assert
        Assert.Throws<ArgumentException>(() =>
            Argon2Utilities.ValidateString(input, nameof(input)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Argon2Utilities_ValidateString_ShouldNot_Throw_When_ParamNameIsNullOrEmpty(
        string param)
    {
        // Arrange
        string input = "test";

        // Act
        Argon2Utilities.ValidateString(input, param);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new byte[] { })]
    public void Argon2Utilities_ValidateCollection_Should_Throw_When_InputIsNullOrEmpty(
        byte[] input)
    {
        // Assert
        Assert.Throws<ArgumentException>(() =>
            Argon2Utilities.ValidateCollection(input, nameof(input)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Argon2Utilities_ValidateCollection_ShouldNot_Throw_When_ParamNameIsNullOrEmpty(
        string param)
    {
        // Arrange
        byte[] input = {0x1, 0x2};

        // Act
        Argon2Utilities.ValidateCollection(input, param);
    }

    [Fact]
    public void Argon2Utilities_ContextDataValid_Should_Return_False_When_InputIsNull()
    {
        // Arrange
        byte[] input = default!;

        // Act
        var result = Argon2Utilities.ContextDataValid(input);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Argon2Utilities_ContextDataValid_Should_Return_False_When_InputIsEmpty()
    {
        // Arrange
        byte[] input = Array.Empty<byte>();

        // Act
        var result = Argon2Utilities.ContextDataValid(input);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Argon2Utilities_ContextDataValid_Should_Return_True_When_InputIsValid()
    {
        // Arrange
        byte[] input = {0x1, 0x2, 0x3, 0x4};

        // Act
        var result = Argon2Utilities.ContextDataValid(input);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Argon2Utilities_ToHexString_Should_Throw_When_InputIsNull()
    {
        // Arrange
        byte[] input = default!;

        // Assert
        Assert.Throws<ArgumentNullException>(() => input.ToHexString());
    }

    [Fact]
    public void Argon2Utilities_ToHexString_Should_Return_EmptyString_When_InputIsEmpty()
    {
        // Arrange
        byte[] input = Array.Empty<byte>();

        // Act
        string result = input.ToHexString();

        // Assert
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void Argon2Utilities_ToHexString_Should_Return_ValidHexString_When_InputIsValid()
    {
        // Arrange
        byte[] input = {0x1, 0x1, 0x1, 0x1, 0x1, 0x1};

        // Act
        string result = input.ToHexString();

        // Assert
        Assert.Equal("010101010101", result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new byte[] { })]
    public void Argon2Utilities_GetEncodedString_Should_Throw_When_InputIsNullOrEmpty(
        byte[] input)
    {
        // Assert
        Assert.Throws<ArgumentException>(() =>
            Argon2Utilities.GetEncodedString(input, true));
    }

    [Theory]
    [InlineData(new byte[] {0x61, 0x62, 0x63, 0x64}, true, "abcd")]
    [InlineData(new byte[] {0x61, 0x62, 0x63, 0x64}, false, "YWJjZA==")]
    public void Argon2Utilities_GetEncodedString_Should_Return_ValidEncodedString_When_InputIsNotNullOrEmpty(
        byte[] input,
        bool encodeHash,
        string expected)
    {
        // Act
        string result = Argon2Utilities.GetEncodedString(input, encodeHash);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(typeof(Argon2Flag), (Argon2Flag) (-1))]
    [InlineData(typeof(Argon2Flag), (Argon2Flag) (1 << 4))]
    [InlineData(typeof(Argon2Type), (Argon2Type) (-1))]
    [InlineData(typeof(Argon2Type), (Argon2Type) 999)]
    [InlineData(typeof(Argon2Version), (Argon2Version) 0xF)]
    [InlineData(typeof(Argon2Version), (Argon2Version) 0xFF)]
    public void Argon2Utilities_ValidateEnum_Should_Throw_When_InputIsInvalidForEnumType(
        Type enumType,
        object value)
    {
        // Assert
        Assert.Throws<InvalidEnumArgumentException>(() =>
            Argon2Utilities.ValidateEnum(enumType, value));
    }

    [Theory]
    [InlineData(null, (Argon2Flag) (-1))]
    [InlineData(typeof(Argon2Flag), null)]
    [InlineData(null, null)]
    public void Argon2Utilities_ValidateEnum_Should_Throw_When_InputParametersAreNull(
        Type enumType,
        object value)
    {
        // Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2Utilities.ValidateEnum(enumType, value));
    }

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
        Assert.Throws<ArgumentException>(() =>
            Argon2Core.Verify(password, encodedHash));
    }

    [Theory]
    [InlineData(null, "test1234")]
    [InlineData("", "test1234")]
    [InlineData("test1234", null)]
    [InlineData("test1234", "")]
    public void Argon2Core_Hash_Should_Throw_When_PasswordOrSaltStringsAreNullOrEmpty(
        string password,
        string salt)
    {
        // Assert
        Assert.Throws<ArgumentException>(() => Argon2Core.Hash(password, salt));
    }

    [Theory]
    [InlineData(null, new byte[] {0x74, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33, 0x34})]
    [InlineData(new byte[] { }, new byte[] {0x74, 0x65, 0x73, 0x74, 0x31, 0x32, 0x33, 0x34})]
    [InlineData(new byte[] {0x74, 0x65, 0x73, 0x74}, null)]
    [InlineData(new byte[] {0x74, 0x65, 0x73, 0x74}, new byte[] { })]
    public void Argon2Core_Hash_Should_Throw_When_PasswordOrSaltCollectionsAreNullOrEmpty(
        byte[] password,
        byte[] salt)
    {
        // Assert
        Assert.Throws<ArgumentException>(() => Argon2Core.Hash(password, salt));
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
    [InlineData(1)]
    [InlineData(-999)]
    public void Argon2Errors_GetErrorMessage_Should_Throw_When_InputEnumerationIsInvalid(
        int error)
    {
        // Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2Errors.GetErrorMessage((Argon2Result) error));
    }

    [Theory]
    [InlineData(Argon2Result.Ok)]
    [InlineData(Argon2Result.VerifyMismatch)]
    [InlineData(Argon2Result.FreeMemoryCbkNull)]
    [InlineData(Argon2Result.MemoryTooLittle)]
    public void Argon2Errors_GetErrorMessage_Should_Return_NonNullOrEmptyString_When_InputEnumerationIsValid(
        Argon2Result error)
    {
        // Act
        var result = Argon2Errors.GetErrorMessage(error);

        // Assert
        Assert.NotNull(result);
        Assert.NotEmpty(result);
    }

    [Fact]
    public void Argon2Context_CreateReasonableContext_Should_Return_NonNullResult_When_Called()
    {
        // Act
        var result = Argon2Context.CreateReasonableContext();

        // Assert
        Assert.NotNull(result);
    }

    [Theory]
    [InlineData(999)]
    [InlineData(-1)]
    public void Argon2PlatformUtilities_GetPlatformArchitecture_Should_Throw_When_InputEnumerationIsInvalid(
        int osArchCode)
    {
        // Assert
        Assert.Throws<Exception>(() =>
            Argon2PlatformUtilities.GetPlatformArchitecture((Architecture) osArchCode));
    }
}