using System;
using Argon2Bindings;
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
}