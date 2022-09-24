using Xunit;
using System.ComponentModel;
using Argon2Bindings;
using Argon2Bindings.Enums;

namespace Argon2BindingsTests;

public class Argon2UtilitiesTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Argon2Utilities_ValidateStringNotNullOrEmpty_Should_Throw_When_InputIsNullOrEmpty
    (
        string input
    )
    {
        // Assert
        Assert.Throws<ArgumentException>(() => Argon2Utilities.ValidateStringNotNullOrEmpty(input));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Argon2Utilities_ValidateStringNotNullOrWhiteSpace_Should_Throw_When_InputIsNullOrWhiteSpace
    (
        string input
    )
    {
        // Assert
        Assert.Throws<ArgumentException>(() => Argon2Utilities.ValidateStringNotNullOrWhiteSpace(input));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new byte[] { })]
    public void Argon2Utilities_ValidateCollection_Should_Throw_When_InputIsNullOrEmpty
    (
        byte[] input
    )
    {
        // Assert
        Assert.Throws<ArgumentException>(() => Argon2Utilities.ValidateCollection(input));
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
        byte[] input = { 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 };

        // Act
        string result = input.ToHexString();

        // Assert
        Assert.Equal("010101010101", result);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new byte[] { })]
    public void Argon2Utilities_GetString_Should_Throw_When_InputIsNullOrEmpty
    (
        byte[] input
    )
    {
        // Assert
        Assert.Throws<ArgumentException>(() => Argon2Utilities.GetString(input, encode: true));
    }

    [Theory]
    [InlineData(new byte[] { 0x61, 0x62, 0x63, 0x64 }, true, "abcd")]
    [InlineData(new byte[] { 0x61, 0x62, 0x63, 0x64 }, false, "YWJjZA==")]
    public void Argon2Utilities_GetString_Should_Return_ValidEncodedString_When_InputIsNotNullOrEmpty
    (
        byte[] input,
        bool encode,
        string expected
    )
    {
        // Act
        string result = Argon2Utilities.GetString(input, encode);

        // Assert
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(typeof(Argon2Flags), (Argon2Flags)(-1))]
    [InlineData(typeof(Argon2Flags), (Argon2Flags)(1 << 4))]
    [InlineData(typeof(Argon2Type), (Argon2Type)(-1))]
    [InlineData(typeof(Argon2Type), (Argon2Type)777)]
    [InlineData(typeof(Argon2Version), (Argon2Version)0xF)]
    [InlineData(typeof(Argon2Version), (Argon2Version)0xFF)]
    public void Argon2Utilities_ValidateEnum_Should_Throw_When_InputIsInvalidForEnumType
    (
        Type enumType,
        object value
    )
    {
        // Assert
        Assert.Throws<InvalidEnumArgumentException>(() => Argon2Utilities.ValidateEnum(enumType, value));
    }

    [Theory]
    [InlineData(null, (Argon2Flags)(-1))]
    [InlineData(typeof(Argon2Flags), null)]
    [InlineData(null, null)]
    public void Argon2Utilities_ValidateEnum_Should_Throw_When_InputParametersAreNull
    (
        Type enumType,
        object value
    )
    {
        // Assert
        Assert.Throws<ArgumentNullException>(() => Argon2Utilities.ValidateEnum(enumType, value));
    }
}