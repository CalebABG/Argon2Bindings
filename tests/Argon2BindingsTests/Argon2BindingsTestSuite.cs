using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Argon2Bindings;
using Argon2Bindings.Attributes;
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
    public void Argon2Utilities_ValidateStringNotNullOrEmpty_Should_Throw_When_InputIsNullOrEmpty(
        string input)
    {
        // Assert
        Assert.Throws<ArgumentException>(() =>
            Argon2Utilities.ValidateStringNotNullOrEmpty(input, nameof(input)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Argon2Utilities_ValidateStringNotNullOrWhiteSpace_ShouldNot_Throw_When_ParamNameIsNullOrEmpty(
        string param)
    {
        // Arrange
        string input = "test";

        // Act
        Argon2Utilities.ValidateStringNotNullOrWhiteSpace(input, param);
    }
    
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Argon2Utilities_ValidateStringNotNullOrWhiteSpace_Should_Throw_When_InputIsNullOrWhiteSpace(
        string input)
    {
        // Assert
        Assert.Throws<ArgumentException>(() =>
            Argon2Utilities.ValidateStringNotNullOrWhiteSpace(input, nameof(input)));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Argon2Utilities_ValidateStringNotNullOrEmpty_ShouldNot_Throw_When_ParamNameIsNullOrEmpty(
        string param)
    {
        // Arrange
        string input = "test";

        // Act
        Argon2Utilities.ValidateStringNotNullOrEmpty(input, param);
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
    [InlineData(typeof(Argon2Type), (Argon2Type) 777)]
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
        var result = Argon2Core.Verify(password, encodedHash);
        
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
        Assert.Throws<ArgumentException>(() => 
            Argon2Core.Hash(password));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new byte[] { })]
    public void Argon2Core_Hash_Should_Throw_When_PasswordCollectionsIsNullOrEmpty(
        byte[] password)
    {
        // Assert
        Assert.Throws<ArgumentException>(() => 
            Argon2Core.Hash(password));
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
    [InlineData("test", "test1234", "$argon2i$v=19$m=4096,t=3,p=1$dGVzdDEyMzQ$mz9PE6IpsqOkYnbENJtM7XWf01XTOBmf5MBkg1IN/Pw")]
    [InlineData("test123", "testing123", "$argon2i$v=19$m=4096,t=3,p=1$dGVzdGluZzEyMw$kOLXgBFKUW5B5jPZY+Ra+uJr4k/h+s742dEQeqJ1xuI")]
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
        var context = new Argon2Context { Type = (Argon2Type) (-1) };
        
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
        Assert.Throws<ArgumentException>(() => 
            Argon2Core.ContextHash(password));
    }
    
    [Theory]
    [InlineData(null)]
    [InlineData(new byte[]{ })]
    public void Argon2Core_ContextHash_Should_Throw_When_PasswordCollectionIsNullOrEmpty(
        byte[] password)
    {
        // Assert
        Assert.Throws<ArgumentException>(() => 
            Argon2Core.ContextHash(password));
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

    [Theory]
    [InlineData(1)]
    [InlineData(-777)]
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
    public void Argon2Context_CreateReasonableContext_Should_Return_NewInstanceWithDifferentConfigurationFromDefault_When_Called()
    {
        // Act
        var result = Argon2Context.CreateReasonableContext();

        // Assert
        Assert.NotEqual(Argon2Defaults.DefaultMemoryCost, result.MemoryCost);
    }

    [Theory]
    [InlineData(777)]
    [InlineData(-1)]
    public void Argon2PlatformUtilities_GetPlatformArchitecture_Should_Throw_When_InputEnumerationIsInvalid(
        int osArchCode)
    {
        // Assert
        Assert.Throws<Exception>(() =>
            Argon2PlatformUtilities.GetPlatformArchitecture((Architecture) osArchCode));
    }
    
    [Theory]
    [InlineData(Architecture.X86)]
    [InlineData(Architecture.X64)]
    [InlineData(Architecture.Arm)]
    [InlineData(Architecture.Arm64)]
    public void Argon2PlatformUtilities_GetPlatformArchitecture_ShouldNot_Throw_When_InputEnumerationIsValid(
        Architecture architecture)
    {
        // Act
        var platformArch = Argon2PlatformUtilities.GetPlatformArchitecture(architecture);
        
        // Assert
        Assert.NotNull(platformArch);
        Assert.NotEmpty(platformArch);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\n")]
    [InlineData("\t")]
    [InlineData("\r")]
    public void Argon2MappingMethodAttribute_Constructor_Should_Throw_When_InputMethodNameIsNullOrWhiteSpace(
        string methodName)
    {
        // Assert
        Assert.Throws<ArgumentException>(() =>
            new Argon2MappingMethodAttribute(methodName));
    }
    
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("\n")]
    [InlineData("\t")]
    [InlineData("\r")]
    public void Argon2ApiBrokenOnPlatformAttribute_Constructor_Should_Throw_When_InputPlatformNameIsNullOrWhiteSpace(
        string platformName)
    {
        // Assert
        Assert.Throws<ArgumentException>(() =>
            new Argon2ApiBrokenOnPlatformAttribute(platformName, RuntimeInformation.OSArchitecture));
    }
    
    [Theory]
    [InlineData(-777)]
    [InlineData(777)]
    public void Argon2ApiBrokenOnPlatformAttribute_Constructor_Should_Throw_When_InputArchitectureEnumerationIsInvalid(
        int architecture)
    {
        // Assert
        Assert.Throws<InvalidEnumArgumentException>(() =>
            new Argon2ApiBrokenOnPlatformAttribute(nameof(OSPlatform.Windows), (Architecture)architecture));
    }
    
    [Theory]
    [InlineData(nameof(OSPlatform.Windows), Architecture.X86)]
    [InlineData(nameof(OSPlatform.OSX), Architecture.Arm64)]
    [InlineData(nameof(OSPlatform.Linux), Architecture.X64)]
    public void Argon2ApiBrokenOnPlatformAttribute_Constructor_ShouldNot_Throw_When_ParametersAreValid(
        string platformName,
        Architecture architecture)
    {
        // Act
        var attrib = new Argon2ApiBrokenOnPlatformAttribute(platformName, architecture);
        
        // Assert
        Assert.NotNull(attrib);
    }

    [Fact]
    public void Argon2DynamicBinding_GetMappingMethod_Should_Throw_When_InputTypeIsNull()
    {
        // Assert
        Assert.Throws<ArgumentNullException>(() =>
            Argon2DynamicBinding.GetMappingMethod(null!));
    }
    
    [Fact]
    public void Argon2DynamicBinding_GetMappingMethod_Should_Throw_When_InputTypeDoesNotHaveMappingMethodAttribute()
    {
        // Assert
        Assert.Throws<Exception>(() =>
            Argon2DynamicBinding.GetMappingMethod(typeof(Argon2Library)));
    }
}