using Xunit;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Argon2Bindings.Attributes;

namespace Argon2BindingsTests;

public class Argon2AttributesTests
{
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
        Assert.Throws<ArgumentException>(() => new Argon2MappingMethodAttribute(methodName));
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
        Assert.Throws<ArgumentException>(() => new Argon2ApiBrokenOnPlatformAttribute(platformName, RuntimeInformation.OSArchitecture));
    }

    [Theory]
    [InlineData(-777)]
    [InlineData(777)]
    public void Argon2ApiBrokenOnPlatformAttribute_Constructor_Should_Throw_When_InputArchitectureEnumerationIsInvalid(
        int architecture)
    {
        // Assert
        Assert.Throws<InvalidEnumArgumentException>(() => new Argon2ApiBrokenOnPlatformAttribute(nameof(OSPlatform.Windows), (Architecture)architecture));
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
}