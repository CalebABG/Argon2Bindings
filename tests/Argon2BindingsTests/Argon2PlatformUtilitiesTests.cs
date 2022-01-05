using Xunit;
using Argon2Bindings;
using System.Runtime.InteropServices;

namespace Argon2BindingsTests;

public class Argon2PlatformUtilitiesTests
{
    [Theory]
    [InlineData(777)]
    [InlineData(-1)]
    public void Argon2PlatformUtilities_GetPlatformArchitecture_Should_Throw_When_InputEnumerationIsInvalid(
        int osArchCode)
    {
        // Assert
        Assert.Throws<Exception>(() => Argon2PlatformUtilities.GetPlatformArchitecture((Architecture)osArchCode));
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
}