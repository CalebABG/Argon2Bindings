using Xunit;
using Argon2Bindings;
using Argon2Bindings.Enums;

namespace Argon2BindingsTests;

public class Argon2ErrorsTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(-777)]
    public void Argon2Errors_GetErrorMessage_Should_Throw_When_InputEnumerationIsInvalid(
        int error)
    {
        // Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Argon2Errors.GetErrorMessage((Argon2Result)error));
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
}