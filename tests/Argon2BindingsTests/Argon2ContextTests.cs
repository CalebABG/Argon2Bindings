using Xunit;
using Argon2Bindings;

namespace Argon2BindingsTests;

public class Argon2ContextTests
{
    [Fact]
    public void Argon2Context_CreateReasonableContext_Should_Return_NewInstanceWithDifferentConfigurationFromDefault_When_Called()
    {
        // Act
        var result = Argon2Context.CreateReasonableContext();

        // Assert
        Assert.NotEqual(Argon2Defaults.DefaultMemoryCost, result.MemoryCost);
    }
}