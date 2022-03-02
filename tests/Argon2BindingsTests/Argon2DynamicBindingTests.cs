using Xunit;
using Argon2Bindings;

namespace Argon2BindingsTests;

public class Argon2DynamicBindingTests
{
    [Fact]
    public void Argon2DynamicBinding_GetMappingMethod_Should_Throw_When_InputTypeIsNull()
    {
        // Assert
        Assert.Throws<ArgumentNullException>(() => Argon2DynamicBinding.GetMappingMethodName(null!));
    }

    [Fact]
    public void Argon2DynamicBinding_GetMappingMethod_Should_Throw_When_InputTypeDoesNotHaveMappingMethodAttribute()
    {
        // Assert
        Assert.Throws<Exception>(() => Argon2DynamicBinding.GetMappingMethodName(typeof(Argon2Library)));
    }
}