using static Argon2Bindings.Argon2Utilities;

namespace Argon2Bindings.Attributes;

/// <summary>
/// Attribute used for specifying which method
/// in the argon2 C library to use.
/// </summary>
/// <remarks>
/// This attribute is to be used with / attached to a
/// binding delegate in <see cref="Argon2Library"/> as a means
/// of mapping the C# delegate with the appropriate / matching argon2 C library
/// function.
/// </remarks>
[AttributeUsage(AttributeTargets.Delegate)]
internal sealed class Argon2MappingMethodAttribute : Attribute
{
    /// <summary>
    /// The name of the argon2 C library function
    /// to map to.
    /// </summary>
    public readonly string Name;

    public Argon2MappingMethodAttribute(string name)
    {
        ValidateStringNotNullOrWhiteSpace(name);
        Name = name;
    }
}