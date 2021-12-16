namespace Argon2Bindings.Enums;

/// <summary>
/// Enum for specifying the argon2 variant.
/// <remarks>
/// This enum is used as an enum mapping to the argon2 C library
/// <b>argon2_type</b> enum type.
/// </remarks>
/// </summary>
public enum Argon2Type
{
    Argon2D = 0,
    Argon2I = 1,
    Argon2Id = 2
}