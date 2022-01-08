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
    /// <summary>
    /// Data Dependent
    /// </summary>
    Argon2D = 0,

    /// <summary>
    /// Data Independent
    /// </summary>
    Argon2I = 1,

    /// <summary>
    /// Hybrid Mode
    /// </summary>
    Argon2Id = 2
}