namespace Argon2Bindings.Enums;

/// <summary>
/// Enum for specifying the argon2 algorithm version.
/// <remarks>
/// This enum is used as an enum mapping to the argon2 C library
/// <b>argon2_version</b> enum type.
/// </remarks>
/// </summary>
public enum Argon2Version
{
    /// <summary>
    /// Version 1.0
    /// </summary>
    Argon2Version10 = 0x10,

    /// <summary>
    /// Version 1.3
    /// </summary>
    Argon2Version13 = 0x13,

    /// <summary>
    /// Latest version
    /// </summary>
    Argon2VersionNumber = Argon2Version13
}