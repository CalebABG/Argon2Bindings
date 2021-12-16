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
    Argon2Version10 = 0x10,
    Argon2Version13 = 0x13,
    Argon2VersionNumber = Argon2Version13
}