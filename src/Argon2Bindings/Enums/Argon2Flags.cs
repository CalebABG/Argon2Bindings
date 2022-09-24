namespace Argon2Bindings.Enums;

/// <summary>
/// Enum for determining which fields are securely wiped.
/// <remarks>
/// This enum is used as an enum mapping to the argon2 C library
/// preprocessor defined flags.
/// </remarks>
/// </summary>
[Flags]
public enum Argon2Flags
{
    /// <summary>
    /// No wipe
    /// </summary>
    Default = 0,

    /// <summary>
    /// Securely wipe password
    /// </summary>
    ClearPassword = 1 << 0,

    /// <summary>
    /// Securely wipe secret
    /// </summary>
    ClearSecret = 1 << 1
}