namespace Argon2Bindings.Enums;

/// <summary>
/// Enum for determining which fields are securely wiped.
/// <remarks>
/// This enum is used as an enum mapping to the argon2 C library
/// preprocessor defined flags.
/// </remarks>
/// </summary>
[Flags]
public enum Argon2Flag
{
    Default = 0,
    ClearPassword = 1 << 0,
    ClearSecret = 1 << 1
}