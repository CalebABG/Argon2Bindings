namespace Argon2Bindings.Enums;

/// <summary>
/// Enum representing the outcome/result of an operation in the argon2 C library.
/// <remarks>
/// This enum is used as an enum mapping to the argon2 C library
/// <b>argon2_error_codes</b> enum type, as well as integer return results.
/// </remarks>
/// </summary>
public enum Argon2Result
{
    Ok = 0,
    OutputPtrNull = -1,
    OutputTooShort = -2,
    OutputTooLong = -3,
    PwdTooShort = -4,
    PwdTooLong = -5,
    SaltTooShort = -6,
    SaltTooLong = -7,
    AdTooShort = -8,
    AdTooLong = -9,
    SecretTooShort = -10,
    SecretTooLong = -11,
    TimeTooSmall = -12,
    TimeTooLarge = -13,
    MemoryTooLittle = -14,
    MemoryTooMuch = -15,
    LanesTooFew = -16,
    LanesTooMany = -17,
    PwdPtrMismatch = -18,
    SaltPtrMismatch = -19,
    SecretPtrMismatch = -20,
    AdPtrMismatch = -21,
    MemoryAllocationError = -22,
    FreeMemoryCbkNull = -23,
    AllocateMemoryCbkNull = -24,
    IncorrectParameter = -25,
    IncorrectType = -26,
    OutPtrMismatch = -27,
    ThreadsTooFew = -28,
    ThreadsTooMany = -29,
    MissingArgs = -30,
    EncodingFail = -31,
    DecodingFail = -32,
    ThreadFail = -33,
    DecodingLengthFail = -34,
    VerifyMismatch = -35
}