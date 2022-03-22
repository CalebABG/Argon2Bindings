using Argon2Bindings.Enums;

namespace Argon2Bindings;

/// <summary>
/// Class which maps argon2 results to their associated
/// error message.
/// </summary>
public static class Argon2Errors
{
    private static readonly Dictionary<Argon2Result, string> ResultMap = new()
    {
        [Argon2Result.Ok] = "OK",
        [Argon2Result.OutputPtrNull] = "Output pointer is NULL",
        [Argon2Result.OutputTooShort] = "Output is too short",
        [Argon2Result.OutputTooLong] = "Output is too long",
        [Argon2Result.PwdTooShort] = "Password is too short",
        [Argon2Result.PwdTooLong] = "Password is too long",
        [Argon2Result.SaltTooShort] = "Salt is too short",
        [Argon2Result.SaltTooLong] = "Salt is too long",
        [Argon2Result.AdTooShort] = "Associated data is too short",
        [Argon2Result.AdTooLong] = "Associated data is too long",
        [Argon2Result.SecretTooShort] = "Secret is too short",
        [Argon2Result.SecretTooLong] = "Secret is too long",
        [Argon2Result.TimeTooSmall] = "Time cost is too small",
        [Argon2Result.TimeTooLarge] = "Time cost is too large",
        [Argon2Result.MemoryTooLittle] = "Memory cost is too small",
        [Argon2Result.MemoryTooMuch] = "Memory cost is too large",
        [Argon2Result.LanesTooFew] = "Too few lanes",
        [Argon2Result.LanesTooMany] = "Too many lanes",
        [Argon2Result.PwdPtrMismatch] = "Password pointer is NULL, but password length is not 0",
        [Argon2Result.SaltPtrMismatch] = "Salt pointer is NULL, but salt length is not 0",
        [Argon2Result.SecretPtrMismatch] = "Secret pointer is NULL, but secret length is not 0",
        [Argon2Result.AdPtrMismatch] = "Associated data pointer is NULL, but ad length is not 0",
        [Argon2Result.MemoryAllocationError] = "Memory allocation error",
        [Argon2Result.FreeMemoryCbkNull] = "The free memory callback is NULL",
        [Argon2Result.AllocateMemoryCbkNull] = "The allocate memory callback is NULL",
        [Argon2Result.IncorrectParameter] = "Argon2_Context context is NULL",
        [Argon2Result.IncorrectType] = "There is no such version of argon2",
        [Argon2Result.OutPtrMismatch] = "Output pointer mismatch",
        [Argon2Result.ThreadsTooFew] = "Not enough threads",
        [Argon2Result.ThreadsTooMany] = "Too many threads",
        [Argon2Result.MissingArgs] = "Missing arguments",
        [Argon2Result.EncodingFail] = "Encoding failed",
        [Argon2Result.DecodingFail] = "Decoding failed",
        [Argon2Result.ThreadFail] = "Threading failure",
        [Argon2Result.DecodingLengthFail] = "Some of encoded parameters are too long or too short",
        [Argon2Result.VerifyMismatch] = "The password does not match the supplied hash",
    };

    /// <summary>
    /// Gets the error message for an argon2 result. <see cref="Argon2Result"/>
    /// </summary>
    /// <param name="result">The result to get the error message for</param>
    /// <returns>The error message that corresponds to the result</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Throws when an invalid or out-of-range result value is passed
    /// </exception>
    public static string GetErrorMessage
    (
        Argon2Result result
    )
    {
        return ResultMap.TryGetValue(result, out var errorMessage)
            ? errorMessage
            : throw new ArgumentOutOfRangeException(nameof(result), result, "Unknown error code");
    }

    /// <summary>
    /// Method which will throw if the provided result
    /// does not match the expected.
    /// </summary>
    /// <param name="result">the result to check</param>
    /// <param name="expected">the expected value</param>
    /// <exception cref="Exception">
    /// Throws if the result does not equal the expected.
    /// </exception>
    public static void ThrowIfNotEqual
    (
        Argon2Result result,
        Argon2Result expected
    )
    {
        if (result != expected)
            throw new Exception(GetErrorMessage(result));
    }
}