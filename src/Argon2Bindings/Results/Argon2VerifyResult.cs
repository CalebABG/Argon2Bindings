using Argon2Bindings.Enums;

namespace Argon2Bindings.Results;

/// <summary>
/// Result data class for the results of verifying a password
/// matches a given argon2 hash.
/// </summary>
public readonly record struct Argon2VerifyResult
{
    public readonly bool Success;
    public readonly string Error;

    private Argon2VerifyResult
    (
        bool success,
        string error = ""
    )
    {
        Success = success;
        Error = error;
    }

    public static Argon2VerifyResult FromSuccess()
    {
        return new(true);
    }

    public static Argon2VerifyResult FromError
    (
        string error
    )
    {
        return new(false, error);
    }

    public static Argon2VerifyResult FromStatus
    (
        Argon2Result status
    )
    {
        return status == Argon2Result.Ok
            ? FromSuccess()
            : FromError(Argon2Errors.GetErrorMessage(status));
    }

    public static Argon2VerifyResult FromError
    (
        Exception exception
    )
    {
        return FromError($"{exception.Message}\n{exception.StackTrace}");
    }
}