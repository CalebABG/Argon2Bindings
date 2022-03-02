namespace Argon2Bindings.Results;

/// <summary>
/// Result data class for the results of verifying a password
/// matches a given argon2 hash.
/// </summary>
public readonly struct Argon2VerifyResult
{
    public readonly bool Success;
    public readonly string Error = "";

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
        string error = ""
    )
    {
        return new(false, error);
    }

    public static Argon2VerifyResult FromError
    (
        Exception exception
    )
    {
        return FromError($"{exception.Message}\n{exception.StackTrace}");
    }

    public override string ToString()
    {
        return $"{nameof(Argon2VerifyResult)} {{ {nameof(Success)}: {Success}, " +
               $"{nameof(Error)}: {Error} }}";
    }
}