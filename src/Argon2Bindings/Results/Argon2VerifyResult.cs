namespace Argon2Bindings.Results;

/// <summary>
/// Result data class for the results of verifying a password
/// matches a given argon2 hash.
/// </summary>
public readonly struct Argon2VerifyResult
{
    public bool Success { get; }
    public string? Error { get; }

    public Argon2VerifyResult(
        bool success,
        string? error = "")
    {
        Success = success;
        Error = error;
    }

    public override string ToString()
    {
        return $"{nameof(Argon2VerifyResult)} {{ {nameof(Success)}: {Success}, " +
               $"{nameof(Error)}: {Error} }}";
    }
}