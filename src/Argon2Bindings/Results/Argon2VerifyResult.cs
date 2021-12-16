namespace Argon2Bindings.Results;

/// <summary>
/// Result data class for the results of verifying a password
/// matches a given argon2 hash.
/// </summary>
/// <param name="Success">The outcome of the verification</param>
/// <param name="Error">The error message as a result of failed verification or other faults</param>
public record Argon2VerifyResult(bool Success, string? Error = "")
{
    public bool Success { get; } = Success;
    public string? Error { get; } = Error;

    public override string ToString()
    {
        return $"{nameof(Argon2VerifyResult)} {{ {nameof(Success)}: {Success}, " +
               $"{nameof(Error)}: {Error} }}";
    }
}