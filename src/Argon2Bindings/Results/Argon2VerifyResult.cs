namespace Argon2Bindings.Results;

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