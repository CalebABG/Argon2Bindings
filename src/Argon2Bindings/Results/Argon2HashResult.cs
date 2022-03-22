using Argon2Bindings.Enums;
using static Argon2Bindings.Argon2Utilities;

namespace Argon2Bindings.Results;

/// <summary>
/// Result data class for the results of a hashing method.
/// </summary>
/// The encoded form of the hash. <br/>
/// Will either be Base64 encoded (with padding, does not alter <see cref="RawHash"/>)
/// when <b>raw</b> hashing is specified to hashing
/// method, or the argon2 <b>encoded</b> hash format when encoded is
/// specified to hashing method.
public readonly record struct Argon2HashResult
{
    public readonly Argon2Result Status;
    public readonly byte[] RawHash;
    public readonly string EncodedHash;

    private Argon2HashResult
    (
        Argon2Result status,
        byte[] rawHash,
        string encodedHash
    )
    {
        Status = status;
        RawHash = rawHash;
        EncodedHash = encodedHash;
    }

    public static Argon2HashResult FromCriteria
    (
        Argon2Result result,
        Argon2Result expected,
        byte[] buffer,
        bool encode
    )
    {
        return result == expected 
            ? FromSuccess(result, buffer, GetString(buffer, encode))
            : FromError(result);
    }

    public static Argon2HashResult FromSuccess
    (
        Argon2Result result,
        byte[] rawHash,
        string encodedHash
    )
    {
        return new(result, rawHash, encodedHash);
    }

    public static Argon2HashResult FromError
    (
        Argon2Result result
    )
    {
        return new(result, Array.Empty<byte>(), string.Empty);
    }
}