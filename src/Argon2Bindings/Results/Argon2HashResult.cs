using Argon2Bindings.Enums;

namespace Argon2Bindings.Results;

/// <summary>
/// Result data class for the results of a hashing method.
/// </summary>
/// The encoded form of the hash. <br/>
/// Will either be Base64 encoded (with padding, does not alter <see cref="RawHash"/>)
/// when <b>raw</b> hashing is specified to hashing
/// method, or the argon2 <b>encoded</b> hash format when encoded is
/// specified to hashing method.
public readonly struct Argon2HashResult
{
    public Argon2Result Status { get; }
    public byte[] RawHash { get; }
    public string EncodedHash { get; }

    public Argon2HashResult(
        Argon2Result status,
        byte[] rawHash,
        string encodedHash)
    {
        Status = status;
        RawHash = rawHash;
        EncodedHash = encodedHash;
    }

    public override string ToString()
    {
        return $"{nameof(Argon2HashResult)} {{ {nameof(Status)}: {Status}, " +
               $"{nameof(RawHash)}: {RawHash.ToHexString()}, " +
               $"{nameof(EncodedHash)}: {EncodedHash} }}";
    }
}