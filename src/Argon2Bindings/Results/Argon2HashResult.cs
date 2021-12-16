using Argon2Bindings.Enums;

namespace Argon2Bindings.Results;

/// <summary>
/// Result data class for the results of a hashing method.
/// </summary>
/// <param name="Status">The outcome of the hashing operation</param>
/// <param name="RawHash">The raw hash</param>
/// <param name="EncodedHash">
/// The encoded form of the hash. <br/>
/// Will either be Base64 encoded (with padding, does not alter <see cref="RawHash"/>)
/// when <b>raw</b> hashing is specified to hashing
/// method, or the argon2 <b>encoded</b> hash format when encoded is
/// specified to hashing method.
/// </param>
public record Argon2HashResult(Argon2Result Status, byte[] RawHash, string EncodedHash)
{
    public Argon2Result Status { get; } = Status;
    public byte[] RawHash { get; } = RawHash;
    public string EncodedHash { get; } = EncodedHash;

    public override string ToString()
    {
        return $"{nameof(Argon2HashResult)} {{ {nameof(Status)}: {Status}, " +
               $"{nameof(RawHash)}: {RawHash.ToHexString()}, " +
               $"{nameof(EncodedHash)}: {EncodedHash} }}";
    }
}