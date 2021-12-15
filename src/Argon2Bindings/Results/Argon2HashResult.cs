using Argon2Bindings.Enums;

namespace Argon2Bindings.Results;

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