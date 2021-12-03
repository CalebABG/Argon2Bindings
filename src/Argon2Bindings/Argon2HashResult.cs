namespace Argon2Bindings;

public record Argon2HashResult(Argon2Result Status, byte[] RawHash, string EncodedHash)
{
    public Argon2Result Status { get; } = Status;
    public byte[] RawHash { get; } = RawHash;
    public string EncodedHash { get; } = EncodedHash;
}