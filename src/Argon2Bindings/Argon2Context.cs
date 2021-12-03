using static Argon2Bindings.Argon2Constants;

namespace Argon2Bindings;

public record Argon2Context
{
    public readonly uint TimeCost = DefaultTimeCost;
    public readonly uint MemoryCost = DefaultMemoryCost;
    public readonly uint DegreeOfParallelism = DefaultDegreeOfParallelism;
    public readonly uint HashLength = DefaultHashLength;
    public readonly Argon2Type Type = DefaultType;
    public readonly Argon2Version Version = DefaultVersion;
}