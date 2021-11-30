using static Argon2Bindings.Argon2Constants;

namespace Argon2Bindings;

public struct Argon2Context
{
    public readonly uint TimeCost;
    public readonly uint MemoryCost;
    public readonly uint DegreeOfParallelism;
    public readonly uint HashLength;
    public readonly Argon2Type Type;
    public readonly Argon2Version Version;

    public Argon2Context()
    {
        TimeCost = DefaultTimeCost;
        MemoryCost = DefaultMemoryCost;
        DegreeOfParallelism = DefaultDegreeOfParallelism;
        HashLength = DefaultHashLength;
        Type = DefaultType;
        Version = DefaultVersion;
    }
}