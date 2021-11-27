using static Argon2Bindings.Argon2Constants;

namespace Argon2Bindings;

public struct Argon2Context
{
    public uint TimeCost;
    public uint MemoryCost;
    public uint DegreeOfParallelism;
    public uint HashLength;
    public Argon2Type Type;

    public Argon2Context()
    {
        TimeCost = DefaultTimeCost;
        MemoryCost = DefaultMemoryCost;
        DegreeOfParallelism = DefaultDegreeOfParallelism;
        HashLength = DefaultHashLength;
        Type = DefaultType;
    }
}