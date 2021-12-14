using static Argon2Bindings.Argon2Constants;

namespace Argon2Bindings;

public struct Argon2Context
{
    public uint TimeCost = DefaultTimeCost;
    public uint MemoryCost = DefaultMemoryCost;
    public uint DegreeOfParallelism = DefaultDegreeOfParallelism;
    public uint HashLength = DefaultHashLength;
    public Argon2Type Type = DefaultType;
    public Argon2Version Version = DefaultVersion;

    public static Argon2Context CreateReasonableContext(
        Argon2Type type = DefaultType)
    {
        return new()
        {
            TimeCost = 3,
            MemoryCost = 1 << 16,
            DegreeOfParallelism = 1,
            HashLength = 32,
            Version = DefaultVersion,
            Type = type,
        };
    }
}