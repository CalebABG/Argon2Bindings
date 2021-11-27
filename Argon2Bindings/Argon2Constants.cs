using static Argon2Bindings.Argon2Type;

namespace Argon2Bindings;

internal static class Argon2Constants
{
    public const uint DefaultTimeCost = 3;
    public const uint DefaultMemoryCost = 12;
    public const uint DefaultDegreeOfParallelism = 1;
    public const uint DefaultHashLength = 32;
    public const Argon2Type DefaultType = Argon2I;
}