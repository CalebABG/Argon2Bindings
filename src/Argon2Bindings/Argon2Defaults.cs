using System.Text;
using Argon2Bindings.Enums;
using static Argon2Bindings.Enums.Argon2Type;
using static Argon2Bindings.Enums.Argon2Version;
using static Argon2Bindings.Enums.Argon2Flag;

namespace Argon2Bindings;

/// <summary>
/// A collection of constants for defining argon2
/// defaults.
/// </summary>
public static class Argon2Defaults
{
    public const uint DefaultTimeCost = 3;
    public const uint DefaultMemoryCost = 1 << 12;
    public const uint DefaultDegreeOfParallelism = 1;
    public const uint DefaultSaltLength = 16;
    public const uint DefaultHashLength = 32;
    public const Argon2Type DefaultType = Argon2I;
    public const Argon2Version DefaultVersion = Argon2VersionNumber;
    public const Argon2Flag DefaultFlag = Default;
    public static readonly Encoding DefaultEncoding = Encoding.UTF8;
}