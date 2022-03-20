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
    /// <summary>
    /// The number of iterations
    /// </summary>
    public const uint DefaultTimeCost = 3;

    /// <summary>
    /// The amount of memory to use in kibibytes (KiB)
    /// </summary>
    public const uint DefaultMemoryCost = 1 << 12;

    /// <summary>
    /// The number of threads and compute lanes to use
    /// </summary>
    public const uint DefaultDegreeOfParallelism = 1;

    /// <summary>
    /// The desired length of the salt in bytes
    /// </summary>
    public const uint DefaultSaltLength = 16;

    /// <summary>
    /// The desired length of the hash in bytes
    /// </summary>
    public const uint DefaultHashLength = 32;

    /// <summary>
    /// The argon2 variant to use
    /// </summary>
    public const Argon2Type DefaultType = Argon2I;

    /// <summary>
    /// The argon2 algorithm version to use
    /// </summary>
    public const Argon2Version DefaultVersion = Argon2VersionNumber;

    /// <summary>
    /// Flag which determines which fields are securely wiped
    /// </summary>
    public const Argon2Flag DefaultFlag = ClearPassword | ClearSecret;

    /// <summary>
    /// The encoding to use for converting strings to byte arrays
    /// </summary>
    public static readonly Encoding DefaultEncoding = Encoding.UTF8;
}