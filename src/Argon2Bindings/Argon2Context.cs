using Argon2Bindings.Enums;
using static Argon2Bindings.Argon2Constants;

namespace Argon2Bindings;

/// <summary>
/// Structure to hold a portion of input parameters for an argon2
/// hashing method.
/// <remarks>
/// This structure is used as a data class for the <see cref="Argon2Bindings.Structures.Argon2MarshalContext"/>.
/// </remarks>
/// </summary>
public struct Argon2Context
{
    /// <summary>
    /// The number of iterations
    /// </summary>
    public uint TimeCost = DefaultTimeCost;

    /// <summary>
    /// The amount of memory to use in kibibytes
    /// </summary>
    public uint MemoryCost = DefaultMemoryCost;

    /// <summary>
    /// The number of threads and compute lanes to use
    /// </summary>
    public uint DegreeOfParallelism = DefaultDegreeOfParallelism;
    
    /// <summary>
    /// The desired length of the hash in bytes
    /// </summary>
    public uint HashLength = DefaultHashLength;

    /// <summary>
    /// The argon2 variant to use
    /// </summary>
    public Argon2Type Type = DefaultType;

    /// <summary>
    /// The argon2 version to use
    /// </summary>
    public Argon2Version Version = DefaultVersion;

    /// <summary>
    /// The Field clearing flags
    /// </summary>
    public Argon2Flag Flags = DefaultFlag;

    public byte[]? Secret;
    public byte[]? AssociatedData;

    /// <summary>
    /// Creates a new instance of a context with reasonably
    /// set input parameters to be used in a argon2 hashing method.
    /// </summary>
    /// <param name="type">The argon2 variant to use</param>
    /// <returns>
    /// A new context instance with reasonable parameters set.
    /// </returns>
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