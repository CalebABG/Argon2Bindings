using Argon2Bindings.Enums;
using static Argon2Bindings.Argon2Defaults;

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
    /// The argon2 algorithm version to use
    /// </summary>
    public Argon2Version Version = DefaultVersion;

    /// <summary>
    /// The field clearing flags
    /// </summary>
    public Argon2Flag Flags = DefaultFlag;

    /// <summary>
    /// (Optional) The secret data used for keyed-hashing.
    /// <remarks>
    /// If provided it will be used during hashing
    /// further preventing brute-forcing the password, as the key would be required.
    /// </remarks> 
    /// </summary>
    public byte[]? Secret;

    /// <summary>
    /// (Optional) The associated data used to provide additional
    /// data during hashing.
    /// <remarks>
    /// If provided it will be used as any additional data, similar
    /// to <see cref="Secret"/>, but works differently. <see cref="Secret"/> should
    /// be a cryptographically secure random key only usable during <b>Hashing</b>.
    /// </remarks> 
    /// </summary>
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
            MemoryCost = 1 << 16,
            Type = type,
        };
    }
}