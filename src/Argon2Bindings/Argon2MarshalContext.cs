using System.Runtime.InteropServices;

namespace Argon2Bindings;

/// <summary>
/// Structure which holds all context parameters for an argon2
/// hashing method. 
/// <remarks>
/// This structure is used as a mapping structure to the argon2 C library
/// <b>argon2_context</b> structure. When used in a binding delegate, this
/// struct is marshalled automatically to the argon2 C library argon2_context type
/// by specifying the <see cref="StructLayoutAttribute"/>.
/// Checkout <seealso cref="Marshal"/>, as well as <seealso cref="StructLayoutAttribute"/>
/// for more details on marshalling and structure layout specifications.
/// </remarks>
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct Argon2MarshalContext
{
    /// <summary>
    /// Output buffer pointer
    /// </summary>
    public byte* Out;

    /// <summary>
    /// Output buffer length
    /// </summary>
    public uint OutLength;

    /// <summary>
    /// Password buffer pointer
    /// </summary>
    public byte* PasswordPtr;

    /// <summary>
    /// Password buffer length
    /// </summary>
    public uint PasswordLength;

    /// <summary>
    /// Salt buffer pointer
    /// </summary>
    public byte* SaltPtr;

    /// <summary>
    /// Salt buffer length
    /// </summary>
    public uint SaltLength;

    /// <summary>
    /// Secret buffer pointer
    /// </summary>
    public byte* SecretPtr;

    /// <summary>
    /// Secret buffer length
    /// </summary>
    public uint SecretLength;

    /// <summary>
    /// Associated data buffer pointer
    /// </summary>
    public byte* AssociatedDataPtr;

    /// <summary>
    /// Associated data buffer length
    /// </summary>
    public uint AssociatedDataLength;

    /// <summary>
    /// Number of iterations
    /// </summary>
    public uint TimeCost;

    /// <summary>
    /// Amount of memory to use in kibibytes
    /// </summary>
    public uint MemoryCost;

    /// <summary>
    /// Number of lanes
    /// </summary>
    public uint Lanes;

    /// <summary>
    /// Number of threads
    /// </summary>
    public uint Threads;

    /// <summary>
    /// Algorithm version number
    /// </summary>
    public uint Version;

    /// <summary>
    /// Pointer to memory allocator
    /// </summary>
    [MarshalAs(UnmanagedType.FunctionPtr)]
    public Argon2MemoryAllocator? AllocateCbk;

    /// <summary>
    /// Pointer to memory de-allocator
    /// </summary>
    [MarshalAs(UnmanagedType.FunctionPtr)]
    public Argon2MemoryDeallocator? FreeCbk;

    /// <summary>
    /// Field clearing flags
    /// </summary>
    public uint Flags;

    /// <summary>
    /// Mapping delegate to argon2 function pointer for memory allocator 
    /// </summary>
    public delegate int Argon2MemoryAllocator(
        byte** memory,
        nuint bytes_to_allocate
    );

    /// <summary>
    /// Mapping delegate to argon2 function pointer for memory de-allocator
    /// </summary>
    public delegate void Argon2MemoryDeallocator(
        byte* memory,
        nuint bytes_to_allocate
    );

    /// <summary>
    /// Creates a new instance of a context given the method
    /// parameters, as well as the input parameters from the
    /// context data class <see cref="Argon2Context"/>.
    /// </summary>
    /// <param name="hashBufferPtr">The pointer to the buffer to write the raw hash to</param>
    /// <param name="hashBufferLen">The length of the hash in bytes</param>
    /// <param name="passwordBufferPtr">The pointer to the password</param>
    /// <param name="passwordBufferLen">The length of the password in bytes</param>
    /// <param name="saltBufferPtr">The pointer to the salt</param>
    /// <param name="saltBufferLen">The length of the salt in bytes</param>
    /// <param name="secretBufferPtr">The pointer to the secret data</param>
    /// <param name="secretBufferLen">The length of the secret data in bytes</param>
    /// <param name="associatedDataBufferPtr">The pointer to the associated data</param>
    /// <param name="associatedDataBufferLen">The length of the associated data in bytes</param>
    /// <param name="context">The context to use</param>
    /// <returns></returns>
    public static Argon2MarshalContext Create(
        byte* hashBufferPtr,
        uint hashBufferLen,
        byte* passwordBufferPtr,
        uint passwordBufferLen,
        byte* saltBufferPtr,
        uint saltBufferLen,
        byte* secretBufferPtr,
        uint secretBufferLen,
        byte* associatedDataBufferPtr,
        uint associatedDataBufferLen,
        Argon2Context context)
    {
        return new()
        {
            Out = hashBufferPtr,
            OutLength = hashBufferLen,
            PasswordPtr = passwordBufferPtr,
            PasswordLength = passwordBufferLen,
            SaltPtr = saltBufferPtr,
            SaltLength = saltBufferLen,
            SecretPtr = secretBufferPtr,
            SecretLength = secretBufferLen,
            AssociatedDataPtr = associatedDataBufferPtr,
            AssociatedDataLength = associatedDataBufferLen,
            TimeCost = context.TimeCost,
            MemoryCost = context.MemoryCost,
            Lanes = context.DegreeOfParallelism,
            Threads = context.DegreeOfParallelism,
            Version = (uint)context.Version,
            AllocateCbk = null,
            FreeCbk = null,
            Flags = (uint)context.Flags
        };
    }
}