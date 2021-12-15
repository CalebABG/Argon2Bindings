using System;
using System.Runtime.InteropServices;

namespace Argon2Bindings.Structures;

[StructLayout(LayoutKind.Sequential)]
internal struct Argon2MarshalContext
{
    public IntPtr Out;
    public uint OutLength;

    public IntPtr PasswordPtr;
    public uint PasswordLength;

    public IntPtr SaltPtr;
    public uint SaltLength;

    public IntPtr SecretPtr;
    public uint SecretLength;

    public IntPtr AssociatedDataPtr;
    public uint AssociatedDataLength;

    public uint TimeCost;
    public uint MemoryCost;
    public uint Lanes;
    public uint Threads;
    public uint Version;
    public uint Flags;

    [MarshalAs(UnmanagedType.FunctionPtr)] 
    public MemoryAllocator? AllocateCbk;

    [MarshalAs(UnmanagedType.FunctionPtr)] 
    public MemoryDeallocator? FreeCbk;

    public unsafe delegate int MemoryAllocator(
        uint** memory,
        nuint bytes_to_allocate
    );

    public unsafe delegate int MemoryDeallocator(
        uint* memory,
        nuint bytes_to_allocate
    );

    public static Argon2MarshalContext Create(
        IntPtr hashBufferPtr,
        uint hashBufferLen,
        IntPtr passwordBufferPtr,
        uint passwordBufferLen,
        IntPtr saltBufferPtr,
        uint saltBufferLen,
        IntPtr secretBufferPtr,
        uint secretBufferLen,
        IntPtr associatedDataBufferPtr,
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
            Version = (uint) context.Version,
            AllocateCbk = null,
            FreeCbk = null,
            Flags = (uint) context.Flags
        };
    }
}