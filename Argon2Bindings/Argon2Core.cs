using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Argon2Bindings;

/* Todo: Add argon2 LICENSE file, binary, provide link to exact version of source which was used to compile binary */
/* Todo: Add argon2 lib comments */
/* Todo: Add test project */

/*
 **Note**
 Always malloc mem for functions where it's 
 expecting a pointer to memory (unless told otherwise)
 
 Steps (Think in terms of IDisposable):
 1. Malloc
 2. Call
 3. Free
*/

public static class Argon2Core
{
    public static byte[] HashRaw(
        string password,
        string salt,
        Argon2Context context)
    {
        return HashRaw(
            Encoding.UTF8.GetBytes(password),
            Encoding.UTF8.GetBytes(salt),
            context
        );
    }

    public static byte[] HashRaw(
        byte[] password,
        byte[] salt,
        Argon2Context context)
    {
        uint passwordLength = (uint) password.Length;
        uint saltLength = (uint) salt.Length;

        IntPtr hashBufferPointer = Marshal.AllocHGlobal((int) context.HashLength);

        IntPtr passPtr = default, saltPtr = default;

        try
        {
            passPtr = GetAllocatedByteArrayIntPtr(password);
            saltPtr = GetAllocatedByteArrayIntPtr(salt);

            Argon2Result result = Argon2Library.argon2i_hash_raw(
                context.TimeCost,
                context.MemoryCost,
                context.DegreeOfParallelism,
                passPtr,
                passwordLength,
                saltPtr,
                saltLength,
                hashBufferPointer,
                context.HashLength
            );

            Console.WriteLine(result);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);

            Marshal.FreeHGlobal(passPtr);
            Marshal.FreeHGlobal(saltPtr);
            Marshal.FreeHGlobal(hashBufferPointer);
        }

        var argon2IHashRaw = GetIntPtrByteArray(hashBufferPointer, (int) context.HashLength);

        /* Todo: Make sure no weird behavior happens with dealloc pass or salt */
        Marshal.FreeHGlobal(passPtr);
        Marshal.FreeHGlobal(saltPtr);
        Marshal.FreeHGlobal(hashBufferPointer);

        return argon2IHashRaw;
    }

    public static string HashEncoded(
        string password,
        string salt,
        Argon2Context context)
    {
        return HashEncoded(
            Encoding.UTF8.GetBytes(password),
            Encoding.UTF8.GetBytes(salt),
            context
        );
    }

    public static string HashEncoded(
        byte[] password,
        byte[] salt,
        Argon2Context context)
    {
        uint passwordLength = (uint) password.Length;
        uint saltLength = (uint) salt.Length;
        uint encodedLength = Argon2GetEncodedLength(
            context.TimeCost,
            context.MemoryCost,
            context.DegreeOfParallelism,
            saltLength,
            context.HashLength,
            context.Type
        );

        IntPtr encodedBufferPointer = Marshal.AllocHGlobal((int) context.HashLength);

        IntPtr passPtr = default,
            saltPtr = default;

        try
        {
            passPtr = GetAllocatedByteArrayIntPtr(password);
            saltPtr = GetAllocatedByteArrayIntPtr(salt);

            Argon2Result argon2Result = Argon2Library.argon2i_hash_encoded(
                context.TimeCost,
                context.MemoryCost,
                context.DegreeOfParallelism,
                passPtr,
                passwordLength,
                saltPtr,
                saltLength,
                context.HashLength,
                encodedBufferPointer,
                encodedLength
            );

            Console.WriteLine(argon2Result);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);

            Marshal.FreeHGlobal(passPtr);
            Marshal.FreeHGlobal(saltPtr);
            Marshal.FreeHGlobal(encodedBufferPointer);
        }

        var argon2IEncodedBytes = GetIntPtrByteArray(encodedBufferPointer, (int) encodedLength);

        /* Todo: Make sure no weird behavior happens with dealloc pass or salt */
        Marshal.FreeHGlobal(passPtr);
        Marshal.FreeHGlobal(saltPtr);
        Marshal.FreeHGlobal(encodedBufferPointer);

        return Encoding.UTF8.GetString(argon2IEncodedBytes);
    }

    private static uint Argon2GetEncodedLength(
        uint timeCost,
        uint memoryCost,
        uint degreeOfParallelism,
        uint saltLength,
        uint hashLength,
        Argon2Type type)
    {
        var length = Argon2Library.argon2_encodedlen(
            timeCost,
            memoryCost,
            degreeOfParallelism,
            saltLength,
            hashLength,
            type
        );

        return length;
    }

    private static byte[] GetIntPtrByteArray(IntPtr ptr, int length)
    {
        byte[] outBytes = new byte[length];
        Marshal.Copy(ptr, outBytes, 0, length);
        return outBytes;
    }

    private static IntPtr GetAllocatedByteArrayIntPtr(byte[] array)
    {
        byte[] retArrayZ = new byte[array.Length];
        Array.Copy(array, retArrayZ, array.Length);

        IntPtr retPtr = Marshal.AllocHGlobal(retArrayZ.Length);
        Marshal.Copy(retArrayZ, 0, retPtr, retArrayZ.Length);

        return retPtr;
    }
}