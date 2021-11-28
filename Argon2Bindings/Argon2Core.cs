using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Argon2Bindings;

/* Todo: Add argon2 LICENSE file, binary, provide link to exact version of source which was used to compile binary */
/* Todo: Add argon2 lib comments */
/* Todo: Add test project */
/* Todo: Automate building argon2 platform binaries (using Docker?) */
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

        IntPtr passPtr = default,
            saltPtr = default,
            hashBufferPointer = Marshal.AllocHGlobal((int) context.HashLength);

        try
        {
            passPtr = GetPointerToBytes(password);
            saltPtr = GetPointerToBytes(salt);

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

            if (result is not Argon2Result.Ok)
                Console.Error.WriteLine(result);
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(e);

            Marshal.FreeHGlobal(passPtr);
            Marshal.FreeHGlobal(saltPtr);
            Marshal.FreeHGlobal(hashBufferPointer);
        }

        var hashRaw = GetBytesFromPointer(hashBufferPointer, (int) context.HashLength);

        /* Todo: Make sure no weird behavior happens with dealloc pass or salt */
        Marshal.FreeHGlobal(passPtr);
        Marshal.FreeHGlobal(saltPtr);
        Marshal.FreeHGlobal(hashBufferPointer);

        return hashRaw;
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
        uint encodedLength = GetEncodedLength(
            context.TimeCost,
            context.MemoryCost,
            context.DegreeOfParallelism,
            saltLength,
            context.HashLength,
            context.Type
        );

        IntPtr passPtr = default,
            saltPtr = default,
            encodedBufferPointer = Marshal.AllocHGlobal((int) context.HashLength);

        try
        {
            passPtr = GetPointerToBytes(password);
            saltPtr = GetPointerToBytes(salt);

            Argon2Result result = Argon2Library.argon2i_hash_encoded(
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

            if (result is not Argon2Result.Ok)
                Console.Error.WriteLine(result);
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(e);

            Marshal.FreeHGlobal(passPtr);
            Marshal.FreeHGlobal(saltPtr);
            Marshal.FreeHGlobal(encodedBufferPointer);
        }

        var encodedBytes = GetBytesFromPointer(encodedBufferPointer, (int) encodedLength);

        /* Todo: Make sure no weird behavior happens with dealloc pass or salt */
        Marshal.FreeHGlobal(passPtr);
        Marshal.FreeHGlobal(saltPtr);
        Marshal.FreeHGlobal(encodedBufferPointer);

        return Encoding.UTF8.GetString(encodedBytes);
    }

    private static uint GetEncodedLength(
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

    private static byte[] GetBytesFromPointer(IntPtr ptr, int length)
    {
        byte[] outBytes = new byte[length];
        Marshal.Copy(ptr, outBytes, 0, length);

        return outBytes;
    }

    private static IntPtr GetPointerToBytes(byte[] array)
    {
        IntPtr ptr = Marshal.AllocHGlobal(array.Length);
        Marshal.Copy(array, 0, ptr, array.Length);

        return ptr;
    }
}