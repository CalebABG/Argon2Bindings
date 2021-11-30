using System;
using System.Runtime.InteropServices;
using System.Text;
using static Argon2Bindings.Utilities;

namespace Argon2Bindings;

/* Todo: Add argon2 LICENSE file, binary, provide link to exact version of source which was used to compile binary */
/* Todo: Add argon2 lib comments */
/* Todo: Add test project */
/* Todo: Automate building argon2 platform binaries (using Docker?) */
/* Todo: Add validation to method parameters for all public api methods  */
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
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var saltBytes = Encoding.UTF8.GetBytes(salt);
        var hashBytes = HashRaw(passwordBytes, saltBytes, context);
        return hashBytes;
    }

    public static byte[] HashRaw(
        byte[] password,
        byte[] salt,
        Argon2Context context)
    {
        var hashBytes = Hash(password, salt, context);
        return hashBytes;
    }

    public static string HashEncoded(
        string password,
        string salt,
        Argon2Context context)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var saltBytes = Encoding.UTF8.GetBytes(salt);
        var hashString = HashEncoded(passwordBytes, saltBytes, context);
        return hashString;
    }

    public static string HashEncoded(
        byte[] password,
        byte[] salt,
        Argon2Context context)
    {
        var hashBytes = Hash(password, salt, context);
        var hashString = Encoding.UTF8.GetString(hashBytes);
        return hashString;
    }

    public static byte[] Hash(
        string password,
        string salt,
        Argon2Context context,
        bool encodeHash = true)
    {
        var hashBytes = Hash(
            Encoding.UTF8.GetBytes(password),
            Encoding.UTF8.GetBytes(salt),
            context,
            encodeHash
        );

        return hashBytes;
    }

    public static byte[] Hash(
        byte[] passwordBytes,
        byte[] saltBytes,
        Argon2Context context,
        bool encodeHash = true)
    {
        bool rawHashRequested = !encodeHash;

        uint passwordLength = Convert.ToUInt32(passwordBytes.Length);
        uint saltLength = Convert.ToUInt32(saltBytes.Length);
        uint encodedLength = rawHashRequested
            ? 0
            : GetEncodedLength(
                context.TimeCost,
                context.MemoryCost,
                context.DegreeOfParallelism,
                saltLength,
                context.HashLength,
                context.Type);

        bool errored = false;
        byte[] outputBytes = { };

        IntPtr passPtr = default,
            saltPtr = default,
            rawHashBufferPointer = rawHashRequested
                ? Marshal.AllocHGlobal(Convert.ToInt32(context.HashLength))
                : IntPtr.Zero,
            encodedBufferPointer = rawHashRequested
                ? IntPtr.Zero
                : Marshal.AllocHGlobal(Convert.ToInt32(encodedLength));

        void SafelyFreePointer(IntPtr pointer)
        {
            if (pointer == IntPtr.Zero) return;
            Marshal.FreeHGlobal(pointer);
        }

        void FreeManagedPointers()
        {
            SafelyFreePointer(passPtr);
            SafelyFreePointer(saltPtr);
            SafelyFreePointer(rawHashBufferPointer);
            SafelyFreePointer(encodedBufferPointer);
        }

        try
        {
            passPtr = GetPointerToBytes(passwordBytes);
            saltPtr = GetPointerToBytes(saltBytes);

            Argon2Result result = Argon2Library.argon2_hash(
                context.TimeCost,
                context.MemoryCost,
                context.DegreeOfParallelism,
                passPtr,
                passwordLength,
                saltPtr,
                saltLength,
                rawHashBufferPointer,
                context.HashLength,
                encodedBufferPointer,
                encodedLength,
                context.Type,
                context.Version);

            if (result is not Argon2Result.Ok)
                throw new Exception(Argon2Errors.GetErrorMessage(result));

            /* Todo: TrimRight null-terminator byte (\x00) */
            outputBytes = rawHashRequested
                ? GetBytesFromPointer(rawHashBufferPointer, Convert.ToInt32(context.HashLength))
                : GetBytesFromPointer(encodedBufferPointer, Convert.ToInt32(encodedLength));
        }
        catch (Exception e)
        {
            errored = true;
            FreeManagedPointers();
            WriteError($"{e.Message}\n {e.StackTrace}");
        }
        finally
        {
            if (!errored)
                FreeManagedPointers();
        }

        return outputBytes;
    }

    public static string GetErrorMessage(
        Argon2Result error)
    {
        var messagePtr = Argon2Library.argon2_error_message(error);
        return Marshal.PtrToStringAuto(messagePtr);
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

    private static byte[] GetBytesFromPointer(
        IntPtr ptr,
        int length)
    {
        byte[] outBytes = new byte[length];
        Marshal.Copy(ptr, outBytes, 0, length);

        return outBytes;
    }

    private static IntPtr GetPointerToBytes(
        byte[] array)
    {
        IntPtr ptr = Marshal.AllocHGlobal(array.Length);
        Marshal.Copy(array, 0, ptr, array.Length);

        return ptr;
    }
}