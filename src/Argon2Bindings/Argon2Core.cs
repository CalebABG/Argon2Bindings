using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using static Argon2Bindings.Argon2Utilities;

namespace Argon2Bindings;

/* Todo: Add argon2 C lib comments */
/* Todo: Add Unit tests */
/* Todo: Add Benchmark tests */
/* Todo: Check/add tests for memory leaks */
/* Todo: Look into optimizing */

public static class Argon2Core
{
    public static Argon2HashResult HashRaw(
        string password,
        string salt,
        Argon2Context? context = null)
    {
        ValidatePasswordAndSaltStrings(password, salt);

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var saltBytes = Encoding.UTF8.GetBytes(salt);

        return HashRaw(passwordBytes, saltBytes, context);
    }

    public static Argon2HashResult HashRaw(
        byte[] password,
        byte[] salt,
        Argon2Context? context = null)
    {
        return Hash(password, salt, context, false);
    }

    public static Argon2HashResult HashEncoded(
        string password,
        string salt,
        Argon2Context? context = null)
    {
        ValidatePasswordAndSaltStrings(password, salt);

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var saltBytes = Encoding.UTF8.GetBytes(salt);

        return HashEncoded(passwordBytes, saltBytes, context);
    }

    public static Argon2HashResult HashEncoded(
        byte[] password,
        byte[] salt,
        Argon2Context? context = null)
    {
        return Hash(password, salt, context);
    }

    private static Argon2HashResult Hash(
        byte[] passwordBytes,
        byte[] saltBytes,
        Argon2Context? context = null,
        bool encodeHash = true)
    {
        ValidatePasswordAndSaltCollections(passwordBytes, saltBytes);

        var ctx = context ?? new();

        bool rawHashRequested = !encodeHash;

        nuint passwordLength = Convert.ToUInt32(passwordBytes.Length);
        nuint saltLength = Convert.ToUInt32(saltBytes.Length);
        nuint encodedLength = rawHashRequested
            ? 0
            : GetEncodedHashLength(
                ctx.TimeCost,
                ctx.MemoryCost,
                ctx.DegreeOfParallelism,
                (uint)saltLength,
                ctx.HashLength,
                ctx.Type);

        bool errored = false;
        byte[] outputBytes = { };

        Argon2Result result = Argon2Result.Ok;

        IntPtr passPtr = default,
            saltPtr = default,
            rawHashBufferPointer = rawHashRequested
                ? Marshal.AllocHGlobal(Convert.ToInt32(ctx.HashLength))
                : IntPtr.Zero,
            encodedBufferPointer = rawHashRequested
                ? IntPtr.Zero
                : Marshal.AllocHGlobal(Convert.ToInt32(encodedLength));

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

            result = Argon2Library.Argon2Hash(
                ctx.TimeCost,
                ctx.MemoryCost,
                ctx.DegreeOfParallelism,
                passPtr,
                passwordLength,
                saltPtr,
                saltLength,
                rawHashBufferPointer,
                ctx.HashLength,
                encodedBufferPointer,
                encodedLength,
                ctx.Type,
                ctx.Version);

            /* Todo: Throw an exception when no success, or return error w/ empty / incomplete data? */
            if (result is not Argon2Result.Ok)
                throw new Exception(Argon2Errors.GetErrorMessage(result));

            /* Todo: TrimRight null-terminator byte (\x00) */
            outputBytes = rawHashRequested
                ? GetBytesFromPointer(rawHashBufferPointer, Convert.ToInt32(ctx.HashLength))
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

        var encodedForm = rawHashRequested
            ? Convert.ToBase64String(outputBytes)
            : Encoding.UTF8.GetString(outputBytes);

        return new(result, outputBytes, encodedForm);
    }

    private static void ValidatePasswordAndSaltStrings(
        string password,
        string salt)
    {
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("Value cannot be null or empty.", nameof(password));

        if (string.IsNullOrEmpty(salt))
            throw new ArgumentException("Value cannot be null or empty.", nameof(salt));
    }

    private static void ValidatePasswordAndSaltCollections(
        byte[] password,
        byte[] salt)
    {
        if (password is null || password.Length < 1)
            throw new ArgumentException("Value cannot be null or an empty collection.", nameof(password));

        if (salt is null || salt.Length < 1)
            throw new ArgumentException("Value cannot be null or an empty collection.", nameof(salt));
    }

    private static nuint GetEncodedHashLength(
        uint timeCost,
        uint memoryCost,
        uint degreeOfParallelism,
        uint saltLength,
        uint hashLength,
        Argon2Type type)
    {
        var length = Argon2Library.Argon2GetEncodedHashLength(
            timeCost,
            memoryCost,
            degreeOfParallelism,
            saltLength,
            hashLength,
            type);

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

    private static void SafelyFreePointer(
        IntPtr pointer)
    {
        if (pointer == IntPtr.Zero) return;
        Marshal.FreeHGlobal(pointer);
    }
}