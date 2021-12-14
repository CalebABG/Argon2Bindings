using System;
using System.Collections;
using System.Runtime.InteropServices;
using System.Text;
using Argon2Bindings.Results;
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
        ValidateString(salt, nameof(salt));
        ValidateString(password, nameof(password));

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
        ValidateString(salt, nameof(salt));
        ValidateString(password, nameof(password));

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

    public static Argon2VerifyResult Verify(
        string inputPassword,
        string encodedPassword,
        Argon2Type type = Argon2Constants.DefaultType)
    {
        ValidateString(inputPassword, nameof(inputPassword));
        ValidateString(encodedPassword, nameof(encodedPassword));

        bool error = false;

        Argon2VerifyResult verifyResult = new(false);

        var inputPasswordBytes = Encoding.UTF8.GetBytes(inputPassword);
        var encodedPasswordBytes = Encoding.UTF8.GetBytes(encodedPassword);

        nuint inputPasswordLength = Convert.ToUInt32(inputPasswordBytes.Length);

        IntPtr inputPasswordBufferPointer = default,
            encodedPasswordBufferPointer = default;

        void FreeManagedPointers()
        {
            SafelyFreePointer(inputPasswordBufferPointer);
            SafelyFreePointer(encodedPasswordBufferPointer);
        }

        try
        {
            inputPasswordBufferPointer = GetPointerToBytes(inputPasswordBytes);
            encodedPasswordBufferPointer = GetPointerToBytes(encodedPasswordBytes);

            var status = Argon2Library.Argon2Verify(
                encodedPasswordBufferPointer,
                inputPasswordBufferPointer,
                inputPasswordLength,
                type);

            verifyResult = status switch
            {
                Argon2Result.Ok => new(true),
                Argon2Result.VerifyMismatch => new(false),
                _ => new(false, Argon2Errors.GetErrorMessage(status))
            };
        }
        catch (Exception e)
        {
            error = true;
            FreeManagedPointers();
            WriteError($"{e.Message}\n {e.StackTrace}");
        }
        finally
        {
            if (!error)
                FreeManagedPointers();
        }

        return verifyResult;
    }

    private static Argon2HashResult Hash(
        byte[] passwordBytes,
        byte[] saltBytes,
        Argon2Context? context = null,
        bool encodeHash = true)
    {
        ValidateCollection(saltBytes, nameof(saltBytes));
        ValidateCollection(passwordBytes, nameof(passwordBytes));

        var ctx = context ?? new();

        bool error = false;

        byte[] outputBytes = { };

        Argon2Result result = Argon2Result.Ok;

        nuint passwordLength = Convert.ToUInt32(passwordBytes.Length);
        nuint saltLength = Convert.ToUInt32(saltBytes.Length);
        nuint bufferLength = encodeHash
            ? GetEncodedHashLength(
                ctx.TimeCost,
                ctx.MemoryCost,
                ctx.DegreeOfParallelism,
                (uint) saltLength,
                ctx.HashLength,
                ctx.Type)
            : ctx.HashLength;

        IntPtr passPtr = default,
            saltPtr = default,
            bufferPointer = default;

        void FreeManagedPointers()
        {
            SafelyFreePointer(passPtr);
            SafelyFreePointer(saltPtr);
            SafelyFreePointer(bufferPointer);
        }

        try
        {
            passPtr = GetPointerToBytes(passwordBytes);
            saltPtr = GetPointerToBytes(saltBytes);
            bufferPointer = Marshal.AllocHGlobal(Convert.ToInt32(bufferLength));

            var hashPtr = encodeHash ? IntPtr.Zero : bufferPointer;
            var encodePtr = encodeHash ? bufferPointer : IntPtr.Zero;
            var encodeLen = encodeHash ? bufferLength : 0;

            result = Argon2Library.Argon2Hash(
                ctx.TimeCost,
                ctx.MemoryCost,
                ctx.DegreeOfParallelism,
                passPtr,
                passwordLength,
                saltPtr,
                saltLength,
                hashPtr,
                ctx.HashLength,
                encodePtr,
                encodeLen,
                ctx.Type,
                ctx.Version);

            /* Todo: Throw an exception when no success, or return error w/ empty / incomplete data? */
            if (result is not Argon2Result.Ok)
                throw new Exception(Argon2Errors.GetErrorMessage(result));

            /* Todo: TrimRight null-terminator byte (\x00) */
            outputBytes = GetBytesFromPointer(bufferPointer, Convert.ToInt32(bufferLength));
        }
        catch (Exception e)
        {
            error = true;
            FreeManagedPointers();
            WriteError($"{e.Message}\n {e.StackTrace}");
        }
        finally
        {
            if (!error)
                FreeManagedPointers();
        }

        var encodedForm = encodeHash
            ? Encoding.UTF8.GetString(outputBytes)
            : Convert.ToBase64String(outputBytes);

        return new(result, outputBytes, encodedForm);
    }

    private static void ValidateString(string @string, string paramName)
    {
        if (string.IsNullOrEmpty(@string))
            throw new ArgumentException("Value cannot be null or an empty.", paramName);
    }

    private static void ValidateCollection(ICollection collection, string paramName)
    {
        if (collection is null || collection.Count < 1)
            throw new ArgumentException("Value cannot be null or an empty collection.", paramName);
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