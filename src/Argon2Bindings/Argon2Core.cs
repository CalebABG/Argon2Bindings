using System;
using System.Collections;
using System.Runtime.InteropServices;
using System.Text;
using Argon2Bindings.Enums;
using Argon2Bindings.Results;
using Argon2Bindings.Structures;
using static Argon2Bindings.Argon2Utilities;

namespace Argon2Bindings;

/* Todo: Add argon2 C lib comments */
/* Todo: Add Unit tests */
/* Todo: Add Benchmark tests */
/* Todo: Check/add tests for memory leaks */
/* Todo: Look into optimizing */

public static class Argon2Core
{
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

    public static Argon2HashResult Hash(
        string password,
        string salt,
        Argon2Context? context = null,
        bool encodeHash = true)
    {
        ValidateString(salt, nameof(salt));
        ValidateString(password, nameof(password));

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var saltBytes = Encoding.UTF8.GetBytes(salt);

        return Hash(passwordBytes, saltBytes, context, encodeHash);
    }

    public static Argon2HashResult Hash(
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
            SafelyFreePointer(saltPtr);
            SafelyFreePointer(passPtr);
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

    public static Argon2HashResult ContextHash(
        string password,
        string salt,
        Argon2Context? context = null)
    {
        ValidateString(salt, nameof(salt));
        ValidateString(password, nameof(password));

        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var saltBytes = Encoding.UTF8.GetBytes(salt);

        return ContextHash(passwordBytes, saltBytes, context);
    }

    /* Todo: Yes, I know there's similar logic here as in method `Hash` (will cleanup/refactor) */
    public static Argon2HashResult ContextHash(
        byte[] passwordBytes,
        byte[] saltBytes,
        Argon2Context? context = null)
    {
        ValidateCollection(saltBytes, nameof(saltBytes));
        ValidateCollection(passwordBytes, nameof(passwordBytes));

        var ctx = context ?? new();

        bool error = false;

        byte[] outputBytes = { };

        Argon2Result result = Argon2Result.Ok;

        nuint passwordLength = Convert.ToUInt32(passwordBytes.Length);
        nuint saltLength = Convert.ToUInt32(saltBytes.Length);
        nuint bufferLength = ctx.HashLength;

        IntPtr passPtr = default,
            saltPtr = default,
            secretPointer = default,
            associatedDataPointer = default,
            bufferPointer = default;

        void FreeManagedPointers()
        {
            SafelyFreePointer(passPtr);
            SafelyFreePointer(saltPtr);
            SafelyFreePointer(secretPointer);
            SafelyFreePointer(associatedDataPointer);
            SafelyFreePointer(bufferPointer);
        }

        bool ContextDataValid(byte[]? data)
        {
            return data is not null && data.Length > 0;
        }

        try
        {
            saltPtr = GetPointerToBytes(saltBytes);
            passPtr = GetPointerToBytes(passwordBytes);

            secretPointer = ContextDataValid(ctx.Secret)
                ? GetPointerToBytes(ctx.Secret!)
                : IntPtr.Zero;

            nuint secretBufferLen = secretPointer == IntPtr.Zero
                ? 0
                : Convert.ToUInt32(ctx.Secret!.Length);

            associatedDataPointer = ContextDataValid(ctx.AssociatedData)
                ? GetPointerToBytes(ctx.AssociatedData!)
                : IntPtr.Zero;

            nuint associatedDataBufferLen = associatedDataPointer == IntPtr.Zero
                ? 0
                : Convert.ToUInt32(ctx.AssociatedData!.Length);

            bufferPointer = Marshal.AllocHGlobal(Convert.ToInt32(bufferLength));

            result = Argon2Library.Argon2ContextHash(
                Argon2MarshalContext.Create(
                    bufferPointer,
                    (uint) bufferLength,
                    passPtr,
                    (uint) passwordLength,
                    saltPtr,
                    (uint) saltLength,
                    secretPointer,
                    (uint) secretBufferLen,
                    associatedDataPointer,
                    (uint) associatedDataBufferLen,
                    ctx),
                ctx.Type
            );

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
            if (!error) FreeManagedPointers();
        }

        var encodedForm = Convert.ToBase64String(outputBytes);

        return new(result, outputBytes, encodedForm);
    }

    private static void ValidateString(
        string input, 
        string paramName)
    {
        if (string.IsNullOrEmpty(input))
            throw new ArgumentException("Value cannot be null or an empty.", paramName);
    }

    private static void ValidateCollection(
        ICollection collection, 
        string paramName)
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