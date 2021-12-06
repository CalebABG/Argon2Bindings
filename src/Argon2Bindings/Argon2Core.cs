using System;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using static Argon2Bindings.Utilities;

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
    internal static readonly Type Argon2CoreDynamic = Argon2Library.CreateDynamicType();

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
        ValidatePasswordAndSaltCollections(password, salt);

        context ??= new();

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
        ValidatePasswordAndSaltCollections(password, salt);

        context ??= new();

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

        uint passwordLength = Convert.ToUInt32(passwordBytes.Length);
        uint saltLength = Convert.ToUInt32(saltBytes.Length);

        bool errored = false;
        byte[] outputBytes = { };

        Argon2Result result = Argon2Result.Ok;

        var bufferLength = GetBufferLength(encodeHash, saltLength, ctx);

        IntPtr passPtr = default,
            saltPtr = default,
            bufferPointer = Marshal.AllocHGlobal(Convert.ToInt32(bufferLength));

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

            string method = GetDynamicHashingMethod(
                encodeHash,
                ctx);

            object[] arguments = GetDynamicMethodArguments(
                encodeHash,
                passPtr,
                passwordLength,
                saltPtr,
                saltLength,
                bufferPointer,
                bufferLength,
                ctx);

            result = InvokeBinding<Argon2Result>(method, arguments);

            /* Todo: Throw an exception when no success, or return error w/ empty / incomplete data? */
            /*if (result is not Argon2Result.Ok)
                throw new Exception(Argon2Errors.GetErrorMessage(result));*/

            /* Todo: TrimRight null-terminator byte (\x00) */
            outputBytes = GetBytesFromPointer(bufferPointer, Convert.ToInt32(bufferLength));
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

        var encodedForm = encodeHash
            ? Encoding.UTF8.GetString(outputBytes)
            : Convert.ToBase64String(outputBytes);

        return new(result, outputBytes, encodedForm);
    }

    public static string GetErrorMessage(
        Argon2Result error)
    {
        var messagePtr = InvokeBinding<IntPtr>(
            nameof(Argon2Library.argon2_error_message),
            new object?[] {error});

        return Marshal.PtrToStringAnsi(messagePtr) ?? string.Empty;
    }

    private static object[] GetDynamicMethodArguments(
        bool encodeHash,
        IntPtr passPtr,
        uint passwordLength,
        IntPtr saltPtr,
        uint saltLength,
        IntPtr bufferPointer,
        nuint bufferLength,
        Argon2Context ctx)
    {
        object[] arguments;
        if (encodeHash)
        {
            arguments = new object[]
            {
                ctx.TimeCost,
                ctx.MemoryCost,
                ctx.DegreeOfParallelism,
                passPtr,
                (nuint) passwordLength,
                saltPtr,
                (nuint) saltLength,
                (nuint) ctx.HashLength,
                bufferPointer,
                bufferLength
            };
        }
        else
        {
            arguments = new object[]
            {
                ctx.TimeCost,
                ctx.MemoryCost,
                ctx.DegreeOfParallelism,
                passPtr,
                (nuint) passwordLength,
                saltPtr,
                (nuint) saltLength,
                bufferPointer,
                bufferLength
            };
        }

        return arguments;
    }

    private static string GetDynamicHashingMethod(
        bool encodeHash,
        Argon2Context ctx)
    {
        string method;
        if (encodeHash)
        {
            method = ctx.Type switch
            {
                Argon2Type.Argon2D => nameof(Argon2Library.argon2d_hash_encoded),
                Argon2Type.Argon2I => nameof(Argon2Library.argon2i_hash_encoded),
                Argon2Type.Argon2Id => nameof(Argon2Library.argon2id_hash_encoded),
                _ => nameof(Argon2Library.argon2i_hash_encoded)
            };
        }
        else
        {
            method = ctx.Type switch
            {
                Argon2Type.Argon2D => nameof(Argon2Library.argon2d_hash_raw),
                Argon2Type.Argon2I => nameof(Argon2Library.argon2i_hash_raw),
                Argon2Type.Argon2Id => nameof(Argon2Library.argon2id_hash_raw),
                _ => nameof(Argon2Library.argon2i_hash_raw)
            };
        }

        return method;
    }

    private static nuint GetBufferLength(
        bool encodeHash,
        uint saltLength,
        Argon2Context ctx)
    {
        nuint bufferLength = encodeHash
            ? GetEncodedHashLength(
                ctx.TimeCost,
                ctx.MemoryCost,
                ctx.DegreeOfParallelism,
                saltLength,
                ctx.HashLength,
                ctx.Type)
            : ctx.HashLength;

        return bufferLength;
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
        if (password is null || password.Length <= 0)
            throw new ArgumentException("Value cannot be null or an empty collection.", nameof(password));

        if (salt is null || salt.Length <= 0)
            throw new ArgumentException("Value cannot be null or an empty collection.", nameof(salt));
    }

    private static T? InvokeBinding<T>(
        string methodName,
        object?[]? methodParameters)
    {
        T retVal = default(T)!;

        var method = Argon2CoreDynamic.GetMethod(methodName, BindingFlags.Public | BindingFlags.Static);
        if (method is null)
            throw new MissingMethodException(nameof(Argon2CoreDynamic), methodName);

        try
        {
            retVal = (T) method.Invoke(null, methodParameters);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }

        return retVal;
    }

    private static nuint GetEncodedHashLength(
        uint timeCost,
        uint memoryCost,
        uint degreeOfParallelism,
        uint saltLength,
        uint hashLength,
        Argon2Type type)
    {
        var length = InvokeBinding<nuint>(
            nameof(Argon2Library.argon2_encodedlen),
            new object[]
            {
                timeCost,
                memoryCost,
                degreeOfParallelism,
                saltLength,
                hashLength,
                type
            });

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