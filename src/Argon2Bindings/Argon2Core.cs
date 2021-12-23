using System;
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
/* Todo: Add Windows x86 + x64 toolchains to Docker binary compilation automation */
/* Todo: Consolidate or unify logic in `Hash` and `ContextHash` methods */

public static class Argon2Core
{
    /// <summary>
    /// Verifies if a password matches a given argon2 hash.
    /// </summary>
    /// <param name="password">The input password to verify</param>
    /// <param name="encodedHash">The encoded argon2 hash</param>
    /// <param name="type">The argon2 variant used</param>
    /// <returns>A result object with the outcome.</returns>
    public static Argon2VerifyResult Verify(
        string password,
        string encodedHash,
        Argon2Type type = Argon2Defaults.DefaultType)
    {
        ValidateStringNotNullOrEmpty(password, nameof(password));
        ValidateStringNotNullOrEmpty(encodedHash, nameof(encodedHash));

        bool error = false;

        Argon2VerifyResult verifyResult = new(false);

        var passwordBytes = Argon2Defaults.DefaultEncoding.GetBytes(password);
        var encodedHashBytes = Argon2Defaults.DefaultEncoding.GetBytes(encodedHash);

        nuint passwordLength = Convert.ToUInt32(passwordBytes.Length);

        IntPtr passwordBufferPointer = default,
            encodedHashBufferPointer = default;

        void FreeManagedPointers()
        {
            SafelyFreePointer(passwordBufferPointer);
            SafelyFreePointer(encodedHashBufferPointer);
        }

        try
        {
            passwordBufferPointer = GetPointerToBytes(passwordBytes);
            encodedHashBufferPointer = GetPointerToBytes(encodedHashBytes);

            var status = Argon2Library.Argon2Verify(
                encodedHashBufferPointer,
                passwordBufferPointer,
                passwordLength,
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
            if (!error) FreeManagedPointers();
        }

        return verifyResult;
    }

    /// <inheritdoc cref="Hash(byte[],byte[],Argon2Context?,bool)" />
    public static Argon2HashResult Hash(
        string password,
        string? salt = null,
        Argon2Context? context = null,
        bool encodeHash = true)
    {
        ValidateStringNotNullOrEmpty(password, nameof(password));

        var saltBytes = GetSaltBytes(salt, context);
        var passwordBytes = Argon2Defaults.DefaultEncoding.GetBytes(password);

        return Hash(passwordBytes, saltBytes, context, encodeHash);
    }

    /// <summary>
    /// Hashes a password with salt and using the given
    /// context input parameters.
    /// </summary>
    /// <param name="password">The password to hash</param>
    /// <param name="salt">The salt to use</param>
    /// <param name="context">The context to use</param>
    /// <param name="encodeHash">
    /// Whether to encode the hash or not.
    /// If not set explicitly, this parameter defaults to <b>true</b>
    /// </param>
    /// <remarks>
    /// The <see cref="Argon2Context.Secret"/> and
    /// <see cref="Argon2Context.AssociatedData"/>
    /// properties are ignored. To make use of those properties,
    /// use either of the <b>ContextHash</b> methods.
    /// </remarks>
    /// <returns>A result object with the outcome.</returns>
    public static Argon2HashResult Hash(
        byte[] password,
        byte[]? salt = null,
        Argon2Context? context = null,
        bool encodeHash = true)
    {
        ValidateCollection(password, nameof(password));

        salt ??= GetSaltBytes(context);

        var ctx = context ?? new();

        bool error = false;
        Argon2Result result = Argon2Result.Ok;

        byte[] outputBytes = Array.Empty<byte>();

        nuint passwordLength = Convert.ToUInt32(password.Length);
        nuint saltLength = Convert.ToUInt32(salt.Length);
        nuint bufferLength = encodeHash
            ? GetEncodedHashLength(
                ctx.TimeCost,
                ctx.MemoryCost,
                ctx.DegreeOfParallelism,
                (uint)saltLength,
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
            passPtr = GetPointerToBytes(password);
            saltPtr = GetPointerToBytes(salt);
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

            if (result is not Argon2Result.Ok)
                throw new Exception(Argon2Errors.GetErrorMessage(result));

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

        var encodedForm = !error ? GetEncodedString(outputBytes, encodeHash) : "";

        return new(result, outputBytes, encodedForm);
    }

    /// <inheritdoc cref="ContextHash(byte[],byte[],Argon2Context?)"/>
    public static Argon2HashResult ContextHash(
        string password,
        string? salt = null,
        Argon2Context? context = null)
    {
        ValidateStringNotNullOrEmpty(password, nameof(password));

        var saltBytes = GetSaltBytes(salt, context);
        var passwordBytes = Argon2Defaults.DefaultEncoding.GetBytes(password);

        return ContextHash(passwordBytes, saltBytes, context);
    }

    /// <summary>
    /// Hashes a password with salt and using the given
    /// context input parameters, optionally using a secret
    /// and associated data byte arrays. 
    /// </summary>
    /// <param name="password">The password to hash</param>
    /// <param name="salt">The salt to use</param>
    /// <param name="context">The context to use</param>
    /// <returns>A result object with the outcome.</returns>
    public static Argon2HashResult ContextHash(
        byte[] password,
        byte[]? salt = null,
        Argon2Context? context = null)
    {
        ValidateCollection(password, nameof(password));

        salt ??= GetSaltBytes(context);

        var ctx = context ?? new();

        bool error = false;
        Argon2Result result = Argon2Result.Ok;

        byte[] outputBytes = Array.Empty<byte>();

        nuint passwordLength = Convert.ToUInt32(password.Length);
        nuint saltLength = Convert.ToUInt32(salt.Length);
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

        try
        {
            saltPtr = GetPointerToBytes(salt);
            passPtr = GetPointerToBytes(password);

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

            var marshalContext = Argon2MarshalContext.Create(
                bufferPointer,
                (uint)bufferLength,
                passPtr,
                (uint)passwordLength,
                saltPtr,
                (uint)saltLength,
                secretPointer,
                (uint)secretBufferLen,
                associatedDataPointer,
                (uint)associatedDataBufferLen,
                ctx);

            result = Argon2Library.Argon2ContextHash(
                ref marshalContext,
                ctx.Type
            );

            if (result is not Argon2Result.Ok)
                throw new Exception(Argon2Errors.GetErrorMessage(result));

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

        var encodedForm = !error ? GetEncodedString(outputBytes, false) : "";

        return new(result, outputBytes, encodedForm);
    }

    /// <summary>
    /// Gets the length in bytes of the encoded hash given the
    /// input parameters.
    /// </summary>
    /// <param name="timeCost">The number of iterations</param>
    /// <param name="memoryCost">The amount of memory in kibibytes</param>
    /// <param name="degreeOfParallelism">The number of threads and compute lanes</param>
    /// <param name="saltLength">The length of the salt in bytes</param>
    /// <param name="hashLength">The length of the hash in bytes</param>
    /// <param name="type">The argon2 variant to use</param>
    /// <returns>
    /// The length of the encoded hash in bytes.
    /// </returns>
    public static nuint GetEncodedHashLength(
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
}