﻿using Argon2Bindings.Enums;
using Argon2Bindings.Results;
using Argon2Bindings.Structures;
using static Argon2Bindings.Argon2Utilities;

namespace Argon2Bindings;

/* Todo: Add Benchmark tests */
/* Todo: Check/add tests for memory leaks */
/* Todo: Look into optimizing */
/* Todo: Add Windows x86 + x64 toolchains to Docker binary compilation automation */
/* Todo: Consolidate or unify logic in `Hash` and `ContextHash` methods */
/* Todo: Create dotnet CLI tool for replacing scripts (use dotnet command line parser nuget) */

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

        var passwordBytes = Argon2Defaults.DefaultEncoding.GetBytes(password);
        var encodedHashBytes = Argon2Defaults.DefaultEncoding.GetBytes(encodedHash);

        nuint passLen = Convert.ToUInt32(passwordBytes.Length);

        try
        {
            unsafe
            {
                fixed (byte* passPtr = passwordBytes,
                       encodedPtr = encodedHashBytes)
                {
                    var status = Argon2Library.Argon2Verify(
                        encodedPtr,
                        passPtr,
                        passLen,
                        type);

                    return status switch
                    {
                        Argon2Result.Ok => new(true),
                        Argon2Result.VerifyMismatch => new(false),
                        _ => new(false, Argon2Errors.GetErrorMessage(status))
                    };
                }
            }
        }
        catch (Exception e)
        {
            WriteError(e);
            return new(false, $"{e.Message}\n{e.StackTrace}");
        }
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
        context ??= new();

        Argon2Result result = Argon2Result.Ok;

        nuint passwordLength = Convert.ToUInt32(password.Length);
        nuint saltLength = Convert.ToUInt32(salt.Length);
        nuint bufferLength = encodeHash
            ? GetEncodedHashLength(
                context.TimeCost,
                context.MemoryCost,
                context.DegreeOfParallelism,
                (uint)saltLength,
                context.HashLength,
                context.Type)
            : context.HashLength;

        try
        {
            unsafe
            {
                byte[] buffer = new byte[Convert.ToInt32(bufferLength)];

                fixed (byte* passPtr = password,
                       saltPtr = salt,
                       bufferPtr = buffer)
                {
                    var hashPtr = encodeHash ? null : bufferPtr;
                    var encodePtr = encodeHash ? bufferPtr : null;
                    var encodeLen = encodeHash ? bufferLength : 0;

                    result = Argon2Library.Argon2Hash(
                        context.TimeCost,
                        context.MemoryCost,
                        context.DegreeOfParallelism,
                        passPtr,
                        passwordLength,
                        saltPtr,
                        saltLength,
                        hashPtr,
                        context.HashLength,
                        (char*)encodePtr,
                        encodeLen,
                        context.Type,
                        context.Version);

                    if (result is not Argon2Result.Ok)
                        throw new Exception(Argon2Errors.GetErrorMessage(result));

                    var encodedForm = GetEncodedString(buffer, encodeHash);
                    return new(result, buffer, encodedForm);
                }
            }
        }
        catch (Exception e)
        {
            WriteError(e);
            return new(result, Array.Empty<byte>(), "");
        }
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
        context ??= new();

        Argon2Result result = Argon2Result.Ok;

        nuint bufferLength = context.HashLength;

        nuint saltLength = Convert.ToUInt32(salt.Length);
        nuint passwordLength = Convert.ToUInt32(password.Length);

        try
        {
            unsafe
            {
                byte[] buffer = new byte[Convert.ToInt32(bufferLength)];

                fixed (byte* passPtr = password,
                       saltPtr = salt,
                       bufferPtr = buffer,
                       secretPtr = context.Secret,
                       associatedPtr = context.AssociatedData)
                {
                    nuint secretBufferLen = secretPtr == null ? 0 : Convert.ToUInt32(context.Secret!.Length);
                    nuint associatedDataBufferLen = associatedPtr == null ? 0 : Convert.ToUInt32(context.AssociatedData!.Length);

                    var marshalContext = Argon2MarshalContext.Create(
                        bufferPtr,
                        (uint)bufferLength,
                        passPtr,
                        (uint)passwordLength,
                        saltPtr,
                        (uint)saltLength,
                        secretPtr,
                        (uint)secretBufferLen,
                        associatedPtr,
                        (uint)associatedDataBufferLen,
                        context);

                    result = Argon2Library.Argon2ContextHash(ref marshalContext, context.Type);

                    if (result is not Argon2Result.Ok)
                        throw new Exception(Argon2Errors.GetErrorMessage(result));

                    var encodedForm = GetEncodedString(buffer, false);
                    return new(result, buffer, encodedForm);
                }
            }
        }
        catch (Exception e)
        {
            WriteError(e);
            return new(result, Array.Empty<byte>(), "");
        }
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