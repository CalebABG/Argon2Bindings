using Argon2Bindings.Enums;
using Argon2Bindings.Results;
using static Argon2Bindings.Argon2Utilities;

namespace Argon2Bindings;

/// <summary>
/// Class which provides the core argon2 hashing methods.
/// </summary>
public static class Argon2Core
{
    /// <summary>
    /// Verifies if a password matches a given argon2 hash.
    /// </summary>
    /// <param name="password">The input password to verify</param>
    /// <param name="encodedHash">The encoded argon2 hash</param>
    /// <param name="type">The argon2 variant used</param>
    /// <returns>A result object with the outcome.</returns>
    /// <exception cref="ArgumentException">
    /// Throws if either <paramref name="password"/> or <paramref name="encodedHash"/> 
    /// are null or empty.
    /// </exception>
    public static unsafe Argon2VerifyResult Verify
    (
        string password,
        string encodedHash,
        Argon2Type type = Argon2Defaults.DefaultType
    )
    {
        ValidateStringNotNullOrEmpty(password);
        ValidateStringNotNullOrEmpty(encodedHash);

        var passwordBytes = GetStringBytes(password);
        var encodedHashBytes = GetStringBytes(encodedHash);

        nuint passLen = Convert.ToUInt32(passwordBytes.Length);

        fixed
        (
            byte* passPtr = passwordBytes,
            encodedPtr = encodedHashBytes
        )
        {
            var status = Argon2Library.Argon2Verify
            (
                encodedPtr,
                passPtr,
                passLen,
                type
            );

            return Argon2VerifyResult.FromStatus(status);
        }
    }

    /// <inheritdoc cref="Hash(byte[],byte[],Argon2Context?,bool)" />
    public static Argon2HashResult Hash
    (
        string password,
        string? salt = null,
        Argon2Context? context = null,
        bool encode = true
    )
    {
        ValidateStringNotNullOrEmpty(password);

        return Hash
        (
            GetStringBytes(password),
            GetSaltBytes(salt, context),
            context,
            encode
        );
    }

    /// <summary>
    /// Hashes a password with a salt using the given
    /// context parameters.
    /// </summary>
    /// <param name="password">The password to hash</param>
    /// <param name="salt">The salt to use</param>
    /// <param name="context">The context to use</param>
    /// <param name="encode">
    /// Whether to encode the hash or not. Defaults to <b>true</b>
    /// </param>
    /// <remarks>
    /// The <see cref="Argon2Context.Secret"/> and
    /// <see cref="Argon2Context.AssociatedData"/>
    /// properties are ignored. To make use of those properties,
    /// use either of the <b>ContextHash</b> methods.
    /// </remarks>
    /// <returns>A result object with the outcome.</returns>
    /// <exception cref="ArgumentException">
    /// Throws if <paramref name="password"/> is null or empty.
    /// </exception>
    public static unsafe Argon2HashResult Hash
    (
        byte[] password,
        byte[]? salt = null,
        Argon2Context? context = null,
        bool encode = true
    )
    {
        ValidateCollection(password);

        salt ??= GetSaltBytes(context);
        context ??= new();

        nuint passwordLength = Convert.ToUInt32(password.Length);
        nuint saltLength = Convert.ToUInt32(salt.Length);

        nuint bufferLength = encode
            ? GetEncodedHashLength(context)
            : context.HashLength;

        byte[] buffer = new byte[bufferLength];

        fixed
        (
            byte* passPtr = password,
            saltPtr = salt,
            bufferPtr = buffer
        )
        {
            // If encoding, use buffer for encoding and set encoding length.
            // Otherwise use buffer for raw hash and set encoding ptr to 
            // null and encoding length to 0.
            byte* hashPtr = encode ? null : bufferPtr;
            byte* encodePtr = encode ? bufferPtr : null;
            nuint encodeLen = encode ? bufferLength : 0;

            var result = Argon2Library.Argon2Hash
            (
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
                context.Version
            );

            return Argon2HashResult.FromCriteria
            (
                result,
                expected: Argon2Result.Ok,
                buffer,
                encode
            );
        }
    }

    /// <inheritdoc cref="ContextHash(byte[],byte[],Argon2Context?)"/>
    public static Argon2HashResult ContextHash
    (
        string password,
        string? salt = null,
        Argon2Context? context = null
    )
    {
        ValidateStringNotNullOrEmpty(password);

        return ContextHash
        (
            GetStringBytes(password),
            GetSaltBytes(salt, context),
            context
        );
    }

    /// <summary>
    /// Hashes a password with a salt and using the given
    /// context parameters, optionally using a secret key
    /// and associated data.
    /// </summary>
    /// <param name="password">The password to hash</param>
    /// <param name="salt">The salt to use</param>
    /// <param name="context">The context to use</param>
    /// <returns>A result object with the outcome.</returns>
    /// <exception cref="ArgumentException">
    /// Throws if <paramref name="password"/> is null or empty.
    /// </exception>
    public static unsafe Argon2HashResult ContextHash
    (
        byte[] password,
        byte[]? salt = null,
        Argon2Context? context = null
    )
    {
        ValidateCollection(password);

        salt ??= GetSaltBytes(context);
        context ??= new();

        nuint bufferLength = context.HashLength;
        nuint saltLength = Convert.ToUInt32(salt.Length);
        nuint passwordLength = Convert.ToUInt32(password.Length);

        byte[] buffer = new byte[bufferLength];

        fixed
        (
            byte* passPtr = password,
            saltPtr = salt,
            bufferPtr = buffer,
            secretPtr = context.Secret,
            associatedPtr = context.AssociatedData
        )
        {
            nuint secretBufferLen = GetBufferLength(secretPtr, context.Secret!);
            nuint associatedDataBufferLen = GetBufferLength(associatedPtr, context.AssociatedData!);

            var marshalContext = Argon2MarshalContext.Create
            (
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
                context
            );

            var result = Argon2Library.Argon2ContextHash
            (
                ref marshalContext,
                context.Type
            );

            return Argon2HashResult.FromCriteria
            (
                result,
                expected: Argon2Result.Ok,
                buffer,
                false
            );
        }
    }

    /// <summary>
    /// Gets the length in bytes of the encoded hash given the
    /// input parameters.
    /// </summary>
    /// <param name="timeCost">The number of iterations</param>
    /// <param name="memoryCost">The amount of memory in kibibytes (KiB)</param>
    /// <param name="degreeOfParallelism">The number of threads and compute lanes</param>
    /// <param name="saltLength">The length of the salt in bytes</param>
    /// <param name="hashLength">The length of the hash in bytes</param>
    /// <param name="type">The argon2 variant to use</param>
    /// <returns>
    /// The length of the encoded hash in bytes.
    /// </returns>
    public static nuint GetEncodedHashLength
    (
        uint timeCost,
        uint memoryCost,
        uint degreeOfParallelism,
        uint saltLength,
        uint hashLength,
        Argon2Type type
    )
    {
        return Argon2Library.Argon2GetEncodedHashLength
        (
            timeCost,
            memoryCost,
            degreeOfParallelism,
            saltLength,
            hashLength,
            type
        );
    }

    /// <summary>
    /// Computes the encoded hash length based on the context.
    /// </summary>
    /// <param name="context">the context to use</param>
    /// <returns>The computed encoded hash length</returns>
    private static nuint GetEncodedHashLength
    (
        Argon2Context context
    )
    {
        return GetEncodedHashLength
        (
            context.TimeCost,
            context.MemoryCost,
            context.DegreeOfParallelism,
            context.SaltLength,
            context.HashLength,
            context.Type
        );
    }
}