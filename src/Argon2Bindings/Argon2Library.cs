using Argon2Bindings.Enums;
using Argon2Bindings.Attributes;
using Argon2Bindings.Structures;

namespace Argon2Bindings;

internal static class Argon2Library
{
    /// <summary>
    /// Binding delegate which performs memory-hard hashing using the given
    /// context parameters.
    /// <param name="context">The context to use <see cref="Argon2MarshalContext"/></param>
    /// <param name="type">The argon2 variant to use for hashing <see cref="Argon2Type"/></param>
    /// <returns>
    /// An error result if something went wrong, otherwise <see cref="Argon2Result.Ok"/> result.
    /// </returns>
    /// </summary>
    [Argon2MappingMethod("argon2_ctx")]
    internal delegate Argon2Result Argon2ContextHashDelegate(
        ref Argon2MarshalContext context,
        Argon2Type type
    );

    /// <summary>
    /// Binding delegate which hashes a password.
    /// <remarks>
    /// This is a generic hashing method which will produce an <b>encoded</b> hash 
    /// or a <b>raw</b> hash if specified.
    /// </remarks>
    /// <param name="t_cost">The number of iterations</param>
    /// <param name="m_cost">The amount of memory to use in kibibytes</param>
    /// <param name="parallelism">The number of threads and compute lanes to use</param>
    /// <param name="pwd">The pointer to the password</param>
    /// <param name="pwdlen">The length of the password in bytes</param>
    /// <param name="salt">The pointer to the salt</param>
    /// <param name="saltlen">The length of the salt in bytes</param>
    /// <param name="hash">The pointer to the buffer to write the raw hash to</param>
    /// <param name="hashlen">The desired length of the hash in bytes</param>
    /// <param name="encoded">The pointer to the buffer to write the encoded hash to</param>
    /// <param name="encodedlen">The length of the encoded hash in bytes</param>
    /// <param name="type">The argon2 variant to use</param>
    /// <param name="version">The argon2 version to use</param>
    /// <returns>
    /// An error result if something went wrong,
    /// otherwise <see cref="Argon2Result.Ok"/> result.
    /// </returns>
    /// </summary>
    [Argon2MappingMethod("argon2_hash")]
    internal unsafe delegate Argon2Result Argon2HashDelegate(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        void* pwd, nuint pwdlen,
        void* salt, nuint saltlen,
        void* hash, nuint hashlen,
        char* encoded, nuint encodedlen,
        Argon2Type type,
        Argon2Version version
    );

    /// <summary>
    /// Binding delegate which returns the encoded hash length.
    /// <param name="t_cost">The number of iterations</param>
    /// <param name="m_cost">The amount of memory in kibibytes</param>
    /// <param name="parallelism">The number of threads and compute lanes</param>
    /// <param name="saltlen">The length of the salt in bytes</param>
    /// <param name="hashlen">The length of the hash in bytes</param>
    /// <param name="type">The argon2 variant to use</param>
    /// <returns>
    /// The encoded hash length for the given input parameters.
    /// </returns>
    /// </summary>
    [Argon2MappingMethod("argon2_encodedlen")]
    internal delegate nuint Argon2GetEncodedHashLengthDelegate(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        uint saltlen,
        uint hashlen,
        Argon2Type type
    );

    /// <summary>
    /// Binding delegate which verifies a password against
    /// an encoded string.
    /// <param name="encoded">The pointer to the encoded hash to use for verification</param>
    /// <param name="pwd">The pointer to the input password</param>
    /// <param name="pwdlen">The length of the input password in bytes</param>
    /// <param name="type">The argon2 variant to use</param>
    /// <returns>
    /// <see cref="Argon2Result.Ok"/> result if verification was successful. <br/>
    /// <see cref="Argon2Result.VerifyMismatch"/> result if verification failed. <br/>
    /// Otherwise an error result.
    /// </returns>
    /// </summary>
    [Argon2MappingMethod("argon2_verify")]
    internal unsafe delegate Argon2Result Argon2VerifyDelegate(
        void* encoded,
        void* pwd,
        nuint pwdlen,
        Argon2Type type
    );

    /// <summary>
    /// Array of delegate types to be passed to 
    /// <see cref="Argon2DynamicBinding"/> to create
    /// usable PInvoke methods.
    /// </summary>
    private static readonly Type[] DelegateTypes =
    {
        typeof(Argon2HashDelegate),
        typeof(Argon2GetEncodedHashLengthDelegate),
        typeof(Argon2VerifyDelegate),
        typeof(Argon2ContextHashDelegate),
    };

    /// <summary>
    /// Type which holds the pinvoke methods created from the
    /// above delegates.
    /// <remarks>
    /// This type is created dynamically through reflection and
    /// uses the delegates above to define PInvoke methods which can be
    /// used to call the native argon2 C library functions.
    /// </remarks>
    /// <seealso cref="Argon2DynamicBinding"/>
    /// </summary>
    private static readonly Type DynamicType;

    /// <inheritdoc cref="Argon2HashDelegate"/>
    internal static readonly Argon2HashDelegate Argon2Hash;

    /// <inheritdoc cref="Argon2GetEncodedHashLengthDelegate"/>
    internal static readonly Argon2GetEncodedHashLengthDelegate Argon2GetEncodedHashLength;

    /// <inheritdoc cref="Argon2VerifyDelegate"/>
    internal static readonly Argon2VerifyDelegate Argon2Verify;

    /// <inheritdoc cref="Argon2ContextHashDelegate"/>
    internal static readonly Argon2ContextHashDelegate Argon2ContextHash;

    static Argon2Library()
    {
        DynamicType = Argon2DynamicBinding.CreateDynamicType(DelegateTypes);

        Argon2Hash = Argon2DynamicBinding.GetDelegate<Argon2HashDelegate>(DynamicType);
        Argon2GetEncodedHashLength = Argon2DynamicBinding.GetDelegate<Argon2GetEncodedHashLengthDelegate>(DynamicType);
        Argon2Verify = Argon2DynamicBinding.GetDelegate<Argon2VerifyDelegate>(DynamicType);
        Argon2ContextHash = Argon2DynamicBinding.GetDelegate<Argon2ContextHashDelegate>(DynamicType);
    }
}