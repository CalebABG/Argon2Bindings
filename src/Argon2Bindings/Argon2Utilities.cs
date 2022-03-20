using System.Text;
using System.Collections;
using System.ComponentModel;
using System.Security.Cryptography;

namespace Argon2Bindings;

/// <summary>
/// A utility class containing useful functions
/// for logging errors to the console, hexifying byte arrays, etc...
/// </summary>
public static class Argon2Utilities
{
    /// <summary>
    /// Returns the hex string representation of the
    /// provided array of bytes.
    /// </summary>
    /// <param name="bytes">The array of bytes</param>
    /// <param name="separator">The separator to use</param>
    /// <returns>
    /// Returns a hex string of the provided bytes.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Throws when the input byte array is null.
    /// </exception>
    public static string ToHexString
    (
        this byte[] bytes,
        string separator = ""
    )
    {
        if (bytes is null)
            throw new ArgumentNullException(nameof(bytes));

        return BitConverter
            .ToString(bytes)
            .Replace("-", separator);
    }

    /// <summary>
    /// Returns the bytes of the string using the provided encoding.
    /// </summary>
    /// <param name="str">The string to get the bytes from</param>
    /// <param name="encoding">The encoding to use</param>
    /// <returns>
    /// Returns the bytes of the string using the encoding if provided,
    /// otherwise the default encoding is used. <see cref="Argon2Defaults.DefaultEncoding"/>
    /// </returns>
    public static byte[] ToBytes
    (
        this string str,
        Encoding? encoding = null
    )
    {
        ValidateStringNotNullOrEmpty(str);
        encoding ??= Argon2Defaults.DefaultEncoding;
        return encoding.GetBytes(str);
    }

    /// <summary>
    /// Checks that the input is not null or empty.
    /// </summary>
    /// <param name="input">the string to validate</param>
    /// <exception cref="ArgumentException">
    /// Throws if the <paramref name="input"/> is null or empty.
    /// </exception>
    internal static void ValidateStringNotNullOrEmpty
    (
        string input
    )
    {
        if (string.IsNullOrEmpty(input))
            throw new ArgumentException("Value cannot be null or an empty.", nameof(input));
    }

    /// <summary>
    /// Checks that the input is not null, empty
    /// or consists of only whitespace.
    /// </summary>
    /// <param name="input">the string to validate</param>
    /// <exception cref="ArgumentException">
    /// Throws if the <paramref name="input"/> is null,
    /// empty, or whitespace.
    /// </exception>
    internal static void ValidateStringNotNullOrWhiteSpace
    (
        string input
    )
    {
        if (string.IsNullOrWhiteSpace(input))
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(input));
    }

    /// <summary>
    /// Checks that the enum value provided is a valid option
    /// within the Enum type.
    /// </summary>
    /// <param name="enumType">The type of Enum</param>
    /// <param name="value">The Enum value to validate</param>
    /// <exception cref="ArgumentNullException">
    /// Throws if either <paramref name="enumType"/> or <paramref name="value"/>
    /// are null.
    /// </exception>
    /// <exception cref="InvalidEnumArgumentException">
    /// Throws if <paramref name="value"/> is not a valid option within the Enum type provided.
    /// </exception>
    internal static void ValidateEnum
    (
        Type enumType,
        object value
    )
    {
        if (enumType == null) throw new ArgumentNullException(nameof(enumType));
        if (value == null) throw new ArgumentNullException(nameof(value));

        if (!Enum.IsDefined(enumType, value))
            throw new InvalidEnumArgumentException($"{nameof(value)} : {(int)value}" +
                                                   $" is an invalid value for enum type {enumType}");
    }

    /// <inheritdoc cref="ValidateEnum(Type, object)"/>
    internal static void ValidateEnum<TEnum>
    (
        object value
    ) where TEnum : Enum
    {
        ValidateEnum(typeof(TEnum), value);
    }

    /// <summary>
    /// Checks that the collection is not null
    /// or empty.
    /// </summary>
    /// <param name="collection">The collection to validate</param>
    /// <exception cref="ArgumentException">
    /// Throws when the collection is null or empty.
    /// </exception>
    internal static void ValidateCollection
    (
        ICollection collection
    )
    {
        if (collection is null || collection.Count < 1)
            throw new ArgumentException("Value cannot be null or an empty collection.", nameof(collection));
    }

    /// <summary>
    /// Generates a salt as a collection of bytes using
    /// a cryptographic random number generator.
    /// </summary>
    /// <param name="saltLength">The length of the salt in bytes</param>
    /// <returns>Returns an array of cryptographically generated random bytes.</returns>
    /// <seealso cref="RandomNumberGenerator"/>
    public static byte[] GenerateSalt
    (
        uint saltLength = Argon2Defaults.DefaultSaltLength
    )
    {
        byte[] salt = new byte[saltLength];
        RandomNumberGenerator.Fill(salt);
        return salt;
    }

    /// <summary>
    /// Generates the salt bytes from provided context.
    /// <remarks>
    /// If the context is not null, the salt length from the context
    /// is used to generate the salt. Otherwise the default salt length is
    /// used to generate the salt <see cref="Argon2Defaults.DefaultSaltLength"/>.
    /// </remarks>
    /// </summary>
    /// <param name="context">The context to get the salt from</param>
    /// <returns>Returns the salt as an array of bytes.</returns>
    /// 
    internal static byte[] GetSaltBytes
    (
        Argon2Context? context
    )
    {
        return GenerateSalt(context?.SaltLength ?? Argon2Defaults.DefaultSaltLength);
    }

    /// <summary>
    /// Gets the salt bytes from the input or the
    /// <see cref="Argon2Context"/>.
    /// <remarks>
    /// If the input is not null or whitespace, gets the bytes from the input.
    /// Otherwise the context is used to generate the salt bytes. 
    /// </remarks>
    /// </summary>
    /// <param name="salt">The string to get the salt from</param>
    /// <param name="context">The context to get the salt from</param>
    /// <returns>Returns the salt as an array of bytes.</returns>
    internal static byte[] GetSaltBytes
    (
        string? salt,
        Argon2Context? context
    )
    {
        return !string.IsNullOrWhiteSpace(salt)
            ? GetStringBytes(salt)
            : GetSaltBytes(context);
    }

    /// <summary>
    /// Gets the bytes of the provided string using the
    /// default encoding <see cref="Argon2Defaults.DefaultEncoding"/>.
    /// </summary>
    /// <param name="str">The string to get the bytes from</param>
    /// <returns>
    /// Returns the bytes of the string using the default encoding.
    /// </returns>
    internal static byte[] GetStringBytes
    (
        string str
    )
    {
        return Argon2Defaults.DefaultEncoding.GetBytes(str);
    }

    /// <summary>
    /// Gets the string representation of the provided bytes.
    /// <remarks>
    /// If <paramref name="encode"/> is set to true, the default
    /// encoding is used to get the string (<see cref="Argon2Defaults.DefaultEncoding"/>).
    /// Otherwise, Base64 is used to get the string from the bytes.
    /// </remarks>
    /// </summary>
    /// <param name="bytes">The array of bytes</param>
    /// <param name="encode">Whether to encode</param>
    /// <returns>
    /// Returns the string representation of the array of bytes.
    /// </returns>
    internal static string GetString
    (
        byte[] bytes,
        bool encode
    )
    {
        ValidateCollection(bytes);
        return encode
            ? Argon2Defaults.DefaultEncoding.GetString(bytes).TrimEnd('\0')
            : Convert.ToBase64String(bytes);
    }

    /// <summary>
    /// Method to get exception details.
    /// </summary>
    /// <param name="exception">the exception to get details from</param>
    /// <returns>The details of the throw exception</returns>
    /// <exception cref="ArgumentNullException">
    /// Throws if the provided exception is null.
    /// </exception>
    internal static string GetExceptionString
    (
        Exception exception
    )
    {
        if (exception is null)
            throw new ArgumentNullException(nameof(exception));

        return exception.ToString();
    }

    /// <summary>
    /// Method to write an error to the console.
    /// <remarks>
    /// Writes the error to the console in <see cref="ConsoleColor.Red"/>
    /// </remarks>
    /// </summary>
    /// <param name="exception">The exception to use</param>
    internal static void WriteError
    (
        Exception exception
    )
    {
        WriteColorfulLine(GetExceptionString(exception), ConsoleColor.Red);
    }

    /// <summary>
    /// Method to write a line to the console in the provided color.
    /// </summary>
    /// <param name="text">The text to write</param>
    /// <param name="color">The color to use</param>
    /// Adapted from: <seealso href="https://weblog.west-wind.com/posts/2020/Jul/10/A-NET-Console-Color-Helper"/>
    private static void WriteColorfulLine
    (
        string text,
        ConsoleColor color = ConsoleColor.White
    )
    {
        var oldColor = Console.ForegroundColor;
        if (oldColor == color)
        {
            Console.WriteLine(text);
        }
        else
        {
            Console.ForegroundColor = color;
            Console.WriteLine(text);
            Console.ForegroundColor = oldColor;
        }
    }
}