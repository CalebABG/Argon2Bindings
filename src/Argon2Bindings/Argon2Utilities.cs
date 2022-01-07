using System.Text;
using System.Collections;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Argon2Bindings;

/// <summary>
/// A utility class containing useful functions
/// for logging errors to the console, hexifying byte arrays, etc...
/// </summary>
public static class Argon2Utilities
{
    public static string ToHexString(
        this byte[] bytes,
        string separator = "")
    {
        if (bytes is null)
            throw new ArgumentNullException(nameof(bytes));

        var output = BitConverter.ToString(bytes);
        return output.Replace("-", separator);
    }

    public static byte[] ToBytes(
        this string str,
        Encoding? encoding = null)
    {
        if (str is null)
            throw new ArgumentNullException(nameof(str));

        encoding ??= Argon2Defaults.DefaultEncoding;
        return encoding.GetBytes(str);
    }

    internal static void ValidateStringNotNullOrEmpty(
        string input,
        string paramName)
    {
        if (string.IsNullOrEmpty(input))
            throw new ArgumentException("Value cannot be null or an empty.", paramName);
    }

    internal static void ValidateStringNotNullOrWhiteSpace(
        string input,
        string paramName)
    {
        if (string.IsNullOrWhiteSpace(input))
            throw new ArgumentException("Value cannot be null or whitespace.", paramName);
    }

    internal static void ValidateEnum(
        Type enumType,
        object value)
    {
        if (enumType == null) throw new ArgumentNullException(nameof(enumType));
        if (value == null) throw new ArgumentNullException(nameof(value));

        if (!Enum.IsDefined(enumType, value))
            throw new InvalidEnumArgumentException($"{nameof(value)} : {(int)value} is an invalid value for enum type {enumType}");
    }

    internal static void ValidateCollection(
        ICollection collection,
        string paramName)
    {
        if (collection is null || collection.Count < 1)
            throw new ArgumentException("Value cannot be null or an empty collection.", paramName);
    }

    public static byte[] GenerateSalt(
        uint saltLength = Argon2Defaults.DefaultSaltLength)
    {
        byte[] salt = new byte[saltLength];
        RandomNumberGenerator.Fill(salt);
        return salt;
    }

    internal static byte[] GetSaltBytes(
        Argon2Context? context)
    {
        uint saltLen = context?.SaltLength ?? Argon2Defaults.DefaultSaltLength;
        return GenerateSalt(saltLen);
    }

    internal static byte[] GetSaltBytes(
        string? salt,
        Argon2Context? context)
    {
        return !string.IsNullOrWhiteSpace(salt)
            ? Argon2Defaults.DefaultEncoding.GetBytes(salt)
            : GetSaltBytes(context);
    }

    internal static string GetEncodedString(
        byte[] outputBytes,
        bool encodeHash)
    {
        ValidateCollection(outputBytes, nameof(outputBytes));

        return encodeHash
            ? Argon2Defaults.DefaultEncoding.GetString(outputBytes).TrimEnd('\0')
            : Convert.ToBase64String(outputBytes);
    }

    internal static bool ContextDataValid(
        byte[]? data)
    {
        return data is not null && data.Length > 0;
    }

    public static void WriteError(
        string text)
    {
        WriteLine(text, ConsoleColor.Red);
    }

    public static void WriteError(
        Exception e)
    {
        WriteLine($"{e.Message}\n{e.StackTrace}", ConsoleColor.Red);
    }

    /* Ref comment: https://weblog.west-wind.com/posts/2020/Jul/10/A-NET-Console-Color-Helper */
    private static void WriteLine(
        string text,
        ConsoleColor color = ConsoleColor.White)
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