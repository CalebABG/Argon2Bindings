using System;
using System.Collections;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

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
        var output = BitConverter.ToString(bytes);
        return output.Replace("-", separator);
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
            throw new InvalidEnumArgumentException($"{nameof(value)} : {(int) value} is an invalid value for enum type {enumType}");
    }

    internal static void ValidateCollection(
        ICollection collection,
        string paramName)
    {
        if (collection is null || collection.Count < 1)
            throw new ArgumentException("Value cannot be null or an empty collection.", paramName);
    }

    internal static string GetEncodedString(
        byte[] outputBytes,
        bool encodeHash)
    {
        ValidateCollection(outputBytes, nameof(outputBytes));

        return encodeHash
            ? Encoding.UTF8.GetString(outputBytes).TrimEnd('\0')
            : Convert.ToBase64String(outputBytes);
    }

    internal static byte[] GetBytesFromPointer(
        IntPtr ptr,
        int length)
    {
        byte[] outBytes = new byte[length];
        Marshal.Copy(ptr, outBytes, 0, length);
        return outBytes;
    }

    internal static IntPtr GetPointerToBytes(
        byte[] array)
    {
        int bytesToAllocate = array.Length + 1;
        
        IntPtr ptr = Marshal.AllocHGlobal(bytesToAllocate);
        Marshal.Copy(array, 0, ptr, array.Length);
        Marshal.WriteByte(ptr, array.Length, 0x0);

        return ptr;
    }

    internal static bool ContextDataValid(
        byte[]? data)
    {
        return data is not null && data.Length > 0;
    }

    internal static void SafelyFreePointer(
        IntPtr pointer)
    {
        if (pointer == IntPtr.Zero) return;
        Marshal.FreeHGlobal(pointer);
    }

    public static void WriteError(
        string text)
    {
        WriteLine(text, ConsoleColor.Red);
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