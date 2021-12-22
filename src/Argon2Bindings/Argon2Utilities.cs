﻿using System;
using System.Collections;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Argon2Bindings.Enums;

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

    internal static void ValidateString(
        string input,
        string paramName)
    {
        if (string.IsNullOrEmpty(input))
            throw new ArgumentException("Value cannot be null or an empty.", paramName);
    }

    internal static void ValidateEnum(Type enumType, object value)
    {
        if (enumType == null) throw new ArgumentNullException(nameof(enumType));
        if (value == null) throw new ArgumentNullException(nameof(value));

        if (!Enum.IsDefined(enumType, value))
            throw new InvalidEnumArgumentException(nameof(value), (int) value, enumType);
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
        IntPtr ptr = Marshal.AllocHGlobal(array.Length);
        Marshal.Copy(array, 0, ptr, array.Length);
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
        ConsoleColor? color = null)
    {
        if (!color.HasValue)
        {
            Console.WriteLine(text);
        }
        else
        {
            var oldColor = Console.ForegroundColor;
            var newColor = color.GetValueOrDefault();

            if (oldColor == newColor)
            {
                Console.WriteLine(text);
            }
            else
            {
                Console.ForegroundColor = newColor;
                Console.WriteLine(text);
                Console.ForegroundColor = oldColor;
            }
        }
    }
}