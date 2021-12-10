using System;

namespace Argon2Bindings;

public static class Argon2Utilities
{
    public static string ToHexString(this byte[] bytes, string separator = "")
    {
        var output = BitConverter.ToString(bytes);
        return output.Replace("-", separator);
    }

    public static void WriteError(string text)
    {
        WriteLine(text, ConsoleColor.Red);
    }

    /* Ref comment: https://weblog.west-wind.com/posts/2020/Jul/10/A-NET-Console-Color-Helper */
    private static void WriteLine(string text, ConsoleColor? color = null)
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