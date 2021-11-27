using System;

namespace Argon2Bindings;

public static class Utilities
{
    public static string ToHexString(this byte[] bytes, string separator = "")
    {
        var output = BitConverter.ToString(bytes);
        return output.Replace("-", separator);
    }
}