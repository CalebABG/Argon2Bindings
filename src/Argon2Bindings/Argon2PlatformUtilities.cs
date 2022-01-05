using System.Runtime.InteropServices;

namespace Argon2Bindings;

/// <summary>
/// Class which provides utility methods for getting platform
/// information.
/// </summary>
public static class Argon2PlatformUtilities
{
    /// <summary>
    /// Gets the target platform's name and argon2 binary extension.
    /// </summary>
    /// <returns>
    /// A tuple with the platform name (a Runtime Identifier name), and the argon2 binary
    /// extension for the given platform.
    /// </returns>
    /// <exception cref="Exception">
    /// Throws if the target platform is not Windows, Mac OS, or Linux. <br/>
    /// More platforms may be supported in the future.
    /// </exception>
    public static (string PlatformName, string PlatformBinaryExtension) GetPlatformNameAndBinaryExtension()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return ("win", "dll");
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) return ("osx", "dylib");
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return ("linux", "so");

        throw new Exception("Platform not currently supported");
    }

    /// <summary>
    /// Gets the target platform's CPU architecture.
    /// </summary>
    /// <returns>
    /// The target platform's CPU architecture.
    /// </returns>
    /// <exception cref="Exception">
    /// Throws if the target platform's CPU architecture is not one of the
    /// specified enumerations.<br/>
    /// More platform CPU architectures may be supported in the future.
    /// </exception>
    public static string GetPlatformArchitecture()
    {
        return GetPlatformArchitecture(RuntimeInformation.OSArchitecture);
    }

    internal static string GetPlatformArchitecture(
        Architecture architecture)
    {
        return architecture switch
        {
            Architecture.Arm => "arm",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            Architecture.X64 => "x64",
            _ => throw new Exception("Architecture not currently supported")
        };
    }
}