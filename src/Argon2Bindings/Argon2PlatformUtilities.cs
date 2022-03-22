using System.Runtime.InteropServices;

namespace Argon2Bindings;

/// <summary>
/// Class which provides utility methods for getting platform
/// information.
/// </summary>
public static class Argon2PlatformUtilities
{
    /// <summary>
    /// Structure to hold platform information.
    /// </summary>
    /// <param name="PlatformName">
    /// The name of the platform
    /// </param>
    /// <param name="PlatformBinaryExtension">
    /// The binary extension type for the platform
    /// </param>
    /// <param name="PlatformArchitecture">
    /// The CPU architecture of the platform
    /// </param>
    public readonly record struct Argon2PlatformInfo
    (
        string PlatformName,
        string PlatformBinaryExtension,
        string PlatformArchitecture
    )
    {
        public readonly string PlatformName = PlatformName;
        public readonly string PlatformBinaryExtension = PlatformBinaryExtension;
        public readonly string PlatformArchitecture = PlatformArchitecture;
    }

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
    public static Argon2PlatformInfo GetPlatformInfo()
    {
        string platformArch = GetPlatformArchitecture();

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return new("win", "dll", platformArch);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return new("osx", "dylib", platformArch);

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return new("linux", "so", platformArch);

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

    /// <inheritdoc cref="GetPlatformArchitecture"/>
    internal static string GetPlatformArchitecture
    (
        Architecture architecture
    )
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