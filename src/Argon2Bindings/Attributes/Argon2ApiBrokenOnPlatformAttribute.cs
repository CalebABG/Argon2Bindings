using System;
using System.Runtime.InteropServices;

namespace Argon2Bindings.Attributes;

/// <summary>
/// Attribute indicating that compatability or functionality
/// is broken / non-functional on a particular platform and architecture.
/// </summary>
[AttributeUsage(AttributeTargets.All, AllowMultiple = true)]
internal class Argon2ApiBrokenOnPlatformAttribute : Attribute
{
    public readonly string Platform;
    public readonly Architecture Architecture;

    public Argon2ApiBrokenOnPlatformAttribute(
        string platform,
        Architecture architecture)
    {
        Platform = platform;
        Architecture = architecture;
    }
}