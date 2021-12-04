using System;
using System.Runtime.InteropServices;

namespace Argon2Bindings;

public static class Argon2Library
{
#if WINDOWS
    private const string DllName = @"libargon2.dll";
#elif MACOS
    private const string DllName = @"libargon2.dylib";
#elif LINUX
    private const string DllName = @"libargon2.so";
#endif

    [DllImport(DllName, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern Argon2Result argon2i_hash_encoded(
        nuint t_cost,
        nuint m_cost,
        nuint parallelism,
        IntPtr pwd, nuint pwdlen,
        IntPtr salt, nuint saltlen,
        nuint hashlen,
        IntPtr encoded, nuint encodedlen);

    [DllImport(DllName, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern Argon2Result argon2i_hash_raw(
        nuint t_cost,
        nuint m_cost,
        nuint parallelism,
        IntPtr pwd, nuint pwdlen,
        IntPtr salt, nuint saltlen,
        IntPtr hash, nuint hashlen);

    [DllImport(DllName, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern Argon2Result argon2_hash(
        nuint t_cost,
        nuint m_cost,
        nuint parallelism,
        IntPtr pwd,
        nuint pwdlen,
        IntPtr salt,
        nuint saltlen,
        IntPtr hash, nuint hashlen,
        IntPtr encoded, nuint encodedlen,
        Argon2Type type,
        Argon2Version version);

    [DllImport(DllName, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern IntPtr argon2_error_message(
        Argon2Result error_code
    );

    [DllImport(DllName, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern nuint argon2_encodedlen(
        nuint t_cost,
        nuint m_cost,
        nuint parallelism,
        nuint saltlen,
        nuint hashlen,
        Argon2Type type);
}