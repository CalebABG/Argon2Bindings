using System;
using System.Runtime.InteropServices;

namespace Argon2Bindings;

public static class Argon2Library
{
#if WINDOWS
    private const string DllName = @"libs\libargon2.dll";
#elif MACOS
    private const string DllName = @"libs\libargon2.1.dylib";
#elif LINUX
    private const string DllName = @"libs\libargon2.so.1";
#endif

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern Argon2Result argon2i_hash_encoded(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd, uint pwdlen,
        IntPtr salt, uint saltlen,
        uint hashlen,
        IntPtr encoded, uint encodedlen);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern Argon2Result argon2i_hash_raw(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd, uint pwdlen,
        IntPtr salt, uint saltlen,
        IntPtr hash, uint hashlen);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern Argon2Result argon2_hash(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd,
        uint pwdlen,
        IntPtr salt,
        uint saltlen,
        IntPtr hash, uint hashlen,
        IntPtr encoded, uint encodedlen,
        Argon2Type type,
        Argon2Version version);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern IntPtr argon2_error_message(
        Argon2Result error_code
    );

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern uint argon2_encodedlen(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        uint saltlen,
        uint hashlen,
        Argon2Type type);
}