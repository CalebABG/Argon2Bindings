using System;
using System.Runtime.InteropServices;

namespace Argon2Bindings;

public static class Argon2Library
{
#if WINDOWS
    private const string DllName = "libargon2.dll";
#elif MACOS
    private const string DllName = "libargon2.1.dylib";
#elif LINUX
    private const string DllName = "libargon2.so.1";
#endif

    [DllImport(DllName, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
    public static extern Argon2Result argon2i_hash_raw(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd, uint pwdlen,
        IntPtr salt, uint saltlen,
        IntPtr hash, uint hashlen);


    [DllImport(DllName, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
    public static extern Argon2Result argon2i_hash_encoded(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd, uint pwdlen,
        IntPtr salt, uint saltlen,
        uint hashlen,
        IntPtr encoded,
        uint encodedlen);

    [DllImport(DllName, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.Cdecl)]
    public static extern uint argon2_encodedlen(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        uint saltlen,
        uint hashlen,
        Argon2Type type);
}