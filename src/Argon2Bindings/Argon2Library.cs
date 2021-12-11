using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

namespace Argon2Bindings;

/*
 * Note:
 * uint32_t -> uint
 * size_t   -> nuint
 */
internal static class Argon2Library
{
    private const string TempDllName = "libargon2";

    /* Note: need to provide non-empty string (but will be replaced dynamically) */
    [DllImport(TempDllName)]
    public static extern Argon2Result argon2i_hash_encoded(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd, uint pwdlen,
        IntPtr salt, uint saltlen,
        uint hashlen,
        IntPtr encoded, uint encodedlen);

    [DllImport(TempDllName)]
    public static extern Argon2Result argon2i_hash_raw(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd, uint pwdlen,
        IntPtr salt, uint saltlen,
        IntPtr hash, uint hashlen);

    [DllImport(TempDllName)]
    public static extern Argon2Result argon2d_hash_encoded(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd, uint pwdlen,
        IntPtr salt, uint saltlen,
        uint hashlen,
        IntPtr encoded, uint encodedlen);

    [DllImport(TempDllName)]
    public static extern Argon2Result argon2d_hash_raw(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd, uint pwdlen,
        IntPtr salt, uint saltlen,
        IntPtr hash, uint hashlen);

    [DllImport(TempDllName)]
    public static extern Argon2Result argon2id_hash_encoded(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd, uint pwdlen,
        IntPtr salt, uint saltlen,
        uint hashlen,
        IntPtr encoded, uint encodedlen);

    [DllImport(TempDllName)]
    public static extern Argon2Result argon2id_hash_raw(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd, uint pwdlen,
        IntPtr salt, uint saltlen,
        IntPtr hash, uint hashlen);

    /* Todo: Fix issue with M1 or dynamic type / Remove method and use type specific methods  */
    /*[DllImport(TempDllName)]
    public static extern Argon2Result argon2_hash(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd, uint pwdlen,
        IntPtr salt, uint saltlen,
        IntPtr hash, uint hashlen,
        IntPtr encoded, uint encodedlen,
        Argon2Type type,
        Argon2Version version);*/

    [DllImport(TempDllName)]
    public static extern IntPtr argon2_error_message(
        Argon2Result error_code
    );

    [DllImport(TempDllName)]
    public static extern uint argon2_encodedlen(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        uint saltlen,
        uint hashlen,
        Argon2Type type);

    internal static Type CreateDynamicType()
    {
        return CreateDynamicType(typeof(Argon2Library), $"{nameof(Argon2Library)}Dynamic");
    }

    /* Reference: https://www.codeproject.com/script/Articles/ViewDownloads.aspx?aid=11310 */
    private static Type CreateDynamicType(Type originalType, string dynamicBaseName)
    {
        AssemblyName assemblyName = new AssemblyName
        {
            Name = dynamicBaseName + "Assembly"
        };

        AssemblyBuilder assemblyBuilder =
            AssemblyBuilder.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);

        ModuleBuilder? moduleBuilder = assemblyBuilder.DefineDynamicModule(dynamicBaseName + "Module");

        TypeBuilder typeBuilder = moduleBuilder.DefineType(dynamicBaseName + "Type", TypeAttributes.Class);

        MethodInfo[] methodInfos = originalType.GetMethods(BindingFlags.Public | BindingFlags.Static);

        string dllPath = GetDynamicDllPath();

        for (var i = 0; i < methodInfos.GetLength(0); ++i)
        {
            MethodInfo mi = methodInfos[i];

            ParameterInfo[] methodParameters = mi.GetParameters();
            int parameterCount = methodParameters.GetLength(0);

            Type[] parameterTypes = new Type[parameterCount];
            ParameterAttributes[] parameterAttributes = new ParameterAttributes[parameterCount];

            for (var j = 0; j < parameterCount; ++j)
            {
                parameterTypes[j] = methodParameters[j].ParameterType;
                parameterAttributes[j] = methodParameters[j].Attributes;
            }

            MethodBuilder methodBuilder = typeBuilder.DefinePInvokeMethod(
                mi.Name,
                dllPath,
                mi.Attributes,
                mi.CallingConvention,
                mi.ReturnType,
                parameterTypes,
                CallingConvention.Cdecl,
                CharSet.Unicode);

            for (var j = 0; j < parameterCount; ++j)
                methodBuilder.DefineParameter(j + 1, parameterAttributes[j], methodParameters[j].Name);

            methodBuilder.SetImplementationFlags(mi.GetMethodImplementationFlags());
        }

        Type dynamicType = typeBuilder.CreateType();

        if (dynamicType is null)
            throw new Exception("Could not create dynamic bindings Type");

        return dynamicType;
    }

    private static string GetDynamicDllPath()
    {
        var platformArch = GetPlatformArch();
        var (platformName, platformBinaryExtension) = GetPlatformNameAndBinaryExtension();
        var argon2BinaryFolder = $"{platformName}-{platformArch}";

        var assemPath = Assembly.GetExecutingAssembly().Location;
        var path = Path.GetFullPath(Path.Combine(
            assemPath, "..", "argon2binaries",
            argon2BinaryFolder, $"libargon2.{platformBinaryExtension}"));

        Console.WriteLine(path);
        return path;
    }

    private static (string platformName, string platformBinaryExtension) GetPlatformNameAndBinaryExtension()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return ("win", "dll");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return ("osx", "dylib");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            return ("linux", "so");

        throw new Exception("Platform not currently supported");
    }

    private static string GetPlatformArch()
    {
        return RuntimeInformation.OSArchitecture switch
        {
            Architecture.Arm => "arm",
            Architecture.Arm64 => "arm64",
            Architecture.X64 => "x64",
            Architecture.X86 => "x86",
            _ => throw new Exception("Architecture not currently supported")
        };
    }
}