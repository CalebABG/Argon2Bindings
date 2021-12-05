using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

namespace Argon2Bindings;

internal static class Argon2Library
{
    /* Note: need to provide non-empty string (but will be replaced by dynamically) */
    [DllImport("libargon2")]
    public static extern Argon2Result argon2i_hash_encoded(
        nuint t_cost,
        nuint m_cost,
        nuint parallelism,
        IntPtr pwd, nuint pwdlen,
        IntPtr salt, nuint saltlen,
        nuint hashlen,
        IntPtr encoded, nuint encodedlen);

    [DllImport("libargon2")]
    public static extern Argon2Result argon2i_hash_raw(
        nuint t_cost,
        nuint m_cost,
        nuint parallelism,
        IntPtr pwd, nuint pwdlen,
        IntPtr salt, nuint saltlen,
        IntPtr hash, nuint hashlen);

    [DllImport("libargon2")]
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

    [DllImport("libargon2")]
    public static extern IntPtr argon2_error_message(
        Argon2Result error_code
    );

    [DllImport("libargon2")]
    public static extern nuint argon2_encodedlen(
        nuint t_cost,
        nuint m_cost,
        nuint parallelism,
        nuint saltlen,
        nuint hashlen,
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

        var moduleBuilder = assemblyBuilder.DefineDynamicModule(dynamicBaseName + "Module");

        TypeBuilder typeBuilder = moduleBuilder.DefineType(dynamicBaseName + "Type", TypeAttributes.Class);

        MethodInfo[] methodInfos = originalType.GetMethods(BindingFlags.Public | BindingFlags.Static);

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
                GetDynamicDllPath(),
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

        return Path.Combine("argon2binaries", argon2BinaryFolder, $"libargon2.{platformBinaryExtension}");
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