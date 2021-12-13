using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using Argon2Bindings.Attributes;

namespace Argon2Bindings;

internal static class Argon2Library
{
    /* Delegates */
    [Argon2MappingMethod("argon2_hash")]
    internal delegate Argon2Result Argon2HashDelegate(
        nuint t_cost,
        nuint m_cost,
        nuint parallelism,
        IntPtr pwd, nuint pwdlen,
        IntPtr salt, nuint saltlen,
        IntPtr hash, nuint hashlen,
        IntPtr encoded, nuint encodedlen,
        Argon2Type type,
        Argon2Version version
    );

    [Argon2MappingMethod("argon2_encodedlen")]
    internal delegate nuint Argon2GetEncodedHashLengthDelegate(
        nuint t_cost,
        nuint m_cost,
        nuint parallelism,
        nuint saltlen,
        nuint hashlen,
        Argon2Type type
    );

    private static string GetMappingMethod(MemberInfo type)
    {
        var attribute = type.GetCustomAttribute<Argon2MappingMethodAttribute>();
        if (attribute is null) throw new Exception("Delegate not given a name to map to argon2 C library");
        return attribute.Name;
    }

    private static readonly Type DynamicType;

    internal static readonly Argon2HashDelegate Argon2Hash;
    internal static readonly Argon2GetEncodedHashLengthDelegate Argon2GetEncodedHashLength;

    static Argon2Library()
    {
        DynamicType = CreateDynamicType();

        Argon2Hash = GetDelegate<Argon2HashDelegate>();
        Argon2GetEncodedHashLength = GetDelegate<Argon2GetEncodedHashLengthDelegate>();
    }

    private static TDelegate GetDelegate<TDelegate>()
        where TDelegate : Delegate
    {
        var delegateType = typeof(TDelegate);
        var mappingMethodName = GetMappingMethod(delegateType);
        return (TDelegate) Delegate.CreateDelegate(delegateType, DynamicType.GetMethod(mappingMethodName)!);
    }

    private static Type CreateDynamicType()
    {
        return CreateDynamicType(
            $"{nameof(Argon2Library)}Dynamic",
            new[]
            {
                typeof(Argon2HashDelegate),
                typeof(Argon2GetEncodedHashLengthDelegate)
            });
    }

    /* Reference: https://www.codeproject.com/script/Articles/ViewDownloads.aspx?aid=11310 */
    private static Type CreateDynamicType(string dynamicBaseName, Type[] delegateTypes)
    {
        AssemblyBuilder assemblyBuilder = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName
        {
            Name = dynamicBaseName + "Assembly"
        }, AssemblyBuilderAccess.Run);

        TypeBuilder typeBuilder = assemblyBuilder
            .DefineDynamicModule(dynamicBaseName + "Module")
            .DefineType(dynamicBaseName + "Type", TypeAttributes.Class);

        string dllPath = GetDynamicDllPath();

        MethodAttributes methodAttributes = MethodAttributes.FamANDAssem |
                                            MethodAttributes.Family |
                                            MethodAttributes.Public |
                                            MethodAttributes.Static |
                                            MethodAttributes.HideBySig |
                                            MethodAttributes.PinvokeImpl;

        for (var i = 0; i < delegateTypes.Length; ++i)
        {
            Type delegateType = delegateTypes[i];

            string mappingMethodName = GetMappingMethod(delegateType);

            MethodInfo method = delegateType.GetMethod("Invoke")!;

            Type[] methodParameterTypes = method.GetParameters()
                .Select(t => t.ParameterType)
                .ToArray();

            MethodBuilder methodBuilder = typeBuilder.DefinePInvokeMethod(
                mappingMethodName,
                dllPath,
                methodAttributes,
                CallingConventions.Standard,
                method.ReturnType,
                methodParameterTypes,
                CallingConvention.Cdecl,
                CharSet.Auto
            );

            for (var j = 0; j < methodParameterTypes.Length; ++j)
                methodBuilder.DefineParameter(j + 1, ParameterAttributes.None, methodParameterTypes[j].Name);

            methodBuilder.SetImplementationFlags(MethodImplAttributes.PreserveSig);
        }

        Type dynamicType = typeBuilder.CreateType();

        if (dynamicType is null)
            throw new Exception("Could not create dynamic binding type");

        return dynamicType;
    }

    private static string GetDynamicDllPath()
    {
        var binaryName = "libargon2";
        var binariesFolder = "argon2binaries";
        var assemblyPath = Assembly.GetExecutingAssembly().Location;

        var platformArch = GetPlatformArchitecture();
        var (platformName, platformBinaryExtension) = GetPlatformNameAndBinaryExtension();
        var platformBinaryFolder = $"{platformName}-{platformArch}";

        var partialPath = Path.Combine(assemblyPath, "..", binariesFolder,
            platformBinaryFolder, $"{binaryName}.{platformBinaryExtension}");

        var fullPath = Path.GetFullPath(partialPath);

        Console.WriteLine(fullPath);
        return fullPath;
    }

    private static (string platformName, string platformBinaryExtension) GetPlatformNameAndBinaryExtension()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return ("win", "dll");
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) return ("osx", "dylib");
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return ("linux", "so");

        throw new Exception("Platform not currently supported");
    }

    private static string GetPlatformArchitecture()
    {
        return RuntimeInformation.OSArchitecture switch
        {
            Architecture.Arm => "arm",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            Architecture.X64 => "x64",
            _ => throw new Exception("Architecture not currently supported")
        };
    }
}