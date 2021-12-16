using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using Argon2Bindings.Attributes;
using Argon2Bindings.Enums;
using Argon2Bindings.Structures;

namespace Argon2Bindings;

internal static class Argon2Library
{
    /// <summary>
    /// Binding delegate which performs memory-hard hashing using the given
    /// context parameters.
    /// <param name="context">The context to use <see cref="Argon2MarshalContext"/></param>
    /// <param name="type">The argon2 variant to use for hashing <see cref="Argon2Type"/></param>
    /// <returns>
    /// An error result if something went wrong, otherwise <see cref="Argon2Result.Ok"/> result.
    /// </returns>
    /// </summary>
    [Argon2ApiBrokenOnPlatform(nameof(OSPlatform.Linux), Architecture.X64)]
    [Argon2ApiBrokenOnPlatform(nameof(OSPlatform.OSX), Architecture.X64)]
    [Argon2MappingMethod("argon2_ctx")]
    internal delegate Argon2Result Argon2ContextHashDelegate(
        ref Argon2MarshalContext context,
        Argon2Type type
    );

    /// <summary>
    /// Binding delegate which hashes a password.
    /// <remarks>
    /// This is a generic hashing method which will produce an <b>encoded</b> hash 
    /// or a <b>raw</b> hash if specified.
    /// </remarks>
    /// <param name="t_cost">The number of iterations</param>
    /// <param name="m_cost">The amount of memory to use in kibibytes</param>
    /// <param name="parallelism">The number of threads and compute lanes to use</param>
    /// <param name="pwd">The pointer to the password</param>
    /// <param name="pwdlen">The length of the password in bytes</param>
    /// <param name="salt">The pointer to the salt</param>
    /// <param name="saltlen">The length of the salt in bytes</param>
    /// <param name="hash">The pointer to the buffer to write the raw hash to</param>
    /// <param name="hashlen">The desired length of the hash in bytes</param>
    /// <param name="encoded">The pointer to the buffer to write the encoded hash to</param>
    /// <param name="encodedlen">The length of the encoded hash in bytes</param>
    /// <param name="type">The argon2 variant to use</param>
    /// <param name="version">The argon2 version to use</param>
    /// <returns>
    /// An error result if something went wrong,
    /// otherwise <see cref="Argon2Result.Ok"/> result.
    /// </returns>
    /// </summary>
    [Argon2MappingMethod("argon2_hash")]
    internal delegate Argon2Result Argon2HashDelegate(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd, nuint pwdlen,
        IntPtr salt, nuint saltlen,
        IntPtr hash, nuint hashlen,
        IntPtr encoded, nuint encodedlen,
        Argon2Type type,
        Argon2Version version
    );

    /// <summary>
    /// Binding delegate which returns the encoded hash length.
    /// <param name="t_cost">The number of iterations</param>
    /// <param name="m_cost">The amount of memory in kibibytes</param>
    /// <param name="parallelism">The number of threads and compute lanes</param>
    /// <param name="saltlen">The length of the salt in bytes</param>
    /// <param name="hashlen">The length of the hash in bytes</param>
    /// <param name="type">The argon2 variant to use</param>
    /// <returns>
    /// The encoded hash length for the given input parameters.
    /// </returns>
    /// </summary>
    [Argon2MappingMethod("argon2_encodedlen")]
    internal delegate nuint Argon2GetEncodedHashLengthDelegate(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        uint saltlen,
        uint hashlen,
        Argon2Type type
    );

    /// <summary>
    /// Binding delegate which verifies a password against
    /// an encoded string.
    /// <param name="encoded">The pointer to the encoded hash to use for verification</param>
    /// <param name="pwd">The pointer to the input password</param>
    /// <param name="pwdlen">The length of the input password in bytes</param>
    /// <param name="type">The argon2 variant to use</param>
    /// <returns>
    /// <see cref="Argon2Result.Ok"/> result if verification was successful. <br/>
    /// <see cref="Argon2Result.VerifyMismatch"/> result if verification failed. <br/>
    /// Otherwise an error result.
    /// </returns>
    /// </summary>
    [Argon2MappingMethod("argon2_verify")]
    internal delegate Argon2Result Argon2VerifyDelegate(
        IntPtr encoded,
        IntPtr pwd,
        nuint pwdlen,
        Argon2Type type
    );

    private static readonly Type[] DelegateTypes =
    {
        typeof(Argon2HashDelegate),
        typeof(Argon2GetEncodedHashLengthDelegate),
        typeof(Argon2VerifyDelegate),
        typeof(Argon2ContextHashDelegate),
    };

    private static readonly Type DynamicType;

    internal static readonly Argon2HashDelegate Argon2Hash;
    internal static readonly Argon2GetEncodedHashLengthDelegate Argon2GetEncodedHashLength;
    internal static readonly Argon2VerifyDelegate Argon2Verify;
    internal static readonly Argon2ContextHashDelegate Argon2ContextHash;

    static Argon2Library()
    {
        DynamicType = CreateDynamicType();

        Argon2Hash = GetDelegate<Argon2HashDelegate>();
        Argon2GetEncodedHashLength = GetDelegate<Argon2GetEncodedHashLengthDelegate>();
        Argon2Verify = GetDelegate<Argon2VerifyDelegate>();
        Argon2ContextHash = GetDelegate<Argon2ContextHashDelegate>();
    }

    private static string GetMappingMethod(MemberInfo type)
    {
        var attribute = type.GetCustomAttribute<Argon2MappingMethodAttribute>();
        if (attribute is null) throw new Exception("Delegate not given a method name to map to argon2 C library");
        return attribute.Name;
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
        return CreateDynamicType(nameof(Argon2Library) + "Dynamic", DelegateTypes);
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