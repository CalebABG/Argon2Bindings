using System;
using System.IO;
using System.Linq;
using System.Net.Sockets;
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
    /* Delegates */
    public delegate Argon2Result Argon2HashDelegate(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        IntPtr pwd, uint pwdlen,
        IntPtr salt, uint saltlen,
        IntPtr hash, uint hashlen,
        IntPtr encoded, uint encodedlen,
        Argon2Type type,
        Argon2Version version
    );
    
    public delegate uint Argon2GetEncodedHashLengthDelegate(
        uint t_cost,
        uint m_cost,
        uint parallelism,
        uint saltlen,
        uint hashlen,
        Argon2Type type
    );
    
    public static Argon2HashDelegate Argon2Hash;
    public static Argon2GetEncodedHashLengthDelegate Argon2GetEncodedHashLength;

    static Argon2Library()
    {
        var dynamicType = CreateDynamicType();

        Argon2Hash = (Argon2HashDelegate) Delegate.CreateDelegate(typeof(Argon2HashDelegate), dynamicType.GetMethod("argon2_hash")!);
        
        Argon2GetEncodedHashLength = (Argon2GetEncodedHashLengthDelegate) Delegate.CreateDelegate(typeof(Argon2GetEncodedHashLengthDelegate), dynamicType.GetMethod("argon2_encodedlen")!);
    }

    internal static Type CreateDynamicType()
    {
        Type typeArgon2Result = typeof(Argon2Result);
        Type typeArgon2Type = typeof(Argon2Type);
        Type typeArgon2Version = typeof(Argon2Version);
        Type typeUInt = typeof(uint);
        Type typeIntPtr = typeof(IntPtr);
        
        return CreateDynamicType(new[]
        {
            new MethodDefinition
            {
                Name = "argon2i_hash_encoded",
                ReturnType = typeArgon2Result,
                Parameters = new MethodParameterDefinition[]
                {
                    new(typeUInt, "t_cost"),
                    new(typeUInt, "m_cost"),
                    new(typeUInt, "parallelism"),
                    new(typeIntPtr, "pwd"),
                    new(typeUInt, "pwdlen"),
                    new(typeIntPtr, "salt"),
                    new(typeUInt, "saltlen"),
                    new(typeUInt, "hashlen"),
                    new(typeIntPtr, "encoded"),
                    new(typeUInt, "encodedlen")
                }
            },
            new MethodDefinition
            {
                Name = "argon2i_hash_raw",
                ReturnType = typeArgon2Result,
                Parameters = new MethodParameterDefinition[]
                {
                    new(typeUInt, "t_cost"),
                    new(typeUInt, "m_cost") ,
                    new(typeUInt, "parallelism"),
                    new(typeIntPtr, "pwd"),
                    new(typeUInt, "pwdlen"),
                    new(typeIntPtr, "salt"),
                    new(typeUInt, "saltlen"),
                    new(typeIntPtr, "hash"),
                    new(typeUInt, "hashlen")
                }
            },
            new MethodDefinition
            {
                Name = "argon2d_hash_encoded",
                ReturnType = typeArgon2Result,
                Parameters = new MethodParameterDefinition[]
                {
                    new(typeUInt, "t_cost"),
                    new(typeUInt, "m_cost"),
                    new(typeUInt, "parallelism"),
                    new(typeIntPtr, "pwd"),
                    new(typeUInt, "pwdlen"),
                    new(typeIntPtr, "salt"),
                    new(typeUInt, "saltlen"),
                    new(typeUInt, "hashlen"),
                    new(typeIntPtr, "encoded"),
                    new(typeUInt, "encodedlen")
                }
            },
            new MethodDefinition
            {
                Name = "argon2d_hash_raw",
                ReturnType = typeArgon2Result,
                Parameters = new MethodParameterDefinition[]
                {
                    new(typeUInt, "t_cost"),
                    new(typeUInt, "m_cost"),
                    new(typeUInt, "parallelism"),
                    new(typeIntPtr, "pwd"),
                    new(typeUInt, "pwdlen"),
                    new(typeIntPtr, "salt"),
                    new(typeUInt, "saltlen"),
                    new(typeIntPtr, "hash"),
                    new(typeUInt, "hashlen")
                }
            },
            new MethodDefinition
            {
                Name = "argon2id_hash_encoded",
                ReturnType = typeArgon2Result,
                Parameters = new MethodParameterDefinition[]
                {
                    new(typeUInt, "t_cost"),
                    new(typeUInt, "m_cost"),
                    new(typeUInt, "parallelism"),
                    new(typeIntPtr, "pwd"),
                    new(typeUInt, "pwdlen"),
                    new(typeIntPtr, "salt"),
                    new(typeUInt, "saltlen"),
                    new(typeUInt, "hashlen"),
                    new(typeIntPtr, "encoded"),
                    new(typeUInt, "encodedlen")
                }
            },
            new MethodDefinition
            {
                Name = "argon2id_hash_raw",
                ReturnType = typeArgon2Result,
                Parameters = new MethodParameterDefinition[]
                {
                    new(typeUInt, "t_cost"),
                    new(typeUInt, "m_cost"),
                    new(typeUInt, "parallelism"),
                    new(typeIntPtr, "pwd"),
                    new(typeUInt, "pwdlen"),
                    new(typeIntPtr, "salt"),
                    new(typeUInt, "saltlen"),
                    new(typeIntPtr, "hash"),
                    new(typeUInt, "hashlen")
                }
            },
            new MethodDefinition
            {
                Name = "argon2_hash",
                ReturnType = typeArgon2Result,
                Parameters = new MethodParameterDefinition[]
                {
                    new(typeUInt, "t_cost"),
                    new(typeUInt, "m_cost"),
                    new(typeUInt, "parallelism"),
                    new(typeIntPtr, "pwd"),
                    new(typeUInt, "pwdlen"),
                    new(typeIntPtr, "salt"),
                    new(typeUInt, "saltlen"),
                    new(typeIntPtr, "hash"),
                    new(typeUInt, "hashlen"),
                    new(typeIntPtr, "encoded"),
                    new(typeUInt, "encodedlen"),
                    new(typeArgon2Type, "type"),
                    new(typeArgon2Version, "version")
                }
            },
            new MethodDefinition
            {
                Name = "argon2_error_message",
                ReturnType = typeIntPtr,
                Parameters = new MethodParameterDefinition[]
                {
                    new(typeArgon2Result, "error_code")
                }
            },
            new MethodDefinition
            {
                Name = "argon2_encodedlen",
                ReturnType = typeUInt,
                Parameters = new MethodParameterDefinition[]
                {
                    new(typeUInt, "t_cost"),
                    new(typeUInt, "m_cost"),
                    new(typeUInt, "parallelism"),
                    new(typeUInt, "saltlen"),
                    new(typeUInt, "hashlen"),
                    new(typeArgon2Type, "type")
                }
            }
        }, $"{nameof(Argon2Library)}Dynamic");
    }

    /* Reference: https://www.codeproject.com/script/Articles/ViewDownloads.aspx?aid=11310 */
    private static Type CreateDynamicType(MethodDefinition[] definitions, string dynamicBaseName)
    {
        AssemblyBuilder assemblyBuilder = AssemblyBuilder.DefineDynamicAssembly(new AssemblyName
        {
            Name = dynamicBaseName + "Assembly"
        }, AssemblyBuilderAccess.Run);

        TypeBuilder typeBuilder = assemblyBuilder.DefineDynamicModule(dynamicBaseName + "Module").DefineType(dynamicBaseName + "Type", TypeAttributes.Class);

        foreach (MethodDefinition definition in definitions)
        {
            MethodBuilder methodBuilder = typeBuilder.DefinePInvokeMethod(
                definition.Name,
                GetDynamicDllPath(),
                MethodAttributes.FamANDAssem | MethodAttributes.Family | MethodAttributes.Public | MethodAttributes.Static | MethodAttributes.HideBySig | MethodAttributes.PinvokeImpl,
                CallingConventions.Standard,
                definition.ReturnType,
                definition.Parameters.Select(t => t.Type).ToArray(),
                CallingConvention.Cdecl,
                CharSet.Auto
            );

            for (var j = 0; j < definition.Parameters.Length; ++j) methodBuilder.DefineParameter(j + 1, ParameterAttributes.None, definition.Parameters[j].Name);

            methodBuilder.SetImplementationFlags(MethodImplAttributes.PreserveSig);
        }

        Type dynamicType = typeBuilder.CreateType();

        if (dynamicType is null) throw new Exception("Could not create dynamic bindings Type");

        return dynamicType;
    }

    private static string GetDynamicDllPath()
    {
        var platformArch = GetPlatformArch();
        var (platformName, platformBinaryExtension) = GetPlatformNameAndBinaryExtension();
        var argon2BinaryFolder = $"{platformName}-{platformArch}";

        var assemPath = Assembly.GetExecutingAssembly().Location;
        var path = Path.GetFullPath(Path.Combine(assemPath, "..", "argon2binaries", argon2BinaryFolder, $"libargon2.{platformBinaryExtension}"));

        Console.WriteLine(path);
        return path;
    }

    private static (string platformName, string platformBinaryExtension) GetPlatformNameAndBinaryExtension()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return ("win", "dll");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) return ("osx", "dylib");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return ("linux", "so");

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