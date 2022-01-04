using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using Argon2Bindings.Attributes;

namespace Argon2Bindings;

/// <summary>
/// Class used for creating a <see cref="Type"/> dynamically
/// through reflection which defines PInvoke methods on the type
/// which can be used to call native argon2 C library functions.
/// </summary>
internal static class Argon2DynamicBinding
{
    private const string AssemblyPrefix = nameof(Argon2DynamicBinding);
    private const string AssemblyName = AssemblyPrefix + "Assembly";
    private const string ModuleName = AssemblyPrefix + "Module";
    private const string TypeName = AssemblyPrefix + "Type";

    private const string Argon2BinaryName = "libargon2";
    private const string Argon2BinariesFolder = "argon2binaries";

    private const MethodAttributes MethodAttribs = MethodAttributes.Public |
                                                   MethodAttributes.Static |
                                                   MethodAttributes.PinvokeImpl;

    /// <summary>
    /// Gets the name of the method to be used which corresponds 
    /// to an argon2 C library function name.
    /// </summary>
    /// <param name="type">The delegate type to retrieve the name from</param>
    /// <returns>
    /// The name of the method to be used.
    /// </returns>
    /// <exception cref="Exception">
    /// Throws if the provided type is null or if the provided delegate's method name is null or empty.
    /// </exception>
    internal static string GetMappingMethod(Type type)
    {
        if (type is null)
            throw new ArgumentNullException(nameof(type), "Type cannot be null");

        var attribute = type.GetCustomAttribute<Argon2MappingMethodAttribute>();
        if (attribute is null)
            throw new Exception("Delegate not given a method name to map to argon2 C library");

        return attribute.Name;
    }

    /// <summary>
    /// Creates a delegate from the provided type.
    /// <remarks>
    /// This method gets the name of the method from the delegate
    /// through the <see cref="Argon2MappingMethodAttribute"/>.
    /// </remarks>
    /// </summary>
    /// <typeparam name="TDelegate">The delegate type to create</typeparam>
    /// <param name="type">The type which holds the</param>
    /// <returns>
    /// The delegate which corresponds to the PInvoke method contained in the type provided.
    /// </returns>
    /// <exception cref="Exception">
    /// Throws when the delegate specified is not annotated with a mapping name or the mapping 
    /// name is null or empty.
    /// </exception>
    internal static TDelegate GetDelegate<TDelegate>(Type type)
        where TDelegate : Delegate
    {
        var delegateType = typeof(TDelegate);
        var mappingMethodName = GetMappingMethod(delegateType);
        return (TDelegate)Delegate.CreateDelegate(delegateType, type.GetMethod(mappingMethodName)!);
    }

    /// <summary>
    /// Builds a <see cref="Type"/> from a collection of delegates.
    /// This type contains PInvoke methods built from the provided collection of delegates,
    /// which can be called to invoke native argon2 C library functions.
    /// </summary>
    /// <param name="delegateTypes">The collection of delegates to be used to build PInvoke methods</param>
    /// <returns>
    /// The dynamically created type with PInvoke methods built from the provided delegates.
    /// </returns>
    internal static Type CreateDynamicType(IReadOnlyList<Type> delegateTypes)
    {
        return CreateDynamicType(
            AssemblyName,
            ModuleName,
            TypeName,
            delegateTypes);
    }

    /// <summary>
    /// Builds a <see cref="Type"/> from a collection of delegates.
    /// This type contains PInvoke methods built from the provided collection of delegates,
    /// which can be called to invoke native argon2 C library functions.
    /// References:
    /// 1. <see href="https://www.codeproject.com/script/Articles/ViewDownloads.aspx?aid=11310" />
    /// 2. <see href="https://docs.microsoft.com/en-us/dotnet/api/system.reflection.emit.modulebuilder.definepinvokemethod?view=netstandard-2.1" />
    /// </summary>
    /// <param name="assemblyName">The name of the assembly</param>
    /// <param name="moduleName">The name of the module</param>
    /// <param name="typeName">The type name</param>
    /// <param name="delegateTypes">The collection of delegates to be used to build PInvoke methods</param>
    /// <returns>
    /// The dynamically created type with PInvoke methods built from the provided delegates.
    /// </returns>
    /// <exception cref="Exception">
    /// Throws when the dynamic type is null or other exceptions are thrown through reflection.
    /// </exception>
    private static Type CreateDynamicType(
        string assemblyName,
        string moduleName,
        string typeName,
        IReadOnlyList<Type> delegateTypes)
    {
        AssemblyBuilder assemblyBuilder = AssemblyBuilder.DefineDynamicAssembly(
            new AssemblyName(assemblyName),
            AssemblyBuilderAccess.Run);

        TypeBuilder typeBuilder = assemblyBuilder
            .DefineDynamicModule(moduleName)
            .DefineType(typeName, TypeAttributes.Class);

        string dllPath = GetDynamicDllPath();

        for (var i = 0; i < delegateTypes.Count; ++i)
        {
            Type delegateType = delegateTypes[i];

            string mappingMethodName = GetMappingMethod(delegateType);

            MethodInfo delegateMethod = delegateType.GetMethod("Invoke")!;

            Type[] methodParameterTypes = delegateMethod.GetParameters()
                .Select(t => t.ParameterType)
                .ToArray();

            MethodBuilder methodBuilder = typeBuilder.DefinePInvokeMethod(
                mappingMethodName,
                dllPath,
                MethodAttribs,
                CallingConventions.Standard,
                delegateMethod.ReturnType,
                methodParameterTypes,
                CallingConvention.Cdecl,
                CharSet.Auto
            );

            var implFlags = methodBuilder.GetMethodImplementationFlags() |
                            MethodImplAttributes.PreserveSig;

            methodBuilder.SetImplementationFlags(implFlags);
        }

        Type dynamicType = typeBuilder.CreateType();

        if (dynamicType is null)
            throw new Exception("Could not create dynamic binding type");

        return dynamicType;
    }

    /// <summary>
    /// Locates the argon2 binary for the target
    /// platform + cpu architecture.
    /// </summary>
    /// <returns>
    /// The full path to the correct argon2 binary for the target
    /// platform.
    /// </returns>
    private static string GetDynamicDllPath()
    {
        var currentDomainBaseDirectory = AppDomain.CurrentDomain.BaseDirectory;

        var platformArch = Argon2PlatformUtilities.GetPlatformArchitecture();
        var (platformName, platformBinaryExtension) = Argon2PlatformUtilities.GetPlatformNameAndBinaryExtension();
        var platformBinaryFolder = $"{platformName}-{platformArch}";

        var partialPath = Path.Combine(currentDomainBaseDirectory, Argon2BinariesFolder,
            platformBinaryFolder, $"{Argon2BinaryName}.{platformBinaryExtension}");

        var fullPath = Path.GetFullPath(partialPath);
        return fullPath;
    }
}