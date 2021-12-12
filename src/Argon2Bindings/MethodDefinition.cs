using System;

namespace Argon2Bindings;

public class MethodDefinition
{
    public string Name { get; set; } = null!;
    public Type ReturnType { get; set; } = null!;
    public MethodParameterDefinition[] Parameters { get; set; } = null!;
}