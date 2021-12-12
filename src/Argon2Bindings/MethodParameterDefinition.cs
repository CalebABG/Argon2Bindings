using System;

namespace Argon2Bindings;

public class MethodParameterDefinition
{
    public MethodParameterDefinition(Type type, string name)
    {
        Name = name;
        Type = type;
    }
    
    public string Name { get; }
    public Type Type { get; }
}