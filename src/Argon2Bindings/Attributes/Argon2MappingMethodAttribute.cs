using System;

namespace Argon2Bindings.Attributes;

internal class Argon2MappingMethodAttribute : Attribute
{
    public readonly string Name;

    public Argon2MappingMethodAttribute(string name)
    {
        Name = name;
    }
}