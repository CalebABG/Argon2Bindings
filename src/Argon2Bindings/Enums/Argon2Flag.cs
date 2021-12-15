namespace Argon2Bindings.Enums;

public enum Argon2Flag
{
    Default = 0,
    ClearPassword = 1 << 0,
    ClearSecret = 1 << 1
}