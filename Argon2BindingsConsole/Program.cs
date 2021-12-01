using Argon2Bindings;

const string salt = "testing123";
const string pass = "test";

for (var i = 0; i < 5; ++i)
{
    Console.WriteLine($"\nTEST: {i + 1}");

    byte[] rawHashBytes = Argon2Core.HashRaw(pass, salt);
    Console.WriteLine($"RAW (HEX): {rawHashBytes.ToHexString()}");

    string encodedHash = Argon2Core.HashEncoded(pass, salt);
    Console.WriteLine($"Encoded (B64): {encodedHash}");
}