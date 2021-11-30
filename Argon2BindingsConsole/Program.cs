using System.Text;
using Argon2Bindings;

const string salt = "testing123";
const string pass = "test";

Argon2Context context = new();

/*byte[] outEncodedBytes = Argon2Core.Hash(pass, salt, context);
Console.WriteLine($"Encoded (B64): {Encoding.UTF8.GetString(outEncodedBytes)}");*/

for (var i = 0; i < 5; ++i)
{
    Console.WriteLine($"\nTEST: {i + 1}");

    byte[] rawHashBytes = Argon2Core.HashRaw(pass, salt, context);
    Console.WriteLine($"RAW (HEX): {rawHashBytes.ToHexString()}");

    string encodedHash = Argon2Core.HashEncoded(pass, salt, context);
    Console.WriteLine($"Encoded (B64): {encodedHash}");
}