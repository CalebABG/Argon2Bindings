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

    byte[] outRawBytes = Argon2Core.Hash(pass, salt, context, false);
    Console.WriteLine($"RAW (HEX): {outRawBytes.ToHexString()}");

    byte[] outEncodedBytes = Argon2Core.Hash(pass, salt, context);
    Console.WriteLine($"Encoded (B64): {Encoding.UTF8.GetString(outEncodedBytes)}");
}