using System.Text;
using Argon2Bindings;

const string salt = "testing123";
const string pass = "testing12345";

Argon2Context context = new();

byte[] outEncodedString = Argon2Core.Hash(Encoding.UTF8.GetBytes(pass), Encoding.UTF8.GetBytes(salt), context);
Console.WriteLine($"ENCODED (B64): {Encoding.UTF8.GetString(outEncodedString)}");

/*for (var i = 0; i < 5; ++i)
{
    Console.WriteLine($"\nTEST: {i + 1}");

    var outBytes = Argon2Core.HashRaw(pass, salt, context);
    var outString = outBytes.ToHexString();
    Console.WriteLine($"RAW (HEX): {outString}");

    var outEncodedString = Argon2Core.HashEncoded(pass, salt, context);
    Console.WriteLine($"ENCODED (B64): {outEncodedString}");
}*/