using System.Runtime.InteropServices;
using Argon2Bindings;

var d = Argon2Library.CreateDynamicType();
var t = d.GetMethod(nameof(Argon2Library.argon2_error_message));
var r = (IntPtr)t.Invoke(null, new object[]
{
    Argon2Result.DecodingFail
});

/* Todo: Update method in Argon2Core `argon2_error_message` */
var s = Marshal.PtrToStringUTF8(r);
Console.WriteLine(s);

/*const string salt = "testing123";
const string pass = "test";

int rawHashFailures = 0,
    encodedHashFailures = 0;

const string format = "{0}\t\t{1}\t\t{2}\t\t{3}\n";

Console.WriteLine("Legend:\nR = Raw Hash\nE = Encoded Hash\n");
Console.WriteLine("Run #\t\tType\t\tResult\t\tOutput\n");

for (var i = 0; i < 5; ++i)
{
    var rawHashResult = Argon2Core.HashRaw(pass, salt);
    if (rawHashResult.Status is not Argon2Result.Ok)
        ++rawHashFailures;

    Console.Write(format, $"{i + 1}", "R (HEX)", rawHashResult.Status,
        rawHashResult.RawHash.ToHexString());

    var encodedHashResult = Argon2Core.HashEncoded(pass, salt);
    if (encodedHashResult.Status is not Argon2Result.Ok)
        ++encodedHashFailures;

    Console.WriteLine(format, $"{i + 1}", "E (B64)", encodedHashResult.Status,
        encodedHashResult.EncodedHash);
}

Console.WriteLine($"Total Raw Hash Failures: {rawHashFailures}\nTotal Encoded Hash Failures: {encodedHashFailures}");*/