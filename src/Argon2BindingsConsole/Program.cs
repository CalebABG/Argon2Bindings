using Argon2Bindings;

const string salt = "testing123";
const string pass = "test";

int rawHashFailures = 0,
    encodedHashFailures = 0;

const string format = "{0}\t\t{1}\t\t{2}\t\t{3}\n";

Console.WriteLine("Legend:\nR = Raw Hash\nE = Encoded Hash\n");
Console.WriteLine("Run #\t\tType\t\tResult\t\tOutput\n");

for (var i = 0; i < 5; ++i)
{
    var runNum = $"{i + 1}";

    var rawHashResult = Argon2Core.HashRaw(pass, salt);
    if (rawHashResult.Status is not Argon2Result.Ok)
        ++rawHashFailures;
    else
        Console.Write(format, runNum, "R (HEX)", rawHashResult.Status, rawHashResult.RawHash.ToHexString());

    var encodedHashResult = Argon2Core.HashEncoded(pass, salt);
    if (encodedHashResult.Status is not Argon2Result.Ok)
        ++encodedHashFailures;
    else
        Console.WriteLine(format, runNum, "E (B64)", encodedHashResult.Status, encodedHashResult.EncodedHash);
}

Console.WriteLine($"Total Raw Hash Failures: {rawHashFailures}\nTotal Encoded Hash Failures: {encodedHashFailures}");