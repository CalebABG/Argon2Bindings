using System.Diagnostics;
using Argon2Bindings;

const string salt = "testing123";
const string pass = "test";
Argon2Context context = new()
{
    TimeCost = 3,
    MemoryCost = 1 << 4,
    DegreeOfParallelism = 1,
    Type = Argon2Type.Argon2I,
};

PrintHashAndVerify();
// PrintTabularHashResults();

void PrintHashAndVerify()
{
    var stopwatch = Stopwatch.StartNew();
    var hash = Argon2Core.HashEncoded(pass, salt, context);

    stopwatch.Stop();
    Console.WriteLine($"\nHash Time: {stopwatch.ElapsedMilliseconds}ms");
    Console.WriteLine(hash);

    stopwatch.Restart();
    var verify = Argon2Core.Verify(pass, hash.EncodedHash, context.Type);

    stopwatch.Stop();
    Console.WriteLine($"\nVerify Time: {stopwatch.ElapsedMilliseconds}ms");
    Console.WriteLine(verify);
}

void PrintTabularHashResults()
{
    int rawHashFailures = 0,
        encodedHashFailures = 0;

    const string format = "{0}\t\t{1}\t\t{2}\t\t{3}\n";

    Console.WriteLine("Legend:\nR = Raw Hash\nE = Encoded Hash\n");
    Console.WriteLine("Run #\t\tType\t\tResult\t\tOutput\n");

    for (var i = 0; i < 5; ++i)
    {
        var runNum = $"{i + 1}";

        var rawHashResult = Argon2Core.HashRaw(pass, salt, context);
        if (rawHashResult.Status is not Argon2Result.Ok)
            ++rawHashFailures;
        else
            Console.Write(format, runNum, "R (HEX)", rawHashResult.Status, rawHashResult.RawHash.ToHexString());


        var encodedHashResult = Argon2Core.HashEncoded(pass, salt, context);
        if (encodedHashResult.Status is not Argon2Result.Ok)
            ++encodedHashFailures;
        else
            Console.WriteLine(format, runNum, "E (B64)", encodedHashResult.Status, encodedHashResult.EncodedHash);
    }

    Console.WriteLine($"Total Raw Hash Failures: {rawHashFailures}\nTotal Encoded Hash Failures: {encodedHashFailures}");
}