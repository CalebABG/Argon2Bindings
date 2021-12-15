using System.Diagnostics;
using Argon2Bindings;
using Argon2Bindings.Enums;

namespace Argon2BindingsConsole;

public static class Program
{
    private const string Salt = "testing123";
    private const string Password = "test";

    private static readonly Argon2Context Context = new() { };

    public static void Main(string[] args)
    {
        PrintContextHash();
        // PrintHashAndVerify();
        // PrintTabularHashResults();
    }

    private static void PrintContextHash()
    {
        var result = Argon2Core.ContextHash(Password, Salt, Context);
        Console.WriteLine(result);
    }

    private static void PrintHashAndVerify()
    {
        var stopwatch = Stopwatch.StartNew();
        var hash = Argon2Core.Hash(Password, Salt, Context);

        stopwatch.Stop();
        Console.WriteLine($"\nHash Time: {stopwatch.ElapsedMilliseconds}ms");
        Console.WriteLine(hash);

        stopwatch.Restart();
        var verify = Argon2Core.Verify(Password, hash.EncodedHash, Context.Type);

        stopwatch.Stop();
        Console.WriteLine($"\nVerify Time: {stopwatch.ElapsedMilliseconds}ms");
        Console.WriteLine(verify);
    }

    private static void PrintTabularHashResults()
    {
        int rawHashFailures = 0,
            encodedHashFailures = 0;

        const string format = "{0}\t\t{1}\t\t{2}\t\t{3}\n";

        Console.WriteLine("Legend:\nR = Raw Hash\nE = Encoded Hash\n");
        Console.WriteLine("Run #\t\tType\t\tResult\t\tOutput\n");

        for (var i = 0; i < 5; ++i)
        {
            var runNum = $"{i + 1}";

            var rawHashResult = Argon2Core.Hash(Password, Salt, Context, false);
            if (rawHashResult.Status is not Argon2Result.Ok)
                ++rawHashFailures;
            else
                Console.Write(format, runNum, "R (HEX)", rawHashResult.Status, rawHashResult.RawHash.ToHexString());

            var encodedHashResult = Argon2Core.Hash(Password, Salt, Context);
            if (encodedHashResult.Status is not Argon2Result.Ok)
                ++encodedHashFailures;
            else
                Console.WriteLine(format, runNum, "E (B64)", encodedHashResult.Status, encodedHashResult.EncodedHash);
        }

        Console.WriteLine($"Total Raw Hash Failures: {rawHashFailures}\n" +
                          $"Total Encoded Hash Failures: {encodedHashFailures}");
    }
}