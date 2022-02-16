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
        PrintHash();
        // PrintContextHash();
        // PrintTabularHashResults();
    }

    private static void PrintContextHash()
    {
        var stopwatch = Stopwatch.StartNew();

        var result = Argon2Core.ContextHash(Password, Salt, Context);
        stopwatch.Stop();

        PrintTime(stopwatch);
        Console.WriteLine(result);
    }

    private static void PrintHash()
    {
        var stopwatch = Stopwatch.StartNew();
        var hash = Argon2Core.Hash(Password, Salt, Context);

        stopwatch.Stop();
        PrintTime(stopwatch);
        Console.WriteLine(hash);
    }

    private static void PrintTabularHashResults()
    {
        var hashStopWatch = new Stopwatch();

        long totalTime = 0;

        int rawHashFailures = 0,
            encodedHashFailures = 0;

        const string format = "{0}\t\t{1}\t\t{2}\t\t{3}";

        Console.WriteLine("\nLegend:\nR = Raw Hash\nE = Encoded Hash\n");
        Console.WriteLine("Run #\t\tType\t\tResult\t\tOutput\n");

        for (var i = 0; i < 5; ++i)
        {
            var runNum = $"{i + 1}";

            hashStopWatch.Start();
            var rawHashResult = Argon2Core.Hash(Password, Salt, Context, false);
            hashStopWatch.Stop();

            var rawHashTime = hashStopWatch.ElapsedMilliseconds;
            totalTime += rawHashTime;

            if (rawHashResult.Status is not Argon2Result.Ok) ++rawHashFailures;
            else Console.WriteLine(format, runNum, "R (HEX)", rawHashResult.Status, rawHashResult.RawHash.ToHexString());

            hashStopWatch.Restart();
            var encodedHashResult = Argon2Core.Hash(Password, Salt, Context);
            hashStopWatch.Stop();

            var encodedHashTime = hashStopWatch.ElapsedMilliseconds;
            totalTime += encodedHashTime;

            if (encodedHashResult.Status is not Argon2Result.Ok) ++encodedHashFailures;
            else Console.WriteLine(format, runNum, "E (B64)", encodedHashResult.Status, encodedHashResult.EncodedHash);

            Console.WriteLine($"\t\t\t\t\t\tR Hash Time:\t{rawHashTime / 1000.0}s");
            Console.WriteLine($"\t\t\t\t\t\tE Hash Time:\t{encodedHashTime / 1000.0}s\n");
        }

        Console.WriteLine($"Total Time:\t{totalTime / 1000.0}s\n" +
                          $"Total Raw Hash Failures:\t{rawHashFailures}\n" +
                          $"Total Encoded Hash Failures:\t{encodedHashFailures}");
    }

    private static void PrintTime(Stopwatch stopwatch, string text = "Took:")
    {
        Console.WriteLine($"\n{text} {stopwatch.ElapsedMilliseconds / 1000.0}s");
    }
}