using Argon2Bindings;
using Argon2Bindings.Enums;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnostics.Windows.Configs;
using BenchmarkDotNet.Reports;
using BenchmarkDotNet.Running;

namespace Argon2BindingsBenchmarks;

public static class Program
{
    [ShortRunJob]
    [NativeMemoryProfiler]
    [MemoryDiagnoser]
    public class Argon2BindingsBenchmarker
    {
        private const string Salt = "testing123";
        private const string Password = "test";

        private static readonly Argon2Context Context = new()
        {
            Type = Argon2Type.Argon2Id,
            MemoryCost = 1 << 16,
            DegreeOfParallelism = 2,
        };

        [Benchmark]
        public void HashRaw()
        {
            var hash = Argon2Core.Hash(Password, Salt, Context, false);
            Console.WriteLine(hash.EncodedHash);
        }

        [Benchmark]
        public void HashEncoded()
        {
            var hash = Argon2Core.Hash(Password, Salt, Context);
            Console.WriteLine(hash.EncodedHash);
        }

        [Benchmark]
        public void ContextHash()
        {
            var hash = Argon2Core.ContextHash(Password, Salt, Context);
            Console.WriteLine(hash.EncodedHash);
        }

        [Benchmark]
        public void Verify()
        {
            var password = "test";
            var encodedHash = "$argon2i$v=19$m=2048,t=3,p=1$dGVzdGluZzQ1Ng$VaMcEYLV/tlKirCtI1MOF5UfaD6BCQvbTNggdHDVLNo";
            var result = Argon2Core.Verify(password, encodedHash);
            Console.WriteLine(result.Success);
        }
    }

    public static void Main(string[] args)
    {
        Summary? summary = BenchmarkRunner.Run<Argon2BindingsBenchmarker>();
    }
}