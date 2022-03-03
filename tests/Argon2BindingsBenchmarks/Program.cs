using Argon2Bindings;
using Argon2Bindings.Enums;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
#if WINDOWS
using BenchmarkDotNet.Diagnostics.Windows.Configs;
#endif

namespace Argon2BindingsBenchmarks;

public static class Program
{
    [ShortRunJob]
#if WINDOWS
    [NativeMemoryProfiler]
#endif
    [MemoryDiagnoser]
    public class Argon2BindingsBenchmark
    {
        private const string Salt = "testing123";
        private const string Password = "test";

        private const string VerifyPasswordHash = "$argon2i$v=19$m=2048,t=3,p=1$dGVzdGluZzQ1Ng" +
                                                  "$VaMcEYLV/tlKirCtI1MOF5UfaD6BCQvbTNggdHDVLNo";

        private static readonly Argon2Context Context = new()
        {
            Type = Argon2Type.Argon2Id,
            MemoryCost = 1 << 16,
            DegreeOfParallelism = 2,
        };

        [Benchmark]
        public void HashRaw()
        {
            Argon2Core.Hash(Password, Salt, Context, false);
        }

        [Benchmark]
        public void HashEncoded()
        {
            Argon2Core.Hash(Password, Salt, Context);
        }

        [Benchmark]
        public void ContextHash()
        {
            Argon2Core.ContextHash(Password, Salt, Context);
        }

        [Benchmark]
        public void Verify()
        {
            Argon2Core.Verify(Password, VerifyPasswordHash);
        }
    }

    public static void Main(string[] args)
    {
        BenchmarkRunner.Run<Argon2BindingsBenchmark>();
    }
}