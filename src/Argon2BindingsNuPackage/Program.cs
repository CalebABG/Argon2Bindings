namespace Argon2BindingsNuPackage;

// Steps:
// 1. Package the Argon2Bindings Library
// 2. Validate that the nuget package is in the `nupackages` folder
// 3. Do a `dotnet restore Argon2Bindings.sln` to pickup the local bindings package
// 4. Install the `Argon2Bindings` nuget package
//    - Nuget: (check `Prerelease` box)
//    - CLI:
//       - From Solution folder:  dotnet add src/Argon2BindingsNuPackage package Argon2Bindings --prerelease
//       - From Project folder:   dotnet add package Argon2Bindings --prerelease
// 5. Uncomment the code below, build and run
public static class Program
{
    public static void Main(string[] args)
    {
        // var result = Argon2Bindings.Argon2Core.Hash("test");
        // Console.WriteLine(result);
    }
}