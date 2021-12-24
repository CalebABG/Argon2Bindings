using Argon2Bindings;

var result = Argon2Core.Hash("test");
Console.WriteLine(result);