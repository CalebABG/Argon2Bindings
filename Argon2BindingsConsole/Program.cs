using Argon2Bindings;

const string salt = "testing123";
const string pass = "test";

var context = new Argon2Context();

var outBytes = Argon2Core.HashRaw(pass, salt, context);
var outString = outBytes.ToHexString();
Console.WriteLine(outString);

var outEncodedString = Argon2Core.HashEncoded(pass, salt, context);
Console.WriteLine(outEncodedString);