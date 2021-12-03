# Building and Running the Project

## Change Binary CPU Architecture

At the time of writing this, this project does not yet have a mechanism to dynamically load the needed argon2 binaries
for each platform and cpu architecture.

Due to this, depending on your cpu architecture, you may need to make one small change.

By default the cpu architecture for each platform when loading the argon2 binaries is set to `x64`. Which means that
only 64bit cpus are taken into consideration by default.

If your cpu architecture is different, modify the `DllName` string constant for your platform
in [Argon2Library](../src/Argon2Bindings/Argon2Library.cs). The current format of the DllName constant
is: `<binaries_folder>\<platform_name-cpu_architecture>\libargon2.<extension>`

**Ex.** If your platform is Windows `x86` (32bit), then your change would look like this:

- `win-x86`
    - `win` being the `platform_name` and `x86` being the `cpu_architecture`

## Building

Even though the bindings project targets `netstandard2.0` currently, the other projects take full advantage of dotnet 6,
so the minimum SDK version needed to build and run the project is `dotnet 6 SDK`. If you don't have the SDK installed
you can get it here: [download dotnet sdk](https://dotnet.microsoft.com/download)

With that taken care of, all you need to do to build the projects source is to open a command prompt or terminal window
and change into the root directory of this repo.

Then to build, enter and execute this command:

- `dotnet build Argon2Bindings.sln`

If everything has gone well and no errors, you have just built the solution 🎉

## Running

To run any of the executable projects, open a command prompt or terminal window and change into the root directory of
this repo.

Then to run the console test application, enter and execute this command:

- `dotnet run --project src\Argon2BindingsConsole\Argon2BindingsConsole.csproj`

To run the unit tests, enter and execute this command:

- `dotnet run --project tests\Argon2BindingsTests\Argon2BindingsTests.csproj`
