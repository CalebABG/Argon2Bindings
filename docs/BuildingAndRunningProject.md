# Building and Running the Project

## Building and Cleaning

Even though the bindings project targets `netstandard2.1` currently, the other projects take full advantage of dotnet 6,
so the minimum SDK version needed to build and run the project is `dotnet 6 SDK`. If you don't have the SDK installed
you can get it here: [Dotnet SDK Download](https://dotnet.microsoft.com/download)

With that taken care of, all you need to do to build the projects source is to open a command prompt or terminal window
and change into the root directory of this repo.

Then to build, enter and execute this command:

- `dotnet build Argon2Bindings.sln`

If everything has gone well and no errors, you have just built the solution 🎉

To clean the solution is just as easy:

- `dotnet clean Argon2Bindings.sln`

## Running

To run any of the executable projects, open a command prompt or terminal window and change into the root directory of
this repo.

Then to run the console test application, enter and execute this command:

- `dotnet run --project src\Argon2BindingsConsole\Argon2BindingsConsole.csproj`

To run the unit tests, enter and execute this command:

- `dotnet run --project tests\Argon2BindingsTests\Argon2BindingsTests.csproj`
