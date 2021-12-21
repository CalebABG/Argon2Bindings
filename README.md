# C# Argon2 Binding Library (EXPERIMENTAL)

## Research & Development

As the title suggests, this project is very much a `work in progress` (WIP). The project is an attempt to create a
wrapper library for the [Argon2 C library](https://github.com/P-H-C/phc-winner-argon2).

With that being said, this repo should **NOT** be used as a means for a viable C# Argon2 library at this time. Please
refer to the [Packaging / Usage](#packaging--usage) for more details on project usage.

Credit and appropriate licenses for original sources of the Argon2 C library shall be included within the repo, as well
as top level comments for files where needed / appropriate. The Argon2 C library source code license in this repo can be found
here [Argon2 License](licenses/PHC-WINNER-ARGON2_LICENSE.txt).

Binaries are compiled from [Argon2 source](https://github.com/P-H-C/phc-winner-argon2) - branch: `master` -
commit: `f57e61e19229e23c`

## Compiling Argon2 Source

Checkout this handy writeup for how to compile the Argon2 source code for your platform

- [How to compile Argon2 source](docs/CompilingArgon2Source.md)

### Resources

- [GCC online documentation](https://gcc.gnu.org/onlinedocs/)
- [GCC and Makefiles](https://youtu.be/OnEF1MexJlI)
- [Differences between windows build files](https://github.com/P-H-C/phc-winner-argon2/issues/258)
- [Understanding and Using Makefile Flags](https://earthly.dev/blog/make-flags/)
- [.NET Runtime Identififers](https://docs.microsoft.com/en-us/dotnet/core/rid-catalog)
- [.NET Platform Invoke (P/Invoke)](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke)
- [.NET Native interoperability best practices](https://docs.microsoft.com/en-us/dotnet/standard/native-interop/best-practices)
- [Mono Interop with Native Libraries](https://www.mono-project.com/docs/advanced/pinvoke/)
- [Cross compiling for arm or aarch64 on Debian or Ubuntu](https://jensd.be/1126/linux/cross-compiling-for-arm-or-aarch64-on-debian-or-ubuntu)

## Building / Running

Head over to this doc for how to build and run this projects solution

- [How to build and run this project](docs/BuildingAndRunningProject.md)

## Packaging / Usage

At this time, this project serves as a vessel for learning and experimenting in the world of C# to C Bindings, and
Platform Invocation (PInvoke) + Interoperability. As such, for now, there are no plans for releasing a publicly
available / usable Nuget package for the library.

Depending on the functionality and development of this project, this repo may be scrapped and rebuilt, where the new
project may have a Nuget package released.