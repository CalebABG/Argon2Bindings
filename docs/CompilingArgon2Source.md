# Compiling Argon2 Source

## When compiling the Argon2 source for your platform, make sure to copy the binary to the corresponding subfolder in this directory.

## Binaries are compiled from [argon2 source code](https://github.com/P-H-C/phc-winner-argon2) - branch: `master` - commit: `f57e61e19229e23c`

## Copying output binaries:

Once you've successfully compiled a binary for your platform, locate the corresponding platform + cpu architecture
folder in [argon2binaries](../src/Argon2Bindings/argon2binaries) and copy your compiled binary to corresponding folder.

**Ex.** If you are compiling for Windows x64, then the corresponding folder would be:

- `src\Argon2Bindings\argon2binaries\win-x64\`

When copying the binary on Windows, change the compiled binary name:

- `Argon2OptDll.dll` or `Argon2RefDll.dll` &#8594; `libargon2.dll`

When copying the binary on Mac / Linux, copy the binary without the ABI version:

- Mac:  `libargon2.<ABI-VERSION>.dylib` &#8594; `libargon2.dylib`
- Linux `libargon2.so.<ABI-VERSION>`    &#8594; `libargon2.so`

## Setup

1. Clone the source code: `git clone https://github.com/P-H-C/phc-winner-argon2.git`
2. Open a terminal and change directory to source code: `cd phc-winner-argon2.git`

## Mac

You can compile using: `make clean && make`

## Linux

Make sure you have the needed tools to build C/C++:

- `sudo apt update && sudo apt install build-essential`

Then you can compile with this command:

- `make clean && make`

## Windows

You can compile using `Git Bash` or `Visual Studio 2019 or 2022`. Using `Visual Studio` may be simpler and more
convenient.

### Visual Studio

Open the argon2 solution file with Visual Studio. You may need to modify your Visual Studio installation to enable the
building of C/C++ source code, so if you get errors when attempting to build the first time, modify your installation
and add the needed components.

With the needed components installed, the next issue you may run into is a targeting issue. The solution has the target
Windows SDK set to `8.1` (at the time of this doc), and depending on your Visual Studio installation, your installed
target platform may / will probably be higher.

**Fix**:

1. Right click on the `Argon2` solution in the `Solution Explorer`
2. Look for a menu option called: `Retarget solution` and click it
3. Select an SDK target you'd like to target and make sure each project checkbox is checked, then click `OK`

Then set your Solution Configuration to be `ReleaseStatic` and change your Solution Platform to match the architecture
of your CPU (32bit = `x86`, 64bit = `x64`)

After that, in the top menu bar, look for a menu option called: `Build`, and click `Build Solution`

Now, in the root of the cloned argon2 source folder, look for a folder called: `vs2015`. Then change to this
path: `vs2015\build\`

**Finally** look for two `.dll` files

1. `Argon2OptDll.dll`
2. `Argon2RefDll.dll`

You can use either one, the `Opt` dll is a optimized version that uses Advanced Vector Extensions (AVX). While `Ref` is
a portable version - insight
from: [Differences between windows build files](https://github.com/P-H-C/phc-winner-argon2/issues/258).

### Git Bash

TODO: Add more documentation for Git Bash

Compile: `make CC=gcc`