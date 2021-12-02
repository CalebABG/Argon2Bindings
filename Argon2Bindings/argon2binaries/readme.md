# This folder contains subfolders which have the name of each platform, and contain the compiled argon2 binary for the platform (platforms this project currently supports, more may be added in future, if newer platforms arise).

## When compiling the argon2 source for your platform, make sure to copy the binary to the corresponding subfolder in this directory.

## Binaries are compiled from [argon2 source code](https://github.com/P-H-C/phc-winner-argon2) - branch: `master` - commit: `f57e61e19229e23c`

## Note:
When copying the binary on Mac / Linux, copy the binary without the ABI version:

- Mac:  `libargon2.<ABI-VERSION>.dylib` -> `libargon2.dylib`
- Linux `libargon2.so.<ABI-VERSION>`    -> `libargon2.so`