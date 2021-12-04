#!/usr/bin/env bash

# Adapted from phxql / argon2-jvm - https://github.com/phxql/argon2-jvm/blob/master/libargon2/context/build-libargon2.sh

set -euo pipefail

# Create output folders
mkdir -p /output/{linux-arm,linux-arm64,linux-x86,linux-x64}

ARGON2_ABI_VERSION="1"
ARGON2_COMPILED_BINARY_PREFIX="libargon2.so"

ARGON2_COMPILED_BINARY="$ARGON2_COMPILED_BINARY_PREFIX.$ARGON2_ABI_VERSION"
ARGON2_OUTPUT_BINARY=$ARGON2_COMPILED_BINARY_PREFIX

ARGON2_REPO_NAME="phc-winner-argon2"
# Latest repo commit or last commit of latest release
ARGON2_COMMIT_ID="f57e61e19229e23c"

# Clone Argon2 source
cd /tmp
git clone https://github.com/P-H-C/$ARGON2_REPO_NAME.git
cd $ARGON2_REPO_NAME
git checkout $ARGON2_COMMIT_ID

# Used for `OPTTARGET` as 'generic' for -march is not a valid option
NONE_ARCH_TARGET=""

# Compile for x86
make clean && CFLAGS=-m32 OPTTARGET=$NONE_ARCH_TARGET make
cp $ARGON2_COMPILED_BINARY /output/linux-x86/$ARGON2_OUTPUT_BINARY

# Compile for x64
make clean && CFLAGS=-m64 OPTTARGET=$NONE_ARCH_TARGET make
cp $ARGON2_COMPILED_BINARY /output/linux-x64/$ARGON2_OUTPUT_BINARY

# Compile for ARM
make clean && CC=arm-linux-gnueabihf-gcc make
cp $ARGON2_COMPILED_BINARY /output/linux-arm/$ARGON2_OUTPUT_BINARY

# Compile for ARM-64
make clean && CC=aarch64-linux-gnu-gcc make
cp $ARGON2_COMPILED_BINARY /output/linux-arm64/$ARGON2_OUTPUT_BINARY
