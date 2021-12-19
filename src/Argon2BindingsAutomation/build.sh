#!/usr/bin/env bash

# Adapted from phxql / argon2-jvm - https://github.com/phxql/argon2-jvm/blob/master/libargon2/context/build-libargon2.sh

set -euo pipefail

# Create platform folders
mkdir -p /output/{linux-arm,linux-arm64,linux-x86,linux-x64}

ARGON2_ABI_VERSION="1"
ARGON2_COMPILED_BINARY_PREFIX="libargon2.so"

ARGON2_COMPILED_BINARY="$ARGON2_COMPILED_BINARY_PREFIX.$ARGON2_ABI_VERSION"
ARGON2_OUTPUT_BINARY=$ARGON2_COMPILED_BINARY_PREFIX

# Repo name & latest repo commit or last commit of latest release
ARGON2_REPO_NAME="phc-winner-argon2"
ARGON2_COMMIT_ID="f57e61e19229e23c"

# Clone Argon2 source & checkout given commit
echo "Cloning Argon2 source & checking out commit: $ARGON2_COMMIT_ID"
cd /tmp
git clone https://github.com/P-H-C/$ARGON2_REPO_NAME.git
cd $ARGON2_REPO_NAME
git checkout $ARGON2_COMMIT_ID

# Used for `OPTTARGET`
ARCH_TARGET="generic"

printf "\nCompiling for: x86\n"
make clean && CFLAGS=-m32 OPTTARGET=$ARCH_TARGET make
cp $ARGON2_COMPILED_BINARY /output/linux-x86/$ARGON2_OUTPUT_BINARY

printf "\nCompiling for: x64\n"
make clean && CFLAGS=-m64 OPTTARGET=$ARCH_TARGET make
cp $ARGON2_COMPILED_BINARY /output/linux-x64/$ARGON2_OUTPUT_BINARY

printf "\nCompiling for: arm\n"
make clean && CC=arm-linux-gnueabihf-gcc make
cp $ARGON2_COMPILED_BINARY /output/linux-arm/$ARGON2_OUTPUT_BINARY

printf "\nCompiling for: arm64 (aarch64)\n"
make clean && CC=aarch64-linux-gnu-gcc make
cp $ARGON2_COMPILED_BINARY /output/linux-arm64/$ARGON2_OUTPUT_BINARY
