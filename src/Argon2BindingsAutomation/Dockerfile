# Adapted from phxql / argon2-jvm - https://github.com/phxql/argon2-jvm/blob/master/libargon2/Dockerfile

# Note: Run these commands in the current folder
# Build:     docker build -t argon2bindings-automation-linux .
# Run:       docker run --rm -v ${PWD}/output:/output argon2bindings-automation-linux
# Remove:    docker image rm argon2bindings-automation-linux

FROM ubuntu:20.04

WORKDIR /
ADD build.sh .
RUN chmod +x build.sh 

RUN apt update \
    && apt install -y wget git make binutils gcc gcc-multilib \
    && apt install -y gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu \
    && apt clean

CMD ./build.sh