#!/usr/bin/env bash

set -euo pipefail

printf "\nCreating Nuget Package\n"
dotnet pack src/Argon2Bindings/Argon2Bindings.csproj --output nupackages