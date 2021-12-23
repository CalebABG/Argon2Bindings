#!/usr/bin/env bash

set -euo pipefail

printf "\nCleaning Solution\n"
dotnet clean Argon2Bindings.sln

printf "\nBuilding Solution\n"
dotnet build Argon2Bindings.sln