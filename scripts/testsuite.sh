#!/usr/bin/env bash

set -euo pipefail

printf "\nRunning Test Suite\n"
dotnet test --logger "console;verbosity=detailed"