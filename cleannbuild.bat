@echo off

echo "Cleaning Solution"
dotnet clean Argon2Bindings.sln

echo "Building Solution"
dotnet build Argon2Bindings.sln

echo "Clean and Build Finished!"