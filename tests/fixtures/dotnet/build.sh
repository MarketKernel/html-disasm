#!/bin/sh
# Builds what the CIL tests open: hello.cs (the same program as hello.c, in C#) and more.cs
# (every kind of operand, and the names and constants ildasm writes in its own ways) as one
# assembly, hello.dll, with the .NET SDK (10 or newer), deterministic and without a PDB; and
# hello.il, Microsoft's ildasm's text of it, which tests/cil.mjs compares the decoder with.
# ildasm comes from NuGet (runtime.osx-arm64.Microsoft.NETCore.ILDAsm, unzipped into
# private/ildasm), or set ILDASM.
set -e
cd "$(dirname "$0")"
dotnet build -c Release -o out --nologo -v quiet
cp out/hello.dll hello.dll
rm -rf out obj bin
node ../../../tools/verify-cil.mjs hello.dll --reference hello.il
