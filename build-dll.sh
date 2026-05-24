#!/bin/bash

set -e

ARCH=${1:-x64}
SOURCE_DIR=win32_utf8

if [ ! -f "$SOURCE_DIR/win32_utf8_build_dynamic.c" ]; then
    git submodule update --init --recursive "$SOURCE_DIR"
fi

cd "$SOURCE_DIR"

rm -f win32_utf8.dll

make -f ../resources/win32_utf8/Makefile ARCH=$ARCH

cp ./win32_utf8.dll ../win32_utf8.$ARCH.dll
echo "Build complete. The DLL is at win32_utf8.$ARCH.dll"
