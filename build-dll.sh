#!/bin/bash

set -e

ARCH=${1:-x64}

if [ ! -d "win32_utf8" ]; then
    git clone https://github.com/thpatch/win32_utf8.git
fi

cd win32_utf8

if [ ! -f "../resources/win32_utf8/Makefile" ]; then
  curl -O https://raw.githubusercontent.com/Alex4386/win32_utf8_bin/main/resources/win32_utf8/Makefile
  make ARCH=$ARCH
else
  make -f ../resources/win32_utf8/Makefile ARCH=$ARCH
fi

cp ./win32_utf8.dll ../win32_utf8.$ARCH.dll
echo "Build complete. The DLL is at win32_utf8.$ARCH.dll"
