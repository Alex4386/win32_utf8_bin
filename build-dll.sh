#!/bin/bash

set -e

ARCH=${1:-x64}
BUILD_LAUNCHER=0
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
SOURCE_DIR="$SCRIPT_DIR/win32_utf8"
CROSS_PREFIX_x64=${CROSS_PREFIX_x64:-x86_64-w64-mingw32-}
CROSS_PREFIX_x86=${CROSS_PREFIX_x86:-i686-w64-mingw32-}

usage() {
    echo "usage: $0 [x86|x64|all] [--launcher]" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        x86|x64|all)
            ARCH=$1
            ;;
        --launcher)
            BUILD_LAUNCHER=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 2
            ;;
    esac
    shift
done

ensure_source() {
    if [ ! -f "$SOURCE_DIR/win32_utf8_build_dynamic.c" ]; then
        git -C "$SCRIPT_DIR" submodule update --init --recursive win32_utf8 || true
    fi

    if [ ! -f "$SOURCE_DIR/win32_utf8_build_dynamic.c" ]; then
        echo "error: win32_utf8/win32_utf8_build_dynamic.c not found" >&2
        echo "hint: initialize the win32_utf8 submodule or set up $SOURCE_DIR before building" >&2
        exit 1
    fi
}

compiler_for_arch() {
    case "$1" in
        x64) echo "${CROSS_PREFIX_x64}gcc" ;;
        x86) echo "${CROSS_PREFIX_x86}gcc" ;;
        *)
            usage
            exit 2
            ;;
    esac
}

build_arch() {
    local arch=$1

    ensure_source

    (
        local cc
        cc=$(compiler_for_arch "$arch")

        cd "$SOURCE_DIR"
        rm -f win32_utf8.dll
        "$cc" -shared -mwindows -o win32_utf8.dll win32_utf8_build_dynamic.c \
            -I"$SCRIPT_DIR/launcher/src" \
            -DUNICODE -D_UNICODE \
            -ldsound -lpsapi -lole32 -lshlwapi -lversion -lwininet
        cp ./win32_utf8.dll "$SCRIPT_DIR/win32_utf8.$arch.dll"
    )
    echo "Build complete. The DLL is at win32_utf8.$arch.dll"

    if [ "$BUILD_LAUNCHER" -eq 1 ]; then
        make -C "$SCRIPT_DIR" ARCH="$arch"
        echo "Build complete. The launcher is at win32_utf8_launcher_$arch.exe"
    fi
}

case "$ARCH" in
    x86|x64)
        build_arch "$ARCH"
        ;;
    all)
        build_arch x86
        build_arch x64
        ;;
    *)
        usage
        exit 2
        ;;
esac
