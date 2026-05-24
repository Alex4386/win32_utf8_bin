#!/bin/bash

set -e

ARCH=${1:-x64}
BUILD_LAUNCHER=0
SOURCE_DIR=win32_utf8

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
        git submodule update --init --recursive "$SOURCE_DIR" || true
    fi

    if [ ! -f "$SOURCE_DIR/win32_utf8_build_dynamic.c" ]; then
        echo "error: $SOURCE_DIR/win32_utf8_build_dynamic.c not found" >&2
        echo "hint: initialize the win32_utf8 submodule or set up $SOURCE_DIR before building" >&2
        exit 1
    fi
}

build_arch() {
    local arch=$1

    ensure_source

    (
        cd "$SOURCE_DIR"
        rm -f win32_utf8.dll
        make -f ../resources/win32_utf8/Makefile ARCH="$arch"
        cp ./win32_utf8.dll "../win32_utf8.$arch.dll"
    )
    echo "Build complete. The DLL is at win32_utf8.$arch.dll"

    if [ "$BUILD_LAUNCHER" -eq 1 ]; then
        make ARCH="$arch"
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
