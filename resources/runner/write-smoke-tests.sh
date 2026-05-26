#!/bin/sh

set -e

arch=$1
out=$2

if [ -z "$arch" ] || [ -z "$out" ]; then
    echo "usage: write-smoke-tests.sh <x86|x64> <output.cmd>" >&2
    exit 2
fi

tmp="${out}.tmp"

cat > "$tmp" <<EOF
@echo off
setlocal
cd /d "%~dp0"
set ARCH=$arch
set PROP=dll_propagator.$arch.dll
set PAYLOAD=tests\payload_marker_$arch.dll
set PROBE=tests\probe_$arch.exe
set PARENT=tests\process_parent_$arch.exe
set LAUNCHER=win32_utf8_launcher_$arch.exe

tests\injection_driver_$arch.exe %PROP% %PAYLOAD% %PROBE% direct payload_marker_$arch.dll || exit /b 1
tests\injection_driver_$arch.exe %PROP% %PAYLOAD% %PARENT% w %PROBE% payload_marker_$arch.dll || exit /b 1
tests\injection_driver_$arch.exe %PROP% %PAYLOAD% %PARENT% nested %PROBE% payload_marker_$arch.dll || exit /b 1
%LAUNCHER% --codepage=shift-jis -- tests\shell_link_ansi_$arch.exe || exit /b 1
%LAUNCHER% --codepage=shift-jis -- tests\mixed_encoding_path_$arch.exe || exit /b 1

echo smoke tests passed for $arch
EOF

awk '{ printf "%s\r\n", $0 }' "$tmp" > "$out"
rm -f "$tmp"
