# win32_utf8_bin
A GitHub Actions built-version of [`win32_utf8`](https://github.com/Alex4386/win32_utf8_ext) in Dynamic Release.
[![Build](https://github.com/Alex4386/win32_utf8_bin/actions/workflows/build.yml/badge.svg)](https://github.com/Alex4386/win32_utf8_bin/actions/workflows/build.yml)

> [!NOTE]
> Due to GitHub Actions restrictions, We are using Visual Studio 2019 as target.  
> as thus, Windows XP support is inevitably dropped due to VS2019's lack of support for WinXP.  
> 
> If you need to use prebuilt dlls for win32_utf8, You need to use MinGW builds.  

## What is `win32_utf8`?
See [`win32_utf8` README](https://github.com/Alex4386/win32_utf8_ext).

The source is tracked as the `win32_utf8` git submodule. Initialize
submodules before building from a fresh checkout:

```sh
git submodule update --init --recursive
```

## Standalone launcher
The standalone launcher embeds a generic propagator DLL and the `win32_utf8`
payload DLL. With no arguments it opens a file dialog. CLI mode requires a `--`
separator:

```sh
win32_utf8_launcher.exe [--codepage=<name-or-number>] -- target.exe arg0 arg1
```

Known codepage aliases include `acp`, `oem`, `utf-8`, `shift-jis`, `korean`,
`cp932`, and `cp949`. Numeric Windows codepages are also accepted.

At runtime the launcher writes both DLLs once, starts the target program
suspended, loads the propagator into it, passes a `PROPAGATOR_CONFIG` to the
exported `PropagatorInitialize` entrypoint, and then resumes the process.

The propagator is payload-agnostic. It loads the DLL paths listed in the config
and hooks common Win32 `CreateProcess*` APIs so child processes receive the same
config and payloads. Direct native syscalls, direct `ShellExecuteEx` detouring,
protected processes, cross-bitness injection, and elevated or brokered launches
that hide the child process handle are best-effort or unsupported.

Payload-specific behavior stays in payloads. The propagator only loads payload
DLLs, calls an optional configured initializer, and passes the same opaque
payload init data to child processes.

## License
Following upstream, [UNLICENSE](UNLICENSE)
