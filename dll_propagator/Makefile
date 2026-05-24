# Makefile for dll_propagator

# Default architecture
ARCH ?= x64

ifeq ($(ARCH),x64)
	CC = x86_64-w64-mingw32-gcc
else
	CC = i686-w64-mingw32-gcc
endif

DLL_NAME = dll_propagator.$(ARCH).dll

# Source file
SRC = src/dll_propagator.c src/detour.c ../common/shared.c

# Compiler and linker flags
CFLAGS = -D_WIN32_WINNT=0x0501
LDFLAGS = -shared

all: $(DLL_NAME)

$(DLL_NAME): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRC)

clean:
	rm -f child.dll dll_propagator.*.dll ../win32_utf8.*.o

.PHONY: all clean
