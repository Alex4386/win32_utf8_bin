# Makefile for win32_utf8

# Cross-compiler prefix
CROSS_PREFIX_x64 ?= x86_64-w64-mingw32-
CROSS_PREFIX_x86 ?= i686-w64-mingw32-

# Default architecture
ARCH ?= x64

# Set the cross-compiler based on the architecture
CROSS_PREFIX = $(CROSS_PREFIX_$(ARCH))

CC = $(CROSS_PREFIX)gcc
DLL_NAME = win32_utf8.dll

SRC = win32_utf8_build_dynamic.c
INCLUDE = -I../launcher/src
DEFINES = -DUNICODE -D_UNICODE
LDFLAGS = -shared -mwindows
LIBS = -ldsound -lpsapi -lole32 -lshlwapi -lversion -lwininet

all: $(DLL_NAME)

$(DLL_NAME): $(SRC)
	$(CC) $(LDFLAGS) -o $@ $< $(INCLUDE) $(DEFINES) $(LIBS)

clean:
	rm -f $(DLL_NAME)

.PHONY: all clean