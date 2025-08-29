# Makefile for dll_propagator

# Default architecture
ARCH ?= x64

ifeq ($(ARCH),x64)
	CC = x86_64-w64-mingw32-gcc
	OBJCOPY = x86_64-w64-mingw32-objcopy
	OBJCOPY_ARCH = pe-x86-64
	CC_ARCH = i386:x86-64
else
	CC = i686-w64-mingw32-gcc
	OBJCOPY = i686-w64-mingw32-objcopy
	OBJCOPY_ARCH = pe-i386
	CC_ARCH = i386
endif

DLL_NAME = dll_propagator.$(ARCH).dll

# Source file
SRC = src/dll_propagator.c ../common/shared.c

DLL_TO_EMBED ?= child.dll
EMBEDDED_OBJ = $(basename $(DLL_TO_EMBED)).o

# Compiler and linker flags
LDFLAGS = -shared

all: $(DLL_NAME)

$(DLL_NAME): $(SRC) $(EMBEDDED_OBJ)
	$(CC) $(LDFLAGS) -o $@ $(SRC) $(EMBEDDED_OBJ) -lshlwapi -DPROPAGATED_DLL_NAME="\"$(notdir $(DLL_TO_EMBED))\""
	rm -f child.dll

$(EMBEDDED_OBJ):
	rm -f child.dll
	cp -f $(DLL_TO_EMBED) child.dll
	$(OBJCOPY) -I binary -O $(OBJCOPY_ARCH) -B $(CC_ARCH) --rename-section .data=.rdata,CONTENTS,ALLOC,LOAD,READONLY,DATA child.dll $(EMBEDDED_OBJ)

clean:
	rm -f child.dll dll_propagator.*.dll

.PHONY: all clean
