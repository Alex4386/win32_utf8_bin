# Makefile for launcher

ARCH ?= x64
PROPAGATOR_DLL ?= ../dll_propagator/dll_propagator.dll

ifeq ($(ARCH),x64)
	OBJCOPY = x86_64-w64-mingw32-objcopy
	OBJCOPY_ARCH = pe-x86-64
	CC = x86_64-w64-mingw32-gcc
	CC_ARCH = i386:x86-64
else
	OBJCOPY = i686-w64-mingw32-objcopy
	OBJCOPY_ARCH = pe-i386
	CC = i686-w64-mingw32-gcc
	CC_ARCH = i386
endif

TARGET = win32_utf8_launcher_$(ARCH).exe
SRC = src/*.c ../common/shared.c

# Object file to be embedded in launcher
OBJ_PROP = propagator_dll_$(ARCH).o

all: $(TARGET)

$(TARGET): $(SRC) $(OBJ_PROP)
	$(CC) -o $@ $(OBJ_PROP) $(SRC) -lcomdlg32

$(OBJ_PROP): $(PROPAGATOR_DLL)
	cp $< $(notdir $<)
	$(OBJCOPY) -I binary -O $(OBJCOPY_ARCH) -B $(CC_ARCH) --rename-section .data=.rdata,CONTENTS,ALLOC,LOAD,READONLY,DATA $(notdir $<) $@
	rm $(notdir $<)

clean:
	rm -f $(TARGET) $(OBJ_PROP)

.PHONY: all clean
