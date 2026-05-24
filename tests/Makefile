ARCH ?= x64

ifeq ($(ARCH),x64)
	CC = x86_64-w64-mingw32-gcc
else
	CC = i686-w64-mingw32-gcc
endif

CFLAGS = -D_WIN32_WINNT=0x0501
TARGETS = probe_$(ARCH).exe process_parent_$(ARCH).exe payload_marker_$(ARCH).dll injection_driver_$(ARCH).exe win32_utf8_ansi_$(ARCH).exe shell_link_ansi_$(ARCH).exe

all: $(TARGETS)

probe_$(ARCH).exe: probe.c
	$(CC) $(CFLAGS) -o $@ $< -lshell32

process_parent_$(ARCH).exe: process_parent.c
	$(CC) $(CFLAGS) -o $@ $< -lshell32

win32_utf8_ansi_$(ARCH).exe: win32_utf8_ansi.c
	$(CC) $(CFLAGS) -municode -o $@ $<

shell_link_ansi_$(ARCH).exe: shell_link_ansi.c
	$(CC) $(CFLAGS) -o $@ $< -lole32 -luuid

payload_marker_$(ARCH).dll: payload_marker.c
	$(CC) $(CFLAGS) -shared -o $@ $<

injection_driver_$(ARCH).exe: injection_driver.c ../common/shared.c ../common/shared.h
	$(CC) $(CFLAGS) -o $@ injection_driver.c ../common/shared.c -lshell32

run-injection: all
	./injection_driver_$(ARCH).exe ../dll_propagator/dll_propagator.$(ARCH).dll ./payload_marker_$(ARCH).dll ./probe_$(ARCH).exe direct payload_marker_$(ARCH).dll
	./injection_driver_$(ARCH).exe ../dll_propagator/dll_propagator.$(ARCH).dll ./payload_marker_$(ARCH).dll ./process_parent_$(ARCH).exe w ./probe_$(ARCH).exe payload_marker_$(ARCH).dll
	./injection_driver_$(ARCH).exe ../dll_propagator/dll_propagator.$(ARCH).dll ./payload_marker_$(ARCH).dll ./process_parent_$(ARCH).exe nested ./probe_$(ARCH).exe payload_marker_$(ARCH).dll

clean:
	rm -f probe_*.exe process_parent_*.exe payload_marker_*.dll injection_driver_*.exe win32_utf8_ansi_*.exe shell_link_ansi_*.exe w32u8_*.tmp

.PHONY: all run-injection clean
