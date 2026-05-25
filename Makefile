ARCH ?= x64

ifeq ($(ARCH),x64)
	OBJCOPY = x86_64-w64-mingw32-objcopy
	OBJCOPY_ARCH = pe-x86-64
	CC_ARCH = i386:x86-64
else
	OBJCOPY = i686-w64-mingw32-objcopy
	OBJCOPY_ARCH = pe-i386
	CC_ARCH = i386
endif

# Define DLL names
WIN32_UTF8_DLL = ./win32_utf8.$(ARCH).dll
PROPAGATOR_DLL = dll_propagator/dll_propagator.$(ARCH).dll
LAUNCHER_EXE = launcher/win32_utf8_launcher_$(ARCH).exe
ARTIFACT_DIR = artifacts/win32_utf8_runner_$(ARCH)
ARTIFACT_TESTS = \
	tests/injection_driver_$(ARCH).exe \
	tests/payload_marker_$(ARCH).dll \
	tests/probe_$(ARCH).exe \
	tests/process_parent_$(ARCH).exe \
	tests/win32_utf8_ansi_$(ARCH).exe \
	tests/shell_link_ansi_$(ARCH).exe

TARGET = $(notdir $(LAUNCHER_EXE))

all: $(TARGET)

all-arch:
	$(MAKE) ARCH=x86
	$(MAKE) ARCH=x64

tests:
	$(MAKE) -C tests ARCH=$(ARCH)

test-injection: $(PROPAGATOR_DLL) tests
	$(MAKE) -C tests ARCH=$(ARCH) run-injection

artifact: $(TARGET) $(PROPAGATOR_DLL) $(WIN32_UTF8_DLL) tests
	rm -rf $(ARTIFACT_DIR)
	mkdir -p $(ARTIFACT_DIR)/tests
	cp $(TARGET) $(ARTIFACT_DIR)/
	cp $(WIN32_UTF8_DLL) $(ARTIFACT_DIR)/
	cp $(PROPAGATOR_DLL) $(ARTIFACT_DIR)/
	cp $(ARTIFACT_TESTS) $(ARTIFACT_DIR)/tests/
	sh resources/runner/write-smoke-tests.sh $(ARCH) $(ARTIFACT_DIR)/run-smoke-tests.cmd

$(TARGET): $(LAUNCHER_EXE)
	cp $< $@

$(LAUNCHER_EXE): $(PROPAGATOR_DLL) $(WIN32_UTF8_DLL)
	$(MAKE) -C launcher ARCH=$(ARCH) PROPAGATOR_DLL=$(abspath $(PROPAGATOR_DLL)) PAYLOAD_DLL=$(abspath $(WIN32_UTF8_DLL))

$(PROPAGATOR_DLL):
	$(MAKE) -C dll_propagator ARCH=$(ARCH)

$(WIN32_UTF8_DLL):
	./build-dll.sh $(ARCH)

clean:
	rm -f win32_utf8_launcher_*.exe
	rm -rf artifacts
	rm -f launcher/win32_utf8_launcher_*.exe
	rm -f ./win32_utf8.*.dll ./win32_utf8.*.o win32_utf8/win32_utf8.dll
	$(MAKE) -C dll_propagator clean
	$(MAKE) -C launcher clean
	$(MAKE) -C tests clean

.PHONY: all all-arch tests test-injection artifact clean
