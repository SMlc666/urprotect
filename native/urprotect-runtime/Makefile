SHELL := /bin/sh

CC ?= cc
BUILD_DIR ?= build
CFLAGS ?= -std=c11 -O2 -g0 -Wall -Wextra -Werror -Wshadow -Wconversion
CPPFLAGS := -Iinclude -I../urprotect-launcher -I../../third_party/miniz
MINIZ_CPPFLAGS := -DMINIZ_NO_STDIO -DMINIZ_NO_TIME -DMINIZ_NO_DEFLATE_APIS \
                  -DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_ZLIB_APIS \
                  -DMINIZ_NO_ZLIB_COMPATIBLE_NAMES -DMINIZ_NO_MALLOC \
                  -DMINIZ_LITTLE_ENDIAN=1 -DMINIZ_HAS_64BIT_REGISTERS=1 \
                  -DMINIZ_USE_UNALIGNED_LOADS_AND_STORES=0
MINIZ_CFLAGS := -std=c11 -O2 -g0 -Wall -Wextra
SELF_TEST := $(BUILD_DIR)/host-context-self-test
HOST_CONTEXT_LAUNCHER := $(BUILD_DIR)/host-context-launcher
ENTRY_FIXTURE := $(BUILD_DIR)/host-context-entry-fixture.so
ENTRY_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-entry-fixture.o
SYMBOL_FIXTURE := $(BUILD_DIR)/host-context-symbol-fixture.so
SYMBOL_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-symbol-fixture.o
SYMBOL_SELF_TEST := $(BUILD_DIR)/host-context-symbol-self-test
SYMBOL_SELF_TEST_OBJECT := $(BUILD_DIR)/host_context_symbol_self_test.o
PLT_FIXTURE := $(BUILD_DIR)/host-context-plt-fixture.so
PLT_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-plt-fixture.o
PLT_SELF_TEST := $(BUILD_DIR)/host-context-plt-self-test
PLT_SELF_TEST_OBJECT := $(BUILD_DIR)/host_context_plt_self_test.o
VERSION_SELF_TEST := $(BUILD_DIR)/host-context-version-self-test
VERSION_SELF_TEST_OBJECT := $(BUILD_DIR)/host_context_version_self_test.o
DEPENDENCY_FIXTURE := $(BUILD_DIR)/host-context-dependency-fixture.so
DEPENDENCY_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-dependency-fixture.o
TLS_FIXTURE := $(BUILD_DIR)/host-context-tls-fixture.so
TLS_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-tls-fixture.o
PROPERTY_FIXTURE := $(BUILD_DIR)/host-context-property-fixture.so
PROPERTY_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-property-fixture.o
RUNTIME_OBJECTS := $(BUILD_DIR)/runtime.o $(BUILD_DIR)/sha256.o $(BUILD_DIR)/miniz_tinfl.o
RUNTIME_OBJECTS += $(BUILD_DIR)/host_adapter.o
RUNTIME_OBJECTS += $(BUILD_DIR)/host_image_validation.o
SELF_TEST_OBJECT := $(BUILD_DIR)/host_context_self_test.o
LDLIBS ?= -ldl

.PHONY: all test test-adapter runtime self-test host-context-launcher symbol-fixture symbol-self-test plt-fixture plt-self-test version-self-test dependency-fixture tls-fixture property-fixture contract-probe contract-check clean check-host

all: test

check-host:
	@host_arch="$$(uname -m)"; \
	if [ "$$host_arch" != "aarch64" ]; then \
		echo "HostContext runtime tests require an aarch64 host; got $$host_arch" >&2; \
		exit 2; \
	fi

runtime: check-host $(RUNTIME_OBJECTS)

self-test: check-host $(SELF_TEST)
	"$(SELF_TEST)" "$(ENTRY_FIXTURE)"

host-context-launcher: $(HOST_CONTEXT_LAUNCHER)

symbol-fixture: $(SYMBOL_FIXTURE)

symbol-self-test: $(SYMBOL_SELF_TEST) $(SYMBOL_FIXTURE)
	"$(SYMBOL_SELF_TEST)" "$(SYMBOL_FIXTURE)"

plt-fixture: $(PLT_FIXTURE)

plt-self-test: $(PLT_SELF_TEST) $(PLT_FIXTURE)
	"$(PLT_SELF_TEST)" "$(PLT_FIXTURE)"

version-self-test: $(VERSION_SELF_TEST) $(DEPENDENCY_FIXTURE)
	URP_HOST_VALIDATION_TRACE=1 "$(VERSION_SELF_TEST)" "$(DEPENDENCY_FIXTURE)"

dependency-fixture: $(DEPENDENCY_FIXTURE)

tls-fixture: $(TLS_FIXTURE)

property-fixture: $(PROPERTY_FIXTURE)

test: check-host $(SELF_TEST) $(PLT_SELF_TEST) $(PLT_FIXTURE) $(VERSION_SELF_TEST) $(DEPENDENCY_FIXTURE)
	"$(SELF_TEST)" "$(ENTRY_FIXTURE)"
	"$(PLT_SELF_TEST)" "$(PLT_FIXTURE)"
	URP_HOST_VALIDATION_TRACE=1 "$(VERSION_SELF_TEST)" "$(DEPENDENCY_FIXTURE)"

test-adapter: check-host $(SELF_TEST)
	"$(SELF_TEST)" "$(ENTRY_FIXTURE)" --adapter-v2

contract-probe: $(BUILD_DIR)/contract-probe

contract-check: contract-probe
	"$(BUILD_DIR)/contract-probe"

$(SELF_TEST): $(SELF_TEST_OBJECT) $(RUNTIME_OBJECTS) $(ENTRY_FIXTURE)
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(SELF_TEST_OBJECT) $(RUNTIME_OBJECTS) $(LDLIBS) -o "$@"

$(HOST_CONTEXT_LAUNCHER): $(BUILD_DIR)/host_context_launcher.o $(RUNTIME_OBJECTS)
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(BUILD_DIR)/host_context_launcher.o $(RUNTIME_OBJECTS) $(LDLIBS) -o "$@"
	chmod 0755 "$@"

$(SYMBOL_SELF_TEST): $(SYMBOL_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(SYMBOL_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o -ldl -o "$@"

$(ENTRY_FIXTURE): $(ENTRY_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --no-undefined --eh-frame-hdr -z now "$<" -o "$@"

$(SYMBOL_FIXTURE): $(SYMBOL_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --no-undefined --eh-frame-hdr -z now "$<" -o "$@"

$(PLT_SELF_TEST): $(PLT_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(PLT_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o -ldl -o "$@"

$(VERSION_SELF_TEST): $(VERSION_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(VERSION_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o -ldl -o "$@"

$(PLT_FIXTURE): $(PLT_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --eh-frame-hdr -z now "$<" -o "$@"

# Keep this dependency oracle focused on GLOB_DAT/version requirements; the
# separately tested PLT slice owns JUMP_SLOT semantics.
$(DEPENDENCY_FIXTURE): $(DEPENDENCY_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none -z now "$<" -lc -o "$@"

# Direct linking avoids driver-injected weak PLT imports unrelated to these
# TLS/property fixtures, keeping each positive oracle isolated to its feature.
$(TLS_FIXTURE): $(TLS_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none -z now "$<" -o "$@"

$(PROPERTY_FIXTURE): $(PROPERTY_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none -z now "$<" -o "$@"

$(ENTRY_FIXTURE_OBJECT): host_context_entry_fixture.c include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -c "$<" -o "$@"

$(SYMBOL_FIXTURE_OBJECT): host_context_symbol_fixture.c include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -c "$<" -o "$@"

$(PLT_FIXTURE_OBJECT): host_context_plt_fixture.c include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -c "$<" -o "$@"

$(DEPENDENCY_FIXTURE_OBJECT): host_context_dependency_fixture.c include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -fno-plt -c "$<" -o "$@"

$(TLS_FIXTURE_OBJECT): host_context_tls_fixture.c include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -ftls-model=initial-exec -c "$<" -o "$@"

$(PROPERTY_FIXTURE_OBJECT): host_context_property_fixture.c include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -mbranch-protection=bti -c "$<" -o "$@"

$(BUILD_DIR)/host_context_self_test.o: host_context_self_test.c host_image_validation.h include/urp/host_context.h include/urp/runtime.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

$(BUILD_DIR)/host_context_launcher.o: host_context_launcher.c include/urp/host_context.h include/urp/runtime.h include/urp/host_adapter.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

$(SYMBOL_SELF_TEST_OBJECT): host_context_symbol_self_test.c include/urp/host_context.h include/urp/host_adapter.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

$(PLT_SELF_TEST_OBJECT): host_context_plt_self_test.c include/urp/host_adapter.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

$(VERSION_SELF_TEST_OBJECT): host_context_version_self_test.c include/urp/host_adapter.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

$(BUILD_DIR)/contract-probe: contract_probe.c include/urp/host_context.h include/urp/payload_frame.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) "$<" -o "$@"

$(BUILD_DIR)/runtime.o: runtime.c include/urp/host_context.h include/urp/runtime.h ../urprotect-launcher/sha256.h ../../third_party/miniz/miniz_tinfl.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

$(BUILD_DIR)/host_adapter.o: host_adapter.c host_image_validation.h include/urp/host_context.h include/urp/host_adapter.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -DURP_HOST_ADAPTER_TEST_DIAGNOSTICS=1 -c "$<" -o "$@"

$(BUILD_DIR)/host_image_validation.o: host_image_validation.c host_image_validation.h include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -DURP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS=1 -c "$<" -o "$@"

$(BUILD_DIR)/sha256.o: ../urprotect-launcher/sha256.c ../urprotect-launcher/sha256.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

$(BUILD_DIR)/miniz_tinfl.o: ../../third_party/miniz/miniz_tinfl.c \
	../../third_party/miniz/miniz.h ../../third_party/miniz/miniz_common.h \
	../../third_party/miniz/miniz_export.h ../../third_party/miniz/miniz_tdef.h \
	../../third_party/miniz/miniz_tinfl.h ../../third_party/miniz/miniz_zip.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(MINIZ_CPPFLAGS) $(MINIZ_CFLAGS) -c "$<" -o "$@"

clean:
	rm -rf "$(BUILD_DIR)"
