SHELL := /bin/sh

CC ?= cc
CXX ?= c++
AS ?= as
PYTHON ?= python3
BUILD_DIR ?= build
CFLAGS ?= -std=c11 -O2 -g0 -Wall -Wextra -Werror -Wshadow -Wconversion -pthread
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
GRAPH_FIXTURE := $(BUILD_DIR)/host-context-graph-fixture.so
GRAPH_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-graph-fixture.o
GRAPH_REVERSED_FIXTURE := $(BUILD_DIR)/host-context-graph-reversed-fixture.so
GRAPH_LOADER_FAILURE_FIXTURE := $(BUILD_DIR)/host-context-graph-loader-failure-fixture.so
GRAPH_LOADER_FAILURE_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-graph-loader-failure-fixture.o
FAKE_LOADER_FIXTURE := $(BUILD_DIR)/fake-loader-root/ld-linux-aarch64.so.1
FAKE_LOADER_FIXTURE_OBJECT := $(BUILD_DIR)/host_context_fake_loader.o
FAKE_LOADER_PROBE := $(BUILD_DIR)/host-context-fake-loader-probe
GRAPH_SELF_TEST := $(BUILD_DIR)/host-context-graph-self-test
GRAPH_SELF_TEST_OBJECT := $(BUILD_DIR)/host_context_graph_self_test.o
TLS_FIXTURE := $(BUILD_DIR)/host-context-tls-fixture.so
TLS_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-tls-fixture.o
TLSLE_FIXTURE := $(BUILD_DIR)/host-context-tlsle-fixture.so
TLSLE_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-tlsle-fixture.S.o
TLSLD_FIXTURE := $(BUILD_DIR)/host-context-tlsld-fixture.so
TLSLD_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-tlsld-fixture.S.o
TLSGD_FIXTURE := $(BUILD_DIR)/host-context-tlsgd-fixture.so
TLSGD_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-tlsgd-fixture.S.o
TLSDESC_FIXTURE := $(BUILD_DIR)/host-context-tlsdesc-fixture.so
TLSDESC_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-tlsdesc-fixture.S.o
THREADED_TLS_FIXTURE := $(BUILD_DIR)/host-context-threaded-tls-fixture.so
THREADED_TLS_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-threaded-tls-fixture.o
THREADED_TLS_HARNESS := $(BUILD_DIR)/host-context-threaded-tls-harness
THREADED_TLS_TRACE_TEST := $(BUILD_DIR)/host-context-threaded-tls-trace-test
THREADED_TLS_RUNTIME_TEST := $(BUILD_DIR)/host-context-threaded-tls-runtime-test
THREAD_ADAPTER_TEST := $(BUILD_DIR)/host-context-thread-adapter-test
CFI_FIXTURE := $(BUILD_DIR)/host-context-cfi-fixture.so
CFI_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-cfi-fixture.o
CFI_RUNTIME_TEST := $(BUILD_DIR)/host-context-cfi-runtime-test
CFI_RUNTIME_TEST_OBJECT := $(BUILD_DIR)/host_context_cfi_runtime_test.o
CFI_CPP_EXCEPTION_BRIDGE_OBJECT := $(BUILD_DIR)/host_context_cfi_exception_bridge.o
CFI_REGISTER_CALL_OBJECT := $(BUILD_DIR)/host_context_cfi_register_call.S.o
JUMP_TABLE_FIXTURE := $(BUILD_DIR)/host-context-jump-table-fixture.so
JUMP_TABLE_FIXTURE_S := $(BUILD_DIR)/host-context-jump-table-fixture.S.o
JUMP_TABLE_INDEX_CLOBBER_FIXTURE := $(BUILD_DIR)/host-context-jump-table-index-clobber-fixture.so
JUMP_TABLE_INDEX_CLOBBER_FIXTURE_S := $(BUILD_DIR)/host-context-jump-table-index-clobber-fixture.S.o
EXTERNAL_JUMP_TABLE_FIXTURE := $(BUILD_DIR)/host-context-external-jump-table-fixture.so
EXTERNAL_JUMP_TABLE_FIXTURE_S := $(BUILD_DIR)/host-context-external-jump-table-fixture.S.o
EXTERNAL_PROVIDER_SONAME := liburprotect-jump-table-provider.so.1
EXTERNAL_PROVIDER_FIXTURE := $(BUILD_DIR)/$(EXTERNAL_PROVIDER_SONAME)
EXTERNAL_PROVIDER_OBJECT := $(BUILD_DIR)/host-context-external-provider-fixture.S.o
EXTERNAL_PROVIDER_BAD_SIZE := $(BUILD_DIR)/host-context-external-provider-bad-size.so
EXTERNAL_PROVIDER_BAD_SIZE_OBJECT := $(BUILD_DIR)/host-context-external-provider-bad-size.S.o
EXTERNAL_PROVIDER_WRONG_SONAME := $(BUILD_DIR)/liburprotect-wrong-provider.so.1
EXTERNAL_PROVIDER_DEPENDENCY := $(BUILD_DIR)/host-context-external-provider-dependency.so
EXTERNAL_PROVIDER_CONFLICT := $(BUILD_DIR)/host-context-external-provider-conflict.so
EXTERNAL_PROVIDER_SYMBOL_CONFLICT := $(BUILD_DIR)/host-context-external-provider-symbol-conflict.so
EXTERNAL_PROVIDER_CONFLICT_OBJECT := $(BUILD_DIR)/host-context-external-provider-conflict.S.o
EXTERNAL_PROVIDER_CONSUMER := $(BUILD_DIR)/host-context-external-provider-consumer.so
EXTERNAL_PROVIDER_BAD_CONSUMER := $(BUILD_DIR)/host-context-external-provider-wrong-consumer.so
EXTERNAL_PROVIDER_CONSUMER_OBJECT := $(BUILD_DIR)/host-context-external-provider-consumer-fixture.S.o
EXTERNAL_PROVIDER_TEST := $(BUILD_DIR)/host-context-external-provider-self-test
SHARED_JUMP_TABLE_FIXTURE := $(BUILD_DIR)/host-context-shared-jump-table-fixture.so
SHARED_JUMP_TABLE_FIXTURE_S := $(BUILD_DIR)/host-context-shared-jump-table-fixture.S.o
DYNAMIC_IMPORT_FIXTURE := $(BUILD_DIR)/host-context-dynamic-import-fixture.so
DYNAMIC_IMPORT_FIXTURE_S := $(BUILD_DIR)/host-context-dynamic-import-fixture.S.o
STATIC_FUNCTION_POINTER_FIXTURE := $(BUILD_DIR)/host-context-static-function-pointer-fixture.so
STATIC_FUNCTION_POINTER_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-static-function-pointer-fixture.o
NATIVE_IMAGE_HANDOFF := $(BUILD_DIR)/native-image-handoff
HOST_CONTEXT_IMAGE_HANDOFF := $(BUILD_DIR)/host-context-image-handoff
HOST_IMAGE_VALIDATION_PROBE := $(BUILD_DIR)/host-image-validation-probe
HOST_IMAGE_VALIDATION_TEST_OBJECT := $(BUILD_DIR)/host_image_validation_test.o
TLS_VALIDATION_TEST := $(BUILD_DIR)/host-context-tls-validation-test
DYNAMIC_TLS_FIXTURE := $(BUILD_DIR)/host-context-dynamic-tls-fixture.so
DYNAMIC_TLS_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-dynamic-tls-fixture.o
PROPERTY_FIXTURE := $(BUILD_DIR)/host-context-property-fixture.so
PROPERTY_FIXTURE_OBJECT := $(BUILD_DIR)/host-context-property-fixture.o
RUNTIME_OBJECTS := $(BUILD_DIR)/runtime.o $(BUILD_DIR)/sha256.o $(BUILD_DIR)/miniz_tinfl.o
RUNTIME_OBJECTS += $(BUILD_DIR)/host_adapter.o
RUNTIME_OBJECTS += $(BUILD_DIR)/host_image_validation.o
SELF_TEST_OBJECT := $(BUILD_DIR)/host_context_self_test.o
LDLIBS ?= -ldl -pthread
ENTRY_FIXTURE_LDFLAGS ?=
HOST_CONTEXT_PLATFORM_CFLAGS ?=

.PHONY: all test runtime self-test host-context-launcher host-context-image-handoff host-image-validation-probe tls-validation-test symbol-fixture symbol-self-test plt-fixture plt-self-test version-self-test dependency-fixture tls-fixture tlsle-fixture tlsld-fixture tlsgd-fixture tlsdesc-fixture threaded-tls-fixture threaded-tls-harness threaded-tls-trace-test threaded-tls-runtime-test thread-adapter-test cfi-fixture cfi-runtime-test jump-table-fixture jump-table-index-clobber-fixture external-jump-table-fixture external-provider-fixtures external-provider-self-test shared-jump-table-fixture dynamic-import-fixture static-function-pointer-fixture native-image-handoff native-handoff-test property-fixture graph-fixture graph-self-test contract-probe contract-check clean check-host

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
	"$(VERSION_SELF_TEST)" "$(DEPENDENCY_FIXTURE)"

dependency-fixture: $(DEPENDENCY_FIXTURE)

tls-fixture: $(TLS_FIXTURE)

tlsle-fixture: $(TLSLE_FIXTURE)

tlsld-fixture: $(TLSLD_FIXTURE)

tlsgd-fixture: $(TLSGD_FIXTURE)

tlsdesc-fixture: $(TLSDESC_FIXTURE)

dynamic-tls-fixture: $(DYNAMIC_TLS_FIXTURE)

threaded-tls-fixture: $(THREADED_TLS_FIXTURE)

threaded-tls-harness: $(THREADED_TLS_HARNESS)

threaded-tls-trace-test: $(THREADED_TLS_TRACE_TEST)
	"$(THREADED_TLS_TRACE_TEST)"

threaded-tls-runtime-test: $(THREADED_TLS_RUNTIME_TEST)

thread-adapter-test: $(THREAD_ADAPTER_TEST) $(THREADED_TLS_FIXTURE) $(DYNAMIC_TLS_FIXTURE)
	"$(THREAD_ADAPTER_TEST)" "$(THREADED_TLS_FIXTURE)" "$(DYNAMIC_TLS_FIXTURE)"

cfi-fixture: $(CFI_FIXTURE)

cfi-runtime-test: $(CFI_RUNTIME_TEST)

jump-table-fixture: $(JUMP_TABLE_FIXTURE)

jump-table-index-clobber-fixture: $(JUMP_TABLE_INDEX_CLOBBER_FIXTURE)

external-jump-table-fixture: $(EXTERNAL_JUMP_TABLE_FIXTURE)

external-provider-fixtures: $(EXTERNAL_PROVIDER_FIXTURE) $(EXTERNAL_PROVIDER_BAD_SIZE) $(EXTERNAL_PROVIDER_WRONG_SONAME) $(EXTERNAL_PROVIDER_DEPENDENCY) $(EXTERNAL_PROVIDER_CONFLICT) $(EXTERNAL_PROVIDER_SYMBOL_CONFLICT) $(EXTERNAL_PROVIDER_CONSUMER) $(EXTERNAL_PROVIDER_BAD_CONSUMER)

external-provider-self-test: $(EXTERNAL_PROVIDER_TEST) external-provider-fixtures $(DEPENDENCY_FIXTURE)
	env -u LD_LIBRARY_PATH -u LD_PRELOAD -u LD_AUDIT "$(abspath $(EXTERNAL_PROVIDER_TEST))" "$(abspath $(EXTERNAL_PROVIDER_FIXTURE))" "$(abspath $(EXTERNAL_PROVIDER_CONSUMER))" "$(abspath $(EXTERNAL_PROVIDER_BAD_SIZE))" "$(abspath $(EXTERNAL_PROVIDER_WRONG_SONAME))" "$(abspath $(EXTERNAL_PROVIDER_DEPENDENCY))" "$(abspath $(EXTERNAL_PROVIDER_CONFLICT))" "$(abspath $(EXTERNAL_PROVIDER_SYMBOL_CONFLICT))" "$(abspath $(EXTERNAL_PROVIDER_BAD_CONSUMER))" "$(abspath $(DEPENDENCY_FIXTURE))"

shared-jump-table-fixture: $(SHARED_JUMP_TABLE_FIXTURE)

dynamic-import-fixture: $(DYNAMIC_IMPORT_FIXTURE)

static-function-pointer-fixture: $(STATIC_FUNCTION_POINTER_FIXTURE)

property-fixture: $(PROPERTY_FIXTURE)

graph-fixture: $(GRAPH_FIXTURE) $(GRAPH_REVERSED_FIXTURE) $(GRAPH_LOADER_FAILURE_FIXTURE) $(FAKE_LOADER_FIXTURE)

graph-self-test: $(GRAPH_SELF_TEST) $(GRAPH_FIXTURE) $(GRAPH_REVERSED_FIXTURE) $(GRAPH_LOADER_FAILURE_FIXTURE) $(DEPENDENCY_FIXTURE)
	env -u LD_LIBRARY_PATH -u LD_PRELOAD -u LD_AUDIT "$(GRAPH_SELF_TEST)" "$(GRAPH_FIXTURE)" "$(DEPENDENCY_FIXTURE)" "$(GRAPH_LOADER_FAILURE_FIXTURE)"
	env -u LD_LIBRARY_PATH -u LD_PRELOAD -u LD_AUDIT "$(GRAPH_SELF_TEST)" "$(GRAPH_REVERSED_FIXTURE)" "$(DEPENDENCY_FIXTURE)" "$(GRAPH_LOADER_FAILURE_FIXTURE)"

test: check-host $(SELF_TEST) $(THREAD_ADAPTER_TEST) $(THREADED_TLS_FIXTURE) $(TLS_FIXTURE) $(TLSLE_FIXTURE) $(TLSLD_FIXTURE) $(TLSGD_FIXTURE) $(TLSDESC_FIXTURE) $(HOST_IMAGE_VALIDATION_PROBE) $(TLS_VALIDATION_TEST) $(THREADED_TLS_TRACE_TEST) $(DYNAMIC_TLS_FIXTURE) $(PLT_SELF_TEST) $(PLT_FIXTURE) $(VERSION_SELF_TEST) $(DEPENDENCY_FIXTURE) $(GRAPH_SELF_TEST) $(GRAPH_FIXTURE) $(GRAPH_REVERSED_FIXTURE) $(GRAPH_LOADER_FAILURE_FIXTURE) $(FAKE_LOADER_FIXTURE) $(NATIVE_IMAGE_HANDOFF) $(HOST_CONTEXT_IMAGE_HANDOFF) external-provider-self-test
	"$(SELF_TEST)" "$(ENTRY_FIXTURE)"
	@set +e; "$(HOST_CONTEXT_IMAGE_HANDOFF)" "$(ENTRY_FIXTURE)" urp_entry "$(BUILD_DIR)/host-context-image-handoff.json"; status=$$?; set -e; test "$$status" -eq 23
	"$(THREAD_ADAPTER_TEST)" "$(THREADED_TLS_FIXTURE)" "$(DYNAMIC_TLS_FIXTURE)"
	"$(HOST_IMAGE_VALIDATION_PROBE)" "$(TLS_FIXTURE)"
	"$(HOST_IMAGE_VALIDATION_PROBE)" "$(TLSLE_FIXTURE)"
	"$(HOST_IMAGE_VALIDATION_PROBE)" "$(TLSLD_FIXTURE)"
	"$(HOST_IMAGE_VALIDATION_PROBE)" "$(TLSGD_FIXTURE)"
	"$(HOST_IMAGE_VALIDATION_PROBE)" "$(TLSDESC_FIXTURE)"
	"$(TLS_VALIDATION_TEST)" "$(TLS_FIXTURE)" "$(TLSGD_FIXTURE)" "$(TLSDESC_FIXTURE)" "$(TLSLD_FIXTURE)"
	"$(THREADED_TLS_TRACE_TEST)"
	"$(PLT_SELF_TEST)" "$(PLT_FIXTURE)"
	"$(VERSION_SELF_TEST)" "$(DEPENDENCY_FIXTURE)"
	./test_native_image_handoff.sh "$(NATIVE_IMAGE_HANDOFF)"
	env -u LD_LIBRARY_PATH -u LD_PRELOAD -u LD_AUDIT "$(GRAPH_SELF_TEST)" "$(GRAPH_FIXTURE)" "$(DEPENDENCY_FIXTURE)" "$(GRAPH_LOADER_FAILURE_FIXTURE)"
	env -u LD_LIBRARY_PATH -u LD_PRELOAD -u LD_AUDIT "$(GRAPH_SELF_TEST)" "$(GRAPH_REVERSED_FIXTURE)" "$(DEPENDENCY_FIXTURE)" "$(GRAPH_LOADER_FAILURE_FIXTURE)"

contract-probe: $(BUILD_DIR)/contract-probe

contract-check: contract-probe
	"$(BUILD_DIR)/contract-probe"

native-image-handoff: $(NATIVE_IMAGE_HANDOFF)

host-context-image-handoff: $(HOST_CONTEXT_IMAGE_HANDOFF)

host-image-validation-probe: $(HOST_IMAGE_VALIDATION_PROBE)

tls-validation-test: $(TLS_VALIDATION_TEST)

native-handoff-test: $(NATIVE_IMAGE_HANDOFF)
	./test_native_image_handoff.sh "$(NATIVE_IMAGE_HANDOFF)"

$(NATIVE_IMAGE_HANDOFF): native_image_handoff.c ../urprotect-launcher/sha256.c ../urprotect-launcher/sha256.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) native_image_handoff.c ../urprotect-launcher/sha256.c -o "$@"

$(HOST_CONTEXT_IMAGE_HANDOFF): host_context_image_handoff.c ../urprotect-launcher/sha256.c ../urprotect-launcher/sha256.h $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) host_context_image_handoff.c ../urprotect-launcher/sha256.c $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o $(LDLIBS) -o "$@"

$(EXTERNAL_PROVIDER_TEST): host_context_external_provider_self_test.c host_image_validation.h include/urp/host_adapter.h $(BUILD_DIR)/host_adapter.o $(HOST_IMAGE_VALIDATION_TEST_OBJECT) $(BUILD_DIR)/sha256.o
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -DURP_HOST_ADAPTER_TEST_DIAGNOSTICS=1 -DURP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS=1 "$<" $(BUILD_DIR)/host_adapter.o $(HOST_IMAGE_VALIDATION_TEST_OBJECT) $(BUILD_DIR)/sha256.o $(LDLIBS) -o "$@"

$(HOST_IMAGE_VALIDATION_PROBE): host_image_validation_probe.c host_image_validation.h $(BUILD_DIR)/host_image_validation.o
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) host_image_validation_probe.c $(BUILD_DIR)/host_image_validation.o -o "$@"

# The TLS bounds oracle uses the identical validation code built with
# test-only diagnostics, so CI can distinguish malformed ELF from a
# semantically unsupported relocation without changing production acceptance.
$(TLS_VALIDATION_TEST): host_context_tls_validation_test.c host_image_validation.h $(HOST_IMAGE_VALIDATION_TEST_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) host_context_tls_validation_test.c $(HOST_IMAGE_VALIDATION_TEST_OBJECT) -o "$@"

$(SELF_TEST): $(SELF_TEST_OBJECT) $(RUNTIME_OBJECTS) $(ENTRY_FIXTURE)
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(SELF_TEST_OBJECT) $(RUNTIME_OBJECTS) $(LDLIBS) -o "$@"

$(HOST_CONTEXT_LAUNCHER): $(BUILD_DIR)/host_context_launcher.o $(RUNTIME_OBJECTS)
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(BUILD_DIR)/host_context_launcher.o $(RUNTIME_OBJECTS) $(LDLIBS) -o "$@"
	chmod 0755 "$@"

$(SYMBOL_SELF_TEST): $(SYMBOL_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o $(BUILD_DIR)/sha256.o
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(SYMBOL_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o $(BUILD_DIR)/sha256.o -ldl -o "$@"

$(ENTRY_FIXTURE): $(ENTRY_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --no-undefined --eh-frame-hdr -z now $(ENTRY_FIXTURE_LDFLAGS) "$<" -o "$@"

$(SYMBOL_FIXTURE): $(SYMBOL_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --no-undefined --eh-frame-hdr -z now "$<" -o "$@"

$(PLT_SELF_TEST): $(PLT_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o $(BUILD_DIR)/sha256.o
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(PLT_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o $(BUILD_DIR)/sha256.o -ldl -o "$@"

$(VERSION_SELF_TEST): $(VERSION_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o $(BUILD_DIR)/sha256.o
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(VERSION_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o $(BUILD_DIR)/sha256.o -ldl -o "$@"

$(PLT_FIXTURE): $(PLT_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --eh-frame-hdr -z now "$<" -o "$@"

# Keep this dependency oracle focused on GLOB_DAT/version requirements; the
# separately tested PLT slice owns JUMP_SLOT semantics.
$(DEPENDENCY_FIXTURE): $(DEPENDENCY_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --hash-style=gnu --build-id=none -z now "$<" -lc -o "$@"


$(GRAPH_FIXTURE): $(GRAPH_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --hash-style=gnu --build-id=none -z now --no-as-needed "$<" -lc -l:ld-linux-aarch64.so.1 -o "$@"

$(GRAPH_REVERSED_FIXTURE): $(GRAPH_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --hash-style=gnu --build-id=none -z now --no-as-needed "$<" -l:ld-linux-aarch64.so.1 -lc -o "$@"

$(GRAPH_LOADER_FAILURE_FIXTURE): $(GRAPH_LOADER_FAILURE_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --hash-style=gnu --build-id=none -z now --no-as-needed --unresolved-symbols=ignore-all "$<" -lc -l:ld-linux-aarch64.so.1 -o "$@"

$(FAKE_LOADER_FIXTURE): $(FAKE_LOADER_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)/fake-loader-root"
	$(LD) -shared --hash-style=gnu --build-id=none -z now -soname ld-linux-aarch64.so.1 "$<" -o "$@"

$(FAKE_LOADER_PROBE): host_context_fake_loader_probe.c host_context_graph_fixture_contract.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) "$<" -ldl -o "$@"

$(GRAPH_SELF_TEST): $(GRAPH_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o $(BUILD_DIR)/sha256.o
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(GRAPH_SELF_TEST_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o $(BUILD_DIR)/sha256.o -ldl -o "$@"

$(GRAPH_FIXTURE_OBJECT): host_context_graph_fixture.c host_context_graph_fixture_contract.h include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -fno-plt -c "$<" -o "$@"

$(GRAPH_LOADER_FAILURE_FIXTURE_OBJECT): host_context_graph_loader_failure_fixture.c include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -fno-plt -c "$<" -o "$@"

$(FAKE_LOADER_FIXTURE_OBJECT): host_context_fake_loader.c
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -fno-plt -c "$<" -o "$@"

$(GRAPH_SELF_TEST_OBJECT): host_context_graph_self_test.c host_context_graph_fixture_contract.h host_image_validation.h include/urp/host_context.h include/urp/host_adapter.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -DURP_HOST_ADAPTER_TEST_DIAGNOSTICS=1 -c "$<" -o "$@"

# Direct linking avoids driver-injected weak PLT imports unrelated to these
# TLS/property fixtures, keeping each positive oracle isolated to its feature.
$(TLS_FIXTURE): $(TLS_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none -z now --emit-relocs "$<" -o "$@"

$(TLSLE_FIXTURE): $(TLSLE_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none -z now --emit-relocs "$<" -o "$@"

$(TLSLE_FIXTURE_OBJECT): host_context_tlsle_fixture.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) -o "$@" "$<"

$(TLSLD_FIXTURE): $(TLSLD_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none -z now --no-as-needed --emit-relocs "$<" -lc -o "$@"

$(TLSLD_FIXTURE_OBJECT): host_context_tlsld_fixture.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) -o "$@" "$<"

$(TLSGD_FIXTURE): $(TLSGD_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	# The strict runtime parser deliberately does not accept DT_HASH alongside
	# glibc version requirements. Build this legitimate TLSGD test DSO with
	# GNU hash, like the runtime's approved glibc versioned-dependency subset.
	$(LD) -shared --hash-style=gnu --build-id=none -z now --no-as-needed --emit-relocs "$<" -lc -o "$@"

$(TLSGD_FIXTURE_OBJECT): host_context_tlsgd_fixture.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) -o "$@" "$<"

$(TLSDESC_FIXTURE): $(TLSDESC_FIXTURE_OBJECT) patch_tlsdesc_dynamic_tags.py
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none -z now --emit-relocs "$<" -o "$@"
	$(PYTHON) patch_tlsdesc_dynamic_tags.py "$@"

$(TLSDESC_FIXTURE_OBJECT): host_context_tlsdesc_fixture.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) -o "$@" "$<"

$(THREADED_TLS_FIXTURE): $(THREADED_TLS_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none -z now "$<" -o "$@"

$(DYNAMIC_TLS_FIXTURE): $(DYNAMIC_TLS_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none -z now "$<" -o "$@"

$(THREADED_TLS_HARNESS): host_context_threaded_tls_harness.c host_context_threaded_tls_trace.c host_context_threaded_tls_trace.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) host_context_threaded_tls_harness.c host_context_threaded_tls_trace.c -o "$@"

$(THREADED_TLS_TRACE_TEST): host_context_threaded_tls_trace_test.c host_context_threaded_tls_trace.c host_context_threaded_tls_trace.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) host_context_threaded_tls_trace_test.c host_context_threaded_tls_trace.c -o "$@"


$(THREAD_ADAPTER_TEST): host_context_thread_adapter_test.c $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o $(BUILD_DIR)/sha256.o
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -DURP_HOST_ADAPTER_TEST_DIAGNOSTICS=1 "$<" $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o $(BUILD_DIR)/sha256.o -ldl -pthread -o "$@"

$(CFI_FIXTURE): $(CFI_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none -z now --eh-frame-hdr "$<" -o "$@"

$(CFI_FIXTURE_OBJECT): host_context_cfi_fixture.c include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -O2 -fPIC -fno-plt -fno-omit-frame-pointer -fasynchronous-unwind-tables -c "$<" -o "$@"

$(CFI_RUNTIME_TEST): $(CFI_RUNTIME_TEST_OBJECT) $(CFI_CPP_EXCEPTION_BRIDGE_OBJECT) $(CFI_REGISTER_CALL_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o $(BUILD_DIR)/sha256.o
	@mkdir -p "$(BUILD_DIR)"
	$(CXX) $(filter-out -std=c11,$(CFLAGS)) $(CFI_RUNTIME_TEST_OBJECT) $(CFI_CPP_EXCEPTION_BRIDGE_OBJECT) $(CFI_REGISTER_CALL_OBJECT) $(BUILD_DIR)/host_adapter.o $(BUILD_DIR)/host_image_validation.o $(BUILD_DIR)/sha256.o -ldl -rdynamic -o "$@"

$(CFI_RUNTIME_TEST_OBJECT): host_context_cfi_runtime_test.c host_context_cfi_exception_bridge.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fasynchronous-unwind-tables -fno-omit-frame-pointer -c "$<" -o "$@"

$(CFI_CPP_EXCEPTION_BRIDGE_OBJECT): host_context_cfi_exception_bridge.cpp host_context_cfi_exception_bridge.h
	@mkdir -p "$(BUILD_DIR)"
	$(CXX) $(CPPFLAGS) $(filter-out -std=c11,$(CFLAGS)) -std=c++17 -fexceptions -fasynchronous-unwind-tables -fno-omit-frame-pointer -c "$<" -o "$@"

$(CFI_REGISTER_CALL_OBJECT): host_context_cfi_register_call.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) -o "$@" "$<"

$(JUMP_TABLE_FIXTURE): $(JUMP_TABLE_FIXTURE_S)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --no-undefined --eh-frame-hdr -z now "$<" -o "$@"

$(JUMP_TABLE_FIXTURE_S): host_context_jump_table_fixture.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) -o "$@" "$<"

$(JUMP_TABLE_INDEX_CLOBBER_FIXTURE): $(JUMP_TABLE_INDEX_CLOBBER_FIXTURE_S)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --no-undefined --eh-frame-hdr -z now "$<" -o "$@"

$(JUMP_TABLE_INDEX_CLOBBER_FIXTURE_S): host_context_jump_table_fixture.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) --defsym URP_JUMP_TABLE_INDEX_CLOBBER=1 -o "$@" "$<"

$(EXTERNAL_JUMP_TABLE_FIXTURE): $(EXTERNAL_JUMP_TABLE_FIXTURE_S)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --hash-style=gnu -z now "$<" -o "$@"

$(EXTERNAL_JUMP_TABLE_FIXTURE_S): host_context_external_jump_table_fixture.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) -o "$@" "$<"

$(EXTERNAL_PROVIDER_FIXTURE): $(EXTERNAL_PROVIDER_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared -z separate-code --build-id=sha1 --hash-style=gnu -soname $(EXTERNAL_PROVIDER_SONAME) "$<" -o "$@"

$(EXTERNAL_PROVIDER_OBJECT): host_context_external_provider_fixture.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) -o "$@" "$<"

$(EXTERNAL_PROVIDER_BAD_SIZE): $(EXTERNAL_PROVIDER_BAD_SIZE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared -z separate-code --build-id=sha1 --hash-style=gnu -soname $(EXTERNAL_PROVIDER_SONAME) "$<" -o "$@"

$(EXTERNAL_PROVIDER_BAD_SIZE_OBJECT): host_context_external_provider_fixture.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) --defsym URP_PROVIDER_BAD_SIZE=1 -o "$@" "$<"

$(EXTERNAL_PROVIDER_WRONG_SONAME): $(EXTERNAL_PROVIDER_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared -z separate-code --build-id=sha1 --hash-style=gnu -soname liburprotect-wrong-provider.so.1 "$<" -o "$@"

$(EXTERNAL_PROVIDER_DEPENDENCY): $(EXTERNAL_PROVIDER_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared -z separate-code --build-id=sha1 --hash-style=gnu -soname $(EXTERNAL_PROVIDER_SONAME) --no-as-needed "$<" -lc -o "$@"

$(EXTERNAL_PROVIDER_CONFLICT): $(EXTERNAL_PROVIDER_CONFLICT_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared -z separate-code --build-id=sha1 --hash-style=gnu -soname $(EXTERNAL_PROVIDER_SONAME) "$<" -o "$@"

$(EXTERNAL_PROVIDER_CONFLICT_OBJECT): host_context_external_provider_fixture.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) --defsym URP_PROVIDER_VARIANT=1 -o "$@" "$<"

$(EXTERNAL_PROVIDER_SYMBOL_CONFLICT): $(EXTERNAL_PROVIDER_CONFLICT_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared -z separate-code --build-id=sha1 --hash-style=gnu -soname liburprotect-symbol-conflict.so.1 "$<" -o "$@"

$(EXTERNAL_PROVIDER_CONSUMER): $(EXTERNAL_PROVIDER_CONSUMER_OBJECT) $(EXTERNAL_PROVIDER_FIXTURE)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --hash-style=gnu --no-undefined -z now "$<" -L"$(BUILD_DIR)" -l:$(EXTERNAL_PROVIDER_SONAME) -o "$@"

$(EXTERNAL_PROVIDER_BAD_CONSUMER): $(EXTERNAL_PROVIDER_CONSUMER_OBJECT) $(EXTERNAL_PROVIDER_WRONG_SONAME)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --hash-style=gnu --no-undefined -z now "$<" -L"$(BUILD_DIR)" -l:liburprotect-wrong-provider.so.1 -o "$@"

$(EXTERNAL_PROVIDER_CONSUMER_OBJECT): host_context_external_provider_consumer_fixture.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) -o "$@" "$<"

$(SHARED_JUMP_TABLE_FIXTURE): $(SHARED_JUMP_TABLE_FIXTURE_S)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --no-undefined --eh-frame-hdr -z now --emit-relocs "$<" -o "$@"

$(SHARED_JUMP_TABLE_FIXTURE_S): host_context_shared_jump_table_fixture.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) -o "$@" "$<"

$(DYNAMIC_IMPORT_FIXTURE): $(DYNAMIC_IMPORT_FIXTURE_S)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --hash-style=gnu -z now --unresolved-symbols=ignore-all "$<" -o "$@"

$(DYNAMIC_IMPORT_FIXTURE_S): host_context_dynamic_import_fixture.S
	@mkdir -p "$(BUILD_DIR)"
	$(AS) -o "$@" "$<"

$(STATIC_FUNCTION_POINTER_FIXTURE): $(STATIC_FUNCTION_POINTER_FIXTURE_OBJECT)
	@mkdir -p "$(BUILD_DIR)"
	$(LD) -shared --build-id=none --no-undefined --emit-relocs -z now "$<" -o "$@"

$(STATIC_FUNCTION_POINTER_FIXTURE_OBJECT): host_context_static_function_pointer_fixture.c
	@mkdir -p "$(BUILD_DIR)"
	$(CC) -std=c11 -O1 -fPIC -fno-inline -fno-optimize-sibling-calls -fno-unwind-tables -fno-asynchronous-unwind-tables -Wall -Wextra -Werror -c "$<" -o "$@"

$(THREADED_TLS_RUNTIME_TEST): host_context_threaded_tls_runtime_test.c $(RUNTIME_OBJECTS)
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) "$<" $(RUNTIME_OBJECTS) $(LDLIBS) -o "$@"

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

$(THREADED_TLS_FIXTURE_OBJECT): host_context_threaded_tls_fixture.c include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -fno-plt -ftls-model=initial-exec -pthread -c "$<" -o "$@"

$(DYNAMIC_TLS_FIXTURE_OBJECT): host_context_dynamic_tls_fixture.c
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -ftls-model=global-dynamic -c "$<" -o "$@"

$(PROPERTY_FIXTURE_OBJECT): host_context_property_fixture.c include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -mbranch-protection=bti -c "$<" -o "$@"

$(BUILD_DIR)/host_context_self_test.o: host_context_self_test.c host_image_validation.h android_packed_relocation_tags.h include/urp/host_context.h include/urp/runtime.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) $(HOST_CONTEXT_PLATFORM_CFLAGS) -c "$<" -o "$@"

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

$(BUILD_DIR)/host_image_validation.o: host_image_validation.c host_image_validation.h android_packed_relocation_tags.h include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) $(HOST_CONTEXT_PLATFORM_CFLAGS) -c "$<" -o "$@"

$(HOST_IMAGE_VALIDATION_TEST_OBJECT): host_image_validation.c host_image_validation.h android_packed_relocation_tags.h include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) $(HOST_CONTEXT_PLATFORM_CFLAGS) -DURP_HOST_IMAGE_VALIDATION_TEST_DIAGNOSTICS=1 -c "$<" -o "$@"

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
