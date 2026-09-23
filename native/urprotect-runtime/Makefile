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
ENTRY_FIXTURE := $(BUILD_DIR)/host-context-entry-fixture.so
RUNTIME_OBJECTS := $(BUILD_DIR)/runtime.o $(BUILD_DIR)/sha256.o $(BUILD_DIR)/miniz_tinfl.o
RUNTIME_OBJECTS += $(BUILD_DIR)/host_adapter.o
SELF_TEST_OBJECT := $(BUILD_DIR)/host_context_self_test.o
LDLIBS ?= -ldl

.PHONY: all test runtime self-test clean check-host

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

test: check-host $(SELF_TEST)
	"$(SELF_TEST)" "$(ENTRY_FIXTURE)"

$(SELF_TEST): $(SELF_TEST_OBJECT) $(RUNTIME_OBJECTS) $(ENTRY_FIXTURE)
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CFLAGS) $(SELF_TEST_OBJECT) $(RUNTIME_OBJECTS) $(LDLIBS) -o "$@"

$(ENTRY_FIXTURE): host_context_entry_fixture.c include/urp/host_context.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared -nostdlib -nodefaultlibs \
		-Wl,--build-id=none,--no-undefined,-z,now "$<" -o "$@"

$(BUILD_DIR)/host_context_self_test.o: host_context_self_test.c include/urp/host_context.h include/urp/runtime.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

$(BUILD_DIR)/runtime.o: runtime.c include/urp/host_context.h include/urp/runtime.h ../urprotect-launcher/sha256.h ../../third_party/miniz/miniz_tinfl.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -c "$<" -o "$@"

$(BUILD_DIR)/host_adapter.o: host_adapter.c include/urp/host_context.h include/urp/host_adapter.h
	@mkdir -p "$(BUILD_DIR)"
	$(CC) $(CPPFLAGS) $(CFLAGS) -DURP_HOST_ADAPTER_TEST_DIAGNOSTICS=1 -c "$<" -o "$@"

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
